#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "fcntl.h"

struct spinlock tickslock;
uint ticks;

extern char trampoline[], uservec[], userret[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

extern int devintr();

void
trapinit(void)
{
  initlock(&tickslock, "time");
}

// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}

//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
void
usertrap(void)
{
  int which_dev = 0;

  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
  w_stvec((uint64)kernelvec);

  struct proc *p = myproc();
  
  // save user program counter.
  p->trapframe->epc = r_sepc();
  
  if(r_scause() == 8){
    // system call

    if(p->killed)
      exit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->trapframe->epc += 4;

    // an interrupt will change sstatus &c registers,
    // so don't enable until done with those registers.
    intr_on();

    syscall();
  } else if((which_dev = devintr()) != 0){
    // ok
  } 
  else if(r_scause() == 13 || r_scause() == 15){
    // page fault
    uint64 fault_addr = r_stval();
    // check if this va is in the vma range [start_addr, start_addr + length)
    // and also check p->vmas[i].valid b/c 1. When a VMA is unmapped, you'll set valid = 0 to mark the slot as free. But start_addr still has the old value — it's not zeroed out.
    // So without checking valid, you might match a stale VMA that was already freed.
    // we should break once we found the vma and mapped the page!
    int handled = 0;
    for(int i = 0; i < 16; i++){
      if(p->vmas[i].valid && fault_addr >= p->vmas[i].start_addr && fault_addr < p->vmas[i].start_addr + p->vmas[i].length){
        // found the VMA
        // 2. kalloc a physical page
        void *pa = kalloc();
        if(pa == 0){
          p->killed = 1;
          break;
        }
        // 3. zero it out with memset
        memset(pa, 0, PGSIZE);
    
        // 4. read file data into pa using readi:
        struct vma *vma = &p->vmas[i];
        // if the fault_addr is on the next page of the start_addr, the readi offset should add the page_size into it
        // round down fault_addr to page boundary, then calculate offset into file
        uint64 page_offset = PGROUNDDOWN(fault_addr) - vma->start_addr;
        ilock(vma->f->ip);
        readi(vma->f->ip, 0, (uint64)pa, vma->offset + page_offset, PGSIZE);
        iunlock(vma->f->ip);
        
        // 5. mappages into pagetable with correct permissions
        //    prot → PTE flags (PROT_READ→PTE_R, PROT_WRITE→PTE_W, always PTE_U)
        // PROT_READ	0x1
        // PROT_WRITE	0x2
        // PTE_R	1 << 1 = 0x2
        // PTE_W	1 << 2 = 0x4
        // PTE_U	1 << 4 = 0x10
        // mappages(myproc()->pagetable, fault_addr, PGSIZE, pa, vma->prot | PTE_U);
        int perm = PTE_U;
        if(vma->prot & PROT_READ)  perm |= PTE_R;
        if(vma->prot & PROT_WRITE) perm |= PTE_W;
        // Note we use PGROUNDDOWN(fault_addr) not fault_addr — the VA must be page-aligned for mappages.
        if(mappages(p->pagetable, PGROUNDDOWN(fault_addr), PGSIZE, (uint64)pa, perm) < 0){
          kfree(pa);
          p->killed = 1;
        }
        handled = 1;
        break;
      }
    }
    // After the loop, if no VMA matched, it's a real invalid access — fall through to the existing p->killed = 1 error handling.
    if (!handled) {
      p->killed = 1;
    }
  } else {
    printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
    printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
    p->killed = 1;
  }

  if(p->killed)
    exit(-1);

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2)
    yield();

  usertrapret();
}

//
// return to user space
//
void
usertrapret(void)
{
  struct proc *p = myproc();

  // we're about to switch the destination of traps from
  // kerneltrap() to usertrap(), so turn off interrupts until
  // we're back in user space, where usertrap() is correct.
  intr_off();

  // send syscalls, interrupts, and exceptions to trampoline.S
  w_stvec(TRAMPOLINE + (uservec - trampoline));

  // set up trapframe values that uservec will need when
  // the process next re-enters the kernel.
  p->trapframe->kernel_satp = r_satp();         // kernel page table
  p->trapframe->kernel_sp = p->kstack + PGSIZE; // process's kernel stack
  p->trapframe->kernel_trap = (uint64)usertrap;
  p->trapframe->kernel_hartid = r_tp();         // hartid for cpuid()

  // set up the registers that trampoline.S's sret will use
  // to get to user space.
  
  // set S Previous Privilege mode to User.
  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode
  w_sstatus(x);

  // set S Exception Program Counter to the saved user pc.
  w_sepc(p->trapframe->epc);

  // tell trampoline.S the user page table to switch to.
  uint64 satp = MAKE_SATP(p->pagetable);

  // jump to trampoline.S at the top of memory, which 
  // switches to the user page table, restores user registers,
  // and switches to user mode with sret.
  uint64 fn = TRAMPOLINE + (userret - trampoline);
  ((void (*)(uint64,uint64))fn)(TRAPFRAME, satp);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
void 
kerneltrap()
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    printf("scause %p\n", scause);
    printf("sepc=%p stval=%p\n", r_sepc(), r_stval());
    panic("kerneltrap");
  }

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2 && myproc() != 0 && myproc()->state == RUNNING)
    yield();

  // the yield() may have caused some traps to occur,
  // so restore trap registers for use by kernelvec.S's sepc instruction.
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  acquire(&tickslock);
  ticks++;
  wakeup(&ticks);
  release(&tickslock);
}

// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr()
{
  uint64 scause = r_scause();

  if((scause & 0x8000000000000000L) &&
     (scause & 0xff) == 9){
    // this is a supervisor external interrupt, via PLIC.

    // irq indicates which device interrupted.
    int irq = plic_claim();

    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ){
      virtio_disk_intr();
    } else if(irq){
      printf("unexpected interrupt irq=%d\n", irq);
    }

    // the PLIC allows each device to raise at most one
    // interrupt at a time; tell the PLIC the device is
    // now allowed to interrupt again.
    if(irq)
      plic_complete(irq);

    return 1;
  } else if(scause == 0x8000000000000001L){
    // software interrupt from a machine-mode timer interrupt,
    // forwarded by timervec in kernelvec.S.

    if(cpuid() == 0){
      clockintr();
    }
    
    // acknowledge the software interrupt by clearing
    // the SSIP bit in sip.
    w_sip(r_sip() & ~2);

    return 2;
  } else {
    return 0;
  }
}

