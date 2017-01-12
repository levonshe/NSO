#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm-generic/cacheflush.h>
#include <linux/syscalls.h>
//#include <linux/page.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/types.h>
MODULE_LICENSE("GPL");


/* Helpers */
int set_addr_rw(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (!pte) return -1;
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
    return 1;

}

int set_addr_ro(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (!pte) return -1;
    pte->pte = pte->pte &~_PAGE_RW;
    return 1;

}

void * usr_low;
void * usr_upper;
void * src_low;
void * src_uppper;

struct task_struct *mon_thread;

asmlinkage long (*org_sys_ptrace)(long request, long pid, unsigned long addr,
                           unsigned long data);
static int monitor(void *data) {
  struct task_struct *child = ( struct task_struct *) data;
  int child_pid = child->pid;
  
  long rc;
  rc = org_sys_ptrace(PTRACE_ATTACH, child_pid, 0, 0);
  printk (KERN_DEBUG " ptrace asked attach , for pid=%d rc=%d\n", child_pid, (int) rc);
  rc = org_sys_ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
  printk (KERN_DEBUG " ptrace asked signlestep , for pid=%d rc=%d\n", child_pid, (int) rc);
  while (kthread_should_stop()) {
    if (signal_pending(current) ) {
	rc = org_sys_ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
	printk (KERN_DEBUG " ptrace asked signlestep , rc=%d\n", (int) rc);
    }
  }
  return rc;     
}
//#define page_to_virt(page)  pfn_to_virt(page_to_pfn(page))
#if 0
find_who_hold_address()
{
  struct task_struct *p;
  struct vm_area_struct * vma;
         read_lock(&tasklist_lock);
         for_each_process(p) {
	   
	     
                 if (p->flags & PF_KTHREAD)
                         continue;
                 if (is_global_init(p))
                         continue;
		  
		  vma = find_vma(current->mm, usr_low);
	      if (vma)
		  sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
                 //do_send_sig_info(sig, SEND_SIG_FORCED, p, true);
	   
	
         read_unlock(&tasklist_lock);
	 }
}
#endif


asmlinkage long (*mmap2)(unsigned long addr, unsigned long len,
                        unsigned long prot, unsigned long flags,
                        unsigned long fd, unsigned long pgoff);
asmlinkage long my_mmap2(unsigned long addr, unsigned long len,
                        unsigned long prot, unsigned long flags,
                        unsigned long fd, unsigned long pgoff)
{
  long ret, rc;
  //struct vm_area_struct * vma;
  
  ret = mmap2(addr, len, prot, flags, fd, pgoff);
  if ( ( (memcmp(current->comm, "a.out", 5)) == 0) &&
    len >1024)  {
    printk (KERN_DEBUG "MY  MMAP len=%d, ret=0x%lx, command=%s\n", (int)len,  ret, current->comm);
    if (current->ptrace == 0 ) {
      //rc = org_sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
      
     //printk (KERN_DEBUG " ptrace activated for pid=%d , rc=%d\n", current->pid, (int) rc);
     mon_thread = kthread_run(monitor, current, "sstep-%d", current->pid); 
    }
  #if 0
      vma = find_vma(current->mm, usr_low);
      if ( vma) {
	   set process as traced
  #endif
  }
  return ret;
  
  
}



static void **syscall_table;

static int __init hijack_init(void)
{
    int ret;
    long sct_virt_addr;
    
    void * mmap_addr=  (void *) kallsyms_lookup_name("sys_mmap");  
    void * mmap_pgof_addr=  (void *) kallsyms_lookup_name("sys_mmap_pgoff");  
 
    printk(KERN_ALERT "\nINTERCEPT INIT, sys_mmap addr is %p\n", mmap_addr);
    
    printk(KERN_ALERT "\nINTERCEPT INIT, sys_mmap_pgoff addr is %p\n", mmap_pgof_addr);
    
    syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        printk("Cannot find the system call table virt address\n"); 
        return -1;
    }
      
    printk (KERN_DEBUG "Found sys_call_table %lX\n",(unsigned long) syscall_table);
    //printk (KERN_DEBUG "Found sys_old_mmap %p\n", sys_mmap);
    
    printk (KERN_DEBUG "Found sys_call_table[__NR_mmap] %p\n", syscall_table[__NR_mmap]);
   
    printk (KERN_DEBUG "Setting syscall table page to read and write\n");
    sct_virt_addr = PAGE_ALIGN((unsigned long) syscall_table);
   
    ret = set_addr_rw((unsigned long)syscall_table);
   
   
    if (! ret) {
        printk(KERN_DEBUG "Cannot set the memory to rw at sct_virt_addr %p, rc=%d\n", syscall_table, ret);
    } else {
        printk(KERN_DEBUG "Page at %luX set to rw, rc=%d\n", sct_virt_addr, ret );
    }


    //orig_sys_mmap = syscall_table[__NR_mmap];
    mmap2 = syscall_table[__NR_mmap];
    org_sys_ptrace = syscall_table[__NR_ptrace];
    printk(KERN_DEBUG "LEV SAVED original mmap2 NR_mmap = %d func at %p \n",__NR_mmap, mmap2);
    
    //return 0;
    syscall_table[__NR_mmap] = my_mmap2;
    //usleep_range(300000, 6000000);
    //syscall_table[__NR_mmap] = mmap2;
    printk(KERN_DEBUG "LEV sys_mmap hijacked to my_mmap2 =%p , syscall_table[__NR_mmap]=%p !!\n", my_mmap2, syscall_table[__NR_mmap]);
    //printk(KERN_DEBUG "LEV sys_mmap hijacked to my_old_mmap =%p , syscall_table[__NR_mmap]=%p !!\n", my_old_mmap, syscall_table[__NR_mmap]);

    
                                    
    return 0;
}

static void __exit hijack_release(void)
{
    int ret;
    
    unsigned long sct_virt_addr = (unsigned long) syscall_table;

    
    printk (KERN_DEBUG "Setting syscall back to original\n");
    
   
    syscall_table[__NR_mmap] = mmap2;

    if (syscall_table) {
        printk (KERN_DEBUG "Setting syscall table back to read only\n");

	ret = set_addr_ro((unsigned long)syscall_table);
	if (!ret) {
	    printk(KERN_ALERT "%s:Unable to set syscall table page at %p to READ_ONLY, rc=%d\n",
				KBUILD_MODNAME, (void *) sct_virt_addr, ret);
	}
	printk(KERN_DEBUG "syscall table page at %p set to READ_ONLY\n",(void *) sct_virt_addr);
    }
    printk(KERN_DEBUG "stopping monitor thread pid=%d\n", mon_thread->pid);
    kthread_stop(mon_thread);
    
}
module_init(hijack_init);
module_exit(hijack_release);