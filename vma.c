#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm-generic/cacheflush.h>
#include <linux/syscalls.h>
//#include <linux/page.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/types.h>
#include <linux/kprobes.h>
MODULE_LICENSE("GPL");

unsigned long  usr_low =    0x55a0acee8010;
unsigned long  usr_upper = 0x56098ae94f50;
unsigned long  src_low = 0x56098ae94f50;
unsigned long  src_upper = 0x58098ae91010;
#define NR_RANGES 20
static int usr_ranges; // couunt 
static int src_ranges;
static int active_usr_ranges; // couunt 
static int active_src_ranges;
typedef struct __range { 
    unsigned long low;
    unsigned long upper;
    uint8_t  enabled;
} range_t;
static range_t usr_mem_range[NR_RANGES];
static range_t src_mem_range[NR_RANGES];
static range_t active_src_mem_range;
static int checked_pid=0;
/* pre_handler: this is called just before the probed instruction 
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
#define ALLOW 1
#define DENY 0
#define TRUE 1
#define FALSE 0

static int active_exe_range = FALSE;
int  in_usr_range(struct vm_area_struct *vma, unsigned long address)
{
    int n;
    
    
    for ( n = usr_ranges; n > 0; n--) {
	if (! usr_mem_range[n].enabled) {
	    continue;
	}
	if ( address > usr_mem_range[n].low && address < usr_mem_range[n].upper ) {
	    return TRUE;
	}
    }
	Address is not in any allowed usr_range
    return FALSE;
}
static int in_allowed_exe = FALSE;
int void in_src_range(struct vm_area_struct *vma, unsigned long address)
{
    int n;
    
    
    for ( n = src_ranges; n > 0; n--) {
	if (! src_mem_range[n].enabled) {
	    continue;
	}
	if ( address > src_mem_range[n].low && address < src_mem_range[n].upper ) {
	    in_allowed_exe = TRUE;
	    return TRUE;
	}
    }
    Address is not in any allowed src_range
    in_allowed_exe = FALSE;
    return FALSE;
}

int allow_access(struct vm_area_struct *vma, unsigned long address){
   
    if (active_src_ranges == 0 ){
	    return ALLOW;
    }
    if ( (vma->vm_flags == VM_EXEC) || (vm_flags == VM_EXECUTABLE) && 
	( ! in_active_range( vma, address) ) {
	    return ALLOW;
    }
    else {
	// Check usr addrses
	if ( ! in_allowed_exe ) {
	    return ALLOW;
	}
	if ( in_usr_range( vma, address) ) {
	    return ALLOW;
	}
    }
    return DENY;
}
int hook_page_fault(struct vm_area_struct *vma, unsigned long address, unsigned  int flags) 
{
//     int irgflags;

    if ( current->pid != checked_pid) {
	jprobe_return();
	return 0;
    }
    if (current->ptrace) {
	send_sig(SIGIO, current, 1);
    }
    if ( ( memcmp(current->comm, "a.out", 5)) == 0) 
    {
	
	printk("Address passed to page_fault =%p\n", (void *)address);
	if ( ! allow_access(vma, address) ) {
	//if (vma->vm_start <= usr_low && vma->vm_end < usr_upper)
	{
	  send_sig(SIGILL, current, 1);
	}
	
    }
     jprobe_return();
    return 0;
}


static struct jprobe mm_fault_jprobe = {
    .entry = hook_page_fault,
    .kp = {
	.symbol_name	= "handle_mm_fault",
    },
};






static void **syscall_table;

asmlinkage 
long (*mmap2)(unsigned long addr, unsigned long len,
                        unsigned long prot, unsigned long flags,
                        unsigned long fd, unsigned long pgoff);
asmlinkage 
long my_mmap2(unsigned long addr, unsigned long len,
                        unsigned long prot, unsigned long flags,
                        unsigned long fd, unsigned long pgoff)
{
  long ret, rc;
  struct vm_area_struct * vma;
 
  ret = mmap2(addr, len, prot, flags, fd, pgoff);
  if (  (memcmp(current->comm, "a.out", 5)) == 0) {
   
    printk (KERN_DEBUG "MY  MMAP len=%d, ret=0x%lx, command=%s\n", (int)len,  ret, current->comm);
    
	
	
	checked_pid = current->pid;
	
     
  }
  return ret;

}


static int __init monvm_init(void)
{
    int ret;
    
    
    ret = register_jprobe(&mm_fault_jprobe);
    if (ret < 0) {
	pr_err(KERN_INFO "register_jprobe failed, returned %d\n", ret);
	return -1;
    }
    pr_info("Planted jprobe at %p, handler addr %p\n",
	    mm_fault_jprobe.kp.addr, mm_fault_jprobe.entry);
    
    syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        printk("Cannot find the system call table virt address\n");
        return -1;
    }
    mmap2 = syscall_table[__NR_mmap];
    printk (KERN_DEBUG " mmap2 address=%p\n", mmap2 );
    ret = set_addr_rw((unsigned long)syscall_table);


    if (! ret) {
        printk(KERN_DEBUG "Cannot set the syscall_table to rw at %p, rc=%d\n", 
syscall_table, ret);
    } else {
        printk(KERN_DEBUG "Page of syscall_table  at %p set to rw, rc=%d\n", 
syscall_table, ret );
    }

    syscall_table[__NR_mmap] = my_mmap2; 

    return 0;
}

static void __exit monvm_release(void)
{
    int ret;
    
    
    syscall_table[__NR_mmap] = mmap2;
    ret = set_addr_ro((unsigned long)syscall_table);
    unregister_jprobe(&mm_fault_jprobe);
  

    
 
   //printk(KERN_DEBUG "stopping monitor thread pid=%d\n", mon_thread->pid);
   //kthread_stop(mon_thread);
    
}
module_init(monvm_init);
module_exit(monvm_release);