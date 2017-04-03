// callmodule.c with pid, url: http://stackoverflow.com/questions/21668727/

#include <linux/module.h>
#include <linux/slab.h> //kzalloc
#include <linux/syscalls.h> // SIGCHLD, ... sys_wait4, ...
#include <linux/kallsyms.h> // kallsyms_lookup, print_symbol
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/kernel.h>

// global variable - to avoid intervening too much in the return of call_usermodehelperB:
static int callmodule_pid;

// >>>>>>>>>>>>>>>>>>>>>>

// modified kernel functions - taken from
// http://lxr.missinglinkelectronics.com/linux+v2.6.38/+save=include/linux/kmod.h
// http://lxr.linux.no/linux+v2.6.38/+save=kernel/kmod.c

// define a modified struct (with extra pid field) here:
struct subprocess_infoB {
    struct work_struct work;
    struct completion *complete;
    char *path;
    char **argv;
    char **envp;
    int wait; //enum umh_wait wait;
    int retval;
    int (*init)(struct subprocess_info *info);
    void (*cleanup)(struct subprocess_info *info);
    void *data;
  pid_t pid;
};

// forward declare:
struct subprocess_infoB *call_usermodehelper_setupB(char *path, char **argv,
                          char **envp, gfp_t gfp_mask);

static inline int
call_usermodehelper_fnsB(char *path, char **argv, char **envp,
            int wait, //enum umh_wait wait,
            int (*init)(struct subprocess_info *info),
            void (*cleanup)(struct subprocess_info *), void *data)
{
    struct subprocess_info *info;
    struct subprocess_infoB *infoB;
    gfp_t gfp_mask = (wait == UMH_NO_WAIT) ? GFP_ATOMIC : GFP_KERNEL;
  int ret;

  populate_rootfs_wait(); // is in linux-headers-2.6.38-16-generic/include/linux/kmod.h

    infoB = call_usermodehelper_setupB(path, argv, envp, gfp_mask);
  printk(KBUILD_MODNAME ":a: pid %d\n", infoB->pid);
  info = (struct subprocess_info *) infoB;

    if (info == NULL)
        return -ENOMEM;

    call_usermodehelper_setfns(info, init, cleanup, data);
  printk(KBUILD_MODNAME ":b: pid %d\n", infoB->pid);

  // this must be called first, before infoB->pid is populated (by __call_usermodehelperB):
  ret = call_usermodehelper_exec(info, wait);

  // assign global pid here, so rest of the code has it:
  callmodule_pid = infoB->pid;
  printk(KBUILD_MODNAME ":c: pid %d\n", callmodule_pid);

    return ret;
}

static inline int
call_usermodehelperB(char *path, char **argv, char **envp, int wait) //enum umh_wait wait)
{
    return call_usermodehelper_fnsB(path, argv, envp, wait,
                       NULL, NULL, NULL);
}

/* This is run by khelper thread  */
static void __call_usermodehelperB(struct work_struct *work)
{
    struct subprocess_infoB *sub_infoB =
        container_of(work, struct subprocess_infoB, work);
    int wait = sub_infoB->wait; // enum umh_wait wait = sub_info->wait;
    pid_t pid;
    struct subprocess_info *sub_info;
  // hack - declare function pointers, to use for wait_for_helper/____call_usermodehelper
  int (*ptrwait_for_helper)(void *data);
  int (*ptr____call_usermodehelper)(void *data);
  // assign function pointers to verbatim addresses as obtained from /proc/kallsyms
  ptrwait_for_helper = (void *)0xffffffff81082390;
  ptr____call_usermodehelper = (void *)0xffffffff81082ae0;

  sub_info = (struct subprocess_info *)sub_infoB;

    /* CLONE_VFORK: wait until the usermode helper has execve'd
     * successfully We need the data structures to stay around
     * until that is done.  */
    if (wait == UMH_WAIT_PROC)
        pid = kernel_thread((*ptrwait_for_helper), sub_info, //(wait_for_helper, sub_info,
                    CLONE_FS | CLONE_FILES | SIGCHLD);
    else
        pid = kernel_thread((*ptr____call_usermodehelper), sub_info, //(____call_usermodehelper, sub_info,
                    CLONE_VFORK | SIGCHLD);

  printk(KBUILD_MODNAME ": : pid %d\n", pid);
  // grab and save the pid here:
  sub_infoB->pid = pid;
    switch (wait) {
    case UMH_NO_WAIT:
        call_usermodehelper_freeinfo(sub_info);
        break;

    case UMH_WAIT_PROC:
        if (pid > 0)
            break;
        /* FALLTHROUGH */
    case UMH_WAIT_EXEC:
        if (pid < 0)
            sub_info->retval = pid;
        complete(sub_info->complete);
    }
}

/**
 * call_usermodehelper_setup - prepare to call a usermode helper
 */
struct subprocess_infoB *call_usermodehelper_setupB(char *path, char **argv,
                          char **envp, gfp_t gfp_mask)
{
    struct subprocess_infoB *sub_infoB;
    sub_infoB = kzalloc(sizeof(struct subprocess_infoB), gfp_mask);
    if (!sub_infoB)
        goto out;

    INIT_WORK(&sub_infoB->work, __call_usermodehelperB);
    sub_infoB->path = path;
    sub_infoB->argv = argv;
    sub_infoB->envp = envp;
  out:
    return sub_infoB;
}

// <<<<<<<<<<<<<<<<<<<<<<

static int __init callmodule_init(void)
{
    int ret = 0;
  char userprog[] = "/home/chinmay_dd/Projects/newproj/test";
    char *argv[] = {userprog, "2", NULL };
    char *envp[] = {"HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
  struct task_struct *p;
  struct task_struct *par;
  struct task_struct *pc;
  struct list_head *children_list_head;
  struct list_head *cchildren_list_head;
  char *state_str;

    printk(KBUILD_MODNAME ": > init %s\n", userprog);
    /* last parameter: 1 -> wait until execution has finished, 0 go ahead without waiting*/
    /* returns 0 if usermode process was started successfully, errorvalue otherwise*/
    /* no possiblity to get return value of usermode process*/
  // note - only one argument allowed for print_symbol
  print_symbol(KBUILD_MODNAME ": symbol @ 0xffffffff81082390 is %s\n", 0xffffffff81082390); // shows wait_for_helper+0x0/0xb0
  print_symbol(KBUILD_MODNAME ": symbol @ 0xffffffff81082ae0 is %s\n", 0xffffffff81082ae0); // shows ____call_usermodehelper+0x0/0x90
    ret = call_usermodehelperB(userprog, argv, envp, UMH_WAIT_EXEC);
    if (ret != 0)
        printk(KBUILD_MODNAME ": error in call to usermodehelper: %i\n", ret);
    else
        printk(KBUILD_MODNAME ": everything all right; pid %d\n", callmodule_pid);
  // find the task:
  // note: sometimes p may end up being NULL here, causing kernel oops -
  // just exit prematurely in that case
  rcu_read_lock();
  p = pid_task(find_vpid(callmodule_pid), PIDTYPE_PID);
  rcu_read_unlock();
  if (p == NULL) {
    printk(KBUILD_MODNAME ": p is NULL - exiting\n");
    return 0;
  }
  // p->comm should be the command/program name (as per userprog)
  // (out here that task is typically in runnable state)
  state_str = (p->state==-1)?"unrunnable":((p->state==0)?"runnable":"stopped");
  printk(KBUILD_MODNAME ": pid task a: %p c: %s p: [%d] s: %s\n",
    p, p->comm, p->pid, state_str);

  // find parent task:
  // parent task could typically be: c: kworker/u:1 p: [14] s: stopped
  par = p->parent;
  if (par == NULL) {
    printk(KBUILD_MODNAME ": par is NULL - exiting\n");
    return 0;
  }
  state_str = (par->state==-1)?"unrunnable":((par->state==0)?"runnable":"stopped");
  printk(KBUILD_MODNAME ": parent task a: %p c: %s p: [%d] s: %s\n",
    par, par->comm, par->pid, state_str);

  // iterate through parent's (and our task's) child processes:
  rcu_read_lock(); // read_lock(&tasklist_lock);
  list_for_each(children_list_head, &par->children){
    p = list_entry(children_list_head, struct task_struct, sibling);
    printk(KBUILD_MODNAME ": - %s [%d] \n", p->comm, p->pid);
    // note: trying to print "%p",p here results with oops/segfault:
    // printk(KBUILD_MODNAME ": - %s [%d] %p\n", p->comm, p->pid, p);
    if (p->pid == callmodule_pid) {
      list_for_each(cchildren_list_head, &p->children){
        pc = list_entry(cchildren_list_head, struct task_struct, sibling);
        printk(KBUILD_MODNAME ": - - %s [%d] \n", pc->comm, pc->pid);
      }
    }
  }
  rcu_read_unlock(); //~ read_unlock(&tasklist_lock);

  return 0;
}

static void __exit callmodule_exit(void)
{
    printk(KBUILD_MODNAME ": < exit\n");
}

module_init(callmodule_init);
module_exit(callmodule_exit);
MODULE_LICENSE("GPL");


/*

NOTES:

  // assign function pointers to verbatim addresses as obtained from /proc/kallsyms:
  // ( cast to void* to avoid "warning: assignment makes pointer from integer without a cast",
  // see also http://stackoverflow.com/questions/3941793/what-is-guaranteed-about-the-size-of-a-function-pointer )

// $ sudo grep 'wait_for_helper\|____call_usermodehelper' /proc/kallsyms
// c1065b60 t wait_for_helper
// c1065ed0 t ____call_usermodehelper
// protos:
// static int wait_for_helper(void *data)
// static int ____call_usermodehelper(void *data)
// see also:
// http://www.linuxforu.com/2012/02/function-pointers-and-callbacks-in-c-an-odyssey/


// from include/linux/kmod.h:

//~ enum umh_wait {
    //~ UMH_NO_WAIT = -1,   * don't wait at all * 
    //~ UMH_WAIT_EXEC = 0,  * wait for the exec, but not the process * 
    //~ UMH_WAIT_PROC = 1,  * wait for the process to complete * 
//~ };

// however, note:
// /usr/src/linux-headers-2.6.38-16-generic/include/linux/kmod.h:
// #define UMH_NO_WAIT  0 ; UMH_WAIT_EXEC   1 ; UMH_WAIT_PROC   2 ; UMH_KILLABLE    4 !
// those defines end up here, regardless of the enum definition above
// (NB: 0,1,2,4 enumeration starts from kmod.h?v=3.4 on lxr.free-electrons.com !)
// also, note, in "generic" include/, prototypes of call_usermodehelper(_fns)
// use int wait, and not enum umh_wait wait ...

// seems these cannot be used from a module, nonetheless:
//~ extern int wait_for_helper(void *data);
//~ extern int ____call_usermodehelper(void *data);
// we probably would have to (via http://www.linuxconsulting.ro/pidwatcher/)
// edit /usr/src/linux/kernel/ksyms.c and add:
//EXPORT_SYMBOL(wait_for_helper);
// but that is kernel re-compilation...

// http://stackoverflow.com/questions/19360298/triggering-user-space-with-kernel
// You should not be using PIDs to identify processes within the kernel. The process can exit and a different process re-use that PID. Instead, you should be using a pointer to the task_struct for the process (rather than storing current->pid at registration time, just store current)

# reports task name from the pid (pid_task(find_get_pid(..)):
http://tuxthink.blogspot.dk/2012/07/module-to-find-task-from-its-pid.html

  // find the task:
    //~ rcu_read_lock();
  // uprobes uses this - but find_task_by_pid is not exported for modules:
    //~ p = find_task_by_pid(callmodule_pid);
    //~ if (p)
        //~ get_task_struct(p);
    //~ rcu_read_unlock();
  // see: [http://www.gossamer-threads.com/lists/linux/kernel/1260996 find_task_by_pid() problem | Linux | Kernel]

  // http://stackoverflow.com/questions/18408766/make-a-system-call-to-get-list-of-processes
  // this macro loops through *all* processes; our callmodule_pid should be listed by it
  //~ for_each_process(p)
    //~ pr_info("%s [%d]\n", p->comm, p->pid);

  // [https://lists.debian.org/debian-devel/2008/05/msg00034.html Re: problems for making kernel module]
  // note - WARNING: "tasklist_lock" ... undefined; because tasklist_lock removed in 2.6.1*:
  // "tasklist_lock protects the kernel internal task list.  Modules have no business looking at it";
  // http://stackoverflow.com/questions/13002444/list-all-threads-within-the-current-process
  // "all methods that loop over the task lists need to be wrapped in rcu_read_lock(); / rcu_read_unlock(); to be correct."
  // http://stackoverflow.com/questions/19208487/kernel-module-that-iterates-over-all-tasks-using-depth-first-tree
  // http://stackoverflow.com/questions/5728592/how-can-i-get-the-children-process-list-in-kernel-code
  // http://stackoverflow.com/questions/1446239/traversing-task-struct-children-in-linux-kernel
  // http://stackoverflow.com/questions/8207160/kernel-how-to-iterate-the-children-of-the-current-process
  // http://stackoverflow.com/questions/10262017/linux-kernel-list-list-head-init-vs-init-list-head
  // http://stackoverflow.com/questions/16230524/explain-list-for-each-entry-and-list-for-each-entry-safe "list_entry is just an alias for container_of"

*/
