#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chinmay_dd");
MODULE_DESCRIPTION("Something cool");

struct task_struct *g, *p;
const char *DATA_PATH = "/home/chinmay_dd/Projects/malware/data.txt";

// Opening a file
struct file* file_open(const char* path, int flags, int rights) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

// Closing a file
void file_close(struct file* file) {
    filp_close(file, NULL);
}

// Reading data from a file
int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

// Writing data to a file
int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

// Syncing changes to a file
int file_sync(struct file* file) {
    vfs_fsync(file, 0);
    return 0;
}

static int __init hello_init(void)
{
    // char userprog[] = "/home/chinmay_dd/Projects/malware/test_files/test2";
    // char *argv[] = {userprog, "2", NULL};
    // char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin/:/usr/bin", NULL};

    // int ret = call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    // printk(KERN_INFO "Return value of the helper: %d\n", ret);

    for_each_process(p) {
      if (strcmp(p->comm, "vim") == 0) {
        struct file *data = file_open(DATA_PATH, O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        // Collect data for the particular process.
        // fpu_counter was removed from task_struct since it was arch-specific
        // Dont know what to do with this
        // char page_table_lock[8];
        char map_count[8];
        char hiwater_rss[8];
        char hiwater_vm[8];
        char total_vm[8];
        char exec_vm[8];
        char shared_vm[8];
        char nr_ptes[8];
        char utime[8];
        char stime[8];
        char nvcsw[8];
        char nivcsw[8];
        char min_flt[8];
        // char alloc_lock[8];
        // char count[8];
        
        file_write (data, 0, p->comm, sizeof (p->comm));
        
        snprintf (map_count, sizeof (map_count), ",%d,", p->active_mm->map_count);
        file_write (data, 0, map_count, sizeof (map_count));

        snprintf (hiwater_rss, sizeof (hiwater_rss), "%ld,", p->active_mm->hiwater_rss);
        file_write (data, 0, hiwater_rss, sizeof (hiwater_rss));

        snprintf (hiwater_vm, sizeof (hiwater_vm), "%ld,", p->active_mm->hiwater_vm);
        file_write (data, 0, hiwater_vm, sizeof (hiwater_vm));

        snprintf (total_vm, sizeof (total_vm), "%ld,", p->active_mm->total_vm);
        file_write (data, 0, total_vm, sizeof (total_vm));

        snprintf (exec_vm, sizeof (exec_vm), "%ld,", p->active_mm->exec_vm);
        file_write (data, 0, exec_vm, sizeof (exec_vm));

        snprintf (shared_vm, sizeof (shared_vm), "%ld,", p->active_mm->shared_vm);
        file_write (data, 0, shared_vm, sizeof (shared_vm));

        snprintf (nr_ptes, sizeof (nr_ptes), "%ld,", p->active_mm->nr_ptes);
        file_write (data, 0, nr_ptes, sizeof (nr_ptes));

        snprintf (utime, sizeof (utime), "%ld,", (long)p->utime);
        file_write (data, 0, utime, sizeof (utime));

        snprintf (stime, sizeof (stime), "%ld,", (long)p->stime);
        file_write (data, 0, stime, sizeof (stime));
        
        snprintf (nvcsw, sizeof (nvcsw), "%ld,", (long)p->nvcsw);
        file_write (data, 0, nvcsw, sizeof (nvcsw));
        
        snprintf (nivcsw, sizeof (nivcsw), "%ld,", (long)p->nivcsw);
        file_write (data, 0, nivcsw, sizeof (nivcsw));
        
        snprintf (min_flt, sizeof (min_flt), "%ld,", (long)p->min_flt);
        file_write (data, 0, min_flt, sizeof (min_flt));

        // snprintf (alloc_lock, sizeof (alloc_lock), "%ld", (long)p->alloc_lock.x);
        // file_write (data, 0, alloc_lock, sizeof (alloc_lock));
        
        // snprintf (count, sizeof(count), "%ld,", (long)p->fs->users);
        // file_write (data, 0, count, sizeof (count)); 
      }
    }
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}

module_init(hello_init);
module_exit(hello_cleanup);
