#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("chinmay_dd");
MODULE_DESCRIPTION("Malware data collection");

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
    printk(KERN_INFO "Hello world!\n");
    for_each_process(p) {
      if (strcmp(p->comm, "vim") == 0) {
        struct file *data = file_open(DATA_PATH, O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        // Write data every fucking 15 ms and gg
        char *proc_name = p->comm;
        file_write(data, 0, proc_name, 10);
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
