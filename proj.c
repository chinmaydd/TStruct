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
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chinmay_dd");
MODULE_DESCRIPTION("Collect task_struct data for processes in the linux kernel for fun and research");

static char *DATA_PATH = "/home/krypt0/MalwareAnalysis/data/0000.txt";
static char *ELF_PATH = "/home/krypt0/MalwareAnalysis/elfs/0000";
static char *PROC_NAME = "0000";

module_param(DATA_PATH, charp, 0);
module_param(ELF_PATH, charp, 0);
module_param(PROC_NAME, charp, 0);

MODULE_PARM_DESC(DATA_PATH, "Used to provide file path for data to be written into it");
MODULE_PARM_DESC(ELF_PATH, "Used to provide file path for the elf to be tested");
MODULE_PARM_DESC(PROC_NAME, "USed to provide the process name which needs to be tracked.");

struct task_struct *g, *p;

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
    // char userprog[] = "/home/krypt0/MalwareAnalysis/elfs/0000";
    char *argv[] = {ELF_PATH, NULL};
    char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin/:/bin:/usr/bin", NULL};

    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

    // MAKE WAY FOR SOME NEXT LEVEL MAGIC
    // 1337 HAXXXXX
    msleep(1);
    // 1337 HAXXXXX
    
    struct file *data = file_open (DATA_PATH, O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    
    if (ret!=0) {
      printk("Error in helper.\n");
      return 0;
    } else {
      printk("It's all coming together.\n");
    }

    for_each_process(p) {
      if (strcmp(p->comm, PROC_NAME) == 0) {
        // printk(KERN_INFO "FOUND IT");
        // Collect data for the particular process.
        // fpu_counter was removed from task_struct since it was arch-specific
        // Dont know what to do with this
        // char page_table_lock[8];
        char map_count[8] = "";
        char hiwater_rss[8] = "";
        char hiwater_vm[8] = "";
        char total_vm[8] = "";
        char exec_vm[8] = "";
        char shared_vm[8] = "";
        char nr_ptes[8] = "";
        char utime[8] = "";
        char stime[8] = "";
        char nvcsw[8] = "";
        char nivcsw[8] = "";
        char min_flt[8] = "";
        // char alloc_lock[8];
        // char count[8];
        int i = 0; 
        long int pos = 0;

        while (i < 1000) {
          if (!(pid_alive (p))) {
              break;
          }

          i += 1;

          if (p->active_mm == NULL) {
              return 0;
          }
        
          snprintf (map_count, sizeof (map_count), "%d,", p->active_mm->map_count);
          file_write (data, pos, map_count, sizeof (map_count));
          pos = pos + 1 + sizeof (map_count);

          snprintf (hiwater_rss, sizeof (hiwater_rss), "%lu,", p->active_mm->hiwater_rss);
          file_write (data, pos, hiwater_rss, sizeof (hiwater_rss));
          pos = pos + 1 + sizeof (hiwater_rss);

          snprintf (hiwater_vm, sizeof (hiwater_vm), "%lu,", p->active_mm->hiwater_vm);
          file_write (data, pos, hiwater_vm, sizeof (hiwater_vm));
          pos = pos + 1 + sizeof (hiwater_vm);

          snprintf (total_vm, sizeof (total_vm), "%ld,", p->active_mm->total_vm);
          file_write (data, pos, total_vm, sizeof (total_vm));
          pos = pos + 1 + sizeof (total_vm);

          snprintf (exec_vm, sizeof (exec_vm), "%ld,", p->active_mm->exec_vm);
          file_write (data, pos, exec_vm, sizeof (exec_vm));
          pos = pos + 1 + sizeof (exec_vm);

          snprintf (shared_vm, sizeof (shared_vm), "%ld,", p->active_mm->shared_vm);
          file_write (data, pos, shared_vm, sizeof (shared_vm));
          pos = pos + 1 + sizeof (shared_vm);

          snprintf (nr_ptes, sizeof (nr_ptes), "%ld,", p->active_mm->nr_ptes);
          file_write (data, pos, nr_ptes, sizeof (nr_ptes));
          pos = pos + 1 + sizeof (nr_ptes);

          snprintf (utime, sizeof (utime), "%ld,", (long)p->utime);
          file_write (data, pos, utime, sizeof (utime));
          pos = pos + 1 + sizeof (utime);

          snprintf (stime, sizeof (stime), "%ld,", (long)p->stime);
          file_write (data, pos, stime, sizeof (stime));
          pos = pos + 1 + sizeof (stime);
          
          snprintf (nvcsw, sizeof (nvcsw), "%ld,", (long)p->nvcsw);
          file_write (data, pos, nvcsw, sizeof (nvcsw));
          pos = pos + 1 + sizeof (nvcsw);
          
          snprintf (nivcsw, sizeof (nivcsw), "%ld,", (long)p->nivcsw);
          file_write (data, pos, nivcsw, sizeof (nivcsw));
          pos = pos + 1 + sizeof (nivcsw);
          
          snprintf (min_flt, sizeof (min_flt), "%ld\n", (long)p->min_flt);
          file_write (data, pos, min_flt, sizeof (min_flt));
          pos = pos + 1 + sizeof (min_flt);

          // snprintf (alloc_lock, sizeof (alloc_lock), "%ld", (long)p->alloc_lock.x);
          // file_write (data, 0, alloc_lock, sizeof (alloc_lock));
          
          // snprintf (count, sizeof(count), "%ld,", (long)p->fs->users);
          // file_write (data, 0, count, sizeof (count)); 
        }
      }
    }
    file_close (data);
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}

module_init(hello_init);
module_exit(hello_cleanup);
