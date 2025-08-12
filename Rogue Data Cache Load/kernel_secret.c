// kernel_secret.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_NAME "kernel_secret"
#define DEFAULT_SECRET "Kernel_Secret_String_1234567890"

static char *secret = DEFAULT_SECRET;
module_param(secret, charp, 0444);
MODULE_PARM_DESC(secret, "Secret string to place in kernel memory");

static char *buf_page = NULL;
static struct proc_dir_entry *proc_entry;

/* proc read: return address and content */
static ssize_t proc_read(struct file *file, char __user *user_buf,
                         size_t count, loff_t *ppos)
{
    char kbuf[256];
    int len;

    if (*ppos > 0)
        return 0; /* EOF for simple single-read */

    /* print pointer as numeric value (hex) and the stored string */
    len = snprintf(kbuf, sizeof(kbuf),
                   "addr=0x%lx\ncontent=%s\n",
                   (unsigned long)buf_page,
                   buf_page ? buf_page : "(null)");

    if (len < 0)
        return -EFAULT;

    if (count < (size_t)len)
        return -EINVAL;

    if (copy_to_user(user_buf, kbuf, len))
        return -EFAULT;

    *ppos = len;
    return len;
}

static const struct proc_ops proc_file_ops = {
    .proc_read = proc_read,
};

static int __init ks_init(void)
{
    pr_info("kernel_secret: init\n");

    /* allocate one PAGE (GFP_KERNEL) and populate with secret */
    buf_page = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf_page) {
        pr_err("kernel_secret: kmalloc failed\n");
        return -ENOMEM;
    }

    memset(buf_page, 0, PAGE_SIZE);
    strncpy(buf_page, secret, PAGE_SIZE - 1);

    /* optional: print to dmesg (may be filtered by kptr_restrict) */
    pr_info("kernel_secret: stored secret at %p (content: %.32s...)\n",
            buf_page, buf_page);

    /* create /proc entry */
    proc_entry = proc_create(PROC_NAME, 0444, NULL, &proc_file_ops);
    if (!proc_entry) {
        pr_err("kernel_secret: proc_create failed\n");
        kfree(buf_page);
        buf_page = NULL;
        return -ENOMEM;
    }

    pr_info("kernel_secret: /proc/%s ready\n", PROC_NAME);
    return 0;
}

static void __exit ks_exit(void)
{
    pr_info("kernel_secret: exit\n");

    if (proc_entry)
        proc_remove(proc_entry);

    if (buf_page) {
        /* wipe before free (defensive) */
        memset(buf_page, 0, PAGE_SIZE);
        kfree(buf_page);
        buf_page = NULL;
    }
}

module_init(ks_init);
module_exit(ks_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("assistant");
MODULE_DESCRIPTION("Place a known string in kernel memory and expose address via /proc");
