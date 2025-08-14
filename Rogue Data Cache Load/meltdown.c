#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static char *secret_string = "MELTDOWN_TEST_123\n";  // 测试字符串
static char *buf;  // 缓冲区存放字符串
static unsigned long buf_addr;  // 缓存区地址

// 模块初始化
static int __init meltdown_init(void)
{
    // 分配一页内存，写入我们的字符串
    buf = kmalloc(4096, GFP_KERNEL);  // 分配 4KB 内存
    if (!buf) {
        pr_err("Failed to allocate memory for the string.\n");
        return -ENOMEM;
    }

    // 写入字符串
    strncpy(buf, secret_string, strlen(secret_string));

    // 获取分配内存的地址
    buf_addr = (unsigned long)buf;

    pr_info("Secret string address: 0x%lx\n", buf_addr);  // 打印地址

    return 0;
}

// 模块卸载
static void __exit meltdown_exit(void)
{
    pr_info("Cleaning up...\n");
    kfree(buf);  // 释放内存
}

module_init(meltdown_init);
module_exit(meltdown_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple kernel module for Meltdown PoC.");
