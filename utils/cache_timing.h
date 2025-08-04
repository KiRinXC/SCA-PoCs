#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>    // 用于 malloc/free
#include <x86intrin.h> 
#include "./cache_instr.h"


#define ARRAY_SIZE 1024 * 1024 * 16   // 数组大小：16 MB
#define CACHE_LINE_SIZE 64            // 典型缓存行大小（字节）
#define TEST_ITERATIONS 10000         // 测量迭代次数

// 计算统计信息（最小值、最大值、平均值）
void calculate_statistics(uint64_t *times, int count, uint64_t *min, uint64_t *max, double *avg) {
    *min = times[0];
    *max = times[0];
    uint64_t sum = 0;

    for (int i = 0; i < count; i++) {
        if (times[i] < *min) *min = times[i];
        if (times[i] > *max) *max = times[i];
        sum += times[i];
    }

    *avg = (double)sum / count;
}

int detect_flush_reload_threshold() {
    // 分配一个大数组，用于内存访问测试
    char *array = (char *)malloc(ARRAY_SIZE);
    if (array == NULL) {
        printf("内存分配失败\n");
        return 1;
    }

    // 初始化数组，确保数据加载到内存中
    for (uint64_t i = 0; i < ARRAY_SIZE; i++) {
        array[i] = (char)i;
    }

    // 计时相关变量
    unsigned int aux;
    uint64_t start_cycles, end_cycles;

    uint64_t hit_times[TEST_ITERATIONS];  // 缓存命中的时间
    uint64_t miss_times[TEST_ITERATIONS]; // 缓存未命中的时间

    // 多次测量缓存命中时间
    for (int i = 0; i < TEST_ITERATIONS; i++) {

        start_cycles = rdtscp();   // 开始计时

        maccess(&array[0]);

        end_cycles = rdtscp();     // 结束计时

        hit_times[i] = end_cycles - start_cycles; // 记录时间差
    }

    // 多次测量缓存未命中时间
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        flush((void *)&array[0]);       // 强制刷新缓存行（模拟未命中）

        start_cycles = rdtscp();        // 开始计时

        maccess(&array[0]);             // 访问内存（预期缓存未命中）

        end_cycles = rdtscp();          // 结束计时

        miss_times[i] = end_cycles - start_cycles; // 记录时间差
    }

    // 计算缓存命中的统计信息
    uint64_t hit_min, hit_max;
    double hit_avg;
    calculate_statistics(hit_times, TEST_ITERATIONS, &hit_min, &hit_max, &hit_avg);

    // 计算缓存未命中的统计信息
    uint64_t miss_min, miss_max;
    double miss_avg;
    calculate_statistics(miss_times, TEST_ITERATIONS, &miss_min, &miss_max, &miss_avg);

    // 打印结果
    printf("缓存命中统计信息：\n");
    printf("  最小时间：%llu 周期\n", hit_min);
    printf("  平均时间：%f 周期\n", hit_avg);
    printf("  最大时间：%llu 周期\n", hit_max);

    printf("缓存未命中统计信息：\n");
    printf("  最小时间：%llu 周期\n", miss_min);
    printf("  平均时间：%f 周期\n", miss_avg);
    printf("  最大时间：%llu 周期\n", miss_max);

    // 释放分配的内存
    free((void *)array);

    return hit_avg;  //返回阈值
}
