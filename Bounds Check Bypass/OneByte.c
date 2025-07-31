#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <x86intrin.h> /* 需要支持 rdtsc, rdtscp, clflush, mfence*/

unsigned int array_size = 16;

void victim_function(size_t x) {
    volatile int sink = 0;
    if (x < array_size) {
        sink += 1;
    } else {
        sink += 2;
    }

}

void train_branch_predictor() {
    for (int j = 1000; j >= 0; j--) {
        // 将 array1_size 赶出缓存，防止推测时其在缓存
        size_t training_x = j % array_size; // 正常访问
        _mm_lfence();
        victim_function(training_x);
    }
}

typedef struct {
    uint64_t predict;
    uint64_t mispredict;
} PredictionResult;

PredictionResult test_prediction_effectiveness(int index) {
    PredictionResult result;
    unsigned int aux;
    uint64_t start, end;
    uint64_t diff_predict, diff_mispredict;

    // _mm_clflush(&array_size); //不需要清除，否则会包含从主存中访问 array_size 的时间
    int normal_index = index % array_size; // 正常访问
    _mm_lfence(); // 确保所有内存操作完成

    start = __rdtscp(&aux);
    victim_function(normal_index); 
    end = __rdtscp(&aux);
    result.predict = end - start;
    printf("Predict hit access time: %llu cycles\n", result.predict);


    int malicious_index = ((index * 13) + 3) & 17 + 16; // 恶意访问
    _mm_lfence(); // 确保所有内存操作完成

    start = __rdtscp(&aux);
    victim_function(malicious_index); 
    end = __rdtscp(&aux);
    result.mispredict = end - start;
    printf("Mispredict access time: %llu cycles\n", result.mispredict);


    return result;
}
void calculate_statistics(uint64_t *times, int count, uint64_t *min, uint64_t *max, double *avg) {
    *min = times[0];
    *max = times[0];
    uint64_t sum = 0;

    for (int i = 0; i < count; i++) {
        if (times[i] < *min) {
            *min = times[i];
        }
        if (times[i] > *max) {
            *max = times[i];
        }
        sum += times[i];
    }

    *avg = (double)sum / count;
}


void main() {
    int epochs = 16;
    uint64_t diff_predict[epochs];
    uint64_t diff_mispredict[epochs];
    for (int i=0; i<epochs; i++)
    {
        _mm_lfence(); // 确保所有内存操作完成
        // 训练分支预测器
        train_branch_predictor();
        _mm_lfence(); // 确保所有内存操作完成
        // 测试分支预测效果
        PredictionResult r = test_prediction_effectiveness(i);
        diff_predict[i] = r.predict;
        diff_mispredict[i] = r.mispredict;
    }
    uint64_t min_predict, max_predict, min_mispredict, max_mispredict;
    double avg_predict, avg_mispredict;
    calculate_statistics(diff_predict, epochs, &min_predict, &max_predict, &avg_predict);
    calculate_statistics(diff_mispredict, epochs, &min_mispredict, &max_mispredict, &avg_mispredict);
    printf("Branch predictor statistics:\n");
    printf("  Predict hit: Min %llu, Max %llu, Avg %.2f cycles\n", 
           min_predict, max_predict, avg_predict);
    printf("  Mispredict: Min %llu, Max %llu, Avg %.2f cycles\n", 
           min_mispredict, max_mispredict, avg_mispredict);

    // train_branch_predictor();
    // _mm_lfence(); // 确保所有内存操作完成
    // test_prediction_effectiveness();

}
