#include <stdio.h>
#include <stdint.h>
#include <stdlib.h> // For malloc/free
#include <x86intrin.h> // For __rdtscp() and __rdtsc()

#define ARRAY_SIZE 1024 * 1024 * 16   // 16 MB
#define CACHE_LINE_SIZE 64           // Typical cache line size in bytes
#define TEST_ITERATIONS 10000        // Number of iterations for measuring

// Function to calculate statistics
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

int main() {
    // Allocate a large array to perform memory access tests
    volatile char *array = (volatile char *)malloc(ARRAY_SIZE);
    if (array == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    // Initialize the array to ensure it is loaded into memory
    for (uint64_t i = 0; i < ARRAY_SIZE; i++) {
        array[i] = (char)i;
    }

    // Variables to hold timing results
    unsigned int aux;
    uint64_t start_cycles, end_cycles;
    volatile char temp; // To prevent compiler optimization
    uint64_t hit_times[TEST_ITERATIONS]; // Cache hit times
    uint64_t miss_times[TEST_ITERATIONS]; // Cache miss times

    // Measure cache hit time multiple times
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        start_cycles = __rdtscp(&aux); // Start reading the timestamp
        temp = array[0];               // Access memory (cache hit expected)
        end_cycles = __rdtscp(&aux);   // End reading the timestamp
        hit_times[i] = end_cycles - start_cycles; // Record the time
    }

    // Measure cache miss time multiple times
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        start_cycles = __rdtscp(&aux); // Start reading the timestamp
        for (uint64_t j = 0; j < ARRAY_SIZE; j += CACHE_LINE_SIZE * 1024) {
            temp = array[j];           // Access sparse memory locations (cache miss expected)
        }
        end_cycles = __rdtscp(&aux);   // End reading the timestamp
        miss_times[i] = end_cycles - start_cycles; // Record the time
    }

    // Calculate statistics for cache hit
    uint64_t hit_min, hit_max;
    double hit_avg;
    calculate_statistics(hit_times, TEST_ITERATIONS, &hit_min, &hit_max, &hit_avg);

    // Calculate statistics for cache miss
    uint64_t miss_min, miss_max;
    double miss_avg;
    calculate_statistics(miss_times, TEST_ITERATIONS, &miss_min, &miss_max, &miss_avg);

    // Print results
    printf("Cache hit statistics:\n");
    printf("  Min time: %llu cycles\n", hit_min);
    printf("  Avg time: %f cycles\n", hit_avg);
    printf("  Max time: %llu cycles\n", hit_max);


    printf("Cache miss statistics:\n");
    printf("  Min time: %llu cycles\n", miss_min);
    printf("  Avg time: %f cycles\n", miss_avg);
    printf("  Max time: %llu cycles\n", miss_max);
    

    // Free allocated memory
    free((void *)array);

    return 0;
}
