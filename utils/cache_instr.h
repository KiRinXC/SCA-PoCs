#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <x86intrin.h>


/*内联汇编的写法*/
void maccess(void *p) { __asm__ volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }
void flush(void *p){ __asm__ volatile("clflush 0(%0)\n" : : "c"(p) : "rax");}
void mfence() { __asm__ volatile("mfence"); }
uint64_t rdtscp()
{
    uint64_t a, d;
    mfence();
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
      a = (d << 32) | a;
    mfence();
    return a;
}


/*一般写法*/
// void maccess(void *p) { volatile char val = *(volatile char *)p;}
// void flush(void *p) { _mm_clflush(p);}
// void mfence() { _mm_mfence();}
// uint64_t rdtscp()
// {
//     unsigned int aux;
//     mfence();
//     uint64_t point = _rdtscp(&aux);
//     mfence();
//     return point;
// }


