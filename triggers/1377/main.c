#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return 2;
    }

    unsigned char *mapping = mmap(
        NULL,
        (size_t)page_size * 2,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    if (mapping == MAP_FAILED) {
        return 2;
    }

    float *source = (float *)(mapping + page_size - (long)(2 * sizeof(float)));
    source[0] = 1.5f;
    source[1] = -2.25f;
    if (mprotect(mapping + page_size, (size_t)page_size, PROT_NONE) != 0) {
        return 2;
    }

    double destination[2];
    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "cvtps2pd (%[source]), %%xmm0\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n\t"
        "movupd %%xmm0, (%[destination])\n\t"
        :
        : [source] "r"(source), [destination] "r"(destination)
        : "xmm0", "memory");

    return destination[0] == 1.5 && destination[1] == -2.25 ? 0 : 1;
}
