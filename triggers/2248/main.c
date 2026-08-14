#include <stdint.h>

int64_t callme(uint64_t ignored0, uint64_t ignored1, int64_t a, int64_t b, int64_t shift);

int main(void) {
    return callme(0, 0, 0, 1, 2) == -1 ? 0 : 1;
}
