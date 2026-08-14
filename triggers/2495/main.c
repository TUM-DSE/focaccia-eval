#include <stdint.h>

static const uint8_t input_r8[8] = {0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t input_mm0[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t output_r8[8];

int main(void) {
    __asm__ volatile(
        "movq (%[input_r8]), %%r8\n\t"
        "movq (%[input_mm0]), %%mm0\n\t"
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        ".byte 0x4f, 0x0f, 0x7e, 0xc0\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n\t"
        "movq %%r8, (%[output_r8])\n\t"
        "emms\n\t"
        :
        : [input_r8] "r"(input_r8), [input_mm0] "r"(input_mm0),
          [output_r8] "r"(output_r8)
        : "r8", "memory", "mm0");

    for (unsigned int index = 0; index < sizeof(output_r8); ++index) {
        if (output_r8[index] != 0xff) {
            return 1;
        }
    }
    return 0;
}
