#include <stdint.h>

int main(void) {
    const uint64_t source = 1;
    uint64_t blsi_result;
    uint64_t blsr_result;
    unsigned char blsi_carry;
    unsigned char blsr_carry;

    __asm__ volatile(
        ".global focaccia_trace_start\n"
        "focaccia_trace_start:\n\t"
        "blsiq %[source], %[result]\n\t"
        "setc %[carry]\n\t"
        : [result] "=r"(blsi_result), [carry] "=qm"(blsi_carry)
        : [source] "r"(source)
        : "cc");

    __asm__ volatile(
        "blsrq %[source], %[result]\n\t"
        "setc %[carry]\n\t"
        ".global focaccia_trace_stop\n"
        "focaccia_trace_stop:\n"
        : [result] "=r"(blsr_result), [carry] "=qm"(blsr_carry)
        : [source] "r"(source)
        : "cc");

    return blsi_result == 1 && blsi_carry == 1 && blsr_result == 0 &&
                   blsr_carry == 0
               ? 0
               : 1;
}
