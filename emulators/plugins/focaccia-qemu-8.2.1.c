#include <glib.h>
#include <stddef.h>
#include <stdint.h>

#include <qemu-plugin.h>

struct qemu_plugin_compat_scoreboard {
    uint64_t instruction_address;
};

typedef struct {
    struct qemu_plugin_compat_scoreboard *score;
    size_t offset;
} qemu_plugin_compat_u64;

static struct qemu_plugin_compat_scoreboard *
qemu_plugin_compat_scoreboard_new(size_t element_size);
static void qemu_plugin_compat_scoreboard_free(
    struct qemu_plugin_compat_scoreboard *score
);
static uint64_t qemu_plugin_compat_u64_get(
    qemu_plugin_compat_u64 entry,
    unsigned int vcpu_index
);
static void qemu_plugin_compat_register_vcpu_insn_exec_cb(
    struct qemu_plugin_insn *instruction,
    qemu_plugin_vcpu_udata_cb_t callback,
    enum qemu_plugin_cb_flags flags,
    void *userdata
);
static void qemu_plugin_compat_register_vcpu_insn_exec_inline_per_vcpu(
    struct qemu_plugin_insn *instruction,
    enum qemu_plugin_op operation,
    qemu_plugin_compat_u64 entry,
    uint64_t value
);

#define qemu_plugin_scoreboard qemu_plugin_compat_scoreboard
#define qemu_plugin_u64 qemu_plugin_compat_u64
#define qemu_plugin_scoreboard_new qemu_plugin_compat_scoreboard_new
#define qemu_plugin_scoreboard_free qemu_plugin_compat_scoreboard_free
#define qemu_plugin_scoreboard_u64_in_struct(score, type, member) \
    (qemu_plugin_compat_u64) {(score), offsetof(type, member)}
#define qemu_plugin_u64_get qemu_plugin_compat_u64_get
#define qemu_plugin_register_vcpu_insn_exec_cb \
    qemu_plugin_compat_register_vcpu_insn_exec_cb
#define QEMU_PLUGIN_INLINE_STORE_U64 QEMU_PLUGIN_INLINE_ADD_U64
#define qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu \
    qemu_plugin_compat_register_vcpu_insn_exec_inline_per_vcpu

#include "focaccia.c"

#undef qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu
#undef QEMU_PLUGIN_INLINE_STORE_U64
#undef qemu_plugin_register_vcpu_insn_exec_cb
#undef qemu_plugin_u64_get
#undef qemu_plugin_scoreboard_u64_in_struct
#undef qemu_plugin_scoreboard_free
#undef qemu_plugin_scoreboard_new
#undef qemu_plugin_u64
#undef qemu_plugin_scoreboard

static void qemu_plugin_compat_register_vcpu_insn_exec_inline_per_vcpu(
    struct qemu_plugin_insn *instruction,
    enum qemu_plugin_op operation,
    qemu_plugin_compat_u64 entry,
    uint64_t value
)
{
    (void)instruction;
    (void)operation;
    (void)entry;
    (void)value;
}

static struct qemu_plugin_compat_scoreboard *
qemu_plugin_compat_scoreboard_new(size_t element_size)
{
    if (element_size != sizeof(FocacciaScoreboard)) {
        return NULL;
    }
    return g_new0(struct qemu_plugin_compat_scoreboard, 1);
}

static void qemu_plugin_compat_scoreboard_free(
    struct qemu_plugin_compat_scoreboard *score
)
{
    g_free(score);
}

static uint64_t qemu_plugin_compat_u64_get(
    qemu_plugin_compat_u64 entry,
    unsigned int vcpu_index
)
{
    if (vcpu_index != 0 || entry.score == NULL ||
        entry.offset + sizeof(uint64_t) > sizeof(*entry.score)) {
        protocol_failure("invalid compatibility scoreboard access");
    }
    return *(uint64_t *)((uint8_t *)entry.score + entry.offset);
}

static void qemu_plugin_compat_execute_instruction(
    unsigned int vcpu_index,
    void *userdata
)
{
    if (instruction_address.score == NULL ||
        instruction_address.offset + sizeof(uint64_t) >
            sizeof(*instruction_address.score)) {
        protocol_failure("invalid compatibility instruction address");
    }
    *(uint64_t *)((uint8_t *)instruction_address.score +
                  instruction_address.offset) = (uintptr_t)userdata;
    execute_instruction(vcpu_index, NULL);
}

static void qemu_plugin_compat_register_vcpu_insn_exec_cb(
    struct qemu_plugin_insn *instruction,
    qemu_plugin_vcpu_udata_cb_t callback,
    enum qemu_plugin_cb_flags flags,
    void *userdata
)
{
    if (callback != execute_instruction || userdata != NULL) {
        protocol_failure("unsupported compatibility callback registration");
    }
    qemu_plugin_register_vcpu_insn_exec_cb(
        instruction,
        qemu_plugin_compat_execute_instruction,
        flags,
        (void *)(uintptr_t)qemu_plugin_insn_vaddr(instruction)
    );
}
