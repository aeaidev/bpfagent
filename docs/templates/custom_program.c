// SPDX-License-Identifier: Dual MIT/GPL
/*
 * Template: eBPF kernel program in C for bpfagent (see docs/PLUGINS_C.md)
 *
 * This is the C counterpart of the Rust eBPF template in docs/PLUGINS.md.
 * To use it:
 * 1. Copy this file to ebpf/my_program/my_program.c — bpfagent/build.rs
 *    discovers ebpf/*\/*.c automatically and compiles it with clang into
 *    OUT_DIR on every cargo build (see docs/PLUGINS_C.md, step 3)
 * 2. Write the userspace handler in Rust exactly as in docs/PLUGINS.md —
 *    aya loads the clang-produced object identically to a Rust-produced one
 *    (a complete example: docs/templates/custom.rs)
 *
 * The file is self-contained on purpose: it declares the few BPF helpers it
 * uses directly instead of pulling in kernel headers or libbpf, so a bare
 * clang with a BPF backend is enough to build it.
 */

typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(NAME) __attribute__((section(NAME), used))

/* BPF helpers are addressed by number; the kernel resolves them at load
 * time. Add prototypes here for any additional helpers you need (the numbers
 * are stable, see the BPF_FUNC_* enum in include/uapi/linux/bpf.h). */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_trace_printk)(const char *fmt, int fmt_size,
                                ...) = (void *)6;

/*
 * A BTF-style map definition: the .maps section plus the BTF that clang -g
 * emits lets aya create the map at load time. BPF_MAP_TYPE_HASH is 2.
 */
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} counters SEC(".maps") = {
    .type = 2,
    .max_entries = 128,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};

/*
 * The section name tells aya the program type ("tracepoint/...", "kprobe/...",
 * "xdp", "classifier", ...). The function name becomes the aya program name:
 * EbpfProgram::bpf_program_name() and ebpf.program_mut() must match it.
 * For tracepoints the attach category/event are given again in the userspace
 * attach() call.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int my_handler(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    /* Count openat() calls per PID. */
    __u64 *count = bpf_map_lookup_elem(&counters, &pid);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&counters, &pid, &new_count, 0);

    /* bpf_trace_printk writes to /sys/kernel/tracing/trace_pipe — aya-log
     * does NOT capture it (aya-log is a Rust-only protocol). */
    char msg[] = "my_handler: openat by pid %d\n";
    bpf_trace_printk(msg, sizeof(msg), pid);

    (void)ctx;
    return 0;
}

/* Required or the kernel rejects the object. aya maps this section too. */
char LICENSE[] SEC("license") = "Dual MIT/GPL";
