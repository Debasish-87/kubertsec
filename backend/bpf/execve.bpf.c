#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ─────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────*/

#define TASK_COMM_LEN  16
#define MAX_ARGS       128
#define MAX_ARGS_COUNT 6     /* read up to 6 argv elements */

typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef unsigned short      u16;
typedef unsigned char       u8;

/* __user is a kernel annotation — not available in BPF compilation */
#ifndef __user
#define __user
#endif

/* Event types — must match Go constants in pkg/ebpf/events.go */
#define EVENT_EXEC    1
#define EVENT_CONNECT 2
#define EVENT_FILE    3
#define EVENT_CLONE   4

/* ─────────────────────────────────────────────────────────────
 * Event structure
 *
 * Layout is fixed — Go struct must match exactly.
 * Pad to 8-byte alignment so binary.Read works correctly.
 * ───────────────────────────────────────────────────────────*/
struct event {
    u32 pid;
    u32 tgid;
    u32 uid;

    char comm[TASK_COMM_LEN]; /* 16 bytes */
    char args[MAX_ARGS];      /* 128 bytes */

    /* IPv4 */
    u32 daddr;
    u16 dport;

    u8  event_type;
    u8  is_ipv6;    /* 1 = IPv6, 0 = IPv4 */

    /* IPv6 address (16 bytes) */
    u8  daddr6[16];

    u8  pad[4];     /* align to 8-byte boundary */
};

/* ─────────────────────────────────────────────────────────────
 * Ring buffer map
 * ───────────────────────────────────────────────────────────*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26); /* 64 MiB */
} events SEC(".maps");

/* ─────────────────────────────────────────────────────────────
 * PID filter map (optional — allowlist PIDs to suppress)
 * ───────────────────────────────────────────────────────────*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u8);
} pid_filter SEC(".maps");

/* ─────────────────────────────────────────────────────────────
 * String helpers
 * ───────────────────────────────────────────────────────────*/

static __always_inline int str_len(const char *buf)
{
#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        if (buf[i] == 0)
            return i;
    }
    return MAX_ARGS;
}

static __always_inline void append_arg(char *dst, const char *src)
{
    int len = str_len(dst);
    if (len >= MAX_ARGS - 2)
        return;
    dst[len] = ' ';
    bpf_probe_read_user_str(&dst[len + 1], MAX_ARGS - len - 1, src);
}

/* Read up to MAX_ARGS_COUNT argv elements into e->args */
static __always_inline void read_args(struct event *e, struct pt_regs *ctx)
{
    const char **argv = (const char **)PT_REGS_PARM2(ctx);
    if (!argv)
        return;

    const char *arg = NULL;

#pragma unroll
    for (int i = 0; i < MAX_ARGS_COUNT; i++) {
        bpf_probe_read_user(&arg, sizeof(arg), &argv[i]);
        if (!arg)
            break;
        if (i == 0)
            bpf_probe_read_user_str(e->args, sizeof(e->args), arg);
        else
            append_arg(e->args, arg);
    }
}

/* ─────────────────────────────────────────────────────────────
 * Common exec handler (shared by execve, execveat, do_execveat_common)
 * ───────────────────────────────────────────────────────────*/
static __always_inline int handle_exec(struct pt_regs *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->tgid       = pid_tgid >> 32;
    e->pid        = (u32)pid_tgid;
    e->uid        = (u32)uid_gid;
    e->event_type = EVENT_EXEC;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    read_args(e, ctx);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 * execve / execveat kprobes
 * ───────────────────────────────────────────────────────────*/
SEC("kprobe/__x64_sys_execve")
int trace_execve(struct pt_regs *ctx)
{
    return handle_exec(ctx);
}

SEC("kprobe/__x64_sys_execveat")
int trace_execveat(struct pt_regs *ctx)
{
    return handle_exec(ctx);
}

SEC("kprobe/do_execveat_common")
int trace_exec_common(struct pt_regs *ctx)
{
    return handle_exec(ctx);
}

/* ─────────────────────────────────────────────────────────────
 * Tracepoint fallback for exec
 * ───────────────────────────────────────────────────────────*/
SEC("tracepoint/sched/sched_process_exec")
int trace_sched_exec(void *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->tgid       = pid_tgid >> 32;
    e->pid        = (u32)pid_tgid;
    e->uid        = (u32)uid_gid;
    e->event_type = EVENT_EXEC;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 * fork / clone tracking (EVENT_CLONE)
 * ───────────────────────────────────────────────────────────*/
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->tgid       = pid_tgid >> 32;
    e->pid        = (u32)pid_tgid;
    e->uid        = (u32)uid_gid;
    e->event_type = EVENT_CLONE;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 * TCP IPv4 connect monitor
 * ───────────────────────────────────────────────────────────*/
SEC("kprobe/tcp_v4_connect")
int trace_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->tgid       = pid_tgid >> 32;
    e->pid        = (u32)pid_tgid;
    e->uid        = (u32)uid_gid;
    e->event_type = EVENT_CONNECT;
    e->is_ipv6    = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 * TCP IPv6 connect monitor
 * ───────────────────────────────────────────────────────────*/
SEC("kprobe/tcp_v6_connect")
int trace_connect6(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->tgid       = pid_tgid >> 32;
    e->pid        = (u32)pid_tgid;
    e->uid        = (u32)uid_gid;
    e->event_type = EVENT_CONNECT;
    e->is_ipv6    = 1;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct in6_addr daddr6;
    BPF_CORE_READ_INTO(&daddr6, sk, __sk_common.skc_v6_daddr);
    __builtin_memcpy(e->daddr6, &daddr6, 16);

    e->dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 * openat file access monitor
 * ───────────────────────────────────────────────────────────*/
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->tgid       = pid_tgid >> 32;
    e->pid        = (u32)pid_tgid;
    e->uid        = (u32)uid_gid;
    e->event_type = EVENT_FILE;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename = (const char *)ctx->args[1];
    if (!filename) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    long res = bpf_probe_read_user_str(e->args, sizeof(e->args), filename);
    if (res < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
