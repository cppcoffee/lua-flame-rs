/* SPDX-License-Identifier: MIT */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/*
 * Minimal arm64 kernel/UAPI types required by profile.bpf.c.
 *
 * This profiler does not dereference kernel-internal structures, so a full
 * kernel-generated vmlinux.h is unnecessary. The register and perf-event
 * layouts below are stable Linux UAPI definitions from
 * arch/arm64/include/uapi/asm/ptrace.h and include/uapi/linux/bpf_perf_event.h.
 */
#include <linux/types.h>
#include <linux/bpf.h>

typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

typedef __s32 int32_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef unsigned long size_t;
typedef int pid_t;

#ifndef __cplusplus
typedef _Bool bool;
enum {
    false = 0,
    true = 1,
};
#endif

struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

typedef struct user_pt_regs bpf_user_pt_regs_t;

struct bpf_perf_event_data {
    bpf_user_pt_regs_t regs;
    __u64 sample_period;
    __u64 addr;
};

struct pt_regs;

#endif /* __VMLINUX_H__ */
