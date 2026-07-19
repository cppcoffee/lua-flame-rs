/* SPDX-License-Identifier: MIT */
/* eBPF program: sample C + Lua stacks (5.2 / 5.3 / 5.4) for flame-graph
 * generation.
 *
 * Two output streams, keyed by a per-sample nonce so user space can
 * correlate them:
 *
 *   1. do_perf_event: captures user registers and stack bytes for DWARF
 *      unwinding, plus bpf_get_stack() IPs as a per-sample fallback.
 *   2. walk_lua_stack: emits one `lua_stack_event` per Lua frame.
 *
 * All version-dependent Lua runtime offsets are passed in via the loff_*
 * rodata fields below (filled by user space before load); see
 * docs/multi-version.md for the per-version offset table.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "lua_state.h"
#include "common.h"

/* Also controls whether C closures and light C functions are emitted. */
const volatile bool collect_native_stacks = false;
const volatile pid_t targ_pid = -1;

/* ---- version-dependent Lua offsets (set from user space) -------------- *
 * Defaults target Lua 5.4 (default ABI on Linux x86_64 / aarch64); user
 * space overrides all of them with the right table for the detected
 * version. See walker_offsets() in src/main.rs. */
const volatile u32 loff_state_ci = 32;            /* offsetof(lua_State, ci) */
const volatile u32 loff_ci_savedpc = 32;          /* CallInfo.u.l.savedpc / l.savedpc */
const volatile u32 loff_ci_callstatus = 62;       /* CallInfo.callstatus (u16 in 5.3/5.4, u8 in 5.2) */
const volatile u32 loff_callstatus_mask = 0xffff; /* width mask: u16 -> 0xffff, u8 -> 0xff */
const volatile u32 loff_lua_frame_mask = 0x2;     /* CIST_C (5.4) / CIST_LUA (5.3, bit 1) / CIST_LUA (5.2, bit 0) */
/* 0 => a SET bit means a C frame (5.4 only: CIST_C set => C frame).
 * 1 => a SET bit means a Lua frame (5.3 / 5.2: CIST_LUA set => Lua frame). */
const volatile u32 loff_lua_frame_when_set = 0;
const volatile u32 loff_proto_linedefined = 44;
const volatile u32 loff_proto_source = 112;

/* per-tid lua_State* and shallow C API nesting depth */
struct lua_state_slot {
    u64 ptr;
    u32 depth;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct lua_state_slot);
} lua_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} seq_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} native_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} lua_events_out SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct native_event);
} native_buf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct lua_stack_event);
} lua_event_buf SEC(".maps");

/* ---- source line resolution ------------------------------------------- *
 * Done in user space: BPF only forwards pc, Proto*, and linedefined. The
 * forward walk over Proto->lineinfo[] would blow up the verifier if unrolled
 * inside BPF (it can be thousands of bytes for large functions).
 */

/* emit one lua frame */
static __always_inline void emit_lua(struct bpf_perf_event_data *ctx, CallInfo *ci, u32 pid, u32 tid, u32 seq,
                                     int level)
{
    StackValue *func_slot = LUARD_T(ci, func, StackValue *);
    if (!valid_user_ptr((uint64_t)func_slot)) {
        return;
    }
    TValue v;
    __builtin_memset(&v, 0, sizeof(v));
    if (bpf_probe_read_user(&v, sizeof(v), func_slot)) {
        return;
    }
    lu_byte tt = v.tt_;

    u32 zero = 0;
    struct lua_stack_event *e = bpf_map_lookup_elem(&lua_event_buf, &zero);
    if (!e) {
        return;
    }
    e->key.pid = pid;
    e->key.tid = tid;
    e->key.seq = seq;
    e->level = level;
    e->funcp = 0;
    e->line = 0;
    e->type = 0;
    e->name[0] = 0;
    /* also clear the version-dependent raw fields so stale data from a
     * previous (different frame type) event never leaks into user space. */
    e->proto = 0;
    e->savedpc = 0;
    e->linedefined = 0;

    /* callstatus is a u16 in 5.3/5.4 and a u8 in 5.2; read 2 bytes and mask. */
    u16 cs_raw = 0;
    LUARD_OFF(&cs_raw, ci, loff_ci_callstatus);
    u32 callstatus = cs_raw & loff_callstatus_mask;

    /* Translate "is this a Lua frame?" across versions:
     *   5.4:     CIST_C   (bit 1) SET => C frame      => lua_frame_when_set == 0
     *   5.3:     CIST_LUA (bit 1) SET => Lua frame    => lua_frame_when_set == 1
     *   5.2:     CIST_LUA (bit 0) SET => Lua frame    => lua_frame_when_set == 1
     */
    bool mask_set = (callstatus & loff_lua_frame_mask) != 0;
    bool lua_when_set = loff_lua_frame_when_set != 0;
    bool is_lua_frame = lua_when_set ? mask_set : !mask_set;

    if (!is_lua_frame) {
        /* In Lua-only mode, drop C closures and light C functions at the
         * source — user space never sees them, the perf buffer never
         * carries them, and the folded stack stays pure-Lua. */
        if (!collect_native_stacks) {
            return;
        }
        /* C closure or light C function. Match each known tag explicitly
         * rather than "anything not LUA_VLCF" — an unexpected tag (e.g.
         * corrupted/garbage slot) must not be reported as a C:0x0 frame. */
        if ((tt & ~BIT_ISCOLLECTABLE) == LUA_VLCF) {
            e->type = FUNC_TYPE_LCF;
            e->funcp = (uint64_t)v.value_.p;
        } else if ((tt & ~BIT_ISCOLLECTABLE) == LUA_VCCL) {
            CClosure *ccl = (CClosure *)(unsigned long)v.value_.gc;
            e->type = FUNC_TYPE_C;
            e->funcp = (uint64_t)LUARD_T(ccl, f, lua_CFunction);
        } else {
            return;
        }
        bpf_perf_event_output(ctx, &lua_events_out, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return;
    }

    /* Lua closure: read LClosure.p */
    if ((tt & ~BIT_ISCOLLECTABLE) != LUA_VLCL) {
        return;
    }
    LClosure *cl = (LClosure *)(unsigned long)v.value_.gc;
    struct Proto *pt = LUARD_T(cl, p, struct Proto *);
    if (!valid_user_ptr((uint64_t)pt)) {
        return;
    }
    e->type = FUNC_TYPE_LUA;
    e->proto = (uint64_t)pt;

    /* linedefined and source live at version-dependent offsets. */
    int linedefined = 0;
    LUARD_OFF(&linedefined, pt, loff_proto_linedefined);
    e->linedefined = linedefined;

    /* User space reads Proto->code and validates savedpc against it. */
    const Instruction *savedpc = NULL;
    LUARD_OFF(&savedpc, ci, loff_ci_savedpc);
    if (valid_user_ptr((uint64_t)savedpc)) {
        e->savedpc = (uint64_t)savedpc;
    }

    uint64_t source = 0;
    LUARD_OFF(&source, pt, loff_proto_source);
    if (valid_user_ptr(source)) {
        /* TString contents live at +24 in 5.2/5.3/5.4 (see lua_state.h). */
        const char *src = (const char *)(source + (const char *)&((TString *)0)->contents - (const char *)0);
        bpf_probe_read_user_str(&e->name, sizeof(e->name), src);
    }

    bpf_perf_event_output(ctx, &lua_events_out, BPF_F_CURRENT_CPU, e, sizeof(*e));
}

/* Walk the CallInfo linked list from the current ci back to the root. */
static __always_inline void walk_lua_stack(struct bpf_perf_event_data *ctx, u32 tid, u32 pid, u32 seq)
{
    struct lua_state_slot *slot = bpf_map_lookup_elem(&lua_states, &tid);
    if (!slot || !slot->ptr) {
        return;
    }
    uint64_t L = slot->ptr;

    CallInfo *ci = NULL;
    LUARD_OFF(&ci, L, loff_state_ci);
    if (!valid_user_ptr((uint64_t)ci)) {
        return;
    }

    int out = 0;
#pragma unroll
    for (int i = 0; i < MAX_LUA_DEPTH; i++) {
        if (!valid_user_ptr((uint64_t)ci)) {
            break;
        }
        emit_lua(ctx, ci, pid, tid, seq, out);
        out++;
        CallInfo *prev = LUARD_T(ci, previous, CallInfo *);
        if (!valid_user_ptr((uint64_t)prev) || prev == ci) {
            break;
        }
        ci = prev;
    }
}

static __always_inline void get_pid_tid(u32 *pid, u32 *tid)
{
    u64 id = bpf_get_current_pid_tgid();
    *pid = id >> 32;
    *tid = (u32)id;
}

static __always_inline u32 read_user_stack_snapshot(struct native_event *event)
{
    u32 bytes_read = 0;

#pragma unroll
    for (u32 offset = 0; offset < USER_STACK_SNAPSHOT_SIZE; offset += USER_STACK_SNAPSHOT_CHUNK_SIZE) {
        if (bpf_probe_read_user(event->stack + offset, USER_STACK_SNAPSHOT_CHUNK_SIZE,
                                (const void *)(event->sp + offset)) != 0) {
            break;
        }
        bytes_read += USER_STACK_SNAPSHOT_CHUNK_SIZE;
    }

    if (bytes_read == 0) {
        if (bpf_probe_read_user(event->stack, 256, (const void *)event->sp) == 0) {
            return 256;
        }
        if (bpf_probe_read_user(event->stack, 128, (const void *)event->sp) == 0) {
            return 128;
        }
        if (bpf_probe_read_user(event->stack, 64, (const void *)event->sp) == 0) {
            return 64;
        }
        if (bpf_probe_read_user(event->stack, 32, (const void *)event->sp) == 0) {
            return 32;
        }
        if (bpf_probe_read_user(event->stack, 16, (const void *)event->sp) == 0) {
            return 16;
        }
        if (bpf_probe_read_user(event->stack, 8, (const void *)event->sp) == 0) {
            return 8;
        }
    }
    return bytes_read;
}

static __always_inline u32 next_seq(u32 tid)
{
    u32 *p = bpf_map_lookup_elem(&seq_map, &tid);
    u32 v = p ? *p + 1 : 1;
    bpf_map_update_elem(&seq_map, &tid, &v, BPF_ANY);
    return v;
}

static __always_inline u64 get_lua_state_arg1(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_arm64)
    return *(const volatile u64 *)ctx;
#else
    return (u64)PT_REGS_PARM1(ctx);
#endif
}

/* ---- perf-event sampler ---------------------------------------------- */
SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
    u32 pid, tid;
    get_pid_tid(&pid, &tid);
    if (targ_pid != -1 && targ_pid != pid) {
        return 0;
    }

    u32 seq = next_seq(tid);

    {
        u32 zero = 0;
        struct native_event *ne = bpf_map_lookup_elem(&native_buf, &zero);
        if (ne) {
            ne->key.pid = pid;
            ne->key.tid = tid;
            ne->key.seq = seq;
            ne->stack_len = 0;
            ne->ip = 0;
            ne->sp = 0;
            ne->fp = 0;
            ne->lr = 0;
            long n = bpf_get_stack(ctx, ne->ips, sizeof(ne->ips), BPF_F_USER_STACK);
            ne->ip_cnt = n > 0 ? n / sizeof(u64) : 0;
            if (collect_native_stacks) {
                ne->ip = PT_REGS_IP(&ctx->regs);
                ne->sp = PT_REGS_SP(&ctx->regs);
                ne->fp = PT_REGS_FP(&ctx->regs);
#if defined(__TARGET_ARCH_arm64)
                ne->lr = PT_REGS_RET(&ctx->regs);
#endif
                if (ne->sp) {
                    ne->stack_len = read_user_stack_snapshot(ne);
                }
                bpf_perf_event_output(ctx, &native_events, BPF_F_CURRENT_CPU, ne, sizeof(*ne));
            } else {
                bpf_perf_event_output(ctx, &native_events, BPF_F_CURRENT_CPU, ne,
                                      __builtin_offsetof(struct native_event, stack));
            }
        }
    }

    walk_lua_stack(ctx, tid, pid, seq);

    return 0;
}

/* ---- uprobe: capture lua_State* on entry to lua_resume/lua_pcall ------ */
SEC("uprobe")
int handle_entry_lua(struct pt_regs *ctx)
{
    u32 pid, tid;
    get_pid_tid(&pid, &tid);
    if (targ_pid != -1 && targ_pid != pid) {
        return 0;
    }
    u64 L = get_lua_state_arg1(ctx);
    if (!L) {
        return 0;
    }
    struct lua_state_slot *old = bpf_map_lookup_elem(&lua_states, &tid);
    struct lua_state_slot slot = {};
    slot.ptr = L;
    slot.depth = 1;
    if (old && old->depth < 0xffff) {
        slot.depth = old->depth + 1;
    }
    bpf_map_update_elem(&lua_states, &tid, &slot, BPF_ANY);
    return 0;
}

/* ---- uretprobe: leave lua_resume/lua_pcall ---------------------------- */
SEC("uretprobe")
int handle_return_lua(struct pt_regs *ctx)
{
    u32 pid, tid;
    get_pid_tid(&pid, &tid);
    if (targ_pid != -1 && targ_pid != pid) {
        return 0;
    }
    struct lua_state_slot *slot = bpf_map_lookup_elem(&lua_states, &tid);
    if (!slot || slot->depth <= 1) {
        bpf_map_delete_elem(&lua_states, &tid);
    } else {
        struct lua_state_slot next = *slot;
        next.depth--;
        bpf_map_update_elem(&lua_states, &tid, &next, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
