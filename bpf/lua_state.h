#ifndef __LUA_STATE_H
#define __LUA_STATE_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* =========================================================================
 *  Lua runtime structures, version-invariant slices.
 *
 *  Only the *prefix* of each structure that is identical across Lua 5.2 / 5.3
 *  / 5.4 on 64-bit Linux is modelled here. Every field that moves between
 *  versions — savedpc, callstatus, Proto layout, the CallInfo / lua_State
 *  pointer offsets — is read at runtime via the `loff_*` rodata config (see
 *  profile.bpf.c) so a single BPF binary serves all three versions.
 *
 *  Layout assumptions (true for 5.2, 5.3, 5.4 on Linux x86_64/aarch64):
 *    - sizeof(long)==8, sizeof(void*)==8, sizeof(double)==8
 *    - Instruction is a 32-bit opcode
 *    - StkId is StackValue* (16 bytes each)
 *    - COMMON_HEADER is { GCObject *next; lu_byte tt; lu_byte marked; }
 *
 *  Each field is read via bpf_probe_read_user, so the BPF verifier always
 *  sees a fixed offset (no struct-following deref).
 * ========================================================================= */

#define LUARD_T(src, field, type)                                                                                      \
    ({                                                                                                                 \
        type _v;                                                                                                       \
        __builtin_memset(&_v, 0, sizeof(_v));                                                                          \
        bpf_probe_read_user(&_v, sizeof(_v), (const void *)&(src)->field);                                             \
        _v;                                                                                                            \
    })

/* Read `sizeof(*dst)` bytes from (base + off), used for fields that live at
 * different offsets per Lua version (savedpc, callstatus, proto fields, ...). */
#define LUARD_OFF(dst, base, off) bpf_probe_read_user(dst, sizeof(*(dst)), (const void *)((const char *)(base) + (off)))

/* ---- scalar typedefs -------------------------------------------------- */
typedef unsigned char lu_byte;
typedef uint32_t Instruction;
typedef int32_t lua_Integer;
typedef unsigned long long lua_CFunction; /* stored as raw pointer */

/* ---- tagged value ----------------------------------------------------- *
 * Value (8 bytes) + tt_ (1 byte) -> 16-byte slot, with 7 bytes of padding. */
typedef struct TValue {
    union {
        unsigned long long u64;
        void *gc;
        void *p;
        lua_Integer i;
        double n;
    } value_;
    lu_byte tt_;
} TValue;

/* Stack slot == TValue. */
typedef TValue StackValue;

/* CommonHeader for all GCObjects, inlined into each struct. */
#define COMMON_HEADER                                                                                                  \
    struct GCObject *next;                                                                                             \
    lu_byte tt;                                                                                                        \
    lu_byte marked

/* ---- TString ---------------------------------------------------------- *
 * The `contents` member exists only literally in 5.4, but `getstr()` in
 * 5.2/5.3 computes the same address (`(char*)(ts+1)` == offset 24), so this
 * struct's `contents[0]` is valid for reading chunk names on all three. */
typedef struct TString {
    COMMON_HEADER;
    lu_byte extra;
    lu_byte shrlen;
    unsigned int hash;
    union {
        size_t lnglen;
        struct TString *hnext;
    } u;
    char contents[1];
} TString;

/* ---- Closures --------------------------------------------------------- *
 * 5.2 / 5.3 / 5.4 share the closure prefix: COMMON_HEADER(10) + nupvalues(1)
 * + 1 pad + gclist(8) + f / p (8). Pointer to the closure body's variant
 * field lives at offset 24 in every version. */
struct Proto; /* forward decl — we never deref it in BPF, only read by offset */

typedef struct CClosure {
    COMMON_HEADER;
    lu_byte nupvalues;
    struct GCObject *gclist;
    lua_CFunction f; /* lua_CFunction, stored as raw pointer */
} CClosure;

typedef struct LClosure {
    COMMON_HEADER;
    lu_byte nupvalues;
    struct GCObject *gclist;
    struct Proto *p;
} LClosure;

/* ---- CallInfo --------------------------------------------------------- *
 * The 4-pointer prefix {func, top, previous, next} occupies bytes 0..31 in
 * Lua 5.2, 5.3, and 5.4. The tail (savedpc, callstatus, ...) is read via
 * the `loff_ci_*` config. We model only this prefix. */
typedef struct CallInfo {
    StackValue *func;          /* 0 */
    StackValue *top;           /* 8 */
    struct CallInfo *previous; /* 16 */
    struct CallInfo *next;     /* 24 */
} CallInfo;

/* ---- type tags (collectable form, with BIT_ISCOLLECTABLE=0x40) -------- *
 * These tag values are the same in 5.2 / 5.3 / 5.4 (lobject.h). */
#define LUA_VLCL          0x6  /* Lua closure */
#define LUA_VLCF          0x16 /* light C function (NOT collectable) */
#define LUA_VCCL          0x26 /* C closure */
#define BIT_ISCOLLECTABLE (1u << 6)

static __always_inline bool valid_user_ptr(uint64_t ptr)
{
    /* Lower bound only: a null or near-null pointer is never a real Lua
     * object. The upper bound is left to bpf_probe_read_user — hardcoding
     * 1<<47 would wrongly reject aarch64 user addresses in the
     * 0x0000aaaa... / 0x0000ffff... range and x86_64 LA57 (5-level) layouts. */
    return ptr >= 4096;
}

#endif /* __LUA_STATE_H */
