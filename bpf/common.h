#ifndef __COMMON_H
#define __COMMON_H

#define MAX_ENTRIES                    10240
#define CHUNKNAME_LEN                  128
#define MAX_LUA_DEPTH                  32
#define PERF_MAX_STACK_DEPTH           32
#define USER_STACK_SNAPSHOT_SIZE       4096
#define USER_STACK_SNAPSHOT_CHUNK_SIZE 512

enum func_type {
    FUNC_TYPE_LUA = 0,
    FUNC_TYPE_C = 1,
    FUNC_TYPE_LCF = 2, /* light C function */
};

struct sample_key {
    unsigned int pid;
    unsigned int tid;
    unsigned int seq; /* per-tid sample sequence */
};

/* Native stack input. bpf_get_stack fills `ips` leaf-first; registers and
 * stack bytes are used for user-space DWARF unwinding. */
struct native_event {
    struct sample_key key; /* correlates with lua_stack_event.key */
    unsigned int ip_cnt;
    unsigned int stack_len;
    unsigned long long ip;
    unsigned long long sp;
    unsigned long long fp;
    unsigned long long lr;
    unsigned long long ips[PERF_MAX_STACK_DEPTH];
    unsigned char stack[USER_STACK_SNAPSHOT_SIZE];
};

/* one walked Lua 5.4 frame. */
struct lua_stack_event {
    struct sample_key key;    /* same key as the native sample */
    int level;                /* 0 = topmost */
    int type;                 /* enum func_type */
    char name[CHUNKNAME_LEN]; /* chunkname, e.g. "@foo.lua" */
    unsigned long long funcp; /* C function address (FUNC_TYPE_C / FUNC_TYPE_LCF) */
    int line;                 /* source line (resolved in user space for LUA frames) */
    /* raw inputs for user-space line resolution (Lua frames only) */
    unsigned long long proto;   /* Proto* */
    unsigned long long savedpc; /* Instruction* */
    int linedefined;
};

#endif /* __COMMON_H */
