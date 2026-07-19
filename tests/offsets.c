/* tests/offsets.c : compile-time verification of the Lua runtime offsets
 * baked into lua-flame-rs against the *real* Lua internal headers of one
 * version at a time.
 *
 * This program does NOT run as part of cargo test — it needs the Lua source
 * tree and is meant to be compiled manually when porting / validating.
 *
 * Usage (download from https://www.lua.org/ftp/):
 *
 *   # 5.4.8
 *   cc -I/path/to/lua-5.4.8/src tests/offsets.c -o /tmp/offsets54 && /tmp/offsets54
 *
 *   # 5.3.6
 *   cc -I/path/to/lua-5.3.6/src tests/offsets.c -o /tmp/offsets53 && /tmp/offsets53
 *
 *   # 5.2.3
 *   cc -I/path/to/lua-5.2.3/src tests/offsets.c -o /tmp/offsets52 && /tmp/offsets52
 *
 * The per-version path is selected by LUA_VERSION_NUM from lua.h; no -D flag
 * is needed. Each CHECK prints ok/FAIL for one (field, got, want) triple; the
 * program exits non-zero if any assertion failed.
 */
#include <stdio.h>
#include <stddef.h>
#include "lstate.h"
#include "lobject.h"

static int fails = 0;
static int checks = 0;

#define CHECK(label, got, want)                                                     \
    do {                                                                            \
        long _g = (long)(got);                                                      \
        long _w = (long)(want);                                                     \
        checks++;                                                                   \
        if (_g != _w) {                                                             \
            printf("FAIL %-44s got %ld want %ld\n", label, _g, _w);                 \
            fails++;                                                                \
        } else {                                                                    \
            printf("ok   %-44s %ld\n", label, _g);                                  \
        }                                                                           \
    } while (0)

#if LUA_VERSION_NUM == 504

int main(void)
{
    /* lua_State */
    CHECK("offsetof(lua_State, ci)", offsetof(lua_State, ci), 32);

    /* CallInfo */
    CHECK("offsetof(CallInfo, u.l.savedpc)", offsetof(CallInfo, u.l.savedpc), 32);
    CHECK("offsetof(CallInfo, callstatus)", offsetof(CallInfo, callstatus), 62);
    CHECK("sizeof(callstatus)", sizeof(((CallInfo *)0)->callstatus), 2);
    CHECK("CIST_C == 0x2", (long)CIST_C, 0x2);

    /* Proto */
    CHECK("offsetof(Proto, code)", offsetof(Proto, code), 64);
    CHECK("offsetof(Proto, linedefined)", offsetof(Proto, linedefined), 44);
    CHECK("offsetof(Proto, source)", offsetof(Proto, source), 112);
    CHECK("offsetof(Proto, sizecode)", offsetof(Proto, sizecode), 24);
    CHECK("offsetof(Proto, sizelineinfo)", offsetof(Proto, sizelineinfo), 28);
    CHECK("offsetof(Proto, sizeabslineinfo)", offsetof(Proto, sizeabslineinfo), 40);
    CHECK("offsetof(Proto, abslineinfo)", offsetof(Proto, abslineinfo), 96);
    CHECK("offsetof(Proto, lineinfo)", offsetof(Proto, lineinfo), 88);

    /* TString */
    CHECK("offsetof(TString, contents)", offsetof(TString, contents), 24);

    /* LClosure.p / CClosure.f */
    CHECK("offsetof(LClosure, p)", offsetof(LClosure, p), 24);
    CHECK("offsetof(CClosure, f)", offsetof(CClosure, f), 24);

    printf("\n%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}

#elif LUA_VERSION_NUM == 503

int main(void)
{
    CHECK("offsetof(lua_State, ci)", offsetof(lua_State, ci), 32);
    CHECK("offsetof(CallInfo, u.l.savedpc)", offsetof(CallInfo, u.l.savedpc), 40);
    CHECK("offsetof(CallInfo, callstatus)", offsetof(CallInfo, callstatus), 66);
    CHECK("sizeof(callstatus)", sizeof(((CallInfo *)0)->callstatus), 2);
    /* 5.3 has CIST_LUA at bit 1 (set => Lua frame), NOT CIST_C like 5.4. */
    CHECK("CIST_LUA == 0x2", (long)CIST_LUA, 0x2);

    CHECK("offsetof(Proto, code)", offsetof(Proto, code), 56);
    CHECK("offsetof(Proto, linedefined)", offsetof(Proto, linedefined), 40);
    CHECK("offsetof(Proto, source)", offsetof(Proto, source), 104);
    CHECK("offsetof(Proto, sizecode)", offsetof(Proto, sizecode), 24);
    CHECK("offsetof(Proto, sizelineinfo)", offsetof(Proto, sizelineinfo), 28);
    /* 5.3 has no abslineinfo */
    CHECK("offsetof(Proto, lineinfo)", offsetof(Proto, lineinfo), 72);

    CHECK("sizeof(UTString)", sizeof(UTString), 24);

    CHECK("offsetof(LClosure, p)", offsetof(LClosure, p), 24);
    CHECK("offsetof(CClosure, f)", offsetof(CClosure, f), 24);

    printf("\n%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}

#elif LUA_VERSION_NUM == 502

int main(void)
{
    CHECK("offsetof(lua_State, ci)", offsetof(lua_State, ci), 32);
    /* In 5.2, CallInfo.u is a union of c (C) and l (Lua). savedpc lives at
     * u.l.savedpc; verify the offset of the variant that holds it. */
    CHECK("offsetof(CallInfo, u.l.savedpc)", offsetof(CallInfo, u.l.savedpc), 56);
    CHECK("offsetof(CallInfo, callstatus)", offsetof(CallInfo, callstatus), 34);
    CHECK("sizeof(callstatus)", sizeof(((CallInfo *)0)->callstatus), 1);
    /* 5.2's CIST_LUA is bit 0; set => Lua frame. */
    CHECK("CIST_LUA == 0x1", (long)CIST_LUA, 0x1);

    CHECK("offsetof(Proto, code)", offsetof(Proto, code), 24);
    CHECK("offsetof(Proto, lineinfo)", offsetof(Proto, lineinfo), 40);
    CHECK("offsetof(Proto, sizecode)", offsetof(Proto, sizecode), 88);
    CHECK("offsetof(Proto, sizelineinfo)", offsetof(Proto, sizelineinfo), 92);
    /* 5.2 linedefined is at the back of the struct (after the
     * sizep/sizelocvars/etc. block); verify the value we use. */
    CHECK("offsetof(Proto, linedefined)", offsetof(Proto, linedefined), 104);
    CHECK("offsetof(Proto, source)", offsetof(Proto, source), 72);

    /* 5.2 TString is itself the union; getstr computes ts+sizeof(TString) == 24. */
    CHECK("sizeof(TString)", sizeof(TString), 24);

    CHECK("offsetof(LClosure, p)", offsetof(LClosure, p), 24);
    CHECK("offsetof(CClosure, f)", offsetof(CClosure, f), 24);

    printf("\n%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}

#else
#error "unsupported LUA_VERSION_NUM; expected 502, 503, or 504"
#endif
