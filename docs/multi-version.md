# Multi-version Lua support

`lua-flame-rs` profiles PUC Lua 5.2, 5.3, and 5.4 from a single profiler
binary. This note records the version-dependent pieces and how the offsets
were validated.

## Why a single binary works

The Lua interpreter's runtime structures share a stable *prefix* across
versions — `lua_State.ci`, the first four pointers of `CallInfo` (`func`,
`top`, `previous`, `next`), the `TValue` / `LClosure` / `CClosure` / `TString`
layouts, and the type tags. Only a handful of fields move:

- `CallInfo.u.l.savedpc` — byte 32 in 5.4, 40 in 5.3, 56 in 5.2.
- `CallInfo.callstatus` — byte 62 in 5.4 (u16), 66 in 5.3 (u16), 34 in 5.2 (u8).
- The `Proto` layout — substantially rearranged between 5.2 and 5.3, then
  again (mildly) in 5.4 with the introduction of `abslineinfo`.

`bpf/lua_state.h` therefore models only the version-invariant prefix of
`CallInfo` and forwards every version-dependent field through a runtime offset
(`LUARD_OFF`). The offsets themselves are stored as `.rodata` config (`loff_*`)
that user space fills in before loading the BPF program.

## The version-detection ladder

`src/syms.rs::find_lua_module` walks:

1. **Explicit path** — `--lua-module PATH`. Fallback for when auto-discovery
   can't decide (multiple Lua modules loaded, non-obvious path). Statically
   linked Lua is handled by stage 3 below without any flag.
2. **Mappings whose name contains "lua"** — fast path for `liblua5.X.so`.
3. **The main executable** — covers statically linked Lua.
4. **Every remaining executable file-backed mapping** — last resort.

Each candidate is gated by `scan_lua_symbols`, which requires **at least one
of `lua_resume` / `lua_pcallk` / `lua_callk`** (any one is enough to drive
profiling — statically linked + LTO-gc'd binaries that dropped `lua_resume`
but kept `lua_pcallk` still work) and rejects LuaJIT (`luaJIT_setmode`).

Version detection (`detect_version`) runs in three steps:

1. **Sentinel symbols** (authoritative). Each version exports API functions
   the others don't:
   - **5.4-only**: `lua_resetthread` (new signature), `lua_closethread`,
     `lua_setcstacklimit`, `lua_toclose`, `lua_warning`, `lua_getiuservalue`.
   - **5.3-only**: `lua_stringtonumber` (added in 5.3, kept in 5.4 — so this
     alone distinguishes 5.3 from 5.2, not from 5.4; the 5.4 sentinels fire
     first in the if-chain).
   - **5.2-only**: `lua_getctx` (removed in 5.3 — the continuation context
     moved into CallInfo). `lua_cpcall` and `lua_pushglobaltable` are also
     5.2-era but exist as macros in later versions, so they're not reliable
     ELF symbols; `lua_getctx` alone is the authoritative sentinel.
2. **File-name substring** — `liblua5.4.so`, `lua-5.3`, `lua.so.5.2`.
3. **`--lua-version` override** — required when the target is stripped or
   LTO + `--gc-sections` dropped the sentinel symbols.

## The offset table

Validated with `tests/offsets.c` against the upstream Lua 5.2.3, 5.3.6, and
5.4.8 source trees. To re-validate after a Lua point release:

```sh
cc -I/path/to/lua-5.4.8/src tests/offsets.c -o /tmp/o54 && /tmp/o54
cc -I/path/to/lua-5.3.6/src tests/offsets.c -o /tmp/o53 && /tmp/o53
cc -I/path/to/lua-5.2.3/src tests/offsets.c -o /tmp/o52 && /tmp/o52
```

The version is read from `LUA_VERSION_NUM` in `lua.h` — no `-D` flag needed.

### BPF walker offsets (`WalkerOffsets` in `src/main.rs`)

| Field                  | 5.4  | 5.3  | 5.2  | Notes |
|------------------------|------|------|------|-------|
| `state_ci`             | 32   | 32   | 32   | `offsetof(lua_State, ci)` |
| `ci_savedpc`           | 32   | 40   | 56   | `CallInfo.u.l.savedpc` |
| `ci_callstatus`        | 62   | 66   | 34   | u16 in 5.3/5.4, u8 in 5.2 |
| `callstatus_mask`      | 0xffff | 0xffff | 0xff | width mask |
| `lua_frame_mask`       | 0x2  | 0x2  | 0x1  | see semantics below |
| `lua_frame_when_set`   | 0    | 1    | 1    | see semantics below |
| `proto_code`           | 64   | 56   | 24   | |
| `proto_linedefined`    | 44   | 40   | 104  | |
| `proto_source`         | 112  | 104  | 72   | `TString.contents` is at +24 in all three |

### Lua frame vs. C frame — the tricky bit

The `callstatus` flag that distinguishes a Lua frame from a C frame is
**inverted** between 5.4 and {5.3, 5.2}:

- **5.4**: `CIST_C` (bit 1) **set** => **C** frame. `lua_frame_when_set = 0`.
- **5.3**: `CIST_LUA` (bit 1) **set** => **Lua** frame. `lua_frame_when_set = 1`.
- **5.2**: `CIST_LUA` (bit 0) **set** => **Lua** frame. `lua_frame_when_set = 1`.

`emit_lua` in `bpf/profile.bpf.c` computes `is_lua_frame` uniformly:

```c
bool mask_set = (callstatus & loff_lua_frame_mask) != 0;
bool lua_when_set = loff_lua_frame_when_set != 0;
bool is_lua_frame = lua_when_set ? mask_set : !mask_set;
```

### Proto layout (`ProtoLayout` in `src/lineresolve.rs`)

| Field             | 5.4 | 5.3 | 5.2 | Notes |
|-------------------|-----|-----|-----|-------|
| `off_sizecode`    | 24  | 24  | 88  | |
| `off_sizelineinfo`| 28  | 28  | 92  | |
| `off_sizeabs`     | 40  | 0   | 0   | 5.4 only |
| `off_code`        | 64  | 56  | 24  | |
| `off_lineinfo`    | 88  | 72  | 40  | |
| `off_abslineinfo` | 96  | 0   | 0   | 5.4 only |
| `delta_encoded`   | true | false | false | see below |

### Line-info decoding

- **5.4**: `lineinfo[i]` is a signed-byte *delta* added to a running line;
  absolute lines are recorded in the side table `abslineinfo[]` indexed by pc.
  The resolver walks forward from pc 0, mirroring Lua's `luaG_getfuncline` /
  `getbaseline`. Sentinel value `0x80` (-128) means "look in abslineinfo".
- **5.2 / 5.3**: `lineinfo[i]` is a plain `int` line number indexed by pc —
  one `pread`, no walk.

The two paths share all the prelude (savedpc → pc, sizecode bounds check) and
diverge only in the final table lookup (`resolve_delta` vs. `resolve_direct`).

## What still doesn't work across versions

- **LuaJIT**: rejected at attach. Its `CallInfo` / `Proto` / `TValue` layouts
  are entirely different and would need a separate BPF program.
- **Non-default ABIs**: a Lua built with `-DLUA_32BITS` (32-bit `lua_Integer`
  / `Instruction` pair packed differently) will not match the table.
- **Stripped static binaries without any Lua entry point**: if LTO +
  `--gc-sections` removed *all* of `lua_resume` / `lua_pcallk` / `lua_callk`,
  there's nothing to uprobe. `--lua-version` only helps when sentinel symbols
  are gone but at least one entry point survives (the host's actual call
  sites — typically `lua_pcallk` — keep their symbols alive).
