//! User-space line resolution for Lua 5.2 / 5.3 / 5.4 frames.
//!
//! BPF sends us a raw (Proto*, savedpc, linedefined) tuple; we read
//! `Proto->code / lineinfo / abslineinfo` from the target process via
//! /proc/<pid>/mem and reconstruct the source line.
//!
//! Two layouts:
//!   - Lua 5.4: `lineinfo[i]` is a signed byte *delta*; absolute lines live
//!     in the side table `abslineinfo`. Walked forward from pc 0 exactly as
//!     Lua's `luaG_getfuncline` / `getbaseline` does.
//!   - Lua 5.2 / 5.3: `lineinfo[i]` is a plain `int` line number indexed by
//!     pc — no deltas, no side table. Direct lookup.
//!
//! Doing this in BPF blew up the verifier (lineinfo can be thousands of
//! bytes). Doing it here is bounded by pc and far cheaper than a single
//! DWARF unwind.

use crate::syms::LuaVersion;
use anyhow::Result;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};

pub const INSTRUCTION_SIZE: u64 = 4;

/// Per-version byte offsets of the `Proto` fields the resolver reads. These
/// are the default-layout offsets on Linux x86_64/aarch64 (long=pointer=8,
/// Instruction=4) and are validated by `tests/offsets.c` against the real Lua
/// headers.
#[derive(Clone, Copy, Debug)]
pub struct ProtoLayout {
    pub off_sizecode: u64,
    pub off_sizelineinfo: u64,
    /// 0 => no abslineinfo field (Lua 5.2 / 5.3).
    pub off_sizeabs: u64,
    pub off_code: u64,
    pub off_lineinfo: u64,
    /// 0 => no abslineinfo array (Lua 5.2 / 5.3).
    pub off_abslineinfo: u64,
    /// true => lineinfo is signed-byte deltas (5.4); false => i32 lines.
    pub delta_encoded: bool,
}

impl ProtoLayout {
    pub fn for_version(v: LuaVersion) -> Self {
        match v {
            LuaVersion::Lua54 => ProtoLayout {
                off_sizecode: 24,
                off_sizelineinfo: 28,
                off_sizeabs: 40,
                off_code: 64,
                off_lineinfo: 88,
                off_abslineinfo: 96,
                delta_encoded: true,
            },
            LuaVersion::Lua53 => ProtoLayout {
                off_sizecode: 24,
                off_sizelineinfo: 28,
                off_sizeabs: 0,
                off_code: 56,
                off_lineinfo: 72,
                off_abslineinfo: 0,
                delta_encoded: false,
            },
            LuaVersion::Lua52 => ProtoLayout {
                off_sizecode: 88,
                off_sizelineinfo: 92,
                off_sizeabs: 0,
                off_code: 24,
                off_lineinfo: 40,
                off_abslineinfo: 0,
                delta_encoded: false,
            },
        }
    }
}

const ABSLINEINFO_SIZE: u64 = 8; /* int pc; int line; */

pub struct LineResolver {
    mem: std::fs::File,
    layout: ProtoLayout,
}

impl LineResolver {
    pub fn new(pid: i32, layout: ProtoLayout) -> Result<Self> {
        let mem = OpenOptions::new()
            .read(true)
            .open(format!("/proc/{pid}/mem"))?;
        Ok(Self { mem, layout })
    }

    /// Resolve a source line for the Lua frame described by (proto, savedpc,
    /// linedefined). `savedpc` points at the *next* instruction to execute;
    /// the line we want is for the just-finished instruction (savedpc - 1).
    /// Returns 0 if it cannot be determined.
    pub fn resolve(&mut self, proto: u64, savedpc: u64, linedefined: i32) -> i32 {
        if proto == 0 || savedpc == 0 {
            return linedefined.max(0);
        }

        let code_ptr = match self.read_u64(proto + self.layout.off_code) {
            Ok(v) => v,
            Err(_) => return linedefined.max(0),
        };
        if code_ptr == 0 || savedpc < code_ptr {
            return linedefined.max(0);
        }
        let byte_off = savedpc - code_ptr;
        if byte_off < INSTRUCTION_SIZE {
            return linedefined.max(0);
        }
        // savedpc - 1 -> the just-executed instruction
        let pc = (byte_off / INSTRUCTION_SIZE) as i32 - 1;
        if pc < 0 {
            return linedefined.max(0);
        }

        let sizecode = self.read_i32(proto + self.layout.off_sizecode).unwrap_or(0);
        if sizecode <= 0 || pc >= sizecode {
            return linedefined.max(0);
        }

        if self.layout.delta_encoded {
            self.resolve_delta(proto, pc, linedefined)
        } else {
            self.resolve_direct(proto, pc, linedefined)
        }
    }

    /// Lua 5.2 / 5.3: `lineinfo[pc]` is a plain `int`. One read, no walk.
    fn resolve_direct(&mut self, proto: u64, pc: i32, linedefined: i32) -> i32 {
        let sizelineinfo = self
            .read_i32(proto + self.layout.off_sizelineinfo)
            .unwrap_or(0);
        if sizelineinfo <= 0 || pc >= sizelineinfo {
            return linedefined.max(0);
        }
        let lineinfo_ptr = match self.read_u64(proto + self.layout.off_lineinfo) {
            Ok(v) if v != 0 => v,
            _ => return linedefined.max(0),
        };
        // lineinfo is `int lineinfo[]`; pc is in [0, sizelineinfo).
        match self.read_i32(lineinfo_ptr + (pc as u64) * 4) {
            Ok(line) if line > 0 => line,
            _ => linedefined.max(0),
        }
    }

    /// Lua 5.4: walk `lineinfo[0..=pc]` summing signed-byte deltas, applying
    /// any abslineinfo entry whose pc <= i. Mirrors `luaG_getfuncline`.
    fn resolve_delta(&mut self, proto: u64, pc: i32, linedefined: i32) -> i32 {
        let sizelineinfo = self
            .read_i32(proto + self.layout.off_sizelineinfo)
            .unwrap_or(0);
        if sizelineinfo <= 0 {
            return linedefined.max(0);
        }
        let lineinfo_ptr = match self.read_u64(proto + self.layout.off_lineinfo) {
            Ok(v) => v,
            Err(_) => return linedefined.max(0),
        };

        let sizeabs = self.read_i32(proto + self.layout.off_sizeabs).unwrap_or(0);
        let abs_ptr = if sizeabs > 0 {
            self.read_u64(proto + self.layout.off_abslineinfo)
                .unwrap_or(0)
        } else {
            0
        };

        // Cap the walk at the smaller of pc and sizelineinfo - 1.
        let limit = pc.min(sizelineinfo - 1);
        if limit < 0 {
            return linedefined.max(0);
        }

        let mut deltas = vec![0i8; (limit + 1) as usize];
        if self
            .read_bytes(
                lineinfo_ptr,
                deltas.as_mut_ptr() as *mut u8,
                deltas.len() as u64,
            )
            .is_err()
        {
            return linedefined.max(0);
        }

        let mut abs_entries: Vec<(i32, i32)> = Vec::new();
        if sizeabs > 0 && abs_ptr != 0 {
            let mut buf = vec![0u8; (sizeabs as usize) * ABSLINEINFO_SIZE as usize];
            if self
                .read_bytes(abs_ptr, buf.as_mut_ptr(), buf.len() as u64)
                .is_ok()
            {
                for chunk in buf.chunks_exact(ABSLINEINFO_SIZE as usize) {
                    let ai_pc = i32::from_le_bytes(chunk[0..4].try_into().unwrap());
                    let ai_line = i32::from_le_bytes(chunk[4..8].try_into().unwrap());
                    abs_entries.push((ai_pc, ai_line));
                }
            }
        }

        walk_line(&deltas, &abs_entries, linedefined, limit)
    }

    fn read_u64(&mut self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_bytes(addr, buf.as_mut_ptr(), 8)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_i32(&mut self, addr: u64) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.read_bytes(addr, buf.as_mut_ptr(), 4)?;
        Ok(i32::from_le_bytes(buf))
    }

    fn read_bytes(&mut self, addr: u64, dst: *mut u8, len: u64) -> Result<()> {
        self.mem.seek(SeekFrom::Start(addr))?;
        unsafe {
            let slice = std::slice::from_raw_parts_mut(dst, len as usize);
            self.mem.read_exact(slice)?;
        }
        Ok(())
    }
}

/// Resolve the source line for instruction `pc` by walking `lineinfo` forward
/// from index 0. Each `lineinfo[i]` is a signed delta added to the running
/// line — except where it equals the sentinel `ABSLINEINFO` (-128), which
/// means "an entry in `abslineinfo` covers this index"; in that case the abs
/// entry's line replaces the running line instead. Mirrors Lua 5.4's
/// `luaG_getfuncline` / `getbaseline`. Pure (no I/O) so it can be unit-tested
/// with hand-crafted inputs.
fn walk_line(deltas: &[i8], abs: &[(i32, i32)], linedefined: i32, pc: i32) -> i32 {
    const ABSLINEINFO: i8 = -128;
    if pc < 0 {
        return linedefined.max(0);
    }
    let limit = pc.min(deltas.len() as i32 - 1).max(0);
    let mut line = linedefined;
    let mut abs_idx = 0;
    for i in 0..=limit {
        let d = deltas[i as usize];
        if d == ABSLINEINFO {
            // Pull the absolute line from abslineinfo. Lua keeps these
            // sorted by pc; advance the cursor without rewind.
            if abs_idx < abs.len() && abs[abs_idx].0 == i {
                line = abs[abs_idx].1;
                abs_idx += 1;
            }
        } else {
            line = line.wrapping_add(d as i32);
        }
    }
    line.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABS: i8 = -128;

    #[test]
    fn walk_line_no_abs_uses_pure_deltas() {
        // deltas: [0, +1, +1, +1], linedefined=10 -> lines at pc 0..3 are
        // 10, 11, 12, 13 (matching Lua's luaG_getfuncline: sum lineinfo[0..=pc]).
        let deltas = [0i8, 1, 1, 1];
        assert_eq!(walk_line(&deltas, &[], 10, 0), 10);
        assert_eq!(walk_line(&deltas, &[], 10, 1), 11);
        assert_eq!(walk_line(&deltas, &[], 10, 2), 12);
        assert_eq!(walk_line(&deltas, &[], 10, 3), 13);
    }

    #[test]
    fn walk_line_abs_entry_replaces_sentinel_delta() {
        // Index 2 carries the ABSLINEINFO sentinel; abs[0] gives the line.
        // deltas: [1, 1, ABS, 1, 1], linedefined=10, abs=[(2, 100)]
        //   pc=0 -> 10+1=11
        //   pc=1 -> 11+1=12
        //   pc=2 -> 100 (sentinel, abs replaces)
        //   pc=3 -> 101
        //   pc=4 -> 102
        let deltas = [1i8, 1, ABS, 1, 1];
        let abs = [(2, 100)];
        assert_eq!(walk_line(&deltas, &abs, 10, 1), 12);
        assert_eq!(walk_line(&deltas, &abs, 10, 2), 100);
        assert_eq!(walk_line(&deltas, &abs, 10, 3), 101);
        assert_eq!(walk_line(&deltas, &abs, 10, 4), 102);
    }

    #[test]
    fn walk_line_negative_delta() {
        // Function that goes back to an earlier line.
        let deltas = [1i8, 1, -3, 1];
        assert_eq!(walk_line(&deltas, &[], 5, 0), 6);
        assert_eq!(walk_line(&deltas, &[], 5, 1), 7);
        assert_eq!(walk_line(&deltas, &[], 5, 2), 4);
        assert_eq!(walk_line(&deltas, &[], 5, 3), 5);
    }

    #[test]
    fn walk_line_pc_beyond_deltas_clamps() {
        let deltas = [1i8, 1];
        // pc=10 but only 2 deltas: should clamp to pc=1's line.
        assert_eq!(
            walk_line(&deltas, &[], 0, 10),
            walk_line(&deltas, &[], 0, 1)
        );
    }

    #[test]
    fn walk_line_missing_abs_entry_falls_back_to_zero_delta() {
        // If lineinfo[i] is the sentinel but no matching abs entry exists
        // (corrupt/truncated), treat as 0 delta — i.e. keep current line.
        let deltas = [1i8, ABS, 1];
        assert_eq!(walk_line(&deltas, &[], 10, 0), 11);
        assert_eq!(walk_line(&deltas, &[], 10, 1), 11);
        assert_eq!(walk_line(&deltas, &[], 10, 2), 12);
    }

    #[test]
    fn proto_layout_54_matches_documented_offsets() {
        let l = ProtoLayout::for_version(LuaVersion::Lua54);
        assert_eq!(l.off_sizecode, 24);
        assert_eq!(l.off_sizelineinfo, 28);
        assert_eq!(l.off_sizeabs, 40);
        assert_eq!(l.off_code, 64);
        assert_eq!(l.off_lineinfo, 88);
        assert_eq!(l.off_abslineinfo, 96);
        assert!(l.delta_encoded);
    }

    #[test]
    fn proto_layout_53_has_no_abslineinfo() {
        let l = ProtoLayout::for_version(LuaVersion::Lua53);
        assert_eq!(l.off_sizecode, 24);
        assert_eq!(l.off_sizelineinfo, 28);
        assert_eq!(l.off_sizeabs, 0);
        assert_eq!(l.off_code, 56);
        assert_eq!(l.off_lineinfo, 72);
        assert_eq!(l.off_abslineinfo, 0);
        assert!(!l.delta_encoded);
    }

    #[test]
    fn proto_layout_52_matches_lstate_h() {
        // Lua 5.2 Proto: lineinfo is way up at +40, with code up front at
        // +24, and sizecode / sizelineinfo at the back (+88 / +92).
        let l = ProtoLayout::for_version(LuaVersion::Lua52);
        assert_eq!(l.off_sizecode, 88);
        assert_eq!(l.off_sizelineinfo, 92);
        assert_eq!(l.off_sizeabs, 0);
        assert_eq!(l.off_code, 24);
        assert_eq!(l.off_lineinfo, 40);
        assert_eq!(l.off_abslineinfo, 0);
        assert!(!l.delta_encoded);
    }
}
