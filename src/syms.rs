//! Locate the Lua runtime backing a target PID — a shared library *or* a
//! statically linked executable — detect the Lua version (5.2 / 5.3 / 5.4),
//! and resolve the file offsets of the API entry points we uprobe.
//!
//! Detection order:
//!   1. version-specific sentinels (symbols only one minor version exports);
//!   2. version substring in the file name (`liblua5.3.so`, `lua-5.4`, ...);
//!   3. `--lua-version` override (for stripped / LTO-gc'd builds).
//!
//! LuaJIT is explicitly rejected up front — its internals are incompatible.

use crate::unwind::parse_maps;
use anyhow::{anyhow, bail, Result};
use object::read::ObjectSymbol;
use object::{Object, ObjectSegment, SegmentFlags, SymbolKind};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LuaVersion {
    Lua52,
    Lua53,
    Lua54,
}

impl LuaVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            LuaVersion::Lua52 => "5.2",
            LuaVersion::Lua53 => "5.3",
            LuaVersion::Lua54 => "5.4",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "5.2" => Ok(LuaVersion::Lua52),
            "5.3" => Ok(LuaVersion::Lua53),
            "5.4" => Ok(LuaVersion::Lua54),
            other => Err(anyhow!(
                "unsupported Lua version '{other}' (expected 5.2, 5.3, or 5.4)"
            )),
        }
    }
}

/// Symbol file offsets we attach uprobes to. Any of these may be 0 if the
/// symbol is absent (stripped / unused in the target) — the caller skips
/// attachment then.
#[derive(Clone, Copy, Debug, Default)]
pub struct LuaOffsets {
    pub lua_resume: u64,
    pub lua_pcallk: u64,
    pub lua_callk: u64,
}

pub struct LuaModule {
    pub path: PathBuf,
    pub version: LuaVersion,
    pub offsets: LuaOffsets,
}

/// Locate the Lua runtime attached to `pid` and the entry points we probe.
///
/// `forced_path` and `forced_version` (set by `--lua-module` / `--lua-version`)
/// short-circuit auto-discovery. Otherwise the lookup walks:
///   0. the explicit path (if given);
///   1. every executable mapping whose name contains "lua" (dynamic-lib fast
///      path — `liblua5.4.so`, `lua5.3`, ...);
///   2. the main executable (statically linked Lua);
///   3. every remaining executable file-backed mapping.
///
/// Each candidate is gated by a successful `scan_lua_symbols`, so false
/// positives (e.g. `libdbus` matching "lua" by accident) are rejected cheaply.
pub fn find_lua_module(
    pid: i32,
    forced_path: Option<&Path>,
    forced_version: Option<LuaVersion>,
) -> Result<LuaModule> {
    if let Some(p) = forced_path {
        return module_from_path(p, forced_version)
            .with_context(|| format!("--lua-module {}", p.display()));
    }

    let mut tried: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    // Stage 1: mappings whose name suggests Lua (cheap filter; gated by scan).
    for path in lua_named_maps(pid)? {
        if seen.insert(path.clone()) {
            match module_from_path(&path, forced_version) {
                Ok(m) => return Ok(m),
                Err(_) => tried.push(path),
            }
        }
    }

    // Stage 2: the main executable — covers statically linked Lua.
    let exe_res = fs::read_link(format!("/proc/{pid}/exe"));
    if let Ok(exe) = exe_res {
        let exe = strip_deleted(&exe);
        if seen.insert(exe.clone()) {
            match module_from_path(&exe, forced_version) {
                Ok(m) => return Ok(m),
                Err(_) => tried.push(exe),
            }
        }
    }

    // Stage 3: any remaining executable file-backed mapping.
    for path in all_exec_maps(pid)? {
        if seen.insert(path.clone()) {
            match module_from_path(&path, forced_version) {
                Ok(m) => return Ok(m),
                Err(_) => tried.push(path),
            }
        }
    }

    bail!(
        "no Lua 5.2/5.3/5.4 runtime found for pid {pid}. \
         Tried: {}. \
         If the binary embeds Lua statically, the main executable is scanned \
         automatically — usually only --lua-version 5.2|5.3|5.4 is needed \
         (when stripped / LTO-gc'd of version sentinels). Use --lua-module \
         PATH only if auto-discovery picks the wrong ELF. At least one of \
         lua_resume / lua_pcallk / lua_callk must survive in the symbol \
         table for us to uprobe.",
        tried
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

#[derive(Default)]
struct LuaSymbols {
    lua_resume: Option<u64>,
    lua_pcallk: Option<u64>,
    lua_callk: Option<u64>,
    is_luajit: bool,
    has_v54_sentinel: bool,
    has_v53_sentinel: bool,
    has_v52_sentinel: bool,
}

fn scan_lua_symbols(path: &Path) -> Result<LuaSymbols> {
    let bytes = fs::read(path)?;
    let elf = object::File::parse(bytes.as_slice())?;
    let mut out = LuaSymbols::default();
    for sym in elf.symbols().chain(elf.dynamic_symbols()) {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name_bytes() else {
            continue;
        };
        // one symbol per arm; cheaper than a hashset for so few names
        let vaddr = sym.address();
        macro_rules! assign {
            ($field:ident) => {
                if name == stringify!($field).as_bytes() {
                    out.$field = vaddr_to_file_offset(&elf, vaddr).ok();
                    continue;
                }
            };
        }
        assign!(lua_resume);
        assign!(lua_pcallk);
        assign!(lua_callk);
        match name {
            // LuaJIT: reject up front, its internals are entirely different.
            b"luaJIT_setmode" => out.is_luajit = true,
            // Lua 5.4-only (added after 5.3): resetthread signature change,
            // closethread, cstacklimit, and the toclose/warning/getiuservalue
            // family.
            b"lua_resetthread" | b"lua_closethread" | b"lua_setcstacklimit" => {
                out.has_v54_sentinel = true;
            }
            b"lua_toclose" | b"lua_warning" | b"lua_getiuservalue" => {
                out.has_v54_sentinel = true;
            }
            // Lua 5.3-only: lua_stringtonumber was added in 5.3.
            b"lua_stringtonumber" => out.has_v53_sentinel = true,
            // Lua 5.2-only sentinel: lua_getctx was removed in 5.3 (the
            // continuation context moved into CallInfo). cpcall and
            // pushglobaltable are also 5.2-era but they exist as macros in
            // later versions and aren't reliable ELF symbols — getctx is.
            b"lua_getctx" => out.has_v52_sentinel = true,
            _ => {}
        }
    }
    Ok(out)
}

fn module_from_path(path: &Path, forced_version: Option<LuaVersion>) -> Result<LuaModule> {
    let syms = scan_lua_symbols(path)?;
    if syms.is_luajit {
        bail!(
            "{} embeds LuaJIT, which is not supported (only PUC Lua 5.2/5.3/5.4)",
            path.display()
        );
    }
    // lua_resume is the *preferred* entry hook (it's what gives us the
    // lua_State* for coroutines), but lua_pcallk and lua_callk also drive
    // execution. Statically linked + LTO-gc'd binaries may keep pcallk while
    // dropping resume, so accept any one of the three.
    if syms.lua_resume.is_none() && syms.lua_pcallk.is_none() && syms.lua_callk.is_none() {
        bail!(
            "no lua_resume / lua_pcallk / lua_callk symbol in {} \
             — need at least one Lua entry point to attach",
            path.display()
        );
    }
    let version = match forced_version {
        Some(v) => v,
        None => detect_version(&syms, path)?,
    };
    Ok(LuaModule {
        path: path.to_path_buf(),
        version,
        offsets: LuaOffsets {
            lua_resume: syms.lua_resume.unwrap_or(0),
            lua_pcallk: syms.lua_pcallk.unwrap_or(0),
            lua_callk: syms.lua_callk.unwrap_or(0),
        },
    })
}

fn detect_version(syms: &LuaSymbols, path: &Path) -> Result<LuaVersion> {
    if syms.has_v54_sentinel {
        return Ok(LuaVersion::Lua54);
    }
    if syms.has_v53_sentinel {
        return Ok(LuaVersion::Lua53);
    }
    if syms.has_v52_sentinel {
        return Ok(LuaVersion::Lua52);
    }
    version_from_name(path).ok_or_else(|| {
        anyhow!(
            "cannot determine Lua version of {} \
             (no version-specific symbols found — likely stripped or LTO-gc'd); \
             pass --lua-version 5.2|5.3|5.4",
            path.display()
        )
    })
}

fn version_from_name(path: &Path) -> Option<LuaVersion> {
    let name = path.file_name()?.to_str()?.to_lowercase();
    // Order matters: most-specific first. Accept `lua5.4`, `lua-5.4`,
    // `lua.so.5.4`, `lua5.4.so.0`, etc.
    for (needle, ver) in [
        ("5.4", LuaVersion::Lua54),
        ("5.3", LuaVersion::Lua53),
        ("5.2", LuaVersion::Lua52),
    ] {
        if name.contains(&format!("lua{needle}"))
            || name.contains(&format!("lua-{needle}"))
            || name.contains(&format!("lua.so.{needle}"))
        {
            return Some(ver);
        }
    }
    None
}

/// Convert a symbol's virtual address to its ELF file offset (what uprobe
/// attachment expects) via the executable PT_LOAD segment containing it.
fn vaddr_to_file_offset(elf: &object::File<'_>, vaddr: u64) -> Result<u64> {
    const PF_X: u32 = 1;
    for seg in elf.segments() {
        let SegmentFlags::Elf { p_flags } = seg.flags() else {
            continue;
        };
        let p_vaddr = seg.address();
        let p_memsz = seg.size();
        if (p_flags & PF_X) != 0 && p_vaddr <= vaddr && vaddr < p_vaddr.saturating_add(p_memsz) {
            let (p_offset, _) = seg.file_range();
            return Ok(vaddr - p_vaddr + p_offset);
        }
    }
    Err(anyhow!(
        "symbol vaddr {vaddr:#x} is not inside an executable PT_LOAD segment"
    ))
}

fn lua_named_maps(pid: i32) -> Result<Vec<PathBuf>> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in parse_maps(&maps) {
        if !m.executable {
            continue;
        }
        let Some(p) = m.path.as_deref() else { continue };
        if !p.to_lowercase().contains("lua") {
            continue;
        }
        if seen.insert(p.to_string()) {
            out.push(PathBuf::from(p));
        }
    }
    Ok(out)
}

fn all_exec_maps(pid: i32) -> Result<Vec<PathBuf>> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in parse_maps(&maps) {
        if !m.executable {
            continue;
        }
        let Some(p) = m.path.as_deref() else { continue };
        if seen.insert(p.to_string()) {
            out.push(PathBuf::from(p));
        }
    }
    Ok(out)
}

/// `/proc/<pid>/exe` and maps paths may carry a trailing " (deleted)" when
/// the underlying file was replaced; strip it so fs::read can find the file.
fn strip_deleted(p: &Path) -> PathBuf {
    match p.to_str() {
        Some(s) => PathBuf::from(s.strip_suffix(" (deleted)").unwrap_or(s)),
        None => p.to_path_buf(),
    }
}

// anyhow::Context is re-exported via anyhow; pull the trait into scope here.
#[allow(unused_imports)]
use anyhow::Context as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_accepts_known() {
        assert_eq!(LuaVersion::parse("5.2").unwrap(), LuaVersion::Lua52);
        assert_eq!(LuaVersion::parse("5.3").unwrap(), LuaVersion::Lua53);
        assert_eq!(LuaVersion::parse("5.4").unwrap(), LuaVersion::Lua54);
    }

    #[test]
    fn parse_version_rejects_unknown() {
        assert!(LuaVersion::parse("5.1").is_err());
        assert!(LuaVersion::parse("5.5").is_err());
        assert!(LuaVersion::parse("luajit").is_err());
        assert!(LuaVersion::parse("").is_err());
    }

    #[test]
    fn version_from_name_matches_substrings() {
        assert_eq!(
            version_from_name(Path::new("/usr/lib/liblua5.4.so.0")),
            Some(LuaVersion::Lua54)
        );
        assert_eq!(
            version_from_name(Path::new("/usr/lib/liblua5.3.so.0")),
            Some(LuaVersion::Lua53)
        );
        assert_eq!(
            version_from_name(Path::new("/usr/lib/lua-5.2.so")),
            Some(LuaVersion::Lua52)
        );
        assert_eq!(
            version_from_name(Path::new("/usr/lib/x86_64-linux-gnu/liblua5.4.so.0")),
            Some(LuaVersion::Lua54)
        );
    }

    #[test]
    fn version_from_name_returns_none_for_unrelated() {
        assert_eq!(version_from_name(Path::new("/bin/sh")), None);
        assert_eq!(version_from_name(Path::new("/usr/lib/liblua.so")), None);
    }

    #[test]
    fn detect_version_prefers_sentinels_over_name() {
        // 5.4 sentinel wins even though the file name says "5.3" (e.g. a
        // distro that ships 5.4 as liblua5.3-compat — pathological but the
        // symbol is authoritative).
        let syms = LuaSymbols {
            has_v54_sentinel: true,
            ..Default::default()
        };
        assert_eq!(
            detect_version(&syms, Path::new("/usr/lib/lua5.3")).unwrap(),
            LuaVersion::Lua54
        );
    }

    #[test]
    fn detect_version_53_then_52_by_sentinel() {
        let s53 = LuaSymbols {
            has_v53_sentinel: true,
            ..Default::default()
        };
        assert_eq!(
            detect_version(&s53, Path::new("/x/anything")).unwrap(),
            LuaVersion::Lua53
        );
        let s52 = LuaSymbols {
            has_v52_sentinel: true,
            ..Default::default()
        };
        assert_eq!(
            detect_version(&s52, Path::new("/x/anything")).unwrap(),
            LuaVersion::Lua52
        );
    }

    #[test]
    fn detect_version_falls_back_to_name_then_error() {
        // No sentinels, but name has "lua5.2".
        let syms = LuaSymbols::default();
        assert_eq!(
            detect_version(&syms, Path::new("/usr/lib/liblua5.2.so")).unwrap(),
            LuaVersion::Lua52
        );
        // No sentinels and an uninformative name -> error.
        let err = detect_version(&syms, Path::new("/usr/bin/myapp")).unwrap_err();
        assert!(format!("{err}").contains("--lua-version"));
    }
}
