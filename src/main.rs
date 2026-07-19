//! lua-flame-rs: eBPF-based Lua 5.2 / 5.3 / 5.4 CPU flame-graph profiler.

mod lineresolve;
mod perf;
mod syms;
mod types;
mod unwind;

use anyhow::{anyhow, bail, Context, Result};
use blazesym::symbolize::source::{Process, Source};
use blazesym::symbolize::{Input, Symbolized, Symbolizer};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    PerfBuffer, PerfBufferBuilder,
};
use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lineresolve::{LineResolver, ProtoLayout};
use syms::{LuaModule, LuaVersion};
use types::{LuaStackEvent, NativeEvent, SampleKey, FUNC_TYPE_C, FUNC_TYPE_LCF, FUNC_TYPE_LUA};
use unwind::{NativeSample, UserUnwinder};

mod profile {
    include!(concat!(env!("OUT_DIR"), "/profile.skel.rs"));
}
use profile::{ProfileSkel, ProfileSkelBuilder};

#[derive(Parser, Debug)]
#[command(version, about = "eBPF-based Lua 5.2/5.3/5.4 flame graph profiler")]
struct Args {
    #[arg(short, long)]
    pid: i32,
    #[arg(short = 'F', long, default_value_t = 99)]
    frequency: u64,
    #[arg(short, long, default_value_t = 0)]
    duration: u64,
    /// Include native C frames in addition to Lua frames.
    #[arg(long)]
    include_c_stacks: bool,
    /// Override Lua-module auto-discovery. The main executable and any
    /// mapping whose name contains "lua" are scanned automatically, so
    /// statically linked Lua does NOT need this flag. Use only when
    /// auto-discovery picks the wrong ELF (multiple Lua modules loaded,
    /// non-obvious path) — the target ELF must export at least one of
    /// lua_resume / lua_pcallk / lua_callk.
    #[arg(long, value_name = "PATH")]
    lua_module: Option<PathBuf>,
    /// Force the Lua version instead of auto-detection. Required when the
    /// target is stripped (or LTO-gc'd) so the version sentinels are gone.
    #[arg(long, value_name = "5.2|5.3|5.4", value_parser = parse_lua_version)]
    lua_version: Option<LuaVersion>,
    #[arg(short, long, default_value = "folded.txt")]
    output: String,
}

fn parse_lua_version(s: &str) -> Result<LuaVersion, String> {
    LuaVersion::parse(s).map_err(|e| format!("{e}"))
}

/// Version-dependent offsets the BPF walker needs (filled into rodata before
/// load). See docs/multi-version.md for the full table and how each was
/// derived from the upstream Lua headers.
struct WalkerOffsets {
    state_ci: u32,
    ci_savedpc: u32,
    ci_callstatus: u32,
    callstatus_mask: u32,
    lua_frame_mask: u32,
    lua_frame_when_set: u32,
    proto_linedefined: u32,
    proto_source: u32,
}

fn walker_offsets(v: LuaVersion) -> WalkerOffsets {
    match v {
        // Lua 5.4: CIST_C (bit 1) set => C frame; callstatus is u16.
        LuaVersion::Lua54 => WalkerOffsets {
            state_ci: 32,
            ci_savedpc: 32,
            ci_callstatus: 62,
            callstatus_mask: 0xffff,
            lua_frame_mask: 0x2,
            lua_frame_when_set: 0,
            proto_linedefined: 44,
            proto_source: 112,
        },
        // Lua 5.3: CIST_LUA (bit 1) set => Lua frame (same semantics as 5.2,
        // inverted relative to 5.4's CIST_C). callstatus is still u16 here.
        LuaVersion::Lua53 => WalkerOffsets {
            state_ci: 32,
            ci_savedpc: 40,
            ci_callstatus: 66,
            callstatus_mask: 0xffff,
            lua_frame_mask: 0x2,
            lua_frame_when_set: 1,
            proto_linedefined: 40,
            proto_source: 104,
        },
        // Lua 5.2: CIST_LUA = bit 0; set => Lua frame; callstatus is u8.
        LuaVersion::Lua52 => WalkerOffsets {
            state_ci: 32,
            ci_savedpc: 56,
            ci_callstatus: 34,
            callstatus_mask: 0xff,
            lua_frame_mask: 0x1,
            lua_frame_when_set: 1,
            proto_linedefined: 104,
            proto_source: 72,
        },
    }
}

static EXITING: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
struct NativeUnwindStats {
    succeeded: u64,
    fallback: u64,
    snapshot_truncated: u64,
    depth_limited: u64,
}

/// Perf-buffer drop counters. Surfaced so that silent sample loss under load
/// is observable; a non-zero `lost_*` at shutdown means the flame graph is
/// missing samples (and the user should lower `--frequency`, raise
/// `buffer_pages`, or both).
#[derive(Default)]
struct LostStats {
    native: u64,
    lua: u64,
}

/// Aggregated in-flight samples keyed by (pid, tid, seq).
///
/// Memory model: native + Lua events arrive in the same perf-buffer drain
/// cycle for a given sample. To resolve `Proto*` pointers while they are
/// still live in the target (before the function returns and the GC reclaims
/// the closure), samples are processed incrementally — one poll cycle after
/// the native half arrived — rather than held until shutdown.
#[derive(Default)]
struct Pending {
    native: HashMap<SampleKey, Vec<u64>>,
    lua: HashMap<SampleKey, Vec<LuaStackEvent>>,
    /// Keys whose native half arrived in the *current* poll cycle. They get
    /// one extra cycle (≤ poll_timeout) for their Lua siblings to land
    /// before being processed.
    just_arrived: HashSet<SampleKey>,
    /// Symmetric watermark for the Lua side: a Lua half that arrived this
    /// cycle gets one extra cycle for its native sibling. If the native half
    /// never shows up (perf-buffer loss on the native channel), the Lua
    /// event is folded against an empty native stack the cycle after — not
    /// held until shutdown. Bounds memory under sustained native loss.
    lua_just_arrived: HashSet<SampleKey>,
    folded: HashMap<String, u64>,
    unwind_stats: NativeUnwindStats,
    lost: LostStats,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let include_native_stacks = args.include_c_stacks;

    let module = syms::find_lua_module(args.pid, args.lua_module.as_deref(), args.lua_version)
        .with_context(|| format!("locating lua runtime for pid {}", args.pid))?;
    let offs = module.offsets;
    println!(
        "[+] pid {} -> {} (Lua {})\n    lua_resume={:#x} lua_pcallk={:#x} lua_callk={:#x}",
        args.pid,
        module.path.display(),
        module.version.as_str(),
        offs.lua_resume,
        offs.lua_pcallk,
        offs.lua_callk
    );

    let user_unwinder = create_user_unwinder(args.pid, include_native_stacks);

    bump_memlock_rlimit()?;

    let mut object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let skel = load_bpf(&mut object, args.pid, include_native_stacks, module.version)?;

    let links = attach_lua_probes(&skel, &module)?;
    let perf_links = attach_perf_events(&skel, args.frequency)?;

    let pending = Arc::new(Mutex::new(Pending::default()));
    let (pb_native, pb_lua) =
        build_perf_buffers(&skel, &pending, user_unwinder, include_native_stacks)?;

    let mut processor =
        SampleProcessor::new(pending, args.pid, module.version, include_native_stacks);
    let poll_result = capture_samples(
        &pb_native,
        &pb_lua,
        args.frequency,
        args.duration,
        &mut processor,
    );
    drop(pb_native);
    drop(pb_lua);

    processor.finish();
    let folded = processor.take_folded();
    write_capture_outputs(
        &folded,
        std::path::Path::new(&args.output),
        module.version,
        include_native_stacks,
    )?;

    drop(links);
    drop(perf_links);
    poll_result
}

fn create_user_unwinder(pid: i32, include_native_stacks: bool) -> Option<UserUnwinder> {
    if !include_native_stacks {
        return None;
    }
    match UserUnwinder::new(pid) {
        Ok(unwinder) => {
            println!(
                "[+] loaded DWARF unwind data for {} native modules",
                unwinder.module_count()
            );
            Some(unwinder)
        }
        Err(error) => {
            eprintln!(
                "[!] user-space DWARF unwinder unavailable: {error:#}; using bpf_get_stack fallback"
            );
            None
        }
    }
}

fn load_bpf<'obj>(
    object: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    pid: i32,
    include_native_stacks: bool,
    version: LuaVersion,
) -> Result<ProfileSkel<'obj>> {
    let open_skel = ProfileSkelBuilder::default().open(object)?;
    open_skel.maps.rodata_data.targ_pid = pid;
    open_skel.maps.rodata_data.collect_native_stacks = include_native_stacks;
    let w = walker_offsets(version);
    open_skel.maps.rodata_data.loff_state_ci = w.state_ci;
    open_skel.maps.rodata_data.loff_ci_savedpc = w.ci_savedpc;
    open_skel.maps.rodata_data.loff_ci_callstatus = w.ci_callstatus;
    open_skel.maps.rodata_data.loff_callstatus_mask = w.callstatus_mask;
    open_skel.maps.rodata_data.loff_lua_frame_mask = w.lua_frame_mask;
    open_skel.maps.rodata_data.loff_lua_frame_when_set = w.lua_frame_when_set;
    open_skel.maps.rodata_data.loff_proto_linedefined = w.proto_linedefined;
    open_skel.maps.rodata_data.loff_proto_source = w.proto_source;
    Ok(open_skel.load()?)
}

fn attach_lua_probes(skel: &ProfileSkel<'_>, module: &LuaModule) -> Result<Vec<libbpf_rs::Link>> {
    // Attach whichever entry points survived dynamic/static linking. Keeping
    // this in one place makes the entry/return pairing explicit.
    let offs = module.offsets;
    let mut links = Vec::new();
    let prog_entry = &skel.progs.handle_entry_lua;
    if offs.lua_resume != 0 {
        links.push(prog_entry.attach_uprobe(false, -1, &module.path, offs.lua_resume as usize)?);
    }
    if offs.lua_pcallk != 0 {
        links.push(prog_entry.attach_uprobe(false, -1, &module.path, offs.lua_pcallk as usize)?);
    }
    if offs.lua_callk != 0 {
        links.push(prog_entry.attach_uprobe(false, -1, &module.path, offs.lua_callk as usize)?);
    }
    if offs.lua_resume != 0 {
        links.push(skel.progs.handle_return_lua.attach_uprobe(
            true,
            -1,
            &module.path,
            offs.lua_resume as usize,
        )?);
    }
    if offs.lua_pcallk != 0 {
        links.push(skel.progs.handle_return_lua.attach_uprobe(
            true,
            -1,
            &module.path,
            offs.lua_pcallk as usize,
        )?);
    }
    if offs.lua_callk != 0 {
        links.push(skel.progs.handle_return_lua.attach_uprobe(
            true,
            -1,
            &module.path,
            offs.lua_callk as usize,
        )?);
    }

    if links.is_empty() {
        bail!(
            "no Lua entry-point uprobes were attached (expected at least one of \
             lua_resume / lua_pcallk / lua_callk in {})",
            module.path.display()
        );
    }
    Ok(links)
}

fn attach_perf_events(skel: &ProfileSkel<'_>, frequency: u64) -> Result<Vec<libbpf_rs::Link>> {
    let nr_cpus = libbpf_rs::num_possible_cpus()?;
    let mut links = Vec::with_capacity(nr_cpus);
    for cpu in 0..nr_cpus as i32 {
        let fd = perf::open_cpu_clock(frequency, cpu)?;
        links.push(skel.progs.do_perf_event.attach_perf_event(fd)?);
    }
    Ok(links)
}

fn build_perf_buffers<'skel>(
    skel: &'skel ProfileSkel<'_>,
    pending: &Arc<Mutex<Pending>>,
    user_unwinder: Option<UserUnwinder>,
    include_native_stacks: bool,
) -> Result<(PerfBuffer<'skel>, PerfBuffer<'skel>)> {
    let native_samples = pending.clone();
    let lua_samples = pending.clone();
    let native_loss = pending.clone();
    let lua_loss = pending.clone();
    let mut callback_unwinder = user_unwinder;

    let native = PerfBufferBuilder::new(&skel.maps.native_events)
        .pages(64)
        .sample_cb(move |_cpu, data: &[u8]| {
            if let Some(event) = native_event_from_bytes(data) {
                handle_native(
                    &event,
                    &native_samples,
                    callback_unwinder.as_mut(),
                    include_native_stacks,
                );
            }
        })
        .lost_cb(move |_cpu, count| {
            native_loss.lock().unwrap().lost.native += count;
        })
        .build()?;

    let lua = PerfBufferBuilder::new(&skel.maps.lua_events_out)
        .pages(64)
        .sample_cb(move |_cpu, data: &[u8]| {
            if let Some(event) = from_bytes_aligned::<LuaStackEvent>(data) {
                handle_lua(event, &lua_samples);
            }
        })
        .lost_cb(move |_cpu, count| {
            lua_loss.lock().unwrap().lost.lua += count;
        })
        .build()?;

    Ok((native, lua))
}

struct SampleProcessor {
    pending: Arc<Mutex<Pending>>,
    resolver: Option<LineResolver>,
    source: Source<'static>,
    symbolizer: Symbolizer,
    include_native_stacks: bool,
}

impl SampleProcessor {
    fn new(
        pending: Arc<Mutex<Pending>>,
        pid: i32,
        version: LuaVersion,
        include_native_stacks: bool,
    ) -> Self {
        // Resolve Proto->lineinfo while sampled Proto pointers are still live.
        let resolver = LineResolver::new(pid, ProtoLayout::for_version(version))
            .map_err(|error| {
                eprintln!(
                    "[!] line resolver unavailable: {error}; Lua lines will fall back to linedefined"
                );
                error
            })
            .ok();
        let source = Source::Process(Process {
            pid: (pid as u32).into(),
            debug_syms: true,
            perf_map: false,
            map_files: false,
            vdso: false,
            _non_exhaustive: (),
        });
        Self {
            pending,
            resolver,
            source,
            symbolizer: Symbolizer::new(),
            include_native_stacks,
        }
    }

    fn fold_ready(&mut self) {
        process_ready_samples(
            &self.pending,
            self.resolver.as_mut(),
            &self.source,
            &self.symbolizer,
            self.include_native_stacks,
        );
        // Bound memory when the native perf buffer loses a sample counterpart.
        drain_lua_orphans(
            &self.pending,
            self.resolver.as_mut(),
            &self.source,
            &self.symbolizer,
            self.include_native_stacks,
        );
    }

    fn process_cycle(&mut self) {
        self.fold_ready();
        advance_watermarks(&self.pending);
    }

    fn finish(&mut self) {
        // Two passes promote and then consume records from the final poll.
        advance_watermarks(&self.pending);
        self.fold_ready();
        advance_watermarks(&self.pending);
        self.fold_ready();
    }

    fn take_folded(&self) -> HashMap<String, u64> {
        let mut pending = self.pending.lock().unwrap();
        if self.include_native_stacks {
            println!(
                "[+] user-space DWARF unwind: {} succeeded, {} fell back, {} snapshots exhausted, {} hit the {}-frame limit",
                pending.unwind_stats.succeeded,
                pending.unwind_stats.fallback,
                pending.unwind_stats.snapshot_truncated,
                pending.unwind_stats.depth_limited,
                types::PERF_MAX_STACK_DEPTH
            );
        }
        if pending.lost.native != 0 || pending.lost.lua != 0 {
            eprintln!(
                "[!] perf-buffer records lost: native={}, lua={} \
                 (consider lowering --frequency)",
                pending.lost.native, pending.lost.lua
            );
        }
        std::mem::take(&mut pending.folded)
    }
}

fn capture_samples(
    native: &PerfBuffer,
    lua: &PerfBuffer,
    frequency: u64,
    duration: u64,
    processor: &mut SampleProcessor,
) -> Result<()> {
    println!(
        "[+] sampling at {} Hz for {} ...",
        frequency,
        if duration == 0 {
            "ever".into()
        } else {
            format!("{duration}s")
        }
    );
    install_ctrlc();
    let start = std::time::Instant::now();
    while !EXITING.load(Ordering::SeqCst) {
        native
            .poll(Duration::from_millis(100))
            .map_err(|error| anyhow!("native perf-buffer poll failed: {error}"))?;
        lua.poll(Duration::from_millis(100))
            .map_err(|error| anyhow!("lua perf-buffer poll failed: {error}"))?;
        processor.process_cycle();
        if duration > 0 && start.elapsed() >= Duration::from_secs(duration) {
            break;
        }
    }
    Ok(())
}

fn write_capture_outputs(
    folded: &HashMap<String, u64>,
    output: &std::path::Path,
    version: LuaVersion,
    include_native_stacks: bool,
) -> Result<()> {
    write_folded(folded, output)?;
    let svg = output.with_extension("svg");
    let title = if include_native_stacks {
        format!("lua-flame-rs (C + Lua {})", version.as_str())
    } else {
        format!("lua-flame-rs (Lua {} only)", version.as_str())
    };
    match make_svg(output, &svg, &title) {
        Ok(()) => println!("[+] flame graph SVG: {}", svg.display()),
        Err(error) => println!("[!] SVG generation failed: {error}"),
    }
    Ok(())
}

fn from_bytes_aligned<T: plain::Plain + Default>(data: &[u8]) -> Option<T> {
    let sz = std::mem::size_of::<T>();
    if data.len() < sz {
        return None;
    }
    let mut val = T::default();
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), &mut val as *mut T as *mut u8, sz);
    }
    Some(val)
}

fn native_event_from_bytes(data: &[u8]) -> Option<NativeEvent> {
    let prefix_size = std::mem::size_of::<NativeEvent>() - types::USER_STACK_SNAPSHOT_SIZE;
    if data.len() < prefix_size {
        return None;
    }
    let mut event = NativeEvent::default();
    let copy_len = data.len().min(std::mem::size_of::<NativeEvent>());
    unsafe {
        std::ptr::copy_nonoverlapping(
            data.as_ptr(),
            &mut event as *mut NativeEvent as *mut u8,
            copy_len,
        );
    }
    event.stack_len = event
        .stack_len
        .min(data.len().saturating_sub(prefix_size) as u32);
    Some(event)
}

fn handle_native(
    ne: &NativeEvent,
    p: &Mutex<Pending>,
    unwinder: Option<&mut UserUnwinder>,
    collect_native_stacks: bool,
) {
    let sample = NativeSample::from_event(ne);
    let (ips, unwind_result) = if let Some(unwinder) = unwinder {
        let attempt = unwinder.unwind(&sample);
        let succeeded = attempt.ips.is_some();
        let ips = attempt.ips.unwrap_or_else(|| sample.fallback_ips.to_vec());
        (
            ips,
            Some((succeeded, attempt.snapshot_truncated, attempt.depth_limited)),
        )
    } else {
        (sample.fallback_ips.to_vec(), None)
    };
    let mut g = p.lock().unwrap();
    g.native.insert(ne.key, ips);
    g.just_arrived.insert(ne.key);
    if let Some((succeeded, snapshot_truncated, depth_limited)) = unwind_result {
        g.unwind_stats.succeeded += u64::from(succeeded);
        g.unwind_stats.fallback += u64::from(!succeeded);
        g.unwind_stats.snapshot_truncated += u64::from(snapshot_truncated);
        g.unwind_stats.depth_limited += u64::from(depth_limited);
    } else if collect_native_stacks {
        g.unwind_stats.fallback += 1;
    }
}

fn handle_lua(le: LuaStackEvent, p: &Mutex<Pending>) {
    let mut g = p.lock().unwrap();
    g.lua.entry(le.key).or_default().push(le);
    g.lua_just_arrived.insert(le.key);
}

/// Fold every sample whose native half arrived in a *previous* poll cycle.
///
/// The watermark is `pending.just_arrived`: keys inserted this cycle get one
/// extra poll (≤ 100ms) for their Lua siblings to land, then become eligible.
/// This bounds in-flight memory to roughly `frequency * 0.1s` samples and —
/// more importantly — resolves `Proto->lineinfo` while the target's `Proto*`
/// is still live, instead of long after the function has returned and the
/// closure may have been GC'd.
fn process_ready_samples(
    pending: &Mutex<Pending>,
    mut resolver: Option<&mut LineResolver>,
    src: &Source,
    sym: &Symbolizer,
    include_c_stacks: bool,
) {
    let ready: Vec<SampleKey> = {
        let g = pending.lock().unwrap();
        g.native
            .keys()
            .filter(|k| !g.just_arrived.contains(*k))
            .copied()
            .collect()
    };
    if ready.is_empty() {
        // Nothing eligible this cycle. Per-key watermark entries stay put —
        // each in-flight key needs exactly one cycle of grace, regardless of
        // what other keys are doing. A blanket clear() here would let keys
        // whose Lua/native half just arrived be drained prematurely.
        return;
    }
    // We need the resolver mutable; split it out of pending so we don't hold
    // the pending lock across /proc/<pid>/mem reads.
    let mut g = pending.lock().unwrap();
    let mut folded_acc: Vec<(String, u64)> = Vec::with_capacity(ready.len());
    for &key in &ready {
        let Some(ips) = g.native.remove(&key) else {
            continue;
        };
        let mut lua = g.lua.remove(&key).unwrap_or_default();
        if let Some(r) = resolver.as_mut() {
            for ev in lua.iter_mut() {
                if ev.r#type == FUNC_TYPE_LUA && ev.line == 0 {
                    ev.line = r.resolve(ev.proto, ev.savedpc, ev.linedefined);
                }
            }
        }
        // This key is fully consumed; drop its watermark entries so they
        // don't outlive the data they were protecting.
        g.just_arrived.remove(&key);
        g.lua_just_arrived.remove(&key);
        if let Some(stack) = build_stack(&ips, &lua, src, sym, include_c_stacks) {
            folded_acc.push((stack, 1));
        }
    }
    for (stack, n) in folded_acc {
        *g.folded.entry(stack).or_insert(0) += n;
    }
}

/// Drain Lua events whose native half never arrived (perf-buffer loss on
/// the native side but not the Lua side), folded against an empty native
/// stack so we don't silently drop Lua-only samples.
///
/// Called every poll cycle AND at shutdown. Each call folds Lua events that
/// have been waiting for at least one cycle (i.e. are NOT in
/// `lua_just_arrived`) and still have no native counterpart. This bounds
/// `Pending.lua` even under sustained native-channel loss — without it, a
/// `--duration 0` run with native loss would accumulate Lua orphans linearly
/// until shutdown.
fn drain_lua_orphans(
    pending: &Mutex<Pending>,
    mut resolver: Option<&mut LineResolver>,
    src: &Source,
    sym: &Symbolizer,
    include_c_stacks: bool,
) {
    let orphan_keys: Vec<SampleKey> = {
        let g = pending.lock().unwrap();
        g.lua
            .keys()
            .filter(|k| !g.lua_just_arrived.contains(*k) && !g.native.contains_key(*k))
            .copied()
            .collect()
    };
    if orphan_keys.is_empty() {
        return;
    }
    let mut g = pending.lock().unwrap();
    let mut folded_acc: Vec<(String, u64)> = Vec::new();
    for &key in &orphan_keys {
        let Some(mut lua) = g.lua.remove(&key) else {
            continue;
        };
        if let Some(r) = resolver.as_mut() {
            for ev in lua.iter_mut() {
                if ev.r#type == FUNC_TYPE_LUA && ev.line == 0 {
                    ev.line = r.resolve(ev.proto, ev.savedpc, ev.linedefined);
                }
            }
        }
        g.lua_just_arrived.remove(&key);
        if let Some(stack) = build_stack(&[], &lua, src, sym, include_c_stacks) {
            folded_acc.push((stack, 1));
        }
    }
    for (stack, n) in folded_acc {
        *g.folded.entry(stack).or_insert(0) += n;
    }
}

/// Promote this cycle's arrivals to next-cycle eligibility. MUST be called
/// after process_ready_samples + drain_lua_orphans so a key whose Lua or
/// native half just arrived gets exactly one cycle of grace before becoming
/// eligible for either path.
fn advance_watermarks(pending: &Mutex<Pending>) {
    let mut g = pending.lock().unwrap();
    g.just_arrived.clear();
    g.lua_just_arrived.clear();
}

fn build_stack(
    ips: &[u64],
    lua: &[LuaStackEvent],
    src: &Source,
    sym: &Symbolizer,
    include_c_stacks: bool,
) -> Option<String> {
    let mut native_frames: Vec<Option<String>> = Vec::new();

    if include_c_stacks {
        for &ip in ips.iter().rev() {
            if ip == 0 {
                continue;
            }
            match sym.symbolize_single(src, Input::AbsAddr(ip)) {
                Ok(Symbolized::Sym(s)) if is_native_function_symbol(&s.name) => {
                    native_frames.push(Some(format!("{}+{:#x}", s.name, s.offset)));
                }
                _ => native_frames.push(None),
            }
        }
    }
    fold_symbolized_stack(&native_frames, lua, include_c_stacks)
}

fn is_native_function_symbol(name: &str) -> bool {
    !name.is_empty()
        && !matches!(
            name,
            "$a" | "$d" | "$t" | "$x" | "$a.0" | "$d.0" | "$t.0" | "$x.0"
        )
        && !name
            .strip_prefix('$')
            .and_then(|name| name.split_once('.'))
            .is_some_and(|(kind, suffix)| {
                matches!(kind, "a" | "d" | "t" | "x")
                    && !suffix.is_empty()
                    && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
}

fn fold_symbolized_stack(
    native_frames: &[Option<String>],
    lua: &[LuaStackEvent],
    include_c_stacks: bool,
) -> Option<String> {
    let mut frames: Vec<String> = Vec::new();
    let mut lua_idx = 0usize;
    let lua_sorted: Vec<LuaStackEvent> = {
        let mut v: Vec<LuaStackEvent> = lua.to_vec();
        v.sort_by_key(|e| std::cmp::Reverse(e.level));
        v
    };

    for native in native_frames {
        if let Some(name) = native {
            if include_c_stacks {
                frames.push(name.clone());
            }
        } else if lua_idx < lua_sorted.len() {
            if let Some(frame) = format_lua_frame(&lua_sorted[lua_idx], include_c_stacks) {
                frames.push(frame);
            }
            lua_idx += 1;
        } else if include_c_stacks {
            frames.push("[unknown]".into());
        }
    }
    while lua_idx < lua_sorted.len() {
        if let Some(frame) = format_lua_frame(&lua_sorted[lua_idx], include_c_stacks) {
            frames.push(frame);
        }
        lua_idx += 1;
    }
    if frames.is_empty() {
        None
    } else {
        Some(frames.join(";"))
    }
}

fn format_lua_frame(ev: &LuaStackEvent, include_c_stacks: bool) -> Option<String> {
    match ev.r#type {
        FUNC_TYPE_LUA => {
            let chunk = strip_chunkname(&ev.name_str());
            if ev.line > 0 {
                Some(format!("L:{}:{}", chunk, ev.line))
            } else if !chunk.is_empty() {
                Some(format!("L:{}", chunk))
            } else {
                None
            }
        }
        FUNC_TYPE_C | FUNC_TYPE_LCF => {
            // Belt-and-suspenders: BPF already drops these when native stack
            // collection is disabled. If one slips through (stale binary,
            // partial reload, etc.) honour the user's --include-c-stacks
            // choice here too.
            if include_c_stacks {
                Some(format!("C:{:#x}", ev.funcp))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn strip_chunkname(s: &str) -> String {
    let s = s.trim_start_matches('\0');
    let s = s.strip_prefix('@').unwrap_or(s);
    s.rsplit('/').next().unwrap_or(s).to_string()
}

fn write_folded(folded: &HashMap<String, u64>, out: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut keys: Vec<&String> = folded.keys().collect();
    keys.sort();
    for k in keys {
        writeln!(f, "{} {}", k, folded[k])?;
    }
    println!(
        "[+] wrote {} unique stacks to {}",
        folded.len(),
        out.display()
    );
    Ok(())
}

fn make_svg(folded: &std::path::Path, svg: &std::path::Path, title: &str) -> Result<()> {
    use inferno::flamegraph::{from_files, Options};
    let mut opts = Options::default();
    opts.title = title.to_string();
    from_files(
        &mut opts,
        &[folded.to_path_buf()],
        std::fs::File::create(svg)?,
    )
    .map_err(|e| anyhow!("inferno: {e}"))?;
    Ok(())
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("[!] setrlimit(RLIMIT_MEMLOCK) failed: {err}; continuing");
    }
    Ok(())
}

fn install_ctrlc() {
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handle_sigint as *const () as usize;
        libc::sigemptyset(&mut act.sa_mask);
        libc::sigaction(libc::SIGINT, &act, std::ptr::null_mut());
    }
}

extern "C" fn handle_sigint(_sig: libc::c_int) {
    EXITING.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lua_event(key: SampleKey, level: i32, name: &str, line: i32) -> LuaStackEvent {
        let mut ev = LuaStackEvent {
            key,
            level,
            r#type: FUNC_TYPE_LUA,
            line,
            ..LuaStackEvent::default()
        };
        let bytes = name.as_bytes();
        let n = bytes.len().min(ev.name.len() - 1);
        ev.name[..n].copy_from_slice(&bytes[..n]);
        ev
    }

    #[test]
    fn cli_defaults_to_lua_only() {
        let args = Args::try_parse_from(["lua-flame-rs", "--pid", "42"]).unwrap();

        assert!(!args.include_c_stacks);
    }

    #[test]
    fn cli_enables_c_and_lua_stacks_explicitly() {
        let args =
            Args::try_parse_from(["lua-flame-rs", "--pid", "42", "--include-c-stacks"]).unwrap();

        assert!(args.include_c_stacks);
    }

    #[test]
    fn folded_stack_uses_lua_root_to_leaf_order() {
        let key = SampleKey {
            pid: 10,
            tid: 20,
            seq: 1,
        };
        let lua = [
            lua_event(key, 0, "@leaf.lua", 30),
            lua_event(key, 2, "@root.lua", 10),
            lua_event(key, 1, "@mid.lua", 20),
        ];
        let native = [
            Some("entry+0x0".to_string()),
            None,
            Some("tail+0x4".to_string()),
        ];

        let folded = fold_symbolized_stack(&native, &lua, true).unwrap();

        assert_eq!(
            folded,
            "entry+0x0;L:root.lua:10;tail+0x4;L:mid.lua:20;L:leaf.lua:30"
        );
    }

    #[test]
    fn folded_stack_default_drops_native_but_keeps_lua() {
        let key = SampleKey {
            pid: 10,
            tid: 20,
            seq: 2,
        };
        let lua = [lua_event(key, 0, "@/srv/app.lua", 42)];
        let native = [Some("native+0x1".to_string()), None];

        let folded = fold_symbolized_stack(&native, &lua, false).unwrap();

        assert_eq!(folded, "L:app.lua:42");
    }

    #[test]
    fn arm_mapping_symbols_are_not_rendered_as_functions() {
        for name in ["$a", "$d", "$t", "$x", "$x.0", "$d.123"] {
            assert!(!is_native_function_symbol(name), "accepted {name}");
        }
        for name in ["main", "luaV_execute", "$x.data", "$custom"] {
            assert!(is_native_function_symbol(name), "rejected {name}");
        }
    }

    #[test]
    fn pending_uses_tid_as_part_of_sample_key() {
        let pending = Mutex::new(Pending::default());
        let k1 = SampleKey {
            pid: 100,
            tid: 11,
            seq: 1,
        };
        let k2 = SampleKey {
            pid: 100,
            tid: 12,
            seq: 1,
        };
        let mut ne1 = NativeEvent {
            key: k1,
            ip_cnt: 1,
            ..NativeEvent::default()
        };
        ne1.ips[0] = 0x1111;
        let mut ne2 = NativeEvent {
            key: k2,
            ip_cnt: 1,
            ..NativeEvent::default()
        };
        ne2.ips[0] = 0x2222;

        handle_native(&ne1, &pending, None, false);
        handle_native(&ne2, &pending, None, false);
        handle_lua(lua_event(k1, 0, "@one.lua", 1), &pending);
        handle_lua(lua_event(k2, 0, "@two.lua", 2), &pending);

        let guard = pending.lock().unwrap();
        assert_eq!(guard.native[&k1], vec![0x1111]);
        assert_eq!(guard.native[&k2], vec![0x2222]);
        assert_eq!(guard.lua[&k1][0].name_str(), "@one.lua");
        assert_eq!(guard.lua[&k2][0].name_str(), "@two.lua");
    }

    #[test]
    fn native_event_parser_accepts_snapshot_free_prefix() {
        let mut event = NativeEvent {
            key: SampleKey {
                pid: 1,
                tid: 2,
                seq: 3,
            },
            ip_cnt: 1,
            ..NativeEvent::default()
        };
        event.ips[0] = 0x1234;
        let prefix_size = std::mem::size_of::<NativeEvent>() - types::USER_STACK_SNAPSHOT_SIZE;
        let bytes = unsafe {
            std::slice::from_raw_parts(&event as *const NativeEvent as *const u8, prefix_size)
        };

        let parsed = native_event_from_bytes(bytes).unwrap();

        assert_eq!(parsed.key, event.key);
        assert_eq!(parsed.ips[0], 0x1234);
        assert_eq!(parsed.stack_len, 0);
        assert!(parsed.stack.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn lua_frame_formatting_handles_known_types() {
        let key = SampleKey::default();
        let lua = lua_event(key, 0, "@/a/b/c.lua", 99);
        assert_eq!(format_lua_frame(&lua, true).unwrap(), "L:c.lua:99");

        let c = LuaStackEvent {
            r#type: FUNC_TYPE_C,
            funcp: 0x1234,
            ..LuaStackEvent::default()
        };
        assert_eq!(format_lua_frame(&c, true).unwrap(), "C:0x1234");

        let lcf = LuaStackEvent {
            r#type: FUNC_TYPE_LCF,
            funcp: 0x5678,
            ..LuaStackEvent::default()
        };
        assert_eq!(format_lua_frame(&lcf, true).unwrap(), "C:0x5678");
    }

    #[test]
    fn lua_frame_formatting_drops_empty_lua_frames() {
        let empty = LuaStackEvent {
            r#type: FUNC_TYPE_LUA,
            line: 0,
            ..LuaStackEvent::default()
        };

        assert_eq!(format_lua_frame(&empty, true), None);
    }

    #[test]
    fn lua_only_mode_drops_c_and_lcf_frames() {
        // Regression: without --include-c-stacks, FUNC_TYPE_C and
        // FUNC_TYPE_LCF events must NOT appear in the folded stack. Catches
        // both the BPF collect_native_stacks gate and the belt-and-suspenders
        // user-space filter in format_lua_frame.
        let c = LuaStackEvent {
            r#type: FUNC_TYPE_C,
            funcp: 0x1234,
            ..LuaStackEvent::default()
        };
        let lcf = LuaStackEvent {
            r#type: FUNC_TYPE_LCF,
            funcp: 0x5678,
            ..LuaStackEvent::default()
        };
        assert_eq!(format_lua_frame(&c, false), None);
        assert_eq!(format_lua_frame(&lcf, false), None);

        // And the full fold path: a C frame slot in native_frames + a C/LCF
        // Lua event must yield a pure-Lua stack with no "C:" frames.
        let key = SampleKey {
            pid: 1,
            tid: 2,
            seq: 3,
        };
        let lua = [
            LuaStackEvent {
                key,
                level: 1,
                r#type: FUNC_TYPE_C,
                funcp: 0xabcd,
                ..LuaStackEvent::default()
            },
            lua_event(key, 0, "@root.lua", 10),
        ];
        let folded = fold_symbolized_stack(&[None, None], &lua, false).unwrap();
        assert!(!folded.contains("C:"), "folded contains C frame: {folded}");
        assert_eq!(folded, "L:root.lua:10");
    }

    #[test]
    fn walker_offsets_54_matches_lstate_h() {
        let w = walker_offsets(LuaVersion::Lua54);
        assert_eq!(w.state_ci, 32);
        assert_eq!(w.ci_savedpc, 32);
        assert_eq!(w.ci_callstatus, 62);
        assert_eq!(w.callstatus_mask, 0xffff);
        assert_eq!(w.proto_linedefined, 44);
        assert_eq!(w.proto_source, 112);
    }

    #[test]
    fn walker_offsets_53_savedpc_and_callstatus_moved() {
        let w = walker_offsets(LuaVersion::Lua53);
        assert_eq!(w.ci_savedpc, 40);
        assert_eq!(w.ci_callstatus, 66);
        assert_eq!(w.proto_linedefined, 40);
        assert_eq!(w.proto_source, 104);
        // 5.3 uses CIST_LUA (bit 1) set => Lua frame — same semantics as
        // 5.2, NOT 5.4's inverted CIST_C.
        assert_eq!(w.lua_frame_mask, 0x2);
        assert_eq!(w.lua_frame_when_set, 1);
    }

    #[test]
    fn walker_offsets_52_inverts_callstatus_semantics() {
        let w = walker_offsets(LuaVersion::Lua52);
        assert_eq!(w.ci_savedpc, 56);
        assert_eq!(w.ci_callstatus, 34);
        assert_eq!(w.callstatus_mask, 0xff); // u8, not u16
                                             // 5.2 uses CIST_LUA = bit 0; set => Lua frame (inverted relative to
                                             // 5.4's CIST_C).
        assert_eq!(w.lua_frame_mask, 0x1);
        assert_eq!(w.lua_frame_when_set, 1);
        assert_eq!(w.proto_linedefined, 104);
        assert_eq!(w.proto_source, 72);
    }

    #[test]
    fn walker_offsets_54_uses_cist_c_set_means_c_frame() {
        // 5.4 is the odd one out — CIST_C set means a C frame (when_set=0),
        // every other version inverts this.
        let w = walker_offsets(LuaVersion::Lua54);
        assert_eq!(w.lua_frame_mask, 0x2);
        assert_eq!(w.lua_frame_when_set, 0);
    }

    #[test]
    fn cli_accepts_lua_version_override() {
        let args =
            Args::try_parse_from(["lua-flame-rs", "--pid", "42", "--lua-version", "5.3"]).unwrap();
        assert_eq!(args.lua_version, Some(LuaVersion::Lua53));
    }

    #[test]
    fn cli_rejects_unsupported_lua_version() {
        let r = Args::try_parse_from(["lua-flame-rs", "--pid", "42", "--lua-version", "5.1"]);
        assert!(r.is_err());
    }

    #[test]
    fn cli_accepts_lua_module_path() {
        let args = Args::try_parse_from([
            "lua-flame-rs",
            "--pid",
            "42",
            "--lua-module",
            "/opt/app/bin/mylua",
        ])
        .unwrap();
        assert_eq!(
            args.lua_module.as_deref(),
            Some(std::path::Path::new("/opt/app/bin/mylua"))
        );
    }

    // ---- incremental aggregation helpers -----------------------------------
    //
    // These tests pin the watermark logic in process_ready_samples and the
    // orphan-drain path in drain_lua_orphans. Without them, a future edit to
    // just_arrived / lua_just_arrived handling could silently break
    // long-running captures (memory growth, dropped Lua frames) without
    // showing up in the rest of the suite.

    fn dummy_source(pid: u32) -> Source<'static> {
        Source::Process(Process {
            pid: pid.into(),
            debug_syms: true,
            perf_map: false,
            map_files: false,
            vdso: false,
            _non_exhaustive: (),
        })
    }

    fn native_event_with(key: SampleKey, ip: u64) -> NativeEvent {
        let mut ne = NativeEvent {
            key,
            ip_cnt: 1,
            ..NativeEvent::default()
        };
        ne.ips[0] = ip;
        ne
    }

    #[test]
    fn process_ready_samples_defers_first_cycle_then_folds() {
        // A native half arriving in cycle 1 must NOT be folded in cycle 1 —
        // its Lua siblings may not have drained yet. It must be folded in
        // cycle 2 (with the Lua events that arrived meanwhile).
        let pending = Mutex::new(Pending::default());
        let key = SampleKey {
            pid: 1,
            tid: 2,
            seq: 7,
        };
        let src = dummy_source(1);
        let sym = Symbolizer::new();

        // Cycle 1: native arrives (marked just_arrived), Lua also arrives.
        handle_native(&native_event_with(key, 0xdead), &pending, None, false);
        handle_lua(lua_event(key, 0, "@app.lua", 42), &pending);

        // After cycle 1: nothing should be folded yet.
        process_ready_samples(&pending, None, &src, &sym, false);
        advance_watermarks(&pending);
        {
            let g = pending.lock().unwrap();
            assert!(g.folded.is_empty(), "folded prematurely in cycle 1");
            assert!(g.native.contains_key(&key), "native half drained too early");
            assert!(g.lua.contains_key(&key), "lua half drained too early");
        }

        // Cycle 2: now eligible, and the Lua half is still there to be
        // folded with it.
        process_ready_samples(&pending, None, &src, &sym, false);
        {
            let g = pending.lock().unwrap();
            assert_eq!(g.folded.len(), 1, "expected exactly one folded stack");
            assert_eq!(g.folded["L:app.lua:42"], 1);
            assert!(!g.native.contains_key(&key), "native half not drained");
            assert!(!g.lua.contains_key(&key), "lua half not drained");
        }
    }

    #[test]
    fn process_ready_samples_drops_c_frames_in_lua_only_mode() {
        // End-to-end: a sample whose CallInfo walk would have produced a
        // C-frame event (FUNC_TYPE_C) must not leak into a Lua-only folded
        // stack through process_ready_samples. (BPF already filters these
        // via collect_native_stacks; this is the user-space backstop.)
        let pending = Mutex::new(Pending::default());
        let key = SampleKey {
            pid: 1,
            tid: 2,
            seq: 1,
        };
        let src = dummy_source(1);
        let sym = Symbolizer::new();

        handle_native(&native_event_with(key, 0xcafe), &pending, None, false);
        // Mixed CallInfo: a C closure plus the leaf Lua frame.
        handle_lua(
            LuaStackEvent {
                key,
                level: 1,
                r#type: FUNC_TYPE_C,
                funcp: 0xbeef,
                ..LuaStackEvent::default()
            },
            &pending,
        );
        handle_lua(lua_event(key, 0, "@root.lua", 11), &pending);

        // Cycle 1 just arrived; cycle 2 folds (advance_watermarks between
        // them is what promotes cycle 1's arrivals to eligibility).
        process_ready_samples(&pending, None, &src, &sym, false);
        advance_watermarks(&pending);
        process_ready_samples(&pending, None, &src, &sym, false);
        let folded = {
            let g = pending.lock().unwrap();
            g.folded.keys().cloned().collect::<Vec<_>>()
        };
        assert_eq!(folded, vec!["L:root.lua:11".to_string()]);
    }

    #[test]
    fn drain_lua_orphans_runs_every_cycle_under_sustained_loss() {
        // Sustained native-channel loss must NOT accumulate Lua orphans
        // until shutdown — drain_lua_orphans is called every cycle so a
        // `--duration 0` long run stays bounded.
        let pending = Mutex::new(Pending::default());
        let key1 = SampleKey {
            pid: 1,
            tid: 2,
            seq: 1,
        };
        let key2 = SampleKey {
            pid: 1,
            tid: 2,
            seq: 2,
        };
        let src = dummy_source(1);
        let sym = Symbolizer::new();

        // Cycle 1: orphan Lua arrives (no native). Still in lua_just_arrived
        // so not yet eligible — advance_watermarks only promotes AFTER both
        // fold passes have run.
        handle_lua(lua_event(key1, 0, "@/x/lost1.lua", 1), &pending);
        process_ready_samples(&pending, None, &src, &sym, false);
        drain_lua_orphans(&pending, None, &src, &sym, false);
        advance_watermarks(&pending);
        {
            let g = pending.lock().unwrap();
            assert!(g.folded.is_empty(), "orphan folded in its arrival cycle");
            assert!(g.lua.contains_key(&key1));
        }

        // Cycle 2: key1 now eligible, gets folded. A second orphan arrives.
        handle_lua(lua_event(key2, 0, "@/x/lost2.lua", 2), &pending);
        process_ready_samples(&pending, None, &src, &sym, false);
        drain_lua_orphans(&pending, None, &src, &sym, false);
        advance_watermarks(&pending);
        {
            let g = pending.lock().unwrap();
            assert_eq!(g.folded.get("L:lost1.lua:1"), Some(&1));
            assert!(!g.lua.contains_key(&key1), "key1 not drained in cycle 2");
            // key2 still has one cycle of grace.
            assert!(g.lua.contains_key(&key2));
        }

        // Cycle 3: key2 folded.
        drain_lua_orphans(&pending, None, &src, &sym, false);
        let g = pending.lock().unwrap();
        assert_eq!(g.folded.get("L:lost2.lua:2"), Some(&1));
        assert!(g.lua.is_empty());
    }

    #[test]
    fn drain_lua_orphans_skips_keys_with_live_native_half() {
        // A key that has BOTH halves in flight (Lua waiting on the watermark,
        // native waiting on its own watermark) must NOT be folded by
        // drain_lua_orphans — it's the native-channel-loss path, and once
        // the native half becomes ready it should drive the fold via
        // process_ready_samples (which includes the Lua frames).
        let pending = Mutex::new(Pending::default());
        let key = SampleKey {
            pid: 1,
            tid: 2,
            seq: 5,
        };
        let src = dummy_source(1);
        let sym = Symbolizer::new();

        // Both halves arrive in the same cycle.
        handle_native(&native_event_with(key, 0x1234), &pending, None, false);
        handle_lua(lua_event(key, 0, "@app.lua", 99), &pending);

        // Even after the Lua watermark clears (cycle 2), the presence of the
        // native half in `native` must keep this key off the orphan path.
        drain_lua_orphans(&pending, None, &src, &sym, false);
        advance_watermarks(&pending);
        drain_lua_orphans(&pending, None, &src, &sym, false);
        {
            let g = pending.lock().unwrap();
            assert!(g.folded.is_empty(), "live-native key folded as orphan");
            assert!(g.lua.contains_key(&key));
            assert!(g.native.contains_key(&key));
        }

        // And process_ready_samples handles it correctly once eligible.
        advance_watermarks(&pending);
        process_ready_samples(&pending, None, &src, &sym, false);
        let g = pending.lock().unwrap();
        assert_eq!(g.folded.get("L:app.lua:99"), Some(&1));
    }

    #[test]
    fn process_ready_samples_is_idempotent_when_nothing_in_flight() {
        // Calling the helpers on an empty Pending must be a no-op (e.g. when
        // the target is idle between samples); this guards a regression
        // where just_arrived.clear() might run twice on the same cycle and
        // accidentally promote stragglers.
        let pending = Mutex::new(Pending::default());
        let src = dummy_source(1);
        let sym = Symbolizer::new();
        for _ in 0..3 {
            process_ready_samples(&pending, None, &src, &sym, false);
            drain_lua_orphans(&pending, None, &src, &sym, false);
            advance_watermarks(&pending);
        }
        let g = pending.lock().unwrap();
        assert!(g.folded.is_empty());
        assert!(g.native.is_empty());
        assert!(g.lua.is_empty());
        assert!(g.just_arrived.is_empty());
        assert!(g.lua_just_arrived.is_empty());
    }
}
