use crate::types::{NativeEvent, PERF_MAX_STACK_DEPTH, USER_STACK_SNAPSHOT_SIZE};
use anyhow::{Context, Result};
use framehop::{
    CacheNative, ExplicitModuleSectionInfo, MayAllocateDuringUnwind, Module, UnwindRegsNative,
    Unwinder, UnwinderNative,
};
use object::read::{ObjectSection, ObjectSegment};
use object::File as ElfFile;
use object::Object;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSample<'a> {
    pub fallback_ips: &'a [u64],
    pub ip: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
    pub stack: &'a [u8],
}

impl<'a> NativeSample<'a> {
    pub fn from_event(event: &'a NativeEvent) -> Self {
        let ip_count = event.ip_cnt.min(PERF_MAX_STACK_DEPTH as u32) as usize;
        let stack_len = event.stack_len.min(USER_STACK_SNAPSHOT_SIZE as u32) as usize;
        Self {
            fallback_ips: &event.ips[..ip_count],
            ip: event.ip,
            sp: event.sp,
            fp: event.fp,
            lr: event.lr,
            stack: &event.stack[..stack_len],
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct UnwindAttempt {
    pub ips: Option<Vec<u64>>,
    pub snapshot_truncated: bool,
    pub depth_limited: bool,
}

pub struct UserUnwinder {
    unwinder: UnwinderNative<Vec<u8>, MayAllocateDuringUnwind>,
    cache: CacheNative<MayAllocateDuringUnwind>,
    module_count: usize,
}

impl UserUnwinder {
    pub fn new(pid: i32) -> Result<Self> {
        let maps_path = format!("/proc/{pid}/maps");
        let maps_text = fs::read_to_string(&maps_path)
            .with_context(|| format!("reading target mappings from {maps_path}"))?;
        let mappings = parse_maps(&maps_text);
        let page_size = page_size();
        let mut unwinder = UnwinderNative::<Vec<u8>, MayAllocateDuringUnwind>::new();
        let mut module_count = 0;

        let mut file_mappings: HashMap<FileId, Vec<&MapEntry>> = HashMap::new();
        for mapping in &mappings {
            if mapping.executable && mapping.path.is_some() {
                file_mappings
                    .entry(FileId::from_mapping(mapping))
                    .or_default()
                    .push(mapping);
            }
        }

        for mappings in file_mappings.into_values() {
            let Some(first) = mappings.first().copied() else {
                continue;
            };
            let Some(bytes) = read_mapped_file(pid, first, &mappings) else {
                continue;
            };
            let Ok(elf) = ElfFile::parse(bytes.as_slice()) else {
                continue;
            };
            if !is_native_architecture(elf.architecture()) {
                continue;
            }

            let load_biases: HashSet<u64> = mappings
                .iter()
                .filter_map(|mapping| load_bias_for_mapping(mapping, &elf, page_size))
                .collect();
            if load_biases.is_empty() {
                continue;
            }

            let sections = module_sections(&elf);
            if sections.eh_frame.is_none() && sections.debug_frame.is_none() {
                continue;
            }

            for load_bias in load_biases {
                let Some(avma_range) = module_avma_range(load_bias, &elf, page_size) else {
                    continue;
                };
                unwinder.add_module(Module::new(
                    first.path.as_deref().unwrap_or("[unknown]").to_string(),
                    avma_range,
                    load_bias,
                    sections.clone(),
                ));
                module_count += 1;
            }
        }

        Ok(Self {
            unwinder,
            cache: CacheNative::new(),
            module_count,
        })
    }

    pub fn module_count(&self) -> usize {
        self.module_count
    }

    pub fn unwind(&mut self, sample: &NativeSample<'_>) -> UnwindAttempt {
        if sample.ip == 0 || sample.sp == 0 {
            return UnwindAttempt::default();
        }
        if sample.stack.len() < 8 {
            return UnwindAttempt {
                snapshot_truncated: true,
                ..UnwindAttempt::default()
            };
        }

        let regs = native_regs(sample, self.unwinder.max_known_code_address());
        let mut snapshot_truncated = false;
        let mut read_stack = |address| {
            read_stack_word(sample.sp, sample.stack, address).map_err(|()| {
                snapshot_truncated = true;
            })
        };
        let mut frames = Vec::with_capacity(PERF_MAX_STACK_DEPTH);
        let mut iterator =
            self.unwinder
                .iter_frames(sample.ip, regs, &mut self.cache, &mut read_stack);

        let mut reached_depth_limit = false;
        loop {
            if frames.len() == PERF_MAX_STACK_DEPTH {
                reached_depth_limit = true;
                break;
            }
            match iterator.next() {
                Ok(Some(frame)) => frames.push(frame.address_for_lookup()),
                Ok(None) | Err(_) => break,
            }
        }

        UnwindAttempt {
            ips: (frames.len() >= 2).then_some(frames),
            snapshot_truncated,
            depth_limited: reached_depth_limit,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub executable: bool,
    pub device: String,
    pub inode: u64,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileId {
    device: String,
    inode: u64,
    path: String,
}

impl FileId {
    fn from_mapping(mapping: &MapEntry) -> Self {
        Self {
            device: mapping.device.clone(),
            inode: mapping.inode,
            path: mapping.path.clone().unwrap_or_default(),
        }
    }
}

pub(crate) fn parse_maps(contents: &str) -> Vec<MapEntry> {
    contents.lines().filter_map(parse_map_line).collect()
}

fn parse_map_line(line: &str) -> Option<MapEntry> {
    let mut fields = line.split_ascii_whitespace();
    let range = fields.next()?;
    let permissions = fields.next()?;
    let offset = u64::from_str_radix(fields.next()?, 16).ok()?;
    let device = fields.next()?.to_string();
    let inode = fields.next()?.parse().ok()?;
    let raw_path = fields.collect::<Vec<_>>().join(" ");
    let path = if raw_path.starts_with('/') {
        Some(
            unescape_maps_path(raw_path.strip_suffix(" (deleted)").unwrap_or(&raw_path))
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        None
    };
    let (start, end) = range.split_once('-')?;

    Some(MapEntry {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        offset,
        executable: permissions.as_bytes().get(2) == Some(&b'x'),
        device,
        inode,
        path,
    })
}

fn unescape_maps_path(path: &str) -> PathBuf {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let octal = &bytes[index + 1..index + 4];
            if octal.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
                decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + octal[2] - b'0');
                index += 4;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    PathBuf::from(String::from_utf8_lossy(&decoded).into_owned())
}

fn read_mapped_file(pid: i32, first: &MapEntry, mappings: &[&MapEntry]) -> Option<Vec<u8>> {
    let path = Path::new(first.path.as_deref()?);
    if let Ok(relative) = path.strip_prefix("/") {
        let root_path = PathBuf::from(format!("/proc/{pid}/root")).join(relative);
        if let Ok(bytes) = fs::read(root_path) {
            return Some(bytes);
        }
    }
    if let Ok(bytes) = fs::read(path) {
        return Some(bytes);
    }
    mappings.iter().find_map(|mapping| {
        fs::read(format!(
            "/proc/{pid}/map_files/{:x}-{:x}",
            mapping.start, mapping.end
        ))
        .ok()
    })
}

fn page_size() -> u64 {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as u64
    } else {
        4096
    }
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|value| align_down(value, alignment))
}

fn load_bias_for_mapping(mapping: &MapEntry, elf: &ElfFile<'_>, page_size: u64) -> Option<u64> {
    elf.segments().find_map(|seg| {
        let (p_offset, _) = seg.file_range();
        if align_down(p_offset, page_size) != mapping.offset {
            return None;
        }
        mapping
            .start
            .checked_sub(align_down(seg.address(), page_size))
    })
}

fn module_avma_range(load_bias: u64, elf: &ElfFile<'_>, page_size: u64) -> Option<Range<u64>> {
    let mut start = u64::MAX;
    let mut end = 0;
    for seg in elf.segments() {
        let p_vaddr = seg.address();
        let p_memsz = seg.size();
        start = start.min(align_down(p_vaddr, page_size));
        let segment_end = align_up(p_vaddr.checked_add(p_memsz)?, page_size)?;
        end = end.max(segment_end);
    }
    if start >= end {
        return None;
    }
    Some(load_bias.checked_add(start)?..load_bias.checked_add(end)?)
}

fn module_sections(elf: &ElfFile<'_>) -> ExplicitModuleSectionInfo<Vec<u8>> {
    let text_svma = section_range(elf, ".text");
    let got_svma = section_range(elf, ".got");
    let eh_frame_svma = section_range(elf, ".eh_frame");
    let eh_frame_hdr_svma = section_range(elf, ".eh_frame_hdr");
    ExplicitModuleSectionInfo {
        base_svma: 0,
        text_svma,
        got_svma,
        eh_frame: section_data(elf, ".eh_frame", false),
        eh_frame_svma,
        eh_frame_hdr: section_data(elf, ".eh_frame_hdr", false),
        eh_frame_hdr_svma,
        debug_frame: section_data(elf, ".debug_frame", true),
        ..Default::default()
    }
}

fn section_range(elf: &ElfFile<'_>, name: &str) -> Option<Range<u64>> {
    let section = elf.section_by_name(name)?;
    let end = section.address().checked_add(section.size())?;
    Some(section.address()..end)
}

fn section_data(elf: &ElfFile<'_>, name: &str, decompress: bool) -> Option<Vec<u8>> {
    let section = elf.section_by_name(name)?;
    if decompress {
        section
            .uncompressed_data()
            .ok()
            .map(|data| data.into_owned())
    } else {
        section.data().ok().map(ToOwned::to_owned)
    }
}

#[cfg(target_arch = "x86_64")]
fn is_native_architecture(architecture: object::Architecture) -> bool {
    architecture == object::Architecture::X86_64
}

#[cfg(target_arch = "aarch64")]
fn is_native_architecture(architecture: object::Architecture) -> bool {
    architecture == object::Architecture::Aarch64
}

#[cfg(target_arch = "x86_64")]
fn native_regs(sample: &NativeSample<'_>, _max_known_address: u64) -> UnwindRegsNative {
    UnwindRegsNative::new(sample.ip, sample.sp, sample.fp)
}

#[cfg(target_arch = "aarch64")]
fn native_regs(sample: &NativeSample<'_>, max_known_address: u64) -> UnwindRegsNative {
    use framehop::aarch64::PtrAuthMask;

    UnwindRegsNative::new_with_ptr_auth_mask(
        PtrAuthMask::from_max_known_address(max_known_address),
        sample.lr,
        sample.sp,
        sample.fp,
    )
}

fn read_stack_word(stack_base: u64, stack: &[u8], address: u64) -> Result<u64, ()> {
    let offset = address.checked_sub(stack_base).ok_or(())? as usize;
    let end = offset.checked_add(8).ok_or(())?;
    let bytes = stack.get(offset..end).ok_or(())?;
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| ())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_maps_file_mappings() {
        let maps = parse_maps(
            "00400000-00452000 r-xp 00000000 08:02 123 /usr/bin/app\n\
             7f000000-7f001000 rw-p 00001000 08:02 123 /usr/bin/app\n\
             7ffd0000-7ffd1000 r-xp 00000000 00:00 0 [vdso]\n",
        );

        assert_eq!(maps.len(), 3);
        assert_eq!(maps[0].start, 0x0040_0000);
        assert_eq!(maps[0].end, 0x0045_2000);
        assert!(maps[0].executable);
        assert_eq!(maps[0].path.as_deref(), Some("/usr/bin/app"));
        assert!(!maps[1].executable);
        assert_eq!(maps[2].path, None);
    }

    #[test]
    fn parses_deleted_and_escaped_paths() {
        let mapping =
            parse_map_line("1000-2000 r-xp 00000000 08:02 7 /tmp/a\\040file (deleted)").unwrap();

        assert_eq!(mapping.path.as_deref(), Some("/tmp/a file"));
    }

    #[test]
    fn reads_unaligned_words_inside_stack_snapshot() {
        let stack: Vec<u8> = (0..32).collect();

        assert_eq!(
            read_stack_word(0x1000, &stack, 0x1003),
            Ok(u64::from_le_bytes([3, 4, 5, 6, 7, 8, 9, 10]))
        );
        assert_eq!(read_stack_word(0x1000, &stack, 0x0fff), Err(()));
        assert_eq!(read_stack_word(0x1000, &stack, 0x1019), Err(()));
    }
}
