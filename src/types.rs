//! Mirror of the C-side `common.h` shared between eBPF and user space.

use plain::Plain;

pub const CHUNKNAME_LEN: usize = 128;
pub const PERF_MAX_STACK_DEPTH: usize = 32;
pub const USER_STACK_SNAPSHOT_SIZE: usize = 4096;

pub const FUNC_TYPE_LUA: i32 = 0;
pub const FUNC_TYPE_C: i32 = 1;
pub const FUNC_TYPE_LCF: i32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct SampleKey {
    pub pid: u32,
    pub tid: u32,
    pub seq: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NativeEvent {
    pub key: SampleKey,
    pub ip_cnt: u32,
    pub stack_len: u32,
    pub ip: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
    pub ips: [u64; PERF_MAX_STACK_DEPTH],
    pub stack: [u8; USER_STACK_SNAPSHOT_SIZE],
}

impl Default for NativeEvent {
    fn default() -> Self {
        Self {
            key: SampleKey::default(),
            ip_cnt: 0,
            stack_len: 0,
            ip: 0,
            sp: 0,
            fp: 0,
            lr: 0,
            ips: [0; PERF_MAX_STACK_DEPTH],
            stack: [0; USER_STACK_SNAPSHOT_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LuaStackEvent {
    pub key: SampleKey,
    pub level: i32,
    pub r#type: i32,
    pub name: [u8; CHUNKNAME_LEN],
    pub funcp: u64,
    pub line: i32,
    pub proto: u64,
    pub savedpc: u64,
    pub linedefined: i32,
}

impl Default for LuaStackEvent {
    fn default() -> Self {
        Self {
            key: SampleKey::default(),
            level: 0,
            r#type: 0,
            name: [0; CHUNKNAME_LEN],
            funcp: 0,
            line: 0,
            proto: 0,
            savedpc: 0,
            linedefined: 0,
        }
    }
}

impl LuaStackEvent {
    pub fn name_str(&self) -> String {
        let n = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..n]).into_owned()
    }
}

unsafe impl Plain for NativeEvent {}
unsafe impl Plain for LuaStackEvent {}
