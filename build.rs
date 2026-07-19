// Build script: compiles the eBPF C program and generates the Rust skeleton.
use libbpf_cargo::SkeletonBuilder;
use std::path::PathBuf;

fn main() {
    let bpf_src = PathBuf::from("bpf/profile.bpf.c");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let obj_out = PathBuf::from(&out_dir).join("profile.bpf.o");
    let skel_out = PathBuf::from(&out_dir).join("profile.skel.rs");

    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    let (bpf_arch, multiarch_include) = match target_arch.as_str() {
        "x86_64" => ("x86", "x86_64-linux-gnu"),
        "aarch64" => ("arm64", "aarch64-linux-gnu"),
        other => panic!("unsupported target architecture for BPF build: {other}"),
    };

    let clang_args: Vec<String> = vec![
        "-g".into(),
        "-O2".into(),
        "-target".into(),
        "bpf".into(),
        format!("-D__TARGET_ARCH_{bpf_arch}"),
        format!("-I/usr/include/{multiarch_include}"),
        "-Ibpf".into(),
    ];

    let mut builder = SkeletonBuilder::new();
    let result = builder
        .source(bpf_src.clone())
        .obj(&obj_out)
        .clang_args(&clang_args)
        .build_and_generate(&skel_out);

    if let Err(e) = result {
        panic!("skeleton generation failed: {e}");
    }

    println!("cargo:rerun-if-changed={}", bpf_src.display());
    println!("cargo:rerun-if-changed=bpf/lua_state.h");
    println!("cargo:rerun-if-changed=bpf/common.h");
    println!("cargo:rerun-if-changed=bpf/vmlinux.h");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
}
