// LOW-008 (commit 080): build.rs gates the protoc-required path
// behind a runtime-detectable flag. When protoc is missing, the
// crate emits a stub `arxia.rs` AND defines `cfg(arxia_proto_stub)`
// so downstream callers (and tests) can detect the stub mode at
// compile time and either skip protoc-dependent paths or surface
// a deliberate error. This makes the silent-stub fallback
// auditable.
fn main() {
    let protoc_available = std::process::Command::new("protoc")
        .arg("--version")
        .output()
        .is_ok();

    if protoc_available {
        prost_build::compile_protos(&["proto/arxia.proto", "proto/transport.proto"], &["proto/"])
            .expect("Failed to compile protobuf definitions");
        println!("cargo:rustc-cfg=arxia_proto_real");
    } else {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        for stub_file in ["arxia.rs", "arxia.transport.rs"] {
            let path = std::path::Path::new(&out_dir).join(stub_file);
            std::fs::write(&path, "// protoc not found - stub generated\n").unwrap();
        }
        println!("cargo:rustc-cfg=arxia_proto_stub");
        println!("cargo:warning=protoc not found, using stub protobuf module (LOW-008: cfg=arxia_proto_stub set)");
    }

    // LOW-008: declare the cfg flags so rustc doesn't warn about
    // unknown ones on stable Rust 1.80+ (where unexpected_cfgs
    // is now lint-warned by default).
    println!("cargo:rustc-check-cfg=cfg(arxia_proto_real)");
    println!("cargo:rustc-check-cfg=cfg(arxia_proto_stub)");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto/arxia.proto");
    println!("cargo:rerun-if-changed=proto/transport.proto");
}
