use std::{
    env::{self, current_dir},
    path::PathBuf,
    process::Command,
    str::FromStr,
};

use cc::Build;

fn main() {
    let grammar = current_dir()
        .unwrap()
        .join("vendor")
        .join("tree-sitter-zeek")
        .join("grammar.js");

    println!("cargo:rerun-if-changed=vendor/tree-sitter-zeek/grammar.js");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Run `tree-sitter generate`.
    assert!(Command::new("tree-sitter")
        .arg("generate")
        .arg(&grammar)
        .current_dir(&out_dir)
        .status()
        .expect("failed to generate tree-sitter bindings")
        .success());

    // Compile tree-sitter C output.
    let src_dir = out_dir.join("src");

    Build::new()
        .file(src_dir.join("parser.c"))
        .include(out_dir.join("src"))
        .warnings(false)
        .compile("tree-sitter-zeek");
}
