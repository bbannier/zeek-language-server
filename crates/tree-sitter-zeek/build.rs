use cc::Build;
use regex::Regex;
use std::{
    collections::HashSet,
    env::{self},
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

fn generate_keywords(grammar: &Path) {
    let file = File::open(grammar).unwrap();
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents).unwrap();

    let mut set: HashSet<String> = HashSet::new();
    let re = Regex::new(r"'(@?&?[a-z]+-?_?[a-z]+)'").unwrap();
    for cap in re.captures_iter(&contents) {
        if cap[1].eq("zeek") || cap[1].eq("extras") {
            continue;
        }
        set.insert(cap[1].to_string());
    }

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("keywords.rs");

    let source = std::format!(
        "
    pub static KEYWORDS: [&str; {}] = [{}];",
        set.len(),
        set.iter()
            .map(|keyword| format!("{:#?}", &keyword))
            .collect::<Vec<_>>()
            .join(", ")
    );

    fs::write(dest_path, source).unwrap();

    println!("cargo:rerun-if-changed=vendor/tree-sitter-zeek/grammar.js");
}

fn main() {
    let grammar = PathBuf::from("vendor")
        .join("tree-sitter-zeek")
        .join("grammar.js");

    println!("cargo:rerun-if-changed={}", grammar.to_str().unwrap());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    tree_sitter_generate::generate_parser_in_directory(
        &out_dir,
        Some(grammar.to_str().unwrap()),
        tree_sitter::LANGUAGE_VERSION,
        None,
        None,
    )
    .expect("could not generate parser");

    // Compile tree-sitter C output.
    let src_dir = out_dir.join("src");

    Build::new()
        .file(src_dir.join("parser.c"))
        .include(out_dir.join("src"))
        .warnings(false)
        .compile("tree-sitter-zeek");

    generate_keywords(&grammar);
}
