//! This crate provides a Zeek grammar for the [tree-sitter][] parsing library.
//!
//! Typically, you will use the [`language_zeek`][language func] function to add this grammar to a
//! tree-sitter [Parser][], and then use the parser to parse some code:
//!
//! ```
//! use tree_sitter::Parser;
//!
//! let code = r#"
//!     event foo(c: connection)
//!         {
//!         print c;
//!         }
//! "#;
//! let mut parser = Parser::new();
//! parser
//!     .set_language(&tree_sitter_zeek::language_zeek())
//!     .expect("Error loading Zeek grammar");
//! let parsed = parser.parse(code, None).unwrap();
//! let root = parsed.root_node();
//! assert!(!root.has_error());
//! ```
//!
//! [Language]: https://docs.rs/tree-sitter/*/tree_sitter/struct.Language.html
//! [language func]: fn.language_zeek.html
//! [Parser]: https://docs.rs/tree-sitter/*/tree_sitter/struct.Parser.html
//! [tree-sitter]: https://tree-sitter.github.io/

// This makes a constant `KEYWORDS` available which contains keywords of the language.
include!(concat!(env!("OUT_DIR"), "/keywords.rs"));

use tree_sitter::Language;

extern "C" {
    fn tree_sitter_zeek() -> Language;
}

/// Returns the tree-sitter [Language][] for Zeek.
///
/// [Language]: https://docs.rs/tree-sitter/*/tree_sitter/struct.Language.html
#[must_use]
pub fn language_zeek() -> Language {
    unsafe { tree_sitter_zeek() }
}

/// The syntax highlighting query for this language.
pub const HIGHLIGHT_QUERY: &str = include_str!("../vendor/tree-sitter-zeek/queries/highlights.scm");

// /// The local-variable syntax highlighting query for this language.
// pub const LOCALS_QUERY: &str = "";

// /// The symbol tagging query for this language.
// pub const TAGGING_QUERY: &str = "";

/// The content of the [`node-types.json`][] file for this grammar.
///
/// [`node-types.json`]: https://tree-sitter.github.io/tree-sitter/using-parsers#static-node-types
pub const ZEEK_NODE_TYPES: &str = include_str!(concat!(env!("OUT_DIR"), "/src/node-types.json"));
