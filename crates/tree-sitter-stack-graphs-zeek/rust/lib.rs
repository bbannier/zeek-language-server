use anyhow::Result;
use tree_sitter_stack_graphs::{
    loader::{FileAnalyzers, LanguageConfiguration},
    CancellationFlag,
};

/// The stack graphs query for this language
pub const STACK_GRAPHS_TSG_SOURCE: &str = include_str!("../src/stack-graphs.tsg");

/// The stack graphs builtins configuration for this language
pub const STACK_GRAPHS_BUILTINS_CONFIG: &str = include_str!("../src/builtins.cfg");
/// The stack graphs builtins source for this language
pub const STACK_GRAPHS_BUILTINS_SOURCE: &str = include_str!("../src/builtins.zeek");

/// A language configuration for this language.
///
/// # Errors
///
/// Returns an error if the configuration cannot be created.
pub fn language_configuration(
    cancellation_flag: &dyn CancellationFlag,
) -> Result<LanguageConfiguration> {
    LanguageConfiguration::from_tsg_str(
        tree_sitter_zeek::language_zeek(),
        Some(String::from("source.zeek")),
        None,
        vec![String::from("zeek")],
        STACK_GRAPHS_TSG_SOURCE,
        Some(STACK_GRAPHS_BUILTINS_SOURCE),
        Some(STACK_GRAPHS_BUILTINS_CONFIG),
        FileAnalyzers::new(),
        cancellation_flag,
    )
    .map_err(Into::into)
}
