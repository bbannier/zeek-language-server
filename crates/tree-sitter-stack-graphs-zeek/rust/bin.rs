// -*- coding: utf-8 -*-
// ------------------------------------------------------------------------------------------------
// Copyright © 2022, stack-graphs authors.
// Licensed under either of Apache License, Version 2.0, or MIT license, at your option.
// Please see the LICENSE-APACHE or LICENSE-MIT files in this distribution for license details.
// ------------------------------------------------------------------------------------------------

use tree_sitter_stack_graphs::cli::LanguageConfigurationsCli as Cli;
use tree_sitter_stack_graphs::NoCancellation;

fn main() -> anyhow::Result<()> {
    Cli::main(vec![tree_sitter_stack_graphs_zeek::language_configuration(
        &NoCancellation,
    )])
}
