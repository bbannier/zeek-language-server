# Language server for Zeek script

This project implements a
[language server](https://microsoft.github.io/language-server-protocol/)
for [Zeek](https://zeek.org/) script.

This is pre-alpha software with lots of bugs which implements almost no useful
features.

## Installation

This project requires Rust which can be set up e.g., with [rustup] and
[tree-sitter](https://tree-sitter.github.io/) CLI tools.

The project can then be installed with

```sh
# Also available in many distribution repositories.
cargo install tree-sitter-cli

# Install actual server.
cargo install --git https://github.com/bbannier/zeek-language-server.git
```

This installs a binary `zeek-language-server` which provides the full server.

We also provide a [minimal extension for vscode](vscode/README.md).

[rustup]: https://rustup.rs
