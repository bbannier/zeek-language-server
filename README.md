# Language server for Zeek script

This project implements a
[language server](https://microsoft.github.io/language-server-protocol/)
for [Zeek](https://zeek.org/) script.

This is pre-alpha software with lots of bugs which implements almost no useful
features.

## Installation

In order to see symbols from Zeek system scripts, Zeek needs to be installed
and `zeek-config` should be in `PATH`.

### Editor setup

#### vscode

We provide a [minimal extension for
vscode](https://github.com/bbannier/zeek-language-server/tree/main/vscode). An
extension VSIX file is created for each
[release](https://github.com/bbannier/zeek-language-server/releases). On
startup the extension will automatically download the server binary for the
release.

#### Other editors

We provide [binaries for
releases](https://github.com/bbannier/zeek-language-server/releases) for x86_64
Darwin or Linux systems. You should then set up your client to use this binary.
A list of editor plugins can be found e.g.,
[here](https://langserver.org/#implementations-client).

## Building from source

This project requires Rust to build which can be set up e.g., with [rustup] and
[tree-sitter](https://tree-sitter.github.io/) CLI tools.

The project can then be installed with

```sh
# Also available in many distribution repositories.
cargo install tree-sitter-cli

# Install actual server.
cargo install --git https://github.com/bbannier/zeek-language-server.git
```

This installs a binary `zeek-language-server` which provides the full server.

[rustup]: https://rustup.rs
