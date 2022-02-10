# Language server for Zeek script

This project implements a
[language server](https://microsoft.github.io/language-server-protocol/)
for [Zeek](https://zeek.org/) script.

This is pre-alpha software which implements almost no useful features.

## Installation

This project requires Rust which can be set up e.g., with [rustup].

The project can then be installed with

```.console
cargo install --git https://github.com/bbannier/zeek-language-server.git
```

This installs a binary `zeek-language-server` which provides the full server.

[rustup]: https://rustup.rs
