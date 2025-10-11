# Language server for Zeek script

This project implements a
[language server](https://microsoft.github.io/language-server-protocol/)
for [Zeek](https://zeek.org/) script.

This is alpha-quality software, especially regarding type resolution. While it
already now provides useful results, not all of Zeek script is resolved; we do
however strive to either correctly resolve symbols or not at all, i.e., if a
result is presented it should be correct.

## Installation

Binaries for a number of different platforms are hosted on
[GitHub](https://github.com/bbannier/zeek-language-server/releases/latest) and
can be installed with

```console
curl -L https://github.com/bbannier/zeek-language-server/releases/latest/download/zeek-language-server-installer.sh | sh
```

This also installs a binary which can be used to update the installation.

```console
$ zeek-language-server-update
Checking for updates...
Already up to date; not upgrading
```

Alternatively one can install the binary with a Python package manager, e.g.,
[`pipx`](https://pipx.pypa.io/)

```console
$ pipx install git+https://github.com/bbannier/zeek-language-server@t/wip
  installed package zeek-language-server 0.73.3, installed using Python 3.13.8
  These apps are now globally available
    - zeek-language-server
done! ✨ 🌟 ✨
```

### Building from source

This project requires Rust to build which can be set up e.g., with
[rustup](https://rustup.rs).

The project can then be installed with

```sh
cargo install --git https://github.com/bbannier/zeek-language-server.git
```

This installs a binary `zeek-language-server` which provides the full server.

## Setup

In order to see symbols from Zeek system scripts, Zeek needs to be installed
and `zeek-config` should be in `PATH`.

For optional formatting support
[`zeek-format`](https://github.com/zeek/zeekscript/) should be in `PATH`.

### Configuration

The server interprets the following `initializationOptions`:

- `inlay_hints_parameters` (default: `true`):
  Whether to show inlay hints for function call parameters
- `inlay_hints_variables` (default: `true`):
  Whether to show inlay hints for variable declarations
- `references` (default: `false`):
  Whether to enable _Go To References_.
- `rename` (default: `false`):
  Whether to enable _Rename_.
- `semantic_highlighting` (default: `true`)
  Enable semantic highlighting.

- `debug_ast_nodes` (default: `false`)
  Enable debug output of AST nodes on hover

  **WARNING**: Since typically Zeek scripts have incomplete `@load` statements
  the provided list is very likely incomplete. Use a tool like `grep` to search
  for all references of an identifier.

#### Editor setup

##### vscode

We provide a [minimal extension for
vscode](https://github.com/bbannier/zeek-language-server/tree/main/vscode)
which is [published to the vscode
marketplace](https://marketplace.visualstudio.com/items?itemName=bbannier.zeek-language-server).
Additionally, an extension VSIX file is created for each
[release](https://github.com/bbannier/zeek-language-server/releases). On
startup the extension will automatically download the server binary for the
release.

#### Emacs

For installation instructions on Emacs, see
[here](README.emacs.md).

#### JetBrains IDEs

For installation instructions on JetBrains IDEs, see
[here](README.intellij.md).

#### Other editors

We provide [binaries for
releases](https://github.com/bbannier/zeek-language-server/releases) for x86_64
Darwin or Linux systems. You should then set up your client to use this binary.
A list of editor plugins can be found e.g.,
[here](https://langserver.org/#implementations-client).

## Debugging

See [these instructions](./DEBUGGING.md) for VS Code setup and the list of
features (some of which are VS Code specific).

## Development

This server provides support for highlighting via [tree-sitter highlighting
queries](https://tree-sitter.github.io/tree-sitter/syntax-highlighting). To
tweak existing or for adding new queries one needs to edit the files in
[`crates/tree-sitter-zeek/vendor`](https://github.com/bbannier/zeek-language-server/tree/main/crates/tree-sitter-zeek/vendor),
and perform a bump of the submodule.
