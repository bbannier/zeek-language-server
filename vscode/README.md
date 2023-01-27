# Zeek language support for Visual Studio Code

Microsoft Visual Studio Code language extension for Zeek (Bro) Script.

## Features

- [x] IntelliSense (requires
      [zeek-language-server](https://github.com/bbannier/zeek-language-server))
- [x] Formatting (requires [zeek-format](https://github.com/zeek/zeekscript))
- [x] Syntax Highlighting
- [x] Snippets
- [x] Command to publish open file to <https://try.zeek.org>

## Requirements

This extension needs `zeek-language-server` for IntelliSense features to work.
The extension can download server binaries for x86_64 Darwin and Linux
platforms if none is found in the system. If no binaries are provided for your
platform you can try to [build the language server
yourself](https://github.com/bbannier/zeek-language-server#building-from-source).

For IntelliSense a [Zeek](https://zeek.org) installation is required;
`zeek-config` should to be in `PATH`, or alternatively set `ZEEKPATH` to the
prefixes containing the system Zeek scripts.

Formatting requires [`zeek-format`](https://github.com/zeek/zeekscript)
somewhere in `PATH`.

## Configuration

This extension provides configuration through VSCode's configuration settings.
All configuration settings are under `zeekLanguageServer.*`.

- `zeekLanguageServer.zeekBinaryDirectory`: directory containing Zeek
  executables. If unset we will attempt to find them in PATH.
- `zeekLanguageServer.checkZeekFormat`: check for zeek-format
  on startup
- `zeekLanguageServer.ZEEKPATH`: Colon-separated list of alternative Zeek
  prefixes to use. By default prefixes are determined from the output of
  `zeek-config`.
