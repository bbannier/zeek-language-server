# Zeek language support for Visual Studio Code

Microsoft Visual Studio Code language extension for Zeek (Bro) Script.

## Requirements

This extension needs the platform-dependent `zeek-language-server` binary to
work. The extension can download server binaries for x86_64 Darwin and Linux
platforms if the executable was not found in the system. If no binaries are
provided for your platform you can try to [build the language server
yourself](https://github.com/bbannier/zeek-language-server#building-from-source).

To browse and complete Zeek standard library functions a
[Zeek](https://zeek.org) installation is required; `zeek-config` should to be
in `PATH`, or alternatively set `ZEEKPATH` to the prefixes containing the
system Zeek executables.

Formatting requires [`zeek-format`](https://github.com/zeek/zeekscript)
somewhere in `PATH`.
