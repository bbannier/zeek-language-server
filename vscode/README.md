# Zeek language support for Visual Studio Code

Microsoft Visual Studio Code language extension for Zeek (Bro) Script.

> Power by zeek-language-server.

## Features

- [x] IntelliSense
- [x] Syntax Highlighting
- [x] Snippets

## Requirements

This extension currently provides binaries for x86_64 Darwin and Linux
platforms.[^other] A VSIX file is [published on
Github](https://github.com/bbannier/zeek-language-server/releases/).

A [Zeek](https://zeek.org) installation is required, and `zeek-config` needs to
be in `PATH`.

## Configuration

This extension provides configuration through VSCode's configuration settings.
All configuration settings are under `zeekLanguageServer.*`.

- `zeekLanguageServer.path`: if set used to launch the language server
  executable; if unset the executable is looked up in `PATH`.

## Building from source

This extension needs `zeek-language-server` to work. See [its
documentation](https://github.com/bbannier/zeek-language-server) on
how to install it.

In a copy of this directory:

1. Install dependencies

   ```.console
   yarn install
   ```

2. Build the extension

   ```.console
   yarn vsix
   ```

3. Install the extension

   ```.console
   code --install-extension zeek-language-server.vsix
   ```

[^other]:
    The underlying [language server
    binary](https://github.com/bbannier/zeek-language-server) might be buildable
    on other platforms, but needs to be provided out of band. If such a binary
    exists elsewhere one currently needs to point `zeekLanguageServer.path` to
    it as otherwise the extension will automatically attempt to download the
    upstream binary (which will fail on unsupported platforms).
