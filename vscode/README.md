# zeek-language-server

Provides support for zeek-language-server, a LSP server for Zeek script.

## Quick start

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

## Configuration

This extension provides configuration through VSCode's configuration settings.
All configuration settings are under `zeekLanguageServer.*`.

- `zeekLanguageServer.path`: if set used to launch the language server
  executable; if unset the executable is looked up in `PATH`.
