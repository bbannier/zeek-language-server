# Debugging VSCode plugin and the language server

## Prerequisites

- You can successfully build this project from source.
- Install [LLDB](https://lldb.llvm.org/) and the [LLDB Extension](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb).
- Open the root folder in VSCode. Press <kbd>Ctrl+Shift+D</kbd> and here you can access the preconfigured debug setups.

## Common knowledge

* All debug configurations open a new `[Extension Development Host]` VSCode instance
where **only** the [Zeek](https://marketplace.visualstudio.com/items?itemName=bbannier.zeek-language-server) extension being debugged is enabled.
* To activate the extension you need to open any Zeek script file (`.zeek/.bro`) in `[Extension Development Host]`.


## Debug TypeScript VSCode extension

- `Run Extension (Debug Build)` - runs extension with the locally built LSP server (`target/debug/zeek-language-server`).

TypeScript debugging is configured to watch your source edits and recompile.
To apply changes to an already running debug process, press <kbd>Ctrl+Shift+P</kbd> and run the following command in your `[Extension Development Host]`

```
> Developer: Reload Window
```

## Debug LSP server

- When attaching a debugger to an already running `zeek-language-server` server on Linux you might need to enable `ptrace` for unrelated processes by running:

  ```
  echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
  ```


- By default, the LSP server is built without debug information. To enable it, you'll need to change `Cargo.toml`:
  ```toml
    [profile.dev]
    debug = 2
  ```

- Select `Run Extension (Debug Build)` to run your locally built `target/debug/zeek-language-server`.

- In the original VSCode window once again select the `Attach To Server` debug configuration.

- A list of running processes should appear. Select the `zeek-language-server` from this repo.

- Navigate to `src/lsp.rs` and add a breakpoint to the `hover` function.

- Go back to the `[Extension Development Host]` instance and hover over a Zeek variable and your breakpoint should hit.

## Troubleshooting

### Can't find the `zeek-language-server` process

It could be a case of just jumping the gun.

The `zeek-language-server` is only started once the `onLanguage:zeek` activation.

Make sure you open a Zeek script file in the `[Extension Development Host]` and try again.

### Can't connect to `zeek-language-server`

Make sure you have run `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`.

By default this should reset back to 1 every time you log in.

### Breakpoints are never being hit

Check your version of `lldb`. If it's version 6 and lower, use the `classic` adapter type.
It's `lldb.adapterType` in settings file.

If you're running `lldb` version 7, change the lldb adapter type to `bundled` or `native`.
