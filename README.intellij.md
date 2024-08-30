# IntelliJ Setup for zeek-language-server

This guide explains how to configure the Zeek language server with JetBrains
IDEs (CLion, PyCharm, RustRover, etc.). It provides step-by-step
instructions for setup and configuration.

## Prerequisites

Ensure that:

- `zeek-language-server` is installed
- Both `zeek-language-server` and `zeek-config` are in your system `PATH`

For information on building from source, refer to the [main README](README.md).

## Installation Steps

### Install LSP4IJ Plugin

1. Open your JetBrains IDE
2. Go to Plugins -> Marketplace
3. Search for and install
[LSP4IJ](https://plugins.jetbrains.com/plugin/23257-lsp4ij) by RedHat
4. Restart IDE

For more information, visit the [LSP4IJ plugin
page](https://plugins.jetbrains.com/plugin/23257-lsp4ij).

Developer documentation is available in the LSP4IJ GitHub
repository.

### Configure Language Server

1. Open Settings/Preferences:
   - Windows/Linux: File > Settings
   - macOS: IntelliJ IDEA > Preferences

2. Navigate to Languages & Frameworks > Language Servers

3. Click the "+" button to add a new server definition

4. Configure the server:
   - Name: "Zeek"
   - Server:
     - Command: Full path to `zeek-language-server`
       Example (macOS): `/Users/username/.cargo/bin/zeek-language-server`
   - Mappings -> File name patterns(1)
     - File name patterns: `*.zeek`
     - Language ID: `zeek`
   - Configuration:

     ```json
     {
       "check_for_updates": true,
       "inlay_hints_parameters": true,
       "inlay_hints_variables": true,
       "references": false,
       "rename": false
     }
     ```

5. Click "Apply" then "OK" to save the settings

6. Restart your IDE for the changes to take effect

## Usage

Open a Zeek script file (`.zeek` extension). The language server should now be
active for Zeek files.

## Troubleshooting

If you encounter issues:

- Ensure the `zeek-language-server` path is correct
- Consult the IDE's log files for any error messages

For further assistance, refer to the [main README](README.md) or the project's
[issue tracker](https://github.com/bbannier/zeek-language-server/issues).
