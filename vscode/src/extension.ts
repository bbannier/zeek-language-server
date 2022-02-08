import { ExtensionContext, workspace } from "vscode";

import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

let client: LanguageClient;

export async function activate(context: ExtensionContext) {
  // TODO(bbannier): If config is not set, instead look up the binary in `PATH`.
  const serverPath = workspace
    .getConfiguration("zeekLanguageServer")
    .get<string>("path");

  const serverExecutable: Executable = {
    command: serverPath,
  };

  const serverOptions: ServerOptions = {
    run: serverExecutable,
    debug: serverExecutable,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "zeek" }],
  };

  client = new LanguageClient(
    "zeek-language-server",
    "Zeek Language Server",
    serverOptions,
    clientOptions
  );
  client.start();
}

export async function deactivate(): Promise<void> {
  if (client) {
    await client.stop();
  }
}
