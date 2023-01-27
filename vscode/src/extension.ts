import { inspect } from "util";
import got from "got";
import {
  ConfigurationTarget,
  ExtensionContext,
  Uri,
  workspace,
  window,
  commands,
  env,
} from "vscode";
import * as child_process from "child_process";

import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

import { promisify } from "util";
import { Utils } from "vscode-uri";

const PLATFORMS = {
  linux: "x86_64-unknown-linux-gnu",
  darwin: "x86_64-apple-darwin",
};

const execFile = promisify(child_process.execFile);

const log = new (class {
  private readonly output = window.createOutputChannel("zeek-language-server");

  info(...msg: [unknown, ...unknown[]]): void {
    log.write("INFO", ...msg);
  }

  error(...msg: [unknown, ...unknown[]]): void {
    log.write("ERROR", ...msg);
    log.output.show(true);
  }

  private write(label: string, ...messageParts: unknown[]): void {
    const message = messageParts.map(log.stringify).join(" ");
    const dateTime = new Date().toLocaleString();
    log.output.appendLine(`${label} [${dateTime}]: ${message}`);
  }

  private stringify(val: unknown): string {
    if (typeof val === "string") return val;
    return inspect(val, {
      colors: false,
      depth: 6, // heuristic
    });
  }
})();

function getLanguageServerPath(context: ExtensionContext): string {
  // Do not attempt to start server on unsupported platforms.
  const platform = process.platform;
  if (!PLATFORMS[platform]) {
    throw new Error(`IntelliSense is unsupported on platform ${platform}`);
  }

  return `${context.extensionPath}/bin/zeek-language-server-${PLATFORMS[platform]}`;
}

/** Publish the currently open document to try.zeek.org and open the result. */
async function tryZeek(): Promise<void> {
  const document = window.activeTextEditor.document;
  const name = Utils.basename(document.uri);
  const content = document.getText();

  log.info(`Creating try.zeek.org content for ${document.uri.fsPath}`);

  interface Source {
    name: string;
    content: string;
  }
  interface Query {
    sources: Source[];
    version: string;
    pcap: string;
  }

  // try.zeek.org expects a file `main.zeek`. Add a dummy file loading
  // the main content unless the file is already called `main.zeek`.
  const sources: Source[] = [{ name, content }];
  if (name != "main.zeek") {
    sources.push({ name: "main.zeek", content: `@load ${name}` });
  }

  const query: Query = {
    sources,
    version: "5.0.0",
    pcap: "",
  };

  const body = JSON.stringify(query);

  const res = await got.post("https://try.zeek.org/run", {
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body,
  });

  const { job } = JSON.parse(res.body);
  log.info(`Got try.zeek.org post ${job}`);

  env.openExternal(Uri.parse(`https://try.zeek.org/#/tryzeek/saved/${job}`));
}

let CLIENT: LanguageClient;

async function checkDependencies(): Promise<void> {
  // Check for `zeek-format`.
  if (
    workspace
      .getConfiguration("zeekLanguageServer")
      .get<boolean>("checkZeekFormat")
  ) {
    try {
      await execFile("zeek-format", ["--version"]);
    } catch (error) {
      const installZeekFormat = "Install zeek-format";
      const doNotCheck = "Do not check again";
      const selected = await window.showInformationMessage(
        "Formatting support not available",
        installZeekFormat,
        doNotCheck,
      );
      if (selected == installZeekFormat)
        env.openExternal(Uri.parse("https://github.com/zeek/zeekscript"));
      else if (selected == doNotCheck)
        await workspace
          .getConfiguration()
          .update(
            "zeekLanguageServer.checkZeekFormat",
            false,
            ConfigurationTarget.Global,
          );
    }
  }
}

export async function activate(context: ExtensionContext): Promise<void> {
  // Register commands.
  context.subscriptions.push(commands.registerCommand("zeek.tryZeek", tryZeek));

  await checkDependencies();

  // Start the server.
  const serverExecutable: Executable = {
    command: getLanguageServerPath(context),
  };

  const env = {};
  const configuration = workspace.getConfiguration("zeekLanguageServer");

  const cfg_path = configuration.get<string>("zeekBinaryDirectory");
  const path = process.env["PATH"];
  if (cfg_path) {
    env["PATH"] = `${cfg_path}:${path}`;
  } else {
    env["PATH"] = path;
  }

  const zeekpath = configuration.get<string>("ZEEKPATH");
  if (zeekpath) {
    env["ZEEKPATH"] = zeekpath;
  } else {
    env["ZEEKPATH"] = process.env["ZEEKPATH"];
  }

  if (Object.keys(env).length > 0) {
    log.info(env);
    serverExecutable.options = { env };
  }

  const serverOptions: ServerOptions = {
    run: serverExecutable,
    debug: serverExecutable,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "zeek" }],
    initializationOptions: { check_for_updates: true },
  };

  CLIENT = new LanguageClient(
    "zeek-language-server",
    "Zeek Language Server",
    serverOptions,
    clientOptions,
  );

  log.info("Starting Zeek Language Server...");
  CLIENT.start();
}

export async function deactivate(): Promise<void> {
  if (CLIENT) {
    await CLIENT.stop();
  }
}
