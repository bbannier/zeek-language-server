import { inspect } from "util";
import {
  ConfigurationTarget,
  ExtensionContext,
  ProgressLocation,
  Uri,
  workspace,
  window,
  commands,
  env,
} from "vscode";
import * as fs from "node:fs";
import * as path from "node:path";
import * as child_process from "node:child_process";

import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

const BASE_URL =
  "https://github.com/bbannier/zeek-language-server/releases/download";

const PLATFORMS = {
  linux: "x86_64-unknown-linux-gnu",
  darwin: "x86_64-apple-darwin",
};

class ZeekLanguageServer {
  private readonly context: ExtensionContext;
  private readonly version: string;

  constructor(context: ExtensionContext) {
    this.context = context;
    this.version = context.extension.packageJSON["version"];
  }

  /** Finds the server binary. */
  public async getPath(): Promise<string> {
    let pathFound: string;
    const needCheckingPaths: string[] = [];

    // Check configured path.
    const configPath = workspace
      .getConfiguration("zeekLanguageServer")
      .get<string>("path");
    if (configPath) {
      needCheckingPaths.push(configPath);
    }

    // Check in PATH.
    needCheckingPaths.push("zeek-language-server");

    // Check for already downloaded binary.
    const defaultPath = Uri.joinPath(
      this.context.globalStorageUri,
      "server",
      "zeek-language-server",
    ).fsPath;
    needCheckingPaths.push(defaultPath);

    for (const path of needCheckingPaths) {
      if (await this.check(path)) {
        pathFound = path;
        break;
      }
    }

    if (!pathFound) {
      await this.download(defaultPath);
      pathFound = defaultPath;
    }

    log.info(`Found ${pathFound}.`);
    return pathFound;
  }

  private async check(file: string): Promise<boolean> {
    const expectOut = `zeek-language-server ${this.version}`;

    try {
      const stdout = child_process.execFileSync(file, ["--version"]).toString();
      return stdout.startsWith(expectOut);
    } catch (error) {
      console.debug(`check for 'zeek-language-server failed': ${error}`);
      return false;
    }
  }

  private async getDownloadUrl(): Promise<string> {
    const platform = process.platform;
    const variant = PLATFORMS[platform];

    if (variant) {
      return `${BASE_URL}/v${this.version}/zeek-language-server-${variant}`;
    } else {
      log.error(`Unsupported platform ${platform}`);
      return Promise.reject();
    }
  }

  private async download(dest: string) {
    const url = await this.getDownloadUrl();
    log.info(`Downloading ${url} to ${dest}`);

    if (fs.existsSync(dest)) {
      fs.rmSync(dest);
    } else {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
    }

    const params = {
      title: "Downloading zeek-language-server binary",
      location: ProgressLocation.Notification,
      cancelable: false,
    };

    await window.withProgress(
      params,
      async (progressHandle, cancellationHandle) => {
        let lastPercent = 0;

        const response = await fetch(url);
        const reader = response.body.getReader();

        cancellationHandle.onCancellationRequested(() => {
          reader.cancel("cancelled by user");
        });

        const contentLength = parseInt(response.headers.get("Content-Length"));
        let receivedLength = 0;
        const chunks = []; // array of received binary chunks (comprises the body)
        for (;;) {
          const { done, value } = await reader.read();

          if (done) {
            break;
          }

          chunks.push(value);
          receivedLength += value.length;

          const percent = (receivedLength / contentLength) * 100;
          const message = `${percent.toFixed(0)}%`;
          const increment = percent - lastPercent;
          progressHandle.report({ message, increment });
          lastPercent = percent;
        }

        const chunksAll = new Uint8Array(receivedLength);
        let position = 0;
        for (const chunk of chunks) {
          chunksAll.set(chunk, position);
          position += chunk.length;
        }

        fs.writeFileSync(dest, chunksAll, { mode: 0o755 });
      },
    );
  }
}

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

/** Publish the currently open document to try.zeek.org and open the result. */
async function tryZeek(): Promise<void> {
  const document = window.activeTextEditor.document;
  const name = path.basename(document.uri.path);
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

  interface Result {
    job: string;
    stdout: string;
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

  const response = await fetch("https://try.zeek.org/run", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(query),
  });

  const result = (await response.json()) as Result;

  log.info(`Got try.zeek.org post ${result.job}`);

  env.openExternal(
    Uri.parse(`https://try.zeek.org/#/tryzeek/saved/${result.job}`),
  );
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
      child_process.execFileSync("zeek-format", ["--version"]);
    } catch (error) {
      console.debug(`check for 'zeek-format' failed': ${error}`);
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
  // Do not attempt to start server on unsupported platforms.
  const platform = process.platform;
  if (!PLATFORMS[platform]) {
    log.info(`IntelliSense is unsupported on platform ${platform}`);
    return;
  }

  // Register commands.
  context.subscriptions.push(commands.registerCommand("zeek.tryZeek", tryZeek));

  await checkDependencies();

  // Start the server.
  const serverExecutable: Executable = {
    command:
      process.env.__ZEEK_LSP_SERVER_DEBUG ??
      (await new ZeekLanguageServer(context).getPath()),
    args: [],
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

  const debugLogging = configuration.get<string>("debugLogging");
  if (debugLogging) {
    serverExecutable.args.push("-f", debugLogging);
  }

  if (Object.keys(env).length > 0) {
    log.info(env);
    serverExecutable.options = { env };
  }

  let checkForUpdates = configuration.get<boolean>("checkForUpdates");
  if (checkForUpdates === undefined || checkForUpdates === null) {
    const path = configuration.get<string>("path");
    checkForUpdates = path.length > 0;
  }

  const inlayHintsVariables = configuration.get<boolean>(
    "inlayHints.variables.enabled",
  );
  const inlayHintsParameters = configuration.get<boolean>(
    "inlayHints.parameters.enabled",
  );
  const references = configuration.get<boolean>("references.enabled");
  const rename = configuration.get<boolean>("rename.enabled");

  const serverOptions: ServerOptions = {
    run: serverExecutable,
    debug: serverExecutable,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "zeek" }],
    initializationOptions: {
      check_for_updates: checkForUpdates,
      inlay_hints_parameters: inlayHintsParameters,
      inlay_hints_variables: inlayHintsVariables,
      references,
      rename,
    },
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
