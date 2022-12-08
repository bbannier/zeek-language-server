import { inspect } from "util";
import got from "got";
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
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as stream from "stream";
import * as child_process from "child_process";

import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

import { promisify } from "util";
import { Utils } from "vscode-uri";

const BASE_URL =
  "https://github.com/bbannier/zeek-language-server/releases/download";

const PLATFORMS = {
  linux: "x86_64-unknown-linux-gnu",
  darwin: "x86_64-apple-darwin",
};

const exists = promisify(fs.exists);
const pipeline = promisify(stream.pipeline);
const execFile = promisify(child_process.execFile);

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
      const { stdout } = await execFile(file, ["--version"]);
      return stdout.startsWith(expectOut);
    } catch (error) {
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
    const tempDest = path.join(
      path.dirname(dest),
      `.tmp${crypto.randomBytes(5).toString("hex")}`,
    );

    if (await exists(dest)) await fs.promises.rm(dest);
    else await fs.promises.mkdir(path.dirname(dest), { recursive: true });

    const params = {
      title: "Downloading zeek-language-server binary",
      location: ProgressLocation.Notification,
      cancelable: false,
    };

    await window.withProgress(
      params,
      async (progressHandle, cancellationHandle) => {
        let lastPercent = 0;

        const stream = got.stream(url).on("downloadProgress", (progress) => {
          if (!progress.total) {
            return;
          }

          const message = `${(progress.percent * 100).toFixed(0)}%`;
          const increment = (progress.percent - lastPercent) * 100;
          progressHandle.report({ message, increment });
          lastPercent = progress.percent;
        });

        cancellationHandle.onCancellationRequested(stream.destroy.bind(stream));

        await pipeline(stream, fs.createWriteStream(tempDest, { mode: 0o755 }));
      },
    );

    await fs.promises.rename(tempDest, dest);
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
  const server = new ZeekLanguageServer(context);

  const serverExecutable: Executable = {
    command: await server.getPath(),
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

  let checkForUpdates = configuration.get<boolean>("checkForUpdates");
  if (checkForUpdates === undefined || checkForUpdates === null) {
    const path = configuration.get<string>("path");
    checkForUpdates = path.length > 0;
  }

  const serverOptions: ServerOptions = {
    run: serverExecutable,
    debug: serverExecutable,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "zeek" }],
    initializationOptions: { check_for_updates: checkForUpdates },
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
