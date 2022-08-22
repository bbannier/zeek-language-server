import { inspect } from "util";
import got from "got";
import {
  ExtensionContext,
  ProgressLocation,
  Uri,
  workspace,
  window,
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

  public async getPath(): Promise<string> {
    let pathFound: string;
    const needCheckingPaths: string[] = ["zeek-language-server"];

    const variant = PLATFORMS[process.platform];
    needCheckingPaths.push(`zeek-language-server-${variant}`);

    const configPath = workspace.getConfiguration("zeekLanguageServer").get<string>("path");
    if (configPath) {
      needCheckingPaths.push(configPath);
    }

    const defaultPath = Uri.joinPath(
      this.context.globalStorageUri,
      "server",
      "zeek-language-server"
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
      `.tmp${crypto.randomBytes(5).toString("hex")}`
    );

    if (await exists(dest))
      await fs.promises.rm(dest);
    else
      await fs.promises.mkdir(path.dirname(dest), { recursive: true });

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
          const message = `${(progress.percent * 100).toFixed(0)}%`;
          const increment = progress.percent - lastPercent;
          progressHandle.report({ message, increment });
          lastPercent = progress.percent;
        });

        cancellationHandle.onCancellationRequested(stream.destroy.bind(stream));

        await pipeline(stream, fs.createWriteStream(tempDest, { mode: 0o755 }));
      }
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

let CLIENT: LanguageClient;

export async function activate(context: ExtensionContext): Promise<void> {
  const server = new ZeekLanguageServer(context);

  const serverExecutable: Executable = {
    command: await server.getPath(),
  };

  const serverOptions: ServerOptions = {
    run: serverExecutable,
    debug: serverExecutable,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "zeek" }],
  };

  CLIENT = new LanguageClient(
    "zeek-language-server",
    "Zeek Language Server",
    serverOptions,
    clientOptions
  );

  log.info("Starting Zeek Language Server...");
  CLIENT.start();
}

export async function deactivate(): Promise<void> {
  if (CLIENT) {
    await CLIENT.stop();
  }
}
