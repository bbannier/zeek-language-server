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

import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";
import { promisify } from "util";

const TAG = "v0.2.0";
const BASE_URL =
  "https://github.com/bbannier/zeek-language-server/releases/download";

const PLATFORMS = {
  linux: "x86_64-unknown-linux-gnu",
  darwin: "x86_64-apple-darwin",
};

const exists = promisify(fs.exists);
const pipeline = promisify(stream.pipeline);

export const getServerDestination = async (
  context: ExtensionContext,
  tag: string
): Promise<string> => {
  const { globalStorageUri } = context;
  const uri = Uri.joinPath(
    globalStorageUri,
    "server",
    `zeek-language-server-${tag}`
  );

  const { fsPath } = uri;
  await fs.promises.mkdir(path.dirname(fsPath), { recursive: true });
  return fsPath;
};

const getServerUrl = async (tag: string): Promise<string> => {
  const platform = process.platform;
  const variant = PLATFORMS[platform];

  if (variant) {
    return `${BASE_URL}/${tag}/zeek-language-server-${variant}`;
  } else {
    log.error(`Unsupported platform ${platform}`);
    return Promise.reject();
  }
};

const getServerOrDownload = async (
  context: ExtensionContext,
  tag: string
): Promise<string> => {
  // FIXME(bbannier): check whether executable is somewhere in PATH.
  const dest = await getServerDestination(context, tag);
  if (!(await exists(dest))) {
    const url = await getServerUrl(tag);
    log.info(`Downloading ${url} to ${dest}`);
    const tempDest = path.join(
      path.dirname(dest),
      `.tmp${crypto.randomBytes(5).toString("hex")}`
    );

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

  return dest;
};

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
  const config = workspace.getConfiguration("zeekLanguageServer");
  const userDefinedServerPath = config.get<string>("path");
  const serverPath =
    userDefinedServerPath == ""
      ? await getServerOrDownload(context, TAG)
      : userDefinedServerPath;

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

  CLIENT = new LanguageClient(
    "zeek-language-server",
    "Zeek Language Server",
    serverOptions,
    clientOptions
  );
  CLIENT.start();
}

export async function deactivate(): Promise<void> {
  if (CLIENT) {
    await CLIENT.stop();
  }
}
