import * as child_process from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import process from "node:process";
import { inspect } from "node:util";
import {
  commands,
  ConfigurationTarget,
  env,
  type ExtensionContext,
  ProgressLocation,
  Uri,
  window,
  workspace,
} from "vscode";

import * as tar from "tar";
import {
  type Executable,
  LanguageClient,
  type LanguageClientOptions,
  type ServerOptions,
} from "vscode-languageclient/node";
import { XzReadableStream } from "xz-decompress";

const BASE_URL =
  "https://github.com/bbannier/zeek-language-server/releases/download";

class ZeekLanguageServer {
  private readonly context: ExtensionContext;
  private readonly version: string;

  constructor(context: ExtensionContext) {
    this.context = context;
    this.version = context.extension.packageJSON.version;
  }

  /** Finds the server binary. */
  public async getPath(): Promise<string> {
    let pathFound = "";
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
      if (this.check(path)) {
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

  private check(file: string): boolean {
    const expectOut = `zeek-language-server ${this.version}`;

    try {
      const stdout = child_process.execFileSync(file, ["--version"]).toString();
      return stdout.startsWith(expectOut);
    } catch (error) {
      console.debug(`check for 'zeek-language-server failed': ${error}`);
      return false;
    }
  }

  private getDownloadUrl(): string {
    let arch = "";
    switch (process.arch) {
      case "arm64":
        arch = "aarch64";
        break;

      case "x64":
        arch = "x86_64";
        break;

      default:
        throw new Error(
          `Unsupported platform ${process.platform} ${process.arch}`,
        );
    }

    let platform = "";
    switch (process.platform) {
      case "darwin":
        platform = "apple-darwin";
        break;

      case "linux":
        platform = "unknown-linux-gnu";
        break;

      case "win32":
        platform = "pc-windows-msvc";
        break;

      default:
        throw new Error(
          `Unsupported platform ${process.platform} ${process.arch}`,
        );
    }

    return `${BASE_URL}/v${this.version}/zeek-language-server-${arch}-${platform}.tar.xz`;
  }

  private async download(dest: string) {
    const url = this.getDownloadUrl();
    log.info(`Downloading ${url} to ${dest}`);

    const dest_dir = path.dirname(dest);
    fs.mkdirSync(dest_dir, { recursive: true });

    await window.withProgress(
      {
        title: "Downloading zeek-language-server binary",
        location: ProgressLocation.Window,
        cancellable: true,
      },
      async (progressHandle, cancellationHandle) => {
        const response = await fetch(url);
        const content = new XzReadableStream(
          response.body as ReadableStream<Uint8Array>,
        );
        const reader = content.getReader();

        cancellationHandle.onCancellationRequested(() => {
          reader.cancel("cancelled by user");
        });

        let receivedLength = 0;
        const chunks = []; // array of received binary chunks (comprises the body)
        for (;;) {
          const { done, value } = await reader.read();

          if (done) {
            break;
          }

          chunks.push(value);
          receivedLength += value.length;

          progressHandle.report({ increment: 0 });
        }

        const chunksAll = new Uint8Array(receivedLength);
        let position = 0;
        for (const chunk of chunks) {
          chunksAll.set(chunk, position);
          position += chunk.length;
        }

        const tar_file = `${dest}.tmp.tar`;
        fs.writeFileSync(tar_file, chunksAll);

        await tar.extract({
          file: tar_file,
          strip: 1,
          preserveOwner: false,
          noMtime: true,
          cwd: dest_dir,
        });

        fs.unlinkSync(tar_file);
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
  const editor = window.activeTextEditor;
  if (!editor) return;
  const document = editor.document;
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
  if (name !== "main.zeek") {
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
      if (selected === installZeekFormat) {
        env.openExternal(Uri.parse("https://github.com/zeek/zeekscript"));
      } else if (selected === doNotCheck) {
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
}

export async function activate(context: ExtensionContext): Promise<void> {
  // Register commands.
  context.subscriptions.push(commands.registerCommand("zeek.tryZeek", tryZeek));

  await checkDependencies();

  const env: { [key: string]: string } = {};
  const configuration = workspace.getConfiguration("zeekLanguageServer");

  const cfg_path = configuration.get<string>("zeekBinaryDirectory");
  const path = process.env.PATH;
  if (cfg_path) {
    env.PATH = `${cfg_path}:${path}`;
  } else if (path) {
    env.PATH = path;
  }

  const zeekpath = configuration.get<string>("ZEEKPATH");
  if (zeekpath) {
    env.ZEEKPATH = zeekpath;
  } else {
    const zeekpath = process.env.ZEEKPATH;
    if (zeekpath) env.ZEEKPATH = zeekpath;
  }

  const server_args = [];

  const debugLogging = configuration.get<string>("debugLogging");
  if (debugLogging) {
    server_args.push("-f", debugLogging);
  }

  // Start the server.
  const serverExecutable: Executable = {
    command:
      process.env.__ZEEK_LSP_SERVER_DEBUG ??
      (await new ZeekLanguageServer(context).getPath()),
    args: server_args,
  };

  if (Object.keys(env).length > 0) {
    log.info(env);
    serverExecutable.options = { env };
  }

  const inlay_hints_variables = configuration.get<boolean>(
    "inlayHints.variables.enabled",
  );
  const inlay_hints_parameters = configuration.get<boolean>(
    "inlayHints.parameters.enabled",
  );
  const references = configuration.get<boolean>("references.enabled");
  const rename = configuration.get<boolean>("rename.enabled");
  const semantic_highlighting = configuration.get<boolean>(
    "semantic_highlighting.enabled",
  );
  const debug_ast_nodes = configuration.get<boolean>("debug.AST_nodes");

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "zeek" }],
    initializationOptions: {
      inlay_hints_parameters,
      inlay_hints_variables,
      references,
      rename,
      semantic_highlighting,
      debug_ast_nodes,
    },
  };

  const serverOptions: ServerOptions = {
    run: serverExecutable,
    debug: serverExecutable,
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
