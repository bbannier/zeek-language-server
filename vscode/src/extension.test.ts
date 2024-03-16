import { ConfigurationTarget, workspace, window, env } from "vscode";
import { checkDependencies } from "./extension";
import { jest, expect, test } from "@jest/globals";
import { WorkspaceConfiguration } from "vscode";
import * as cp from "node:child_process";
import { after, afterEach, describe } from "node:test";

jest.mock("node:child_process");

class MockWorkspace implements WorkspaceConfiguration {
  [key: string]: any;
  get<T>(section: string): T {
    return this[section];
  }
  has(_section: string) {
    return true;
  }
  inspect<T>(_section: string): {
    key: string;
    defaultValue?: T;
    globalValue?: T;
    workspaceValue?: T;
    workspaceFolderValue?: T;
    defaultLanguageValue?: T;
    globalLanguageValue?: T;
    workspaceLanguageValue?: T;
    workspaceFolderLanguageValue?: T;
    languageIds?: string[];
  } {
    return null;
  }
  update(section: string, value: any): Thenable<void> {
    section = section.split(".", 2)[1];
    this[section] = value;
    return null;
  }
}

describe("checkDependencies", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  type ShowInformationMessage = (message: string, ...items: string[]) => string;
  let showInformationMessage = jest.spyOn(
    window,
    "showInformationMessage",
  ) as unknown as jest.MockedFunction<ShowInformationMessage>;

  let config = new MockWorkspace();
  config["checkZeekFormat"] = true;

  jest.spyOn(workspace, "getConfiguration").mockReturnValue(config);

  test("found", async () => {
    jest.spyOn(cp, "execFileSync").mockImplementationOnce(function (
      this: cp.ChildProcess,
    ): Buffer {
      // Simulate that zeek-format was found.
      return Buffer.from("1.2.3");
    });

    await checkDependencies();

    expect(cp.execFileSync).toHaveBeenCalledWith("zeek-format", ["--version"]);
    expect(showInformationMessage).not.toHaveBeenCalled();
  });

  test("not found with installation", async () => {
    jest.spyOn(cp, "execFileSync").mockImplementationOnce(function (
      this: cp.ChildProcess,
    ): Buffer {
      // Simulate that zeek-format was not found.
      throw new Error();
    });

    showInformationMessage.mockReturnValueOnce("Install zeek-format");

    await checkDependencies();

    expect(workspace.getConfiguration).toHaveBeenCalled();
    expect(cp.execFileSync).toHaveBeenCalledWith("zeek-format", ["--version"]);
    expect(showInformationMessage).toHaveBeenCalled();
    expect(env.openExternal).toHaveBeenCalled();
  });

  test("not found without installation", async () => {
    jest.spyOn(cp, "execFileSync").mockImplementationOnce(function (
      this: cp.ChildProcess,
    ): Buffer {
      // Simulate that zeek-format was not found.
      throw new Error();
    });

    showInformationMessage.mockReturnValueOnce("Do not check again");

    expect(config["checkZeekFormat"]).toBeTruthy();

    await checkDependencies();

    expect(workspace.getConfiguration).toHaveBeenCalled();
    expect(cp.execFileSync).toHaveBeenCalledWith("zeek-format", ["--version"]);
    expect(showInformationMessage).toHaveBeenCalled();
    expect(config["checkZeekFormat"]).toBeFalsy();
  });
});
