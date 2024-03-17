const languages = {
  createDiagnosticCollection: jest.fn(),
};

const StatusBarAlignment = {};

const window = {
  createStatusBarItem: jest.fn(() => ({
    show: jest.fn(),
  })),
  showErrorMessage: jest.fn(),
  showWarningMessage: jest.fn(),
  createTextEditorDecorationType: jest.fn(),
  createOutputChannel: jest.fn(),
  showInformationMessage: jest.fn(),
};

const ConfigurationTarget = {
  Global: 1,
};

const workspace = {
  getConfiguration: jest.fn(),
  workspaceFolders: [],
  onDidSaveTextDocument: jest.fn(),
};

const env = {
  openExternal: jest.fn(),
};

const OverviewRulerLane = {
  Left: null,
};

const Uri = {
  file: (f) => f,
  parse: jest.fn(),
};
const Range = jest.fn();
const Diagnostic = jest.fn();
const DiagnosticSeverity = { Error: 0, Warning: 1, Information: 2, Hint: 3 };
const CompletionItem = jest.fn();
const CodeAction = jest.fn();
const CodeLens = jest.fn();
const DocumentLink = jest.fn();
const CallHierarchyItem = jest.fn();
const TypeHierarchyItem = jest.fn();
const SymbolInformation = jest.fn();
const InlayHint = jest.fn();
const CancellationError = jest.fn();

const debug = {
  onDidTerminateDebugSession: jest.fn(),
  startDebugging: jest.fn(),
};

const commands = {
  executeCommand: jest.fn(),
};

const vscode = {
  CallHierarchyItem,
  CancellationError,
  CodeAction,
  CodeLens,
  CompletionItem,
  ConfigurationTarget,
  Diagnostic,
  DiagnosticSeverity,
  DocumentLink,
  InlayHint,
  OverviewRulerLane,
  Range,
  StatusBarAlignment,
  SymbolInformation,
  TypeHierarchyItem,
  Uri,
  commands,
  debug,
  env,
  languages,
  window,
  workspace,
};

module.exports = vscode;
