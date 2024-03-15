const workspace = {
  getConfiguration: jest.fn(),
};

const vscode = {
  workspace,
};

module.exports = vscode;
