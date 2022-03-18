# Emacs setup for zeek-language-server

This file documents the configuration needed to interface emacs with `zeek-language-server`. These instructions use `lsp-mode`. There's the possibility it would also work with `elgot` (an `lsp-mode` replacement), but that exercise is left to the reader. `lsp-mode` comes with an astonishing amount of options for configuring the look and operation of the LSP features in emacs. This guide only presents the most basic configuration. More information about lsp-mode is available in their [documentation](https://emacs-lsp.github.io/lsp-mode/).

This guide assumes that you have installed `zeek-language-server` and that it is in your `PATH`.

## Prerequisites

There are some emacs packages that are required for this to work. You can install all of these from your favorite emacs package repository using `M-x package-install`. The required packages are:

```
use-package
lsp-mode
lsp-ui
yasnippet
```

It also requires the Zeek major mode from https://github.com/zeek/emacs-zeek-mode. Either copy the file into a directory in your emacs `load-path` or load the file manually like below in your `.emacs`:

```
(load-file "/path/to/zeek-mode")
```

Once the above packages are installed, add the following basic configuration for them to your `.emacs`, preferably near the top:

```
(require 'package)
(add-to-list 'package-archives
         '("melpa-stable" . "https://stable.melpa.org/packages/") t)

(package-initialize)

(eval-when-compile
  (require 'use-package))

(use-package lsp-mode
         :commands lsp)
(use-package lsp-ui)
(use-package yasnippet)
(use-package zeek-mode)
```

## Setup

1. If needed, add the path to `zeek-config` to your environment's `PATH` variable.
2. Add a hook to `lsp-mode` for zeek files and register the language server.

```
(add-hook 'zeek-mode-hook 'lsp)
(with-eval-after-load 'lsp-mode
  (add-to-list 'lsp-language-id-configuration
    '(zeek-mode . "zeek"))

  (lsp-register-client
    (make-lsp-client :new-connection (lsp-stdio-connection "zeek-language-server")
                     :activation-fn (lsp-activate-on "zeek")
                     :server-id 'zeek)))
```

3. Open a zeek script file in emacs. At this point you should notice two things about your emacs window. First, in the modeline it should list that it is using the zeek major-mode and that it connected to the LSP server. These are shown something like `(zeek LSP[zeek:pid])`. Second, you should have line at the top of the window that gives information about where in the Zeek file you are.
