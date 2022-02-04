use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use lspower::lsp::Url;
use salsa::Snapshot;
use tracing::{error, instrument};

use crate::{
    lsp::Database,
    parse::Parse,
    query::{self, Decl, DeclKind, ModuleId, Query},
    to_point, to_range, zeek, Files,
};

#[salsa::query_group(AstStorage)]
pub trait Ast: Files + Parse + Query {
    #[salsa::input]
    fn prefixes(&self) -> Arc<Vec<PathBuf>>;

    #[salsa::input]
    fn files(&self) -> Arc<BTreeSet<Arc<Url>>>;

    #[must_use]
    fn loaded_files(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn loaded_files_recursive(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn loaded_decls(&self, url: Arc<Url>) -> Arc<Vec<Decl>>;

    #[must_use]
    fn implicit_decls(&self) -> Arc<Vec<Decl>>;
}

#[allow(clippy::needless_pass_by_value)]
fn loaded_files(db: &dyn Ast, uri: Arc<Url>) -> Arc<Vec<Arc<Url>>> {
    let files = db.files();

    let prefixes = db.prefixes();

    let loads: Vec<_> = db.loads(uri.clone()).iter().map(PathBuf::from).collect();

    let mut loaded_files = Vec::new();

    for load in &loads {
        if let Some(f) = load_to_file(load, uri.as_ref(), &files, &prefixes) {
            loaded_files.push(f);
        }
    }

    Arc::new(loaded_files)
}

#[instrument(skip(db))]
fn loaded_files_recursive(db: &dyn Ast, url: Arc<Url>) -> Arc<Vec<Arc<Url>>> {
    let mut files = db.loaded_files(url).as_ref().clone();

    loop {
        let mut new_files = Vec::new();

        for f in &files {
            for load in db.loaded_files(f.clone()).as_ref() {
                if !files.iter().any(|f| f.as_ref() == load.as_ref()) {
                    new_files.push(load.clone());
                }
            }
        }

        if new_files.is_empty() {
            break;
        }

        for n in new_files {
            files.push(n);
        }
    }

    Arc::new(files)
}

#[instrument(skip(db))]
fn loaded_decls(db: &dyn Ast, url: Arc<Url>) -> Arc<Vec<Decl>> {
    let mut decls = Vec::new();

    for load in db.loaded_files_recursive(url).as_ref() {
        for decl in db.decls(load.clone()).iter() {
            decls.push(decl.clone());
        }
    }

    Arc::new(decls)
}

#[instrument(skip(db))]
fn implicit_decls(db: &dyn Ast) -> Arc<Vec<Decl>> {
    let implicit_load = zeek::init_script_filename();

    let mut implicit_file = None;
    // This loop looks horrible, but is okay since this function will be cached most of the time
    // (unless global state changes).
    for f in db.files().iter() {
        let path = match f.to_file_path() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if !path.ends_with(&implicit_load) {
            continue;
        }

        for p in db.prefixes().iter() {
            if path.strip_prefix(p).is_ok() {
                implicit_file = Some(f.clone());
                break;
            }
        }
    }

    let implicit_load = match implicit_file {
        Some(f) => f,
        None => return Arc::new(Vec::new()), // TODO(bbannier): this could also be an error.
    };

    db.loaded_decls(implicit_load)
}

pub(crate) fn load_to_file(
    load: &Path,
    base: &Url,
    files: &BTreeSet<Arc<Url>>,
    prefixes: &[PathBuf],
) -> Option<Arc<Url>> {
    let file_dir = base
        .to_file_path()
        .ok()
        .and_then(|f| f.parent().map(Path::to_path_buf));

    let load = match load.strip_prefix(".") {
        Ok(l) => l,
        Err(_) => load,
    };

    file_dir.iter().chain(prefixes.iter()).find_map(|prefix| {
        // Files in the given prefix.
        let files: Vec<_> = files
            .iter()
            .filter_map(|f| {
                if let Ok(p) = f.to_file_path().ok()?.strip_prefix(prefix) {
                    Some((f, p.to_path_buf()))
                } else {
                    None
                }
            })
            .collect();

        // File known w/ extension.
        let known_exactly = files.iter().find(|(_, p)| p.ends_with(load));

        // File known w/o extension.
        let known_no_ext = files
            .iter()
            .find(|(_, p)| p.ends_with(load.with_extension("zeek")));

        // Load is directory with `__load__.zeek`.
        let known_directory = files
            .iter()
            .find(|(_, p)| p.ends_with(load.join("__load__.zeek")));

        known_exactly
            .or(known_no_ext)
            .or(known_directory)
            .map(|(f, _)| (*f).clone())
    })
}

/// Find decl with ID from the node up the tree and in all other loaded files.
pub(crate) fn resolve(
    snapshot: &Snapshot<Database>,
    node: tree_sitter::Node,
    scope: Option<tree_sitter::Node>,
    uri: Arc<Url>,
) -> Option<Decl> {
    let source = snapshot.source(uri.clone());

    // By default we interpret `node` as the scope.
    let scope = match scope {
        Some(s) => s,
        None => node,
    };

    match node.kind() {
        // If we are on an `expr` or `init` node unwrap it and work on whatever is inside.
        "expr" | "init" => {
            return node
                .named_child(0)
                .and_then(|c| resolve(snapshot, c, Some(scope), uri.clone()));
        }
        // If we are on a `field_access` or `field_check` search the rhs in the scope of the lhs.
        "field_access" | "field_check" => {
            let rhs = node.named_child(0)?;
            let lhs = node.named_child(1)?;

            return resolve(snapshot, lhs, Some(rhs), uri);
        }
        _ => {}
    }

    // If the ID is part of a field access or check resolve it in the referenced record.
    if let Some(p) = node.parent() {
        let id = node.utf8_text(source.as_bytes()).ok()?;

        if p.kind() == "field_access" || p.kind() == "field_check" {
            let lhs = node
                .prev_named_sibling()
                .and_then(|s| resolve(snapshot, s, Some(scope), uri.clone()))?;

            let typ = typ(snapshot, &lhs)?;

            let fields = match typ.kind {
                DeclKind::Type(fields) => fields,
                _ => return None,
            };

            // Find the given id in the fields.
            let field = fields.into_iter().find(|f| f.id == id);

            if field.is_some() {
                return field;
            }
        }
    }

    // Try to find a decl with name of the given node up the tree.
    let id = node.utf8_text(source.as_bytes()).ok()?;

    let mut node = node;
    let mut decl;
    loop {
        decl = query::decl_at(id, node, uri.clone(), source.as_bytes()).or(match node.kind() {
            "func_decl" => {
                // Synthesize declarations for function arguments. Ideally the grammar would expose
                // these directly.
                let func_params = node.named_child(1)?;
                if func_params.kind() != "func_params" {
                    error!("expected 'func_params', got '{}'", func_params.kind());
                    return None;
                }

                let formal_args = func_params.named_child(0)?;
                if formal_args.kind() != "formal_args" {
                    error!("expected 'formal_args', got '{}'", formal_args.kind());
                    return None;
                }

                for i in 0..formal_args.named_child_count() {
                    let arg = formal_args.named_child(i)?;
                    if arg.kind() != "formal_arg" {
                        error!("expected 'formal_arg', got '{}'", arg.kind());
                        return None;
                    }

                    let arg_id_ = arg.named_child(0)?;
                    if arg_id_.kind() != "id" {
                        error!("expected 'id', got '{}'", arg_id_.kind());
                        return None;
                    }

                    let arg_id = arg_id_.utf8_text(source.as_bytes()).ok()?;
                    if arg_id != id {
                        continue;
                    }

                    return Some(Decl {
                        module: ModuleId::None,
                        id: arg_id.to_string(),
                        fqid: arg_id.to_string(),
                        kind: DeclKind::Variable,
                        is_export: None,
                        range: to_range(arg_id_.range()).ok()?,
                        selection_range: to_range(arg.range()).ok()?,
                        uri,
                        documentation: format!(
                            "```zeek\n{}\n```",
                            arg.utf8_text(source.as_bytes()).ok()?
                        ),
                    });
                }
                None
            }
            _ => None,
        });

        if decl.is_some() {
            return decl;
        }

        if let Some(p) = node.parent() {
            node = p;
        } else {
            break;
        }
    }

    // We haven't found a decl yet, look in loaded modules.
    snapshot
        .implicit_decls()
        .iter()
        .chain(snapshot.loaded_decls(uri).iter())
        .find(|d| d.fqid == id)
        .cloned()
}

/// Determine the type of the given decl.
pub(crate) fn typ(db: &Snapshot<Database>, decl: &Decl) -> Option<Decl> {
    /// Helper to extract function return values.
    fn fn_result(decl: tree_sitter::Node) -> Option<tree_sitter::Node> {
        // The return type is stored in the func_params.
        let func_params = decl
            .named_children(&mut decl.walk())
            .find(|c| c.kind() == "func_params")?;

        // A `type` directly stored in the `func_params` is the return type.
        func_params
            .named_children(&mut func_params.walk())
            .find(|c| c.kind() == "type")
    }

    let uri = &decl.uri;

    let tree = db.parse(uri.clone())?;

    let node_for_decl = |d: &Decl| -> Option<tree_sitter::Node> {
        tree.root_node().named_descendant_for_point_range(
            to_point(d.range.start).ok()?,
            to_point(d.range.end).ok()?,
        )
    };

    let node = node_for_decl(decl)?;

    let d = match node.kind() {
        "var_decl" | "formal_arg" => {
            let typ = node.named_child(1)?;

            match typ.kind() {
                "type" => resolve(db, typ, None, uri.clone()),
                "initializer" => typ
                    .named_children(&mut typ.walk())
                    .find(|n| n.kind() == "init")
                    .and_then(|n| resolve(db, n, None, uri.clone())),
                _ => None,
            }
        }
        "id" => {
            let parent = node.parent()?;
            parent
                .named_children(&mut parent.walk())
                .find_map(|n| match n.kind() {
                    "type" => resolve(db, n, None, uri.clone()),
                    _ => None,
                })
        }
        _ => None,
    };

    // Perform additional unwrapping if needed.
    d.and_then(|d| match d.kind {
        // For function declarations produce the function's return type.
        DeclKind::FuncDecl | DeclKind::FuncDef => {
            resolve(db, fn_result(node_for_decl(&d)?)?, None, d.uri.clone())
        }

        // Other kinds we return directly.
        _ => Some(d),
    })
}

#[cfg(test)]
mod test {
    use std::{path::PathBuf, str::FromStr, sync::Arc};

    use insta::assert_debug_snapshot;
    use lspower::lsp::{Position, Url};

    use crate::{ast::Ast, lsp::TestDatabase, parse::Parse, Files};

    #[test]
    fn loaded_files_recursive() {
        let mut db = TestDatabase::new();

        let a = Arc::new(Url::from_file_path("/tmp/a.zeek").unwrap());
        db.add_file(
            a.clone(),
            "@load b\n
             @load d;",
        );

        let b = Arc::new(Url::from_file_path("/tmp/b.zeek").unwrap());
        db.add_file(b.clone(), "@load c");

        let c = Arc::new(Url::from_file_path("/tmp/c.zeek").unwrap());
        db.add_file(c.clone(), "@load d");

        let d = Arc::new(Url::from_file_path("/tmp/d.zeek").unwrap());
        db.add_file(d.clone(), "");

        assert_debug_snapshot!(db.0.loaded_files_recursive(a));
    }

    #[test]
    fn loaded_files() {
        let mut db = TestDatabase::new();

        // Prefix file both in file directory and in prefix. This should appear exactly once.
        let pre1 = PathBuf::from_str("/tmp/p").unwrap();
        let p1 = Arc::new(Url::from_file_path(pre1.join("p1/p1.zeek")).unwrap());
        db.add_prefix(pre1);
        db.add_file(p1.clone(), "");

        // Prefix file in external directory.
        let pre2 = PathBuf::from_str("/p").unwrap();
        let p2 = Arc::new(Url::from_file_path(pre2.join("p2/p2.zeek")).unwrap());
        db.add_prefix(pre2);
        db.add_file(p2.clone(), "");

        let foo = Arc::new(Url::from_file_path("/tmp/foo.zeek").unwrap());
        db.add_file(
            foo.clone(),
            "@load foo\n
             @load foo.zeek\n
             @load p1/p1\n
             @load p2/p2",
        );

        assert_debug_snapshot!(db.0.loaded_files(foo));
    }

    #[test]
    fn resolve() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());

        db.add_file(
            uri.clone(),
            "module x;

type X: record {
    f1: count &optional;
};

type Y: record {
    yx: X &optional;
};

global c: count;
global x: X;

c;
x$f1;
x?$f1;

function fn(x2: X, y: count) {
    y;
    x2$f1;
    x2?$f1;
}

global y: Y;
y$yx$f1;
",
        );

        let db = db.snapshot();
        let source = db.source(uri.clone());
        let tree = db.parse(uri.clone()).unwrap();

        // `c` resolves to `local c: ...`.
        let node = tree
            .named_descendant_for_position(&Position::new(13, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `s?$f1` resolves to `f1: count`.
        let node = tree
            .named_descendant_for_position(&Position::new(15, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `y` resolves to `y: count` via function argument.
        let node = tree
            .named_descendant_for_position(&Position::new(18, 4))
            .unwrap();
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `x2$f1` resolves to `f1:count ...` via function argument.
        let node = tree
            .named_descendant_for_position(&Position::new(19, 7))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `x$f1` resolves to `f1: count ...`.
        let node = tree
            .named_descendant_for_position(&Position::new(14, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `x2$f1` resolves to `f1: count ...`.
        let node = tree
            .named_descendant_for_position(&Position::new(20, 8))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // Check resolution when multiple field accesses are involved.
        let node = tree
            .named_descendant_for_position(&Position::new(24, 5))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));
    }

    #[test]
    fn resolve_initializer() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());

        db.add_file(
            uri.clone(),
            "module x;
type X: record { f: count &optional; };
function fun(): X { return X(); }
global x = fun();
x$f;",
        );

        let db = db.snapshot();
        let source = db.source(uri.clone());
        let tree = db.parse(uri.clone()).unwrap();

        let node = tree
            .named_descendant_for_position(&Position::new(4, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri));
    }

    #[test]
    fn resolve_elsewhere() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/y.zeek").unwrap());

        db.add_file(
            Arc::new(Url::from_file_path("/x.zeek").unwrap()),
            "module x;
            export {
                type X: record { f: count &optional; };
                global x: X;
            }",
        );

        db.add_file(
            uri.clone(),
            "module y;
@load ./x
x::x;",
        );

        let db = db.snapshot();
        let source = db.source(uri.clone());
        let tree = db.parse(uri.clone()).unwrap();

        let node = tree
            .named_descendant_for_position(&Position::new(2, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("x::x"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri));
    }
}
