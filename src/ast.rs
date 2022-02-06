use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use lspower::lsp::Url;
use salsa::Snapshot;
use tracing::instrument;

use crate::{
    lsp::Database,
    parse::Parse,
    query::{self, Decl, DeclKind, Node, Query},
    zeek, Files,
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
pub(crate) fn resolve(snapshot: &Snapshot<Database>, node: Node, uri: Arc<Url>) -> Option<Decl> {
    let source = snapshot.source(uri.clone());

    match node.kind() {
        // If we are on an `expr` or `init` node unwrap it and work on whatever is inside.
        "expr" | "init" => {
            return node
                .named_child_not("nl")
                .and_then(|c| resolve(snapshot, c, uri.clone()));
        }
        // If we are on a `field_access` or `field_check` search the rhs in the scope of the lhs.
        "field_access" | "field_check" => {
            let xs = node.named_children_not("nl");
            let lhs = xs.get(0).copied()?;
            let rhs = xs.get(1).copied()?;

            let id = rhs.utf8_text(source.as_bytes()).ok()?;

            let var_decl = resolve(snapshot, lhs, uri.clone())?;
            let type_decl = typ(snapshot, &var_decl)?;

            match type_decl.kind {
                DeclKind::Type(fields) => {
                    // Find the given id in the fields.
                    return fields.into_iter().find(|f| dbg!(&f.id) == dbg!(id));
                }
                _ => return None,
            }
        }
        _ => {}
    }

    // If the node is part of a field access or check resolve it in the referenced record.
    if let Some(p) = node.parent() {
        if p.kind() == "field_access" || p.kind() == "field_check" {
            return resolve(snapshot, p, uri.clone());
        }
    }

    // Try to find a decl with name of the given node up the tree.
    let id = node.utf8_text(source.as_bytes()).ok()?;

    resolve_id(snapshot, id, node, uri)
}

pub fn resolve_id(db: &Snapshot<Database>, id: &str, scope: Node, uri: Arc<Url>) -> Option<Decl> {
    let source = db.source(uri.clone());

    let mut scope = scope;
    loop {
        if let Some(decl) = query::decl_at(id, scope, uri.clone(), source.as_bytes()) {
            return Some(decl);
        }

        if let Some(p) = scope.parent() {
            scope = p;
        } else {
            break;
        }
    }

    // We haven't found a decl yet, look in loaded modules.
    db.implicit_decls()
        .iter()
        .chain(db.loaded_decls(uri).iter())
        .find(|d| d.fqid == id)
        .cloned()
}

/// Determine the type of the given decl.
pub(crate) fn typ(db: &Snapshot<Database>, decl: &Decl) -> Option<Decl> {
    /// Helper to extract function return values.
    fn fn_result(decl: Node) -> Option<Node> {
        // The return type is stored in the func_params.
        let func_params = decl.named_child("func_params")?;

        // A `type` directly stored in the `func_params` is the return type.
        func_params.named_child("type")
    }

    let uri = &decl.uri;

    let tree = db.parse(uri.clone())?;

    let node = tree
        .root_node()
        .named_descendant_for_point_range(decl.range)?;

    let d = match node.kind() {
        "var_decl" | "formal_arg" => {
            let typ = node.named_children_not("nl").into_iter().nth(1)?;

            match typ.kind() {
                "type" => resolve(db, typ, uri.clone()),
                "initializer" => typ
                    .named_child("init")
                    .and_then(|n| resolve(db, n, uri.clone())),
                _ => None,
            }
        }
        "id" => node
            .parent()?
            .named_child("type")
            .and_then(|n| resolve(db, n, uri.clone())),
        _ => None,
    };

    // Perform additional unwrapping if needed.
    d.and_then(|d| match d.kind {
        // For function declarations produce the function's return type.
        DeclKind::FuncDecl | DeclKind::FuncDef => resolve(
            db,
            fn_result(tree.root_node().named_descendant_for_point_range(d.range)?)?,
            d.uri,
        ),

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
        let root = tree.root_node();

        // `c` resolves to `local c: ...`.
        let node = root
            .named_descendant_for_position(Position::new(13, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(super::resolve(&db, node, uri.clone()));

        // `c?$f1` resolves to `f1: count`.
        let node = root
            .named_descendant_for_position(Position::new(15, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, uri.clone()));

        // `y` resolves to `y: count` via function argument.
        let node = root
            .named_descendant_for_position(Position::new(18, 4))
            .unwrap();
        assert_debug_snapshot!(super::resolve(&db, node, uri.clone()));

        // `x2$f1` resolves to `f1:count ...` via function argument.
        let node = root
            .named_descendant_for_position(Position::new(19, 7))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, uri.clone()));

        // `x$f1` resolves to `f1: count ...`.
        let node = root
            .named_descendant_for_position(Position::new(14, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, uri.clone()));

        // `x2$f1` resolves to `f1: count ...`.
        let node = root
            .named_descendant_for_position(Position::new(20, 8))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, uri.clone()));

        // Check resolution when multiple field accesses are involved.
        let node = root
            .named_descendant_for_position(Position::new(24, 5))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, uri.clone()));
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

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(4, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f"));
        assert_debug_snapshot!(super::resolve(&db, node, uri));
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

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("x::x"));
        assert_debug_snapshot!(super::resolve(&db, node, uri));
    }
}
