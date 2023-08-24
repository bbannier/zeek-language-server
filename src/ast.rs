use std::{
    collections::{BTreeSet, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use tower_lsp::lsp_types::Url;
use tracing::{error, instrument};

use crate::{
    parse::Parse,
    query::{self, Decl, DeclKind, NodeLocation, Query},
    zeek, File, Files,
};

#[salsa::query_group(AstStorage)]
pub trait Ast: Files + Parse + Query {
    #[salsa::input]
    fn workspace_folders(&self) -> Arc<Vec<Url>>;

    #[salsa::input]
    fn prefixes(&self) -> Arc<Vec<PathBuf>>;

    #[must_use]
    fn loaded_files(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn loaded_files_recursive(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    /// Get the decls in uri and all files explicitly loaded by it.
    #[must_use]
    fn explicit_decls_recursive(&self, url: Arc<Url>) -> Arc<BTreeSet<Decl>>;

    #[must_use]
    fn implicit_loads(&self) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn implicit_decls(&self) -> Arc<Vec<Decl>>;

    #[must_use]
    fn possible_loads(&self, uri: Arc<Url>) -> Arc<Vec<String>>;

    /// Find decl with ID from the node up the tree and in all other loaded files.
    #[must_use]
    fn resolve(&self, node: NodeLocation) -> Option<Arc<Decl>>;

    /// Determine the type of the given decl.
    fn typ(&self, decl: Arc<Decl>) -> Option<Arc<Decl>>;

    /// Resolve anidentifier in a scope.
    fn resolve_id(&self, id: Arc<String>, scope: NodeLocation) -> Option<Arc<Decl>>;

    /// Gets decl for the builtin type `id`.
    fn builtin_type(&self, id: Arc<String>) -> Arc<Decl>;
}

#[instrument(skip(db))]
fn resolve_id(db: &dyn Ast, id: Arc<String>, scope: NodeLocation) -> Option<Arc<Decl>> {
    let uri = scope.uri;
    let tree = db.parse(uri.clone())?;
    let scope = tree
        .root_node()
        .named_descendant_for_point_range(scope.range)?;
    let source = db.files().get(&uri).map(|f| f.source())?;

    let node = scope;

    let combined_decl_with_redefs = |decls: Vec<Decl>| -> Option<Decl> {
        let (decl, redefs): (Vec<_>, Vec<_>) = decls.into_iter().partition(|d| !is_redef(d));

        let decl = decl.into_iter().next()?;

        let redefd_fields = redefs
            .into_iter()
            .filter_map(|r| match r.kind {
                DeclKind::RedefRecord(fields) => Some(fields),
                _ => None,
            })
            .flatten();

        match decl.kind {
            DeclKind::Type(mut fields) => {
                fields.extend(redefd_fields);
                Some(Decl {
                    kind: DeclKind::Type(fields),
                    ..decl
                })
            }
            _ => Some(decl),
        }
    };

    let mut decls = Vec::new();
    let mut scope = scope;
    loop {
        decls.extend(
            // Find all decls with this name, defined before the node. We do this so that e.g.,
            // redefs in the same file are only in effect after they have been declared.
            query::decls_(scope, uri.clone(), source.as_bytes())
                .into_iter()
                .filter(|d| d.id == id.as_str() || d.fqid == id.as_str())
                .filter(|d| {
                    let Some(loc) = &d.loc else { return false };
                    loc.range.start <= node.range().start
                }),
        );

        if decls.iter().any(|d| !is_redef(d)) {
            break;
        }

        if let Some(p) = scope.parent() {
            scope = p;
        } else {
            break;
        }
    }

    // If we have found something that isn't a redef this is the decl which should be visible at
    // this point. Combine it with all redefs visible up to this point.
    if decls.iter().any(|d| !is_redef(d)) {
        return combined_decl_with_redefs(decls).map(Arc::new);
    }

    let result = decls.into_iter().next();

    if let Some(r) = &result {
        // If we have found a non-redef decl this is the final decl visible at this point as redefs
        // elsewhere cannot add to it here, yet.
        if !is_redef(r) {
            return Some(Arc::new(r.clone()));
        }
    }

    // We haven't found a full decl yet, look in loaded modules. This needs to take all visible redefs
    // into account.
    let decls = db.decls(uri.clone());
    let implicit_decls = db.implicit_decls();
    let explicit_decls_recursive = db.explicit_decls_recursive(uri.clone());
    let last_decl = if let Some(redef) = &result {
        redef
    } else {
        let all = decls
            .iter()
            .chain(implicit_decls.iter())
            .chain(explicit_decls_recursive.iter())
            .filter(|d| d.fqid == id.as_str())
            .collect::<Vec<_>>();

        // Prefer to return the decl instead of the definition for constructs which support both.
        // In either case, the last instance still wins.
        let only_decls = all.iter().filter(|d| {
            matches!(
                d.kind,
                DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_)
            )
        });

        if let Some(decl) = only_decls.last() {
            decl
        } else {
            *all.last()?
        }
    };

    if is_redef(last_decl) {
        // If we have found a redef resolve it and synthesize a new, full decl.
        // NOTE: since we have found the last decl, all other relevant redefs are already in scope.
        let redef = last_decl;
        let decls = resolve_redef(db, redef, uri);

        let original_decl = decls.iter().find(|d| !is_redef(d))?.clone();
        let redefs = decls
            .iter()
            .filter(|d| is_redef(d))
            .filter_map(|r| match &r.kind {
                DeclKind::RedefRecord(fields) => Some(fields.clone()),
                _ => None,
            })
            .flatten();
        match original_decl.kind {
            DeclKind::Type(mut fields) => {
                fields.extend(redefs);
                Some(Arc::new(Decl {
                    kind: DeclKind::Type(fields),
                    ..original_decl
                }))
            }
            _ => None,
        }
    } else {
        // If the decl we have found is not a redef return it directly.
        Some(Arc::new(last_decl.clone()))
    }
}

#[allow(clippy::needless_pass_by_value)]
fn typ(db: &dyn Ast, decl: Arc<Decl>) -> Option<Arc<Decl>> {
    // If we see a type decl with location we are likely dealing with a buildin type already which
    // cannot be further resolved; return it directly.
    if let DeclKind::Type(_) = &decl.kind {
        if decl.loc.is_none() {
            return Some(decl);
        }
    }

    let Some(loc) = &decl.loc else {
        return Some(decl);
    };
    let uri = &loc.uri;

    let tree = db.parse(uri.clone())?;

    let node = tree
        .root_node()
        .named_descendant_for_point_range(loc.range)?;

    let d = match node.kind() {
        "var_decl" | "formal_arg" => {
            let typ = node.named_children_not("nl").into_iter().nth(1)?;

            match typ.kind() {
                "type" => db.resolve(NodeLocation::from_node(uri.clone(), typ)),
                "initializer" => typ
                    .named_child("init")
                    .and_then(|n| db.resolve(NodeLocation::from_node(uri.clone(), n))),
                _ => None,
            }
        }
        "id" => node
            .parent()?
            .named_child("type")
            .and_then(|n| db.resolve(NodeLocation::from_node(uri.clone(), n))),
        _ => None,
    };

    // Perform additional unwrapping if needed.
    d.and_then(|d| {
        let Some(loc) = &d.loc else { return Some(d) };

        match &d.kind {
            // For function declarations produce the function's return type.
            DeclKind::FuncDecl(sig) | DeclKind::FuncDef(sig) => db.resolve_id(
                Arc::new(sig.result.clone()?),
                NodeLocation::from_node(loc.uri.clone(), node),
            ),

            // For enum members return the enum.
            DeclKind::EnumMember => {
                // Depending on whether we are in an enum type decl or enum redef decl we need to go up
                // to a different height. In the end we only use the ID so detect that, so we go to the
                // outer entity and then resolve the ID.
                let mut n = tree
                    .root_node()
                    .named_descendant_for_point_range(loc.range)?;
                while let Some(p) = n.parent() {
                    match n.kind() {
                        "type_decl" | "redef_enum_decl" => break,
                        _ => n = p,
                    }
                }

                db.resolve(NodeLocation::from_node(
                    loc.uri.clone(),
                    n.named_child("id")?,
                ))
            }

            // Return the actual type for variable declarations.
            DeclKind::Global | DeclKind::Variable | DeclKind::LoopIndex(_, _) => db.typ(d),

            // Other kinds we return directly.
            _ => Some(d),
        }
    })
}

fn resolve(db: &dyn Ast, location: NodeLocation) -> Option<Arc<Decl>> {
    let uri = location.uri.clone();
    let tree = db.parse(uri.clone())?;
    let node = tree
        .root_node()
        .named_descendant_for_point_range(location.range)?;
    let source = db.files().get(&uri).map(|f| f.source())?;

    match node.kind() {
        // Builtin types.
        // NOTE: This is driven by what types the parser exposes, extend as possible.
        "ipv4" | "ipv6" | "hostname" | "hex" | "port" | "interval" | "string" | "floatp"
        | "integer" => return Some(db.builtin_type(Arc::new(format!("<{}>", node.kind())))),
        "type" => {
            let text = Arc::new(node.utf8_text(source.as_bytes()).ok()?.to_string());
            return db
                .resolve_id(text.clone(), location)
                .or_else(|| Some(db.builtin_type(text)));
        }

        "expr" | "init" => {
            return node
                .named_child_not("nl")
                .and_then(|c| db.resolve(NodeLocation::from_node(uri.clone(), c)));
        }
        // If we are on a `field_access` or `field_check` search the rhs in the scope of the lhs.
        "field_access" | "field_check" => {
            let xs = node.named_children_not("nl");
            let lhs = xs.get(0).copied()?;
            let rhs = xs.get(1).copied()?;

            let id = rhs.utf8_text(source.as_bytes()).ok()?;

            let var_decl = db.resolve(NodeLocation::from_node(uri, lhs))?;
            let type_decl = db.typ(var_decl)?;

            match &type_decl.kind {
                DeclKind::Type(fields) => {
                    // Find the given id in the fields.
                    return fields
                        .iter()
                        .find(|f| f.id == id)
                        .map(Clone::clone)
                        .map(Arc::new);
                }
                DeclKind::Field => return db.typ(type_decl),
                _ => return None,
            }
        }
        _ => {}
    }

    // If the node is part of a field access or check resolve it in the referenced record.
    if let Some(p) = node.parent() {
        if p.kind() == "field_access" || p.kind() == "field_check" {
            return db.resolve(NodeLocation::from_node(uri, p));
        }
    }

    // Try to find a decl with name of the given node up the tree.
    let id = node.utf8_text(source.as_bytes()).ok()?.to_string();

    if let Some(r) = db.resolve_id(Arc::new(id.clone()), location.clone()) {
        // If we have found something which can have separate declaration and definition
        // return the declaration if possible. At this point this must be in another file.
        match r.kind {
            DeclKind::FuncDef(_) | DeclKind::EventDef(_) | DeclKind::HookDef(_) => {
                if let Some(decl) =
                    db.resolve_id(Arc::new(id), NodeLocation::from_node(uri, tree.root_node()))
                {
                    return Some(decl);
                }
            }
            _ => {}
        };

        // We seem to only know the definition.
        return Some(r);
    }

    // If we arrive here and the identifier does not contain `::` it could also refer to a
    // declaration in the same module, but defined in a different file. Try to find it by
    // searching for it by its fully-qualified name.
    if !id.contains("::") {
        if let Some(module) = tree
            .root_node()
            .named_child("module_decl")
            .and_then(|d| d.named_child("id"))
            .and_then(|id| id.utf8_text(source.as_bytes()).ok())
        {
            if let Some(r) = db.resolve_id(Arc::new(format!("{module}::{id}")), location) {
                return Some(r);
            }
        }
    }
    None
}

#[allow(clippy::needless_pass_by_value)]
fn loaded_files(db: &dyn Ast, uri: Arc<Url>) -> Arc<Vec<Arc<Url>>> {
    let files = db.files();

    let prefixes = db.prefixes();

    let loads: Vec<_> = db.loads(uri.clone()).iter().map(PathBuf::from).collect();

    let mut loaded_files = Vec::new();

    for load in &loads {
        if let Some(f) = load_to_file(load, uri.as_ref(), &files.keys().collect(), &prefixes) {
            loaded_files.push(f.clone());
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
fn explicit_decls_recursive(db: &dyn Ast, uri: Arc<Url>) -> Arc<BTreeSet<Decl>> {
    let mut decls = db.decls(uri.clone()).as_ref().clone();

    for load in db.loaded_files_recursive(uri).as_ref() {
        for decl in &*db.decls(load.clone()) {
            decls.insert(decl.clone());
        }
    }

    Arc::new(decls)
}

#[instrument(skip(db))]
fn implicit_loads(db: &dyn Ast) -> Arc<Vec<Arc<Url>>> {
    let mut loads = Vec::new();

    // These loops looks horrible, but is okay since this function will be cached most of the time
    // (unless global state changes).
    for essential_input in zeek::essential_input_files() {
        let mut implicit_file = None;
        for f in db.files().keys() {
            let Ok(path) = f.to_file_path() else { continue };

            if !path.ends_with(essential_input) {
                continue;
            }

            for p in db.prefixes().iter() {
                if path.strip_prefix(p).is_ok() {
                    implicit_file = Some(f.clone());
                    break;
                }
            }
        }

        if let Some(implicit_load) = implicit_file {
            loads.push(implicit_load);
        } else {
            error!("could not resolve load of '{essential_input}'");
            continue;
        };
    }

    Arc::new(loads)
}

#[instrument(skip(db))]
fn implicit_decls(db: &dyn Ast) -> Arc<Vec<Decl>> {
    let mut decls = HashSet::new();

    for implicit_load in db.implicit_loads().as_ref() {
        decls.extend(
            db.explicit_decls_recursive(implicit_load.clone())
                .as_ref()
                .iter()
                .cloned(),
        );
    }

    let decls = decls.into_iter().collect::<Vec<_>>();
    Arc::new(decls)
}

#[instrument(skip(db))]
fn possible_loads(db: &dyn Ast, uri: Arc<Url>) -> Arc<Vec<String>> {
    let Ok(path) = uri.to_file_path() else {
        return Arc::new(Vec::new());
    };

    let Some(path) = path.parent() else {
        return Arc::new(Vec::new());
    };

    let prefixes = db.prefixes();
    let files = db.files();

    let loads = files
        .keys()
        .filter(|f| f.path() != uri.path())
        .filter_map(|f| {
            // Always strip any extension.
            let f = f.to_file_path().ok()?.with_extension("");

            // For `__load__.zeek` files one should use the directory name for loading.
            let f = if f.file_stem()? == "__load__" {
                f.parent()?
            } else {
                &f
            };

            if let Ok(f) = f.strip_prefix(path) {
                Some(String::from(Path::new(".").join(f).to_str()?))
            } else {
                prefixes.iter().find_map(|p| {
                    let l = f.strip_prefix(p).ok()?.to_str()?;
                    Some(String::from(l))
                })
            }
        })
        .collect();

    Arc::new(loads)
}

#[must_use]
pub fn is_redef(d: &Decl) -> bool {
    matches!(
        &d.kind,
        DeclKind::Redef | DeclKind::RedefEnum(_) | DeclKind::RedefRecord(_)
    )
}

#[instrument(skip(db))]
fn resolve_redef(db: &dyn Ast, redef: &Decl, scope: Arc<Url>) -> Arc<Vec<Decl>> {
    if !is_redef(redef) {
        return Arc::new(Vec::new());
    }

    let implicit_decls = db.implicit_decls();
    let loaded_decls = db.explicit_decls_recursive(scope.clone());
    let decls = db.decls(scope);

    let all_decls: HashSet<_> = implicit_decls
        .iter()
        .chain(loaded_decls.iter())
        .chain(decls.iter())
        .collect();

    let xs = all_decls
        .into_iter()
        .filter(|x| x.fqid == redef.fqid)
        .cloned()
        .collect::<Vec<_>>();
    Arc::new(xs)
}

pub(crate) fn load_to_file<'url>(
    load: &Path,
    base: &Url,
    files: &BTreeSet<&'url Arc<Url>>,
    prefixes: &[PathBuf],
) -> Option<&'url Arc<Url>> {
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

        let load_with_extension = {
            let mut l = load.as_os_str().to_owned();
            l.push(".zeek");
            PathBuf::from(l)
        };

        // File known w/o extension.
        let known_no_ext = files
            .iter()
            .find(|(_, p)| p.ends_with(&load_with_extension));

        // Load is directory with `__load__.zeek`.
        let known_directory = files
            .iter()
            .find(|(_, p)| p.ends_with(load.join("__load__.zeek")));

        known_exactly
            .or(known_no_ext)
            .or(known_directory)
            .map(|(f, _)| **f)
    })
}

#[allow(clippy::needless_pass_by_value)]
fn builtin_type(_: &dyn Ast, id: Arc<String>) -> Arc<Decl> {
    Arc::new(Decl {
        module: query::ModuleId::Global,
        id: id.to_string(),
        fqid: id.to_string(),
        kind: DeclKind::Type(Vec::new()),
        is_export: None,
        loc: None,
        documentation: format!("Builtin type '{id}'"),
    })
}

#[cfg(test)]
mod test {
    use std::{path::PathBuf, str::FromStr, sync::Arc};

    use insta::assert_debug_snapshot;
    use tower_lsp::lsp_types::{Position, Range, Url};

    use crate::{
        ast::Ast,
        lsp::TestDatabase,
        parse::Parse,
        query::{DeclKind, NodeLocation},
        File, Files,
    };

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
        db.add_file(b, "@load c");

        let c = Arc::new(Url::from_file_path("/tmp/c.zeek").unwrap());
        db.add_file(c, "@load d");

        let d = Arc::new(Url::from_file_path("/tmp/d.zeek").unwrap());
        db.add_file(d, "");

        assert_debug_snapshot!(db.0.loaded_files_recursive(a));
    }

    #[test]
    fn loaded_files() {
        let mut db = TestDatabase::new();

        // Prefix file both in file directory and in prefix. This should appear exactly once.
        let pre1 = PathBuf::from_str("/tmp/p").unwrap();
        let p1 = Arc::new(Url::from_file_path(pre1.join("p1/p1.zeek")).unwrap());
        db.add_prefix(pre1);
        db.add_file(p1, "");

        // Prefix file in external directory.
        let pre2 = PathBuf::from_str("/p").unwrap();
        let p2 = Arc::new(Url::from_file_path(pre2.join("p2/p2.zeek")).unwrap());
        db.add_prefix(pre2);
        db.add_file(p2, "");

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

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        // `c` resolves to `local c: ...`.
        let node = root
            .named_descendant_for_position(Position::new(13, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), node)));

        // `c?$f1` resolves to `f1: count`.
        let node = root
            .named_descendant_for_position(Position::new(15, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), node)));

        // `y` resolves to `y: count` via function argument.
        let node = root
            .named_descendant_for_position(Position::new(18, 4))
            .unwrap();
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), node)));

        // `x2$f1` resolves to `f1:count ...` via function argument.
        let node = root
            .named_descendant_for_position(Position::new(19, 7))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), node)));

        // `x$f1` resolves to `f1: count ...`.
        let node = root
            .named_descendant_for_position(Position::new(14, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), node)));

        // `x2$f1` resolves to `f1: count ...`.
        let node = root
            .named_descendant_for_position(Position::new(20, 8))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), node)));

        // Check resolution when multiple field accesses are involved.
        let node = root
            .named_descendant_for_position(Position::new(24, 5))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, node)));
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

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(4, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, node)));
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

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("x::x"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, node)));
    }

    #[test]
    fn resolve_same_module_elsewhere() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/y.zeek").unwrap());

        db.add_file(
            Arc::new(Url::from_file_path("/x.zeek").unwrap()),
            "module x;
            export {
                type X: record { f: count &optional; };
                global y: X;
            }",
        );

        db.add_file(
            uri.clone(),
            "module x;
@load ./x
y;",
        );

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("y"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, node)));
    }

    #[test]
    fn resolve_redef() {
        let mut db = TestDatabase::new();
        db.add_file(
            Arc::new(Url::from_file_path("/x.zeek").unwrap()),
            "module x;
type X: record { x1: count; };",
        );

        let uri = Arc::new(Url::from_file_path("/y.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "module y;
@load x
redef record x::X += { x2: count; };
global x: x::X;
x;
x$x1;
x$x2;",
        );

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let x = root
            .named_descendant_for_position(Position::new(4, 0))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()), Ok("x"));
        assert_eq!(
            db.resolve(NodeLocation::from_node(uri.clone(), x))
                .unwrap()
                .kind,
            super::DeclKind::Global
        );

        let x1 = root
            .named_descendant_for_position(Position::new(5, 3))
            .unwrap();
        assert_eq!(x1.utf8_text(source.as_bytes()), Ok("x1"));
        assert_eq!(
            db.resolve(NodeLocation::from_node(uri.clone(), x1))
                .unwrap()
                .kind,
            super::DeclKind::Field
        );

        let x2 = root
            .named_descendant_for_position(Position::new(6, 3))
            .unwrap();
        assert_eq!(x2.utf8_text(source.as_bytes()), Ok("x2"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, x2)));
    }

    #[test]
    fn redef_global_record() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());

        db.add_file(
            Arc::new(Url::from_file_path("/init-bare.zeek").unwrap()),
            "module GLOBAL;
type connection: record { id: string; };",
        );
        db.add_file(
            uri.clone(),
            "module x;
@load init-bare
redef record connection += { name: string; };
global c: connection;",
        );

        let db = db.snapshot();
        let tree = db.parse(uri.clone()).unwrap();
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();

        let c = tree
            .root_node()
            .named_descendant_for_position(Position::new(3, 7))
            .unwrap();
        assert_eq!(c.utf8_text(source.as_bytes()), Ok("c"));
        let c_res = db.resolve(NodeLocation::from_node(uri, c)).unwrap();
        assert_eq!(c_res.kind, super::DeclKind::Global);
        let c_type = db.typ(c_res).unwrap();
        assert_debug_snapshot!(c_type);
    }

    #[test]
    fn redef_record_same_file() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "module x;
type A: record {};
global g: A;
redef record A += { c: count &optional; };
function f(a: A) {
    a$c;
}",
        );

        let db = db.snapshot();
        let tree = db.parse(uri.clone()).unwrap();
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();

        let g = tree
            .root_node()
            .named_descendant_for_position(Position::new(2, 7))
            .unwrap();
        assert_eq!(g.utf8_text(source.as_bytes()), Ok("g"));
        assert_debug_snapshot!(db.typ(db.resolve(NodeLocation::from_node(uri.clone(), g)).unwrap()));

        let f_a = tree
            .root_node()
            .named_descendant_for_position(Position::new(4, 11))
            .unwrap();
        assert_eq!(f_a.utf8_text(source.as_bytes()), Ok("a"));
        assert_debug_snapshot!(db.typ(
            db.resolve(NodeLocation::from_node(uri.clone(), f_a))
                .unwrap()
        ));

        let a = tree
            .root_node()
            .named_descendant_for_position(Position::new(5, 4))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()), Ok("a"));
        assert_debug_snapshot!(db.typ(db.resolve(NodeLocation::from_node(uri.clone(), a)).unwrap()));

        let a_c = tree
            .root_node()
            .named_descendant_for_position(Position::new(5, 6))
            .unwrap();
        assert_eq!(a_c.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, a_c)));
    }

    #[test]
    fn typ_fn_call() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "module x;
type X1: record { f: count &optional; };
type X2: record { f: count &optional; };
global f1: function(): X1;
function f2(): X2 { return X2()};
global x1 = f1();
global x2 = f2();
",
        );

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let x1 = root
            .named_descendant_for_position(Position::new(5, 8))
            .unwrap();
        assert_eq!(x1.utf8_text(source.as_bytes()), Ok("x1"));
        assert_eq!(
            &db.typ(
                db.resolve(NodeLocation::from_node(uri.clone(), x1))
                    .unwrap()
            )
            .unwrap()
            .id,
            "X1"
        );

        let x2 = root
            .named_descendant_for_position(Position::new(6, 8))
            .unwrap();
        assert_eq!(x2.utf8_text(source.as_bytes()), Ok("x2"));
        assert_eq!(
            &db.typ(db.resolve(NodeLocation::from_node(uri, x2)).unwrap())
                .unwrap()
                .id,
            "X2"
        );
    }

    #[test]
    fn typ_var_decl() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "
            type B: record {
                i: count;
            };
            type A: record {
                b: B;
            };
            event foo(a: A) {
                local b0: B = a$b;
                local b1 = a$b;
                local i1 = a$b$i;
                local i2 = b1$i;
            }
            ",
        );

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        {
            let b0 = root
                .named_descendant_for_position(Position::new(8, 22))
                .unwrap();
            assert_eq!(b0.utf8_text(source.as_bytes()).unwrap(), "b0");

            let decl = db
                .resolve(NodeLocation::from_node(uri.clone(), b0))
                .unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(db.typ(decl));
        }

        {
            let b1 = root
                .named_descendant_for_position(Position::new(9, 22))
                .unwrap();
            assert_eq!(b1.utf8_text(source.as_bytes()).unwrap(), "b1");

            let decl = db
                .resolve(NodeLocation::from_node(uri.clone(), b1))
                .unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(db.typ(decl));
        }

        {
            let i1 = root
                .named_descendant_for_position(Position::new(10, 22))
                .unwrap();
            assert_eq!(i1.utf8_text(source.as_bytes()).unwrap(), "i1");

            let decl = db
                .resolve(NodeLocation::from_node(uri.clone(), i1))
                .unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(db.typ(decl));
        }

        {
            let i2 = root
                .named_descendant_for_position(Position::new(11, 22))
                .unwrap();
            assert_eq!(i2.utf8_text(source.as_bytes()).unwrap(), "i2");

            let decl = db.resolve(NodeLocation::from_node(uri, i2)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(db.typ(decl));
        }
    }

    #[test]
    fn typ_builtin() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "
            global x = 1;
            global y = x + 1;

            global i1 = 1.1.1.1;
            global i2 = [dada:beef::ffff:ffff:ffff:ffff];
            global h = example.org;
            global he = 0x1234;
            global p = 8080/tcp;
            global i3 = 10 mins;
            global s = \"str\";
            global f = 0.1234;",
        );

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        for (i, _) in source
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
        {
            let pos = Position::new(i.try_into().unwrap(), 19);
            assert_debug_snapshot!(db
                .resolve(NodeLocation::from_range(uri.clone(), Range::new(pos, pos)))
                .and_then(|d| db.typ(d)));
        }

        // Validate that type is inferred for derived values.
        let x = root
            .named_descendant_for_position(Position::new(1, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        let x_typ = db
            .resolve(NodeLocation::from_node(uri.clone(), x))
            .and_then(|d| db.typ(d));
        let y = root
            .named_descendant_for_position(Position::new(2, 19))
            .unwrap();
        assert_eq!(y.utf8_text(source.as_bytes()).unwrap(), "y");
        let y_typ = db
            .resolve(NodeLocation::from_node(uri.clone(), y))
            .and_then(|d| db.typ(d));
        assert_eq!(x_typ, y_typ);
    }

    #[test]
    fn typ_explicit() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "
            global a : count = 42;

            type X: record {};
            global x: X;
            ",
        );

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(1, 19))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(db
            .resolve(NodeLocation::from_node(uri.clone(), a))
            .and_then(|d| db.typ(d)));

        let x = root
            .named_descendant_for_position(Position::new(4, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        assert_debug_snapshot!(db
            .resolve(NodeLocation::from_node(uri, x))
            .and_then(|d| db.typ(d)));
    }

    #[test]
    fn for_parameters_vec() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            r#"function f() {
for (i in vector(1, 2, 3)) { i; }
i;
for (s in set(1, 2, 3)) { s; }
for (ta, tb in table([1]="a", [2]="b")) { ta; tb; }
}"#,
        );

        let db = db.0;
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();

        // Vector iteration.
        let i1 = root
            .named_descendant_for_position(Position::new(1, 29))
            .unwrap();
        assert_eq!(i1.utf8_text(source.as_bytes()), Ok("i"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), i1)));

        // TODO(bbannier): In Zeek we should be able to see the loop parameter after the loop, but
        // currently don't. It seems one should be able to see the loop var eve if the loop is
        // wrapped in `{...}`, unsure how to model that.
        let i2 = root
            .named_descendant_for_position(Position::new(2, 0))
            .unwrap();
        assert_eq!(i2.utf8_text(source.as_bytes()), Ok("i"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), i2)));

        // Set iteration.
        let s = root
            .named_descendant_for_position(Position::new(3, 26))
            .unwrap();
        assert_eq!(s.utf8_text(source.as_bytes()), Ok("s"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), s)));

        // Table iteration.
        let ta = root
            .named_descendant_for_position(Position::new(4, 42))
            .unwrap();
        let tb = root
            .named_descendant_for_position(Position::new(4, 46))
            .unwrap();
        assert_eq!(ta.utf8_text(source.as_bytes()), Ok("ta"));
        assert_eq!(tb.utf8_text(source.as_bytes()), Ok("tb"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), ta)));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, tb)));
    }

    #[test]
    fn enum_value_docs() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "
            export {
                    type E: enum {
                            ## A.
                            A,
                            ## B.
                            B,
                            ## C.
                            C,
                    };

                    global a = A;
                    global b = B;
                    global c = C;
            }",
        );

        let db = db.0;
        let source = db.files().get(&uri).map(|f| f.source()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(11, 31))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "A");
        assert_eq!(
            db.resolve(NodeLocation::from_node(uri.clone(), a))
                .unwrap()
                .documentation
                .lines()
                .next(),
            Some("A.")
        );

        let b = root
            .named_descendant_for_position(Position::new(12, 31))
            .unwrap();
        assert_eq!(b.utf8_text(source.as_bytes()).unwrap(), "B");
        assert_eq!(
            db.resolve(NodeLocation::from_node(uri.clone(), b))
                .unwrap()
                .documentation
                .lines()
                .next(),
            Some("B.")
        );

        let c = root
            .named_descendant_for_position(Position::new(13, 31))
            .unwrap();
        assert_eq!(c.utf8_text(source.as_bytes()).unwrap(), "C");
        assert_eq!(
            db.resolve(NodeLocation::from_node(uri.clone(), c))
                .unwrap()
                .documentation
                .lines()
                .next(),
            Some("C.")
        );
    }
}
