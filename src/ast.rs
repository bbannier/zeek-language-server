use itertools::Itertools;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use tower_lsp_server::{UriExt, lsp_types::Uri};
use tracing::{instrument, warn};

use crate::{
    Str,
    parse::Parse,
    query::{self, Decl, DeclKind, Index, NodeLocation, Query, Type},
    zeek,
};

#[salsa::query_group(AstStorage)]
pub trait Ast: Parse + Query {
    #[salsa::input]
    fn workspace_folders(&self) -> Arc<[Uri]>;

    #[salsa::input]
    fn prefixes(&self) -> Arc<[PathBuf]>;

    #[must_use]
    fn loaded_files(&self, url: Arc<Uri>) -> Arc<[Arc<Uri>]>;

    #[must_use]
    fn loaded_files_recursive(&self, url: Arc<Uri>) -> Arc<[Arc<Uri>]>;

    /// Get the decls in uri and all files explicitly loaded by it.
    #[must_use]
    fn explicit_decls_recursive(&self, url: Arc<Uri>) -> Arc<[Decl]>;

    #[must_use]
    fn implicit_loads(&self) -> Arc<[Arc<Uri>]>;

    #[must_use]
    fn implicit_decls(&self) -> Arc<[Decl]>;

    #[must_use]
    fn possible_loads(&self, uri: Arc<Uri>) -> Arc<[Str]>;

    /// Find decl with ID from the node up the tree and in all other loaded files.
    #[must_use]
    fn resolve(&self, node: NodeLocation) -> Option<Arc<Decl>>;

    /// Determine the type of the given decl.
    fn typ(&self, decl: Arc<Decl>) -> Option<Arc<Decl>>;

    /// Resolve identifier in a scope.
    fn resolve_id(&self, id: Str, scope: NodeLocation) -> Option<Arc<Decl>>;

    /// Resolve type in a scope.
    fn resolve_type(&self, typ: Type, scope: Option<NodeLocation>) -> Option<Arc<Decl>>;
}

#[instrument(skip(db))]
fn resolve_id(db: &dyn Ast, id: Str, scope: NodeLocation) -> Option<Arc<Decl>> {
    let uri = scope.uri;
    let tree = db.parse(Arc::clone(&uri))?;
    let scope = tree
        .root_node()
        .named_descendant_for_point_range(scope.range)?;
    let source = db.source(Arc::clone(&uri))?;

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
            query::decls_(scope, Arc::clone(&uri), source.as_bytes())
                .into_iter()
                .filter(|d| d.id == id || d.fqid == id)
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
    let decls = db.decls(Arc::clone(&uri));
    let implicit_decls = db.implicit_decls();
    let explicit_decls_recursive = db.explicit_decls_recursive(Arc::clone(&uri));
    let last_decl = if let Some(redef) = &result {
        redef
    } else {
        let all = decls
            .iter()
            .chain(implicit_decls.iter())
            .chain(explicit_decls_recursive.iter())
            .filter(|d| d.fqid == id)
            .collect::<Vec<_>>();

        // Prefer to return the decl instead of the definition for constructs which support both.
        // In either case, the last instance still wins.
        let mut only_decls = all.iter().filter(|d| {
            matches!(
                d.kind,
                DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_)
            )
        });

        if let Some(decl) = only_decls.next_back() {
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

#[instrument(skip(db))]
fn resolve_type(db: &dyn Ast, typ: Type, scope: Option<NodeLocation>) -> Option<Arc<Decl>> {
    #[allow(clippy::needless_pass_by_value)]
    fn builtin_type(id: Str, typ: Type) -> Arc<Decl> {
        Arc::new(Decl {
            module: query::ModuleId::Global,
            id: id.clone(),
            fqid: id.clone(),
            kind: DeclKind::Builtin(typ),
            is_export: None,
            loc: None,
            documentation: format!("Builtin type '{id}'").as_str().into(),
        })
    }

    Some(match &typ {
        Type::Id(id) => scope
            .and_then(|s| resolve_id(db, id.clone(), s))
            .unwrap_or_else(|| builtin_type(format!("{id}").into(), typ.clone())),
        Type::Addr => builtin_type("addr".into(), typ),
        Type::Any => builtin_type("any".into(), typ),
        Type::Bool => builtin_type("bool".into(), typ),
        Type::Count => builtin_type("count".into(), typ),
        Type::Double => builtin_type("double".into(), typ),
        Type::Int => builtin_type("int".into(), typ),
        Type::Interval => builtin_type("interval".into(), typ),
        Type::String => builtin_type("string".into(), typ),
        Type::Subnet => builtin_type("subnet".into(), typ),
        Type::Pattern => builtin_type("pattern".into(), typ),
        Type::Port => builtin_type("port".into(), typ),
        Type::Table(ks, v) => {
            let ks: Vec<_> = ks
                .iter()
                .map(|k| {
                    db.resolve_type(k.clone(), scope.clone())
                        .map(|d| d.fqid.clone())
                })
                .collect::<Option<_>>()?;
            let ks = ks.into_iter().join(", ");
            let v = db
                .resolve_type((**v).clone(), scope)
                .map(|d| d.fqid.clone())?;
            builtin_type(format!("table[{ks}] of {v}").into(), typ)
        }
        Type::Set(xs) => {
            let xs = xs
                .iter()
                .map(|x| {
                    db.resolve_type(x.clone(), scope.clone())
                        .map(|d| d.fqid.clone())
                })
                .collect::<Option<Vec<_>>>()?;
            let xs = xs.into_iter().join(", ");
            builtin_type(format!("set[{xs}]").into(), typ)
        }
        Type::Time => builtin_type("time".into(), typ),
        Type::Timer => builtin_type("timer".into(), typ),
        Type::List(x) => builtin_type(
            format!(
                "list of {}",
                db.resolve_type((**x).clone(), scope)
                    .map(|d| d.fqid.clone())?
            )
            .into(),
            typ,
        ),
        Type::Vector(x) => builtin_type(
            format!(
                "vector of {}",
                db.resolve_type((**x).clone(), scope)
                    .map(|d| d.fqid.clone())?
            )
            .into(),
            typ,
        ),
        Type::File(x) => builtin_type(
            format!(
                "file of {}",
                db.resolve_type((**x).clone(), scope)
                    .map(|d| d.fqid.clone())?
            )
            .into(),
            typ,
        ),
        Type::Opaque(x) => builtin_type(
            format!(
                "opaque of {}",
                db.resolve_type((**x).clone(), scope)
                    .map(|d| d.fqid.clone())?
            )
            .into(),
            typ,
        ),
    })
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn typ(db: &dyn Ast, decl: Arc<Decl>) -> Option<Arc<Decl>> {
    // If we see a type decl with location we are likely dealing with a builtin type already which
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

    let tree = db.parse(Arc::clone(uri))?;

    let node = tree
        .root_node()
        .named_descendant_for_point_range(loc.range)?;

    if let DeclKind::Index(i, from) = &decl.kind {
        let from = db
            .resolve_id(
                from.as_str().into(),
                NodeLocation::from_node(Arc::clone(uri), node),
            )
            .and_then(|r| db.typ(r))?;

        let DeclKind::Builtin(typ) = &from.kind else {
            // TODO(bbannier): report diagnostic for iteration over non-builtins.
            return None;
        };

        let loc = decl
            .loc
            .as_ref()
            .map(|l| NodeLocation::from_range(Arc::clone(&l.uri), l.range));

        let idx = match *i {
            Index::Loop(i) => Some(i),
            _ => None,
        };

        #[allow(clippy::match_same_arms)]
        return match typ {
            Type::Vector(id) => match idx? {
                0 => db.resolve_type(Type::Count, loc),
                1 => db.resolve_type((**id).clone(), loc),
                _ => None,
            },
            Type::Set(xs) => {
                let idx = idx.or(match i {
                    Index::Key(i) => Some(*i),
                    _ => None,
                })?;
                xs.get(idx).and_then(|x| db.resolve_type(x.clone(), loc))
            }
            Type::List(_) => None, // Not implemented in Zeek.
            Type::Table(ks, v) => {
                let typ = match idx {
                    Some(0) => ks.first()?,
                    Some(1) => v,
                    Some(_) => return None,
                    None => match *i {
                        Index::Key(i) => ks.get(i)?,
                        Index::Value => v,
                        Index::Loop(_) => return None, // Should not reach here.
                    },
                };
                db.resolve_type(typ.clone(), loc)
            }
            _ => None,
        };
    }

    let make_typ = |typ| {
        let source = db.source(Arc::clone(uri))?;
        query::typ(typ, source.as_bytes())
            .and_then(|t| db.resolve_type(t, Some(NodeLocation::from_node(Arc::clone(uri), typ))))
    };

    let d = match node.kind() {
        "var_decl" | "const_decl" | "option_decl" | "formal_arg" => {
            let typ = node.named_children_not("nl").into_iter().nth(1)?;

            match typ.kind() {
                "type" => make_typ(typ),
                "initializer" => typ
                    .named_child("expr")
                    .and_then(|n| db.resolve(NodeLocation::from_node(Arc::clone(uri), n))),
                _ => None,
            }
        }
        "id" => node.parent()?.named_child("type").and_then(make_typ),
        _ => None,
    };

    // Perform additional unwrapping if needed.
    d.and_then(|d| {
        let Some(loc) = &d.loc else { return Some(d) };

        match &d.kind {
            // For function declarations produce the function's return type.
            DeclKind::FuncDecl(sig) | DeclKind::FuncDef(sig) => db.resolve_type(
                sig.result.clone()?,
                Some(NodeLocation::from_node(Arc::clone(&loc.uri), node)),
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
                    Arc::clone(&loc.uri),
                    n.named_child("id")?,
                ))
            }

            // Return the actual type for variable declarations.
            DeclKind::Const
            | DeclKind::Field(_)
            | DeclKind::Global
            | DeclKind::Index(_, _)
            | DeclKind::Variable => db.typ(d),

            // Other kinds we return directly.
            _ => Some(d),
        }
    })
}

#[allow(clippy::too_many_lines)]
fn resolve(db: &dyn Ast, location: NodeLocation) -> Option<Arc<Decl>> {
    let uri = Arc::clone(&location.uri);
    let tree = db.parse(Arc::clone(&uri))?;
    let node = tree
        .root_node()
        .named_descendant_for_point_range(location.range)?;
    let source = db.source(Arc::clone(&uri))?;

    let id: Str = node.utf8_text(source.as_bytes()).ok()?.into();

    match node.kind() {
        // Builtin types.
        // NOTE: This is driven by what types the parser exposes, extend as possible.

        // TODO(bbannier): the parser doesn't cleanly expose whether an integer is an `int` or a
        // `count`, use a dummy type until we resolve it
        "integer" => {
            return db.resolve_type(
                Type::Id(format!("<{}>", node.kind()).into()),
                Some(location),
            );
        }

        "hostname" => {
            return db.resolve_type(Type::Set(vec![Type::Addr]), Some(location));
        }
        "floatp" => return db.resolve_type(Type::Double, Some(location)),
        "ipv4" | "ipv6" => return db.resolve_type(Type::Addr, Some(location)),
        "subnet" => return db.resolve_type(Type::Subnet, Some(location)),
        "interval" => return db.resolve_type(Type::Interval, Some(location)),
        "port" => return db.resolve_type(Type::Port, Some(location)),
        "string" => return db.resolve_type(Type::String, Some(location)),
        "hex" => return db.resolve_type(Type::Count, Some(location)),

        "constant" => {
            match node.utf8_text(source.as_bytes()).ok()? {
                "T" | "F" => return db.resolve_type(Type::Bool, Some(location)),
                _ => return None,
            };
        }

        "type" => {
            return query::typ(node, source.as_bytes())
                .and_then(|t| db.resolve_type(t, Some(location)));
        }

        "expr" => {
            // Try to interpret expr as a cast `_ as @type`.
            if let Some(typ) = query::typ_from_cast(node, source.as_bytes()) {
                return db.resolve_type(typ, Some(location));
            }

            return node
                .named_child_not("nl")
                .and_then(|c| db.resolve(NodeLocation::from_node(Arc::clone(&uri), c)));
        }
        // If we are on a `field_access` or `field_check` search the rhs in the scope of the lhs.
        "field_access" | "field_check" => {
            let xs = node.named_children_not("nl");
            let lhs = xs.first().copied()?;
            let rhs = xs.get(1).copied()?;

            let id = rhs.utf8_text(source.as_bytes()).ok()?;

            let var_decl = db.resolve(NodeLocation::from_node(uri, lhs))?;
            let type_decl = db.typ(var_decl)?;

            match &type_decl.kind {
                DeclKind::Type(fields) => {
                    // Find the given id in the fields.
                    return fields.iter().find(|f| &*f.id == id).cloned().map(Arc::new);
                }
                DeclKind::Field(_) => return db.typ(type_decl),
                _ => return None,
            }
        }
        "id" => {
            // If the node is part of a record initializer resolve the field.

            // The expr holding the record initializer.
            if let Some(expr) = node
                .parent()
                .and_then(|p| if p.kind() == "expr" { p.parent() } else { None })
                .and_then(|p| {
                    if p.kind() == "expr_list" {
                        p.parent()
                    } else {
                        None
                    }
                })
                .filter(|p| p.kind() == "expr")
            {
                // If the expr has an ID we are in code like `X($abc=123)`.
                let type_ = expr
                    .named_child("id")
                    .and_then(|id| db.resolve(NodeLocation::from_node(Arc::clone(&uri), id)))
                    // Otherwise check the RHS for expressions like `local a: A = [$abc=123]`.
                    .or_else(|| {
                        let parent = expr.parent()?;

                        let type_id = parent.named_child("expr").and_then(|c| c.named_child("id"));

                        if let Some(id) = type_id {
                            db.resolve(NodeLocation::from_node(Arc::clone(&uri), id))
                                .and_then(|decl| db.typ(decl))
                        } else if parent.kind() == "initializer" {
                            parent.prev_sibling().and_then(|t| {
                                db.resolve(NodeLocation::from_node(Arc::clone(&uri), t))
                            })
                        } else {
                            None
                        }
                    });

                if let Some(type_) = type_ {
                    if let Decl {
                        kind: DeclKind::Type(fields),
                        ..
                    } = type_.as_ref()
                    {
                        return fields.iter().find(|f| f.id == id).cloned().map(Arc::new);
                    }
                }
            }
        }
        _ => {}
    }

    // If the node is part of a field access or check resolve it in the referenced record.
    if let Some(p) = node.parent() {
        if matches!(p.kind(), "field_access" | "field_check") {
            return db.resolve(NodeLocation::from_node(uri, p));
        }
    }

    // Try to find a decl with name of the given node up the tree.

    if let Some(r) = db.resolve_id(id.clone(), location.clone()) {
        // If we have found something which can have separate declaration and definition
        // return the declaration if possible. At this point this must be in another file.
        match r.kind {
            DeclKind::FuncDef(_) | DeclKind::EventDef(_) | DeclKind::HookDef(_) => {
                if let Some(decl) =
                    db.resolve_id(id, NodeLocation::from_node(uri, tree.root_node()))
                {
                    return Some(decl);
                }
            }
            _ => {}
        }

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
            if let Some(r) = db.resolve_id(format!("{module}::{id}").as_str().into(), location) {
                return Some(r);
            }
        }
    }
    None
}

#[allow(clippy::needless_pass_by_value)]
fn loaded_files(db: &dyn Ast, uri: Arc<Uri>) -> Arc<[Arc<Uri>]> {
    let files = db.files();

    let prefixes = db.prefixes();

    let loads: Vec<_> = db
        .loads(Arc::clone(&uri))
        .iter()
        .map(|load| PathBuf::from(load.as_str()))
        .collect();

    let mut loaded_files = Vec::new();

    for load in &loads {
        if let Some(f) = load_to_file(load, uri.as_ref(), &files, &prefixes) {
            loaded_files.push(f);
        }
    }

    Arc::from(loaded_files)
}

#[instrument(skip(db))]
fn loaded_files_recursive(db: &dyn Ast, url: Arc<Uri>) -> Arc<[Arc<Uri>]> {
    let mut files: Vec<_> = db.loaded_files(url).iter().cloned().collect();

    loop {
        let mut new_files = Vec::new();

        for f in &files {
            for load in db.loaded_files(Arc::clone(f)).as_ref() {
                if !files.iter().any(|f| f.as_ref() == load.as_ref()) {
                    new_files.push(Arc::clone(load));
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

    Arc::from(files)
}

#[instrument(skip(db))]
fn explicit_decls_recursive(db: &dyn Ast, uri: Arc<Uri>) -> Arc<[Decl]> {
    let d = db.decls(Arc::clone(&uri));
    let decls1 = d.iter().cloned();

    let d = db.loaded_files_recursive(uri);
    let decls2 = d.iter().flat_map(|load| {
        let decls: Vec<_> = db.decls(Arc::clone(load)).iter().cloned().collect();
        decls
    });

    let d = decls1.chain(decls2).unique();

    Arc::from(d.into_iter().collect::<Vec<_>>())
}

#[instrument(skip(db))]
fn implicit_loads(db: &dyn Ast) -> Arc<[Arc<Uri>]> {
    let mut loads = Vec::new();

    // These loops looks horrible, but is okay since this function will be cached most of the time
    // (unless global state changes).
    for essential_input in zeek::essential_input_files() {
        let mut implicit_file = None;
        for f in &*db.files() {
            let Some(path) = f.to_file_path() else {
                continue;
            };

            if !path.ends_with(essential_input) {
                continue;
            }

            for p in db.prefixes().iter() {
                if path.strip_prefix(p).is_ok() {
                    implicit_file = Some(Arc::clone(f));
                    break;
                }
            }
        }

        // Not being able to resolve the load is potentially not an
        // error since this might race with prefixes being loaded.
        if let Some(implicit_load) = implicit_file {
            loads.push(implicit_load);
        }
    }

    Arc::from(loads)
}

#[instrument(skip(db))]
fn implicit_decls(db: &dyn Ast) -> Arc<[Decl]> {
    let loads = db.implicit_loads();

    loads
        .iter()
        .cloned()
        .flat_map(|load| {
            let xs: Vec<_> = db
                .explicit_decls_recursive(Arc::clone(&load))
                .iter()
                .cloned()
                .collect();
            xs
        })
        .unique()
        .collect()
}

#[instrument(skip(db))]
fn possible_loads(db: &dyn Ast, uri: Arc<Uri>) -> Arc<[Str]> {
    let Some(path) = uri.to_file_path() else {
        return Arc::default();
    };

    let Some(path) = path.parent() else {
        return Arc::default();
    };

    let prefixes = db.prefixes();
    let files = db.files();

    let loads: Vec<_> = files
        .iter()
        .filter(|f| f.path().as_str() != uri.path().as_str())
        .filter_map(|f| {
            // Always strip any extension.
            let f = f.to_file_path()?.with_extension("");

            // For `__load__.zeek` files one should use the directory name for loading.
            let f = if f.file_stem()? == "__load__" {
                f.parent()?
            } else {
                &f
            };

            if let Ok(f) = f.strip_prefix(path) {
                Some(Str::from(Path::new(".").join(f).to_str()?))
            } else {
                prefixes.iter().find_map(|p| {
                    let l = f.strip_prefix(p).ok()?.to_str()?;
                    Some(Str::from(l))
                })
            }
        })
        .collect();

    Arc::from(loads)
}

#[must_use]
pub fn is_redef(d: &Decl) -> bool {
    matches!(
        &d.kind,
        DeclKind::Redef | DeclKind::RedefEnum(_) | DeclKind::RedefRecord(_)
    )
}

#[instrument(skip(db))]
fn resolve_redef(db: &dyn Ast, redef: &Decl, scope: Arc<Uri>) -> Arc<[Decl]> {
    if !is_redef(redef) {
        return Arc::default();
    }

    let implicit_decls = db.implicit_decls();
    let loaded_decls = db.explicit_decls_recursive(Arc::clone(&scope));
    let decls = db.decls(scope);

    implicit_decls
        .iter()
        .chain(loaded_decls.iter())
        .chain(decls.iter())
        .unique()
        .filter(|x| x.fqid == redef.fqid)
        .cloned()
        .collect()
}

pub(crate) fn load_to_file(
    load: &Path,
    base: &Uri,
    files: &[Arc<Uri>],
    prefixes: &[PathBuf],
) -> Option<Arc<Uri>> {
    let file_dir = base
        .to_file_path()
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
                if let Ok(p) = f.to_file_path()?.strip_prefix(prefix) {
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
            .map(|(f, _)| Arc::clone(f))
    })
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use std::{ops::Deref, path::PathBuf, str::FromStr, sync::Arc};

    use insta::assert_debug_snapshot;
    use tower_lsp_server::{
        UriExt,
        lsp_types::{Position, Range, Uri},
    };

    use crate::{
        Files,
        ast::Ast,
        lsp::TestDatabase,
        parse::Parse,
        query::{self, DeclKind, NodeLocation},
    };

    #[test]
    fn loaded_files_recursive() {
        let mut db = TestDatabase::default();

        let a = Arc::new(Uri::from_file_path("/tmp/a.zeek").unwrap());
        db.add_file(
            (*a).clone(),
            "@load b\n
             @load d;",
        );

        let b = Uri::from_file_path("/tmp/b.zeek").unwrap();
        db.add_file(b, "@load c");

        let c = Uri::from_file_path("/tmp/c.zeek").unwrap();
        db.add_file(c, "@load d");

        let d = Uri::from_file_path("/tmp/d.zeek").unwrap();
        db.add_file(d, "");

        assert_debug_snapshot!(db.0.loaded_files_recursive(a));
    }

    #[test]
    fn loaded_files() {
        let mut db = TestDatabase::default();

        // Prefix file both in file directory and in prefix. This should appear exactly once.
        let pre1 = PathBuf::from_str("/tmp/p").unwrap();
        let p1 = Uri::from_file_path(pre1.join("p1/p1.zeek")).unwrap();
        db.add_prefix(pre1);
        db.add_file(p1, "");

        // Prefix file in external directory.
        let pre2 = PathBuf::from_str("/p").unwrap();
        let p2 = Uri::from_file_path(pre2.join("p2/p2.zeek")).unwrap();
        db.add_prefix(pre2);
        db.add_file(p2, "");

        let foo = Arc::new(Uri::from_file_path("/tmp/foo.zeek").unwrap());
        db.add_file(
            (*foo).clone(),
            "@load foo\n
             @load foo.zeek\n
             @load p1/p1\n
             @load p2/p2",
        );

        assert_debug_snapshot!(db.0.loaded_files(foo));
    }

    #[test]
    fn resolve() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        db.add_file(
            (*uri).clone(),
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
        let source = db.source(uri.clone()).unwrap();
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
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        db.add_file(
            (*uri).clone(),
            "module x;
type X: record { f: count &optional; };
function fun(): X { return X(); }
global x = fun();
x$f;",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(4, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, node)));
    }

    #[test]
    fn resolve_ref() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        db.add_file(
            Arc::deref(&uri).clone(),
            "global x = 123;
            function foo(x: int) {}
            function bar() { foo(x); }
            ",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 33))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("x"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, node)));
    }

    #[test]
    fn resolve_elsewhere() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/y.zeek").unwrap());

        db.add_file(
            Uri::from_file_path("/x.zeek").unwrap(),
            "module x;
            export {
                type X: record { f: count &optional; };
                global x: X;
            }",
        );

        db.add_file(
            (*uri).clone(),
            "module y;
@load ./x
x::x;",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
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
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/y.zeek").unwrap());

        db.add_file(
            Uri::from_file_path("/x.zeek").unwrap(),
            "module x;
            export {
                type X: record { f: count &optional; };
                global y: X;
            }",
        );

        db.add_file(
            (*uri).clone(),
            "module x;
@load ./x
y;",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
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
        let mut db = TestDatabase::default();
        db.add_file(
            Uri::from_file_path("/x.zeek").unwrap(),
            "module x;
type X: record { x1: count; };",
        );

        let uri = Arc::new(Uri::from_file_path("/y.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "module y;
@load x
redef record x::X += { x2: count; };
global x: x::X;
x;
x$x1;
x$x2;",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
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
        assert!(matches!(
            db.resolve(NodeLocation::from_node(uri.clone(), x1))
                .unwrap()
                .kind,
            super::DeclKind::Field(_)
        ));

        let x2 = root
            .named_descendant_for_position(Position::new(6, 3))
            .unwrap();
        assert_eq!(x2.utf8_text(source.as_bytes()), Ok("x2"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, x2)));
    }

    #[test]
    fn redef_enum() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        db.add_file(
            Uri::from_file_path("/base.zeek").unwrap(),
            "type E: enum { eA, };",
        );
        db.add_file(
            (*uri).clone(),
            "
@load /base

redef enum E += {
    eB,
};

global e: E = eB;

module foo;
redef enum E += {
    eC,
};

global e_foo: E = eC;
",
        );

        let db = db.snapshot();
        let tree = db.parse(uri.clone()).unwrap();
        let source = db.source(uri.clone()).unwrap();

        let type_ = tree
            .root_node()
            .named_descendant_for_position(Position::new(7, 14))
            .unwrap();
        assert_eq!(type_.utf8_text(source.as_bytes()), Ok("eB"));
        assert_debug_snapshot!(
            db.resolve(NodeLocation::from_node(uri.clone(), type_))
                .unwrap()
        );

        let type_ = tree
            .root_node()
            .named_descendant_for_position(Position::new(14, 18))
            .unwrap();
        assert_eq!(type_.utf8_text(source.as_bytes()), Ok("eC"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, type_)).unwrap());
    }

    #[test]
    fn redef_global_record() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        db.add_file(
            Uri::from_file_path("/init-bare.zeek").unwrap(),
            "module GLOBAL;
type connection: record { id: string; };",
        );
        db.add_file(
            (*uri).clone(),
            "module x;
@load init-bare
redef record connection += { name: string; };
global c: connection;",
        );

        let db = db.snapshot();
        let tree = db.parse(uri.clone()).unwrap();
        let source = db.source(uri.clone()).unwrap();

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
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
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
        let source = db.source(uri.clone()).unwrap();

        let g = tree
            .root_node()
            .named_descendant_for_position(Position::new(2, 7))
            .unwrap();
        assert_eq!(g.utf8_text(source.as_bytes()), Ok("g"));
        assert_debug_snapshot!(
            db.typ(db.resolve(NodeLocation::from_node(uri.clone(), g)).unwrap())
        );

        let f_a = tree
            .root_node()
            .named_descendant_for_position(Position::new(4, 11))
            .unwrap();
        assert_eq!(f_a.utf8_text(source.as_bytes()), Ok("a"));
        assert_debug_snapshot!(
            db.typ(
                db.resolve(NodeLocation::from_node(uri.clone(), f_a))
                    .unwrap()
            )
        );

        let a = tree
            .root_node()
            .named_descendant_for_position(Position::new(5, 4))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()), Ok("a"));
        assert_debug_snapshot!(
            db.typ(db.resolve(NodeLocation::from_node(uri.clone(), a)).unwrap())
        );

        let a_c = tree
            .root_node()
            .named_descendant_for_position(Position::new(5, 6))
            .unwrap();
        assert_eq!(a_c.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri, a_c)));
    }

    #[test]
    fn typ_fn_call() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
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
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let x1 = root
            .named_descendant_for_position(Position::new(5, 8))
            .unwrap();
        assert_eq!(x1.utf8_text(source.as_bytes()), Ok("x1"));
        assert_eq!(
            &*db.typ(
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
            &*db.typ(db.resolve(NodeLocation::from_node(uri, x2)).unwrap())
                .unwrap()
                .id,
            "X2"
        );
    }

    #[test]
    fn typ_var_decl() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
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
        let source = db.source(uri.clone()).unwrap();
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
    fn typ_var_from_call() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "
                function foo(): count { return 0; }
                const a = foo();
             }",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(2, 22))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            db.resolve(NodeLocation::from_node(uri.clone(), a))
                .and_then(|d| db.typ(d))
        );
    }

    #[test]
    fn typ_const_decl() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "export {
                const a = 42;
                const b = a;
             }",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(1, 22))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            db.resolve(NodeLocation::from_node(uri.clone(), a))
                .and_then(|d| db.typ(d))
        );

        let b = root
            .named_descendant_for_position(Position::new(2, 22))
            .unwrap();
        assert_eq!(b.utf8_text(source.as_bytes()).unwrap(), "b");
        assert_debug_snapshot!(
            db.resolve(NodeLocation::from_node(uri.clone(), b))
                .and_then(|d| db.typ(d))
        );
    }

    #[test]
    fn typ_builtin() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
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
            global f = 0.1234;
            global b1 = T;
            global b2 = F;
            ",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        for (i, line) in source
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
        {
            let pos = Position::new(i.try_into().unwrap(), 19);
            assert_debug_snapshot!((
                line,
                db.resolve(NodeLocation::from_range(uri.clone(), Range::new(pos, pos)))
                    .and_then(|d| db.typ(d))
            ));
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
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "
            global a : count = 42;

            type X: record {};
            global x: X;
            ",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(1, 19))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            db.resolve(NodeLocation::from_node(uri.clone(), a))
                .and_then(|d| db.typ(d))
        );

        let x = root
            .named_descendant_for_position(Position::new(4, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        assert_debug_snapshot!(
            db.resolve(NodeLocation::from_node(uri, x))
                .and_then(|d| db.typ(d))
        );
    }

    #[test]
    fn typ_cast() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "
            global a : count = 42;
            global x = a as string;
            ",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let x = root
            .named_descendant_for_position(Position::new(2, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        assert_debug_snapshot!(
            db.resolve(NodeLocation::from_node(uri, x))
                .and_then(|d| db.typ(d))
        );
    }

    #[test]
    fn for_parameters_vec() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
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
        let source = db.source(uri.clone()).unwrap();

        // Vector iteration.
        let i1 = root
            .named_descendant_for_position(Position::new(1, 29))
            .unwrap();
        assert_eq!(i1.utf8_text(source.as_bytes()), Ok("i"));
        assert_debug_snapshot!(db.resolve(NodeLocation::from_node(uri.clone(), i1)));

        let i2 = root
            .named_descendant_for_position(Position::new(2, 0))
            .unwrap();
        assert_eq!(
            i2.utf8_text(db.source(uri.clone()).unwrap().as_bytes()),
            Ok("i")
        );
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
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
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
        let source = db.source(uri.clone()).unwrap();
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

    #[test]
    fn multiline_zeekygen_docs_not_wrapped() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "
        ## Multiline
        ## documentation.
        global foo = 123;
        foo;
        ",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let foo = root
            .named_descendant_for_position(Position::new(4, 10))
            .unwrap();
        assert_eq!(foo.utf8_text(source.as_bytes()).unwrap(), "foo");

        let decl = db.resolve(NodeLocation::from_node(uri, foo)).unwrap();
        assert!(
            decl.documentation
                .starts_with("Multiline\ndocumentation.\n"),
            "{docs}",
            docs = &decl.documentation
        );
    }

    #[test]
    fn resolve_type() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "
local x1: addr;
local x2: any;
local x3: bool;
local x4: count;
local x5: double;
local x6: int;
local x7: interval;
local x8: subnet;
local x9: pattern;
local x10: port;
local x11: table[count, string] of int;
local x12: set[count, string];
local x13: time;
local x14: timer;
local x15: list of count;
local x16: vector of count;
local x17: file of count;
local x18: opaque of count;
            ",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let check = |position: Position, expected_id: &str| {
            let n = root.named_descendant_for_position(position).unwrap();
            assert_eq!(n.utf8_text(source.as_bytes()), Ok(expected_id));
            let typ = n.parent().unwrap().named_child("type").unwrap();
            let t = query::typ(typ, source.as_bytes()).unwrap();
            let resolved = db
                .resolve_type(t, Some(NodeLocation::from_node(uri.clone(), typ)))
                .unwrap();
            assert_debug_snapshot!(resolved);
        };

        check(Position::new(1, 6), "x1");
        check(Position::new(2, 6), "x2");
        check(Position::new(3, 6), "x3");
        check(Position::new(4, 6), "x4");
        check(Position::new(5, 6), "x5");
        check(Position::new(6, 6), "x6");
        check(Position::new(7, 6), "x7");
        check(Position::new(8, 6), "x8");
        check(Position::new(9, 6), "x9");
        check(Position::new(10, 6), "x10");
        check(Position::new(11, 6), "x11");
        check(Position::new(12, 6), "x12");
        check(Position::new(13, 6), "x13");
        check(Position::new(14, 6), "x14");
        check(Position::new(15, 6), "x15");
        check(Position::new(16, 6), "x16");
        check(Position::new(17, 6), "x17");
        check(Position::new(18, 6), "x18");
    }

    #[test]
    fn resolve_record_type() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "
            type R: record {
                a: count;
            };

            event zeek_init() {
                local r: R;
                local my_a = r$a;
            }",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(7, 22))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "my_a");

        assert_debug_snapshot!(
            db.resolve(NodeLocation::from_node(uri.clone(), a))
                .and_then(|d| db.typ(d))
        );
    }

    #[test]
    fn loop_vars_vector() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            r#"
global vs: vector of string = vector("a");
event zeek_init() { for (v in vs) ; }
event zeek_init() { for (i, v in vs) ; }
                 "#,
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let v = root
            .named_descendant_for_position(Position::new(2, 25))
            .unwrap();
        assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
        let decl = db.resolve(NodeLocation::from_node(uri.clone(), v)).unwrap();
        let typ = db.typ(decl).unwrap();
        assert_debug_snapshot!(typ);

        let i = root
            .named_descendant_for_position(Position::new(3, 25))
            .unwrap();
        assert_eq!(i.utf8_text(source.as_bytes()), Ok("i"));
        let decl = db.resolve(NodeLocation::from_node(uri.clone(), i)).unwrap();
        let typ = db.typ(decl).unwrap();
        assert_debug_snapshot!(typ);

        let v = root
            .named_descendant_for_position(Position::new(3, 28))
            .unwrap();
        assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
        let decl = db.resolve(NodeLocation::from_node(uri.clone(), v)).unwrap();
        let typ = db.typ(decl).unwrap();
        assert_debug_snapshot!(typ);
    }

    #[test]
    fn loop_vars_set() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            r#"
global vs: set[string] = set("a");
event zeek_init() { for (v in vs) ; }
                 "#,
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let v = root
            .named_descendant_for_position(Position::new(2, 25))
            .unwrap();
        assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
        let decl = db.resolve(NodeLocation::from_node(uri, v)).unwrap();
        let typ = db.typ(decl).unwrap();
        assert_debug_snapshot!(typ);
    }

    #[test]
    fn loop_vars_set_multiple_types() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            r#"
global vs: set[count, string] = { [1, "one"] };
event zeek_init() { for ([c, s] in vs) ; }
                     "#,
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        let c = root
            .named_descendant_for_position(Position::new(2, 26))
            .unwrap();
        assert_eq!(c.utf8_text(source.as_bytes()), Ok("c"));
        let decl = db.resolve(NodeLocation::from_node(uri.clone(), c)).unwrap();
        let typ = db.typ(decl).unwrap();
        assert_debug_snapshot!(typ);

        let s = root
            .named_descendant_for_position(Position::new(2, 29))
            .unwrap();
        assert_eq!(s.utf8_text(source.as_bytes()), Ok("s"));
        let decl = db.resolve(NodeLocation::from_node(uri, s)).unwrap();
        let typ = db.typ(decl).unwrap();
        assert_debug_snapshot!(typ);
    }

    #[test]
    fn loop_vars_table() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            r"
global t1: table[string] of count;
global t2: table[string, double] of count;

event zeek_init() { for ( k, v in t1 ) ; }
event zeek_init() { for ( [ k1, k2 ], v in t2 ) ; }
event zeek_init() { for ( [ k1, k2 ] in t2 ) ; }
                     ",
        );

        let db = db.0;
        let source = db.source(uri.clone()).unwrap();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();

        {
            let k = root
                .named_descendant_for_position(Position::new(4, 26))
                .unwrap();
            assert_eq!(k.utf8_text(source.as_bytes()), Ok("k"));
            let decl = db.resolve(NodeLocation::from_node(uri.clone(), k)).unwrap();
            let typ = db.typ(decl).unwrap();
            assert_debug_snapshot!(typ);

            let v = root
                .named_descendant_for_position(Position::new(4, 29))
                .unwrap();
            assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
            let decl = db.resolve(NodeLocation::from_node(uri.clone(), v)).unwrap();
            let typ = db.typ(decl).unwrap();
            assert_debug_snapshot!(typ);
        }

        {
            let k1 = root
                .named_descendant_for_position(Position::new(5, 28))
                .unwrap();
            assert_eq!(k1.utf8_text(source.as_bytes()), Ok("k1"));
            let decl = db
                .resolve(NodeLocation::from_node(uri.clone(), k1))
                .unwrap();
            let typ = db.typ(decl).unwrap();
            assert_debug_snapshot!(typ);

            let k2 = root
                .named_descendant_for_position(Position::new(5, 32))
                .unwrap();
            assert_eq!(k2.utf8_text(source.as_bytes()), Ok("k2"));
            let decl = db
                .resolve(NodeLocation::from_node(uri.clone(), k2))
                .unwrap();
            let typ = db.typ(decl).unwrap();
            assert_debug_snapshot!(typ);

            let v = root
                .named_descendant_for_position(Position::new(5, 38))
                .unwrap();
            assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
            let decl = db.resolve(NodeLocation::from_node(uri.clone(), v)).unwrap();
            let typ = db.typ(decl).unwrap();
            assert_debug_snapshot!(typ);
        }

        {
            let k1 = root
                .named_descendant_for_position(Position::new(6, 28))
                .unwrap();
            assert_eq!(k1.utf8_text(source.as_bytes()), Ok("k1"));
            let decl = db
                .resolve(NodeLocation::from_node(uri.clone(), k1))
                .unwrap();
            let typ = db.typ(decl).unwrap();
            assert_debug_snapshot!(typ);

            let k2 = root
                .named_descendant_for_position(Position::new(6, 32))
                .unwrap();
            assert_eq!(k2.utf8_text(source.as_bytes()), Ok("k2"));
            let decl = db
                .resolve(NodeLocation::from_node(uri.clone(), k2))
                .unwrap();
            let typ = db.typ(decl).unwrap();
            assert_debug_snapshot!(typ);
        }
    }
}
