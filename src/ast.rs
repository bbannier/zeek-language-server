use itertools::Itertools;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tower_lsp_server::ls_types::Uri;
use tracing::{instrument, warn};

use crate::{
    Db, DeclFqid, InternedStr, SourceFile,
    query::{self, Decl, DeclKind, Index, NodeLocation, Type},
    zeek,
};

#[allow(clippy::too_many_lines)]
#[instrument(skip(db))]
pub(crate) fn resolve_id(db: &dyn Db, id: InternedStr, scope: &NodeLocation) -> Option<Arc<Decl>> {
    let uri = Arc::clone(&scope.uri);
    let sf = db.source_file(&uri)?;
    let source = sf.text(db);
    let tree = crate::parse::parse(db, sf)?;
    let scope_node = tree
        .root_node()
        .named_descendant_for_point_range(scope.range)?;

    let node = scope_node;

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
    let mut scope = scope_node;
    loop {
        decls.extend(
            query::decls_(scope, &uri, source.as_bytes())
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

    if decls.iter().any(|d| !is_redef(d)) {
        return combined_decl_with_redefs(decls).map(Arc::new);
    }

    let result = decls.into_iter().next();

    if let Some(r) = &result
        && !is_redef(r)
    {
        return Some(Arc::new(r.clone()));
    }

    let sf = db.source_file(&uri)?;
    let decls = crate::query::decls(db, sf);
    let implicit_decls = crate::ast::implicit_decls(db);
    let explicit_decls_recursive = crate::ast::explicit_decls_recursive(db, sf);
    let last_decl = if let Some(redef) = &result {
        redef
    } else {
        let all = decls
            .iter()
            .chain(implicit_decls.iter())
            .chain(explicit_decls_recursive.iter())
            .filter(|d| d.fqid == id)
            .collect::<Vec<_>>();

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
        let key = DeclFqid::new(db, last_decl.fqid, sf);
        let decls = crate::ast::resolve_redef(db, key);

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
        Some(Arc::new(last_decl.clone()))
    }
}

#[instrument(skip(db))]

pub(crate) fn resolve_type(
    db: &dyn Db,
    typ: Type,
    scope: Option<&NodeLocation>,
) -> Option<Arc<Decl>> {
    fn builtin_type(id: InternedStr, typ: Type) -> Arc<Decl> {
        Arc::new(Decl {
            module: query::ModuleId::Global,
            id,
            fqid: id,
            kind: DeclKind::Builtin(typ),
            is_export: None,
            loc: None,
            documentation: format!("Builtin type '{id}'").as_str().into(),
        })
    }

    Some(match &typ {
        Type::Id(id) => scope
            .and_then(|s| crate::ast::resolve_id(db, *id, s))
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
                .map(|k| crate::ast::resolve_type(db, k.clone(), scope.clone()).map(|d| d.fqid))
                .collect::<Option<_>>()?;
            let ks = ks.into_iter().join(", ");
            let v = crate::ast::resolve_type(db, (**v).clone(), scope).map(|d| d.fqid)?;
            builtin_type(format!("table[{ks}] of {v}").into(), typ)
        }
        Type::Set(xs) => {
            let xs = xs
                .iter()
                .map(|x| crate::ast::resolve_type(db, x.clone(), scope.clone()).map(|d| d.fqid))
                .collect::<Option<Vec<_>>>()?;
            let xs = xs.into_iter().join(", ");
            builtin_type(format!("set[{xs}]").into(), typ)
        }
        Type::Time => builtin_type("time".into(), typ),
        Type::Timer => builtin_type("timer".into(), typ),
        Type::List(x) => builtin_type(
            format!(
                "list of {}",
                crate::ast::resolve_type(db, (**x).clone(), scope).map(|d| d.fqid)?
            )
            .into(),
            typ,
        ),
        Type::Vector(x) => builtin_type(
            format!(
                "vector of {}",
                crate::ast::resolve_type(db, (**x).clone(), scope).map(|d| d.fqid)?
            )
            .into(),
            typ,
        ),
        Type::File(x) => builtin_type(
            format!(
                "file of {}",
                crate::ast::resolve_type(db, (**x).clone(), scope).map(|d| d.fqid)?
            )
            .into(),
            typ,
        ),
        Type::Opaque(x) => builtin_type(
            format!(
                "opaque of {}",
                crate::ast::resolve_type(db, (**x).clone(), scope).map(|d| d.fqid)?
            )
            .into(),
            typ,
        ),
    })
}

#[allow(clippy::too_many_lines)]
#[instrument(skip(db))]

pub(crate) fn typ(db: &dyn Db, decl: Arc<Decl>) -> Option<Arc<Decl>> {
    if let DeclKind::Type(_) = &decl.kind
        && decl.loc.is_none()
    {
        return Some(decl);
    }

    let Some(loc) = &decl.loc else {
        return Some(decl);
    };
    let uri = &loc.uri;

    let sf = db.source_file(uri)?;
    let tree = crate::parse::parse(db, sf)?;

    let node = tree
        .root_node()
        .named_descendant_for_point_range(loc.range)?;

    if let DeclKind::Index(i, from) = &decl.kind {
        let loc = NodeLocation::from_node(Arc::clone(uri), node);
        let from = crate::ast::resolve_id(db, from.as_str().into(), &loc)
            .and_then(|r| crate::ast::typ(db, r))?;

        let DeclKind::Builtin(typ) = &from.kind else {
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
                0 => crate::ast::resolve_type(db, Type::Count, loc.as_ref()),
                1 => crate::ast::resolve_type(db, (**id).clone(), loc.as_ref()),
                _ => None,
            },
            Type::Set(xs) => {
                let idx = idx.or(match i {
                    Index::Key(i) => Some(*i),
                    _ => None,
                })?;
                xs.get(idx)
                    .and_then(|x| crate::ast::resolve_type(db, x.clone(), loc.as_ref()))
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
                crate::ast::resolve_type(db, typ.clone(), loc.as_ref())
            }
            _ => None,
        };
    }

    let make_typ = |typ| {
        let sf = db.source_file(&uri)?;
        let source = sf.text(db);
        let loc = NodeLocation::from_node(Arc::clone(uri), typ);
        query::typ(typ, source.as_bytes()).and_then(|t| crate::ast::resolve_type(db, t, Some(&loc)))
    };

    let d = match node.kind() {
        "var_decl" | "const_decl" | "option_decl" | "formal_arg" => {
            let typ = node.named_children_not("nl").into_iter().nth(1)?;

            match typ.kind() {
                "type" => make_typ(typ),
                "initializer" => typ.named_child("expr").and_then(|n| {
                    let loc = NodeLocation::from_node(Arc::clone(uri), n);
                    crate::ast::resolve(db, &loc)
                }),
                _ => None,
            }
        }
        "id" => node.parent()?.named_child("type").and_then(make_typ),
        _ => None,
    };

    d.and_then(|d| {
        let Some(loc) = &d.loc else { return Some(d) };

        match &d.kind {
            // For function declarations produce the function's return type.
            DeclKind::FuncDecl(sig) | DeclKind::FuncDef(sig) => {
                let fn_loc = NodeLocation::from_node(Arc::clone(&loc.uri), node);
                crate::ast::resolve_type(db, sig.result.clone()?, Some(&fn_loc))
            }

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

                let r_loc = NodeLocation::from_node(Arc::clone(&loc.uri), n.named_child("id")?);
                crate::ast::resolve(db, &r_loc)
            }

            // Return the actual type for variable declarations.
            DeclKind::Const
            | DeclKind::Field(_)
            | DeclKind::Global
            | DeclKind::Index(_, _)
            | DeclKind::Variable => crate::ast::typ(db, d),

            // Other kinds we return directly.
            _ => Some(d),
        }
    })
}

#[allow(clippy::too_many_lines)]
#[instrument(skip(db))]

pub(crate) fn resolve(db: &dyn Db, location: &NodeLocation) -> Option<Arc<Decl>> {
    let sf = db.source_file(&location.uri)?;
    let source = sf.text(db);
    let tree = crate::parse::parse(db, sf)?;
    let node = tree
        .root_node()
        .named_descendant_for_point_range(location.range)?;

    let id: InternedStr = node.utf8_text(source.as_bytes()).ok()?.into();

    match node.kind() {
        // Builtin types.
        // NOTE: This is driven by what types the parser exposes, extend as possible.

        // TODO(bbannier): the parser doesn't cleanly expose whether an integer is an `int` or a
        // `count`, use a dummy type until we resolve it
        "integer" => {
            return crate::ast::resolve_type(
                db,
                Type::Id(format!("<{}>", node.kind()).into()),
                Some(location),
            );
        }

        "hostname" => {
            return crate::ast::resolve_type(db, Type::Set(vec![Type::Addr]), Some(location));
        }
        "floatp" => return crate::ast::resolve_type(db, Type::Double, Some(location)),
        "ipv4" | "ipv6" => return crate::ast::resolve_type(db, Type::Addr, Some(location)),
        "subnet" => return crate::ast::resolve_type(db, Type::Subnet, Some(location)),
        "interval" => return crate::ast::resolve_type(db, Type::Interval, Some(location)),
        "port" => return crate::ast::resolve_type(db, Type::Port, Some(location)),
        "string" => return crate::ast::resolve_type(db, Type::String, Some(location)),
        "hex" => return crate::ast::resolve_type(db, Type::Count, Some(location)),

        "constant" => {
            match node.utf8_text(source.as_bytes()).ok()? {
                "T" | "F" => return crate::ast::resolve_type(db, Type::Bool, Some(location)),
                _ => return None,
            };
        }

        "type" => {
            return query::typ(node, source.as_bytes())
                .and_then(|t| crate::ast::resolve_type(db, t, Some(location)));
        }

        "expr" => {
            // Try to interpret expr as a cast `_ as @type`.
            if let Some(typ) = query::typ_from_cast(node, source.as_bytes()) {
                return crate::ast::resolve_type(db, typ, Some(location));
            }

            return node.named_child_not("nl").and_then(|c| {
                crate::ast::resolve(db, &NodeLocation::from_node(Arc::clone(&location.uri), c))
            });
        }
        // If we are on a `field_access` or `field_check` search the rhs in the scope of the lhs.
        "field_access" | "field_check" => {
            let xs = node.named_children_not("nl");
            let lhs = xs.first().copied()?;
            let rhs = xs.get(1).copied()?;

            let id = rhs.utf8_text(source.as_bytes()).ok()?;

            let var_decl =
                crate::ast::resolve(db, &NodeLocation::from_node(Arc::clone(&location.uri), lhs))?;
            let type_decl = crate::ast::typ(db, var_decl)?;

            match &type_decl.kind {
                DeclKind::Type(fields) => {
                    return fields.iter().find(|f| &*f.id == id).cloned().map(Arc::new);
                }
                DeclKind::Field(_) => return crate::ast::typ(db, type_decl),
                _ => return None,
            }
        }
        "id" => {
            // If the node is part of a record initializer resolve the field.
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
                    .and_then(|id| {
                        crate::ast::resolve(
                            db,
                            &NodeLocation::from_node(Arc::clone(&location.uri), id),
                        )
                    })
                    // Otherwise check the RHS for expressions like `local a: A = [$abc=123]`.
                    .or_else(|| {
                        let parent = expr.parent()?;

                        let type_id = parent.named_child("expr").and_then(|c| c.named_child("id"));

                        if let Some(id) = type_id {
                            crate::ast::resolve(
                                db,
                                &NodeLocation::from_node(Arc::clone(&location.uri), id),
                            )
                            .and_then(|decl| crate::ast::typ(db, decl))
                        } else if parent.kind() == "initializer" {
                            parent.prev_sibling().and_then(|t| {
                                crate::ast::resolve(
                                    db,
                                    &NodeLocation::from_node(Arc::clone(&location.uri), t),
                                )
                            })
                        } else {
                            None
                        }
                    });

                if let Some(type_) = type_
                    && let Decl {
                        kind: DeclKind::Type(fields),
                        ..
                    } = type_.as_ref()
                {
                    return fields.iter().find(|f| f.id == id).cloned().map(Arc::new);
                }
            }
        }
        _ => {}
    }

    // If the node is part of a field access or check resolve it in the referenced record.
    if let Some(p) = node.parent()
        && matches!(p.kind(), "field_access" | "field_check")
    {
        return crate::ast::resolve(db, &NodeLocation::from_node(Arc::clone(&location.uri), p));
    }

    // Try to find a decl with name of the given node up the tree.
    if let Some(r) = crate::ast::resolve_id(db, id, location) {
        // If we have found something which can have separate declaration and definition
        // return the declaration if possible. At this point this must be in another file.
        match r.kind {
            DeclKind::FuncDef(_) | DeclKind::EventDef(_) | DeclKind::HookDef(_) => {
                let root_loc = NodeLocation::from_node(Arc::clone(&location.uri), tree.root_node());
                if let Some(decl) = crate::ast::resolve_id(db, id, &root_loc) {
                    return Some(decl);
                }
            }
            _ => {}
        }

        return Some(r);
    }

    // If we arrive here and the identifier does not contain `::` it could also refer to a
    // declaration in the same module, but defined in a different file. Try to find it by
    // searching for it by its fully-qualified name.
    if !id.contains("::")
        && let Some(module) = tree
            .root_node()
            .named_child("module_decl")
            .and_then(|d| d.named_child("id"))
            .and_then(|id| id.utf8_text(source.as_bytes()).ok())
        && let Some(r) =
            crate::ast::resolve_id(db, format!("{module}::{id}").as_str().into(), location)
    {
        return Some(r);
    }
    None
}

#[instrument(skip(db))]
#[salsa::tracked(no_eq)]
pub(crate) fn loaded_files(db: &dyn Db, sf: SourceFile) -> Arc<[Arc<Uri>]> {
    let uri = sf.uri(db);
    let files = db.files();
    let prefixes = db.prefixes();

    let loads: Vec<_> = crate::query::loads(db, sf)
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
#[salsa::tracked(no_eq)]
pub(crate) fn loaded_files_recursive(db: &dyn Db, sf: SourceFile) -> Arc<[Arc<Uri>]> {
    let mut files: Vec<_> = loaded_files(db, sf).iter().cloned().collect();

    loop {
        let mut new_files = Vec::new();

        for f in &files {
            let Some(sf) = db.source_file(f) else {
                continue;
            };
            for load in loaded_files(db, sf).as_ref() {
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
#[salsa::tracked(no_eq)]
pub(crate) fn explicit_decls_recursive(db: &dyn Db, sf: SourceFile) -> Arc<[Decl]> {
    let d = crate::query::decls(db, sf);
    let decls1 = d.iter().cloned();

    let d = loaded_files_recursive(db, sf);
    let decls2 = d.iter().flat_map(|load| {
        let Some(sf) = db.source_file(load) else {
            return Vec::new();
        };
        let decls: Vec<_> = crate::query::decls(db, sf).iter().cloned().collect();
        decls
    });

    let d = decls1.chain(decls2).unique();

    Arc::from(d.into_iter().collect::<Vec<_>>())
}

#[instrument(skip(db))]
#[salsa::tracked(no_eq)]
pub(crate) fn implicit_loads(db: &dyn Db) -> Arc<[Arc<Uri>]> {
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

            for p in &db.prefixes() {
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
#[salsa::tracked(no_eq)]
pub(crate) fn implicit_decls(db: &dyn Db) -> Arc<[Decl]> {
    let loads = crate::ast::implicit_loads(db);

    loads
        .iter()
        .cloned()
        .flat_map(|load| {
            let Some(sf) = db.source_file(&load) else {
                return Vec::new();
            };
            let xs: Vec<_> = crate::ast::explicit_decls_recursive(db, sf)
                .iter()
                .cloned()
                .collect();
            xs
        })
        .unique()
        .collect()
}

#[instrument(skip(db))]
pub(crate) fn possible_loads(db: &dyn Db, uri: &Arc<Uri>) -> Vec<InternedStr> {
    let Some(path) = uri.to_file_path() else {
        return Vec::new();
    };

    let Some(path) = path.parent() else {
        return Vec::new();
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
                Some(InternedStr::from(Path::new(".").join(f).to_str()?))
            } else {
                prefixes.iter().find_map(|p| {
                    let l = f.strip_prefix(p).ok()?.to_str()?;
                    Some(InternedStr::from(l))
                })
            }
        })
        .collect();

    loads
}

#[must_use]
pub fn is_redef(d: &Decl) -> bool {
    matches!(
        &d.kind,
        DeclKind::Redef | DeclKind::RedefEnum(_) | DeclKind::RedefRecord(_)
    )
}

#[instrument(skip(db))]
#[salsa::tracked(no_eq)]
fn resolve_redef(db: &dyn Db, key: DeclFqid<'_>) -> Arc<[Decl]> {
    let fqid = key.fqid(db);
    let scope = key.scope(db);

    let implicit_decls = crate::ast::implicit_decls(db);
    let loaded_decls = crate::ast::explicit_decls_recursive(db, scope);
    let decls = crate::query::decls(db, scope);

    implicit_decls
        .iter()
        .chain(loaded_decls.iter())
        .chain(decls.iter())
        .unique()
        .filter(|x| x.fqid == fqid)
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

    let load_with_extension = {
        let mut l = load.as_os_str().to_owned();
        l.push(".zeek");
        l
    };

    let load_file = load.join("__load__.zeek");

    let get_uri = |prefix: &PathBuf| {
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
        if let Some((u, _)) = files.par_iter().find_any(|(_, p)| p.ends_with(load)) {
            return Some(Arc::clone(u));
        }

        // File known w/o extension.
        if let Some((u, _)) = files
            .par_iter()
            .find_any(|(_, p)| p.ends_with(&load_with_extension))
        {
            return Some(Arc::clone(u));
        }

        // Load is directory with `__load__.zeek`.
        if let Some((u, _)) = files.par_iter().find_any(|(_, p)| p.ends_with(&load_file)) {
            return Some(Arc::clone(u));
        }

        None
    };

    if let Some(dir) = file_dir
        && let Some(uri) = get_uri(&dir)
    {
        return Some(uri);
    }

    prefixes.par_iter().find_map_any(get_uri)
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use std::{ops::Deref, path::PathBuf, str::FromStr, sync::Arc};

    use insta::assert_debug_snapshot;
    use tower_lsp_server::ls_types::{Position, Range, Uri};

    use crate::{
        Db,
        ast::{self, typ},
        lsp::TestDatabase,
        query::{DeclKind, NodeLocation},
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

        assert_debug_snapshot!(ast::loaded_files_recursive(
            &db.0,
            db.0.source_file(&a).unwrap()
        ));
    }

    #[test]
    fn loaded_files() {
        let mut db = TestDatabase::default();

        let pre1 = PathBuf::from_str("/tmp/p").unwrap();
        let p1 = Uri::from_file_path(pre1.join("p1/p1.zeek")).unwrap();
        db.add_prefix(pre1);
        db.add_file(p1, "");

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

        assert_debug_snapshot!(ast::loaded_files(&db.0, db.0.source_file(&foo).unwrap()));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        let node = root
            .named_descendant_for_position(Position::new(13, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));

        let node = root
            .named_descendant_for_position(Position::new(15, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));

        let node = root
            .named_descendant_for_position(Position::new(18, 4))
            .unwrap();
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));

        let node = root
            .named_descendant_for_position(Position::new(19, 7))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));

        let node = root
            .named_descendant_for_position(Position::new(14, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));

        let node = root
            .named_descendant_for_position(Position::new(20, 8))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));

        let node = root
            .named_descendant_for_position(Position::new(24, 5))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(4, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 33))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("x"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("x::x"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("y"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), node)
        ));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        let x = root
            .named_descendant_for_position(Position::new(4, 0))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()), Ok("x"));
        assert_eq!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), x))
                .unwrap()
                .kind,
            super::DeclKind::Global
        );

        let x1 = root
            .named_descendant_for_position(Position::new(5, 3))
            .unwrap();
        assert_eq!(x1.utf8_text(source.as_bytes()), Ok("x1"));
        assert!(matches!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), x1))
                .unwrap()
                .kind,
            super::DeclKind::Field(_)
        ));

        let x2 = root
            .named_descendant_for_position(Position::new(6, 3))
            .unwrap();
        assert_eq!(x2.utf8_text(source.as_bytes()), Ok("x2"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), x2)
        ));
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

        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let source = db.0.source(&uri).unwrap();

        let type_ = tree
            .root_node()
            .named_descendant_for_position(Position::new(7, 14))
            .unwrap();
        assert_eq!(type_.utf8_text(source.as_bytes()), Ok("eB"));
        assert_debug_snapshot!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), type_)).unwrap()
        );

        let type_ = tree
            .root_node()
            .named_descendant_for_position(Position::new(14, 18))
            .unwrap();
        assert_eq!(type_.utf8_text(source.as_bytes()), Ok("eC"));
        assert_debug_snapshot!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), type_)).unwrap()
        );
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

        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let source = db.0.source(&uri).unwrap();

        let c = tree
            .root_node()
            .named_descendant_for_position(Position::new(3, 7))
            .unwrap();
        assert_eq!(c.utf8_text(source.as_bytes()), Ok("c"));
        let c_res = ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), c)).unwrap();
        assert_eq!(c_res.kind, super::DeclKind::Global);
        let c_type = typ(&db.0, c_res).unwrap();
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

        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let source = db.0.source(&uri).unwrap();

        let g = tree
            .root_node()
            .named_descendant_for_position(Position::new(2, 7))
            .unwrap();
        assert_eq!(g.utf8_text(source.as_bytes()), Ok("g"));
        assert_debug_snapshot!(typ(
            &db.0,
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), g)).unwrap()
        ));

        let f_a = tree
            .root_node()
            .named_descendant_for_position(Position::new(4, 11))
            .unwrap();
        assert_eq!(f_a.utf8_text(source.as_bytes()), Ok("a"));
        assert_debug_snapshot!(typ(
            &db.0,
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), f_a)).unwrap()
        ));

        let a = tree
            .root_node()
            .named_descendant_for_position(Position::new(5, 4))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()), Ok("a"));
        assert_debug_snapshot!(typ(
            &db.0,
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), a)).unwrap()
        ));

        let a_c = tree
            .root_node()
            .named_descendant_for_position(Position::new(5, 6))
            .unwrap();
        assert_eq!(a_c.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(ast::resolve(
            &db.0,
            &NodeLocation::from_node(Arc::clone(&uri), a_c)
        ));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        let x1 = root
            .named_descendant_for_position(Position::new(5, 8))
            .unwrap();
        assert_eq!(x1.utf8_text(source.as_bytes()), Ok("x1"));
        assert_eq!(
            &*typ(
                &db.0,
                ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), x1)).unwrap()
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
            &*typ(
                &db.0,
                ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), x2)).unwrap()
            )
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        {
            let b0 = root
                .named_descendant_for_position(Position::new(8, 22))
                .unwrap();
            assert_eq!(b0.utf8_text(source.as_bytes()).unwrap(), "b0");

            let decl = ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), b0)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(typ(&db.0, decl));
        }

        {
            let b1 = root
                .named_descendant_for_position(Position::new(9, 22))
                .unwrap();
            assert_eq!(b1.utf8_text(source.as_bytes()).unwrap(), "b1");

            let decl = ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), b1)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(typ(&db.0, decl));
        }

        {
            let i1 = root
                .named_descendant_for_position(Position::new(10, 22))
                .unwrap();
            assert_eq!(i1.utf8_text(source.as_bytes()).unwrap(), "i1");

            let decl = ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), i1)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(typ(&db.0, decl));
        }

        {
            let i2 = root
                .named_descendant_for_position(Position::new(11, 22))
                .unwrap();
            assert_eq!(i2.utf8_text(source.as_bytes()).unwrap(), "i2");

            let decl = ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), i2)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(typ(&db.0, decl));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(2, 22))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), a))
                .and_then(|d| typ(&db.0, d))
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(1, 22))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), a))
                .and_then(|d| typ(&db.0, d))
        );

        let b = root
            .named_descendant_for_position(Position::new(2, 22))
            .unwrap();
        assert_eq!(b.utf8_text(source.as_bytes()).unwrap(), "b");
        assert_debug_snapshot!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), b))
                .and_then(|d| typ(&db.0, d))
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        for (i, line) in source
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
        {
            let pos = Position::new(i.try_into().unwrap(), 19);
            assert_debug_snapshot!((
                line,
                ast::resolve(
                    &db.0,
                    &NodeLocation::from_range(Arc::clone(&uri), Range::new(pos, pos))
                )
                .and_then(|d| typ(&db.0, d))
            ));
        }

        // Validate that type is inferred for derived values.
        let x = root
            .named_descendant_for_position(Position::new(1, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        let x_typ = ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), x))
            .and_then(|d| typ(&db.0, d));
        let y = root
            .named_descendant_for_position(Position::new(2, 19))
            .unwrap();
        assert_eq!(y.utf8_text(source.as_bytes()).unwrap(), "y");
        let y_typ = ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), y))
            .and_then(|d| typ(&db.0, d));
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(1, 19))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), a))
                .and_then(|d| typ(&db.0, d))
        );

        let x = root
            .named_descendant_for_position(Position::new(4, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        assert_debug_snapshot!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), x))
                .and_then(|d| typ(&db.0, d))
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

        let source = db.0.source(&uri).unwrap();
        let sf = db.0.source_file(&uri).unwrap();
        let tree = crate::parse::parse(&db.0, sf).unwrap();
        let root = tree.root_node();

        let x = root
            .named_descendant_for_position(Position::new(2, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        assert_debug_snapshot!(
            ast::resolve(&db.0, &NodeLocation::from_node(Arc::clone(&uri), x))
                .and_then(|d| typ(&db.0, d))
        );
    }
}
