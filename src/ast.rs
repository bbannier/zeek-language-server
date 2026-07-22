use itertools::Itertools;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tower_lsp_server::ls_types::Uri;
use tracing::{instrument, warn};

use crate::{
    Db, InternedStr, InternedUri,
    query::{self, Decl, DeclKind, Index, NodeLocation, Type},
    zeek,
};

#[salsa::tracked(returns(clone), unsafe(non_salsa_values))]
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
#[instrument(skip(db))]
pub fn resolve_id(db: &dyn Db, id: InternedStr, scope: NodeLocation) -> Option<Arc<Decl>> {
    let uri = scope.uri;
    let tree = crate::parse::parse(db, uri)?;
    let scope = tree
        .root_node()
        .named_descendant_for_point_range(scope.range)?;
    let source = crate::source(db, uri)?;

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
            query::decls_(db, scope, uri, source.as_bytes())
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
    let decls = crate::query::decls(db, uri);
    let implicit_decls = implicit_decls(db);
    let explicit_decls_recursive = explicit_decls_recursive(db, uri);
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

#[salsa::tracked(returns(clone), unsafe(non_salsa_values))]
#[instrument(skip(db))]
pub fn resolve_type(db: &dyn Db, typ: Type, scope: Option<NodeLocation>) -> Option<Arc<Decl>> {
    #[allow(clippy::needless_pass_by_value)]
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
            .and_then(|s| resolve_id(db, *id, s))
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
                .map(|k| resolve_type(db, k.clone(), scope).map(|d| d.fqid))
                .collect::<Option<_>>()?;
            let ks = ks.into_iter().join(", ");
            let v = resolve_type(db, (**v).clone(), scope).map(|d| d.fqid)?;
            builtin_type(format!("table[{ks}] of {v}").into(), typ)
        }
        Type::Set(xs) => {
            let xs = xs
                .iter()
                .map(|x| resolve_type(db, x.clone(), scope).map(|d| d.fqid))
                .collect::<Option<Vec<_>>>()?;
            let xs = xs.into_iter().join(", ");
            builtin_type(format!("set[{xs}]").into(), typ)
        }
        Type::Time => builtin_type("time".into(), typ),
        Type::Timer => builtin_type("timer".into(), typ),
        Type::List(x) => builtin_type(
            format!(
                "list of {}",
                resolve_type(db, (**x).clone(), scope).map(|d| d.fqid)?
            )
            .into(),
            typ,
        ),
        Type::Vector(x) => builtin_type(
            format!(
                "vector of {}",
                resolve_type(db, (**x).clone(), scope).map(|d| d.fqid)?
            )
            .into(),
            typ,
        ),
        Type::File(x) => builtin_type(
            format!(
                "file of {}",
                resolve_type(db, (**x).clone(), scope).map(|d| d.fqid)?
            )
            .into(),
            typ,
        ),
        Type::Opaque(x) => builtin_type(
            format!(
                "opaque of {}",
                resolve_type(db, (**x).clone(), scope).map(|d| d.fqid)?
            )
            .into(),
            typ,
        ),
    })
}

pub fn typ(db: &dyn Db, decl: Arc<Decl>) -> Option<Arc<Decl>> {
    typ_impl(db, decl, ())
}

// salsa-0.28 requires single-arg tracked functions to implement `SalsaStructInDb`; the dummy `()`
// bypasses that via the RequiresInterning path until `Arc<Decl>` is replaced with an interned type.
#[salsa::tracked(returns(clone), unsafe(non_salsa_values))]
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn typ_impl(db: &dyn Db, decl: Arc<Decl>, _: ()) -> Option<Arc<Decl>> {
    // If we see a type decl with location we are likely dealing with a builtin type already which
    // cannot be further resolved; return it directly.
    if let DeclKind::Type(_) = &decl.kind
        && decl.loc.is_none()
    {
        return Some(decl);
    }

    let Some(loc) = &decl.loc else {
        return Some(decl);
    };
    let uri = loc.uri;

    let tree = crate::parse::parse(db, uri)?;

    let node = tree
        .root_node()
        .named_descendant_for_point_range(loc.range)?;

    if let DeclKind::Index(i, from) = &decl.kind {
        let from = resolve_id(db, from.as_str().into(), NodeLocation::from_node(uri, node))
            .and_then(|r| typ(db, r))?;

        let DeclKind::Builtin(typ) = &from.kind else {
            // TODO(bbannier): report diagnostic for iteration over non-builtins.
            return None;
        };

        let loc = decl
            .loc
            .as_ref()
            .map(|l| NodeLocation::from_range(l.uri, l.range));

        let idx = match *i {
            Index::Loop(i) => Some(i),
            _ => None,
        };

        #[allow(clippy::match_same_arms)]
        return match typ {
            Type::Vector(id) => match idx? {
                0 => resolve_type(db, Type::Count, loc),
                1 => resolve_type(db, (**id).clone(), loc),
                _ => None,
            },
            Type::Set(xs) => {
                let idx = idx.or(match i {
                    Index::Key(i) => Some(*i),
                    _ => None,
                })?;
                xs.get(idx).and_then(|x| resolve_type(db, x.clone(), loc))
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
                resolve_type(db, typ.clone(), loc)
            }
            _ => None,
        };
    }

    let make_typ = |typ| {
        let source = crate::source(db, uri)?;
        query::typ(typ, source.as_bytes())
            .and_then(|t| resolve_type(db, t, Some(NodeLocation::from_node(uri, typ))))
    };

    let d = match node.kind() {
        "var_decl" | "const_decl" | "option_decl" | "formal_arg" => {
            let typ = node.named_children_not("nl").into_iter().nth(1)?;

            match typ.kind() {
                "type" => make_typ(typ),
                "initializer" => typ
                    .named_child("expr")
                    .and_then(|n| resolve(db, NodeLocation::from_node(uri, n))),
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
            DeclKind::FuncDecl(sig) | DeclKind::FuncDef(sig) => resolve_type(
                db,
                sig.result.clone()?,
                Some(NodeLocation::from_node(loc.uri, node)),
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

                resolve(db, NodeLocation::from_node(loc.uri, n.named_child("id")?))
            }

            // Return the actual type for variable declarations.
            DeclKind::Const
            | DeclKind::Field(_)
            | DeclKind::Global
            | DeclKind::Index(_, _)
            | DeclKind::Variable => typ(db, d),

            // Other kinds we return directly.
            _ => Some(d),
        }
    })
}

#[allow(clippy::needless_pass_by_value)]
pub fn resolve(db: &dyn Db, location: NodeLocation) -> Option<Arc<Decl>> {
    resolve_impl(db, location.uri, location.range)
}

// `NodeLocation` is not a Salsa struct (`Range` isn't a Salsa value), so the tracked impl takes
// `uri` and `range` separately to bypass the single-arg `SalsaStructInDb` requirement.
#[salsa::tracked(returns(clone))]
#[allow(clippy::too_many_lines)]
fn resolve_impl(
    db: &dyn Db,
    uri: InternedUri,
    range: tower_lsp_server::ls_types::Range,
) -> Option<Arc<Decl>> {
    let location = NodeLocation::from_range(uri, range);
    let tree = crate::parse::parse(db, uri)?;
    let node = tree.root_node().named_descendant_for_point_range(range)?;
    let source = crate::source(db, uri)?;

    let id: InternedStr = node.utf8_text(source.as_bytes()).ok()?.into();

    match node.kind() {
        // Builtin types.
        // NOTE: This is driven by what types the parser exposes, extend as possible.

        // TODO(bbannier): the parser doesn't cleanly expose whether an integer is an `int` or a
        // `count`, use a dummy type until we resolve it
        "integer" => {
            return resolve_type(
                db,
                Type::Id(format!("<{}>", node.kind()).into()),
                Some(location),
            );
        }

        "hostname" => {
            return resolve_type(db, Type::Set(vec![Type::Addr]), Some(location));
        }
        "floatp" => return resolve_type(db, Type::Double, Some(location)),
        "ipv4" | "ipv6" => return resolve_type(db, Type::Addr, Some(location)),
        "subnet" => return resolve_type(db, Type::Subnet, Some(location)),
        "interval" => return resolve_type(db, Type::Interval, Some(location)),
        "port" => return resolve_type(db, Type::Port, Some(location)),
        "string" => return resolve_type(db, Type::String, Some(location)),
        "hex" => return resolve_type(db, Type::Count, Some(location)),

        "constant" => {
            match node.utf8_text(source.as_bytes()).ok()? {
                "T" | "F" => return resolve_type(db, Type::Bool, Some(location)),
                _ => return None,
            };
        }

        "type" => {
            return query::typ(node, source.as_bytes())
                .and_then(|t| resolve_type(db, t, Some(location)));
        }

        "expr" => {
            // Try to interpret expr as a cast `_ as @type`.
            if let Some(typ) = query::typ_from_cast(node, source.as_bytes()) {
                return resolve_type(db, typ, Some(location));
            }

            return node
                .named_child_not("nl")
                .and_then(|c| resolve(db, NodeLocation::from_node(uri, c)));
        }
        // If we are on a `field_access` or `field_check` search the rhs in the scope of the lhs.
        "field_access" | "field_check" => {
            let xs = node.named_children_not("nl");
            let lhs = xs.first().copied()?;
            let rhs = xs.get(1).copied()?;

            let id = rhs.utf8_text(source.as_bytes()).ok()?;

            let var_decl = resolve(db, NodeLocation::from_node(uri, lhs))?;
            let type_decl = typ(db, var_decl)?;

            match &type_decl.kind {
                DeclKind::Type(fields) => {
                    // Find the given id in the fields.
                    return fields.iter().find(|f| &*f.id == id).cloned().map(Arc::new);
                }
                DeclKind::Field(_) => return typ(db, type_decl),
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
                    .and_then(|id| resolve(db, NodeLocation::from_node(uri, id)))
                    // Otherwise check the RHS for expressions like `local a: A = [$abc=123]`.
                    .or_else(|| {
                        let parent = expr.parent()?;

                        let type_id = parent.named_child("expr").and_then(|c| c.named_child("id"));

                        if let Some(id) = type_id {
                            resolve(db, NodeLocation::from_node(uri, id))
                                .and_then(|decl| typ(db, decl))
                        } else if parent.kind() == "initializer" {
                            parent
                                .prev_sibling()
                                .and_then(|t| resolve(db, NodeLocation::from_node(uri, t)))
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
        return resolve(db, NodeLocation::from_node(uri, p));
    }

    // Try to find a decl with name of the given node up the tree.

    if let Some(r) = resolve_id(db, id, location) {
        // If we have found something which can have separate declaration and definition
        // return the declaration if possible. At this point this must be in another file.
        match r.kind {
            DeclKind::FuncDef(_) | DeclKind::EventDef(_) | DeclKind::HookDef(_) => {
                if let Some(decl) =
                    resolve_id(db, id, NodeLocation::from_node(uri, tree.root_node()))
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
    if !id.contains("::")
        && let Some(module) = tree
            .root_node()
            .named_child("module_decl")
            .and_then(|d| d.named_child("id"))
            .and_then(|id| id.utf8_text(source.as_bytes()).ok())
        && let Some(r) = resolve_id(db, format!("{module}::{id}").as_str().into(), location)
    {
        return Some(r);
    }
    None
}

#[salsa::tracked(returns(clone))]
#[allow(clippy::needless_pass_by_value)]
pub fn loaded_files(db: &dyn Db, uri: InternedUri) -> Arc<[InternedUri]> {
    let arc_uri = uri.uri(db);
    let files: Vec<_> = db.file_list().files(db).iter().map(|f| f.uri(db)).collect();

    let prefixes = db.workspace_state().prefixes(db);

    let loads: Vec<_> = crate::query::loads(db, uri)
        .iter()
        .map(|load| PathBuf::from(load.as_str()))
        .collect();

    let mut loaded_files = Vec::new();

    for load in &loads {
        if let Some(f) = load_to_file(load, arc_uri.as_ref(), &files, &prefixes) {
            loaded_files.push(crate::uri_db(db, f));
        }
    }

    Arc::from(loaded_files)
}

#[salsa::tracked(returns(clone))]
#[instrument(skip_all)]
pub fn loaded_files_recursive(db: &dyn Db, url: InternedUri) -> Arc<[InternedUri]> {
    let mut files: Vec<_> = loaded_files(db, url).iter().copied().collect();

    loop {
        let mut new_files = Vec::new();

        for f in &files {
            for load in loaded_files(db, *f).as_ref() {
                if !files.contains(load) {
                    new_files.push(*load);
                }
            }
        }

        if new_files.is_empty() {
            break;
        }

        files.extend(new_files);
    }

    Arc::from(files)
}

#[salsa::tracked(returns(clone))]
#[instrument(skip_all)]
pub fn explicit_decls_recursive(db: &dyn Db, uri: InternedUri) -> Arc<[Decl]> {
    let d = crate::query::decls(db, uri);
    let decls1 = d.iter().cloned();

    let d = loaded_files_recursive(db, uri);
    let decls2 = d.iter().flat_map(|load| {
        crate::query::decls(db, *load)
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    });

    Arc::from(decls1.chain(decls2).unique().collect::<Vec<_>>())
}

#[salsa::tracked(returns(clone))]
#[instrument(skip(db))]
pub fn implicit_loads(db: &dyn Db) -> Arc<[InternedUri]> {
    let mut loads = Vec::new();

    // These loops looks horrible, but is okay since this function will be cached most of the time
    // (unless global state changes).
    for essential_input in zeek::essential_input_files() {
        let mut implicit_file = None;
        for f in db.file_list().files(db).iter().copied() {
            let arc_f = f.uri(db);
            let Some(path) = arc_f.to_file_path() else {
                continue;
            };

            if !path.ends_with(essential_input) {
                continue;
            }

            for p in db.workspace_state().prefixes(db).iter() {
                if path.strip_prefix(p).is_ok() {
                    implicit_file = Some(f);
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

#[salsa::tracked(returns(clone))]
#[instrument(skip(db))]
pub fn implicit_decls(db: &dyn Db) -> Arc<[Decl]> {
    implicit_loads(db)
        .iter()
        .flat_map(|load| {
            explicit_decls_recursive(db, *load)
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        })
        .unique()
        .collect()
}

#[salsa::tracked(returns(clone))]
#[allow(clippy::needless_pass_by_value)]
#[instrument(skip_all)]
pub fn possible_loads(db: &dyn Db, uri: InternedUri) -> Arc<[InternedStr]> {
    let uri = uri.uri(db);
    let Some(path) = uri.to_file_path() else {
        return Arc::default();
    };

    let Some(path) = path.parent() else {
        return Arc::default();
    };

    let prefixes = db.workspace_state().prefixes(db);
    let files: Vec<_> = db.file_list().files(db).iter().map(|f| f.uri(db)).collect();

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

    Arc::from(loads)
}

#[must_use]
pub fn is_redef(d: &Decl) -> bool {
    matches!(
        &d.kind,
        DeclKind::Redef | DeclKind::RedefEnum(_) | DeclKind::RedefRecord(_)
    )
}

#[allow(clippy::needless_pass_by_value)]
#[instrument(skip(db))]
fn resolve_redef(db: &dyn Db, redef: &Decl, uri: InternedUri) -> Arc<[Decl]> {
    if !is_redef(redef) {
        return Arc::default();
    }

    let implicit_decls = implicit_decls(db);
    let loaded_decls = explicit_decls_recursive(db, uri);
    let decls = crate::query::decls(db, uri);

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

    let load_with_extension = {
        let mut l = load.as_os_str().to_owned();
        l.push(".zeek");
        l
    };

    let load_file = load.join("__load__.zeek");

    let get_uri = |prefix: &PathBuf| {
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
        if let Some((uri, _)) = files.par_iter().find_any(|(_, p)| p.ends_with(load)) {
            return Some(Arc::clone(uri));
        }

        // File known w/o extension.
        if let Some((uri, _)) = files
            .par_iter()
            .find_any(|(_, p)| p.ends_with(&load_with_extension))
        {
            return Some(Arc::clone(uri));
        }

        // Load is directory with `__load__.zeek`.
        if let Some((uri, _)) = files.par_iter().find_any(|(_, p)| p.ends_with(&load_file)) {
            return Some(Arc::clone(uri));
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

    use crate::test_util::assert_debug_snapshot;
    use tower_lsp_server::ls_types::{Position, Range, Uri};

    use crate::{
        lsp::TestDatabase,
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

        let result: Vec<_> = crate::ast::loaded_files_recursive(&db.0, crate::uri_db(&db.0, a))
            .iter()
            .map(|u| u.uri(&db.0).path().to_string())
            .collect();
        assert_debug_snapshot!(result);
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

        let result: Vec<_> = crate::ast::loaded_files(&db.0, crate::uri_db(&db.0, foo))
            .iter()
            .map(|u| u.uri(&db.0).path().to_string())
            .collect();
        assert_debug_snapshot!(result);
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

        let uri = crate::uri_db(&db.0, uri);
        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        // `c` resolves to `local c: ...`.
        let node = root
            .named_descendant_for_position(Position::new(13, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
        ));

        // `c?$f1` resolves to `f1: count`.
        let node = root
            .named_descendant_for_position(Position::new(15, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
        ));

        // `y` resolves to `y: count` via function argument.
        let node = root
            .named_descendant_for_position(Position::new(18, 4))
            .unwrap();
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
        ));

        // `x2$f1` resolves to `f1:count ...` via function argument.
        let node = root
            .named_descendant_for_position(Position::new(19, 7))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
        ));

        // `x$f1` resolves to `f1: count ...`.
        let node = root
            .named_descendant_for_position(Position::new(14, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
        ));

        // `x2$f1` resolves to `f1: count ...`.
        let node = root
            .named_descendant_for_position(Position::new(20, 8))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
        ));

        // Check resolution when multiple field accesses are involved.
        let node = root
            .named_descendant_for_position(Position::new(24, 5))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(4, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 33))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("x"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("x::x"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, node)).unwrap();
        assert_eq!(
            decl.loc.as_ref().unwrap().uri,
            crate::uri_db(&db.0, Arc::new(Uri::from_file_path("/x.zeek").unwrap()))
        );
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();

        let node = tree.root_node();
        let node = node
            .named_descendant_for_position(Position::new(2, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("y"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, node)).unwrap();
        assert_eq!(
            decl.loc.as_ref().unwrap().uri,
            crate::uri_db(&db.0, Arc::new(Uri::from_file_path("/x.zeek").unwrap()))
        );
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let x = root
            .named_descendant_for_position(Position::new(4, 0))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()), Ok("x"));
        assert_eq!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x))
                .unwrap()
                .kind,
            super::DeclKind::Global
        );

        let x1 = root
            .named_descendant_for_position(Position::new(5, 3))
            .unwrap();
        assert_eq!(x1.utf8_text(source.as_bytes()), Ok("x1"));
        let x1_decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x1)).unwrap();
        assert!(matches!(x1_decl.kind, super::DeclKind::Field(_)));
        assert_eq!(
            x1_decl.loc.as_ref().unwrap().uri,
            crate::uri_db(&db.0, Arc::new(Uri::from_file_path("/x.zeek").unwrap()))
        );

        let x2 = root
            .named_descendant_for_position(Position::new(6, 3))
            .unwrap();
        assert_eq!(x2.utf8_text(source.as_bytes()), Ok("x2"));
        let x2_decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x2)).unwrap();
        assert_eq!(
            x2_decl.loc.as_ref().unwrap().uri,
            crate::uri_db(&db.0, Arc::new(Uri::from_file_path("/y.zeek").unwrap()))
        );
        assert_debug_snapshot!(crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x2)));
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
        let uri = crate::uri_db(&db.0, uri);

        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let source = crate::source(&db.0, uri).unwrap();

        let type_ = tree
            .root_node()
            .named_descendant_for_position(Position::new(7, 14))
            .unwrap();
        assert_eq!(type_.utf8_text(source.as_bytes()), Ok("eB"));
        let uri_x = crate::uri_db(&db.0, Arc::new(Uri::from_file_path("/x.zeek").unwrap()));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, type_)).unwrap();
        assert_eq!(decl.loc.as_ref().unwrap().uri, uri_x);
        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, type_)).unwrap()
        );

        let type_ = tree
            .root_node()
            .named_descendant_for_position(Position::new(14, 18))
            .unwrap();
        assert_eq!(type_.utf8_text(source.as_bytes()), Ok("eC"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, type_)).unwrap();
        assert_eq!(decl.loc.as_ref().unwrap().uri, uri_x);
        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, type_)).unwrap()
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
        let uri = crate::uri_db(&db.0, uri);

        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let source = crate::source(&db.0, uri).unwrap();

        let c = tree
            .root_node()
            .named_descendant_for_position(Position::new(3, 7))
            .unwrap();
        assert_eq!(c.utf8_text(source.as_bytes()), Ok("c"));
        let c_res = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, c)).unwrap();
        assert_eq!(c_res.kind, super::DeclKind::Global);
        let c_type = crate::ast::typ(&db.0, c_res).unwrap();
        assert_eq!(
            c_type.loc.as_ref().unwrap().uri,
            crate::uri_db(
                &db.0,
                Arc::new(Uri::from_file_path("/init-bare.zeek").unwrap())
            )
        );
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
        let uri = crate::uri_db(&db.0, uri);

        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let source = crate::source(&db.0, uri).unwrap();

        let g = tree
            .root_node()
            .named_descendant_for_position(Position::new(2, 7))
            .unwrap();
        assert_eq!(g.utf8_text(source.as_bytes()), Ok("g"));
        assert_debug_snapshot!(crate::ast::typ(
            &db.0,
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, g)).unwrap()
        ));

        let f_a = tree
            .root_node()
            .named_descendant_for_position(Position::new(4, 11))
            .unwrap();
        assert_eq!(f_a.utf8_text(source.as_bytes()), Ok("a"));
        assert_debug_snapshot!(crate::ast::typ(
            &db.0,
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, f_a)).unwrap()
        ));

        let a = tree
            .root_node()
            .named_descendant_for_position(Position::new(5, 4))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()), Ok("a"));
        assert_debug_snapshot!(crate::ast::typ(
            &db.0,
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, a)).unwrap()
        ));

        let a_c = tree
            .root_node()
            .named_descendant_for_position(Position::new(5, 6))
            .unwrap();
        assert_eq!(a_c.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, a_c)
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let x1 = root
            .named_descendant_for_position(Position::new(5, 8))
            .unwrap();
        assert_eq!(x1.utf8_text(source.as_bytes()), Ok("x1"));
        assert_eq!(
            &*crate::ast::typ(
                &db.0,
                crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x1)).unwrap()
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
            &*crate::ast::typ(
                &db.0,
                crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x2)).unwrap()
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        {
            let b0 = root
                .named_descendant_for_position(Position::new(8, 22))
                .unwrap();
            assert_eq!(b0.utf8_text(source.as_bytes()).unwrap(), "b0");

            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, b0)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(crate::ast::typ(&db.0, decl));
        }

        {
            let b1 = root
                .named_descendant_for_position(Position::new(9, 22))
                .unwrap();
            assert_eq!(b1.utf8_text(source.as_bytes()).unwrap(), "b1");

            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, b1)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(crate::ast::typ(&db.0, decl));
        }

        {
            let i1 = root
                .named_descendant_for_position(Position::new(10, 22))
                .unwrap();
            assert_eq!(i1.utf8_text(source.as_bytes()).unwrap(), "i1");

            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, i1)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(crate::ast::typ(&db.0, decl));
        }

        {
            let i2 = root
                .named_descendant_for_position(Position::new(11, 22))
                .unwrap();
            assert_eq!(i2.utf8_text(source.as_bytes()).unwrap(), "i2");

            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, i2)).unwrap();
            assert_eq!(decl.kind, DeclKind::Variable);

            assert_debug_snapshot!(crate::ast::typ(&db.0, decl));
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(2, 22))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, a))
                .and_then(|d| crate::ast::typ(&db.0, d))
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(1, 22))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, a))
                .and_then(|d| crate::ast::typ(&db.0, d))
        );

        let b = root
            .named_descendant_for_position(Position::new(2, 22))
            .unwrap();
        assert_eq!(b.utf8_text(source.as_bytes()).unwrap(), "b");
        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, b))
                .and_then(|d| crate::ast::typ(&db.0, d))
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        for (i, line) in source
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
        {
            let pos = Position::new(i.try_into().unwrap(), 19);
            assert_debug_snapshot!((
                line,
                crate::ast::resolve(&db.0, NodeLocation::from_range(uri, Range::new(pos, pos)))
                    .and_then(|d| crate::ast::typ(&db.0, d))
            ));
        }

        // Validate that type is inferred for derived values.
        let x = root
            .named_descendant_for_position(Position::new(1, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        let x_typ = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x))
            .and_then(|d| crate::ast::typ(&db.0, d));
        let y = root
            .named_descendant_for_position(Position::new(2, 19))
            .unwrap();
        assert_eq!(y.utf8_text(source.as_bytes()).unwrap(), "y");
        let y_typ = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, y))
            .and_then(|d| crate::ast::typ(&db.0, d));
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(1, 19))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "a");
        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, a))
                .and_then(|d| crate::ast::typ(&db.0, d))
        );

        let x = root
            .named_descendant_for_position(Position::new(4, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x))
                .and_then(|d| crate::ast::typ(&db.0, d))
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let x = root
            .named_descendant_for_position(Position::new(2, 19))
            .unwrap();
        assert_eq!(x.utf8_text(source.as_bytes()).unwrap(), "x");
        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, x))
                .and_then(|d| crate::ast::typ(&db.0, d))
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
        let uri = crate::uri_db(&db.0, uri);

        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();
        let source = crate::source(&db.0, uri).unwrap();

        // Vector iteration.
        let i1 = root
            .named_descendant_for_position(Position::new(1, 29))
            .unwrap();
        assert_eq!(i1.utf8_text(source.as_bytes()), Ok("i"));
        assert_debug_snapshot!(crate::ast::resolve(&db.0, NodeLocation::from_node(uri, i1)));

        let i2 = root
            .named_descendant_for_position(Position::new(2, 0))
            .unwrap();
        assert_eq!(
            i2.utf8_text(crate::source(&db.0, uri).unwrap().as_bytes()),
            Ok("i")
        );
        assert_debug_snapshot!(crate::ast::resolve(&db.0, NodeLocation::from_node(uri, i2)));

        // Set iteration.
        let s = root
            .named_descendant_for_position(Position::new(3, 26))
            .unwrap();
        assert_eq!(s.utf8_text(source.as_bytes()), Ok("s"));
        assert_debug_snapshot!(crate::ast::resolve(&db.0, NodeLocation::from_node(uri, s)));

        // Table iteration.
        let ta = root
            .named_descendant_for_position(Position::new(4, 42))
            .unwrap();
        let tb = root
            .named_descendant_for_position(Position::new(4, 46))
            .unwrap();
        assert_eq!(ta.utf8_text(source.as_bytes()), Ok("ta"));
        assert_eq!(tb.utf8_text(source.as_bytes()), Ok("tb"));
        assert_debug_snapshot!(crate::ast::resolve(&db.0, NodeLocation::from_node(uri, ta)));
        assert_debug_snapshot!(crate::ast::resolve(&db.0, NodeLocation::from_node(uri, tb)));
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(11, 31))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "A");
        assert_eq!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, a))
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
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, b))
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
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, c))
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let foo = root
            .named_descendant_for_position(Position::new(4, 10))
            .unwrap();
        assert_eq!(foo.utf8_text(source.as_bytes()).unwrap(), "foo");

        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, foo)).unwrap();
        assert!(
            decl.documentation
                .starts_with("Multiline\ndocumentation.\n"),
            "{docs}",
            docs = decl.documentation
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let check = |position: Position, expected_id: &str| {
            let n = root.named_descendant_for_position(position).unwrap();
            assert_eq!(n.utf8_text(source.as_bytes()), Ok(expected_id));
            let typ = n.parent().unwrap().named_child("type").unwrap();
            let t = query::typ(typ, source.as_bytes()).unwrap();
            let resolved =
                crate::ast::resolve_type(&db.0, t, Some(NodeLocation::from_node(uri, typ)))
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let a = root
            .named_descendant_for_position(Position::new(7, 22))
            .unwrap();
        assert_eq!(a.utf8_text(source.as_bytes()).unwrap(), "my_a");

        assert_debug_snapshot!(
            crate::ast::resolve(&db.0, NodeLocation::from_node(uri, a))
                .and_then(|d| crate::ast::typ(&db.0, d))
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let v = root
            .named_descendant_for_position(Position::new(2, 25))
            .unwrap();
        assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, v)).unwrap();
        let typ = crate::ast::typ(&db.0, decl).unwrap();
        assert_debug_snapshot!(typ);

        let i = root
            .named_descendant_for_position(Position::new(3, 25))
            .unwrap();
        assert_eq!(i.utf8_text(source.as_bytes()), Ok("i"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, i)).unwrap();
        let typ = crate::ast::typ(&db.0, decl).unwrap();
        assert_debug_snapshot!(typ);

        let v = root
            .named_descendant_for_position(Position::new(3, 28))
            .unwrap();
        assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, v)).unwrap();
        let typ = crate::ast::typ(&db.0, decl).unwrap();
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let v = root
            .named_descendant_for_position(Position::new(2, 25))
            .unwrap();
        assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, v)).unwrap();
        let typ = crate::ast::typ(&db.0, decl).unwrap();
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        let c = root
            .named_descendant_for_position(Position::new(2, 26))
            .unwrap();
        assert_eq!(c.utf8_text(source.as_bytes()), Ok("c"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, c)).unwrap();
        let typ = crate::ast::typ(&db.0, decl).unwrap();
        assert_debug_snapshot!(typ);

        let s = root
            .named_descendant_for_position(Position::new(2, 29))
            .unwrap();
        assert_eq!(s.utf8_text(source.as_bytes()), Ok("s"));
        let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, s)).unwrap();
        let typ = crate::ast::typ(&db.0, decl).unwrap();
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
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let root = tree.root_node();

        {
            let k = root
                .named_descendant_for_position(Position::new(4, 26))
                .unwrap();
            assert_eq!(k.utf8_text(source.as_bytes()), Ok("k"));
            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, k)).unwrap();
            let typ = crate::ast::typ(&db.0, decl).unwrap();
            assert_debug_snapshot!(typ);

            let v = root
                .named_descendant_for_position(Position::new(4, 29))
                .unwrap();
            assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, v)).unwrap();
            let typ = crate::ast::typ(&db.0, decl).unwrap();
            assert_debug_snapshot!(typ);
        }

        {
            let k1 = root
                .named_descendant_for_position(Position::new(5, 28))
                .unwrap();
            assert_eq!(k1.utf8_text(source.as_bytes()), Ok("k1"));
            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, k1)).unwrap();
            let typ = crate::ast::typ(&db.0, decl).unwrap();
            assert_debug_snapshot!(typ);

            let k2 = root
                .named_descendant_for_position(Position::new(5, 32))
                .unwrap();
            assert_eq!(k2.utf8_text(source.as_bytes()), Ok("k2"));
            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, k2)).unwrap();
            let typ = crate::ast::typ(&db.0, decl).unwrap();
            assert_debug_snapshot!(typ);

            let v = root
                .named_descendant_for_position(Position::new(5, 38))
                .unwrap();
            assert_eq!(v.utf8_text(source.as_bytes()), Ok("v"));
            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, v)).unwrap();
            let typ = crate::ast::typ(&db.0, decl).unwrap();
            assert_debug_snapshot!(typ);
        }

        {
            let k1 = root
                .named_descendant_for_position(Position::new(6, 28))
                .unwrap();
            assert_eq!(k1.utf8_text(source.as_bytes()), Ok("k1"));
            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, k1)).unwrap();
            let typ = crate::ast::typ(&db.0, decl).unwrap();
            assert_debug_snapshot!(typ);

            let k2 = root
                .named_descendant_for_position(Position::new(6, 32))
                .unwrap();
            assert_eq!(k2.utf8_text(source.as_bytes()), Ok("k2"));
            let decl = crate::ast::resolve(&db.0, NodeLocation::from_node(uri, k2)).unwrap();
            let typ = crate::ast::typ(&db.0, decl).unwrap();
            assert_debug_snapshot!(typ);
        }
    }

    #[test]
    fn resolve_builtin_implicit() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file((*uri).clone(), "global x: count;");
        let uri = crate::uri_db(&db.0, uri);

        let source = crate::source(&db.0, uri).unwrap();
        let tree = crate::parse::parse(&db.0, uri).unwrap();
        let node = tree
            .root_node()
            .named_descendant_for_position(Position::new(0, 10))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("count"));
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(uri, node)
        ));
    }

    #[test]
    fn resolve_from_loaded_file() {
        let mut db = TestDatabase::default();
        let a = Arc::new(Uri::from_file_path("/a.zeek").unwrap());
        db.add_file(
            Uri::from_file_path("/b.zeek").unwrap(),
            "module b; export { global VAL: count; }",
        );
        db.add_file(
            (*a).clone(),
            "@load ./b
b::VAL;",
        );

        let source = crate::source(&db.0, crate::uri_db(&db.0, Arc::clone(&a))).unwrap();
        let tree = crate::parse::parse(&db.0, crate::uri_db(&db.0, Arc::clone(&a))).unwrap();
        let node = tree
            .root_node()
            .named_descendant_for_position(Position::new(1, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("b::VAL"));
        let decl = crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(crate::uri_db(&db.0, Arc::clone(&a)), node),
        )
        .unwrap();
        assert_eq!(
            decl.loc.as_ref().unwrap().uri,
            crate::uri_db(&db.0, Arc::new(Uri::from_file_path("/b.zeek").unwrap()))
        );
        assert_debug_snapshot!(crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(crate::uri_db(&db.0, Arc::clone(&a)), node)
        ));
    }

    #[test]
    fn typ_from_loaded_file() {
        let mut db = TestDatabase::default();
        let a = Arc::new(Uri::from_file_path("/a.zeek").unwrap());
        db.add_file(
            Uri::from_file_path("/b.zeek").unwrap(),
            "module b; export { global VAL: count; }",
        );
        db.add_file(
            (*a).clone(),
            "@load ./b
b::VAL;",
        );

        let source = crate::source(&db.0, crate::uri_db(&db.0, Arc::clone(&a))).unwrap();
        let tree = crate::parse::parse(&db.0, crate::uri_db(&db.0, Arc::clone(&a))).unwrap();
        let node = tree
            .root_node()
            .named_descendant_for_position(Position::new(1, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("b::VAL"));
        let decl = crate::ast::resolve(
            &db.0,
            NodeLocation::from_node(crate::uri_db(&db.0, Arc::clone(&a)), node),
        );
        assert_debug_snapshot!(
            decl.as_ref()
                .and_then(|d| crate::ast::typ(&db.0, Arc::clone(d)))
        );
    }
}
