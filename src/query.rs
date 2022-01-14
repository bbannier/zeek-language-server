use log::warn;
use tower_lsp::lsp_types::{Range, Url};
use tree_sitter::Node;

use crate::{parse::tree_sitter_zeek, to_range};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum DeclKind {
    Global,
    Option,
    Const,
    Redef,
    RedefEnum,
    RedefRecord,
    Type,
    Func,
    Hook,
    Event,
}

#[derive(Debug)]
pub struct Decl {
    pub id: String,
    pub kind: DeclKind,
    pub is_export: bool,
    pub range: Range,
    pub selection_range: Range,
}

#[derive(Debug)]
pub struct Module<'a> {
    pub id: Option<&'a str>,
    pub decls: Vec<Decl>,
}

#[must_use]
pub fn default_module_name(uri: &Url) -> Option<&str> {
    uri
        // Assume that text documents refer to file paths.
        .path_segments()
        // The last path component would be the file name.
        .and_then(Iterator::last)
        // Assume that implicit module names only exist for files name like `mod.zeek`, and
        // e.g., multiple `.` are not allowed.
        .and_then(|s| s.split('.').next())
    // If we still cannot extract a name at least provide _something_.
}

#[must_use]
pub fn module<'a>(node: Node, source: &'a str) -> Option<Module<'a>> {
    let query = match tree_sitter::Query::new(
        unsafe { tree_sitter_zeek() },
        "(module (id)*@module_id [\
            (_ (id)@id)@priv_decl \
            (export (_ (id)@id)@pub_decl) \
            ])",
    )
    .ok()
    {
        Some(q) => q,
        None => return None,
    };

    dbg!(&query.capture_names());

    let c_module = query.capture_index_for_name("module_id")?;
    let c_id = query.capture_index_for_name("id")?;
    let c_priv_decl = query.capture_index_for_name("priv_decl")?;
    let c_pub_decl = query.capture_index_for_name("pub_decl")?;

    let decls = tree_sitter::QueryCursor::new()
        .matches(&query, node, source.as_bytes())
        .filter_map(|c| {
            let module_id = c
                .nodes_for_capture_index(c_module)
                .next()
                .and_then(|n| n.utf8_text(source.as_bytes()).ok());

            let id = c
                .nodes_for_capture_index(c_id)
                .next()
                .expect("match should be present");

            let pub_decl = c.nodes_for_capture_index(c_pub_decl).next();
            let priv_decl = c.nodes_for_capture_index(c_priv_decl).next();

            let is_export = pub_decl.is_some();

            let node = if let Some(n) = pub_decl {
                n
            } else if let Some(n) = priv_decl {
                n
            } else {
                unreachable!("we should match either a private or an export node");
            };

            let range = to_range(node.range()).ok()?;
            let selection_range = to_range(id.range()).ok()?;

            let id = id.utf8_text(source.as_bytes()).ok()?.into();

            let kind = match node.kind() {
                "const_decl" => DeclKind::Const,
                "global_decl" => DeclKind::Global,
                "redef_enum_decl" => DeclKind::RedefEnum,
                "redef_record_decl" => DeclKind::RedefRecord,
                "option_decl" => DeclKind::Option,
                "type_decl" => DeclKind::Type,
                "event_decl" => DeclKind::Event,
                "func_decl" => DeclKind::Func,
                "export_decl" | "preproc" => {
                    // These nodes are no interesting decls.
                    return None;
                }
                _ => {
                    warn!("received node kind {} which is unsupported", node.kind());
                    return None;
                }
            };

            Some((
                module_id,
                Decl {
                    id,
                    kind,
                    is_export,
                    range,
                    selection_range,
                },
            ))
        })
        .collect::<Vec<(_, _)>>();

    let id = match decls.get(0) {
        Some((Some(id), _)) => Some(*id),
        _ => None,
    };

    let decls = decls.into_iter().map(|(_, d)| d).collect();

    Some(Module { id, decls })
}

#[cfg(test)]
mod test {
    use super::module;
    use crate::parse::parse_;
    use insta::assert_debug_snapshot;

    #[test]
    fn test_module() {
        let source = "module test; 

              export {
                  const x = 1 &redef;
                  global y = 1;
              }

              type Y: record {
                  y: vector of count &optional;
              };

              event zeek_init() { 1; }";

        let tree = parse_(source, None).expect("cannot parse");

        assert_debug_snapshot!(module(tree.root_node(), source));
    }
}
