//! Shared `syn` traversal: walks a parsed file and yields every function-like
//! item with a body (`fn`, impl method, default trait method), tracking the
//! enclosing `mod`/`impl`/`trait` path so callers get a qualified name.
//!
//! Used by both [`crate::complexity`] and [`crate::duplication`] so the two
//! detectors agree on what counts as "a function" without duplicating the
//! traversal logic.

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, ImplItemFn, ItemFn, ItemImpl, ItemMod, ItemTrait, TraitItemFn, Type};

/// One function-like item discovered while walking a file.
pub struct FunctionSite<'ast> {
    pub qualified_name: String,
    pub span: Span,
    pub block: &'ast Block,
}

/// Visits every `fn`, impl method, and default trait-method body in `file`,
/// invoking `on_function` for each with its qualified name, span, and body.
pub fn walk_functions<'ast>(file: &'ast syn::File, on_function: impl FnMut(FunctionSite<'ast>)) {
    let mut walker = Walker {
        path: Vec::new(),
        on_function,
    };
    walker.visit_file(file);
}

struct Walker<F> {
    path: Vec<String>,
    on_function: F,
}

impl<F> Walker<F> {
    fn qualified_name(&self, name: &str) -> String {
        if self.path.is_empty() {
            name.to_string()
        } else {
            format!("{}::{name}", self.path.join("::"))
        }
    }
}

impl<'ast, F> Walker<F>
where
    F: FnMut(FunctionSite<'ast>),
{
    fn emit(&mut self, name: &str, spanned: &impl Spanned, block: &'ast Block) {
        let qualified_name = self.qualified_name(name);
        (self.on_function)(FunctionSite {
            qualified_name,
            span: spanned.span(),
            block,
        });
    }
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map_or_else(|| "?".to_string(), |segment| segment.ident.to_string()),
        _ => "?".to_string(),
    }
}

impl<'ast, F> Visit<'ast> for Walker<F>
where
    F: FnMut(FunctionSite<'ast>),
{
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if node.content.is_some() {
            self.path.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.path.pop();
        } else {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        self.path.push(type_name(&node.self_ty));
        visit::visit_item_impl(self, node);
        self.path.pop();
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        self.path.push(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.path.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.emit(&node.sig.ident.to_string(), node, &node.block);
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.emit(&node.sig.ident.to_string(), node, &node.block);
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        if let Some(block) = &node.default {
            self.emit(&node.sig.ident.to_string(), node, block);
        }
        visit::visit_trait_item_fn(self, node);
    }
}
