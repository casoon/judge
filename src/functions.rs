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
    /// Span of just the function's identifier — narrower than `span`, which
    /// covers the whole item. Needed to position a Deep Tier query exactly
    /// on the name token (see [`crate::deep`]). Only consumed behind the
    /// `deep` feature, hence the conditional allow — a Fast Tier build has
    /// no reader for it.
    #[cfg_attr(not(feature = "deep"), allow(dead_code))]
    pub ident_span: Span,
    /// The item's own written visibility. `None` for a trait's default
    /// method, which has no visibility of its own — it's as visible as the
    /// trait itself. Same conditional allow as `ident_span`.
    #[cfg_attr(not(feature = "deep"), allow(dead_code))]
    pub vis: Option<&'ast syn::Visibility>,
    /// The item's attributes (`#[test]`, `#[no_mangle]`, …) — used to
    /// recognize entry points beyond `fn main` (see
    /// [`crate::reachability::entry_point_positions`]). Same conditional
    /// allow as `ident_span`.
    #[cfg_attr(not(feature = "deep"), allow(dead_code))]
    pub attrs: &'ast [syn::Attribute],
    /// Whether this function is an `impl` method inside `impl TraitName for
    /// SomeType { .. }` (i.e. the enclosing `ItemImpl.trait_.is_some()`).
    /// `false` for free functions, inherent-impl methods, and trait default
    /// methods (which live in the trait definition, not an impl block).
    /// Used by [`crate::slop_structural_deep`] to exclude trait-dispatch
    /// methods (`Display::fmt`, `Iterator::next`, …) from checks that rely
    /// on literal `.method()` call-site references — those methods are
    /// routinely invoked through operator/macro sugar a reference search
    /// can't see. Same conditional allow as `ident_span`.
    #[cfg_attr(not(feature = "deep"), allow(dead_code))]
    pub in_trait_impl: bool,
}

/// Visits every `fn`, impl method, and default trait-method body in `file`,
/// invoking `on_function` for each with its qualified name, span, and body.
pub fn walk_functions<'ast>(file: &'ast syn::File, on_function: impl FnMut(FunctionSite<'ast>)) {
    let mut walker = Walker {
        path: Vec::new(),
        in_trait_impl: Vec::new(),
        on_function,
    };
    walker.visit_file(file);
}

struct Walker<F> {
    path: Vec<String>,
    /// Stack of `in_trait_impl` flags, one per enclosing `impl` block —
    /// mirrors `path`'s push/pop shape. A stack rather than a single flag
    /// because an `impl` can (rarely) be nested inside a function body.
    in_trait_impl: Vec<bool>,
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

    fn current_in_trait_impl(&self) -> bool {
        self.in_trait_impl.last().copied().unwrap_or(false)
    }
}

impl<'ast, F> Walker<F>
where
    F: FnMut(FunctionSite<'ast>),
{
    fn emit(
        &mut self,
        name: &str,
        spanned: &impl Spanned,
        block: &'ast Block,
        ident_span: Span,
        vis: Option<&'ast syn::Visibility>,
        attrs: &'ast [syn::Attribute],
        in_trait_impl: bool,
    ) {
        let qualified_name = self.qualified_name(name);
        (self.on_function)(FunctionSite {
            qualified_name,
            span: spanned.span(),
            block,
            ident_span,
            vis,
            attrs,
            in_trait_impl,
        });
    }
}

pub(crate) fn type_name(ty: &Type) -> String {
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
        self.in_trait_impl.push(node.trait_.is_some());
        visit::visit_item_impl(self, node);
        self.in_trait_impl.pop();
        self.path.pop();
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        self.path.push(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.path.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.emit(
            &node.sig.ident.to_string(),
            node,
            &node.block,
            node.sig.ident.span(),
            Some(&node.vis),
            &node.attrs,
            false,
        );
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let in_trait_impl = self.current_in_trait_impl();
        self.emit(
            &node.sig.ident.to_string(),
            node,
            &node.block,
            node.sig.ident.span(),
            Some(&node.vis),
            &node.attrs,
            in_trait_impl,
        );
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        if let Some(block) = &node.default {
            self.emit(
                &node.sig.ident.to_string(),
                node,
                block,
                node.sig.ident.span(),
                None,
                &node.attrs,
                false,
            );
        }
        visit::visit_trait_item_fn(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::walk_functions;

    #[test]
    fn qualifies_names_across_mod_impl_and_trait() {
        let file: syn::File = syn::parse_str(
            r#"
mod outer {
    pub struct Foo;

    impl Foo {
        fn method(&self) {}
    }

    pub trait Greet {
        fn hi(&self) {}
        fn required(&self);
    }

    mod inner {
        fn free_fn() {}
    }
}

fn top_level() {}
"#,
        )
        .unwrap();

        let mut names = Vec::new();
        walk_functions(&file, |site| names.push(site.qualified_name));
        names.sort();

        assert_eq!(
            names,
            vec![
                "outer::Foo::method".to_string(),
                "outer::Greet::hi".to_string(),
                "outer::inner::free_fn".to_string(),
                "top_level".to_string(),
            ]
        );
    }

    #[test]
    fn skips_trait_methods_without_a_default_body() {
        let file: syn::File = syn::parse_str(
            r#"
trait Required {
    fn no_default(&self);
}
"#,
        )
        .unwrap();

        let mut names = Vec::new();
        walk_functions(&file, |site| names.push(site.qualified_name));

        assert!(names.is_empty());
    }

    #[test]
    fn declared_module_without_content_does_not_add_a_path_segment() {
        // `mod outer;` (declared, not inline) has no items to walk into here,
        // so this only checks that visiting it doesn't panic or push a path
        // segment that leaks into later sibling items.
        let file: syn::File = syn::parse_str(
            r#"
mod declared_elsewhere;

fn sibling() {}
"#,
        )
        .unwrap();

        let mut names = Vec::new();
        walk_functions(&file, |site| names.push(site.qualified_name));

        assert_eq!(names, vec!["sibling".to_string()]);
    }
}
