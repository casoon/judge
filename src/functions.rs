//! Shared `syn` traversal: walks a parsed file and yields every function-like
//! item with a body (`fn`, impl method, default trait method), tracking the
//! enclosing `mod`/`impl`/`trait` path so callers get a qualified name.
//!
//! Used by both [`crate::complexity`] and [`crate::duplication`] so the two
//! detectors agree on what counts as "a function" without duplicating the
//! traversal logic.

use proc_macro2::Span;
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, ImplItemFn, ItemFn, ItemImpl, ItemMod, ItemTrait, TraitItemFn, Type};

/// One function-like item discovered while walking a file.
pub struct FunctionSite<'ast> {
    pub qualified_name: String,
    pub span: Span,
    pub block: &'ast Block,
    /// Number of parameters in the function's signature (`self` included),
    /// i.e. `sig.inputs.len()`.
    pub arg_count: usize,
    /// The function's full signature — return type, generics, `where`
    /// clause, and everything else `arg_count` doesn't already summarize.
    /// Used by [`crate::complexity`] for signature-shape metrics (return-type
    /// nesting depth, generic/lifetime parameter counts, trait bound counts).
    pub sig: &'ast syn::Signature,
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
    /// Whether this function is only compiled for tests. This is true for a
    /// `#[test]` function and for every function nested in a `#[cfg(test)]`
    /// item such as an inline module, impl block, or trait (including helpers
    /// that do not carry `#[test]` themselves).
    pub is_test_context: bool,
}

/// Reads and parses one Rust source file while leaving each analyzer in
/// control of its own error type. The returned source is kept alongside the
/// AST because several callers also inspect comments or source spans.
pub(crate) fn read_and_parse_source<E>(
    path: &Path,
    io_error: impl FnOnce(std::io::Error) -> E,
    parse_error: impl FnOnce(syn::Error) -> E,
) -> Result<(String, syn::File), E> {
    let source = std::fs::read_to_string(path).map_err(io_error)?;
    let ast = syn::parse_file(&source).map_err(parse_error)?;
    Ok((source, ast))
}

/// Visits every `fn`, impl method, and default trait-method body in `file`,
/// invoking `on_function` for each with its qualified name, span, and body.
pub fn walk_functions<'ast>(file: &'ast syn::File, on_function: impl FnMut(FunctionSite<'ast>)) {
    let mut walker = Walker {
        path: Vec::new(),
        in_trait_impl: Vec::new(),
        test_context: Vec::new(),
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
    /// Scoped test-only context for inline modules and functions. Keeping it
    /// as a stack makes nested function items inherit their enclosing test
    /// context without relying on naming conventions.
    test_context: Vec<bool>,
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

    fn current_test_context(&self) -> bool {
        self.test_context.last().copied().unwrap_or(false)
    }
}

fn has_test_cfg(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Ident>()
                .is_ok_and(|condition| condition == "test")
    })
}

fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("test"))
}

impl<'ast, F> Walker<F>
where
    F: FnMut(FunctionSite<'ast>),
{
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        name: &str,
        spanned: &impl Spanned,
        block: &'ast Block,
        arg_count: usize,
        ident_span: Span,
        vis: Option<&'ast syn::Visibility>,
        attrs: &'ast [syn::Attribute],
        in_trait_impl: bool,
        is_test_context: bool,
        sig: &'ast syn::Signature,
    ) {
        let qualified_name = self.qualified_name(name);
        (self.on_function)(FunctionSite {
            qualified_name,
            span: spanned.span(),
            block,
            arg_count,
            ident_span,
            vis,
            attrs,
            in_trait_impl,
            is_test_context,
            sig,
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
            let is_test_context = self.current_test_context() || has_test_cfg(&node.attrs);
            self.path.push(node.ident.to_string());
            self.test_context.push(is_test_context);
            visit::visit_item_mod(self, node);
            self.test_context.pop();
            self.path.pop();
        } else {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let is_test_context = self.current_test_context() || has_test_cfg(&node.attrs);
        self.path.push(type_name(&node.self_ty));
        self.in_trait_impl.push(node.trait_.is_some());
        self.test_context.push(is_test_context);
        visit::visit_item_impl(self, node);
        self.test_context.pop();
        self.in_trait_impl.pop();
        self.path.pop();
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        let is_test_context = self.current_test_context() || has_test_cfg(&node.attrs);
        self.path.push(node.ident.to_string());
        self.test_context.push(is_test_context);
        visit::visit_item_trait(self, node);
        self.test_context.pop();
        self.path.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let is_test_context =
            self.current_test_context() || has_test_cfg(&node.attrs) || has_test_attr(&node.attrs);
        self.emit(
            &node.sig.ident.to_string(),
            node,
            &node.block,
            node.sig.inputs.len(),
            node.sig.ident.span(),
            Some(&node.vis),
            &node.attrs,
            false,
            is_test_context,
            &node.sig,
        );
        self.test_context.push(is_test_context);
        visit::visit_item_fn(self, node);
        self.test_context.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let in_trait_impl = self.current_in_trait_impl();
        let is_test_context =
            self.current_test_context() || has_test_cfg(&node.attrs) || has_test_attr(&node.attrs);
        self.emit(
            &node.sig.ident.to_string(),
            node,
            &node.block,
            node.sig.inputs.len(),
            node.sig.ident.span(),
            Some(&node.vis),
            &node.attrs,
            in_trait_impl,
            is_test_context,
            &node.sig,
        );
        self.test_context.push(is_test_context);
        visit::visit_impl_item_fn(self, node);
        self.test_context.pop();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        let is_test_context =
            self.current_test_context() || has_test_cfg(&node.attrs) || has_test_attr(&node.attrs);
        if let Some(block) = &node.default {
            self.emit(
                &node.sig.ident.to_string(),
                node,
                block,
                node.sig.inputs.len(),
                node.sig.ident.span(),
                None,
                &node.attrs,
                false,
                is_test_context,
                &node.sig,
            );
        }
        self.test_context.push(is_test_context);
        visit::visit_trait_item_fn(self, node);
        self.test_context.pop();
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
    fn arg_count_reflects_the_signature_parameter_count() {
        let file: syn::File = syn::parse_str(
            r#"
fn no_args() {}

fn several_args(a: i32, b: i32, c: i32) {}
"#,
        )
        .unwrap();

        let mut counts = Vec::new();
        walk_functions(&file, |site| {
            counts.push((site.qualified_name, site.arg_count))
        });

        assert_eq!(
            counts,
            vec![("no_args".to_string(), 0), ("several_args".to_string(), 3),]
        );
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

    #[test]
    fn tracks_test_context_for_test_modules_and_helpers() {
        let file: syn::File = syn::parse_str(
            r#"
fn production() {}

#[cfg(test)]
mod tests {
    #[test]
    fn verifies_behavior() {}

    fn helper() {}
}

struct Fixture;

#[cfg(test)]
impl Fixture {
    fn impl_helper() {}
}
"#,
        )
        .unwrap();

        let mut contexts = Vec::new();
        walk_functions(&file, |site| {
            contexts.push((site.qualified_name, site.is_test_context))
        });

        assert_eq!(
            contexts,
            vec![
                ("production".to_string(), false),
                ("tests::verifies_behavior".to_string(), true),
                ("tests::helper".to_string(), true),
                ("Fixture::impl_helper".to_string(), true),
            ]
        );
    }
}
