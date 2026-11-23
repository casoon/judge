//! Item-level `#[cfg(..)]` conditions for the Fast Tier.
//!
//! Fast Tier rules parse source as written, so every `cfg` branch is
//! analysed as if all of them were compiled together. This module gives a
//! source location the condition it is compiled under, without evaluating
//! anything against the host: the condition is reported as written, so the
//! same tree gives the same output on every platform.
//!
//! - [`CfgExpr`] is a parsed `cfg` predicate. `all`, `any`, `not`,
//!   `feature = ".."`, `target_os`, `target_family`, `target_arch`,
//!   `target_pointer_width`, `unix`, `windows`, `test` and
//!   `debug_assertions` are understood; any other atom stays opaque.
//! - [`CfgIndex`] maps a file and line to the conjunction of every
//!   `#[cfg(..)]` on the items enclosing it. A `#[cfg(..)] mod foo;`
//!   declaration (or one nested in a gated inline module) applies its
//!   condition to the whole module file, and on to the files it declares.
//! - [`mutually_exclusive`] decides conservatively whether two conditions can
//!   never hold in the same build. Only the known exclusive families count:
//!   distinct values of `target_os`, `target_arch` and
//!   `target_pointer_width`; `unix` and `windows`; `X` and `not(X)`. Every
//!   other atom is an independent unknown, so an answer that depends on one
//!   is "not exclusive".
//!
//! Expression-level `cfg!()` and `#[cfg_attr]` are out of scope, and so is
//! feature resolution (that stays with the Deep Tier's
//! `feature-gated-dead-code`). `cfg(test)` code keeps its separate test-code
//! handling (see `crate::functions::attrs_have_cfg_test`); this module only
//! adds the condition as context.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::finding::Finding;
use crate::ingest::Workspace;

/// Evidence key every finding in conditional code carries (`"cfg":
/// "<predicate>"`).
pub const EVIDENCE_KEY: &str = "cfg";

/// A parsed `cfg` predicate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CfgExpr {
    All(Vec<CfgExpr>),
    Any(Vec<CfgExpr>),
    Not(Box<CfgExpr>),
    /// A bare name such as `unix`, `windows`, `test` or `debug_assertions`.
    Name(String),
    /// `key = "value"`, e.g. `feature = "serde"` or `target_os = "linux"`.
    KeyValue(String, String),
    /// A predicate that does not parse as a `cfg` meta item, kept as its
    /// token text.
    Opaque(String),
}

impl fmt::Display for CfgExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn list(f: &mut fmt::Formatter<'_>, name: &str, parts: &[CfgExpr]) -> fmt::Result {
            write!(f, "{name}(")?;
            for (index, part) in parts.iter().enumerate() {
                if index > 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{part}")?;
            }
            f.write_str(")")
        }
        match self {
            Self::All(parts) => list(f, "all", parts),
            Self::Any(parts) => list(f, "any", parts),
            Self::Not(inner) => write!(f, "not({inner})"),
            Self::Name(name) => f.write_str(name),
            Self::KeyValue(key, value) => write!(f, "{key} = {value:?}"),
            Self::Opaque(text) => f.write_str(text),
        }
    }
}

impl CfgExpr {
    /// The conjunction of every `#[cfg(..)]` in `attrs`, or `None` when the
    /// item is unconditional.
    pub fn from_attrs(attrs: &[syn::Attribute]) -> Option<Self> {
        conjunction(
            attrs
                .iter()
                .filter(|attr| attr.path().is_ident("cfg"))
                .map(|attr| match attr.parse_args::<syn::Meta>() {
                    Ok(meta) => Self::from_meta(&meta),
                    Err(_) => Self::Opaque(match &attr.meta {
                        syn::Meta::List(list) => list.tokens.to_string(),
                        other => other.to_token_stream().to_string(),
                    }),
                }),
        )
    }

    fn from_meta(meta: &syn::Meta) -> Self {
        use syn::punctuated::Punctuated;

        let opaque = || Self::Opaque(meta.to_token_stream().to_string());
        match meta {
            syn::Meta::Path(path) => path
                .get_ident()
                .map_or_else(opaque, |ident| Self::Name(ident.to_string())),
            syn::Meta::NameValue(name_value) => {
                let (
                    Some(key),
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(value),
                        ..
                    }),
                ) = (name_value.path.get_ident(), &name_value.value)
                else {
                    return opaque();
                };
                Self::KeyValue(key.to_string(), value.value())
            }
            syn::Meta::List(list) => {
                let Ok(parts) =
                    list.parse_args_with(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
                else {
                    return opaque();
                };
                let parts: Vec<Self> = parts.iter().map(Self::from_meta).collect();
                if list.path.is_ident("all") {
                    Self::All(parts)
                } else if list.path.is_ident("any") {
                    Self::Any(parts)
                } else if list.path.is_ident("not") && parts.len() == 1 {
                    Self::Not(Box::new(parts.into_iter().next().expect("one part")))
                } else {
                    opaque()
                }
            }
        }
    }
}

/// Combines `parts` into one condition: nested `all(..)` are flattened,
/// repeats dropped. `None` for no parts.
fn conjunction(parts: impl IntoIterator<Item = CfgExpr>) -> Option<CfgExpr> {
    fn push(part: CfgExpr, flat: &mut Vec<CfgExpr>) {
        if !flat.contains(&part) {
            flat.push(part);
        }
    }
    let mut flat: Vec<CfgExpr> = Vec::new();
    for part in parts {
        match part {
            CfgExpr::All(inner) if !inner.is_empty() => {
                for nested in inner {
                    push(nested, &mut flat);
                }
            }
            other => push(other, &mut flat),
        }
    }
    match flat.len() {
        0 => None,
        1 => flat.pop(),
        _ => Some(CfgExpr::All(flat)),
    }
}

/// Keys whose values exclude each other: a build has exactly one of each.
const SINGLE_VALUED_KEYS: [&str; 3] = ["target_os", "target_arch", "target_pointer_width"];

/// Upper bound on assignments tried before giving up (and answering "not
/// exclusive"). Real `cfg` predicates stay far below it.
const MAX_ASSIGNMENTS: usize = 1 << 16;

/// The variable an atom reads in [`mutually_exclusive`]'s model.
enum Var {
    /// An independent on/off atom. `unix` and `windows` are the two whose
    /// combination is constrained.
    Flag(String),
    /// One of [`SINGLE_VALUED_KEYS`] compared against a value.
    Single(&'static str, String),
}

fn atom_var(expr: &CfgExpr) -> Var {
    match expr {
        CfgExpr::KeyValue(key, value) if key == "target_family" => match value.as_str() {
            "unix" | "windows" => Var::Flag(value.clone()),
            _ => Var::Flag(expr.to_string()),
        },
        CfgExpr::KeyValue(key, value) => SINGLE_VALUED_KEYS
            .iter()
            .find(|known| *known == key)
            .map_or_else(
                || Var::Flag(expr.to_string()),
                |known| Var::Single(known, value.clone()),
            ),
        _ => Var::Flag(expr.to_string()),
    }
}

#[derive(Default)]
struct Model {
    flags: BTreeSet<String>,
    /// Values mentioned per single-valued key; an extra "none of these"
    /// value is implicit.
    singles: BTreeMap<&'static str, Vec<String>>,
}

impl Model {
    fn collect(&mut self, expr: &CfgExpr) {
        match expr {
            CfgExpr::All(parts) | CfgExpr::Any(parts) => {
                parts.iter().for_each(|part| self.collect(part));
            }
            CfgExpr::Not(inner) => self.collect(inner),
            atom => match atom_var(atom) {
                Var::Flag(name) => {
                    self.flags.insert(name);
                }
                Var::Single(key, value) => {
                    let values = self.singles.entry(key).or_default();
                    if !values.contains(&value) {
                        values.push(value);
                    }
                }
            },
        }
    }
}

struct Assignment<'m> {
    flags: HashMap<&'m str, bool>,
    singles: HashMap<&'static str, Option<&'m str>>,
}

impl Assignment<'_> {
    fn eval(&self, expr: &CfgExpr) -> bool {
        match expr {
            CfgExpr::All(parts) => parts.iter().all(|part| self.eval(part)),
            CfgExpr::Any(parts) => parts.iter().any(|part| self.eval(part)),
            CfgExpr::Not(inner) => !self.eval(inner),
            atom => match atom_var(atom) {
                Var::Flag(name) => self.flags[name.as_str()],
                Var::Single(key, value) => self.singles[key] == Some(value.as_str()),
            },
        }
    }
}

/// Whether some build could satisfy every one of `conditions` at once.
/// Answers `true` whenever the model is too large to enumerate.
fn jointly_satisfiable(conditions: &[&CfgExpr]) -> bool {
    let mut model = Model::default();
    conditions.iter().for_each(|expr| model.collect(expr));
    let flags: Vec<&str> = model.flags.iter().map(String::as_str).collect();
    let singles: Vec<(&'static str, &[String])> = model
        .singles
        .iter()
        .map(|(key, values)| (*key, values.as_slice()))
        .collect();

    let mut total: usize = 1;
    for _ in &flags {
        total = total.saturating_mul(2);
    }
    for (_, values) in &singles {
        total = total.saturating_mul(values.len() + 1);
    }
    if total > MAX_ASSIGNMENTS {
        return true;
    }

    (0..total).any(|mut code| {
        let mut assignment = Assignment {
            flags: HashMap::new(),
            singles: HashMap::new(),
        };
        for flag in &flags {
            assignment.flags.insert(flag, code % 2 == 1);
            code /= 2;
        }
        for (key, values) in &singles {
            let choice = code % (values.len() + 1);
            code /= values.len() + 1;
            assignment
                .singles
                .insert(key, values.get(choice).map(String::as_str));
        }
        let unix = assignment.flags.get("unix").copied().unwrap_or(false);
        let windows = assignment.flags.get("windows").copied().unwrap_or(false);
        !(unix && windows) && conditions.iter().all(|expr| assignment.eval(expr))
    })
}

/// Whether `a` and `b` can never hold in the same build. Conservative: an
/// answer that would depend on an opaque atom's meaning is `false`.
pub fn mutually_exclusive(a: &CfgExpr, b: &CfgExpr) -> bool {
    !jointly_satisfiable(&[a, b])
}

/// A gated item's line range and its own condition.
struct Region {
    start: usize,
    end: usize,
    cfg: CfgExpr,
}

#[derive(Default)]
struct FileCfg {
    /// The file's own `#![cfg(..)]`.
    inner: Option<CfgExpr>,
    /// Gated items in pre-order, so enclosing regions precede nested ones.
    regions: Vec<Region>,
}

/// Every gated item of a set of files plus the condition each module file
/// inherits from its `mod` declaration.
#[derive(Default)]
pub struct CfgIndex {
    files: HashMap<PathBuf, FileCfg>,
    /// Condition a file is compiled under as a whole (its declarations plus
    /// its own `#![cfg(..)]`). Absent for unconditional files.
    file_conditions: HashMap<PathBuf, CfgExpr>,
}

/// Collects [`CfgIndex`] input file by file; [`Self::build`] then resolves
/// the conditions module files inherit.
#[derive(Default)]
pub struct CfgIndexBuilder {
    files: HashMap<PathBuf, FileCfg>,
    /// `(declaring file, module file, condition at the declaration)`.
    declarations: Vec<(PathBuf, PathBuf, Option<CfgExpr>)>,
}

impl CfgIndexBuilder {
    /// Records `ast`, the parsed contents of `path`.
    pub fn add_file(&mut self, path: &Path, ast: &syn::File) {
        let mut collector = RegionCollector {
            file: path,
            active: Vec::new(),
            inline_dirs: Vec::new(),
            regions: Vec::new(),
            declarations: Vec::new(),
        };
        for item in &ast.items {
            collector.visit_item(item);
        }
        self.declarations.extend(
            collector
                .declarations
                .into_iter()
                .map(|(child, cfg)| (path.to_path_buf(), child, cfg)),
        );
        self.files.insert(
            path.to_path_buf(),
            FileCfg {
                inner: CfgExpr::from_attrs(&ast.attrs),
                regions: collector.regions,
            },
        );
    }

    pub fn build(self) -> CfgIndex {
        let mut declared_by: HashMap<&Path, Vec<(&Path, Option<&CfgExpr>)>> = HashMap::new();
        for (parent, child, cfg) in &self.declarations {
            declared_by
                .entry(child.as_path())
                .or_default()
                .push((parent.as_path(), cfg.as_ref()));
        }
        let mut resolved: HashMap<PathBuf, Option<CfgExpr>> = HashMap::new();
        let mut paths: Vec<&PathBuf> = self.files.keys().collect();
        paths.sort();
        for path in paths {
            resolve_file_condition(
                path,
                &self.files,
                &declared_by,
                &mut resolved,
                &mut HashSet::new(),
            );
        }
        CfgIndex {
            file_conditions: resolved
                .into_iter()
                .filter_map(|(path, cfg)| cfg.map(|cfg| (path, cfg)))
                .collect(),
            files: self.files,
        }
    }
}

/// The condition `path` is compiled under as a whole: any of its
/// declarations (each the declaring file's own condition plus the gates at
/// the `mod` item), plus its own `#![cfg(..)]`. A file declared by no
/// parsed file, or by one unconditional declaration, inherits nothing.
fn resolve_file_condition(
    path: &Path,
    files: &HashMap<PathBuf, FileCfg>,
    declared_by: &HashMap<&Path, Vec<(&Path, Option<&CfgExpr>)>>,
    resolved: &mut HashMap<PathBuf, Option<CfgExpr>>,
    visiting: &mut HashSet<PathBuf>,
) -> Option<CfgExpr> {
    if let Some(done) = resolved.get(path) {
        return done.clone();
    }
    if !visiting.insert(path.to_path_buf()) {
        return None;
    }
    let mut inherited: Option<Vec<CfgExpr>> = Some(Vec::new());
    if let Some(declarations) = declared_by.get(path) {
        for (parent, at_declaration) in declarations {
            let parent_cfg = resolve_file_condition(parent, files, declared_by, resolved, visiting);
            match conjunction(parent_cfg.into_iter().chain(at_declaration.cloned())) {
                Some(cfg) => {
                    if let Some(alternatives) = inherited.as_mut() {
                        alternatives.push(cfg);
                    }
                }
                None => inherited = None,
            }
        }
    }
    let inherited = inherited.and_then(|mut alternatives| {
        alternatives.sort_by_key(ToString::to_string);
        alternatives.dedup();
        match alternatives.len() {
            0 => None,
            1 => alternatives.pop(),
            _ => Some(CfgExpr::Any(alternatives)),
        }
    });
    let own = files.get(path).and_then(|file| file.inner.clone());
    let condition = conjunction(inherited.into_iter().chain(own));
    visiting.remove(path);
    resolved.insert(path.to_path_buf(), condition.clone());
    condition
}

impl CfgIndex {
    /// Reads and parses every file in `paths`. Files that cannot be read or
    /// parsed contribute nothing.
    pub fn from_files<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Self {
        let mut builder = CfgIndexBuilder::default();
        for path in paths {
            if let Ok(parsed) = crate::functions::read_and_parse_source(path, |_| (), |_| ()) {
                builder.add_file(path, &parsed.ast);
            }
        }
        builder.build()
    }

    /// The condition line `line` of `file` is compiled under.
    pub fn condition_at(&self, file: &Path, line: usize) -> Option<CfgExpr> {
        self.condition_for_lines(file, line, line)
    }

    /// The condition shared by every line from `start` to `end` of `file`:
    /// the file's own condition plus every gated item enclosing the whole
    /// range, outermost first.
    pub fn condition_for_lines(&self, file: &Path, start: usize, end: usize) -> Option<CfgExpr> {
        let regions = self.files.get(file).map_or(&[][..], |f| &f.regions[..]);
        conjunction(
            self.file_conditions.get(file).cloned().into_iter().chain(
                regions
                    .iter()
                    .filter(|region| region.start <= start && end <= region.end)
                    .map(|region| region.cfg.clone()),
            ),
        )
    }
}

struct RegionCollector<'a> {
    file: &'a Path,
    /// Conditions of the enclosing gated items.
    active: Vec<CfgExpr>,
    /// Enclosing inline `mod name { .. }` blocks, for resolving `mod foo;`.
    inline_dirs: Vec<String>,
    regions: Vec<Region>,
    declarations: Vec<(PathBuf, Option<CfgExpr>)>,
}

impl RegionCollector<'_> {
    fn scoped(
        &mut self,
        attrs: &[syn::Attribute],
        span: proc_macro2::Span,
        visit: impl FnOnce(&mut Self),
    ) {
        let Some(cfg) = CfgExpr::from_attrs(attrs) else {
            visit(self);
            return;
        };
        self.regions.push(Region {
            start: span.start().line,
            end: span.end().line,
            cfg: cfg.clone(),
        });
        self.active.push(cfg);
        visit(self);
        self.active.pop();
    }
}

impl<'ast> Visit<'ast> for RegionCollector<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        self.scoped(item_attrs(item), item.span(), |collector| {
            visit::visit_item(collector, item);
        });
    }

    fn visit_item_mod(&mut self, item_mod: &'ast syn::ItemMod) {
        match &item_mod.content {
            Some((_, items)) => {
                self.inline_dirs.push(item_mod.ident.to_string());
                for item in items {
                    self.visit_item(item);
                }
                self.inline_dirs.pop();
            }
            None => {
                if let Some(child) = crate::rules::module_graph::resolve_mod_item_file(
                    self.file,
                    &self.inline_dirs,
                    item_mod,
                ) {
                    self.declarations
                        .push((child, conjunction(self.active.iter().cloned())));
                }
            }
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs = match item {
            syn::ImplItem::Const(inner) => &inner.attrs[..],
            syn::ImplItem::Fn(inner) => &inner.attrs,
            syn::ImplItem::Type(inner) => &inner.attrs,
            syn::ImplItem::Macro(inner) => &inner.attrs,
            _ => &[],
        };
        self.scoped(attrs, item.span(), |collector| {
            visit::visit_impl_item(collector, item);
        });
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs = match item {
            syn::TraitItem::Const(inner) => &inner.attrs[..],
            syn::TraitItem::Fn(inner) => &inner.attrs,
            syn::TraitItem::Type(inner) => &inner.attrs,
            syn::TraitItem::Macro(inner) => &inner.attrs,
            _ => &[],
        };
        self.scoped(attrs, item.span(), |collector| {
            visit::visit_trait_item(collector, item);
        });
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        let attrs = match item {
            syn::ForeignItem::Fn(inner) => &inner.attrs[..],
            syn::ForeignItem::Static(inner) => &inner.attrs,
            syn::ForeignItem::Type(inner) => &inner.attrs,
            syn::ForeignItem::Macro(inner) => &inner.attrs,
            _ => &[],
        };
        self.scoped(attrs, item.span(), |collector| {
            visit::visit_foreign_item(collector, item);
        });
    }
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(inner) => &inner.attrs,
        syn::Item::Enum(inner) => &inner.attrs,
        syn::Item::ExternCrate(inner) => &inner.attrs,
        syn::Item::Fn(inner) => &inner.attrs,
        syn::Item::ForeignMod(inner) => &inner.attrs,
        syn::Item::Impl(inner) => &inner.attrs,
        syn::Item::Macro(inner) => &inner.attrs,
        syn::Item::Mod(inner) => &inner.attrs,
        syn::Item::Static(inner) => &inner.attrs,
        syn::Item::Struct(inner) => &inner.attrs,
        syn::Item::Trait(inner) => &inner.attrs,
        syn::Item::TraitAlias(inner) => &inner.attrs,
        syn::Item::Type(inner) => &inner.attrs,
        syn::Item::Union(inner) => &inner.attrs,
        syn::Item::Use(inner) => &inner.attrs,
        _ => &[],
    }
}

/// Adds `"cfg": "<predicate>"` to the evidence of every finding located in
/// conditional code. Locations are resolved against `workspace.root`;
/// findings outside the workspace's `.rs` source files, and findings whose
/// evidence already names a condition, are left as they are.
pub fn annotate_findings(findings: &mut [Finding], workspace: &Workspace) {
    let is_rust = |path: &Path| path.extension().is_some_and(|ext| ext == "rs");
    if !findings
        .iter()
        .any(|finding| is_rust(&finding.location.file))
    {
        return;
    }
    let index = CfgIndex::from_files(
        workspace
            .crates
            .iter()
            .flat_map(|krate| krate.source_files.iter().map(|file| file.path.as_path())),
    );
    annotate_with_index(findings, &workspace.root, &index);
}

fn annotate_with_index(findings: &mut [Finding], workspace_root: &Path, index: &CfgIndex) {
    for finding in findings {
        if finding.cfg().is_some() {
            continue;
        }
        let path = workspace_root.join(&finding.location.file);
        if let Some(cfg) = index.condition_at(&path, finding.location.line.get()) {
            set_evidence(finding, &cfg);
        }
    }
}

/// ` [cfg(<predicate>)]` for a finding in conditional code, empty otherwise —
/// the suffix human-readable renderings append to a finding's item.
pub(crate) fn display_suffix(finding: &Finding) -> String {
    finding
        .cfg()
        .map(|cfg| format!(" [cfg({cfg})]"))
        .unwrap_or_default()
}

/// Writes `cfg` into `finding`'s evidence object, creating it if needed.
pub(crate) fn set_evidence(finding: &mut Finding, cfg: &CfgExpr) {
    let value = serde_json::Value::String(cfg.to_string());
    match &mut finding.evidence {
        Some(serde_json::Value::Object(map)) => {
            map.insert(EVIDENCE_KEY.to_string(), value);
        }
        Some(_) => {}
        None => {
            finding.evidence = Some(serde_json::json!({ EVIDENCE_KEY: value }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn parse(predicate: &str) -> CfgExpr {
        let file: syn::File = syn::parse_str(&format!("#[cfg({predicate})] fn f() {{}}")).unwrap();
        let syn::Item::Fn(item) = &file.items[0] else {
            unreachable!()
        };
        CfgExpr::from_attrs(&item.attrs).unwrap()
    }

    fn exclusive(a: &str, b: &str) -> bool {
        mutually_exclusive(&parse(a), &parse(b))
    }

    #[test]
    fn predicates_render_as_written() {
        for predicate in [
            "unix",
            "feature = \"serde\"",
            "not(feature = \"a\")",
            "all(unix, target_pointer_width = \"64\")",
            "any(target_os = \"linux\", target_os = \"macos\")",
            "debug_assertions",
        ] {
            assert_eq!(parse(predicate).to_string(), predicate);
        }
    }

    #[test]
    fn unknown_atoms_stay_opaque() {
        assert_eq!(parse("foo::bar").to_string(), "foo :: bar");
        assert_eq!(parse("weird(1, 2)").to_string(), "weird (1 , 2)");
        assert!(matches!(parse("weird(1, 2)"), CfgExpr::Opaque(_)));
    }

    #[test]
    fn known_exclusive_families_exclude_each_other() {
        assert!(exclusive("unix", "windows"));
        assert!(exclusive("target_os = \"linux\"", "target_os = \"macos\""));
        assert!(exclusive(
            "target_arch = \"x86_64\"",
            "target_arch = \"aarch64\""
        ));
        assert!(exclusive(
            "target_pointer_width = \"32\"",
            "target_pointer_width = \"64\""
        ));
        assert!(exclusive("feature = \"a\"", "not(feature = \"a\")"));
        assert!(exclusive("test", "not(test)"));
        assert!(exclusive("target_family = \"unix\"", "windows"));
        assert!(exclusive("all(unix, feature = \"a\")", "windows"));
        assert!(exclusive(
            "any(target_os = \"linux\", target_os = \"macos\")",
            "target_os = \"windows\""
        ));
    }

    #[test]
    fn everything_else_is_not_exclusive() {
        assert!(!exclusive("feature = \"a\"", "feature = \"b\""));
        assert!(!exclusive("unix", "unix"));
        assert!(!exclusive("unix", "target_os = \"linux\""));
        assert!(!exclusive("target_env = \"gnu\"", "target_env = \"msvc\""));
        assert!(!exclusive("foo", "bar"));
        assert!(!exclusive("any(unix, feature = \"a\")", "windows"));
        assert!(!exclusive("target_family = \"wasm\"", "unix"));
    }

    #[test]
    fn opaque_atoms_still_exclude_their_negation() {
        assert!(exclusive("foo", "not(foo)"));
    }

    #[test]
    fn annotation_adds_the_condition_to_gated_findings_only() {
        use crate::finding::{EvidenceClass, Location, OneBasedLine, Origin, Severity};

        let dir = TempDir::new("cfg-annotate");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "fn plain() {}\n#[cfg(windows)]\nimpl Foo {\n    #[cfg(feature = \"x\")]\n    fn gated() {}\n}\n",
        )
        .unwrap();
        let at = |line: usize, evidence: Option<serde_json::Value>| {
            Finding::new(
                format!("rule:{line}"),
                "rule",
                Severity::Warn,
                Location {
                    file: PathBuf::from("lib.rs"),
                    line: OneBasedLine::new(line).unwrap(),
                    item_path: "item".to_string(),
                },
                EvidenceClass::DerivedFact,
                Origin::Code,
                evidence,
            )
        };
        let mut findings = vec![
            at(1, None),
            at(3, None),
            at(5, Some(serde_json::json!({ "count": 1 }))),
        ];
        let index = CfgIndex::from_files([file.as_path()]);
        annotate_with_index(&mut findings, &dir, &index);

        assert_eq!(findings[0].evidence, None);
        assert_eq!(
            findings[1].evidence,
            Some(serde_json::json!({ "cfg": "windows" }))
        );
        assert_eq!(
            findings[2].evidence,
            Some(serde_json::json!({ "count": 1, "cfg": "all(windows, feature = \"x\")" }))
        );
    }

    #[test]
    fn conditions_nest_and_reach_declared_module_files() {
        let dir = TempDir::new("cfg-index");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let lib = dir.join("src/lib.rs");
        let platform = dir.join("src/platform.rs");
        let nested = dir.join("src/platform/nested.rs");
        std::fs::create_dir_all(dir.join("src/platform")).unwrap();
        std::fs::write(
            &lib,
            "#[cfg(unix)]\nmod platform;\n\n#[cfg(feature = \"a\")]\nmod gated {\n    fn inner() {}\n}\nfn free() {}\n",
        )
        .unwrap();
        std::fs::write(
            &platform,
            "#[cfg(target_os = \"linux\")]\nmod nested;\nfn plain() {}\n",
        )
        .unwrap();
        std::fs::write(&nested, "fn deep() {}\n").unwrap();

        let index = CfgIndex::from_files([lib.as_path(), platform.as_path(), nested.as_path()]);
        assert_eq!(
            index.condition_at(&lib, 6).map(|c| c.to_string()),
            Some("feature = \"a\"".to_string())
        );
        assert_eq!(index.condition_at(&lib, 8), None);
        assert_eq!(
            index.condition_at(&platform, 3).map(|c| c.to_string()),
            Some("unix".to_string())
        );
        assert_eq!(
            index.condition_at(&nested, 1).map(|c| c.to_string()),
            Some("all(unix, target_os = \"linux\")".to_string())
        );
    }
}
