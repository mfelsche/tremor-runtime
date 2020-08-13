// Copyright 2018-2020, Wayfair GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub(crate) mod base_expr;
/// Query AST
pub mod query;
pub(crate) mod raw;
mod support;
mod upable;
use crate::errors::{error_generic, error_no_consts, error_no_locals, ErrorKind, Result};
use crate::impl_expr2;
use crate::interpreter::{exec_binary, exec_unary, AggrType, Cont, Env, ExecOpts, LocalStack};
pub use crate::lexer::CompilationUnit;
use crate::pos::{Location, Range};
use crate::registry::FResult;
use crate::registry::{
    Aggr as AggrRegistry, CustomFn, Registry, TremorAggrFnWrapper, TremorFnWrapper,
};
use crate::script::Return;
use crate::stry;
use crate::{tilde::Extractor, EventContext};
pub use base_expr::BaseExpr;
use halfbrown::HashMap;
pub use query::*;
use raw::{reduce2, NO_AGGRS, NO_CONSTS};
use serde::Serialize;
use simd_json::{borrowed, prelude::*, BorrowedValue as Value, KnownKey};
use std::borrow::{Borrow, Cow};
use std::mem;
use upable::Upable;

#[derive(Default, Clone, Serialize, Debug, PartialEq)]
struct NodeMeta {
    start: Location,
    end: Location,
    name: Option<String>,
    /// Id of current compilation unit part
    cu: usize,
    terminal: bool,
}

impl From<(Location, Location, usize)> for NodeMeta {
    fn from((start, end, cu): (Location, Location, usize)) -> Self {
        Self {
            start,
            end,
            name: None,
            cu,
            terminal: false,
        }
    }
}
/// Information about node metadata
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct NodeMetas {
    nodes: Vec<NodeMeta>,
    #[serde(skip)]
    pub(crate) cus: Vec<CompilationUnit>,
}

impl<'script> NodeMetas {
    /// Initializes meta noes with a given set of
    pub fn new(cus: Vec<CompilationUnit>) -> Self {
        Self {
            nodes: Vec::new(),
            cus,
        }
    }
    pub(crate) fn add_meta(&mut self, mut start: Location, mut end: Location, cu: usize) -> usize {
        let mid = self.nodes.len();
        start.set_cu(cu);
        end.set_cu(cu);
        self.nodes.push((start, end, cu).into());
        mid
    }
    pub(crate) fn add_meta_w_name<S>(
        &mut self,
        mut start: Location,
        mut end: Location,
        name: &S,
        cu: usize,
    ) -> usize
    where
        S: ToString,
    {
        start.set_cu(cu);
        end.set_cu(cu);
        let mid = self.nodes.len();
        self.nodes.push(NodeMeta {
            start,
            end,
            cu,
            name: Some(name.to_string()),
            terminal: false,
        });
        mid
    }

    pub(crate) fn start(&self, idx: usize) -> Option<Location> {
        self.nodes.get(idx).map(|v| v.start)
    }
    pub(crate) fn end(&self, idx: usize) -> Option<Location> {
        self.nodes.get(idx).map(|v| v.end)
    }
    pub(crate) fn name(&self, idx: usize) -> Option<&String> {
        self.nodes.get(idx).map(|v| v.name.as_ref()).and_then(|v| v)
    }
    /// Returns the CU for a meta node
    pub fn cu(&self, idx: usize) -> Option<&str> {
        self.nodes
            .get(idx)
            .and_then(|e| self.cus.get(e.cu))
            .and_then(CompilationUnit::to_str)
    }

    pub(crate) fn name_dflt(&self, idx: usize) -> String {
        self.name(idx)
            .cloned()
            .unwrap_or_else(|| String::from("<UNKNOWN>"))
    }
}

#[derive(Serialize, Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// A warning generated while lexing or parsing
pub struct Warning {
    /// Outer span of the warning
    pub outer: Range,
    /// Inner span of thw warning
    pub inner: Range,
    /// Warning message
    pub msg: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Function<'script> {
    is_const: bool,
    argc: usize,
    name: Cow<'script, str>,
}

/// Documentaiton from constant
#[derive(Debug, Clone, PartialEq)]
pub struct ConstDoc<'script> {
    /// Constant name
    pub name: Cow<'script, str>,
    /// Constant documentation
    pub doc: Option<String>,
    /// Constant value type
    pub value_type: ValueType,
}

impl<'script> ToString for ConstDoc<'script> {
    fn to_string(&self) -> String {
        format!(
            r#"
### {}

*type*: {:?}

{}
        "#,
            self.name,
            self.value_type,
            &self.doc.clone().unwrap_or_default()
        )
    }
}

/// Documentaiton from function
#[derive(Debug, Clone, PartialEq)]
pub struct FnDoc<'script> {
    /// Function name
    pub name: Cow<'script, str>,
    /// Function arguments
    pub args: Vec<Cow<'script, str>>,
    /// Function documentation
    pub doc: Option<String>,
    /// Whether the function is open or not
    // TODO clarify what open exactly is
    pub open: bool,
}

/// Documentaiton from a module
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModDoc<'script> {
    /// Module name
    pub name: Cow<'script, str>,
    /// Module documentation
    pub doc: Option<String>,
}

impl<'script> ModDoc<'script> {
    /// Prints the module documentation
    pub fn print_with_name(&self, name: &str) -> String {
        format!(
            r#"
# {}


{}
        "#,
            name,
            &self.doc.clone().unwrap_or_default()
        )
    }
}

impl<'script> ToString for FnDoc<'script> {
    fn to_string(&self) -> String {
        format!(
            r#"
### {}({})

{}
        "#,
            self.name,
            self.args.join(", "),
            self.doc.clone().unwrap_or_default()
        )
    }
}

/// Documentaiton from a module
#[derive(Debug, Clone, PartialEq)]
pub struct Docs<'script> {
    /// Constatns
    pub consts: Vec<ConstDoc<'script>>,
    /// Functions
    pub fns: Vec<FnDoc<'script>>,
    /// Module level documentation
    pub module: Option<ModDoc<'script>>,
}

impl<'script> Default for Docs<'script> {
    fn default() -> Self {
        Self {
            consts: Vec::new(),
            fns: Vec::new(),
            module: None,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Helper<'script, 'registry>
where
    'script: 'registry,
{
    reg: &'registry Registry,
    aggr_reg: &'registry AggrRegistry,
    can_emit: bool,
    is_in_aggr: bool,
    windows: HashMap<String, WindowDecl<'script>>,
    scripts: HashMap<String, ScriptDecl<'script>>,
    operators: HashMap<String, OperatorDecl<'script>>,
    aggregates: Vec<InvokeAggrFn<'script>>,
    // TODO: Users of the `warnings` field might be helped if `warnings` were a Set. Right now,
    // some places (twice in query/raw.rs) do `append + sort + dedup`. With, e.g., a `BTreeSet`,
    // this could be achieved in a cleaner and faster way, and `Warning` already implements `Ord`
    // anyway.
    warnings: Vec<Warning>,
    shadowed_vars: Vec<String>,
    func_vec: Vec<CustomFn<'script>>,
    pub locals: HashMap<String, usize>,
    pub functions: HashMap<Vec<String>, usize>,
    pub consts: HashMap<Vec<String>, usize>,
    pub streams: HashMap<Vec<String>, usize>,
    pub meta: NodeMetas,
    pub const_values: Vec<Value<'script>>,
    docs: Docs<'script>,
    module: Vec<String>,
    possible_leaf: bool,
    fn_argc: usize,
    is_open: bool,
    file_offset: Location,
    cu: usize,
}

impl<'script, 'registry> Helper<'script, 'registry>
where
    'script: 'registry,
{
    pub fn init_consts(&mut self) {
        self.consts
            .insert(vec!["window".to_owned()], WINDOW_CONST_ID);
        self.consts.insert(vec!["group".to_owned()], GROUP_CONST_ID);
        self.consts.insert(vec!["args".to_owned()], ARGS_CONST_ID);

        // TODO: Document why three `null` values are put in the constants vector.
        self.const_values = vec![Value::null(); 3];
    }
    fn add_const_doc(
        &mut self,
        name: Cow<'script, str>,
        doc: Option<Vec<Cow<'script, str>>>,
        value_type: ValueType,
    ) {
        let doc = doc.map(|d| d.iter().map(|l| l.trim()).collect::<Vec<_>>().join("\n"));
        self.docs.consts.push(ConstDoc {
            name,
            doc,
            value_type,
        })
    }
    pub fn add_meta(&mut self, start: Location, end: Location) -> usize {
        self.meta
            .add_meta(start - self.file_offset, end - self.file_offset, self.cu)
    }
    pub fn add_meta_w_name<S>(&mut self, start: Location, end: Location, name: &S) -> usize
    where
        S: ToString,
    {
        self.meta.add_meta_w_name(
            start - self.file_offset,
            end - self.file_offset,
            name,
            self.cu,
        )
    }
    pub fn has_locals(&self) -> bool {
        self.locals
            .iter()
            .any(|(n, _)| !n.starts_with(" __SHADOW "))
    }
    pub fn swap(
        &mut self,
        aggregates: &mut Vec<InvokeAggrFn<'script>>,
        consts: &mut HashMap<Vec<String>, usize>,
        locals: &mut HashMap<String, usize>,
    ) {
        mem::swap(&mut self.aggregates, aggregates);
        mem::swap(&mut self.consts, consts);
        mem::swap(&mut self.locals, locals);
    }

    pub fn swap2(
        &mut self,
        aggregates: &mut Vec<InvokeAggrFn<'script>>,
        //consts: &mut HashMap<Vec<String>, usize>,
        locals: &mut HashMap<String, usize>,
    ) {
        mem::swap(&mut self.aggregates, aggregates);
        //mem::swap(&mut self.consts, consts);
        mem::swap(&mut self.locals, locals);
    }

    pub fn new(
        reg: &'registry Registry,
        aggr_reg: &'registry AggrRegistry,
        cus: Vec<crate::lexer::CompilationUnit>,
    ) -> Self {
        Helper {
            reg,
            aggr_reg,
            can_emit: true,
            is_in_aggr: false,
            windows: HashMap::new(),
            scripts: HashMap::new(),
            operators: HashMap::new(),
            aggregates: Vec::new(),
            warnings: Vec::new(),
            locals: HashMap::new(),
            consts: HashMap::new(),
            streams: HashMap::new(),
            functions: HashMap::new(),
            func_vec: Vec::new(),
            shadowed_vars: Vec::new(),
            meta: NodeMetas::new(cus),
            docs: Docs::default(),
            module: Vec::new(),
            possible_leaf: false,
            fn_argc: 0,
            is_open: false,
            const_values: Vec::new(),
            file_offset: Location::default(),
            cu: 0,
        }
    }

    #[allow(dead_code)]
    fn register_fun(&mut self, f: CustomFn<'script>) -> Result<usize> {
        let i = self.func_vec.len();
        let mut mf = self.module.clone();
        mf.push(f.name.clone().to_string());

        if self.functions.insert(mf, i).is_none() {
            self.func_vec.push(f);
            Ok(i)
        } else {
            Err(format!("function {} already defined.", f.name).into())
        }
    }

    fn register_shadow_var(&mut self, id: &str) -> usize {
        let r = self.reserve_shadow();
        self.shadowed_vars.push(id.to_string());
        r
    }

    fn end_shadow_var(&mut self) {
        self.shadowed_vars.pop();
    }

    fn find_shadow_var(&self, id: &str) -> Option<String> {
        let mut r = None;
        for (i, s) in self.shadowed_vars.iter().enumerate() {
            if s == id {
                //FIXME: make sure we never overwrite this,
                r = Some(shadow_name(i))
            }
        }
        r
    }

    fn reserve_shadow(&mut self) -> usize {
        self.var_id(&shadow_name(self.shadowed_vars.len()))
    }

    fn reserve_2_shadow(&mut self) -> (usize, usize) {
        let l = self.shadowed_vars.len();
        let n1 = shadow_name(l);
        let n2 = shadow_name(l + 1);
        (self.var_id(&n1), self.var_id(&n2))
    }

    fn var_id(&mut self, id: &str) -> usize {
        let id = if let Some(shadow) = self.find_shadow_var(id) {
            shadow
        } else {
            id.to_string()
        };

        if let Some(idx) = self.locals.get(id.as_str()) {
            *idx
        } else {
            self.locals.insert(id.to_string(), self.locals.len());
            self.locals.len() - 1
        }
    }
    fn is_const(&self, id: &[String]) -> Option<&usize> {
        self.consts.get(id)
    }
}

/// A tremor script instance
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Script<'script> {
    /// Import definitions
    imports: Imports<'script>,
    /// Expressions of the script
    pub(crate) exprs: Exprs<'script>,
    /// Constants defined in this script
    pub consts: Vec<Value<'script>>,
    aggregates: Vec<InvokeAggrFn<'script>>,
    windows: HashMap<String, WindowDecl<'script>>,
    functions: Vec<CustomFn<'script>>,
    locals: usize,
    pub(crate) node_meta: NodeMetas,
    #[serde(skip)]
    /// Documentaiton from the script
    pub docs: Docs<'script>,
}

impl<'input, 'run, 'script, 'event> Script<'script>
where
    'input: 'script,
    'script: 'event,
    'event: 'run,
{
    /// Runs the script and evaluates to a resulting event
    pub fn run(
        &'script self,
        context: &'run crate::EventContext,
        aggr: AggrType,
        event: &'run mut Value<'event>,
        state: &'run mut Value<'static>,
        meta: &'run mut Value<'event>,
    ) -> Result<Return<'event>> {
        let mut local = LocalStack::with_size(self.locals);

        let mut exprs = self.exprs.iter().peekable();
        let opts = ExecOpts {
            result_needed: true,
            aggr,
        };

        let env = Env {
            context,
            consts: &self.consts,
            aggrs: &self.aggregates,
            meta: &self.node_meta,
            recursion_limit: crate::recursion_limit(),
        };

        while let Some(expr) = exprs.next() {
            if exprs.peek().is_none() {
                match stry!(expr.run(opts.with_result(), &env, event, state, meta, &mut local)) {
                    Cont::Drop => return Ok(Return::Drop),
                    Cont::Emit(value, port) => return Ok(Return::Emit { value, port }),
                    Cont::EmitEvent(port) => {
                        return Ok(Return::EmitEvent { port });
                    }
                    Cont::Cont(v) => {
                        return Ok(Return::Emit {
                            value: v.into_owned(),
                            port: None,
                        })
                    }
                }
            } else {
                match stry!(expr.run(opts.without_result(), &env, event, state, meta, &mut local)) {
                    Cont::Drop => return Ok(Return::Drop),
                    Cont::Emit(value, port) => return Ok(Return::Emit { value, port }),
                    Cont::EmitEvent(port) => {
                        return Ok(Return::EmitEvent { port });
                    }
                    Cont::Cont(_v) => (),
                }
            }
        }

        // We know that we never get here, sadly rust doesn't

        Ok(Return::Emit {
            value: Value::null(),
            port: None,
        })
    }
}

/// A lexical compilation unit
#[derive(Debug, PartialEq, Serialize, Clone)]
pub enum LexicalUnit<'script> {
    /// Import declaration with no alias
    NakedImportDecl(Vec<raw::IdentRaw<'script>>),
    /// Import declaration with an alias
    AliasedImportDecl(Vec<raw::IdentRaw<'script>>, raw::IdentRaw<'script>),
    /// Line directive with embedded "<string> <num> ;"
    LineDirective(Cow<'script, str>),
}
// impl_expr2!(Ident);

/// An ident
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct Ident<'script> {
    pub(crate) mid: usize,
    /// the text of the ident
    pub id: Cow<'script, str>,
}
impl_expr2!(Ident);

impl<'script> std::fmt::Display for Ident<'script> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl<'script> From<&'script str> for Ident<'script> {
    fn from(id: &'script str) -> Self {
        Self {
            mid: 0,
            id: id.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Field<'script> {
    pub mid: usize,
    pub name: ImutExprInt<'script>,
    pub value: ImutExprInt<'script>,
}
impl_expr2!(Field);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Record<'script> {
    pub mid: usize,
    pub fields: Fields<'script>,
}
impl_expr2!(Record);
impl<'script> Record<'script> {
    fn try_reduce(self, helper: &Helper<'script, '_>) -> Result<ImutExprInt<'script>> {
        if self
            .fields
            .iter()
            .all(|f| is_lit(&f.name) && is_lit(&f.value))
        {
            let obj: Result<borrowed::Object> = self
                .fields
                .into_iter()
                .map(|f| {
                    reduce2(f.name.clone(), &helper).and_then(|n| {
                        // ALLOW: The grammer guarantees the key of a record is always a string
                        let n = n.as_str().unwrap_or_else(|| unreachable!());
                        reduce2(f.value, &helper).map(|v| (n.to_owned().into(), v))
                    })
                })
                .collect();
            Ok(ImutExprInt::Literal(Literal {
                mid: self.mid,
                value: Value::from(obj?),
            }))
        } else {
            Ok(ImutExprInt::Record(self))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct List<'script> {
    pub mid: usize,
    pub exprs: ImutExprs<'script>,
}
impl_expr2!(List);

impl<'script> List<'script> {
    fn try_reduce(self, helper: &Helper<'script, '_>) -> Result<ImutExprInt<'script>> {
        if self.exprs.iter().map(|v| &v.0).all(is_lit) {
            let elements: Result<Vec<Value>> = self
                .exprs
                .into_iter()
                .map(|v| reduce2(v.0, &helper))
                .collect();
            Ok(ImutExprInt::Literal(Literal {
                mid: self.mid,
                value: Value::from(elements?),
            }))
        } else {
            Ok(ImutExprInt::List(self))
        }
    }
}

/// A Literal
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Literal<'script> {
    /// MetadataId of this node
    pub mid: usize,
    /// Literal Value
    pub value: Value<'script>,
}
impl_expr2!(Literal);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct FnDecl<'script> {
    pub mid: usize,
    pub name: Ident<'script>,
    pub args: Vec<Ident<'script>>,
    pub body: Exprs<'script>,
    pub locals: usize,
    pub open: bool,
    pub inline: bool,
}
impl_expr2!(FnDecl);

fn path_eq<'script>(path: &Path<'script>, expr: &ImutExprInt<'script>) -> bool {
    let path_expr: ImutExprInt = ImutExprInt::Path(path.clone());

    let target_expr = match expr.clone() {
        ImutExprInt::Local {
            //id,
            idx,
            mid,
            is_const,
        } => ImutExprInt::Path(Path::Local(LocalPath {
            //id,
            segments: vec![],
            idx,
            mid,
            is_const,
        })),
        other => other,
    };
    path_expr == target_expr
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) enum Expr<'script> {
    Match(Box<Match<'script>>),
    PatchInPlace(Box<Patch<'script>>),
    MergeInPlace(Box<Merge<'script>>),
    Assign {
        mid: usize,
        path: Path<'script>,
        expr: Box<Expr<'script>>,
    },
    // Moves
    AssignMoveLocal {
        mid: usize,
        path: Path<'script>,
        idx: usize,
    },
    Comprehension(Box<Comprehension<'script>>),
    Drop {
        mid: usize,
    },
    Emit(Box<EmitExpr<'script>>),
    Imut(ImutExprInt<'script>),
}

impl<'script> From<ImutExprInt<'script>> for Expr<'script> {
    fn from(imut: ImutExprInt<'script>) -> Expr<'script> {
        Expr::Imut(imut)
    }
}

/// An immutable expression
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ImutExpr<'script>(pub(crate) ImutExprInt<'script>);

impl<'script> From<Literal<'script>> for ImutExpr<'script> {
    fn from(lit: Literal<'script>) -> Self {
        Self(ImutExprInt::Literal(lit))
    }
}

impl<'script> BaseExpr for ImutExpr<'script> {
    fn mid(&self) -> usize {
        self.0.mid()
    }

    fn s(&self, meta: &NodeMetas) -> Location {
        self.0.s(meta)
    }

    fn e(&self, meta: &NodeMetas) -> Location {
        self.0.e(meta)
    }

    fn extent(&self, meta: &NodeMetas) -> Range {
        self.0.extent(meta)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) enum ImutExprInt<'script> {
    Record(Record<'script>),
    List(List<'script>),
    Binary(Box<BinExpr<'script>>),
    Unary(Box<UnaryExpr<'script>>),
    Patch(Box<Patch<'script>>),
    Match(Box<ImutMatch<'script>>),
    Comprehension(Box<ImutComprehension<'script>>),
    Merge(Box<Merge<'script>>),
    Path(Path<'script>),
    Local {
        //id: Cow<'script, str>,
        idx: usize,
        mid: usize,
        is_const: bool,
    },
    Literal(Literal<'script>),
    Present {
        path: Path<'script>,
        mid: usize,
    },
    Invoke1(Invoke<'script>),
    Invoke2(Invoke<'script>),
    Invoke3(Invoke<'script>),
    Invoke(Invoke<'script>),
    InvokeAggr(InvokeAggr),
    Recur(Recur<'script>),
}

fn is_lit<'script>(e: &ImutExprInt<'script>) -> bool {
    match e {
        ImutExprInt::Literal(_) => true,
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct EmitExpr<'script> {
    pub mid: usize,
    pub expr: ImutExprInt<'script>,
    pub port: Option<ImutExprInt<'script>>,
}
impl_expr2!(EmitExpr);

#[derive(Clone, Serialize)]
pub(crate) struct Invoke<'script> {
    pub mid: usize,
    pub module: Vec<String>,
    pub fun: String,
    #[serde(skip)]
    pub invocable: Invocable<'script>,
    pub args: ImutExprs<'script>,
}
impl_expr2!(Invoke);

impl<'script> Invoke<'script> {
    fn inline(self) -> Result<ImutExprInt<'script>> {
        self.invocable.inline(self.args, self.mid)
    }
    fn can_inline(&self) -> bool {
        self.invocable.can_inline()
    }

    fn try_reduce(self, helper: &Helper<'script, '_>) -> Result<ImutExprInt<'script>> {
        if self.invocable.is_const() && self.args.iter().all(|f| is_lit(&f.0)) {
            let ex = self.extent(&helper.meta);
            let args: Result<Vec<Value<'script>>> = self
                .args
                .into_iter()
                .map(|v| reduce2(v.0, &helper))
                .collect();
            let args = args?;
            // Construct a view into `args`, since `invoke` expects a slice of references.
            let args2: Vec<&Value<'script>> = args.iter().collect();
            let env = Env {
                context: &EventContext::default(),
                consts: &NO_CONSTS,
                aggrs: &NO_AGGRS,
                meta: &helper.meta,
                recursion_limit: crate::recursion_limit(),
            };

            let v = self
                .invocable
                .invoke(&env, &args2)
                .map_err(|e| e.into_err(&ex, &ex, Some(&helper.reg), &helper.meta))?
                .into_static();
            Ok(ImutExprInt::Literal(Literal {
                value: v,
                mid: self.mid,
            }))
        } else {
            Ok(match self.args.len() {
                1 => ImutExprInt::Invoke1(self),
                2 => ImutExprInt::Invoke2(self),
                3 => ImutExprInt::Invoke3(self),
                _ => ImutExprInt::Invoke(self),
            })
        }
    }
}

#[derive(Clone)]
pub(crate) enum Invocable<'script> {
    Intrinsic(TremorFnWrapper),
    Tremor(CustomFn<'script>),
}

impl<'script> Invocable<'script> {
    fn inline(self, args: ImutExprs<'script>, mid: usize) -> Result<ImutExprInt<'script>> {
        match self {
            Invocable::Intrinsic(_f) => Err("can't inline intrinsic".into()),
            Invocable::Tremor(f) => f.inline(args, mid),
        }
    }
    fn can_inline(&self) -> bool {
        match self {
            Invocable::Intrinsic(_f) => false,
            Invocable::Tremor(f) => f.can_inline(),
        }
    }

    fn is_const(&self) -> bool {
        match self {
            Invocable::Intrinsic(f) => f.is_const(),
            Invocable::Tremor(f) => f.is_const(),
        }
    }
    pub fn invoke<'event, 'run>(
        &'script self,
        env: &'run Env<'run, 'event, 'script>,
        args: &'run [&'run Value<'event>],
    ) -> FResult<Value<'event>>
    where
        'script: 'event,
        'event: 'run,
    {
        match self {
            Invocable::Intrinsic(f) => f.invoke(env.context, args),
            Invocable::Tremor(f) => f.invoke(env, args),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Recur<'script> {
    pub mid: usize,
    pub argc: usize,
    pub open: bool,
    pub exprs: ImutExprs<'script>,
}
impl_expr2!(Recur);

#[derive(Clone, Serialize)]
pub(crate) struct InvokeAggr {
    pub mid: usize,
    pub module: String,
    pub fun: String,
    pub aggr_id: usize,
}

/// A Invocable aggregate function
#[derive(Clone, Serialize)]
pub struct InvokeAggrFn<'script> {
    pub(crate) mid: usize,
    /// The invocable function
    #[serde(skip)]
    pub invocable: TremorAggrFnWrapper,
    pub(crate) module: String,
    pub(crate) fun: String,
    /// Arguments passed to the function
    pub args: ImutExprs<'script>,
}
impl_expr2!(InvokeAggrFn);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct TestExpr {
    pub mid: usize,
    pub id: String,
    pub test: String,
    pub extractor: Extractor,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Match<'script> {
    pub mid: usize,
    pub target: ImutExprInt<'script>,
    pub patterns: Predicates<'script>,
}
impl_expr2!(Match);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ImutMatch<'script> {
    pub mid: usize,
    pub target: ImutExprInt<'script>,
    pub patterns: ImutPredicates<'script>,
}
impl_expr2!(ImutMatch);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct PredicateClause<'script> {
    pub mid: usize,
    pub pattern: Pattern<'script>,
    pub guard: Option<ImutExprInt<'script>>,
    pub exprs: Exprs<'script>,
}
impl_expr2!(PredicateClause);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ImutPredicateClause<'script> {
    pub mid: usize,
    pub pattern: Pattern<'script>,
    pub guard: Option<ImutExprInt<'script>>,
    pub exprs: ImutExprs<'script>,
}
impl_expr2!(ImutPredicateClause);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Patch<'script> {
    pub mid: usize,
    pub target: ImutExprInt<'script>,
    pub operations: PatchOperations<'script>,
}
impl_expr2!(Patch);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) enum PatchOperation<'script> {
    Insert {
        ident: ImutExprInt<'script>,
        expr: ImutExprInt<'script>,
    },
    Upsert {
        ident: ImutExprInt<'script>,
        expr: ImutExprInt<'script>,
    },
    Update {
        ident: ImutExprInt<'script>,
        expr: ImutExprInt<'script>,
    },
    Erase {
        ident: ImutExprInt<'script>,
    },
    Copy {
        from: ImutExprInt<'script>,
        to: ImutExprInt<'script>,
    },
    Move {
        from: ImutExprInt<'script>,
        to: ImutExprInt<'script>,
    },
    Merge {
        ident: ImutExprInt<'script>,
        expr: ImutExprInt<'script>,
    },
    TupleMerge {
        expr: ImutExprInt<'script>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Merge<'script> {
    pub mid: usize,
    pub target: ImutExprInt<'script>,
    pub expr: ImutExprInt<'script>,
}
impl_expr2!(Merge);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Comprehension<'script> {
    pub mid: usize,
    pub key_id: usize,
    pub val_id: usize,
    pub target: ImutExprInt<'script>,
    pub cases: ComprehensionCases<'script>,
}
impl_expr2!(Comprehension);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ImutComprehension<'script> {
    pub mid: usize,
    pub key_id: usize,
    pub val_id: usize,
    pub target: ImutExprInt<'script>,
    pub cases: ImutComprehensionCases<'script>,
}
impl_expr2!(ImutComprehension);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ComprehensionCase<'script> {
    pub mid: usize,
    pub key_name: Cow<'script, str>,
    pub value_name: Cow<'script, str>,
    pub guard: Option<ImutExprInt<'script>>,
    pub exprs: Exprs<'script>,
}
impl_expr2!(ComprehensionCase);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ImutComprehensionCase<'script> {
    pub mid: usize,
    pub key_name: Cow<'script, str>,
    pub value_name: Cow<'script, str>,
    pub guard: Option<ImutExprInt<'script>>,
    pub exprs: ImutExprs<'script>,
}
impl_expr2!(ImutComprehensionCase);

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) enum Pattern<'script> {
    //Predicate(PredicatePattern<'script>),
    Record(RecordPattern<'script>),
    Array(ArrayPattern<'script>),
    Expr(ImutExprInt<'script>),
    Assign(AssignPattern<'script>),
    Tuple(TuplePattern<'script>),
    DoNotCare,
    Default,
}
impl<'script> Pattern<'script> {
    fn is_default(&self) -> bool {
        if let Pattern::Default = self {
            true
        } else {
            false
        }
    }
    fn is_assign(&self) -> bool {
        if let Pattern::Assign(_) = self {
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) enum PredicatePattern<'script> {
    TildeEq {
        assign: Cow<'script, str>,
        lhs: Cow<'script, str>,
        #[serde(skip)]
        key: KnownKey<'script>,
        test: Box<TestExpr>,
    },
    Bin {
        lhs: Cow<'script, str>,
        #[serde(skip)]
        key: KnownKey<'script>,
        rhs: ImutExprInt<'script>,
        kind: BinOpKind,
    },
    RecordPatternEq {
        lhs: Cow<'script, str>,
        #[serde(skip)]
        key: KnownKey<'script>,
        pattern: RecordPattern<'script>,
    },
    ArrayPatternEq {
        lhs: Cow<'script, str>,
        #[serde(skip)]
        key: KnownKey<'script>,
        pattern: ArrayPattern<'script>,
    },
    FieldPresent {
        lhs: Cow<'script, str>,
        #[serde(skip)]
        key: KnownKey<'script>,
    },
    FieldAbsent {
        lhs: Cow<'script, str>,
        #[serde(skip)]
        key: KnownKey<'script>,
    },
}

impl<'script> PredicatePattern<'script> {
    pub fn key(&self) -> &KnownKey<'script> {
        use PredicatePattern::{
            ArrayPatternEq, Bin, FieldAbsent, FieldPresent, RecordPatternEq, TildeEq,
        };
        match self {
            TildeEq { key, .. }
            | Bin { key, .. }
            | RecordPatternEq { key, .. }
            | ArrayPatternEq { key, .. }
            | FieldPresent { key, .. }
            | FieldAbsent { key, .. } => &key,
        }
    }

    fn lhs(&self) -> &Cow<'script, str> {
        use PredicatePattern::{
            ArrayPatternEq, Bin, FieldAbsent, FieldPresent, RecordPatternEq, TildeEq,
        };
        match self {
            TildeEq { lhs, .. }
            | Bin { lhs, .. }
            | RecordPatternEq { lhs, .. }
            | ArrayPatternEq { lhs, .. }
            | FieldPresent { lhs, .. }
            | FieldAbsent { lhs, .. } => &lhs,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct RecordPattern<'script> {
    pub mid: usize,
    pub fields: PatternFields<'script>,
}
impl_expr2!(RecordPattern);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) enum ArrayPredicatePattern<'script> {
    Expr(ImutExprInt<'script>),
    Tilde(TestExpr),
    Record(RecordPattern<'script>),
    Ignore,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ArrayPattern<'script> {
    pub mid: usize,
    pub exprs: ArrayPredicatePatterns<'script>,
}
impl_expr2!(ArrayPattern);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct AssignPattern<'script> {
    pub id: Cow<'script, str>,
    pub idx: usize,
    pub pattern: Box<Pattern<'script>>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct TuplePattern<'script> {
    pub mid: usize,
    pub exprs: ArrayPredicatePatterns<'script>,
    pub open: bool,
}
impl_expr2!(TuplePattern);

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) enum Path<'script> {
    Const(LocalPath<'script>),
    Local(LocalPath<'script>),
    Event(EventPath<'script>),
    State(StatePath<'script>),
    Meta(MetadataPath<'script>),
}

impl<'script> Path<'script> {
    pub fn segments(&self) -> &[Segment] {
        match self {
            Path::Const(path) | Path::Local(path) => &path.segments,
            Path::Meta(path) => &path.segments,
            Path::Event(path) => &path.segments,
            Path::State(path) => &path.segments,
        }
    }
    fn try_reduce(self, helper: &Helper<'script, '_>) -> Result<ImutExprInt<'script>> {
        match self {
            Path::Const(LocalPath {
                is_const: true,
                segments,
                idx,
                mid,
            }) if segments.is_empty() && idx > LAST_RESERVED_CONST => {
                if let Some(v) = helper.const_values.get(idx) {
                    let lit = Literal {
                        mid,
                        value: v.clone(),
                    };
                    Ok(ImutExprInt::Literal(lit))
                } else {
                    error_generic(
                        &Range::from((
                            helper.meta.start(mid).unwrap_or_default(),
                            helper.meta.end(mid).unwrap_or_default(),
                        ))
                        .expand_lines(2),
                        &Range::from((
                            helper.meta.start(mid).unwrap_or_default(),
                            helper.meta.end(mid).unwrap_or_default(),
                        )),
                        &format!(
                            "Invalid const reference to '{}'",
                            helper.meta.name_dflt(mid),
                        ),
                        &helper.meta,
                    )
                }
            }
            other => Ok(ImutExprInt::Path(other)),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum Segment<'script> {
    Id {
        #[serde(skip)]
        key: KnownKey<'script>,
        mid: usize,
    },
    Idx {
        idx: usize,
        mid: usize,
    },
    Element {
        expr: ImutExprInt<'script>,
        mid: usize,
    },
    Range {
        lower_mid: usize,
        upper_mid: usize,
        mid: usize,
        range_start: Box<ImutExprInt<'script>>,
        range_end: Box<ImutExprInt<'script>>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct LocalPath<'script> {
    //pub id: Cow<'script, str>,
    pub idx: usize,
    pub is_const: bool,
    pub mid: usize,
    pub segments: Segments<'script>,
}
impl_expr2!(LocalPath);

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MetadataPath<'script> {
    pub mid: usize,
    pub segments: Segments<'script>,
}
impl_expr2!(MetadataPath);

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EventPath<'script> {
    pub mid: usize,
    pub segments: Segments<'script>,
}
impl_expr2!(EventPath);

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StatePath<'script> {
    pub mid: usize,
    pub segments: Segments<'script>,
}
impl_expr2!(StatePath);

/// we're forced to make this pub because of lalrpop
#[derive(Copy, Clone, Debug, PartialEq, Serialize)]
pub enum BinOpKind {
    /// we're forced to make this pub because of lalrpop
    Or,
    /// we're forced to make this pub because of lalrpop
    Xor,
    /// we're forced to make this pub because of lalrpop
    And,

    /// we're forced to make this pub because of lalrpop
    BitOr,
    /// we're forced to make this pub because of lalrpop
    BitXor,
    /// we're forced to make this pub because of lalrpop
    BitAnd,

    /// we're forced to make this pub because of lalrpop
    Eq,
    /// we're forced to make this pub because of lalrpop
    NotEq,

    /// we're forced to make this pub because of lalrpop
    Gte,
    /// we're forced to make this pub because of lalrpop
    Gt,
    /// we're forced to make this pub because of lalrpop
    Lte,
    /// we're forced to make this pub because of lalrpop
    Lt,

    /// we're forced to make this pub because of lalrpop
    RBitShiftSigned,
    /// we're forced to make this pub because of lalrpop
    RBitShiftUnsigned,
    /// we're forced to make this pub because of lalrpop
    LBitShift,

    /// we're forced to make this pub because of lalrpop
    Add,
    /// we're forced to make this pub because of lalrpop
    Sub,
    /// we're forced to make this pub because of lalrpop
    Mul,
    /// we're forced to make this pub because of lalrpop
    Div,
    /// we're forced to make this pub because of lalrpop
    Mod,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct BinExpr<'script> {
    pub mid: usize,
    pub kind: BinOpKind,
    pub lhs: ImutExprInt<'script>,
    pub rhs: ImutExprInt<'script>,
}
impl_expr2!(BinExpr);

impl<'script> BinExpr<'script> {
    fn try_reduce(self, helper: &Helper<'script, '_>) -> Result<ImutExprInt<'script>> {
        match self {
            b
            @
            BinExpr {
                lhs: ImutExprInt::Literal(_),
                rhs: ImutExprInt::Literal(_),
                ..
            } => {
                let lhs = reduce2(b.lhs.clone(), helper)?;
                let rhs = reduce2(b.rhs.clone(), helper)?;
                let value = exec_binary(&b, &b, &helper.meta, b.kind, &lhs, &rhs)?.into_owned();
                let lit = Literal { mid: b.mid, value };
                Ok(ImutExprInt::Literal(lit))
            }
            b => Ok(ImutExprInt::Binary(Box::new(b))),
        }
    }
}

/// we're forced to make this pub because of lalrpop
#[derive(Copy, Clone, Debug, PartialEq, Serialize)]
pub enum UnaryOpKind {
    /// we're forced to make this pub because of lalrpop
    Plus,
    /// we're forced to make this pub because of lalrpop
    Minus,
    /// we're forced to make this pub because of lalrpop
    Not,
    /// we're forced to make this pub because of lalrpop
    BitNot,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct UnaryExpr<'script> {
    pub mid: usize,
    pub kind: UnaryOpKind,
    pub expr: ImutExprInt<'script>,
}
impl_expr2!(UnaryExpr);

impl<'script> UnaryExpr<'script> {
    fn try_reduce(self, helper: &Helper<'script, '_>) -> Result<ImutExprInt<'script>> {
        match self {
            u1
            @
            UnaryExpr {
                expr: ImutExprInt::Literal(_),
                ..
            } => {
                let expr = reduce2(u1.expr.clone(), &helper)?;
                let value = if let Some(v) = exec_unary(u1.kind, &expr) {
                    v.into_owned()
                } else {
                    let ex = u1.extent(&helper.meta);
                    return Err(ErrorKind::InvalidUnary(
                        ex.expand_lines(2),
                        ex,
                        u1.kind,
                        expr.value_type(),
                    )
                    .into());
                };

                let lit = Literal { mid: u1.mid, value };
                Ok(ImutExprInt::Literal(lit))
            }
            u1 => Ok(ImutExprInt::Unary(Box::new(u1))),
        }
    }
}

pub(crate) type Exprs<'script> = Vec<Expr<'script>>;
/// A list of lexical compilation units
pub type Imports<'script> = Vec<LexicalUnit<'script>>;
/// A list of immutable expressions
pub type ImutExprs<'script> = Vec<ImutExpr<'script>>;
pub(crate) type Fields<'script> = Vec<Field<'script>>;
pub(crate) type Segments<'script> = Vec<Segment<'script>>;
pub(crate) type PatternFields<'script> = Vec<PredicatePattern<'script>>;
pub(crate) type Predicates<'script> = Vec<PredicateClause<'script>>;
pub(crate) type ImutPredicates<'script> = Vec<ImutPredicateClause<'script>>;
pub(crate) type PatchOperations<'script> = Vec<PatchOperation<'script>>;
pub(crate) type ComprehensionCases<'script> = Vec<ComprehensionCase<'script>>;
pub(crate) type ImutComprehensionCases<'script> = Vec<ImutComprehensionCase<'script>>;
pub(crate) type ArrayPredicatePatterns<'script> = Vec<ArrayPredicatePattern<'script>>;
/// A vector of statements
pub type Stmts<'script> = Vec<Stmt<'script>>;

fn replace_last_shadow_use<'script>(replace_idx: usize, expr: Expr<'script>) -> Expr<'script> {
    match expr {
        Expr::Assign { path, expr, mid } => match expr.borrow() {
            Expr::Imut(ImutExprInt::Local { idx, .. }) if idx == &replace_idx => {
                Expr::AssignMoveLocal {
                    mid,
                    idx: *idx,
                    path,
                }
            }

            _ => Expr::Assign { path, expr, mid },
        },
        Expr::Match(m) => {
            let mut m: Match<'script> = *m;

            // In each pattern we can replace the use in the last assign
            for p in &mut m.patterns {
                if let Some(expr) = p.exprs.pop() {
                    p.exprs.push(replace_last_shadow_use(replace_idx, expr))
                }
            }

            Expr::Match(Box::new(m))
        }
        other => other,
    }
}

fn shadow_name(id: usize) -> String {
    format!(" __SHADOW {}__ ", id)
}
