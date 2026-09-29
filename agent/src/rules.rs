//! Falco-style YAML rule engine.
//!
//! A rule has a `condition` expressed in a small boolean language over event
//! fields (see `rules/README.md` for the full field reference):
//!
//! ```text
//! evt.type = execve and proc.name in (sh, bash) and not container
//! evt.type = openat and file.path startswith /etc and proc.uid != 0
//! evt.type = mount and (mount.target contains "docker" or mount.fstype = cgroup)
//! ```
//!
//! Grammar (precedence climbing):
//!
//! ```text
//! expr    := or_expr
//! or_expr := and_expr ("or" and_expr)*
//! and_expr:= unary ("and" unary)*
//! unary   := "not" unary | "(" expr ")" | predicate
//! predicate := field ("=" | "==" | "!=" | "<" | "<=" | ">" | ">=" |
//!                    "contains" | "startswith" | "endswith") value
//!            | field ["not"] "in" "(" value ("," value)* ")"
//!            | field "exists"
//!            | field                      # truthy
//! value    := bare-word | "quoted string" | integer (decimal or 0x hex)
//! ```

use std::{fs, path::Path};

use anyhow::{Context as _, Result, anyhow, bail};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// A resolved field value.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl Val {
    fn as_str(&self) -> String {
        match self {
            Val::Str(s) => s.clone(),
            Val::Int(i) => i.to_string(),
            Val::Bool(b) => b.to_string(),
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(*i),
            Val::Str(s) => s.parse().ok(),
            Val::Bool(b) => Some(*b as i64),
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Val::Str(s) => !s.is_empty(),
            Val::Int(i) => *i != 0,
            Val::Bool(b) => *b,
        }
    }
}

/// Something fields can be looked up from (an [`crate::event::EventContext`] in
/// production, a map in tests).
pub trait FieldLookup {
    fn lookup(&self, field: &str) -> Option<Val>;
    /// All fields currently set (used for `%field` output rendering).
    fn fields(&self) -> Vec<(String, Val)>;
}

/// Field lookup over a plain map — used by tests and simple embeddings.
#[derive(Debug, Default, Clone)]
pub struct MapLookup(pub std::collections::BTreeMap<String, Val>);

impl FieldLookup for MapLookup {
    fn lookup(&self, field: &str) -> Option<Val> {
        self.0.get(field).cloned()
    }

    fn fields(&self) -> Vec<(String, Val)> {
        self.0.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    In,
    Contains,
    StartsWith,
    EndsWith,
    Exists,
    LParen,
    RParen,
    Comma,
}

fn tokenize(input: &str) -> Result<Vec<Tok>> {
    let mut toks = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                toks.push(Tok::LParen);
            }
            ')' => {
                chars.next();
                toks.push(Tok::RParen);
            }
            ',' => {
                chars.next();
                toks.push(Tok::Comma);
            }
            '=' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                }
                toks.push(Tok::Eq);
            }
            '!' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    toks.push(Tok::Ne);
                } else {
                    bail!("unexpected '!' (did you mean '!=' or 'not'?)");
                }
            }
            '<' => {
                chars.next();
                toks.push(if chars.peek() == Some(&'=') {
                    chars.next();
                    Tok::Le
                } else {
                    Tok::Lt
                });
            }
            '>' => {
                chars.next();
                toks.push(if chars.peek() == Some(&'=') {
                    chars.next();
                    Tok::Ge
                } else {
                    Tok::Gt
                });
            }
            '\'' | '"' => {
                chars.next();
                let mut s = String::new();
                let mut closed = false;
                while let Some(ch) = chars.next() {
                    if ch == c {
                        closed = true;
                        break;
                    }
                    s.push(ch);
                }
                if !closed {
                    bail!("unterminated string literal");
                }
                toks.push(Tok::Str(s));
            }
            c if c.is_ascii_digit() => {
                // Numbers may look like IPs or versions: `4444`, `0x4206`,
                // `169.254.169.254`, `1.2.3`. Collect the whole literal first,
                // then interpret as decimal/hex integer — falling back to a
                // string value for IP/version-shaped literals.
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let parsed = if let Some(hex) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
                    i64::from_str_radix(hex, 16).ok()
                } else {
                    s.parse::<i64>().ok()
                };
                toks.push(match parsed {
                    Some(i) => Tok::Int(i),
                    None => Tok::Str(s),
                });
            }
            c if c.is_alphanumeric() || c == '_' || c == '.' || c == '-' || c == '/' => {
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || "_.-/".contains(ch) {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                toks.push(match s.to_ascii_lowercase().as_str() {
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    "not" => Tok::Not,
                    "in" => Tok::In,
                    "contains" => Tok::Contains,
                    "startswith" => Tok::StartsWith,
                    "endswith" => Tok::EndsWith,
                    "exists" => Tok::Exists,
                    _ => Tok::Ident(s),
                });
            }
            other => bail!("unexpected character {other:?}"),
        }
    }
    Ok(toks)
}

// ---------------------------------------------------------------------------
// AST + parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Cmp {
        field: String,
        op: Op,
        value: Value,
    },
    In {
        field: String,
        values: Vec<Value>,
    },
    Exists {
        field: String,
    },
    /// Bare field: exists and is truthy (e.g. `container`).
    Truthy {
        field: String,
    },
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, want: &Tok) -> Result<()> {
        match self.next() {
            Some(t) if &t == want => Ok(()),
            other => bail!("expected {want:?}, got {other:?}"),
        }
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        let mut terms = vec![self.parse_and()?];
        while matches!(self.peek(), Some(Tok::Or)) {
            self.next();
            terms.push(self.parse_and()?);
        }
        Ok(if terms.len() == 1 {
            terms.pop().unwrap()
        } else {
            Expr::Or(terms)
        })
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut terms = vec![self.parse_unary()?];
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            terms.push(self.parse_unary()?);
        }
        Ok(if terms.len() == 1 {
            terms.pop().unwrap()
        } else {
            Expr::And(terms)
        })
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        match self.peek() {
            Some(Tok::Not) => {
                self.next();
                Ok(Expr::Not(Box::new(self.parse_unary()?)))
            }
            Some(Tok::LParen) => {
                self.next();
                let e = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::Ident(_)) => self.parse_predicate(),
            other => bail!("expected predicate, got {other:?}"),
        }
    }

    fn parse_predicate(&mut self) -> Result<Expr> {
        let field = match self.next() {
            Some(Tok::Ident(name)) => name,
            other => bail!("expected field name, got {other:?}"),
        };
        match self.peek() {
            None | Some(Tok::And) | Some(Tok::Or) | Some(Tok::RParen) => Ok(Expr::Truthy { field }),
            Some(Tok::Exists) => {
                self.next();
                Ok(Expr::Exists { field })
            }
            Some(Tok::In) => {
                self.next();
                self.parse_in_list(field)
            }
            Some(Tok::Not) => {
                self.next();
                match self.next() {
                    Some(Tok::In) => {
                        let inner = self.parse_in_list(field)?;
                        Ok(Expr::Not(Box::new(inner)))
                    }
                    other => bail!("expected 'in' after 'not', got {other:?}"),
                }
            }
            Some(_) => {
                let op = match self.next() {
                    Some(Tok::Eq) => Op::Eq,
                    Some(Tok::Ne) => Op::Ne,
                    Some(Tok::Lt) => Op::Lt,
                    Some(Tok::Le) => Op::Le,
                    Some(Tok::Gt) => Op::Gt,
                    Some(Tok::Ge) => Op::Ge,
                    Some(Tok::Contains) => Op::Contains,
                    Some(Tok::StartsWith) => Op::StartsWith,
                    Some(Tok::EndsWith) => Op::EndsWith,
                    other => bail!("expected operator, got {other:?}"),
                };
                let value = self.parse_value()?;
                Ok(Expr::Cmp { field, op, value })
            }
        }
    }

    fn parse_in_list(&mut self, field: String) -> Result<Expr> {
        self.expect(&Tok::LParen)?;
        let mut values = Vec::new();
        loop {
            values.push(self.parse_value()?);
            match self.next() {
                Some(Tok::Comma) => continue,
                Some(Tok::RParen) => break,
                other => bail!("expected ',' or ')', got {other:?}"),
            }
        }
        Ok(Expr::In { field, values })
    }

    fn parse_value(&mut self) -> Result<Value> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(Value::Str(s)),
            Some(Tok::Ident(s)) => Ok(Value::Str(s)),
            Some(Tok::Int(i)) => Ok(Value::Int(i)),
            other => bail!("expected value, got {other:?}"),
        }
    }
}

/// Parse a condition string into an [`Expr`] AST.
pub fn parse_condition(input: &str) -> Result<Expr> {
    let mut p = Parser {
        toks: tokenize(input)?,
        pos: 0,
    };
    let expr = p.parse_expr()?;
    if p.pos != p.toks.len() {
        bail!("trailing tokens at position {}", p.pos);
    }
    Ok(expr)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn value_eq(val: &Val, want: &Value) -> bool {
    match want {
        Value::Str(s) => val.as_str() == *s,
        Value::Int(i) => val.as_int() == Some(*i),
    }
}

impl Expr {
    pub fn matches(&self, ctx: &dyn FieldLookup) -> bool {
        match self {
            Expr::And(terms) => terms.iter().all(|t| t.matches(ctx)),
            Expr::Or(terms) => terms.iter().any(|t| t.matches(ctx)),
            Expr::Not(inner) => !inner.matches(ctx),
            Expr::Cmp { field, op, value } => {
                let Some(val) = ctx.lookup(field) else {
                    return false;
                };
                match op {
                    Op::Eq => value_eq(&val, value),
                    Op::Ne => !value_eq(&val, value),
                    Op::Contains => val.as_str().contains(&value.as_raw()),
                    Op::StartsWith => val.as_str().starts_with(&value.as_raw()),
                    Op::EndsWith => val.as_str().ends_with(&value.as_raw()),
                    Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                        let (Some(have), Some(want)) = (val.as_int(), value.as_int()) else {
                            return false;
                        };
                        match op {
                            Op::Lt => have < want,
                            Op::Le => have <= want,
                            Op::Gt => have > want,
                            Op::Ge => have >= want,
                            _ => unreachable!(),
                        }
                    }
                }
            }
            Expr::In { field, values } => {
                let Some(val) = ctx.lookup(field) else {
                    return false;
                };
                values.iter().any(|v| value_eq(&val, v))
            }
            Expr::Exists { field } => ctx.lookup(field).is_some(),
            Expr::Truthy { field } => ctx.lookup(field).is_some_and(|v| v.truthy()),
        }
    }
}

impl Value {
    fn as_raw(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Int(i) => i.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rule schema + engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Debug,
    Info,
    #[default]
    Notice,
    Warning,
    Error,
    Critical,
}

impl Priority {
    pub const fn as_str(self) -> &'static str {
        match self {
            Priority::Debug => "DEBUG",
            Priority::Info => "INFO",
            Priority::Notice => "NOTICE",
            Priority::Warning => "WARNING",
            Priority::Error => "ERROR",
            Priority::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub priority: Priority,
    pub condition: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Alert text; `%field` placeholders are substituted from the event.
    #[serde(default)]
    pub output: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RuleFile {
    List(Vec<Rule>),
    Wrapped { rules: Vec<Rule> },
}

impl RuleFile {
    fn into_rules(self) -> Vec<Rule> {
        match self {
            RuleFile::List(rules) => rules,
            RuleFile::Wrapped { rules } => rules,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub expr: Expr,
}

pub struct RuleEngine {
    pub rules: Vec<CompiledRule>,
}

impl RuleEngine {
    /// Load every `*.yaml` / `*.yml` file in `dir` (sorted for determinism).
    pub fn from_dir(dir: &Path) -> Result<Self> {
        let mut paths: Vec<_> = fs::read_dir(dir)
            .with_context(|| format!("reading rule directory {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        paths.sort();

        let mut rules = Vec::new();
        for path in &paths {
            let text = fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            rules.extend(Self::parse_yaml(&text).with_context(|| format!("{}", path.display()))?);
        }
        Self::compile(rules)
    }

    /// Parse one YAML document containing a rule list (bare or under `rules:`).
    pub fn parse_yaml(text: &str) -> Result<Vec<Rule>> {
        let file: RuleFile = serde_yaml::from_str(text).context("invalid rule YAML")?;
        Ok(file.into_rules())
    }

    pub fn compile(rules: Vec<Rule>) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let expr = parse_condition(&rule.condition)
                .with_context(|| format!("rule {}: {}", rule.id, rule.condition))?;
            compiled.push(CompiledRule { rule, expr });
        }
        Ok(Self { rules: compiled })
    }

    /// All rules whose condition matches the context.
    pub fn evaluate<'a>(&'a self, ctx: &dyn FieldLookup) -> Vec<&'a CompiledRule> {
        self.rules
            .iter()
            .filter(|r| r.expr.matches(ctx))
            .collect()
    }
}

/// Substitute `%field` placeholders in an alert output template.
pub fn render_output(template: &str, ctx: &dyn FieldLookup) -> String {
    let fields = ctx.fields();
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(pos) = rest.find('%') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let name_end = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
            .unwrap_or(after.len());
        let name = &after[..name_end];
        if name.is_empty() {
            out.push('%');
            rest = &after[name_end.min(after.len())..];
            continue;
        }
        match fields.iter().find(|(f, _)| f == name) {
            Some((_, v)) => out.push_str(&v.as_str()),
            None => out.push('%').push_str(name),
        }
        rest = &after[name_end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ctx(pairs: &[(&str, Val)]) -> MapLookup {
        MapLookup(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    #[test]
    fn precedence_and_or() {
        // and binds tighter than or
        let e = parse_condition("a = 1 or b = 2 and c = 3").unwrap();
        assert_eq!(
            e,
            Expr::Or(vec![
                Expr::Cmp {
                    field: "a".into(),
                    op: Op::Eq,
                    value: Value::Int(1)
                },
                Expr::And(vec![
                    Expr::Cmp {
                        field: "b".into(),
                        op: Op::Eq,
                        value: Value::Int(2)
                    },
                    Expr::Cmp {
                        field: "c".into(),
                        op: Op::Eq,
                        value: Value::Int(3)
                    },
                ]),
            ])
        );
    }

    #[test]
    fn parens_and_not() {
        let e = parse_condition("not (a = 1 or b = 2) and c = 3").unwrap();
        assert!(e.matches(&ctx(&[
            ("c", Val::Int(3)),
            ("a", Val::Int(5)),
            ("b", Val::Int(5)),
        ])));
        assert!(!e.matches(&ctx(&[("c", Val::Int(3)), ("a", Val::Int(1))])));
    }

    #[test]
    fn string_predicates() {
        let c = ctx(&[("file.path", Val::Str("/etc/shadow".into()))]);
        assert!(parse_condition("file.path startswith /etc")
            .unwrap()
            .matches(&c));
        assert!(parse_condition("file.path endswith \"shadow\"")
            .unwrap()
            .matches(&c));
        assert!(parse_condition("file.path contains etc").unwrap().matches(&c));
        assert!(!parse_condition("file.path contains proc")
            .unwrap()
            .matches(&c));
    }

    #[test]
    fn in_list_and_exists() {
        let c = ctx(&[("proc.name", Val::Str("bash".into()))]);
        assert!(parse_condition("proc.name in (sh, bash, zsh)")
            .unwrap()
            .matches(&c));
        assert!(!parse_condition("proc.name in (sh, zsh)").unwrap().matches(&c));
        assert!(parse_condition("proc.name exists").unwrap().matches(&c));
        assert!(!parse_condition("net.addr exists").unwrap().matches(&c));
    }

    #[test]
    fn not_in_and_hex() {
        let c = ctx(&[
            ("proc.name", Val::Str("evil".into())),
            ("sys.arg0", Val::Int(0x4206)),
        ]);
        assert!(parse_condition("proc.name not in (sudo, su)").unwrap().matches(&c));
        assert!(!parse_condition("proc.name not in (evil, su)").unwrap().matches(&c));
        assert!(parse_condition("sys.arg0 in (4, 5, 16, 0x4206)")
            .unwrap()
            .matches(&c));
    }

    #[test]
    fn ip_and_version_literals() {
        let c = ctx(&[("net.addr", Val::Str("169.254.169.254".into()))]);
        assert!(parse_condition("net.addr = 169.254.169.254")
            .unwrap()
            .matches(&c));
        assert!(parse_condition("net.addr = \"169.254.169.254\"")
            .unwrap()
            .matches(&c));
    }

    #[test]
    fn truthy_and_numeric() {
        let c = ctx(&[
            ("container", Val::Bool(true)),
            ("proc.uid", Val::Int(0)),
        ]);
        assert!(parse_condition("container").unwrap().matches(&c));
        assert!(!parse_condition("not container").unwrap().matches(&c));
        assert!(parse_condition("proc.uid = 0").unwrap().matches(&c));
        assert!(parse_condition("proc.uid >= 0 and proc.uid <= 0")
            .unwrap()
            .matches(&c));
        assert!(!parse_condition("proc.uid > 0").unwrap().matches(&c));
    }

    #[test]
    fn eq_coerces_strings_and_ints() {
        let c = ctx(&[("net.port", Val::Int(4444))]);
        assert!(parse_condition("net.port = 4444").unwrap().matches(&c));
        assert!(parse_condition("net.port = \"4444\"").unwrap().matches(&c));
    }

    #[test]
    fn yaml_rule_loading() {
        let yaml = r#"
- id: SENTINEL-001
  name: Reverse shell
  priority: critical
  condition: >
    evt.type = execve and proc.name in (sh, bash) and exec.argv contains "-i"
  tags: [attack.t1059]
  output: "reverse shell? %proc.name %exec.argv"
- id: SENTINEL-002
  name: Wrapped form
  condition: evt.type = mount
"#;
        let rules = RuleEngine::parse_yaml(yaml).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].priority, Priority::Critical);

        let wrapped = "rules:\n  - id: X\n    name: n\n    condition: evt.type = execve\n";
        let rules = RuleEngine::parse_yaml(wrapped).unwrap();
        assert_eq!(rules[0].id, "X");
    }

    #[test]
    fn engine_evaluates_all_rules() {
        let engine = RuleEngine::compile(vec![
            Rule {
                id: "A".into(),
                name: "a".into(),
                description: String::new(),
                priority: Priority::Notice,
                condition: "evt.type = execve and proc.name = sh".into(),
                tags: vec![],
                output: String::new(),
            },
            Rule {
                id: "B".into(),
                name: "b".into(),
                description: String::new(),
                priority: Priority::Notice,
                condition: "evt.type = openat".into(),
                tags: vec![],
                output: String::new(),
            },
        ])
        .unwrap();

        let c = ctx(&[
            ("evt.type", Val::Str("execve".into())),
            ("proc.name", Val::Str("sh".into())),
        ]);
        let matched: Vec<_> = engine.evaluate(&c).iter().map(|r| r.rule.id.as_str()).collect();
        assert_eq!(matched, vec!["A"]);
    }

    #[test]
    fn output_rendering() {
        let c = ctx(&[
            ("proc.name", Val::Str("sh".into())),
            ("exec.argv", Val::Str("sh -i".into())),
        ]);
        assert_eq!(
            render_output("%proc.name ran %exec.argv (%proc.pid)", &c),
            "sh ran sh -i (%proc.pid)"
        );
    }

    #[test]
    fn parse_errors_are_reported() {
        assert!(parse_condition("evt.type = ").is_err());
        assert!(parse_condition("evt.type = execve and").is_err());
        assert!(parse_condition("evt.type = execve trailing").is_err());
    }
}
