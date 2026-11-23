//! Safe, zero-`eval` recursive-descent AST formula parser and evaluator.
//!
//! Designed for linear-time $O(L)$ evaluation of node scoring expressions, hard
//! gates, dynamic filter expressions, and threshold trigger rules with hard
//! bounds on expression length (`MAX_EXPR_LEN`) and AST recursion depth
//! (`MAX_AST_DEPTH`), plus division-by-zero and non-finite guards.

use crate::error::{CatError, CatResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use crate::models::{DEFAULT_COST_EFFECTIVE_FORMULA, DEFAULT_MAX_PERF_FORMULA};

/// Hard cap on formula expression byte length to prevent pathological inputs.
pub const MAX_EXPR_LEN: usize = 2048;

/// Hard cap on AST nesting depth to prevent stack overflow during parsing and evaluation.
pub const MAX_AST_DEPTH: usize = 64;

/// Hard cap on total AST nodes parsed from a single expression.
pub const MAX_AST_NODES: usize = 1024;

/// Default sentinel latency (ms) returned when a requested ping metric is absent or disconnected.
pub const DEFAULT_MISSING_PING_MS: f64 = 9999.0;

const EPSILON_ZERO: f64 = 1e-12;
const EPSILON_EQ: f64 = 1e-9;

/// Evaluation context carrying scalar node/probe metrics and per-probe lookup maps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalContext {
    pub up_mbps: f64,
    pub down_mbps: f64,
    pub ping_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub multiplier: f64,
    pub keepalive_ok: bool,
    pub google_clean: bool,
    pub unlocked: bool,
    pub is_443_native: bool,
    pub ok: bool,
    pub per_probe_up_mbps: HashMap<String, f64>,
    pub per_probe_down_mbps: HashMap<String, f64>,
    pub per_probe_ping_ms: HashMap<String, f64>,
    pub per_probe_ok: HashMap<String, bool>,
    pub unlocked_sites: HashMap<String, bool>,
}

impl Default for EvalContext {
    fn default() -> Self {
        Self {
            up_mbps: 0.0,
            down_mbps: 0.0,
            ping_ms: 0.0,
            jitter_ms: 0.0,
            loss_pct: 0.0,
            multiplier: 1.0,
            keepalive_ok: false,
            google_clean: false,
            unlocked: false,
            is_443_native: false,
            ok: false,
            per_probe_up_mbps: HashMap::new(),
            per_probe_down_mbps: HashMap::new(),
            per_probe_ping_ms: HashMap::new(),
            per_probe_ok: HashMap::new(),
            unlocked_sites: HashMap::new(),
        }
    }
}

impl EvalContext {
    fn lookup_scalar(&self, field: ScalarField) -> f64 {
        match field {
            ScalarField::UpMbps => sanitize_f64(self.up_mbps),
            ScalarField::DownMbps => sanitize_f64(self.down_mbps),
            ScalarField::PingMs => sanitize_f64(self.ping_ms),
            ScalarField::JitterMs => sanitize_f64(self.jitter_ms),
            ScalarField::LossPct => sanitize_f64(self.loss_pct),
            ScalarField::Multiplier => sanitize_f64(self.multiplier),
            ScalarField::KeepaliveOk => bool_to_f64(self.keepalive_ok),
            ScalarField::GoogleClean => bool_to_f64(self.google_clean),
            ScalarField::Unlocked => bool_to_f64(self.unlocked),
            ScalarField::Is443Native => bool_to_f64(self.is_443_native),
            ScalarField::Ok => bool_to_f64(self.ok),
        }
    }

    fn lookup_probe_up(&self, probe_id: &str) -> f64 {
        let trimmed = probe_id.trim();
        self.per_probe_up_mbps
            .get(probe_id)
            .or_else(|| self.per_probe_up_mbps.get(trimmed))
            .copied()
            .filter(|v| v.is_finite())
            .map(sanitize_f64)
            .unwrap_or_else(|| sanitize_f64(self.up_mbps))
    }

    fn lookup_probe_down(&self, probe_id: &str) -> f64 {
        let trimmed = probe_id.trim();
        self.per_probe_down_mbps
            .get(probe_id)
            .or_else(|| self.per_probe_down_mbps.get(trimmed))
            .copied()
            .filter(|v| v.is_finite())
            .map(sanitize_f64)
            .unwrap_or_else(|| sanitize_f64(self.down_mbps))
    }

    fn lookup_probe_ping(&self, probe_id: &str) -> f64 {
        let trimmed = probe_id.trim();
        if let Some(v) = self
            .per_probe_ping_ms
            .get(probe_id)
            .or_else(|| self.per_probe_ping_ms.get(trimmed))
            .copied()
            .filter(|v| v.is_finite())
        {
            return sanitize_f64(v);
        }
        if self.ping_ms.is_finite() && (self.ping_ms > 0.0 || self.ok) {
            sanitize_f64(self.ping_ms)
        } else {
            DEFAULT_MISSING_PING_MS
        }
    }

    fn lookup_probe_ok(&self, probe_id: &str) -> f64 {
        let passed = self.per_probe_ok.get(probe_id).copied().unwrap_or(false);
        bool_to_f64(passed)
    }

    fn lookup_site_exact_or_ci(&self, name: &str) -> Option<bool> {
        if let Some(&v) = self.unlocked_sites.get(name) {
            return Some(v);
        }
        for (k, &v) in &self.unlocked_sites {
            if k.eq_ignore_ascii_case(name) {
                return Some(v);
            }
        }
        None
    }

    fn lookup_site_unlocked(&self, site_name: &str) -> f64 {
        let trimmed = site_name.trim();
        if let Some(v) = self.lookup_site_exact_or_ci(trimmed) {
            return bool_to_f64(v);
        }
        let aliases: &[&str] = match trimmed.to_ascii_lowercase().as_str() {
            "google_ai" => &["gemini", "gemini_aistudio"],
            "gemini" => &["gemini_aistudio", "google_ai"],
            "gemini_aistudio" => &["gemini", "google_ai"],
            _ => &[],
        };
        for alias in aliases {
            if let Some(v) = self.lookup_site_exact_or_ci(alias) {
                return bool_to_f64(v);
            }
        }
        0.0
    }
}

/// Parsed, validated safe AST representation of a formula or boolean predicate.
#[derive(Debug, Clone, PartialEq)]
pub struct FormulaExpr {
    source: String,
    root: Expr,
}

impl FormulaExpr {
    /// Parse and validate an expression string into an executable AST.
    pub fn parse(expr: &str) -> CatResult<Self> {
        if expr.len() > MAX_EXPR_LEN {
            return Err(CatError::Formula(format!(
                "formula length {} exceeds maximum allowed {} bytes",
                expr.len(),
                MAX_EXPR_LEN
            )));
        }
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return Err(CatError::Formula("formula expression cannot be empty".into()));
        }

        let tokens = tokenize(trimmed)?;
        let mut parser = Parser::new(&tokens);
        let root = parser.parse_expr(1)?;
        if !parser.is_at_end() {
            let tok = parser.peek();
            return Err(CatError::Formula(format!(
                "unexpected trailing token `{}` at byte offset {}",
                tok.kind.describe(),
                tok.pos
            )));
        }

        let actual_depth = root.depth();
        if actual_depth > MAX_AST_DEPTH {
            return Err(CatError::Formula(format!(
                "formula AST depth {} exceeds maximum allowed {}",
                actual_depth, MAX_AST_DEPTH
            )));
        }

        Ok(Self {
            source: trimmed.to_string(),
            root,
        })
    }

    /// Return the normalized source expression string.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Evaluate the expression into a finite `f64` value.
    pub fn eval_f64(&self, ctx: &EvalContext) -> CatResult<f64> {
        let value = eval_node(&self.root, ctx, 1)?;
        Ok(sanitize_f64(value))
    }

    /// Evaluate the expression as a boolean (`|value| > 1e-12`).
    pub fn eval_bool(&self, ctx: &EvalContext) -> CatResult<bool> {
        let value = self.eval_f64(ctx)?;
        Ok(is_truthy(value))
    }

    /// Return `true` if this AST explicitly references the `multiplier` scalar.
    pub fn uses_multiplier(&self) -> bool {
        self.root.uses_multiplier()
    }

    /// Return `true` if this AST explicitly references the `keepalive_ok` scalar.
    pub fn uses_keepalive_ok(&self) -> bool {
        self.root.uses_keepalive_ok()
    }
}

/// Validate a formula string without evaluating it.
pub fn validate_formula(expr: &str) -> CatResult<()> {
    FormulaExpr::parse(expr).map(|_| ())
}

/// Parse the built-in cost-effective default weighting formula.
pub fn default_cost_effective_formula() -> CatResult<FormulaExpr> {
    FormulaExpr::parse(DEFAULT_COST_EFFECTIVE_FORMULA)
}

/// Parse the built-in maximum-performance default weighting formula.
pub fn default_max_perf_formula() -> CatResult<FormulaExpr> {
    FormulaExpr::parse(DEFAULT_MAX_PERF_FORMULA)
}

// ============================================================================
// AST definitions
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarField {
    UpMbps,
    DownMbps,
    PingMs,
    JitterMs,
    LossPct,
    Multiplier,
    KeepaliveOk,
    GoogleClean,
    Unlocked,
    Is443Native,
    Ok,
}

impl ScalarField {
    fn from_ident(ident: &str) -> Option<Self> {
        match ident {
            "up_mbps" => Some(Self::UpMbps),
            "down_mbps" => Some(Self::DownMbps),
            "ping_ms" | "latency_ms" => Some(Self::PingMs),
            "jitter_ms" => Some(Self::JitterMs),
            "loss_pct" => Some(Self::LossPct),
            "multiplier" => Some(Self::Multiplier),
            "keepalive_ok" => Some(Self::KeepaliveOk),
            "google_clean" => Some(Self::GoogleClean),
            "unlocked" => Some(Self::Unlocked),
            "is_443_native" => Some(Self::Is443Native),
            "ok" => Some(Self::Ok),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnaryOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeLookupKind {
    Up,
    Down,
    Ping,
    Ok,
    SiteUnlocked,
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Number(f64),
    Scalar(ScalarField),
    Unary {
        op: UnaryOp,
        operand: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Abs(Box<Expr>),
    Min(Box<Expr>, Box<Expr>),
    Max(Box<Expr>, Box<Expr>),
    Clamp {
        x: Box<Expr>,
        lo: Box<Expr>,
        hi: Box<Expr>,
    },
    If {
        cond: Box<Expr>,
        then_val: Box<Expr>,
        else_val: Box<Expr>,
    },
    ProbeLookup {
        kind: ProbeLookupKind,
        key: String,
    },
}

impl Expr {
    fn depth(&self) -> usize {
        match self {
            Self::Number(_) | Self::Scalar(_) | Self::ProbeLookup { .. } => 1,
            Self::Unary { operand, .. } | Self::Abs(operand) => 1 + operand.depth(),
            Self::Binary { left, right, .. } | Self::Min(left, right) | Self::Max(left, right) => {
                1 + left.depth().max(right.depth())
            }
            Self::Clamp { x, lo, hi } => 1 + x.depth().max(lo.depth()).max(hi.depth()),
            Self::If {
                cond,
                then_val,
                else_val,
            } => 1 + cond.depth().max(then_val.depth()).max(else_val.depth()),
        }
    }

    fn uses_multiplier(&self) -> bool {
        match self {
            Self::Scalar(ScalarField::Multiplier) => true,
            Self::Number(_) | Self::Scalar(_) | Self::ProbeLookup { .. } => false,
            Self::Unary { operand, .. } | Self::Abs(operand) => operand.uses_multiplier(),
            Self::Binary { left, right, .. } | Self::Min(left, right) | Self::Max(left, right) => {
                left.uses_multiplier() || right.uses_multiplier()
            }
            Self::Clamp { x, lo, hi } => {
                x.uses_multiplier() || lo.uses_multiplier() || hi.uses_multiplier()
            }
            Self::If {
                cond,
                then_val,
                else_val,
            } => cond.uses_multiplier() || then_val.uses_multiplier() || else_val.uses_multiplier(),
        }
    }

    fn uses_keepalive_ok(&self) -> bool {
        match self {
            Self::Scalar(ScalarField::KeepaliveOk) => true,
            Self::Number(_) | Self::Scalar(_) | Self::ProbeLookup { .. } => false,
            Self::Unary { operand, .. } | Self::Abs(operand) => operand.uses_keepalive_ok(),
            Self::Binary { left, right, .. } | Self::Min(left, right) | Self::Max(left, right) => {
                left.uses_keepalive_ok() || right.uses_keepalive_ok()
            }
            Self::Clamp { x, lo, hi } => {
                x.uses_keepalive_ok() || lo.uses_keepalive_ok() || hi.uses_keepalive_ok()
            }
            Self::If {
                cond,
                then_val,
                else_val,
            } => {
                cond.uses_keepalive_ok()
                    || then_val.uses_keepalive_ok()
                    || else_val.uses_keepalive_ok()
            }
        }
    }
}

// ============================================================================
// Lexer
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum TokenKind {
    Number(f64),
    Str(String),
    Ident(String),
    LParen,
    RParen,
    Comma,
    Plus,
    Minus,
    Star,
    Slash,
    Bang,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Eof,
}

impl TokenKind {
    fn describe(&self) -> &'static str {
        match self {
            Self::Number(_) => "number",
            Self::Str(_) => "string",
            Self::Ident(_) => "identifier",
            Self::LParen => "(",
            Self::RParen => ")",
            Self::Comma => ",",
            Self::Plus => "+",
            Self::Minus => "-",
            Self::Star => "*",
            Self::Slash => "/",
            Self::Bang => "!",
            Self::EqEq => "==",
            Self::NotEq => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::AndAnd => "&&",
            Self::OrOr => "||",
            Self::Eof => "<eof>",
        }
    }
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    pos: usize,
}

fn tokenize(input: &str) -> CatResult<Vec<Token>> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut tokens = Vec::with_capacity(len / 2 + 1);

    while i < len {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        let start = i;
        match b {
            b'(' => {
                tokens.push(Token {
                    kind: TokenKind::LParen,
                    pos: start,
                });
                i += 1;
            }
            b')' => {
                tokens.push(Token {
                    kind: TokenKind::RParen,
                    pos: start,
                });
                i += 1;
            }
            b',' => {
                tokens.push(Token {
                    kind: TokenKind::Comma,
                    pos: start,
                });
                i += 1;
            }
            b'+' => {
                tokens.push(Token {
                    kind: TokenKind::Plus,
                    pos: start,
                });
                i += 1;
            }
            b'-' => {
                tokens.push(Token {
                    kind: TokenKind::Minus,
                    pos: start,
                });
                i += 1;
            }
            b'*' => {
                tokens.push(Token {
                    kind: TokenKind::Star,
                    pos: start,
                });
                i += 1;
            }
            b'/' => {
                tokens.push(Token {
                    kind: TokenKind::Slash,
                    pos: start,
                });
                i += 1;
            }
            b'!' => {
                if i + 1 < len && bytes[i + 1] == b'=' {
                    tokens.push(Token {
                        kind: TokenKind::NotEq,
                        pos: start,
                    });
                    i += 2;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Bang,
                        pos: start,
                    });
                    i += 1;
                }
            }
            b'=' => {
                if i + 1 < len && bytes[i + 1] == b'=' {
                    tokens.push(Token {
                        kind: TokenKind::EqEq,
                        pos: start,
                    });
                    i += 2;
                } else {
                    return Err(CatError::Formula(format!(
                        "unexpected single '=' at byte offset {} (use '==' for equality)",
                        start
                    )));
                }
            }
            b'<' => {
                if i + 1 < len && bytes[i + 1] == b'=' {
                    tokens.push(Token {
                        kind: TokenKind::Le,
                        pos: start,
                    });
                    i += 2;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Lt,
                        pos: start,
                    });
                    i += 1;
                }
            }
            b'>' => {
                if i + 1 < len && bytes[i + 1] == b'=' {
                    tokens.push(Token {
                        kind: TokenKind::Ge,
                        pos: start,
                    });
                    i += 2;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Gt,
                        pos: start,
                    });
                    i += 1;
                }
            }
            b'&' => {
                if i + 1 < len && bytes[i + 1] == b'&' {
                    tokens.push(Token {
                        kind: TokenKind::AndAnd,
                        pos: start,
                    });
                    i += 2;
                } else {
                    return Err(CatError::Formula(format!(
                        "unexpected single '&' at byte offset {} (use '&&' for logical AND)",
                        start
                    )));
                }
            }
            b'|' => {
                if i + 1 < len && bytes[i + 1] == b'|' {
                    tokens.push(Token {
                        kind: TokenKind::OrOr,
                        pos: start,
                    });
                    i += 2;
                } else {
                    return Err(CatError::Formula(format!(
                        "unexpected single '|' at byte offset {} (use '||' for logical OR)",
                        start
                    )));
                }
            }
            b'"' | b'\'' => {
                let quote = b;
                i += 1;
                let mut value = String::new();
                let mut closed = false;
                while i < len {
                    let ch_byte = bytes[i];
                    if ch_byte == quote {
                        i += 1;
                        closed = true;
                        break;
                    }
                    if ch_byte == b'\\' {
                        if i + 1 >= len {
                            return Err(CatError::Formula(format!(
                                "unterminated escape sequence in string literal at byte offset {}",
                                start
                            )));
                        }
                        let next_byte = bytes[i + 1];
                        match next_byte {
                            b'\\' => value.push('\\'),
                            b'"' => value.push('"'),
                            b'\'' => value.push('\''),
                            _ => {
                                return Err(CatError::Formula(format!(
                                    "unsupported escape '\\{}' in string literal at byte offset {}",
                                    next_byte as char, i
                                )));
                            }
                        }
                        i += 2;
                        continue;
                    }
                    // Decode UTF-8 scalar safely from remaining slice.
                    let rest = &input[i..];
                    let ch = rest.chars().next().ok_or_else(|| {
                        CatError::Formula(format!(
                            "invalid UTF-8 in string literal at byte offset {}",
                            i
                        ))
                    })?;
                    if ch.is_control() {
                        return Err(CatError::Formula(format!(
                            "control characters are not permitted inside string literal at byte offset {}",
                            i
                        )));
                    }
                    value.push(ch);
                    i += ch.len_utf8();
                }
                if !closed {
                    return Err(CatError::Formula(format!(
                        "unterminated string literal starting at byte offset {}",
                        start
                    )));
                }
                tokens.push(Token {
                    kind: TokenKind::Str(value),
                    pos: start,
                });
            }
            b'0'..=b'9' => {
                while i < len && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i < len && bytes[i] == b'.' {
                    if i + 1 < len && bytes[i + 1].is_ascii_digit() {
                        i += 1;
                        while i < len && bytes[i].is_ascii_digit() {
                            i += 1;
                        }
                    } else {
                        return Err(CatError::Formula(format!(
                            "malformed numeric literal with trailing dot at byte offset {}",
                            start
                        )));
                    }
                }
                if i < len && (bytes[i] == b'e' || bytes[i] == b'E') {
                    i += 1;
                    if i < len && (bytes[i] == b'+' || bytes[i] == b'-') {
                        i += 1;
                    }
                    let exp_start = i;
                    while i < len && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i == exp_start {
                        return Err(CatError::Formula(format!(
                            "malformed exponent in numeric literal at byte offset {}",
                            start
                        )));
                    }
                }
                // Reject numbers immediately glued to identifier chars (e.g. `123abc`).
                if i < len && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
                    return Err(CatError::Formula(format!(
                        "unexpected character '{}' after numeric literal at byte offset {}",
                        bytes[i] as char, i
                    )));
                }
                let raw = &input[start..i];
                let num: f64 = raw.parse().map_err(|_| {
                    CatError::Formula(format!(
                        "invalid numeric literal `{}` at byte offset {}",
                        raw, start
                    ))
                })?;
                if !num.is_finite() {
                    return Err(CatError::Formula(format!(
                        "numeric literal `{}` overflows finite f64 at byte offset {}",
                        raw, start
                    )));
                }
                tokens.push(Token {
                    kind: TokenKind::Number(num),
                    pos: start,
                });
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let ident = input[start..i].to_string();
                tokens.push(Token {
                    kind: TokenKind::Ident(ident),
                    pos: start,
                });
            }
            _ => {
                let bad_ch = input[i..].chars().next().unwrap_or('?');
                return Err(CatError::Formula(format!(
                    "unexpected character '{}' at byte offset {}",
                    bad_ch, start
                )));
            }
        }
    }

    tokens.push(Token {
        kind: TokenKind::Eof,
        pos: len,
    });
    Ok(tokens)
}

// ============================================================================
// Recursive-descent parser
// ============================================================================

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    node_count: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self {
            tokens,
            pos: 0,
            node_count: 0,
        }
    }

    fn peek(&self) -> &'a Token {
        self.tokens
            .get(self.pos)
            .unwrap_or_else(|| self.tokens.last().expect("token stream always ends with Eof"))
    }

    fn is_at_end(&self) -> bool {
        matches!(self.peek().kind, TokenKind::Eof)
    }

    fn advance(&mut self) -> &'a Token {
        let tok = self.peek();
        if !matches!(tok.kind, TokenKind::Eof) {
            self.pos += 1;
        }
        tok
    }

    fn count_node(&mut self) -> CatResult<()> {
        self.node_count += 1;
        if self.node_count > MAX_AST_NODES {
            return Err(CatError::Formula(format!(
                "formula exceeds maximum AST node budget ({})",
                MAX_AST_NODES
            )));
        }
        Ok(())
    }

    fn check_depth(depth: usize) -> CatResult<()> {
        if depth > MAX_AST_DEPTH {
            return Err(CatError::Formula(format!(
                "formula nesting depth exceeds maximum allowed ({})",
                MAX_AST_DEPTH
            )));
        }
        Ok(())
    }

    fn parse_expr(&mut self, depth: usize) -> CatResult<Expr> {
        Self::check_depth(depth)?;
        self.parse_or(depth)
    }

    fn parse_or(&mut self, depth: usize) -> CatResult<Expr> {
        let mut left = self.parse_and(depth)?;
        while matches!(self.peek().kind, TokenKind::OrOr) {
            self.advance();
            let right = self.parse_and(depth)?;
            self.count_node()?;
            left = Expr::Binary {
                op: BinaryOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self, depth: usize) -> CatResult<Expr> {
        let mut left = self.parse_equality(depth)?;
        while matches!(self.peek().kind, TokenKind::AndAnd) {
            self.advance();
            let right = self.parse_equality(depth)?;
            self.count_node()?;
            left = Expr::Binary {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_equality(&mut self, depth: usize) -> CatResult<Expr> {
        let mut left = self.parse_comparison(depth)?;
        loop {
            let op = match self.peek().kind {
                TokenKind::EqEq => BinaryOp::Eq,
                TokenKind::NotEq => BinaryOp::Ne,
                _ => break,
            };
            self.advance();
            let right = self.parse_comparison(depth)?;
            self.count_node()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_comparison(&mut self, depth: usize) -> CatResult<Expr> {
        let mut left = self.parse_additive(depth)?;
        loop {
            let op = match self.peek().kind {
                TokenKind::Lt => BinaryOp::Lt,
                TokenKind::Le => BinaryOp::Le,
                TokenKind::Gt => BinaryOp::Gt,
                TokenKind::Ge => BinaryOp::Ge,
                _ => break,
            };
            self.advance();
            let right = self.parse_additive(depth)?;
            self.count_node()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_additive(&mut self, depth: usize) -> CatResult<Expr> {
        let mut left = self.parse_multiplicative(depth)?;
        loop {
            let op = match self.peek().kind {
                TokenKind::Plus => BinaryOp::Add,
                TokenKind::Minus => BinaryOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_multiplicative(depth)?;
            self.count_node()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_multiplicative(&mut self, depth: usize) -> CatResult<Expr> {
        let mut left = self.parse_unary(depth)?;
        loop {
            let op = match self.peek().kind {
                TokenKind::Star => BinaryOp::Mul,
                TokenKind::Slash => BinaryOp::Div,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary(depth)?;
            self.count_node()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self, depth: usize) -> CatResult<Expr> {
        Self::check_depth(depth)?;
        match self.peek().kind {
            TokenKind::Minus => {
                self.advance();
                let operand = self.parse_unary(depth + 1)?;
                self.count_node()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Neg,
                    operand: Box::new(operand),
                })
            }
            TokenKind::Bang => {
                self.advance();
                let operand = self.parse_unary(depth + 1)?;
                self.count_node()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                })
            }
            _ => self.parse_primary(depth),
        }
    }

    fn parse_primary(&mut self, depth: usize) -> CatResult<Expr> {
        Self::check_depth(depth)?;
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Number(n) => {
                self.advance();
                self.count_node()?;
                Ok(Expr::Number(n))
            }
            TokenKind::LParen => {
                self.advance();
                let inner = self.parse_expr(depth + 1)?;
                if !matches!(self.peek().kind, TokenKind::RParen) {
                    return Err(CatError::Formula(format!(
                        "expected ')' to close '(' opened at byte offset {}",
                        tok.pos
                    )));
                }
                self.advance();
                Ok(inner)
            }
            TokenKind::Ident(ident) => {
                self.advance();
                if matches!(self.peek().kind, TokenKind::LParen) {
                    self.parse_function_call(&ident, tok.pos, depth + 1)
                } else {
                    self.count_node()?;
                    match ident.as_str() {
                        "true" => Ok(Expr::Number(1.0)),
                        "false" => Ok(Expr::Number(0.0)),
                        _ => {
                            let field = ScalarField::from_ident(&ident).ok_or_else(|| {
                                CatError::Formula(format!(
                                    "unknown identifier `{}` at byte offset {}",
                                    ident, tok.pos
                                ))
                            })?;
                            Ok(Expr::Scalar(field))
                        }
                    }
                }
            }
            TokenKind::Str(_) => Err(CatError::Formula(format!(
                "string literals are only allowed as arguments to probe/site lookup functions (byte offset {})",
                tok.pos
            ))),
            _ => Err(CatError::Formula(format!(
                "unexpected token `{}` at byte offset {}",
                tok.kind.describe(),
                tok.pos
            ))),
        }
    }

    fn parse_function_call(
        &mut self,
        name: &str,
        pos: usize,
        depth: usize,
    ) -> CatResult<Expr> {
        Self::check_depth(depth)?;
        // Consume '('
        self.advance();

        match name {
            "probe_up" | "probe_down" | "probe_ping" | "probe_ok" | "site_unlocked" => {
                let kind = match name {
                    "probe_up" => ProbeLookupKind::Up,
                    "probe_down" => ProbeLookupKind::Down,
                    "probe_ping" => ProbeLookupKind::Ping,
                    "probe_ok" => ProbeLookupKind::Ok,
                    _ => ProbeLookupKind::SiteUnlocked,
                };
                let key = match self.peek().kind.clone() {
                    TokenKind::Str(s) => {
                        self.advance();
                        s
                    }
                    _ => {
                        return Err(CatError::Formula(format!(
                            "function `{}` expects a string literal argument at byte offset {}",
                            name, pos
                        )));
                    }
                };
                if key.trim().is_empty() {
                    return Err(CatError::Formula(format!(
                        "function `{}` argument cannot be empty at byte offset {}",
                        name, pos
                    )));
                }
                if !matches!(self.peek().kind, TokenKind::RParen) {
                    return Err(CatError::Formula(format!(
                        "function `{}` takes exactly 1 string argument (byte offset {})",
                        name, pos
                    )));
                }
                self.advance();
                self.count_node()?;
                Ok(Expr::ProbeLookup { kind, key })
            }
            "abs" | "min" | "max" | "clamp" | "if" => {
                let expected_arity = match name {
                    "abs" => 1,
                    "min" | "max" => 2,
                    "clamp" | "if" => 3,
                    _ => unreachable!(),
                };
                let mut args = Vec::with_capacity(expected_arity);
                if !matches!(self.peek().kind, TokenKind::RParen) {
                    loop {
                        args.push(self.parse_expr(depth)?);
                        if matches!(self.peek().kind, TokenKind::Comma) {
                            self.advance();
                            continue;
                        }
                        break;
                    }
                }
                if !matches!(self.peek().kind, TokenKind::RParen) {
                    return Err(CatError::Formula(format!(
                        "expected ')' after arguments to `{}` at byte offset {}",
                        name, pos
                    )));
                }
                self.advance();
                if args.len() != expected_arity {
                    return Err(CatError::Formula(format!(
                        "function `{}` expects {} argument(s), got {} at byte offset {}",
                        name,
                        expected_arity,
                        args.len(),
                        pos
                    )));
                }
                self.count_node()?;
                let mut iter = args.into_iter();
                match name {
                    "abs" => Ok(Expr::Abs(Box::new(iter.next().expect("arity checked")))),
                    "min" => Ok(Expr::Min(
                        Box::new(iter.next().expect("arity checked")),
                        Box::new(iter.next().expect("arity checked")),
                    )),
                    "max" => Ok(Expr::Max(
                        Box::new(iter.next().expect("arity checked")),
                        Box::new(iter.next().expect("arity checked")),
                    )),
                    "clamp" => Ok(Expr::Clamp {
                        x: Box::new(iter.next().expect("arity checked")),
                        lo: Box::new(iter.next().expect("arity checked")),
                        hi: Box::new(iter.next().expect("arity checked")),
                    }),
                    "if" => Ok(Expr::If {
                        cond: Box::new(iter.next().expect("arity checked")),
                        then_val: Box::new(iter.next().expect("arity checked")),
                        else_val: Box::new(iter.next().expect("arity checked")),
                    }),
                    _ => unreachable!(),
                }
            }
            _ => Err(CatError::Formula(format!(
                "unknown or disallowed function `{}` at byte offset {}",
                name, pos
            ))),
        }
    }
}

// ============================================================================
// Evaluator
// ============================================================================

fn eval_node(expr: &Expr, ctx: &EvalContext, depth: usize) -> CatResult<f64> {
    if depth > MAX_AST_DEPTH {
        return Err(CatError::Formula(format!(
            "evaluation depth exceeds maximum allowed ({})",
            MAX_AST_DEPTH
        )));
    }
    match expr {
        Expr::Number(n) => Ok(sanitize_f64(*n)),
        Expr::Scalar(field) => Ok(ctx.lookup_scalar(*field)),
        Expr::ProbeLookup { kind, key } => Ok(match kind {
            ProbeLookupKind::Up => ctx.lookup_probe_up(key),
            ProbeLookupKind::Down => ctx.lookup_probe_down(key),
            ProbeLookupKind::Ping => ctx.lookup_probe_ping(key),
            ProbeLookupKind::Ok => ctx.lookup_probe_ok(key),
            ProbeLookupKind::SiteUnlocked => ctx.lookup_site_unlocked(key),
        }),
        Expr::Unary { op, operand } => {
            let val = eval_node(operand, ctx, depth + 1)?;
            Ok(match op {
                UnaryOp::Neg => sanitize_f64(-val),
                UnaryOp::Not => bool_to_f64(!is_truthy(val)),
            })
        }
        Expr::Binary { op, left, right } => match op {
            BinaryOp::And => {
                let lhs = eval_node(left, ctx, depth + 1)?;
                if !is_truthy(lhs) {
                    return Ok(0.0);
                }
                let rhs = eval_node(right, ctx, depth + 1)?;
                Ok(bool_to_f64(is_truthy(rhs)))
            }
            BinaryOp::Or => {
                let lhs = eval_node(left, ctx, depth + 1)?;
                if is_truthy(lhs) {
                    return Ok(1.0);
                }
                let rhs = eval_node(right, ctx, depth + 1)?;
                Ok(bool_to_f64(is_truthy(rhs)))
            }
            _ => {
                let lhs = eval_node(left, ctx, depth + 1)?;
                let rhs = eval_node(right, ctx, depth + 1)?;
                Ok(match op {
                    BinaryOp::Add => sanitize_f64(lhs + rhs),
                    BinaryOp::Sub => sanitize_f64(lhs - rhs),
                    BinaryOp::Mul => sanitize_f64(lhs * rhs),
                    BinaryOp::Div => safe_div(lhs, rhs),
                    BinaryOp::Eq => bool_to_f64((lhs - rhs).abs() <= EPSILON_EQ),
                    BinaryOp::Ne => bool_to_f64((lhs - rhs).abs() > EPSILON_EQ),
                    BinaryOp::Lt => bool_to_f64(lhs < rhs - EPSILON_EQ),
                    BinaryOp::Le => bool_to_f64(lhs <= rhs + EPSILON_EQ),
                    BinaryOp::Gt => bool_to_f64(lhs > rhs + EPSILON_EQ),
                    BinaryOp::Ge => bool_to_f64(lhs >= rhs - EPSILON_EQ),
                    BinaryOp::And | BinaryOp::Or => unreachable!(),
                })
            }
        },
        Expr::Abs(inner) => Ok(sanitize_f64(eval_node(inner, ctx, depth + 1)?.abs())),
        Expr::Min(a, b) => {
            let va = eval_node(a, ctx, depth + 1)?;
            let vb = eval_node(b, ctx, depth + 1)?;
            Ok(sanitize_f64(va.min(vb)))
        }
        Expr::Max(a, b) => {
            let va = eval_node(a, ctx, depth + 1)?;
            let vb = eval_node(b, ctx, depth + 1)?;
            Ok(sanitize_f64(va.max(vb)))
        }
        Expr::Clamp { x, lo, hi } => {
            let vx = eval_node(x, ctx, depth + 1)?;
            let vlo = eval_node(lo, ctx, depth + 1)?;
            let vhi = eval_node(hi, ctx, depth + 1)?;
            let (low, high) = if vlo <= vhi { (vlo, vhi) } else { (vhi, vlo) };
            Ok(sanitize_f64(vx.max(low).min(high)))
        }
        Expr::If {
            cond,
            then_val,
            else_val,
        } => {
            let vc = eval_node(cond, ctx, depth + 1)?;
            if is_truthy(vc) {
                eval_node(then_val, ctx, depth + 1)
            } else {
                eval_node(else_val, ctx, depth + 1)
            }
        }
    }
}

#[inline]
fn bool_to_f64(v: bool) -> f64 {
    if v { 1.0 } else { 0.0 }
}

#[inline]
fn is_truthy(v: f64) -> bool {
    v.is_finite() && v.abs() > EPSILON_ZERO
}

#[inline]
fn sanitize_f64(v: f64) -> f64 {
    if !v.is_finite() || v == 0.0 {
        0.0
    } else {
        v
    }
}

#[inline]
fn safe_div(lhs: f64, rhs: f64) -> f64 {
    if !rhs.is_finite() || rhs.abs() <= EPSILON_ZERO {
        0.0
    } else {
        sanitize_f64(lhs / rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_unlocked_aliases_google_ai_gemini_and_gemini_aistudio() {
        let expr_google_ai = FormulaExpr::parse(r#"site_unlocked("google_ai")"#).unwrap();
        let expr_google_ai_ci = FormulaExpr::parse(r#"site_unlocked("Google_AI")"#).unwrap();
        let expr_gemini = FormulaExpr::parse(r#"site_unlocked("gemini")"#).unwrap();
        let expr_aistudio = FormulaExpr::parse(r#"site_unlocked("gemini_aistudio")"#).unwrap();
        let expr_claude = FormulaExpr::parse(r#"site_unlocked("claude")"#).unwrap();

        // 1. Only "gemini" present -> google_ai and gemini_aistudio fall back to "gemini".
        let mut ctx_gemini_only = EvalContext::default();
        ctx_gemini_only
            .unlocked_sites
            .insert("gemini".to_string(), true);
        assert!(expr_google_ai.eval_bool(&ctx_gemini_only).unwrap());
        assert!(expr_google_ai_ci.eval_bool(&ctx_gemini_only).unwrap());
        assert!(expr_gemini.eval_bool(&ctx_gemini_only).unwrap());
        assert!(expr_aistudio.eval_bool(&ctx_gemini_only).unwrap());
        assert!(!expr_claude.eval_bool(&ctx_gemini_only).unwrap());

        // 2. Only "gemini_aistudio" present -> google_ai and gemini both fall back to it.
        let mut ctx_aistudio_only = EvalContext::default();
        ctx_aistudio_only
            .unlocked_sites
            .insert("gemini_aistudio".to_string(), true);
        assert!(expr_google_ai.eval_bool(&ctx_aistudio_only).unwrap());
        assert!(expr_gemini.eval_bool(&ctx_aistudio_only).unwrap());
        assert!(expr_aistudio.eval_bool(&ctx_aistudio_only).unwrap());

        // 3. Only "google_ai" present -> gemini and gemini_aistudio both fall back to it.
        let mut ctx_google_ai_only = EvalContext::default();
        ctx_google_ai_only
            .unlocked_sites
            .insert("google_ai".to_string(), true);
        assert!(expr_google_ai.eval_bool(&ctx_google_ai_only).unwrap());
        assert!(expr_gemini.eval_bool(&ctx_google_ai_only).unwrap());
        assert!(expr_aistudio.eval_bool(&ctx_google_ai_only).unwrap());

        // 4. Direct match always takes precedence over fallback aliases.
        let mut ctx_direct_override = EvalContext::default();
        ctx_direct_override
            .unlocked_sites
            .insert("google_ai".to_string(), false);
        ctx_direct_override
            .unlocked_sites
            .insert("gemini".to_string(), true);
        assert!(!expr_google_ai.eval_bool(&ctx_direct_override).unwrap());
        assert!(expr_gemini.eval_bool(&ctx_direct_override).unwrap());

        // 5. Fallback priority for "google_ai": "gemini" before "gemini_aistudio".
        let mut ctx_priority = EvalContext::default();
        ctx_priority
            .unlocked_sites
            .insert("gemini".to_string(), false);
        ctx_priority
            .unlocked_sites
            .insert("gemini_aistudio".to_string(), true);
        assert!(!expr_google_ai.eval_bool(&ctx_priority).unwrap());
    }

    #[test]
    fn probe_lookups_fall_back_to_generic_metrics_when_probe_name_absent() {
        let mut ctx = EvalContext {
            up_mbps: 18.5,
            down_mbps: 240.0,
            ping_ms: 48.0,
            ok: true,
            ..Default::default()
        };
        ctx.per_probe_up_mbps
            .insert("builtin_upload".to_string(), 18.5);
        ctx.per_probe_down_mbps
            .insert("builtin_download".to_string(), 240.0);
        ctx.per_probe_ping_ms
            .insert("builtin_latency".to_string(), 48.0);

        // Missing legacy probe name ("antigravity") falls back gracefully to node generic metrics.
        let trigger = FormulaExpr::parse(r#"probe_up("antigravity") < 2.0"#).unwrap();
        assert!(!trigger.eval_bool(&ctx).unwrap());

        let up_expr = FormulaExpr::parse(r#"probe_up("antigravity")"#).unwrap();
        let down_expr = FormulaExpr::parse(r#"probe_down("antigravity")"#).unwrap();
        let ping_expr = FormulaExpr::parse(r#"probe_ping("antigravity")"#).unwrap();
        assert!((up_expr.eval_f64(&ctx).unwrap() - 18.5).abs() < 1e-9);
        assert!((down_expr.eval_f64(&ctx).unwrap() - 240.0).abs() < 1e-9);
        assert!((ping_expr.eval_f64(&ctx).unwrap() - 48.0).abs() < 1e-9);

        // Explicit per-probe entry always takes precedence over generic fallback (even if low/0).
        ctx.per_probe_up_mbps.insert("antigravity".to_string(), 0.4);
        assert!(trigger.eval_bool(&ctx).unwrap());
        assert!((up_expr.eval_f64(&ctx).unwrap() - 0.4).abs() < 1e-9);

        // When generic metrics are also absent, up/down return 0.0 and ping returns missing sentinel.
        let empty = EvalContext::default();
        assert_eq!(up_expr.eval_f64(&empty).unwrap(), 0.0);
        assert_eq!(down_expr.eval_f64(&empty).unwrap(), 0.0);
        assert_eq!(ping_expr.eval_f64(&empty).unwrap(), DEFAULT_MISSING_PING_MS);

        // `uses_keepalive_ok` AST inspection accurately distinguishes keepalive gates.
        assert!(FormulaExpr::parse("keepalive_ok == 1").unwrap().uses_keepalive_ok());
        assert!(
            FormulaExpr::parse("google_clean == 1 && keepalive_ok == 1")
                .unwrap()
                .uses_keepalive_ok()
        );
        assert!(!FormulaExpr::parse("google_clean == 1").unwrap().uses_keepalive_ok());
    }
}
