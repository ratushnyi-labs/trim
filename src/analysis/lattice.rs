//! Abstract value lattice for constant propagation analysis.
//!
//! Defines a three-point lattice (Bot < Const < Top) for tracking
//! register values during SCCP. Provides meet operations, binary
//! arithmetic evaluation, and comparison evaluation over lattice values.

/// Value lattice for constant propagation.
/// Bot (unreachable) < Const(i64) < Top (unknown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bot,
    Const(i64),
    Top,
}

impl Value {
    /// Lattice meet: combines two values.
    pub fn meet(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Bot, v) | (v, Value::Bot) => v.clone(),
            (Value::Top, _) | (_, Value::Top) => Value::Top,
            (Value::Const(a), Value::Const(b)) => {
                if a == b {
                    Value::Const(*a)
                } else {
                    Value::Top
                }
            }
        }
    }

    /// Returns true if this value is a known constant.
    pub fn is_const(&self) -> bool {
        matches!(self, Value::Const(_))
    }

    /// Extract the constant value, or None if Bot/Top.
    pub fn as_const(&self) -> Option<i64> {
        match self {
            Value::Const(v) => Some(*v),
            _ => None,
        }
    }
}

/// Evaluate binary arithmetic on lattice values.
pub fn eval_binop(op: BinOp, a: &Value, b: &Value) -> Value {
    match (a, b) {
        (Value::Bot, _) | (_, Value::Bot) => Value::Bot,
        (Value::Top, _) | (_, Value::Top) => Value::Top,
        (Value::Const(x), Value::Const(y)) => {
            compute_binop(op, *x, *y)
        }
    }
}

/// Evaluate a concrete binary operation using wrapping arithmetic.
fn compute_binop(op: BinOp, x: i64, y: i64) -> Value {
    let result = match op {
        BinOp::Add => x.wrapping_add(y),
        BinOp::Sub => x.wrapping_sub(y),
        BinOp::And => x & y,
        BinOp::Or => x | y,
        BinOp::Xor => x ^ y,
        BinOp::Shl => x.wrapping_shl(y as u32),
        BinOp::Shr => (x as u64).wrapping_shr(y as u32) as i64,
        BinOp::Sar => x.wrapping_shr(y as u32),
        BinOp::Mul => x.wrapping_mul(y),
    };
    Value::Const(result)
}

/// Evaluate a comparison on lattice values.
pub fn eval_cmp(cc: CondCode, a: &Value, b: &Value) -> Value {
    match (a, b) {
        (Value::Bot, _) | (_, Value::Bot) => Value::Bot,
        (Value::Top, _) | (_, Value::Top) => Value::Top,
        (Value::Const(x), Value::Const(y)) => {
            let r = compare(*x, *y, cc);
            Value::Const(if r { 1 } else { 0 })
        }
    }
}

/// Evaluate a concrete comparison between two integer values.
fn compare(x: i64, y: i64, cc: CondCode) -> bool {
    match cc {
        CondCode::Eq => x == y,
        CondCode::Ne => x != y,
        CondCode::Lt => x < y,
        CondCode::Ge => x >= y,
        CondCode::Le => x <= y,
        CondCode::Gt => x > y,
        CondCode::Ltu => (x as u64) < (y as u64),
        CondCode::Geu => (x as u64) >= (y as u64),
    }
}

/// Binary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Mul,
}

/// Condition codes for comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondCode {
    Eq,
    Ne,
    Lt,
    Ge,
    Le,
    Gt,
    Ltu,
    Geu,
}
