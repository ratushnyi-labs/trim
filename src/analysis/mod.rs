//! Static analysis engine for dead-code detection.
//!
//! Provides control-flow graph construction, dominator tree computation,
//! SSA form construction, sparse conditional constant propagation (SCCP),
//! BFS reachability analysis, and noreturn function detection. These
//! modules work together to identify both dead functions (unreachable
//! from roots) and dead branches (statically resolved conditionals).

pub mod cfg;
pub mod dominance;
pub mod lattice;
pub mod noreturn;
pub mod reachability;
pub mod regstate;
pub mod roots;
pub mod sccp;
pub mod ssa;
