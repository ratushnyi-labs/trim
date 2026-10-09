//! Shared patching utilities for binary compaction.
//!
//! Provides format-agnostic routines used by ELF, PE, and Mach-O
//! compaction: physical text compaction, data pointer patching,
//! relocation interval arithmetic, 32-bit self-relative pointers, and
//! dead-region zero-filling.

pub mod compact;
pub mod data_ptrs;
pub mod relocs;
pub mod relptr;
pub mod zerofill;
