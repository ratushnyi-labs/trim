//! Instruction decoding layer for native binary formats.
//!
//! Provides call graph construction from decoded instructions,
//! function boundary inference for stripped binaries, and data
//! section scanning for embedded code pointers. These modules
//! bridge the architecture-specific decoders (`src/arch/`) with
//! the format-agnostic analysis engine (`src/analysis/`).

pub mod callgraph;
pub mod infer;
pub mod scan;
