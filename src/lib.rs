//! `peek` — a modern, human-friendly replacement for `lsof`.
//!
//! This library crate exposes the platform-specific lookup functions used
//! by the `peek` binary. See [`platform::macos`] for the macOS implementation.

pub mod error;
pub mod platform;

pub use error::PeekError;
