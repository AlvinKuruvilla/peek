//! Platform-specific implementations for process and socket inspection.
//!
//! Each submodule provides the same logical operations (`port_lookup`,
//! `pid_lookup`, etc.) using the native APIs available on that OS.

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;
