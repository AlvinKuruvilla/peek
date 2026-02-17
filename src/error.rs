//! Structured error type for `peek` lookup operations.

use std::path::PathBuf;

/// Errors returned by the platform lookup functions.
#[derive(Debug, thiserror::Error)]
pub enum PeekError {
    /// Failed to enumerate system sockets (port lookup).
    #[error("Failed to enumerate sockets: {0}")]
    SocketEnum(String),

    /// Could not inspect a process (pid lookup).
    #[error("Cannot inspect PID {pid}: {reason}")]
    PidInspect { pid: u32, reason: String },

    /// Could not list file descriptors for a process (pid lookup).
    #[error("Cannot list FDs for PID {pid}: {reason}")]
    FdList { pid: u32, reason: String },

    /// The requested file does not exist (file lookup).
    #[error("No such file: {}", .0.display())]
    NoSuchFile(PathBuf),

    /// Could not canonicalize a file path (file lookup).
    #[error("Cannot resolve path {}: {source}", path.display())]
    PathResolve {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Could not list processes that have a file open (file lookup).
    #[error("Cannot list processes for {}: {reason}", path.display())]
    ProcessList { path: PathBuf, reason: String },
}
