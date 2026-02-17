//! macOS implementation using [`libproc`] and [`netstat2`].
//!
//! - **Port lookup** uses [`netstat2`] to enumerate sockets and match on local port.
//! - **PID lookup** uses [`libproc`] to list file descriptors via `proc_pidinfo`,
//!   then resolves vnode paths through a small FFI call to `proc_pidfdinfo`
//!   with `PROC_PIDFDVNODEPATHINFO` (not exposed by the `libproc` crate).
//! - **File lookup** uses [`libproc`]'s `listpidspath` to find processes with
//!   a given file open.

mod ffi;

use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid::{listpidinfo, pidinfo, pidpath};
use libproc::libproc::task_info::TaskAllInfo;
use libproc::processes;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};
use std::path::Path;
use std::process;

/// A single result row from a port lookup.
///
/// Each entry represents one `(socket, pid)` pair — a process that has a
/// socket bound to the queried port.
pub struct PortEntry {
    /// OS process identifier.
    pub pid: u32,
    /// Short process name (basename of the executable).
    pub process_name: String,
    /// Username of the process owner.
    pub user: String,
    /// Transport protocol (`"TCP"` or `"UDP"`).
    pub protocol: String,
    /// Local address the socket is bound to.
    pub local_addr: String,
    /// Local port number.
    pub local_port: u16,
    /// Remote address (or `"*"` for unconnected sockets).
    pub remote_addr: String,
    /// Remote port number (or `0` for unconnected sockets).
    pub remote_port: u16,
    /// TCP state (e.g. `"LISTEN"`, `"ESTABLISHED"`) or `"-"` for UDP.
    pub state: String,
}

/// Returns all processes that have a socket bound to `port`.
///
/// Queries both IPv4 and IPv6 across TCP and UDP.
///
/// # Errors
///
/// Returns `Err` if the underlying socket enumeration fails.
///
/// # Examples
///
/// An unused port returns an empty list:
///
/// ```
/// use peek::platform::macos;
///
/// let entries = macos::port_lookup(1).unwrap(); // port 1 is almost certainly unused
/// // May or may not be empty depending on the system, but should not panic.
/// ```
///
/// Inspecting a bound port:
///
/// ```no_run
/// use peek::platform::macos;
///
/// let entries = macos::port_lookup(8080).unwrap();
/// for entry in &entries {
///     println!("{} (PID {}) on {}:{}", entry.process_name, entry.pid, entry.local_addr, entry.local_port);
/// }
/// ```
pub fn port_lookup(port: u16) -> Result<Vec<PortEntry>, String> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets = get_sockets_info(af_flags, proto_flags)
        .map_err(|e| format!("Failed to enumerate sockets: {e}"))?;

    let mut entries = Vec::new();

    for socket in sockets {
        if socket.local_port() != port {
            continue;
        }

        for &pid in &socket.associated_pids {
            let (protocol, local_addr, local_port, remote_addr, remote_port, state) =
                match &socket.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(tcp) => (
                        "TCP".to_string(),
                        tcp.local_addr.to_string(),
                        tcp.local_port,
                        tcp.remote_addr.to_string(),
                        tcp.remote_port,
                        format_tcp_state(&tcp.state),
                    ),
                    ProtocolSocketInfo::Udp(udp) => (
                        "UDP".to_string(),
                        udp.local_addr.to_string(),
                        udp.local_port,
                        "*".to_string(),
                        0,
                        "-".to_string(),
                    ),
                };

            let (process_name, user) = process_info_for_pid(pid);

            entries.push(PortEntry {
                pid,
                process_name,
                user,
                protocol,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
            });
        }
    }

    Ok(entries)
}

/// A single open file descriptor belonging to a process.
pub struct FDEntry {
    /// The numeric file descriptor (e.g. `0` for stdin).
    pub fd: i32,
    /// Human-readable type label (`"FILE"`, `"SOCK"`, `"PIPE"`, etc.).
    pub fd_type: String,
    /// Extra detail: file path for vnodes, protocol/port for sockets, or `"-"`.
    pub detail: String,
}

/// Lists all open file descriptors for the given `pid`.
///
/// For each FD, resolves the type and — where possible — a human-readable
/// detail string (file path for vnodes, protocol and port for sockets).
///
/// # Errors
///
/// Returns `Err` if the process does not exist, has exited, or the caller
/// lacks permission to inspect it.
///
/// # Examples
///
/// Inspecting the current process always succeeds:
///
/// ```
/// use peek::platform::macos;
///
/// let pid = std::process::id();
/// let fds = macos::pid_lookup(pid).expect("should be able to inspect own process");
/// assert!(!fds.is_empty(), "a running process always has open FDs");
/// ```
///
/// A nonexistent PID returns an error:
///
/// ```
/// use peek::platform::macos;
///
/// let result = macos::pid_lookup(u32::MAX);
/// assert!(result.is_err());
/// ```
pub fn pid_lookup(pid: u32) -> Result<Vec<FDEntry>, String> {
    let pid_i32 = pid as i32;

    let info = pidinfo::<TaskAllInfo>(pid_i32, 0)
        .map_err(|e| format!("Cannot inspect PID {pid}: {e}"))?;

    let fds = listpidinfo::<ListFDs>(pid_i32, info.pbsd.pbi_nfiles as usize)
        .map_err(|e| format!("Cannot list FDs for PID {pid}: {e}"))?;

    let mut entries = Vec::new();

    for fd in &fds {
        let fd_type = ProcFDType::from(fd.proc_fdtype);

        let (type_str, detail) = match fd_type {
            ProcFDType::VNode => ("FILE".to_string(), ffi::vnode_detail(pid_i32, fd.proc_fd)),
            ProcFDType::Socket => ("SOCK".to_string(), socket_detail(pid_i32, fd.proc_fd)),
            ProcFDType::Pipe => ("PIPE".to_string(), "-".to_string()),
            ProcFDType::KQueue => ("KQUEUE".to_string(), "-".to_string()),
            ProcFDType::PSHM => ("SHM".to_string(), "-".to_string()),
            ProcFDType::PSEM => ("SEM".to_string(), "-".to_string()),
            _ => (format!("{fd_type:?}"), "-".to_string()),
        };

        entries.push(FDEntry {
            fd: fd.proc_fd,
            fd_type: type_str,
            detail,
        });
    }

    Ok(entries)
}

/// A single result row from a file lookup.
///
/// Each entry represents one process that has the queried file open.
pub struct FileEntry {
    /// OS process identifier.
    pub pid: u32,
    /// Short process name (basename of the executable).
    pub process_name: String,
    /// Username of the process owner.
    pub user: String,
    /// Absolute path to the process executable (or `"?"` on failure).
    pub exe_path: String,
}

/// Returns all processes that have the file at `path` open.
///
/// Uses `libproc`'s `listpidspath` under the hood to query the kernel for
/// processes referencing the given path. Each PID is then enriched with the
/// process name, owning user, and executable path.
///
/// # Errors
///
/// Returns `Err` if the path does not exist or cannot be inspected.
///
/// # Examples
///
/// A well-known file like `/etc/hosts` can be queried without error:
///
/// ```
/// use peek::platform::macos;
///
/// // /etc/hosts exists on every macOS system.
/// let result = macos::file_lookup("/etc/hosts");
/// assert!(result.is_ok());
/// ```
///
/// A nonexistent path returns an error:
///
/// ```
/// use peek::platform::macos;
///
/// let result = macos::file_lookup("/nonexistent/file/path");
/// assert!(result.is_err());
/// ```
pub fn file_lookup(path: &str) -> Result<Vec<FileEntry>, String> {
    let path = Path::new(path);

    if !path.exists() {
        return Err(format!("No such file: {}", path.display()));
    }

    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path {}: {e}", path.display()))?;

    let pids = processes::pids_by_path(&canonical, false, false)
        .map_err(|e| format!("Cannot list processes for {}: {e}", canonical.display()))?;

    let mut entries = Vec::new();

    for pid in pids {
        let (process_name, user) = process_info_for_pid(pid);
        let exe_path = exe_path_for_pid(pid);

        entries.push(FileEntry {
            pid,
            process_name,
            user,
            exe_path,
        });
    }

    Ok(entries)
}

/// Returns a short description of a socket FD's protocol and endpoints.
///
/// For TCP sockets this looks like `"TCP *:8080 -> *:443"`, for UDP
/// `"UDP *:5353"`, and for Unix domain sockets simply `"UNIX"`.
/// Returns `"-"` if the socket info cannot be read.
fn socket_detail(pid: i32, fd: i32) -> String {
    let Ok(info) = pidfdinfo::<SocketFDInfo>(pid, fd) else {
        return "-".to_string();
    };

    let kind: SocketInfoKind = info.psi.soi_kind.into();

    match kind {
        SocketInfoKind::Tcp => {
            // SAFETY: We checked `soi_kind == Tcp`, so `pri_tcp` is the active union variant.
            let tcp = unsafe { info.psi.soi_proto.pri_tcp };
            let local_port = u16::from_be(tcp.tcpsi_ini.insi_lport as u16);
            let remote_port = u16::from_be(tcp.tcpsi_ini.insi_fport as u16);
            format!("TCP *:{local_port} -> *:{remote_port}")
        }
        SocketInfoKind::In => {
            // SAFETY: We checked `soi_kind == In`, so `pri_in` is the active union variant.
            let inp = unsafe { info.psi.soi_proto.pri_in };
            let local_port = u16::from_be(inp.insi_lport as u16);
            format!("UDP *:{local_port}")
        }
        SocketInfoKind::Un => "UNIX".to_string(),
        _ => format!("{kind:?}"),
    }
}

/// Returns `(process_name, username)` for the given `pid`.
///
/// Shells out to `ps(1)` in a single call for both fields. The process
/// name is stripped to its basename (e.g. `/usr/bin/python3` becomes
/// `"python3"`). Falls back to `("<pid N>", "?")` on any failure.
fn process_info_for_pid(pid: u32) -> (String, String) {
    let output = process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "user=,comm="])
        .output();

    let fallback = (format!("<pid {pid}>"), "?".to_string());

    let Ok(o) = output else { return fallback };
    if !o.status.success() {
        return fallback;
    }

    let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if line.is_empty() {
        return fallback;
    }

    // `ps -o user=,comm=` output format: "username /full/path/to/binary"
    let (user, comm) = match line.split_once(char::is_whitespace) {
        Some((u, c)) => (u.trim(), c.trim()),
        None => return (line, "?".to_string()),
    };

    let name = Path::new(comm)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| comm.to_string());

    (name, user.to_string())
}

/// Returns the absolute path to the executable for `pid`, or `"?"` on failure.
///
/// # Examples
///
/// ```
/// use peek::platform::macos;
///
/// let path = macos::exe_path_for_pid(std::process::id());
/// assert_ne!(path, "?", "should resolve the current process executable");
/// ```
pub fn exe_path_for_pid(pid: u32) -> String {
    pidpath(pid as i32).unwrap_or_else(|_| "?".to_string())
}

/// Returns the short process name for `pid`, or `"?"` on failure.
///
/// # Examples
///
/// ```
/// use peek::platform::macos;
///
/// let name = macos::name_for_pid(std::process::id());
/// assert_ne!(name, "?", "should resolve the current process name");
/// ```
pub fn name_for_pid(pid: u32) -> String {
    libproc::libproc::proc_pid::name(pid as i32).unwrap_or_else(|_| "?".to_string())
}

/// Converts a [`TcpState`] to its conventional uppercase string form.
fn format_tcp_state(state: &TcpState) -> String {
    match state {
        TcpState::Listen => "LISTEN".to_string(),
        TcpState::Established => "ESTABLISHED".to_string(),
        TcpState::SynSent => "SYN_SENT".to_string(),
        TcpState::SynReceived => "SYN_RECV".to_string(),
        TcpState::FinWait1 => "FIN_WAIT1".to_string(),
        TcpState::FinWait2 => "FIN_WAIT2".to_string(),
        TcpState::TimeWait => "TIME_WAIT".to_string(),
        TcpState::Closed => "CLOSED".to_string(),
        TcpState::CloseWait => "CLOSE_WAIT".to_string(),
        TcpState::LastAck => "LAST_ACK".to_string(),
        TcpState::Closing => "CLOSING".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}
