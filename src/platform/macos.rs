//! macOS implementation using [`libproc`] and [`netstat2`].
//!
//! - **Port lookup** uses [`netstat2`] to enumerate sockets and match on local port.
//! - **PID lookup** uses [`libproc`] to list file descriptors via `proc_pidinfo`,
//!   then resolves vnode paths through a small FFI call to `proc_pidfdinfo`
//!   with `PROC_PIDFDVNODEPATHINFO` (not exposed by the `libproc` crate).

use libc::{c_char, c_int, c_void, gid_t, off_t, uid_t};
use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid::{listpidinfo, pidinfo, pidpath};
use libproc::libproc::task_info::TaskAllInfo;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};
use std::path::Path;
use std::process;

// ---------------------------------------------------------------------------
// Port lookup
// ---------------------------------------------------------------------------

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
/// Queries both IPv4 and IPv6 across TCP and UDP. If the underlying
/// socket enumeration fails, prints an error to stderr and exits.
///
/// # Examples
///
/// An unused port returns an empty list:
///
/// ```
/// use peek::platform::macos;
///
/// let entries = macos::port_lookup(1); // port 1 is almost certainly unused
/// // May or may not be empty depending on the system, but should not panic.
/// ```
///
/// Inspecting a bound port:
///
/// ```no_run
/// use peek::platform::macos;
///
/// let entries = macos::port_lookup(8080);
/// for entry in &entries {
///     println!("{} (PID {}) on {}:{}", entry.process_name, entry.pid, entry.local_addr, entry.local_port);
/// }
/// ```
pub fn port_lookup(port: u16) -> Vec<PortEntry> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets = match get_sockets_info(af_flags, proto_flags) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to enumerate sockets: {e}");
            process::exit(1);
        }
    };

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

    entries
}

// ---------------------------------------------------------------------------
// PID lookup
// ---------------------------------------------------------------------------

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
            ProcFDType::VNode => ("FILE".to_string(), vnode_detail(pid_i32, fd.proc_fd)),
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

/// Returns the filesystem path for a vnode (regular file) FD.
///
/// Uses a direct FFI call to `proc_pidfdinfo` with
/// `PROC_PIDFDVNODEPATHINFO` because the `libproc` crate does not expose
/// the [`VnodeFDInfoWithPath`] struct as a safe Rust type.
///
/// Returns `"-"` if the path cannot be resolved.
fn vnode_detail(pid: i32, fd: i32) -> String {
    let mut info: VnodeFDInfoWithPath = unsafe { std::mem::zeroed() };
    let buffer_size = std::mem::size_of::<VnodeFDInfoWithPath>() as c_int;

    let ret = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDVNODEPATHINFO,
            &mut info as *mut _ as *mut c_void,
            buffer_size,
        )
    };

    if ret <= 0 {
        return "-".to_string();
    }

    // Extract the null-terminated path from the fixed-size `c_char` buffer.
    let path_bytes: Vec<u8> = info
        .pvip
        .vip_path
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();

    String::from_utf8(path_bytes).unwrap_or_else(|_| "-".to_string())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// FFI: vnode_fdinfowithpath
//
// The `libproc` crate exposes `pidfdinfo` for socket FDs (`SocketFDInfo`)
// but not for vnode FDs with path info. We define the minimal set of
// structs needed to call `proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO)`
// and extract the file path.
//
// Struct layouts are taken from XNU's `<sys/proc_info.h>`.
// ---------------------------------------------------------------------------

/// Flavor constant for `proc_pidfdinfo` to request vnode path information.
const PROC_PIDFDVNODEPATHINFO: c_int = 2;

unsafe extern "C" {
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

/// Mirrors XNU's `struct vinfo_stat`.
#[repr(C)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: uid_t,
    vst_gid: gid_t,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: off_t,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

/// Mirrors XNU's `struct vnode_info`.
#[repr(C)]
struct VnodeInfo {
    vi_stat: VinfoStat,
    vi_type: c_int,
    vi_pad: c_int,
    vi_fsid: libc::fsid_t,
}

/// Mirrors XNU's `struct vnode_info_path`.
#[repr(C)]
struct VnodeInfoPath {
    vip_vi: VnodeInfo,
    /// Null-terminated filesystem path, up to 1024 bytes.
    vip_path: [c_char; 1024],
}

/// Mirrors XNU's `struct proc_fileinfo`.
#[repr(C)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: off_t,
    fi_type: i32,
    fi_guardflags: u32,
}

/// Mirrors XNU's `struct vnode_fdinfowithpath`.
///
/// Returned by `proc_pidfdinfo` when called with flavor
/// [`PROC_PIDFDVNODEPATHINFO`].
#[repr(C)]
struct VnodeFDInfoWithPath {
    pfi: ProcFileInfo,
    pvip: VnodeInfoPath,
}
