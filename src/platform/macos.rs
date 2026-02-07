use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};
use std::path::Path;
use std::process;

/// Result of a port lookup: which process is using the port and how.
pub struct PortEntry {
    pub pid: u32,
    pub process_name: String,
    pub user: String,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
}

/// Look up all processes bound to the given port.
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

/// Get the process name and owning user for a PID in a single ps call.
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

    // Format: "username /full/path/to/binary"
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
