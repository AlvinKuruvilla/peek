//! `peek` — a modern, human-friendly replacement for `lsof`.
//!
//! Provides subcommands for the three most common `lsof` use cases:
//! - `peek port <PORT>` — what process is bound to this port?
//! - `peek pid <PID>` — what files does this process have open?
//! - `peek file <PATH>` — what process has this file open?

use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use peek::platform;
use std::collections::BTreeSet;

#[derive(Parser)]
#[command(name = "peek")]
#[command(about = "A modern, human-friendly replacement for lsof")]
struct Cli {
    /// Disable colored output.
    #[arg(long = "no-color", global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show what process is using a given port.
    Port {
        /// Port number to look up.
        port: u16,

        /// Send `SIGTERM` to all processes using this port after displaying them.
        #[arg(long)]
        kill: bool,
    },
    /// Show all open file descriptors for a given process.
    Pid {
        /// Process ID to inspect.
        pid: u32,
    },
    /// Show what process has a given file open.
    File {
        /// Path to the file.
        path: String,
    },
}

/// Colorize a TCP state string according to its semantic meaning.
fn format_state_colored(state: &str) -> String {
    use owo_colors::Stream::Stdout;

    match state {
        "LISTEN" => state.if_supports_color(Stdout, |s| s.green()).to_string(),
        "ESTABLISHED" => state.if_supports_color(Stdout, |s| s.blue()).to_string(),
        "TIME_WAIT" | "CLOSE_WAIT" | "FIN_WAIT_1" | "FIN_WAIT_2" | "LAST_ACK" | "CLOSING" => {
            state.if_supports_color(Stdout, |s| s.yellow()).to_string()
        }
        "CLOSED" => state.if_supports_color(Stdout, |s| s.red()).to_string(),
        "SYN_SENT" | "SYN_RECV" => {
            state.if_supports_color(Stdout, |s| s.magenta()).to_string()
        }
        _ => state.to_string(),
    }
}

fn main() {
    let cli = Cli::parse();

    if cli.no_color {
        owo_colors::set_override(false);
    }

    match cli.command {
        Command::Port { port, kill } => cmd_port(port, kill),
        Command::Pid { pid } => cmd_pid(pid),
        Command::File { path } => cmd_file(&path),
    }
}

/// Handle the `peek port` subcommand.
///
/// Enumerates all TCP/UDP sockets on the system, filters to the requested
/// port, and prints a table of matching processes. When `kill` is `true`,
/// sends `SIGTERM` to each unique PID after printing.
fn cmd_port(port: u16, kill: bool) {
    use owo_colors::Stream::Stdout;

    #[cfg(target_os = "macos")]
    {
        let entries = match platform::macos::port_lookup(port) {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "{}",
                    e.if_supports_color(owo_colors::Stream::Stderr, |s| s.red())
                );
                std::process::exit(1);
            }
        };

        if entries.is_empty() {
            println!(
                "{}",
                format!("No process found on port {port}")
                    .if_supports_color(Stdout, |s| s.dimmed())
            );
            return;
        }

        println!(
            "{:<8} {:<16} {:<12} {:<6} {:<24} {:<24} {}",
            "PID".if_supports_color(Stdout, |s| s.bold()),
            "PROCESS".if_supports_color(Stdout, |s| s.bold()),
            "USER".if_supports_color(Stdout, |s| s.bold()),
            "PROTO".if_supports_color(Stdout, |s| s.bold()),
            "LOCAL".if_supports_color(Stdout, |s| s.bold()),
            "REMOTE".if_supports_color(Stdout, |s| s.bold()),
            "STATE".if_supports_color(Stdout, |s| s.bold()),
        );

        let mut pids_to_kill = BTreeSet::new();

        for e in &entries {
            let local = format!("{}:{}", e.local_addr, e.local_port);
            let remote = if e.remote_port == 0 {
                "*:*".to_string()
            } else {
                format!("{}:{}", e.remote_addr, e.remote_port)
            };

            let pid_str = format!("{:<8}", e.pid);
            let name_str = format!("{:<16}", e.process_name);

            println!(
                "{} {} {:<12} {:<6} {:<24} {:<24} {}",
                pid_str.if_supports_color(Stdout, |s| s.cyan()),
                name_str.if_supports_color(Stdout, |s| s.green()),
                e.user,
                e.protocol,
                local,
                remote,
                format_state_colored(&e.state),
            );

            pids_to_kill.insert(e.pid);
        }

        if kill {
            for pid in &pids_to_kill {
                print!("Killing PID {pid}...");
                // SAFETY: `pid` is a valid PID obtained from the socket table.
                let result = unsafe { libc::kill(*pid as i32, libc::SIGTERM) };
                if result == 0 {
                    println!(
                        " {}",
                        "done".if_supports_color(Stdout, |s| s.green())
                    );
                } else {
                    println!(
                        " {}",
                        "failed (may need sudo)"
                            .if_supports_color(Stdout, |s| s.red())
                    );
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = kill;
        eprintln!(
            "{}",
            "Port lookup not yet implemented for this platform"
                .if_supports_color(owo_colors::Stream::Stderr, |s| s.red())
        );
        std::process::exit(1);
    }
}

/// Handle the `peek pid` subcommand.
///
/// Prints the process name and executable path, then lists every open file
/// descriptor with its type and detail (file path for vnodes, protocol/port
/// for sockets).
fn cmd_pid(pid: u32) {
    use owo_colors::Stream::Stdout;

    #[cfg(target_os = "macos")]
    {
        let name = platform::macos::name_for_pid(pid);
        let exe = platform::macos::exe_path_for_pid(pid);
        println!(
            "PID {} \u{2014} {} ({})",
            pid.if_supports_color(Stdout, |s| s.cyan()),
            name.if_supports_color(Stdout, |s| s.green()),
            exe,
        );
        println!();

        let entries = match platform::macos::pid_lookup(pid) {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "{}",
                    e.if_supports_color(owo_colors::Stream::Stderr, |s| s.red())
                );
                std::process::exit(1);
            }
        };

        if entries.is_empty() {
            println!(
                "{}",
                "No open file descriptors found"
                    .if_supports_color(Stdout, |s| s.dimmed())
            );
            return;
        }

        println!(
            "{:<6} {:<8} {}",
            "FD".if_supports_color(Stdout, |s| s.bold()),
            "TYPE".if_supports_color(Stdout, |s| s.bold()),
            "DETAIL".if_supports_color(Stdout, |s| s.bold()),
        );

        for e in &entries {
            println!("{:<6} {:<8} {}", e.fd, e.fd_type, e.detail);
        }

        println!();
        println!(
            "{}",
            format!("{} open file descriptors", entries.len())
                .if_supports_color(Stdout, |s| s.dimmed())
        );
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        eprintln!(
            "{}",
            "PID lookup not yet implemented for this platform"
                .if_supports_color(owo_colors::Stream::Stderr, |s| s.red())
        );
        std::process::exit(1);
    }
}

/// Handle the `peek file` subcommand.
///
/// Lists all processes that have the given file open, showing PID, process
/// name, user, and executable path.
fn cmd_file(path: &str) {
    use owo_colors::Stream::Stdout;

    #[cfg(target_os = "macos")]
    {
        let entries = match platform::macos::file_lookup(path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "{}",
                    e.if_supports_color(owo_colors::Stream::Stderr, |s| s.red())
                );
                std::process::exit(1);
            }
        };

        if entries.is_empty() {
            println!(
                "{}",
                format!("No process has {path} open")
                    .if_supports_color(Stdout, |s| s.dimmed())
            );
            return;
        }

        println!(
            "{:<8} {:<16} {:<12} {}",
            "PID".if_supports_color(Stdout, |s| s.bold()),
            "PROCESS".if_supports_color(Stdout, |s| s.bold()),
            "USER".if_supports_color(Stdout, |s| s.bold()),
            "EXECUTABLE".if_supports_color(Stdout, |s| s.bold()),
        );

        for e in &entries {
            let pid_str = format!("{:<8}", e.pid);
            let name_str = format!("{:<16}", e.process_name);

            println!(
                "{} {} {:<12} {}",
                pid_str.if_supports_color(Stdout, |s| s.cyan()),
                name_str.if_supports_color(Stdout, |s| s.green()),
                e.user,
                e.exe_path,
            );
        }

        println!();
        println!(
            "{}",
            format!(
                "{} process{} using {}",
                entries.len(),
                if entries.len() == 1 { "" } else { "es" },
                path
            )
            .if_supports_color(Stdout, |s| s.dimmed())
        );
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        eprintln!(
            "{}",
            "File lookup not yet implemented for this platform"
                .if_supports_color(owo_colors::Stream::Stderr, |s| s.red())
        );
        std::process::exit(1);
    }
}
