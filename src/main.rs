//! `peek` — a modern, human-friendly replacement for `lsof`.
//!
//! Provides subcommands for the three most common `lsof` use cases:
//! - `peek port <PORT>` — what process is bound to this port?
//! - `peek pid <PID>` — what files does this process have open?
//! - `peek file <PATH>` — what process has this file open?

use clap::{Parser, Subcommand};
use peek::platform;
use std::collections::BTreeSet;

#[derive(Parser)]
#[command(name = "peek")]
#[command(about = "A modern, human-friendly replacement for lsof")]
struct Cli {
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

fn main() {
    let cli = Cli::parse();

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
    #[cfg(target_os = "macos")]
    {
        let entries = platform::macos::port_lookup(port);

        if entries.is_empty() {
            println!("No process found on port {port}");
            return;
        }

        println!(
            "{:<8} {:<16} {:<12} {:<6} {:<24} {:<24} {}",
            "PID", "PROCESS", "USER", "PROTO", "LOCAL", "REMOTE", "STATE"
        );

        let mut pids_to_kill = BTreeSet::new();

        for e in &entries {
            let local = format!("{}:{}", e.local_addr, e.local_port);
            let remote = if e.remote_port == 0 {
                "*:*".to_string()
            } else {
                format!("{}:{}", e.remote_addr, e.remote_port)
            };

            println!(
                "{:<8} {:<16} {:<12} {:<6} {:<24} {:<24} {}",
                e.pid, e.process_name, e.user, e.protocol, local, remote, e.state
            );

            pids_to_kill.insert(e.pid);
        }

        if kill {
            for pid in &pids_to_kill {
                print!("Killing PID {pid}...");
                // SAFETY: `pid` is a valid PID obtained from the socket table.
                let result = unsafe { libc::kill(*pid as i32, libc::SIGTERM) };
                if result == 0 {
                    println!(" done");
                } else {
                    println!(" failed (may need sudo)");
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = kill;
        eprintln!("Port lookup not yet implemented for this platform");
        std::process::exit(1);
    }
}

/// Handle the `peek pid` subcommand.
///
/// Prints the process name and executable path, then lists every open file
/// descriptor with its type and detail (file path for vnodes, protocol/port
/// for sockets).
fn cmd_pid(pid: u32) {
    #[cfg(target_os = "macos")]
    {
        let name = platform::macos::name_for_pid(pid);
        let exe = platform::macos::exe_path_for_pid(pid);
        println!("PID {pid} — {name} ({exe})");
        println!();

        let entries = match platform::macos::pid_lookup(pid) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        if entries.is_empty() {
            println!("No open file descriptors found");
            return;
        }

        println!("{:<6} {:<8} {}", "FD", "TYPE", "DETAIL");

        for e in &entries {
            println!("{:<6} {:<8} {}", e.fd, e.fd_type, e.detail);
        }

        println!();
        println!("{} open file descriptors", entries.len());
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        eprintln!("PID lookup not yet implemented for this platform");
        std::process::exit(1);
    }
}

/// Handle the `peek file` subcommand.
///
/// Lists all processes that have the given file open, showing PID, process
/// name, user, and executable path.
fn cmd_file(path: &str) {
    #[cfg(target_os = "macos")]
    {
        let entries = match platform::macos::file_lookup(path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        if entries.is_empty() {
            println!("No process has {path} open");
            return;
        }

        println!(
            "{:<8} {:<16} {:<12} {}",
            "PID", "PROCESS", "USER", "EXECUTABLE"
        );

        for e in &entries {
            println!(
                "{:<8} {:<16} {:<12} {}",
                e.pid, e.process_name, e.user, e.exe_path
            );
        }

        println!();
        println!(
            "{} process{} using {}",
            entries.len(),
            if entries.len() == 1 { "" } else { "es" },
            path
        );
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        eprintln!("File lookup not yet implemented for this platform");
        std::process::exit(1);
    }
}
