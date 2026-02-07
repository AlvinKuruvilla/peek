use clap::{Parser, Subcommand};
use std::collections::BTreeSet;

mod platform;

#[derive(Parser)]
#[command(name = "peek")]
#[command(about = "A modern, human-friendly replacement for lsof")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show what process is using a given port
    Port {
        /// Port number to look up
        port: u16,

        /// Kill the process(es) using this port
        #[arg(long)]
        kill: bool,
    },
    /// Show open files for a given process
    Pid {
        /// Process ID to inspect
        pid: u32,
    },
    /// Show what process has a given file open
    File {
        /// Path to the file
        path: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Port { port, kill } => cmd_port(port, kill),
        Command::Pid { pid } => {
            println!("Looking up PID {pid}...");
            todo!("pid file listing")
        }
        Command::File { path } => {
            println!("Looking up file {path}...");
            todo!("file process lookup")
        }
    }
}

fn cmd_port(port: u16, kill: bool) {
    #[cfg(target_os = "macos")]
    {
        let entries = platform::macos::port_lookup(port);

        if entries.is_empty() {
            println!("No process found on port {port}");
            return;
        }

        // Header
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
                // SAFETY: sending SIGTERM to a valid PID.
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
