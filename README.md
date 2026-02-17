# peek

[![CI](https://github.com/AlvinKuruvilla/peek/actions/workflows/ci.yml/badge.svg)](https://github.com/AlvinKuruvilla/peek/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B_(2024_edition)-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)]()
[![Built with LLM assistance](https://img.shields.io/badge/Built%20with-LLM%20assistance-blueviolet.svg)]()

A modern, human-friendly replacement for `lsof`.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Comparison with lsof](#comparison-with-lsof)
- [Platform Support](#platform-support)
- [Development](#development)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Overview

`peek` answers the questions developers actually ask — *"what's on this port?"*, *"what files does this process have open?"*, *"what has this file open?"* — without burying the answer in columns you don't need.

**Key features:**

- Subcommand-based CLI — no flag memorization required
- Shows only the information that matters for each query
- `--kill` flag to terminate processes directly from a port lookup
- Find what processes have a specific file open
- Resolves file paths for open file descriptors
- Displays actual port numbers instead of resolving to obscure service names

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
git clone https://github.com/AlvinKuruvilla/peek.git
cd peek
cargo build --release
# Binary is at target/release/peek
```

## Usage

### Port lookup

Find what's using a port:

```bash
peek port 8080
```

```
PID      PROCESS          USER         PROTO  LOCAL                    REMOTE                   STATE
12345    node             alvin        TCP    :::8080                  *:*                      LISTEN
```

Kill whatever is using a port:

```bash
peek port 8080 --kill
```

### Process file listing

List all open file descriptors for a process:

```bash
peek pid 1234
```

```
PID 1234 — node (/usr/local/bin/node)

FD     TYPE     DETAIL
0      FILE     /dev/null
1      FILE     /var/log/app.log
2      FILE     /var/log/app.log
3      SOCK     TCP *:8080 -> *:0
4      SOCK     UNIX
5      PIPE     -
6      KQUEUE   -

6 open file descriptors
```

### File process lookup

Find what processes have a file open:

```bash
peek file /etc/hosts
```

```
PID      PROCESS          USER         EXECUTABLE
603      Electron         alvin        /Applications/Visual Studio Code.app/.../Electron
1589     Brave Browser    alvin        /Applications/Brave Browser.app/.../Brave Browser

2 processes using /etc/hosts
```

## Comparison with lsof

```
$ lsof -i :9876
COMMAND   PID           USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Python  17455 alvinkuruvilla    5u  IPv6 0x2c4f0834694265a4      0t0  TCP *:sd (LISTEN)

$ peek port 9876
PID      PROCESS          USER         PROTO  LOCAL                    REMOTE                   STATE
17455    Python           alvinkuruvilla TCP    :::9876                  *:*                      LISTEN
```

Notable differences:

| | `lsof` | `peek` |
|---|---|---|
| Port display | Resolves to service name (`sd`) | Shows actual port number (`9876`) |
| Extra columns | FD, TYPE, DEVICE, SIZE/OFF, NODE | Only what you need |
| Kill a port | `lsof -i :9876 \| awk 'NR>1 {print $2}' \| xargs kill` | `peek port 9876 --kill` |
| Interface | Flag-based (`-i`, `-p`, `-F`) | Subcommands (`port`, `pid`, `file`) |

## Platform Support

| Platform | Status |
|---|---|
| macOS | Supported |
| Linux | Planned |

## Development

```bash
# Build
cargo build

# Run
cargo run -- port 8080

# Test
cargo test
```

## Acknowledgements

This project was built with LLM assistance ([Claude](https://claude.ai)) and human review. All code has been reviewed and validated by the maintainer.

## License

[MIT](LICENSE)
