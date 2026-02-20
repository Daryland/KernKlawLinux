# KernKlaw-Linux

> A fully native Linux port of [OpenClaw](https://github.com/openclaw/openclaw) — rewritten from the ground up in pure C99, operating at the kernel level with no Node.js, no TypeScript, no runtime overhead.

---

## What is this?

OpenClaw is an AI assistant daemon — it connects to a local LLM (via Ollama), exposes an interactive shell, and executes extensible "skills" in response to queries or system events.

**KernKlaw-Linux** is a complete reimplementation of that concept designed to live as close to the Linux kernel as possible:

- **eBPF hooks** — kernel tracepoints (`openat`, `write`, `execve`, `tcp_connect`, process exit) feed a BPF ring-buffer directly into the daemon. The AI can react to real kernel events in real time, not polled userspace approximations.
- **io_uring async I/O** — all Ollama HTTP traffic goes through `io_uring` (kernel ≥ 5.6), bypassing traditional socket syscall overhead for high-throughput skill pipelines.
- **Kernel namespace sandboxing** — every skill runs inside `claw-skill-exec`, a setuid binary that immediately unshares mount, PID, network, IPC, and user namespaces before dropping all capabilities and applying a strict seccomp allowlist (~35 syscalls). Skills are fully isolated at the kernel level, not by a container runtime.
- **cgroups v2 resource limits** — CPU time, memory, and process count are enforced by the kernel, not userspace checks.
- **systemd-native** — the daemon integrates with `sd_notify`, journald, and socket activation; no init wrapper needed.

The result is an AI assistant daemon that is entirely self-contained: one `make`, three binaries, no npm, no interpreter, no VM. It runs on any Linux kernel ≥ 5.6 with BTF support.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        claw-shell (REPL)                        │
│  readline • Lobster DSL parser • workflow executor              │
└────────────────────────┬────────────────────────────────────────┘
                         │ Unix socket (proto.h wire format)
┌────────────────────────▼────────────────────────────────────────┐
│                      claw-daemon                                │
│                                                                 │
│  epoll event loop • sd_notify • syslog                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Ollama client│  │ Skill loader │  │   eBPF hooks         │  │
│  │  (libcurl)   │  │ dlopen / exec│  │   (libbpf ringbuf)   │  │
│  └──────────────┘  └──────┬───────┘  └──────────────────────┘  │
└─────────────────────────── │ ───────────────────────────────────┘
                             │ fork+exec / dlopen
┌────────────────────────────▼────────────────────────────────────┐
│                   claw-skill-exec (setuid)                      │
│                                                                 │
│  mount ns • pid ns • net ns • user ns                          │
│  cgroups v2 limits • seccomp allowlist • cap drop              │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Binary | Description |
|--------|-------------|
| `claw-daemon` | Main systemd service; Ollama AI, skills, eBPF |
| `claw-shell` | Interactive REPL + workflow DSL runner |
| `claw-skill-exec` | Sandboxed skill executor (setuid, seccomp) |

## Building

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt-get install -y \
    gcc clang cmake pkg-config make \
    libcurl4-openssl-dev libjson-c-dev libcap-dev \
    libreadline-dev libsystemd-dev liburing-dev \
    libbpf-dev bpftool

# Fedora / RHEL
sudo dnf install -y \
    gcc clang cmake pkgconf \
    libcurl-devel json-c-devel libcap-devel \
    readline-devel systemd-devel liburing-devel \
    libbpf-devel bpftool
```

### Compile

```bash
git clone https://github.com/yourfork/kernklaw-linux
cd kernklaw-linux

make -j$(nproc)            # build all C binaries
make ebpf                  # compile eBPF programs (needs clang + BTF)
```

### CMake alternative

```bash
cmake -B _build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_EBPF=OFF
cmake --build _build -j$(nproc)
cmake --install _build
```

### Static build (Alpine / musl)

```bash
make static CC=musl-gcc
```

## Install

```bash
# Scripted (detects distro, installs deps, builds, installs)
sudo bash packaging/install.sh

# Manual
sudo make install PREFIX=/usr/local
```

## Quick Start

```bash
# Start daemon
sudo systemctl enable --now claw-daemon

# Open interactive shell
claw-shell

# Single query
claw-shell --exec /dev/stdin <<< 'ask "What is the capital of France?"'
```

## Workflow DSL

Save as `hello.claw`, run with `claw-shell hello.claw`:

```
# hello.claw — simple workflow example
workflow

let name = "Linux"

ask "Give me a one-line fact about " + name into fact
print "Fact: " + fact

skill example msg="hello from workflow"

loop 3 {
  print "iteration " + _i
}

! echo "shell command executed"

end
```

## Skills

Skills live in `/etc/claw/skills/<name>/skill.json`. Three types:

### Executable skill (`type: exec`)

```json
{
  "name": "my-tool",
  "type": "exec",
  "exec": "run.sh",
  "description": "Does something useful"
}
```

The script receives the args JSON as `$1` and should print results to stdout.

### Shared-object skill (`type: so`)

```c
// myskill.c
int  skill_init(void);
int  skill_run(const char *args_json, char **output, size_t *outlen);
void skill_destroy(void);
```

```bash
gcc -shared -fPIC -o myskill.so myskill.c -ljson-c
```

See [skills/example/skill-template.c](skills/example/skill-template.c).

### Shell script skill (`type: script`)

```json
{ "type": "script", "exec": "myscript.sh" }
```

## eBPF Hooks

eBPF programs (in `ebpf/`) monitor:

| Program | Tracepoint | Event |
|---------|------------|-------|
| `file_watch.bpf.c` | `sys_enter_openat` | File opens |
| `file_watch.bpf.c` | `sys_enter_write` | File writes |
| `skill_trigger.bpf.c` | `sys_enter_execve` | Process exec |
| `skill_trigger.bpf.c` | `sched_process_exit` | Process exit |
| `skill_trigger.bpf.c` | `kprobe/tcp_connect` | Network connects |

Events flow through a BPF ring-buffer to the daemon for skill auto-triggering.

```bash
# Compile eBPF programs
make ebpf

# BPF objects are installed to /usr/lib/claw/bpf/
```

## io_uring HTTP Client

`src/uring/http_client.c` provides an optional io_uring-based HTTP client
(kernel ≥ 5.6) that replaces libcurl for direct Ollama calls — useful for
extremely high-throughput skill pipelines.

## Security Model

```
claw-daemon  → runs as user 'claw' with minimal caps
               CAP_BPF + CAP_SYS_ADMIN only for eBPF (optional)

claw-skill-exec → setuid root, immediately sandboxes:
    unshare(NEWNS | NEWPID | NETIPC | NETNS | NEWUSER)
    mount private tmpfs /tmp
    drop all capabilities
    apply seccomp allowlist (~35 syscalls)
    RLIMIT: 256MB AS, 30s CPU, 32 procs
    PR_SET_NO_NEW_PRIVS=1
    PR_SET_PDEATHSIG=SIGKILL
```

## NixOS

Add to your `flake.nix`:

```nix
{
  inputs.kernklaw-linux.url = "github:yourfork/kernklaw-linux";

  outputs = { nixpkgs, kernklaw-linux, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        kernklaw-linux.nixosModules.kernklaw-linux
        {
          services.kernklaw-linux = {
            enable      = true;
            model       = "llama3.2";
            ollamaHost  = "http://127.0.0.1:11434";
            enableEbpf  = false;
          };
        }
      ];
    };
  };
}
```

```bash
nix develop github:yourfork/kernklaw-linux  # dev shell
nix build   github:yourfork/kernklaw-linux  # build package
```

## Docker

```bash
# Build image
docker build -t kernklaw-linux:latest .

# Run daemon (connects to host Ollama)
docker run -d \
  --name kernklaw \
  --privileged \
  -v kernklaw-run:/run/claw \
  -e OLLAMA_HOST=http://host-gateway:11434 \
  kernklaw-linux:latest

# Open shell (mount the daemon socket)
docker run --rm -it \
  -v kernklaw-run:/run/claw \
  kernklaw-linux:latest \
  claw-shell
```

## Multi-distro CI (Vagrant)

```bash
vagrant up ubuntu   # Ubuntu 24.04
vagrant up fedora   # Fedora 40
vagrant up nixos    # NixOS 24.05
```

## Project Structure

```
KernKlawLinux/
├── src/
│   ├── common/          # proto.h, log.h, json_utils
│   ├── daemon/          # claw-daemon.c, ollama, ipc, skill_loader, ebpf_hooks
│   ├── shell/           # claw-shell.c, parser (DSL), workflow (interpreter)
│   ├── skill-exec/      # claw-skill-exec.c (sandbox)
│   └── uring/           # io_uring HTTP client
├── ebpf/
│   ├── file_watch.bpf.c
│   └── skill_trigger.bpf.c
├── skills/example/      # Reference skill (exec + .so template)
├── systemd/             # .service files
├── packaging/
│   ├── debian/          # control, rules, postinst
│   ├── rpm/             # kernklaw.spec
│   └── install.sh       # Universal installer
├── nix/flake.nix        # NixOS package + module
├── docker/              # Dockerfile (prod + test)
├── vagrant/Vagrantfile  # Multi-distro CI
├── Makefile
└── CMakeLists.txt
```

## Dependencies

| Library | Purpose | Min version |
|---------|---------|------------|
| libcurl | Ollama HTTP API | 7.68 |
| json-c  | JSON parsing | 0.13 |
| libcap  | Capability manipulation | 2.24 |
| libreadline | Shell REPL | 7.0 |
| libsystemd | sd_notify, journald | 240 |
| liburing | io_uring async I/O | 2.0 |
| libbpf  | eBPF program management | 0.8 |

## License

MIT — see [LICENSE](LICENSE).
