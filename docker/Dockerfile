# Dockerfile — KernKlaw-Linux production image
#
# Multi-stage build:
#   Stage 1: builder  — Debian bookworm with all dev deps
#   Stage 2: runtime  — Minimal debian:bookworm-slim
#
# Usage:
#   docker build -t kernklaw-linux:latest .
#   docker run --rm -it \
#     --privileged \
#     -v /sys/kernel/btf:/sys/kernel/btf:ro \
#     -e OLLAMA_HOST=http://host-gateway:11434 \
#     kernklaw-linux:latest

# ── Stage 1: Build ────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

ARG JOBS=4

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc clang cmake pkg-config make git \
    libcurl4-openssl-dev libjson-c-dev \
    libcap-dev libreadline-dev libsystemd-dev \
    liburing-dev libbpf-dev bpftool \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build all C binaries
RUN make -j${JOBS} all

# Compile eBPF if BTF is available (unlikely in Docker build, skip gracefully)
RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
        make ebpf || true; \
    else \
        echo "[docker] eBPF compilation skipped (no BTF in build stage)"; \
    fi

# ── Stage 2: Runtime ──────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="KernKlaw-Linux"
LABEL org.opencontainers.image.description="AI assistant daemon for Linux"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.source="https://github.com/kernklaw/kernklaw-linux"

# Runtime dependencies only (no dev headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4 libjson-c5 libcap2 libreadline8 \
    liburing2 libbpf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create claw user
RUN groupadd -r claw && \
    useradd -r -g claw -d /var/lib/claw \
            -s /usr/sbin/nologin \
            -c "KernKlaw daemon" claw && \
    mkdir -p /var/lib/claw /var/log/claw /etc/claw/skills \
             /run/claw /usr/lib/claw/bpf && \
    chown claw:claw /var/lib/claw /var/log/claw /run/claw

# Copy binaries from builder
COPY --from=builder /src/bin/claw-daemon      /usr/local/bin/
COPY --from=builder /src/bin/claw-shell       /usr/local/bin/
COPY --from=builder /src/bin/claw-skill-exec  /usr/local/bin/

# eBPF objects (may not exist)
COPY --from=builder /src/ebpf/*.bpf.o /usr/lib/claw/bpf/ 2>/dev/null || true

# Example skills
COPY skills/example /etc/claw/skills/example/

# setuid on sandbox binary
RUN chmod u+s /usr/local/bin/claw-skill-exec && \
    chown root:claw /usr/local/bin/claw-skill-exec

# Runtime dirs
VOLUME ["/etc/claw", "/var/log/claw"]

# Expose nothing (IPC via Unix socket; mount /run/claw as volume)
# For external access mount the socket:
#   -v /run/claw:/run/claw

EXPOSE 0

USER claw
ENV OLLAMA_HOST=http://127.0.0.1:11434
ENV CLAW_DEFAULT_MODEL=llama3.2

CMD ["/usr/local/bin/claw-daemon", "-c", "/etc/claw", "-s", "/etc/claw/skills"]
