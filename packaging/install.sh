#!/bin/bash
# install.sh — Universal installer for KernKlaw-Linux
# Supports: Ubuntu/Debian, Fedora/RHEL, NixOS, Arch Linux
# Usage:
#   sudo ./install.sh [--deb|--rpm|--nix|--arch|--uninstall]

set -euo pipefail

VERSION="0.1.0"
PREFIX="/usr/local"
BINDIR="$PREFIX/bin"
LIBDIR="/usr/lib/claw"
BPFDIR="$LIBDIR/bpf"
SKILLDIR="/etc/claw/skills"
UNITDIR="/lib/systemd/system"
RUNDIR="/run/claw"
LOGDIR="/var/log/claw"

RED="\033[31m"; GRN="\033[32m"; YLW="\033[33m"; RST="\033[0m"

info()    { printf "${GRN}[+]${RST} %s\n" "$*"; }
warn()    { printf "${YLW}[!]${RST} %s\n" "$*"; }
error()   { printf "${RED}[!]${RST} %s\n" "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || error "Required: $1"; }

# ── Detect distro ──────────────────────────────────────────────────────
detect_distro() {
    if   [ -f /etc/debian_version ];  then echo "debian"
    elif [ -f /etc/fedora-release ];  then echo "fedora"
    elif [ -f /etc/arch-release ];    then echo "arch"
    elif [ -f /etc/nixos/configuration.nix ]; then echo "nixos"
    else echo "unknown"
    fi
}

# ── Dependencies by distro ─────────────────────────────────────────────
install_deps_debian() {
    info "Installing dependencies (apt)"
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        gcc clang cmake pkg-config \
        libcurl4-openssl-dev libjson-c-dev \
        libcap-dev libreadline-dev libsystemd-dev \
        liburing-dev libbpf-dev bpftool \
        libjson-c5 libcap2 libreadline8 liburing2
}

install_deps_fedora() {
    info "Installing dependencies (dnf)"
    dnf install -y \
        gcc clang cmake pkgconf \
        libcurl-devel json-c-devel \
        libcap-devel readline-devel systemd-devel \
        liburing-devel libbpf-devel bpftool \
        json-c libcap readline systemd-libs liburing
}

install_deps_arch() {
    info "Installing dependencies (pacman)"
    pacman -Sy --noconfirm \
        gcc clang cmake pkgconf \
        curl json-c libcap readline systemd \
        liburing libbpf bpf
}

# ── Build ──────────────────────────────────────────────────────────────
build() {
    info "Building KernKlaw-Linux v$VERSION"
    SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    cd "$SCRIPT_DIR"

    make -j"$(nproc)" all

    if command -v clang >/dev/null 2>&1 && [ -f /sys/kernel/btf/vmlinux ]; then
        info "Compiling eBPF programs"
        make ebpf 2>/dev/null || warn "eBPF compilation failed (skipping)"
    else
        warn "eBPF compilation skipped (no clang or vmlinux BTF)"
    fi
}

# ── Install files ──────────────────────────────────────────────────────
install_files() {
    info "Installing to $PREFIX"
    SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

    install -d "$BINDIR" "$LIBDIR" "$BPFDIR" "$SKILLDIR" "$UNITDIR"
    install -m 0755 "$SCRIPT_DIR/bin/claw-daemon"     "$BINDIR/"
    install -m 0755 "$SCRIPT_DIR/bin/claw-shell"      "$BINDIR/"
    install -m 4755 "$SCRIPT_DIR/bin/claw-skill-exec" "$BINDIR/"  # setuid

    # eBPF objects
    [ -d "$SCRIPT_DIR/ebpf" ] && \
        find "$SCRIPT_DIR/ebpf" -name "*.bpf.o" -exec install -m 0644 {} "$BPFDIR/" \; 2>/dev/null || true

    # Systemd units
    install -m 0644 "$SCRIPT_DIR/systemd/claw-daemon.service" "$UNITDIR/"
    install -m 0644 "$SCRIPT_DIR/systemd/claw-shell@.service"  "$UNITDIR/"

    # Example skills
    install -d "$SKILLDIR/example"
    install -m 0644 "$SCRIPT_DIR/skills/example/skill.json" "$SKILLDIR/example/"

    # Create claw user
    if ! getent passwd claw >/dev/null 2>&1; then
        info "Creating 'claw' system user"
        useradd -r -g claw -d /var/lib/claw -s /sbin/nologin \
                -c "KernKlaw daemon" claw 2>/dev/null || \
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --comment "KernKlaw daemon" claw || true
        groupadd claw 2>/dev/null || true
    fi

    # Runtime directories
    install -d -o claw -g claw -m 0755 "$RUNDIR" "$LOGDIR" || true

    # Systemd
    if systemctl is-system-running --quiet 2>/dev/null; then
        systemctl daemon-reload
        systemctl enable claw-daemon.service
        info "Service enabled. Start with: systemctl start claw-daemon"
    fi
}

# ── DEB package ────────────────────────────────────────────────────────
build_deb() {
    require dpkg-buildpackage
    info "Building .deb package"
    cd "$(dirname "$0")/.."
    dpkg-buildpackage -b -us -uc
    info "Package built in parent directory"
}

# ── RPM package ────────────────────────────────────────────────────────
build_rpm() {
    require rpmbuild
    info "Building .rpm package"
    SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    RPMBUILD_DIR="$HOME/rpmbuild"
    mkdir -p "$RPMBUILD_DIR"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}

    # Create source tarball
    tar czf "$RPMBUILD_DIR/SOURCES/kernklaw-linux-$VERSION.tar.gz" \
        --transform "s|^\.|kernklaw-linux-$VERSION|" \
        -C "$SCRIPT_DIR" .

    cp "$SCRIPT_DIR/packaging/rpm/kernklaw.spec" "$RPMBUILD_DIR/SPECS/"
    rpmbuild -bb "$RPMBUILD_DIR/SPECS/kernklaw.spec"
    info "RPM built in $RPMBUILD_DIR/RPMS/"
}

# ── Uninstall ──────────────────────────────────────────────────────────
uninstall() {
    info "Uninstalling KernKlaw-Linux"
    systemctl stop    claw-daemon.service 2>/dev/null || true
    systemctl disable claw-daemon.service 2>/dev/null || true

    rm -f "$BINDIR/claw-daemon" "$BINDIR/claw-shell" "$BINDIR/claw-skill-exec"
    rm -f "$UNITDIR/claw-daemon.service" "$UNITDIR/claw-shell@.service"
    rm -rf "$LIBDIR"

    systemctl daemon-reload 2>/dev/null || true
    info "Uninstall complete. /etc/claw and /var/log/claw left intact."
}

# ── Main ───────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || error "Must run as root: sudo $0 $*"

DISTRO=$(detect_distro)
info "Detected distro: $DISTRO"

case "${1:-install}" in
    --deb)       build; build_deb;;
    --rpm)       build; build_rpm;;
    --uninstall) uninstall;;
    install|--install)
        case "$DISTRO" in
            debian) install_deps_debian;;
            fedora) install_deps_fedora;;
            arch)   install_deps_arch;;
            nixos)  warn "NixOS: use 'nix profile install' or add to flake.nix";;
            *)      warn "Unknown distro. Install deps manually.";;
        esac
        build
        install_files
        info "KernKlaw-Linux v$VERSION installed successfully!"
        info "Start daemon: systemctl start claw-daemon"
        info "Open shell:   claw-shell"
        ;;
    *)
        echo "Usage: $0 [--install|--deb|--rpm|--uninstall]"
        exit 1
        ;;
esac
