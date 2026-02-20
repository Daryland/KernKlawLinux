Name:           kernklaw-linux
Version:        0.1.0
Release:        1%{?dist}
Summary:        KernKlaw-Linux AI assistant daemon
License:        MIT
URL:            https://github.com/kernklaw/kernklaw-linux
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  clang
BuildRequires:  cmake >= 3.18
BuildRequires:  pkg-config
BuildRequires:  libcurl-devel
BuildRequires:  json-c-devel
BuildRequires:  libcap-devel
BuildRequires:  readline-devel
BuildRequires:  systemd-devel
BuildRequires:  liburing-devel
BuildRequires:  libbpf-devel
BuildRequires:  bpftool
BuildRequires:  systemd-rpm-macros

Requires:       libcurl
Requires:       json-c
Requires:       libcap
Requires:       readline
Requires:       systemd-libs
Requires:       liburing
Recommends:     ollama

%description
A fully native C implementation of the KernKlaw AI assistant for Linux.
Features local AI inference via Ollama, eBPF system monitoring,
io_uring async I/O, skill plugins with seccomp sandboxing, and
a Lobster-inspired workflow DSL.

%prep
%autosetup

%build
%cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_EBPF=OFF
%cmake_build

%install
%cmake_install

# Set setuid on sandbox binary
chmod 4755 %{buildroot}%{_bindir}/claw-skill-exec

# Create directories
install -d -m 755 %{buildroot}/run/claw
install -d -m 755 %{buildroot}/var/log/claw
install -d -m 755 %{buildroot}/etc/claw
install -d -m 755 %{buildroot}/etc/claw/skills
install -d -m 755 %{buildroot}/usr/lib/claw/bpf

%pre
getent group  claw >/dev/null || groupadd -r claw
getent passwd claw >/dev/null || \
    useradd -r -g claw -d /var/lib/claw \
            -s /sbin/nologin \
            -c "KernKlaw daemon" claw
exit 0

%post
%systemd_post claw-daemon.service

# Set permissions
chown root:claw %{_bindir}/claw-skill-exec
chmod 4755      %{_bindir}/claw-skill-exec

install -d -o claw -g claw -m 755 /run/claw
install -d -o claw -g claw -m 755 /var/log/claw

echo "KernKlaw-Linux %{version} installed."
echo "  Start: systemctl enable --now claw-daemon"

%preun
%systemd_preun claw-daemon.service

%postun
%systemd_postun_with_restart claw-daemon.service

%files
%license LICENSE
%doc README.md
%{_bindir}/claw-daemon
%{_bindir}/claw-shell
%attr(4755,root,claw) %{_bindir}/claw-skill-exec
/lib/systemd/system/claw-daemon.service
/lib/systemd/system/claw-shell@.service
%dir /etc/claw
%dir /etc/claw/skills
%dir /usr/lib/claw/bpf

%changelog
* Thu Feb 20 2026 KernKlaw Project <kernklaw@example.com> - 0.1.0-1
- Initial package
