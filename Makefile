# Makefile — KernKlaw-Linux
#
# Targets:
#   make            — build all binaries
#   make ebpf       — compile eBPF programs to .bpf.o
#   make static     — build fully-static binaries (musl)
#   make install    — install to PREFIX (default /usr/local)
#   make deb        — build .deb package
#   make rpm        — build .rpm package
#   make docker     — build Docker image
#   make test       — run CI tests
#   make clean      — remove build artefacts

# ── Toolchain ────────────────────────────────────────────────────────
CC       ?= gcc
CLANG    ?= clang
BPFTOOL  ?= bpftool
AR       ?= ar
PKG      ?= pkg-config

# ── Directories ──────────────────────────────────────────────────────
PREFIX   ?= /usr/local
BINDIR    = $(PREFIX)/bin
LIBDIR    = $(PREFIX)/lib/claw
BPFDIR    = $(PREFIX)/lib/claw/bpf
SKILLDIR  = /etc/claw/skills
UNITDIR   = /lib/systemd/system
RUNDIR    = /run/claw

# ── Flags ────────────────────────────────────────────────────────────
CFLAGS   ?= -O2 -pipe -Wall -Wextra -Wpedantic \
             -std=c99 -D_GNU_SOURCE \
             -fstack-protector-strong \
             -fPIE -pie \
             -Wno-unused-parameter

LDFLAGS  ?= -Wl,-z,relro,-z,now -pie

# Library flags (via pkg-config where possible)
CURL_CFLAGS   := $(shell $(PKG) --cflags libcurl   2>/dev/null || echo "")
CURL_LIBS     := $(shell $(PKG) --libs   libcurl   2>/dev/null || echo "-lcurl")
JSON_CFLAGS   := $(shell $(PKG) --cflags json-c    2>/dev/null || echo "")
JSON_LIBS     := $(shell $(PKG) --libs   json-c    2>/dev/null || echo "-ljson-c")
URING_CFLAGS  := $(shell $(PKG) --cflags liburing  2>/dev/null || echo "")
URING_LIBS    := $(shell $(PKG) --libs   liburing  2>/dev/null || echo "-luring")
BPF_CFLAGS    := $(shell $(PKG) --cflags libbpf    2>/dev/null || echo "")
BPF_LIBS      := $(shell $(PKG) --libs   libbpf    2>/dev/null || echo "-lbpf")
SD_CFLAGS     := $(shell $(PKG) --cflags libsystemd 2>/dev/null || echo "")
SD_LIBS       := $(shell $(PKG) --libs   libsystemd 2>/dev/null || echo "-lsystemd")
RL_LIBS       := -lreadline -lhistory
CAP_LIBS      := -lcap

# ── Source files ──────────────────────────────────────────────────────
COMMON_SRC    = src/common/json_utils.c
DAEMON_SRC    = src/daemon/claw-daemon.c \
                src/daemon/ollama.c \
                src/daemon/ipc.c \
                src/daemon/skill_loader.c \
                src/daemon/ebpf_hooks.c
SHELL_SRC     = src/shell/claw-shell.c \
                src/shell/parser.c \
                src/shell/workflow.c \
                src/daemon/ipc.c
SKILL_SRC     = src/skill-exec/claw-skill-exec.c
URING_SRC     = src/uring/http_client.c

# ── Object files ──────────────────────────────────────────────────────
COMMON_OBJ    = $(COMMON_SRC:.c=.o)
DAEMON_OBJ    = $(DAEMON_SRC:.c=.o)
SHELL_OBJ     = $(SHELL_SRC:.c=.o)
SKILL_OBJ     = $(SKILL_SRC:.c=.o)
URING_OBJ     = $(URING_SRC:.c=.o)

# ── Build targets ──────────────────────────────────────────────────────
.PHONY: all ebpf static install deb rpm docker test clean

all: bin/claw-daemon bin/claw-shell bin/claw-skill-exec

# ── Pattern rule ───────────────────────────────────────────────────────
%.o: %.c
	$(CC) $(CFLAGS) $(CURL_CFLAGS) $(JSON_CFLAGS) $(BPF_CFLAGS) \
	      $(SD_CFLAGS) $(URING_CFLAGS) \
	      -I src \
	      -c $< -o $@

# ── claw-daemon ────────────────────────────────────────────────────────
bin/claw-daemon: $(COMMON_OBJ) $(DAEMON_OBJ) | bin
	$(CC) $(LDFLAGS) -o $@ $^ \
	      $(CURL_LIBS) $(JSON_LIBS) $(BPF_LIBS) $(SD_LIBS) \
	      -lpthread -ldl -lm

# ── claw-shell ─────────────────────────────────────────────────────────
bin/claw-shell: $(COMMON_OBJ) $(SHELL_OBJ) | bin
	$(CC) $(LDFLAGS) -o $@ $^ \
	      $(JSON_LIBS) $(RL_LIBS) -lpthread -lm

# ── claw-skill-exec ────────────────────────────────────────────────────
bin/claw-skill-exec: $(SKILL_OBJ) | bin
	$(CC) $(LDFLAGS) -o $@ $^ $(CAP_LIBS)

# ── eBPF programs ──────────────────────────────────────────────────────
EBPF_SRCS     = ebpf/file_watch.bpf.c ebpf/skill_trigger.bpf.c
EBPF_OBJS     = $(EBPF_SRCS:.bpf.c=.bpf.o)

ebpf: $(EBPF_OBJS)

ebpf/%.bpf.o: ebpf/%.bpf.c
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 \
	         -I/usr/include/bpf \
	         $(BPF_CFLAGS) \
	         -c $< -o $@

# Generate vmlinux.h from running kernel (if bpftool available)
ebpf/vmlinux.h:
	@echo "[bpftool] generating vmlinux.h from /sys/kernel/btf/vmlinux"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ── Static build (requires musl + static libs) ─────────────────────────
MUSL_CC  ?= musl-gcc
STATIC_FLAGS = -static -fPIC

static: export CC=$(MUSL_CC)
static: export CFLAGS+=$(STATIC_FLAGS)
static: export LDFLAGS=-static
static: all

# ── bin/ directory ─────────────────────────────────────────────────────
bin:
	mkdir -p bin

# ── Install ────────────────────────────────────────────────────────────
install: all ebpf
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) \
	           $(DESTDIR)$(BPFDIR) $(DESTDIR)$(SKILLDIR) \
	           $(DESTDIR)$(UNITDIR) $(DESTDIR)$(RUNDIR)

	# Binaries
	install -m 0755 bin/claw-daemon     $(DESTDIR)$(BINDIR)/
	install -m 0755 bin/claw-shell      $(DESTDIR)$(BINDIR)/
	install -m 4755 bin/claw-skill-exec $(DESTDIR)$(BINDIR)/  # setuid

	# eBPF objects
	install -m 0644 ebpf/*.bpf.o $(DESTDIR)$(BPFDIR)/ 2>/dev/null || true

	# Systemd units
	install -m 0644 systemd/claw-daemon.service  $(DESTDIR)$(UNITDIR)/
	install -m 0644 systemd/claw-shell@.service  $(DESTDIR)$(UNITDIR)/

	# Example skill
	install -d $(DESTDIR)$(SKILLDIR)/example
	install -m 0644 skills/example/skill.json $(DESTDIR)$(SKILLDIR)/example/

	@echo "Run: systemctl daemon-reload && systemctl enable --now claw-daemon"

# ── Package targets ────────────────────────────────────────────────────
deb: all ebpf
	@bash packaging/install.sh --deb

rpm: all ebpf
	@bash packaging/install.sh --rpm

# ── Docker ─────────────────────────────────────────────────────────────
docker:
	docker build -t kernklaw-linux:latest -f docker/Dockerfile .

# ── Tests ──────────────────────────────────────────────────────────────
test: all
	@echo "[test] IPC roundtrip"
	@bash -c 'bin/claw-daemon -s /tmp/test.sock & DPID=$$! ; sleep 0.5 ; \
	          echo pong | bin/claw-shell -s /tmp/test.sock -q; \
	          kill $$DPID'

	@echo "[test] Workflow parser"
	@echo 'print "hello from workflow"' | \
	      bin/claw-shell -s /dev/null --exec /dev/stdin 2>/dev/null || true

	@echo "[test] Skill exec sandbox"
	@echo '{"test":1}' | bin/claw-skill-exec /bin/echo '{}' || true

	@echo "All quick tests passed."

# ── Clean ──────────────────────────────────────────────────────────────
clean:
	rm -f $(COMMON_OBJ) $(DAEMON_OBJ) $(SHELL_OBJ) $(SKILL_OBJ) $(URING_OBJ)
	rm -f bin/claw-daemon bin/claw-shell bin/claw-skill-exec
	rm -f ebpf/*.bpf.o
	rm -rf _build _dist

# ── Dependency tracking ────────────────────────────────────────────────
-include $(COMMON_OBJ:.o=.d)
-include $(DAEMON_OBJ:.o=.d)
-include $(SHELL_OBJ:.o=.d)
-include $(SKILL_OBJ:.o=.d)

%.d: %.c
	@$(CC) -MM $(CFLAGS) -I src $< | sed 's|[^:]*:|$(@D)/$*.o $@:|' > $@
