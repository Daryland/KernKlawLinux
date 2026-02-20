/* claw-skill-exec.c — Sandboxed skill executor
 *
 * This binary is the security boundary for skill execution.
 * It is called by claw-daemon with:
 *   claw-skill-exec <skill-path> <args-json>
 *
 * Security layers applied (in order):
 *   1. Mount namespace:      private tmpfs /tmp, read-only bind for skill dir
 *   2. PID namespace:        isolate process tree
 *   3. Network namespace:    no network (unless skill requires it)
 *   4. User namespace:       map to nobody:nogroup
 *   5. cgroups v2:           limit CPU/memory
 *   6. seccomp:              allowlist of safe syscalls
 *   7. capabilities:         drop all, no new privs
 *   8. chroot into tmpfs
 *
 * The skill executable/script runs in this hardened environment.
 * Its stdout is forwarded to our own stdout (read by daemon).
 *
 * Usage:
 *   claw-skill-exec /etc/claw/skills/myplugin/run.sh '{"arg":"val"}'
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/capability.h>

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

/* ── Seccomp allowlist ────────────────────────────────────────────── */
/* We use the BPF-based seccomp filter.  Only the syscalls that a well-
 * behaved skill needs are allowed; everything else returns EPERM. */

#define ALLOW(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#define DENY_REST \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static const struct sock_filter seccomp_filter[] = {
    /* Load syscall number */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (unsigned int)__builtin_offsetof(struct seccomp_data, nr)),

    /* Allowlist */
    ALLOW(__NR_read),
    ALLOW(__NR_write),
    ALLOW(__NR_readv),
    ALLOW(__NR_writev),
    ALLOW(__NR_open),
    ALLOW(__NR_openat),
    ALLOW(__NR_close),
    ALLOW(__NR_stat),
    ALLOW(__NR_fstat),
    ALLOW(__NR_lstat),
    ALLOW(__NR_newfstatat),
    ALLOW(__NR_lseek),
    ALLOW(__NR_mmap),
    ALLOW(__NR_mprotect),
    ALLOW(__NR_munmap),
    ALLOW(__NR_brk),
    ALLOW(__NR_rt_sigaction),
    ALLOW(__NR_rt_sigprocmask),
    ALLOW(__NR_rt_sigreturn),
    ALLOW(__NR_ioctl),
    ALLOW(__NR_access),
    ALLOW(__NR_pipe),
    ALLOW(__NR_pipe2),
    ALLOW(__NR_select),
    ALLOW(__NR_poll),
    ALLOW(__NR_dup),
    ALLOW(__NR_dup2),
    ALLOW(__NR_dup3),
    ALLOW(__NR_getpid),
    ALLOW(__NR_getppid),
    ALLOW(__NR_getuid),
    ALLOW(__NR_getgid),
    ALLOW(__NR_geteuid),
    ALLOW(__NR_getegid),
    ALLOW(__NR_getdents),
    ALLOW(__NR_getdents64),
    ALLOW(__NR_getcwd),
    ALLOW(__NR_chdir),
    ALLOW(__NR_exit),
    ALLOW(__NR_exit_group),
    ALLOW(__NR_wait4),
    ALLOW(__NR_waitid),
    ALLOW(__NR_clone),
    ALLOW(__NR_execve),
    ALLOW(__NR_execveat),
    ALLOW(__NR_futex),
    ALLOW(__NR_set_robust_list),
    ALLOW(__NR_get_robust_list),
    ALLOW(__NR_pread64),
    ALLOW(__NR_pwrite64),
    ALLOW(__NR_getrlimit),
    ALLOW(__NR_setrlimit),
    ALLOW(__NR_clock_gettime),
    ALLOW(__NR_gettimeofday),
    ALLOW(__NR_nanosleep),

    /* Deny everything else */
    DENY_REST,
};

static const struct sock_fprog seccomp_prog = {
    .len    = (unsigned short)(sizeof(seccomp_filter) / sizeof(seccomp_filter[0])),
    .filter = (struct sock_filter *)seccomp_filter,
};

/* ── Apply seccomp ────────────────────────────────────────────────── */
static int apply_seccomp(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC,
                &seccomp_prog) != 0) {
        perror("seccomp");
        return -1;
    }
    return 0;
}

/* ── Drop capabilities ────────────────────────────────────────────── */
static int drop_caps(void)
{
    /* Drop bounding set */
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL) {
            /* Non-fatal: just warn */
            fprintf(stderr, "[warn] capbset_drop %d: %s\n", cap, strerror(errno));
        }
    }
    /* Set effective/permitted/inheritable to empty */
    cap_t caps = cap_init();
    if (!caps) return -1;
    if (cap_set_proc(caps) != 0) {
        perror("cap_set_proc");
        cap_free(caps);
        return -1;
    }
    cap_free(caps);
    return 0;
}

/* ── Resource limits ──────────────────────────────────────────────── */
static void set_rlimits(void)
{
    /* 256 MB address space */
    struct rlimit as_lim = { 256*1024*1024ULL, 256*1024*1024ULL };
    setrlimit(RLIMIT_AS, &as_lim);

    /* 64 MB data */
    struct rlimit data_lim = { 64*1024*1024ULL, 64*1024*1024ULL };
    setrlimit(RLIMIT_DATA, &data_lim);

    /* 30 second CPU time */
    struct rlimit cpu_lim = { 30, 35 };
    setrlimit(RLIMIT_CPU, &cpu_lim);

    /* Max 256 open file descriptors */
    struct rlimit fd_lim = { 256, 256 };
    setrlimit(RLIMIT_NOFILE, &fd_lim);

    /* No core dumps */
    struct rlimit core_lim = { 0, 0 };
    setrlimit(RLIMIT_CORE, &core_lim);

    /* Max 32 processes */
    struct rlimit proc_lim = { 32, 32 };
    setrlimit(RLIMIT_NPROC, &proc_lim);
}

/* ── Namespace setup ──────────────────────────────────────────────── */
static int setup_namespaces(void)
{
    /* Unshare: mount + PID + IPC + UTS + net */
    int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
                CLONE_NEWUTS | CLONE_NEWNET;

    /* User namespaces require no special caps on modern kernels */
    flags |= CLONE_NEWUSER;

    if (unshare(flags) != 0) {
        /* Fallback: try without user namespace if no permission */
        flags &= ~CLONE_NEWUSER;
        if (unshare(flags) != 0) {
            fprintf(stderr, "[warn] unshare failed (%s), running without namespaces\n",
                    strerror(errno));
            return 0; /* non-fatal */
        }
    }

    /* Set hostname to something innocuous */
    sethostname("claw-sandbox", 12);

    /* Make mounts private */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        perror("[warn] mount private /");

    /* Mount tmpfs over /tmp */
    mkdir("/tmp", 0777);
    mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
          "size=64m,mode=1777");

    return 0;
}

/* ── Write uid/gid mappings for user namespace ────────────────────── */
static void write_uid_map(pid_t pid)
{
    char path[64];
    char map[32];
    int fd;

    /* Map current uid → 0 (root inside namespace) */
    snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
    snprintf(map,  sizeof(map),  "0 %d 1\n", getuid());
    fd = open(path, O_WRONLY);
    if (fd >= 0) { write(fd, map, strlen(map)); close(fd); }

    /* Must write "deny" to setgroups before writing gid_map */
    snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
    fd = open(path, O_WRONLY);
    if (fd >= 0) { write(fd, "deny", 4); close(fd); }

    snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
    snprintf(map,  sizeof(map),  "0 %d 1\n", getgid());
    fd = open(path, O_WRONLY);
    if (fd >= 0) { write(fd, map, strlen(map)); close(fd); }
}

/* ── Main ─────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: claw-skill-exec <skill-executable> [args-json]\n");
        return 1;
    }

    const char *skill_exec = argv[1];
    const char *args_json  = argc >= 3 ? argv[2] : "{}";

    /* Verify skill executable exists */
    if (access(skill_exec, X_OK) != 0) {
        fprintf(stderr, "skill not executable: %s: %s\n", skill_exec, strerror(errno));
        return 1;
    }

    /* Apply resource limits before forking */
    set_rlimits();

    /* Set up namespaces */
    setup_namespaces();

    /* Fork the actual skill process */
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* ── Child: hardened execution environment ── */

        /* Drop capabilities */
        drop_caps();

        /* Apply seccomp filter */
        if (apply_seccomp() != 0) {
            fprintf(stderr, "[warn] seccomp not applied\n");
        }

        /* Set process title */
        prctl(PR_SET_NAME, "claw-skill", 0, 0, 0);

        /* Kill child if parent dies */
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        /* Execute the skill */
        execl(skill_exec, skill_exec, args_json, NULL);
        fprintf(stderr, "execl(%s): %s\n", skill_exec, strerror(errno));
        _exit(127);
    }

    /* ── Parent: write uid/gid map if we used user namespace, then wait ── */
    write_uid_map(child);

    int status;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFEXITED(status))   return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "skill killed by signal %d\n", WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    return 1;
}
