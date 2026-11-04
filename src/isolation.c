#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>
#include <stdint.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include "isolation.h"

#ifndef SEGV_PKUERR
#define SEGV_PKUERR 4
#endif

static volatile sig_atomic_t last_fault_sig = 0;
static volatile sig_atomic_t last_fault_code = 0;

/* Shared by fork and ipc children: no core dumps, then seccomp strict
   (only read, write, exit, sigreturn are allowed afterwards). */
static void sandbox_child(void) {
    prctl(PR_SET_DUMPABLE, 0);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
        syscall(SYS_exit, 10);
}

/* ---------- Mode: none ---------- */
int run_none(plugin_fn run, int in, int *out) {
    *out = run(in);
    return CALL_OK;
}

/* ---------- Mode: fork (new sandboxed process per call) ---------- */
int run_fork(plugin_fn run, int in, int *out) {
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); exit(2); }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(2); }

    if (pid == 0) {
        close(fds[0]);
        sandbox_child();
        int r = run(in);
        if (write(fds[1], &r, sizeof r) != (ssize_t)sizeof r)
            syscall(SYS_exit, 11);
        syscall(SYS_exit, 0);            /* exit_group is blocked by strict mode */
    }

    close(fds[1]);
    ssize_t n = read(fds[0], out, sizeof *out);
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == (ssize_t)sizeof *out)
        return CALL_OK;
    if (WIFSIGNALED(status)) last_fault_sig = WTERMSIG(status);
    return CALL_PLUGIN_FAULT;
}

/* ---------- Mode: ipc (persistent sandboxed worker) ----------
   The realistic process-isolation baseline: one worker stays alive and
   receives each call over a pipe. If it dies, it is reaped and respawned. */
static pid_t ipc_pid = -1;
static int ipc_req = -1, ipc_resp = -1;

static void ipc_start(plugin_fn run) {
    int req[2], resp[2];
    if (pipe(req) != 0 || pipe(resp) != 0) { perror("pipe"); exit(2); }
    signal(SIGPIPE, SIG_IGN);            /* writing to a dead worker must not kill the host */
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(2); }

    if (pid == 0) {
        close(req[1]);
        close(resp[0]);
        sandbox_child();
        int in, r;
        for (;;) {
            if (read(req[0], &in, sizeof in) != (ssize_t)sizeof in)
                syscall(SYS_exit, 0);    /* host closed the pipe: shut down */
            r = run(in);
            if (write(resp[1], &r, sizeof r) != (ssize_t)sizeof r)
                syscall(SYS_exit, 11);
        }
    }

    close(req[0]);
    close(resp[1]);
    ipc_pid = pid;
    ipc_req = req[1];
    ipc_resp = resp[0];
}

static void ipc_stop(void) {
    if (ipc_pid <= 0) return;
    close(ipc_req);
    close(ipc_resp);
    int status = 0;
    waitpid(ipc_pid, &status, 0);
    ipc_pid = -1;
    ipc_req = ipc_resp = -1;
}

void iso_reset(void) { ipc_stop(); }

int run_ipc(plugin_fn run, int in, int *out) {
    if (ipc_pid <= 0) ipc_start(run);
    if (write(ipc_req, &in, sizeof in) == (ssize_t)sizeof in &&
        read(ipc_resp, out, sizeof *out) == (ssize_t)sizeof *out)
        return CALL_OK;

    /* Worker died: reap it, record why, and start a fresh one (recovery) */
    close(ipc_req);
    close(ipc_resp);
    int status = 0;
    waitpid(ipc_pid, &status, 0);
    if (WIFSIGNALED(status)) last_fault_sig = WTERMSIG(status);
    ipc_pid = -1;
    ipc_start(run);
    return CALL_PLUGIN_FAULT;
}

/* ---------- MPK modes ---------- */
static int host_pkey = -1;
static sigjmp_buf mpk_jmp;
static volatile sig_atomic_t in_plugin = 0;

static void mpk_fault_handler(int sig, siginfo_t *si, void *ctx) {
    (void)ctx;
    if (in_plugin) {                     /* fault inside plugin: recover */
        in_plugin = 0;
        last_fault_sig = sig;
        last_fault_code = si->si_code;
        siglongjmp(mpk_jmp, 1);
    }
    signal(sig, SIG_DFL);                /* fault in host code: crash normally */
}

void mpk_setup(char *protected_page, long pagesz) {
    host_pkey = pkey_alloc(0, 0);
    if (host_pkey < 0) { perror("pkey_alloc"); exit(2); }
    if (pkey_mprotect(protected_page, pagesz, PROT_READ | PROT_WRITE, host_pkey) != 0) {
        perror("pkey_mprotect"); exit(2);
    }

    /* Alternate signal stack: without it, a stack overflow leaves no stack
       for the handler to run on, and the kernel kills the process. */
    static char altstack[1 << 16];
    stack_t ss = { .ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0 };
    if (sigaltstack(&ss, NULL) != 0) { perror("sigaltstack"); exit(2); }

    struct sigaction sa = {0};
    sa.sa_sigaction = mpk_fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    int sigs[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGSYS };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
        sigaction(sigs[i], &sa, NULL);
}

int run_mpk(plugin_fn run, int in, int *out) {
    if (sigsetjmp(mpk_jmp, 1) != 0) {
        pkey_set(host_pkey, 0);          /* PKRU reset on signal; restore host access */
        return CALL_PLUGIN_FAULT;
    }
    in_plugin = 1;
    pkey_set(host_pkey, PKEY_DISABLE_ACCESS);
    int r = run(in);
    pkey_set(host_pkey, 0);
    in_plugin = 0;
    *out = r;
    return CALL_OK;
}

/* No signal-mask save: valid only because the handler uses SA_NODEFER,
   so no signal is left blocked after siglongjmp. */
int run_mpk_fast(plugin_fn run, int in, int *out) {
    if (sigsetjmp(mpk_jmp, 0) != 0) {
        pkey_set(host_pkey, 0);
        return CALL_PLUGIN_FAULT;
    }
    in_plugin = 1;
    pkey_set(host_pkey, PKEY_DISABLE_ACCESS);
    int r = run(in);
    pkey_set(host_pkey, 0);
    in_plugin = 0;
    *out = r;
    return CALL_OK;
}

/* ---------- Load-time WRPKRU scanner (mpk_scan) ----------
   Scans the whole .so for 0F 01 EF. Partial defense: misses pkey_set()
   in libc, XRSTOR and code generated at runtime; may flag chance matches. */
long iso_scan_wrpkru(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    long hits = 0;
    int a = -1, b = -1, c;
    while ((c = fgetc(f)) != EOF) {
        if (a == 0x0f && b == 0x01 && c == 0xef) hits++;
        a = b; b = c;
    }
    fclose(f);
    return hits;
}

/* ---------- helpers ---------- */
iso_call_fn iso_by_name(const char *mode) {
    if (strcmp(mode, "none") == 0)     return run_none;
    if (strcmp(mode, "fork") == 0)     return run_fork;
    if (strcmp(mode, "ipc") == 0)      return run_ipc;
    if (strcmp(mode, "mpk") == 0)      return run_mpk;
    if (strcmp(mode, "mpk_fast") == 0) return run_mpk_fast;
    if (strcmp(mode, "mpk_hard") == 0) return run_mpk_fast;
    return NULL;
}

int iso_is_mpk(iso_call_fn call) {
    return call == run_mpk || call == run_mpk_fast;
}

int iso_mode_scans(const char *mode) {
    return strcmp(mode, "mpk_hard") == 0;
}

const char *iso_last_fault(void) {
    static char buf[48];
    const char *s;
    switch (last_fault_sig) {
        case 0:       return "-";
        case SIGSEGV: s = "SIGSEGV"; break;
        case SIGBUS:  s = "SIGBUS";  break;
        case SIGFPE:  s = "SIGFPE";  break;
        case SIGILL:  s = "SIGILL";  break;
        case SIGABRT: s = "SIGABRT"; break;
        case SIGSYS:  s = "SIGSYS";  break;
        case SIGKILL: s = "SIGKILL"; break;
        default:      s = "SIG?";    break;
    }
    if (last_fault_sig == SIGSEGV && last_fault_code != 0) {
        const char *c = last_fault_code == SEGV_MAPERR ? "SEGV_MAPERR" :
                        last_fault_code == SEGV_ACCERR ? "SEGV_ACCERR" :
                        last_fault_code == SEGV_PKUERR ? "SEGV_PKUERR" : "?";
        snprintf(buf, sizeof buf, "%s/%s", s, c);
        return buf;
    }
    return s;
}

/* ---------- mpk_hard: seccomp exit gate ----------
   Seccomp filters are permanent, so instead of toggling a filter around
   plugin calls, exit/exit_group are blocked for the whole process EXCEPT
   when issued from one instruction in the host (the exit gate). A plugin
   calling exit() gets SIGSYS, which the MPK handler treats as a fault.

   The gate is written in top-level assembly so the compiler can never
   duplicate or move it: exactly one syscall instruction, at a known address. */
__asm__(
    ".text\n"
    ".globl iso_raw_exit_group\n"
    ".type iso_raw_exit_group, @function\n"
    "iso_raw_exit_group:\n"
    "    mov $231, %eax\n"          /* __NR_exit_group on x86-64; code is in %edi */
    "    syscall\n"
    ".globl iso_exit_gate\n"
    "iso_exit_gate:\n"              /* seccomp sees the address AFTER syscall */
    "    hlt\n"
    ".size iso_raw_exit_group, .-iso_raw_exit_group\n"
);
__attribute__((noreturn)) void iso_raw_exit_group(int code);
extern char iso_exit_gate[];

static int exit_filter_on = 0;

void iso_harden(void) {
    uint64_t gate = (uint64_t)(uintptr_t)iso_exit_gate;
    uint32_t lo = (uint32_t)gate, hi = (uint32_t)(gate >> 32);

    struct sock_filter f[] = {
        /* 0  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        /* 1  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        /* 2  */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* 3  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* 4  */ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 8, 0),       /* x32 ABI -> trap */
        /* 5  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 2, 0),
        /* 6  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 1, 0),
        /* 7  */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* exit / exit_group: allow only from the host's exit gate */
        /* 8  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
        /* 9  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, lo, 0, 3),
        /* 10 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
        /* 11 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, hi, 0, 1),
        /* 12 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* 13 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };
    struct sock_fprog prog = { .len = sizeof f / sizeof f[0], .filter = f };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { perror("no_new_privs"); exit(2); }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) { perror("seccomp"); exit(2); }
    exit_filter_on = 1;
}

int iso_mode_hardens(const char *mode) {
    return strcmp(mode, "mpk_hard") == 0;
}

/* All host exits go through here. With the filter on, libc's exit path is
   blocked, so flush stdio and leave through the gate. */
void iso_exit(int code) {
    fflush(NULL);
    if (exit_filter_on) iso_raw_exit_group(code);
    exit(code);
}

/* ---------- Snapshot recovery ----------
   At load: copy the plugin's writable segments (.data/.bss), skipping the
   RELRO part that becomes read-only after relocation. After a fault: copy
   them back. Not covered: plugin heap allocations, plugin mmaps, TLS. */
#define SNAP_MAX 8
static struct { char *addr; size_t len; char *copy; } snap[SNAP_MAX];
static int snap_n = 0;
static ElfW(Addr) snap_base = 0;

static int snap_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;
    if (info->dlpi_addr != snap_base) return 0;          /* not our plugin */

    ElfW(Addr) relro_lo = 0, relro_hi = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type == PT_GNU_RELRO) {
            relro_lo = info->dlpi_addr + ph->p_vaddr;
            relro_hi = relro_lo + ph->p_memsz;
        }
    }
    for (int i = 0; i < info->dlpi_phnum && snap_n < SNAP_MAX; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_W)) continue;
        ElfW(Addr) lo = info->dlpi_addr + ph->p_vaddr;
        ElfW(Addr) hi = lo + ph->p_memsz;
        if (relro_hi > lo && relro_lo < hi) {             /* overlaps RELRO */
            if (relro_lo <= lo) lo = relro_hi;            /* RELRO at the start */
            else hi = relro_lo;                           /* RELRO at the end */
        }
        if (lo >= hi) continue;
        size_t len = hi - lo;
        char *copy = malloc(len);
        if (!copy) { perror("malloc"); exit(2); }
        memcpy(copy, (char *)lo, len);
        snap[snap_n].addr = (char *)lo;
        snap[snap_n].len = len;
        snap[snap_n].copy = copy;
        snap_n++;
    }
    return 1;                                              /* found it: stop */
}

void iso_snapshot_free(void) {
    for (int i = 0; i < snap_n; i++) free(snap[i].copy);
    snap_n = 0;
}

int iso_snapshot_take(void *handle) {
    iso_snapshot_free();
    struct link_map *lm = NULL;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &lm) != 0 || !lm) return -1;
    snap_base = lm->l_addr;
    dl_iterate_phdr(snap_cb, NULL);
    return snap_n;                                         /* number of regions saved */
}

void iso_snapshot_restore(void) {
    for (int i = 0; i < snap_n; i++)
        memcpy(snap[i].addr, snap[i].copy, snap[i].len);
}
