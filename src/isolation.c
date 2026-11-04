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
#include <unistd.h>
#include "isolation.h"

#ifndef SEGV_PKUERR
#define SEGV_PKUERR 4
#endif

/* ---------- Mode 1: no isolation ---------- */
int run_none(plugin_fn run, int in, int *out) {
    *out = run(in);
    return CALL_OK;
}

/* ---------- Mode 2: fork + seccomp strict ---------- */
int run_fork(plugin_fn run, int in, int *out) {
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); exit(2); }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(2); }

    if (pid == 0) {
        close(fds[0]);
        prctl(PR_SET_DUMPABLE, 0);        /* no core dump when plugin crashes */
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
            syscall(SYS_exit, 10);
        int r = run(in);
        if (write(fds[1], &r, sizeof r) != (ssize_t)sizeof r)
            syscall(SYS_exit, 11);
        syscall(SYS_exit, 0);             /* exit_group is blocked by strict mode */
    }

    close(fds[1]);
    ssize_t n = read(fds[0], out, sizeof *out);
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == (ssize_t)sizeof *out)
        return CALL_OK;
    return CALL_PLUGIN_FAULT;
}

/* ---------- Mode 3: MPK in-process domain ---------- */
static int host_pkey = -1;
static sigjmp_buf mpk_jmp;
static volatile sig_atomic_t in_plugin = 0;
static volatile sig_atomic_t last_fault_code = 0;

static void mpk_segv_handler(int sig, siginfo_t *si, void *ctx) {
    (void)ctx;
    if (in_plugin) {
        in_plugin = 0;
        last_fault_code = si->si_code;
        siglongjmp(mpk_jmp, 1);
    }
    signal(sig, SIG_DFL);                 /* fault in host code: crash normally */
}

void mpk_setup(char *protected_page, long pagesz) {
    host_pkey = pkey_alloc(0, 0);
    if (host_pkey < 0) { perror("pkey_alloc"); exit(2); }
    if (pkey_mprotect(protected_page, pagesz, PROT_READ | PROT_WRITE, host_pkey) != 0) {
        perror("pkey_mprotect"); exit(2);
    }
    struct sigaction sa = {0};
    sa.sa_sigaction = mpk_segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
}

int run_mpk(plugin_fn run, int in, int *out) {
    if (sigsetjmp(mpk_jmp, 1) != 0) {
        pkey_set(host_pkey, 0);           /* PKRU reset on signal; restore host access */
        return CALL_PLUGIN_FAULT;
    }
    in_plugin = 1;
    pkey_set(host_pkey, PKEY_DISABLE_ACCESS);   /* enter plugin domain */
    int r = run(in);
    pkey_set(host_pkey, 0);                     /* leave plugin domain */
    in_plugin = 0;
    *out = r;
    return CALL_OK;
}

/* ---------- helpers ---------- */
iso_call_fn iso_by_name(const char *mode) {
    if (strcmp(mode, "none") == 0) return run_none;
    if (strcmp(mode, "fork") == 0) return run_fork;
    if (strcmp(mode, "mpk") == 0)  return run_mpk;
    if (strcmp(mode, "mpk_fast") == 0) return run_mpk_fast;
    if (strcmp(mode, "mpk_safe") == 0) return run_mpk_fast;
    return NULL;
}

int iso_last_fault_code(void) { return last_fault_code; }

const char *iso_fault_name(int code) {
    switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
        case SEGV_PKUERR: return "SEGV_PKUERR";
        default:          return "-";
    }
}

/* ---------- Mode 4: MPK without saving the signal mask ----------
   sigsetjmp(..., 0) skips the rt_sigprocmask syscall. Safe only because
   the handler uses SA_NODEFER, so SIGSEGV is not left blocked after
   siglongjmp. Isolates the cost of the domain switch itself. */
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

int iso_is_mpk(iso_call_fn call) {
    return call == run_mpk || call == run_mpk_fast;
}

/* ---------- Load-time defense: reject plugins containing WRPKRU ----------
   Scans the whole .so for the byte sequence 0F 01 EF. Conservative: it may
   reject benign files where the bytes appear by chance, and it does not
   cover XRSTOR or code generated at runtime. */
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

int iso_mode_scans(const char *mode) {
    return strcmp(mode, "mpk_safe") == 0;
}
