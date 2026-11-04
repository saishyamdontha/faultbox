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
    sa.sa_flags = SA_SIGINFO;
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
