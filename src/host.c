#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <unistd.h>
#include "plugin.h"

#ifndef SEGV_PKUERR
#define SEGV_PKUERR 4
#endif

char *host_state = NULL;

enum { CALL_OK = 0, CALL_PLUGIN_FAULT = 1 };

/* ---------- Mode 1: no isolation ---------- */
static int run_none(plugin_fn run, int in, int *out) {
    *out = run(in);
    return CALL_OK;
}

/* ---------- Mode 2: fork + seccomp strict ---------- */
static int run_fork(plugin_fn run, int in, int *out) {
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); exit(2); }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(2); }

    if (pid == 0) {
        close(fds[0]);
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
            syscall(SYS_exit, 10);
        int r = run(in);
        if (write(fds[1], &r, sizeof r) != (ssize_t)sizeof r)
            syscall(SYS_exit, 11);
        syscall(SYS_exit, 0);
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
    if (in_plugin) {                 /* fault inside plugin: recover */
        in_plugin = 0;
        last_fault_code = si->si_code;
        siglongjmp(mpk_jmp, 1);
    }
    signal(sig, SIG_DFL);            /* fault in host code: crash normally */
}

static void mpk_setup(void) {
    long pagesz = sysconf(_SC_PAGESIZE);
    host_pkey = pkey_alloc(0, 0);
    if (host_pkey < 0) { perror("pkey_alloc"); exit(2); }
    if (pkey_mprotect(host_state, pagesz, PROT_READ | PROT_WRITE, host_pkey) != 0) {
        perror("pkey_mprotect"); exit(2);
    }
    struct sigaction sa = {0};
    sa.sa_sigaction = mpk_segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
}

static int run_mpk(plugin_fn run, int in, int *out) {
    if (sigsetjmp(mpk_jmp, 1) != 0) {
        pkey_set(host_pkey, 0);      /* kernel reset PKRU on signal; restore host access */
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

static const char *fault_name(int code) {
    switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
        case SEGV_PKUERR: return "SEGV_PKUERR";
        default:          return "-";
    }
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <none|fork|mpk> <plugin.so>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1], *path = argv[2];

    int (*call)(plugin_fn, int, int *) = NULL;
    if (strcmp(mode, "none") == 0)      call = run_none;
    else if (strcmp(mode, "fork") == 0) call = run_fork;
    else if (strcmp(mode, "mpk") == 0)  call = run_mpk;
    else { fprintf(stderr, "unknown mode: %s\n", mode); return 2; }

    long pagesz = sysconf(_SC_PAGESIZE);
    host_state = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (host_state == MAP_FAILED) { perror("mmap"); return 2; }
    strcpy(host_state, HOST_STATE_OK);

    if (call == run_mpk) mpk_setup();

    void *h = dlopen(path, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    plugin_fn run = (plugin_fn)dlsym(h, "plugin_run");
    if (!run) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }

    int out = 0;
    int rc = call(run, 21, &out);

    int recovered = 0;
    if (rc != CALL_OK && call == run_mpk) {
        dlclose(h);                              /* discard faulted plugin */
        h = dlopen(path, RTLD_NOW);              /* load a fresh instance */
        recovered = (h != NULL);
    }

    int intact = strcmp(host_state, HOST_STATE_OK) == 0;
    printf("mode=%s plugin=%s call=%s fault=%s recovered=%s result=%d host_state=%s\n",
           mode, path, rc == CALL_OK ? "ok" : "plugin_fault",
           fault_name(last_fault_code), recovered ? "yes" : "no",
           out, intact ? "INTACT" : "CORRUPTED");
    if (h) dlclose(h);

    if (!intact) return 3;
    if (rc != CALL_OK) return 4;
    return 0;
}
