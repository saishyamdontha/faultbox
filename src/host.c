#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <unistd.h>
#include "plugin.h"

char *host_state = NULL;

enum { CALL_OK = 0, CALL_PLUGIN_FAULT = 1 };

/* Mode 1: no isolation, plugin runs in host address space */
static int run_none(plugin_fn run, int in, int *out) {
    *out = run(in);
    return CALL_OK;
}

/* Mode 2: fork a child per call, lock it with seccomp strict */
static int run_fork(plugin_fn run, int in, int *out) {
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); exit(2); }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(2); }

    if (pid == 0) {                       /* child = sandbox */
        close(fds[0]);
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
            syscall(SYS_exit, 10);
        int r = run(in);
        if (write(fds[1], &r, sizeof r) != (ssize_t)sizeof r)
            syscall(SYS_exit, 11);
        syscall(SYS_exit, 0);             /* not _exit(): exit_group is blocked */
    }

    close(fds[1]);                        /* parent = host */
    ssize_t n = read(fds[0], out, sizeof *out);
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == (ssize_t)sizeof *out)
        return CALL_OK;
    return CALL_PLUGIN_FAULT;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <none|fork> <plugin.so>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1], *path = argv[2];

    int (*call)(plugin_fn, int, int *) = NULL;
    if (strcmp(mode, "none") == 0)      call = run_none;
    else if (strcmp(mode, "fork") == 0) call = run_fork;
    else { fprintf(stderr, "unknown mode: %s\n", mode); return 2; }

    long pagesz = sysconf(_SC_PAGESIZE);
    host_state = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (host_state == MAP_FAILED) { perror("mmap"); return 2; }
    strcpy(host_state, HOST_STATE_OK);

    void *h = dlopen(path, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    plugin_fn run = (plugin_fn)dlsym(h, "plugin_run");
    if (!run) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }

    int out = 0;
    int rc = call(run, 21, &out);
    int intact = strcmp(host_state, HOST_STATE_OK) == 0;

    printf("mode=%s plugin=%s call=%s result=%d host_state=%s\n",
           mode, path, rc == CALL_OK ? "ok" : "plugin_fault",
           out, intact ? "INTACT" : "CORRUPTED");
    dlclose(h);

    if (!intact) return 3;                /* host memory corrupted */
    if (rc != CALL_OK) return 4;          /* plugin faulted, host survived */
    return 0;
}
