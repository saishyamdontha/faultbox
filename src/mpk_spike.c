#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef SEGV_PKUERR
#define SEGV_PKUERR 4
#endif

static sigjmp_buf recover_point;

static void segv_handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig; (void)ctx;
    siglongjmp(recover_point, si->si_code == SEGV_PKUERR ? 2 : 1);
}

int main(void) {
    long pagesz = sysconf(_SC_PAGESIZE);
    char *host_secret = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    strcpy(host_secret, "host-state-ok");

    int pkey = pkey_alloc(0, 0);
    if (pkey < 0) { perror("pkey_alloc"); return 1; }
    if (pkey_mprotect(host_secret, pagesz, PROT_READ | PROT_WRITE, pkey) != 0) {
        perror("pkey_mprotect"); return 1;
    }

    struct sigaction sa = {0};
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    int r = sigsetjmp(recover_point, 1);
    if (r == 0) {
        pkey_set(pkey, PKEY_DISABLE_ACCESS);
        volatile char c = host_secret[0];
        pkey_set(pkey, 0);
        printf("ISOLATION FAILED: plugin read '%c'\n", c);
        return 1;
    }
    pkey_set(pkey, 0);
    printf("Fault caught (%s). Host alive. Host state: %s\n",
           r == 2 ? "SEGV_PKUERR" : "other SIGSEGV", host_secret);
    pkey_free(pkey);
    munmap(host_secret, pagesz);
    return 0;
}
