#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include "isolation.h"

char *host_state = NULL;
char host_config[64] = HOST_CONFIG_OK;

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static void *load(const char *path, plugin_fn *run) {
    void *h = dlopen(path, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); exit(2); }
    *run = (plugin_fn)dlsym(h, "plugin_run");
    if (!*run) { fprintf(stderr, "dlsym: %s\n", dlerror()); exit(2); }
    return h;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <none|fork|ipc|mpk|mpk_fast> <calls> <fault_trials>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    long calls = atol(argv[2]), trials = atol(argv[3]);
    iso_call_fn call = iso_by_name(mode);
    if (!call) { fprintf(stderr, "unknown mode: %s\n", mode); return 2; }

    long pagesz = sysconf(_SC_PAGESIZE);
    host_state = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (host_state == MAP_FAILED) { perror("mmap"); return 2; }
    strcpy(host_state, HOST_STATE_OK);
    if (iso_is_mpk(call)) mpk_setup(host_state, pagesz);

    /* 1. Per-call overhead (well-behaved plugin) */
    plugin_fn run;
    void *h = load("build/good.so", &run);
    int out = 0;
    long sum = 0;
    for (long i = 0; i < 1000; i++) { call(run, (int)i, &out); sum += out; }  /* warm-up */
    double t0 = now_ns();
    for (long i = 0; i < calls; i++) { call(run, (int)i, &out); sum += out; }
    double t1 = now_ns();
    printf("%s,call_ns,%.1f\n", mode, (t1 - t0) / calls);
    iso_reset();
    dlclose(h);

    /* 2. Fault + recovery latency (crashing plugin); skipped for none */
    if (call != run_none && trials > 0) {
        h = load("build/nullderef.so", &run);
        double total = 0;
        for (long t = 0; t < trials; t++) {
            double a = now_ns();
            int rc = call(run, 0, &out);
            if (rc != CALL_PLUGIN_FAULT) { fprintf(stderr, "expected fault\n"); return 2; }
            if (iso_is_mpk(call)) { dlclose(h); h = load("build/nullderef.so", &run); }
            total += now_ns() - a;
        }
        printf("%s,fault_recovery_us,%.2f\n", mode, total / trials / 1000.0);
        iso_reset();
        dlclose(h);
    }

    if (strcmp(host_state, HOST_STATE_OK) != 0 || strcmp(host_config, HOST_CONFIG_OK) != 0) {
        fprintf(stderr, "host corrupted\n");
        return 3;
    }
    fprintf(stderr, "checksum=%ld\n", sum);   /* keeps the compiler from discarding the loop */
    return 0;
}
