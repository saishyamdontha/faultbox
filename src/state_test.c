#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include "isolation.h"

char *host_state = NULL;
char host_config[64] = HOST_CONFIG_OK;

/* Recovery correctness test with a stateful plugin:
     call(1)  -> 1
     call(-1) -> plugin sets its state to 12345, then crashes
     recover with: skip | reload | snapshot
     call(1)  -> 1 if plugin state was really reset, 12346 if stale.
   "skip" is the negative control: it must FAIL, proving the test can detect
   stale state. */
static int host_main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <mpk|mpk_fast|mpk_hard> <skip|reload|snapshot>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1], *recovery = argv[2];
    iso_call_fn call = iso_by_name(mode);
    if (!call || !iso_is_mpk(call)) { fprintf(stderr, "MPK modes only\n"); return 2; }

    long pagesz = sysconf(_SC_PAGESIZE);
    host_state = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (host_state == MAP_FAILED) { perror("mmap"); return 2; }
    strcpy(host_state, HOST_STATE_OK);
    mpk_setup(host_state, pagesz);
    if (iso_mode_hardens(mode)) iso_harden();

    const char *path = "build/stateful.so";
    void *h = dlopen(path, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    plugin_fn run = (plugin_fn)dlsym(h, "plugin_run");
    if (!run) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }
    if (strcmp(recovery, "snapshot") == 0 && iso_snapshot_take(h) <= 0) {
        fprintf(stderr, "snapshot failed\n");
        return 2;
    }

    int first = 0, crashed = 0, after = 0;
    call(run, 1, &first);
    int rc = call(run, -1, &crashed);
    if (rc != CALL_OK) {
        if (strcmp(recovery, "snapshot") == 0) {
            iso_snapshot_restore();
        } else if (strcmp(recovery, "reload") == 0) {
            dlclose(h);
            h = dlopen(path, RTLD_NOW);
            if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
            run = (plugin_fn)dlsym(h, "plugin_run");
            if (!run) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }
        }
    }
    call(run, 1, &after);

    int pass = (first == 1 && rc != CALL_OK && after == 1);
    printf("%s,%s,%d,%s,%d,%s\n", mode, recovery, first,
           rc != CALL_OK ? "fault" : "no_fault", after, pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}

int main(int argc, char **argv) {
    iso_exit(host_main(argc, argv));
}
