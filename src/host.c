#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include "isolation.h"

char *host_state = NULL;

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <none|fork|mpk> <plugin.so>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1], *path = argv[2];
    iso_call_fn call = iso_by_name(mode);
    if (!call) { fprintf(stderr, "unknown mode: %s\n", mode); return 2; }

    long pagesz = sysconf(_SC_PAGESIZE);
    host_state = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (host_state == MAP_FAILED) { perror("mmap"); return 2; }
    strcpy(host_state, HOST_STATE_OK);
    if (iso_is_mpk(call)) mpk_setup(host_state, pagesz);
    if (iso_mode_scans(mode)) {
        long hits = iso_scan_wrpkru(path);
        if (hits != 0) {
            printf("mode=%s plugin=%s call=rejected reason=wrpkru_found hits=%ld host_state=INTACT\n",
                   mode, path, hits);
            return 5;
        }
    }

    void *h = dlopen(path, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    plugin_fn run = (plugin_fn)dlsym(h, "plugin_run");
    if (!run) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }

    int out = 0;
    int rc = call(run, 21, &out);

    int recovered = 0;
    if (rc != CALL_OK && iso_is_mpk(call)) {
        dlclose(h);                         /* discard faulted plugin */
        h = dlopen(path, RTLD_NOW);         /* load a fresh instance */
        recovered = (h != NULL);
    }

    int intact = strcmp(host_state, HOST_STATE_OK) == 0;
    printf("mode=%s plugin=%s call=%s fault=%s recovered=%s result=%d host_state=%s\n",
           mode, path, rc == CALL_OK ? "ok" : "plugin_fault",
           iso_fault_name(iso_last_fault_code()), recovered ? "yes" : "no",
           out, intact ? "INTACT" : "CORRUPTED");
    if (h) dlclose(h);

    if (!intact) return 3;
    if (rc != CALL_OK) return 4;
    return 0;
}
