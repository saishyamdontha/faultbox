#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include "plugin.h"

char *host_state = NULL;

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <none> <plugin.so>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1], *path = argv[2];

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
    if (strcmp(mode, "none") == 0) {
        out = run(21);
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    int intact = strcmp(host_state, HOST_STATE_OK) == 0;
    printf("mode=%s plugin=%s result=%d host_state=%s\n",
           mode, path, out, intact ? "INTACT" : "CORRUPTED");
    dlclose(h);
    return intact ? 0 : 3;
}
