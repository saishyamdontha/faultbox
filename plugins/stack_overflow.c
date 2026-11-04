#include "plugin.h"
/* Unbounded recursion -> stack overflow -> SIGSEGV on the guard page.
   The handler can only run if it has an alternate signal stack. */
static int recurse(int depth) {
    volatile char buf[1024];
    buf[0] = (char)depth;
    return recurse(depth + 1) + buf[0];
}
int plugin_run(int input) {
    return recurse(input);
}
