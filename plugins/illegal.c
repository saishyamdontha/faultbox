#include "plugin.h"
/* Illegal instruction (ud2) -> SIGILL */
int plugin_run(int input) {
    __builtin_trap();
    return input;
}
