#include "plugin.h"
/* Integer division by zero -> SIGFPE */
int plugin_run(int input) {
    volatile int zero = 0;
    return input / zero;
}
