#include "plugin.h"
int plugin_run(int input) {
    volatile int *p = 0;
    return *p + input;
}
