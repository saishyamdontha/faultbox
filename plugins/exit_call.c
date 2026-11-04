#include <stdlib.h>
#include "plugin.h"
/* Calls exit(): not a memory fault, but it ends whatever process it runs in */
int plugin_run(int input) {
    (void)input;
    exit(42);
}
