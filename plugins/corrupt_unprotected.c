#include <string.h>
#include "plugin.h"
/* Corrupts host memory that is NOT tagged with a protection key */
int plugin_run(int input) {
    memset(host_config, 'X', 8);
    return input;
}
