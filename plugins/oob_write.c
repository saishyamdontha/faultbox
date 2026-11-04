#include <string.h>
#include "plugin.h"
int plugin_run(int input) {
    memset(host_state, 'X', 8);
    return input;
}
