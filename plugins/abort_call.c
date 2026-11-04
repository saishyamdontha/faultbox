#include <stdlib.h>
#include "plugin.h"
/* Failed assertion style abort -> SIGABRT */
int plugin_run(int input) {
    abort();
    return input;
}
