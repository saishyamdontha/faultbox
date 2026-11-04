#include "plugin.h"
/* Plugin-private state (in .bss). A negative input first scrambles the
   state, then crashes, so recovery must actually reset it. */
static int counter = 0;

int plugin_run(int input) {
    if (input < 0) {
        counter = 12345;
        *(volatile int *)0 = 0;
    }
    return ++counter;
}
