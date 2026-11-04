#ifndef FAULTBOX_PLUGIN_H
#define FAULTBOX_PLUGIN_H

#define HOST_STATE_OK "host-state-ok"

/* Every plugin exports this function */
typedef int (*plugin_fn)(int input);
int plugin_run(int input);

/* Host-owned memory, exported by the host (-rdynamic).
   Plugins must NOT touch it; the faulty ones will try. */
extern char *host_state;

#endif
