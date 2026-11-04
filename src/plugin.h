#ifndef FAULTBOX_PLUGIN_H
#define FAULTBOX_PLUGIN_H

#define HOST_STATE_OK  "host-state-ok"
#define HOST_CONFIG_OK "host-config-ok"

/* Every plugin exports this function */
typedef int (*plugin_fn)(int input);
int plugin_run(int input);

/* Host memory visible to plugins (exported by the host with -rdynamic):
   host_state  - one page, tagged with a protection key in MPK modes
   host_config - an ordinary global, never protected */
extern char *host_state;
extern char host_config[];

#endif
