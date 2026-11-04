#ifndef FAULTBOX_ISOLATION_H
#define FAULTBOX_ISOLATION_H
#include "plugin.h"

enum { CALL_OK = 0, CALL_PLUGIN_FAULT = 1 };
typedef int (*iso_call_fn)(plugin_fn run, int in, int *out);

int run_none(plugin_fn run, int in, int *out);
int run_fork(plugin_fn run, int in, int *out);
int run_mpk(plugin_fn run, int in, int *out);

void mpk_setup(char *protected_page, long pagesz);
iso_call_fn iso_by_name(const char *mode);
int iso_last_fault_code(void);
const char *iso_fault_name(int code);

#endif
