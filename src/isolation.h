#ifndef FAULTBOX_ISOLATION_H
#define FAULTBOX_ISOLATION_H
#include "plugin.h"

enum { CALL_OK = 0, CALL_PLUGIN_FAULT = 1 };
typedef int (*iso_call_fn)(plugin_fn run, int in, int *out);

int run_none(plugin_fn run, int in, int *out);      /* no isolation */
int run_fork(plugin_fn run, int in, int *out);      /* new sandboxed process per call */
int run_ipc(plugin_fn run, int in, int *out);       /* persistent sandboxed worker */
int run_mpk(plugin_fn run, int in, int *out);       /* MPK domain, saves signal mask */
int run_mpk_fast(plugin_fn run, int in, int *out);  /* MPK domain, no mask save */

void mpk_setup(char *protected_page, long pagesz);
void iso_reset(void);                                /* stop the ipc worker, if any */

iso_call_fn iso_by_name(const char *mode);
int iso_is_mpk(iso_call_fn call);
int iso_mode_scans(const char *mode);
long iso_scan_wrpkru(const char *path);
const char *iso_last_fault(void);

void iso_harden(void);
int iso_mode_hardens(const char *mode);
__attribute__((noreturn)) void iso_exit(int code);

int iso_snapshot_take(void *handle);
void iso_snapshot_restore(void);
void iso_snapshot_free(void);

#endif
