# faultbox

**In-process fault isolation for untrusted C plugins with x86 memory protection keys (MPK/PKU), compared against process isolation.**

**Technical report:** [PDF](docs/faultbox-technical-report.pdf) ([Markdown source](docs/technical-report.md))

faultbox is a small C plugin host that runs untrusted plugins (`.so` files) under six isolation
modes. For each mode it measures which faults the host survives, and what isolation costs per call
and per recovery.

## Key results

AMD Ryzen 9 8940HX, means of 5 runs pinned to one core.

- **Containment.** Without isolation, all 9 faulty or malicious test plugins crash, kill or corrupt
  the host. Process isolation (`fork`, `ipc`) keeps the host intact against all 9. MPK isolation
  contains 6 of 9: every crash-type fault, but not writes to unprotected host memory, `exit()`, or a
  plugin executing `WRPKRU`.
- **Cost.** The MPK domain switch adds ~21 ns per call. That is ~225x cheaper than a persistent
  seccomp-sandboxed worker process (24 ns vs 5.5 µs per call), and ~4,700x cheaper than forking a
  sandboxed process per call (114 µs).
- **Where the cost hides.** A naive MPK implementation costs 314 ns per call. ~92% of that is
  signal-mask bookkeeping in `sigsetjmp` (one `rt_sigprocmask` syscall per call, confirmed with
  `strace`), not the key switch. Removing it safely (`SA_NODEFER` + mask-free `sigsetjmp`) gives 24 ns.
- **Recovery.** MPK recovers from a crashing plugin in ~30 µs (discard + reload), versus ~125 µs to
  respawn a sandboxed worker.
- **Bypass.** A plugin that executes `WRPKRU` defeats MPK isolation. A load-time scanner (`mpk_scan`)
  rejects it with no false positives on the other 9 plugins, but misses indirect routes such as
  calling glibc's `pkey_set()`.

---

## Threat and fault model

**Assets:** two pieces of host memory.
- `host_state`: one page, tagged with a protection key in MPK modes.
- `host_config`: an ordinary global, never protected.

| Plugin | Behaviour | Fault class |
|---|---|---|
| `good` | Returns `2 * input` | control |
| `nullderef` | Null pointer dereference | crash (SIGSEGV) |
| `oob_write` | Writes into `host_state` (protected) | memory corruption |
| `corrupt_unprotected` | Writes into `host_config` (unprotected) | memory corruption |
| `divzero` | Integer division by zero | crash (SIGFPE) |
| `illegal` | Executes `ud2` | crash (SIGILL) |
| `abort_call` | Calls `abort()` | crash (SIGABRT) |
| `stack_overflow` | Unbounded recursion | crash (SIGSEGV on guard page) |
| `exit_call` | Calls `exit(42)` | process termination |
| `wrpkru_attack` | Executes `WRPKRU` with PKRU = 0, then writes `host_state` | malicious bypass |

The primary model is a **buggy** plugin. The malicious plugin tests where the MPK boundary fails.
This project demonstrates *fault* isolation, not a security sandbox.

---

## Isolation modes

| Mode | Mechanism | Fault handling |
|---|---|---|
| `none` | Plugin runs in the host address space | None |
| `fork` | New process per call, `seccomp` strict mode; result via pipe | Child dies; host continues |
| `ipc` | One persistent worker process under `seccomp` strict; each call is a pipe round-trip | Dead worker is reaped and respawned |
| `mpk` | `host_state` tagged with a protection key; access disabled while the plugin runs | Signal handler `siglongjmp`s back, restores PKRU, discards (`dlclose`) and reloads (`dlopen`) the plugin |
| `mpk_fast` | As `mpk`, with `sigsetjmp(buf, 0)` (no signal-mask save) | As `mpk` |
| `mpk_scan` | As `mpk_fast`, plus a load-time scan rejecting any plugin file containing `0F 01 EF` (`WRPKRU`) | As `mpk`; flagged plugins are never loaded |

Implementation notes:

- **PKRU after recovery:** the kernel resets PKRU on signal delivery, and `siglongjmp` skips
  `sigreturn`, so the host restores access to its key explicitly.
- **Signals handled in MPK modes:** SIGSEGV, SIGBUS, SIGFPE, SIGILL and SIGABRT, on an **alternate
  signal stack** (`sigaltstack`). Without it, a stack overflow leaves the handler no stack to run on.
- **`SA_NODEFER`:** required for `mpk_fast`. Without it, the signal stays blocked after jumping out of
  the handler (the mask is not restored), and the next fault kills the process.
- **Process modes:** children are marked non-dumpable and exit with `syscall(SYS_exit)`, because
  glibc's `_exit()` uses `exit_group`, which seccomp strict forbids. The host ignores SIGPIPE so that
  writing to a dead worker cannot kill it.

---

## Results

### Fault containment (`results/faults.csv`)

| Plugin | none | fork | ipc | mpk / mpk_fast | mpk_scan |
|---|---|---|---|---|---|
| good | ok | ok | ok | ok | ok |
| nullderef | crashed (SIGSEGV) | contained | contained | contained | contained |
| oob_write | corrupted | ok\* | ok\* | contained | contained |
| corrupt_unprotected | corrupted | ok\* | ok\* | **corrupted** | **corrupted** |
| divzero | crashed (SIGFPE) | contained | contained | contained | contained |
| illegal | crashed (SIGILL) | contained | contained | contained | contained |
| abort_call | crashed (SIGABRT) | contained | contained | contained | contained |
| stack_overflow | crashed (SIGSEGV) | contained | contained | contained | contained |
| exit_call | host exited | contained | contained | **host exited** | **host exited** |
| wrpkru_attack | corrupted | ok\* | ok\* | **corrupted** | rejected at load |
| **Host intact (of 9 bad plugins)** | **0** | **9** | **9** | **6** | **7** |

\* The write landed in the worker's private copy-on-write memory, so host memory was never touched.
In process modes, `abort_call` and `exit_call` are contained because seccomp kills the worker
when it attempts a forbidden syscall.

### Performance (`results/bench.csv`, mean of 5 runs)

| Mode | Per call | Overhead vs `none` | Fault + recovery |
|---|---|---|---|
| none | 3.3 ns | – | – |
| mpk_fast | 24.4 ns | +21 ns | 30.1 µs |
| mpk | 314 ns | +311 ns | 31.1 µs |
| ipc | 5,508 ns | +5.5 µs | 125.1 µs |
| fork | 113,838 ns | +114 µs | 111.7 µs |

Methodology:

- Per-call time: calls to `good.so` after 1,000 warm-up calls, timed with `CLOCK_MONOTONIC`.
  1,000,000 calls for `none`/MPK modes, 100,000 for `ipc`, 10,000 for `fork`.
- Fault + recovery: mean over 1,000 calls to `nullderef.so`, including plugin reload (MPK) or worker
  respawn (`ipc`).
- 5 repetitions per mode, pinned to CPU core 2 with `taskset`.
- `mpk_scan` has the same call path as `mpk_fast` and was not benchmarked separately.

### Observations

1. **Cost vs coverage is the real trade-off.** MPK is ~225x cheaper per call than a sandboxed worker
   but contains 6 of 9 fault classes, against 9 of 9 for process isolation.
2. **Most MPK "containment" comes from signal handling, not from MPK.** Only `oob_write` is stopped by
   the protection key itself (`SEGV_PKUERR`). The other five crash faults survive because of the
   handler and the alternate stack.
3. **The domain switch is cheap; bookkeeping is not.** ~92% of naive MPK overhead was one
   `rt_sigprocmask` syscall per call.
4. **Recovery is dominated by process or library setup.** MPK recovery (~30 µs) is likely dominated by
   `dlclose`/`dlopen`. Worker respawn (~125 µs) is likely slower than the fork-per-call fault path
   because it reaps the dead worker and sets up new pipes in addition to forking. Neither has been
   broken down further yet.

---

## Limitations

- **Only one page is protected in MPK modes.** `corrupt_unprotected` shows that the rest of host
  memory is open to plugins.
- **No syscall filtering in MPK modes.** `exit_call` shows a plugin can end the host process.
- **The `WRPKRU` scanner is partial.** It does not stop a plugin from calling glibc's `pkey_set()` (the
  instruction then lives in libc), `XRSTOR`, or code generated at runtime, and may flag chance byte
  matches. It also scans the file by path before loading it, which leaves a time-of-check/time-of-use
  window.
- **Single-threaded:** PKRU is per-thread, and recovery state is global.
- **No hang detection:** a looping plugin blocks the host in `none` and MPK modes.
- **Recovery from repeated `abort()` in one process is untested.** Each fault was tested once per
  host process.
- **Reload resets plugin memory only,** not external side effects.
- **One machine, means only;** CPU frequency scaling was not fixed.

---

## Reproduce

Requirements: Linux on an x86-64 CPU with PKU (`grep -o -m1 pku /proc/cpuinfo`), gcc, glibc >= 2.27.

~~~bash
./scripts/build.sh        # builds host, bench and all plugins into build/
./scripts/run_faults.sh   # fault containment -> results/faults.csv
./scripts/run_bench.sh    # performance       -> results/bench.csv (5 reps, prints means)
~~~

Single run:

~~~bash
./build/host mpk build/oob_write.so
~~~

## Repository layout

~~~
src/plugin.h       plugin interface (plugin_run, host_state, host_config)
src/isolation.c/h  the six isolation modes, MPK fault handling, WRPKRU scanner
src/host.c         runs one plugin call under a chosen mode and reports the outcome
src/bench.c        per-call overhead and fault-recovery benchmark
src/mpk_spike.c    minimal standalone MPK fault-and-recover demo
plugins/           10 test plugins (see threat model)
scripts/           build.sh, run_faults.sh, run_bench.sh
results/           faults.csv, bench.csv
docs/              technical report (Markdown + PDF)
~~~

## Environment

- CPU: AMD Ryzen 9 8940HX (PKU supported)
- OS: Ubuntu 24.04, Linux 7.0.0-42-generic
- Compiler: gcc. Host built with `-O2`, plugins with `-O0` so the fault code is kept as written.

## Related work

In-process isolation with protection keys has been explored in research systems such as ERIM and
Hodor (MPK-based isolation with defenses against `WRPKRU` misuse) and Secure Domain Rewind and
Discard (SDRaD), which uses isolated memory domains with rollback-based recovery. faultbox is a
small, self-contained study of the cost and containment trade-offs between process-level and
MPK-based isolation, not an implementation of those systems.
