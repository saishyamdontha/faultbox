# faultbox

**Cost, coverage and recovery of in-process fault isolation with x86 memory protection keys (MPK/PKU), measured against process isolation.**

**Technical report:** [PDF](docs/faultbox-technical-report.pdf) ([Markdown source](docs/technical-report.md))

faultbox is a C plugin host that runs untrusted plugins (`.so` files) under seven isolation modes.
For each mode it measures which faults the host survives, what isolation costs per call, and how
fast the host recovers after a plugin crashes.

## Key results

AMD Ryzen 9 8940HX, performance power profile, means of 5 runs.

- **Recovery is where in-process isolation wins.** `mpk_hard` recovers from a crashing plugin in
  **1.5 µs** by rewinding the plugin's memory from a load-time snapshot. That is ~80x faster than
  respawning a sandboxed worker process (~120 µs) and ~20x faster than reloading the plugin (30 µs).
- **Per-call cost: a modest win against the best process baseline.** MPK adds ~21 ns per call. The
  fastest process boundary measured, a shared-memory worker spinning on a second core, adds ~42 ns
  (~1.9x more) and permanently occupies a CPU core. A pipe-based worker adds ~5.4 µs (~250x more).
- **Coverage.** Process isolation keeps the host intact against all 9 faulty or malicious plugins.
  Plain MPK isolation manages 6/9. Adding a seccomp-BPF exit gate and a `WRPKRU` scanner
  (`mpk_hard`) raises this to 8/9; writes to unprotected host memory remain uncontained.
- **Where the cost hides.** Naive MPK costs 313 ns per call; ~92% of it is one `rt_sigprocmask`
  syscall per call from saving the signal mask (101,000 vs 0 calls under `strace`). Removing it
  safely gives 24 ns.

---

## Threat and fault model

**Assets:** `host_state`, one page tagged with a protection key in MPK modes, and `host_config`, an
ordinary global that is never protected.

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
| `stateful` | Scrambles its own state, then crashes (recovery test only) | state reset check |

The primary model is a **buggy** plugin. The malicious plugin tests where the MPK boundary fails.
This project demonstrates *fault* isolation, not a security sandbox.

---

## Isolation modes

| Mode | Mechanism | Recovery after a fault |
|---|---|---|
| `none` | Plugin runs in the host address space | None |
| `fork` | New process per call, `seccomp` strict | Child dies; next call forks again |
| `ipc` | Persistent worker under `seccomp` strict; pipe round-trip per call | Worker reaped and respawned |
| `ipc_shm` | Persistent worker under `seccomp` strict; shared-memory channel, both sides spin on separate cores | Worker reaped and respawned |
| `mpk` | `host_state` key disabled while the plugin runs; signal handler recovers | Plugin reloaded (`dlclose` + `dlopen`) |
| `mpk_fast` | As `mpk`, without saving the signal mask | Plugin reloaded |
| `mpk_hard` | As `mpk_fast`, plus a seccomp-BPF exit gate and a load-time `WRPKRU` scan | Plugin memory restored from a load-time snapshot |

Implementation notes:

- **Signals in MPK modes:** SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT and SIGSYS are handled on an
  **alternate signal stack**, so even a stack overflow is recoverable. The kernel resets PKRU on
  signal delivery and `siglongjmp` skips `sigreturn`, so the host restores access to its key
  explicitly.
- **`SA_NODEFER`:** required to skip the signal-mask save. Otherwise the signal stays blocked after
  jumping out of the handler, and the next fault kills the process.
- **Exit gate (`mpk_hard`):** seccomp filters cannot be removed, so the filter blocks `exit` and
  `exit_group` for the whole process **unless the syscall comes from one instruction in the host**,
  checked through the instruction pointer. A plugin calling `exit()` gets SIGSYS and is recovered.
  All host exits go through that gate.
- **Snapshot recovery (`mpk_hard`):** at load, the plugin's writable segments (`.data`/`.bss`,
  excluding RELRO) are copied; after a fault they are copied back.
- **Process modes:** workers are non-dumpable, exit with `syscall(SYS_exit)` (seccomp strict forbids
  `exit_group`), and die with the host (`PR_SET_PDEATHSIG`). The host ignores SIGPIPE. A respawned
  `ipc_shm` worker signals readiness before the host starts spinning; without this, the new worker
  starved on the host's core and recovery took ~3 ms instead of ~121 µs.

---

## Results

### Fault containment (`results/faults.csv`)

| Plugin | none | fork | ipc | ipc_shm | mpk / mpk_fast | mpk_hard |
|---|---|---|---|---|---|---|
| good | ok | ok | ok | ok | ok | ok |
| nullderef | crashed | contained | contained | contained | contained | contained |
| oob_write | corrupted | ok\* | ok\* | ok\* | contained | contained |
| corrupt_unprotected | corrupted | ok\* | ok\* | ok\* | **corrupted** | **corrupted** |
| divzero | crashed | contained | contained | contained | contained | contained |
| illegal | crashed | contained | contained | contained | contained | contained |
| abort_call | crashed | contained | contained | contained | contained | contained |
| stack_overflow | crashed | contained | contained | contained | contained | contained |
| exit_call | host exited | contained | contained | contained | **host exited** | contained |
| wrpkru_attack | corrupted | ok\* | ok\* | ok\* | **corrupted** | rejected at load |
| **Host intact (of 9)** | **0** | **9** | **9** | **9** | **6** | **8** |

\* The write landed in the worker's private copy-on-write memory. In process modes, `abort_call` and
`exit_call` are contained because seccomp kills the worker on the forbidden syscall.

### Performance (`results/bench.csv`, mean of 5 runs)

| Mode | Per call | Overhead vs `none` | Fault + recovery | Recovery method |
|---|---|---|---|---|
| none | 2.7 ns | – | – | – |
| mpk_hard | 24.1 ns | +21.4 ns | 1.5 µs | snapshot restore |
| mpk_fast | 23.9 ns | +21.2 ns | 30.4 µs | plugin reload |
| mpk | 313 ns | +310 ns | 31.3 µs | plugin reload |
| ipc_shm | 44.2 ns | +41.5 ns | 120.8 µs | worker respawn (uses 2 cores) |
| ipc | 5,399 ns | +5.4 µs | 119.3 µs | worker respawn |
| fork | 111,835 ns | +112 µs | 110.2 µs | new process per call |

Methodology:

- Per-call time: calls to `good.so` after 1,000 warm-up calls, timed with `CLOCK_MONOTONIC`.
  1,000,000 calls for `none`, MPK modes and `ipc_shm`; 100,000 for `ipc`; 10,000 for `fork`.
- Fault + recovery: mean over 1,000 calls to `nullderef.so`, including the recovery step.
- Pinned to CPU 2; `ipc_shm` uses CPUs 2 and 4 (separate physical cores). Performance power profile,
  on AC power. 5 repetitions, means reported; a second independent 5-run batch agreed within ~5%.

### Recovery correctness (`results/state.csv`)

`stateful` returns 1, then scrambles its state to 12345 and crashes; after recovery, a correct reset
returns 1 again.

| Mode | Recovery | After recovery | Result |
|---|---|---|---|
| mpk_fast | skip (negative control) | 12346 | FAIL, as expected: the test detects stale state |
| mpk_fast | reload | 1 | PASS |
| mpk_fast | snapshot | 1 | PASS |
| mpk_hard | snapshot | 1 | PASS |

### Observations

1. **In-process isolation's clear win is recovery, not call speed.** Snapshot recovery (1.5 µs) is
   ~80x faster than respawning any process-based worker.
2. **The recovery method matters as much as the isolation mechanism.** Same mode, same fault:
   reload takes 30 µs, snapshot restore 1.5 µs.
3. **Against a well-engineered process boundary, MPK's per-call advantage is ~1.9x**, and the
   process version costs a permanently busy core. Against a conventional pipe-based worker it is
   ~250x.
4. **Most MPK "containment" comes from signal handling, not from MPK.** Only `oob_write` is stopped
   by the protection key itself (`SEGV_PKUERR`).
5. **The domain switch is cheap; bookkeeping is not.** ~92% of naive MPK overhead was one
   `rt_sigprocmask` syscall per call (`results/strace_sigprocmask.txt`).

---

## Limitations

- **Unprotected memory:** only `host_state` is key-protected; `corrupt_unprotected` shows the rest
  of host memory is open to plugins in MPK modes.
- **Exit gate side effects:** when a plugin calls `exit()`, glibc runs `atexit` handlers and flushes
  stdio before the blocked syscall, so some exit-time side effects happen before recovery.
- **Not secure against malicious plugins:** the `WRPKRU` scanner misses `pkey_set()` in libc,
  `XRSTOR` and code generated at runtime; it can flag chance byte matches, and scans by path before
  loading (a time-of-check/time-of-use window). A malicious plugin could also jump to the host's
  exit gate.
- **Snapshot scope:** restores `.data`/`.bss` only, not plugin heap allocations, mmaps or TLS. A
  fault inside libc while holding a lock (e.g. inside `malloc`) could leave the host deadlocked
  under any in-process recovery.
- **`ipc_shm` occupies a core** for as long as the worker exists.
- **Single-threaded;** no hang detection; one machine; means only.

---

## Reproduce

Requirements: Linux on an x86-64 CPU with PKU (`grep -o -m1 pku /proc/cpuinfo`), gcc, glibc >= 2.27,
at least 2 CPU cores for `ipc_shm`.

~~~bash
./scripts/build.sh        # builds host, bench, state_test and all plugins
./scripts/run_faults.sh   # fault containment   -> results/faults.csv
./scripts/run_state.sh    # recovery correctness -> results/state.csv
./scripts/run_bench.sh    # performance          -> results/bench.csv (5 reps, prints means)
~~~

## Repository layout

~~~
src/plugin.h       plugin interface (plugin_run, host_state, host_config)
src/isolation.c/h  isolation modes, MPK fault handling, exit gate, snapshot, WRPKRU scanner
src/host.c         runs one plugin call under a chosen mode and reports the outcome
src/bench.c        per-call overhead and fault-recovery benchmark
src/state_test.c   recovery correctness test with a negative control
src/mpk_spike.c    minimal standalone MPK fault-and-recover demo
plugins/           11 test plugins
scripts/           build.sh, run_faults.sh, run_state.sh, run_bench.sh
results/           faults.csv, state.csv, bench.csv, strace_sigprocmask.txt
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
small, self-contained study of the cost, coverage and recovery trade-offs between process-level and
MPK-based isolation, not an implementation of those systems.
