# faultbox

**In-process fault isolation for untrusted C plugins, using x86 memory protection keys (MPK/PKU).**

faultbox is a small C plugin host that runs untrusted plugins (`.so` files) under four isolation
strategies and measures two things for each one: whether the host survives a faulty plugin,
and what the isolation costs per call.

**Key results (AMD Ryzen 9 8940HX, 5 runs, pinned to one core):**

- Without isolation, 2 of 3 test plugins crash or silently corrupt the host. With fork+seccomp or MPK isolation, the host survives 100% of injected faults with its state intact.
- MPK isolation adds **~21 ns per call**, about **4,500x cheaper** than fork+seccomp process isolation (24 ns vs 109 µs).
- A naive MPK implementation costs 313 ns per call. **~92% of that is signal-mask bookkeeping** in `sigsetjmp`, not the protection-key switch itself. Removing it safely (`SA_NODEFER` + mask-free `sigsetjmp`) brings the cost down to 24 ns.

---

## Threat and fault model

**Asset:** host-owned memory (`host_state`, one page) holding state the host must keep intact.

**Plugin behaviour considered:**

| Fault class | Plugin | Effect without isolation |
|---|---|---|
| Crash | `nullderef.so` (null pointer dereference) | Host process killed (SIGSEGV) |
| Memory corruption | `oob_write.so` (writes into `host_state`) | Host keeps running with **silently corrupted** state |
| Control | `good.so` | Correct result |

**In scope:** buggy plugins, i.e. accidental memory-safety faults.

**Out of scope (see Limitations):** deliberately malicious plugins. In the MPK modes, a malicious
plugin can execute `WRPKRU` and re-enable access to protected memory. This project demonstrates
*fault* isolation, not a security sandbox.

---

## Isolation modes

| Mode | Mechanism | Fault handling |
|---|---|---|
| `none` | Plugin runs directly in the host address space | None |
| `fork` | Child process per call, locked down with `seccomp` strict mode (only `read`, `write`, `exit`, `sigreturn`); result returned via pipe | Child dies; parent sees abnormal exit. Corruption lands in the child's copy-on-write memory |
| `mpk` | `host_state` tagged with a protection key; access disabled (`pkey_set`) while the plugin runs, in the same process | SIGSEGV handler `siglongjmp`s back to the host, restores PKRU, then discards (`dlclose`) and reloads (`dlopen`) the plugin |
| `mpk_fast` | Same as `mpk`, but `sigsetjmp(buf, 0)` (no signal-mask save) with an `SA_NODEFER` handler | Same as `mpk` |

Implementation details worth noting:

- **PKRU after a signal:** the kernel resets PKRU on signal delivery, and `siglongjmp` skips `sigreturn`, so the host explicitly restores access to its key after recovery.
- **Why `SA_NODEFER` makes `mpk_fast` correct:** without it, SIGSEGV stays blocked after jumping out of the handler (because the mask is not restored), and the next fault would kill the process.
- **Fork child:** exits with `syscall(SYS_exit)` because glibc's `_exit()` uses `exit_group`, which seccomp strict mode forbids. It is also marked non-dumpable so crashing children do not write core dumps.
- **Fault classification:** in MPK modes the null dereference is reported as `SEGV_MAPERR` and the host-memory write as `SEGV_PKUERR`. **MPK is what blocks the corruption; the signal handler is what survives the crash.**

---

## Results

### Fault containment (`results/faults.csv`)

| Mode | good | nullderef | oob_write |
|---|---|---|---|
| none | ok | **host crashed** (SIGSEGV) | **host state corrupted** |
| fork | ok | fault contained | ok (write hit the child's private copy) |
| mpk | ok | fault contained, plugin reloaded | fault contained, plugin reloaded |
| mpk_fast | ok | fault contained, plugin reloaded | fault contained, plugin reloaded |

### Performance (`results/bench.csv`, mean of 5 runs)

| Mode | Per-call time | Overhead vs `none` | Fault + recovery |
|---|---|---|---|
| none | 2.9 ns | — | — |
| mpk_fast | 23.9 ns | +21 ns | 29.8 µs |
| mpk | 313 ns | +310 ns | 30.9 µs |
| fork | 109,070 ns | +109 µs | 110 µs |

Methodology:

- Per-call time: 1,000,000 calls of `good.so` (10,000 for `fork`), after 1,000 warm-up calls, timed with `CLOCK_MONOTONIC`.
- Fault + recovery: mean over 1,000 calls of `nullderef.so`. For MPK modes this includes `dlclose` + `dlopen` of the plugin; for `fork` it is the full lifetime of the faulting child.
- 5 repetitions per mode, pinned to CPU core 2 with `taskset`.

### Observations

1. **The domain switch is cheap; bookkeeping is not.** `sigsetjmp(buf, 1)` saves the signal mask with a syscall on every call. It accounts for ~92% of the naive MPK cost ((313 - 24) / 313).
2. **Recovery is dominated by plugin reload.** Both MPK modes recover in ~30 µs regardless of call-path cost, which points to `dlclose`/`dlopen` rather than the fault handling itself. This has not been measured separately yet.
3. **Process isolation is safe but expensive per call.** It also gets corruption protection "for free" through copy-on-write, but costs ~109 µs per call because of `fork` + `waitpid`.

---

## Limitations

- **Not secure against malicious plugins:** a plugin can execute `WRPKRU` (or call `pkey_set`) to re-enable access. Mitigations used in research systems include binary inspection for `WRPKRU`, call gates, and syscall filtering; none are implemented here.
- **Only one page is protected.** The rest of host memory (heap, stack, globals) remains accessible to the plugin in MPK modes.
- **No syscall restriction in MPK modes:** plugins can call any syscall (only `fork` mode uses seccomp).
- **Single-threaded:** PKRU is per-thread, and the recovery state (`sigjmp_buf`, flags) is global.
- **No timeout handling:** a plugin that loops forever hangs the host in `none`/MPK modes.
- **Reload resets plugin memory only:** external side effects (files, sockets) are not rolled back.
- **One machine:** results come from a single AMD Ryzen 9 8940HX laptop.

---

## Reproduce

Requirements: Linux on an x86-64 CPU with PKU (`grep -o -m1 pku /proc/cpuinfo`), gcc, glibc >= 2.27.

~~~bash
./scripts/build.sh        # builds host, bench, and the 3 plugins into build/
./scripts/run_faults.sh   # fault containment -> results/faults.csv
./scripts/run_bench.sh    # performance       -> results/bench.csv (5 reps, prints means)
~~~

Single run:

~~~bash
./build/host mpk build/oob_write.so
# mode=mpk plugin=build/oob_write.so call=plugin_fault fault=SEGV_PKUERR recovered=yes result=0 host_state=INTACT
~~~

---

## Repository layout

~~~
src/plugin.h       plugin interface (plugin_run, host_state)
src/isolation.c/h  the four isolation modes and MPK fault handling
src/host.c         runs one plugin call under a chosen mode and reports the outcome
src/bench.c        per-call overhead and fault-recovery benchmark
src/mpk_spike.c    minimal standalone MPK fault-and-recover demo
plugins/           good.c, nullderef.c, oob_write.c
scripts/           build.sh, run_faults.sh, run_bench.sh
results/           faults.csv, bench.csv
~~~

## Environment

- CPU: AMD Ryzen 9 8940HX (PKU supported)
- OS: Ubuntu 24.04, Linux 7.0.0-42-generic
- Compiler: gcc, host built with `-O2`, plugins with `-O0` so fault code is kept as written

## Related work

In-process isolation with protection keys has been explored in research systems such as ERIM and
Hodor (MPK-based isolation with defenses against `WRPKRU` misuse) and Secure Domain Rewind and
Discard (SDRaD), which uses isolated memory domains with rollback-based recovery. faultbox is a
small, self-contained study of the cost and containment trade-offs between process-level and
MPK-based isolation, not an implementation of those systems.
