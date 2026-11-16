# RAM input shift in tsdecrypt

This standalone fork implements a bounded delay of the **whole incoming
transport stream before ECM/EMM extraction**. It is part of the native
`tsdecrypt` executable; no wrapper, Python runtime or web manager is required.
See [PROVENANCE.md](PROVENANCE.md) for the source revisions.

## Purpose and position in the stream chain

```text
DVBlast output / clear network input
    -> tsdecrypt RAM queue, per-channel Shift
    -> process_packets: PSI, ECM/EMM extraction and decryption
    -> output stream -> optional MPTSD
```

For an encrypted channel, delaying its complete input also delays when its ECMs
reach OSCam. Different shifts can spread otherwise simultaneous requests across
time. Giving every channel the same shift moves the entire burst without spreading
it. This does not make a reader faster, increase its capacity, change card
entitlements, or guarantee an ECM response deadline.

The existing `-T / --input-buffer` serves a different purpose: ECM processing
continues immediately while decoding is delayed. It is not the new input shift.
If both are enabled, the input shift is applied before the existing decode buffer.

The queue retains all TS packets, including EIT/EPG, CAT, ECM, EMM, audio and video.
It does not rewrite PCR, PTS/DTS, EPG event times, service IDs or continuity counters.
Subsequent tsdecrypt PID filtering still follows its normal configuration; the
EPG forwarding options remain necessary. Shifting does not reconstruct
missing EPG or repair continuity errors already present in the input.

## Command-line options

| Option | Meaning |
| --- | --- |
| `--input-shift <ms>` | Whole-input delay, integer 0–10000 ms. Default 0. |
| `--input-shift-memory <bytes>` | Hard limit for this process's queue, including queue metadata. Required for a nonzero shift; at least 4096 bytes and enough for one system page and a queue slot. |
| `--input-shift-status <path>` | Optional atomic JSON counters, initially, every 10 seconds and on termination. Prefer a unique file under `/dev/shm`. |
| `--input-passthrough` | Forward the complete TS without CAMD, PSI parsing, decryption or PID filtering; intended for clear inputs. Can be combined with shift. |

For an existing decrypt command, append, for example:

```sh
--input-shift 1200 --input-shift-memory 16777216 \
--input-shift-status /dev/shm/tsdecrypt-channel-201-shift.json
```

This means **1200 ms** with a **16 MiB per-process cap**. Keep the existing service,
CAMD and EPG options. The memory argument is bytes, not MiB. Use a different status
filename for every process.

A complete clear-stream example with local unicast inputs/outputs:

```sh
tsdecrypt --input-passthrough --input 127.0.0.1:15000 --output 127.0.0.1:15001 --input-shift 1200 --input-shift-memory 16777216 --input-shift-status /dev/shm/tsdecrypt-clear-shift.json
```

Choose unused addresses and avoid feeding the output into its own input. tsdecrypt
accepts the address form above, without a `udp://` prefix.

With shift 0 and ordinary decryption, tsdecrypt keeps the original input path and
creates no shift queue or shift status file. Explicit `--input-passthrough` uses the
new input path even at shift 0, with a small 4096-byte queue allocation. Passthrough
cannot be combined with `--input-buffer`, `--emm`, a constant CW, or an ECM/EMM file.
A nonzero input shift also cannot be used for single ECM/EMM file processing.

## Native implementation

| Source | Responsibility |
| --- | --- |
| [`input-shift.h`](../input-shift.h), [`input-shift.c`](../input-shift.c) | Ring layout, bounded anonymous mapping, monotonic deadlines, enqueue/release and memory counters. |
| [`tsdecrypt.c`](../tsdecrypt.c) | CLI parsing, `run_shifted_input()`, input validation, polling, `shifted_dispatch()` and status snapshots. |
| [`process.c`](../process.c), [`process.h`](../process.h) | `output_raw_packets()` for clear passthrough without rewriting TS packets. |
| [`data.h`](../data.h) | Runtime fields for delay, cap, status path and passthrough. |
| [`Makefile`](../Makefile) | Compiles `input-shift.c`; provides `check-shift`. |

`input_shift_create()` reserves one `MAP_PRIVATE | MAP_ANONYMOUS` mapping, rounded
down to the system page size. Its header and fixed-size slots share that cap.
Each slot holds up to seven 188-byte TS packets (1316 bytes), a length and a deadline.
Even a short block occupies a complete slot.

`input_shift_push()` copies complete input packets into the next slot and sets
`due_ns = receive_time + delay_ms`, using `CLOCK_MONOTONIC`. It does not parse ECMs.
`input_shift_ready()` exposes only the oldest block whose deadline has arrived.
`run_shifted_input()` releases due blocks through `shifted_dispatch()` before
polling for more input. It drains at most 64 blocks per iteration, so a backlog
cannot indefinitely prevent input handling.

Dispatch either calls the existing `process_packets()` path or writes raw packets
in passthrough mode. Timing is based on receive-time deadlines, not PCR pacing.
Scheduler delays can make output late and cause catch-up bursts; this is not a
hard real-time scheduler or a constant-bitrate remultiplexer. Discontinuities in
wall-clock time do not change queue deadlines.

UDP payloads must contain aligned MPEG-TS, at most 1316 bytes, with a sync byte at
every 188-byte boundary. RTP input supports the existing fixed 12-byte header and
MPEG-TS payload type 33; extensions and CSRC lists are rejected. Pipe/file reads
can split packets, so incomplete packets are carried over into the next read.
An unpaced file or pipe can fill the queue much faster than a live UDP source.

## Per-process RAM budget

The standalone executable does not coordinate memory across processes. Each
shifted process needs `--input-shift-memory` in bytes. There is no implicit
shared 512 MiB budget; choose the limits for all instances so their sum fits
your available RAM. A separate manager can allocate these shares, but is not
part of this program.

Approximate payload storage in decimal MB is:

```text
input bitrate in Mbps × shift in seconds ÷ 8
```

Add queue metadata, fixed-slot padding and peak/burst headroom. The calculation
uses the complete input rate, including TS tables, not only the video bitrate.
The cap covers shift queue mappings, not decoder memory, socket buffers, ordinary
process memory or the HLS segment queue. `allocated_bytes` is reserved queue
capacity; it is not RSS or current payload occupancy. Pages touched by a circular
queue may remain resident after packets are released.

Stream buffering creates no disk files. Normal OS swap policy still applies;
this implementation does not lock pages with `mlock`. Status snapshots are small
files and stay in RAM when their destination is `/dev/shm`. Ordinary process logs
retain the existing rotating-log behavior.

## Changing settings, errors and shutdown

- Delay and capacity are fixed at process startup. Restart the affected
  instance to change them; its queue must refill before delayed output resumes.
- Stop old instances before starting replacements when enforcing a total
  memory budget, to avoid overlapping reservations.
- A full queue logs `SHIFT | RAM limit reached`, emits `SHIFT_OVERFLOW`, writes an
  `overflow` status and exits unsuccessfully. It never overwrites an old block
  silently or reduces the requested delay. An external supervisor may retry the process;
  persistent overflow needs a larger cap or a smaller delay. An error/restart
  interrupts the output and discards the remaining queue.
- Missing input does not stall already queued blocks: they continue to drain at
  their deadlines. At clean file/pipe EOF the remaining complete packets drain;
  a partial TS packet at EOF is an error.
- SIGINT/SIGTERM stop promptly instead of waiting through the remaining shift.
  Pending CAMD reads are woken during shutdown. Allocation, malformed input and
  input I/O failures also produce visible errors.
- A status-file write failure warns in the log without intentionally stopping
  reception. Check timestamps/PIDs before interpreting a saved snapshot.

There is **no automatic OSCam-driven shift orchestrator or live in-process delay
adjustment** in this version. Shift values and reader assignments are not
automatically calculated or changed.

## Monitoring and verification

Startup logs contain `SHIFT | Whole input delayed ... ms before ECM; RAM ...`.
Search for `SHIFT |` to find buffer startup, input timeout and error messages.

The optional JSON status contains:

- `shift_ms`, `capacity_bytes`, `allocated_bytes`, `capacity_blocks`;
- `used_bytes` and `peak_bytes` (header plus occupied slots), `queued_bytes`
  (TS payload only), and `queued_blocks`;
- `received_blocks`, `released_blocks`, `overflows`, `max_late_ms`;
- `pid`, `state`, `updated_at` (wall-clock Unix seconds).

`max_late_ms` measures queue release lateness, not OSCam ECM response time.
Read these counters without subscribing to another copy of the stream.

Build and check from the repository root:

```sh
make -j2 dvbcsa
./tsdecrypt --help | grep -- '--input-shift'
make check-shift
```

`tests/run-input-shift-test.sh` tests the ring directly. The real-binary tests in
`tests/input_shift_integration.py` cover delayed packet delivery, unchanged TS
payloads, ECM requests delayed before CAMD, quiet-input draining, overflow,
short reads, malformed input, option validation and prompt shutdown (including
a pending CAMD reply). They use synthetic streams without a DVB device,
card server or credentials. They do not establish a real provider's decryption
quality or a reader's timing capacity.
