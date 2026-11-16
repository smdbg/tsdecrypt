# Changes from upstream

## Standalone fork — 2026-11-16

Based on `gfto/tsdecrypt` revision `f4876e84cf1866645f84b93f830af67193c85f69`.
The original history and notices are retained; see [docs/PROVENANCE.md](docs/PROVENANCE.md).

- `camd-cs378x.c`: recognize OSCam's `0x50` extended-mode announcement as a
  control message, then continue reading the pending legacy CW reply. No
  extended-mode negotiation is introduced. Existing `0x05` handling remains.
- `input-shift.c/h`: bounded anonymous RAM ring, monotonic release deadlines,
  per-process cap including metadata, and queue/overflow/lateness counters.
- `tsdecrypt.c`, `data.h`: native shift/passthrough options, input polling and
  validation, 10-second optional JSON statistics, EOF draining and prompt
  shutdown including a pending CAMD read.
- `process.c/h`: clear raw packet forwarding, interrupted-write handling and
  explicit detection of short output writes.
- `Makefile`: compile the new native module, default to libdvbcsa in a fresh
  checkout, retain the selected backend when installing, and add test targets.
- Include pinned libfuncs/libtsfuncs source directories instead of requiring
  submodule downloads. Preserve their own MIT licenses.
- Document CLI behavior and memory limits in the README, manual and RAM guide.
- Add synthetic cs378x, queue and real-binary input-shift regression tests.

The executable does not allocate a shared cross-process budget, calculate shift
values from OSCam logs, or change card-reader assignments. The original CSA
implementations remain unchanged. Web management and container deployment from
the development project are not included in this standalone fork.
