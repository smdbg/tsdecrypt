# tsdecrypt — standalone fork

A fork of [gfto/tsdecrypt](https://github.com/gfto/tsdecrypt), originally by
Georgi Chorbadzhiyski. It decrypts DVB-CSA MPEG transport streams using control
words from a cs378x or newcamd server. The original Git history is preserved.

This fork adds a **cs378x `0x50` control-reply fix** and **bounded whole-input
RAM Shift**. It is an ordinary native program, with no Docker or web interface
required. It does not use FFmpeg or transcode audio/video.

## Changes in this fork

- Keep waiting for the current legacy CW reply after OSCam's `0x50`
  extended-mode announcement, preventing a queued reply being read for the next
  request. The program does not negotiate the extended mode.
- Delay the entire incoming TS before ECM/EMM extraction and decryption, using
  a bounded RAM queue and monotonic deadlines. Different per-channel shifts can
  spread ECM requests over time; identical shifts do not spread a burst.
- Optional clear-stream passthrough with the same input shift, without CAMD or
  decryption. EPG, ECM, EMM and other packets are retained by the shift queue.
- Explicit per-process queue caps, atomic JSON statistics and visible overflow
  failure rather than silent packet overwriting.
- Preserve the selected CSA backend during build/install; a fresh checkout uses
  libdvbcsa. The existing FFdecsa backend remains available explicitly.

See [CHANGELOG.md](CHANGELOG.md) and [RAM Shift documentation](docs/RAM_INPUT_SHIFT.md).
The CSA algorithms, supported CAM protocols and ordinary PID filtering remain
those of tsdecrypt; this is not a new decoder or automatic card scheduler.

## Build and install

The supported/tested platform for this fork is Linux. On Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y git build-essential libssl-dev libdvbcsa-dev python3
git clone https://github.com/smdbg/tsdecrypt.git
cd tsdecrypt
make -j2
make test
sudo make install
```

Python 3 is only needed for the tests. Runtime dependencies are OpenSSL,
libdvbcsa and the system libraries. `libfuncs` and `libtsfuncs` are included as
source at pinned revisions; **no submodule download is required**.

Installation defaults to `/usr/local`. `PREFIX` and `DESTDIR` are supported.
To install for your user, use `make install PREFIX="$HOME/.local"`.
For an uninstalled build, use `./tsdecrypt` in this directory.

To switch backends, run either `make dvbcsa` or `make ffdecsa`. The latter runs
upstream's CPU-specific FFdecsa selection. The version string reports the chosen
backend; `make install` will not silently switch it. FFdecsa and its selector are
retained upstream code; their performance depends on the CPU and input mode.

## Run with a CAM server

Adapt this example to your authorized input service and server. The identifiers,
addresses and credentials below are placeholders, not a working account:

```bash
tsdecrypt \
  --input 239.10.0.1:1234 --input-service 101 \
  --output 239.10.1.1:1234 --output-ttl 1 \
  --camd-proto cs378x --camd-server 192.0.2.10:2233 \
  --camd-user YOUR_USER --camd-pass YOUR_PASSWORD \
  --ca-system CONAX --caid 0x0B00 \
  --output-eit-pass --output-tdt-pass
```

Use `--output-intf LOCAL_IPV4` when multicast output needs a specific local
interface. Input/output address arguments use `IPv4:port`, without `udp://`.
The service and CA settings must match the source. Keep `--output-eit-pass`
when EPG is required; the shift queue itself does not change downstream filters.

## Add RAM Shift to a channel

Append these options to its decrypt command:

```bash
--input-shift 1200 --input-shift-memory 16777216 \
--input-shift-status /dev/shm/tsdecrypt-channel-101.json
```

This requests **1200 ms** of delay with a **16 MiB cap for that process**. Use a
unique status path for each instance. Range: 0..10000 ms; zero retains the
ordinary input path. The memory argument is in bytes and is required for a
nonzero shift.

The existing `--input-buffer` delays decoding while processing ECM immediately.
The new `--input-shift` delays the entire input, including ECM. Neither makes a
card faster. The shift is fixed at startup, does not rewrite PCR/PTS/DTS and is
not an automatic OSCam-driven load balancer.

There is no implicit shared 512 MiB budget in the standalone binary. When running
several channels, choose each cap so their total fits the intended RAM budget.
Queue data uses anonymous RAM, not stream files; normal OS swap policy applies.

## Delay a clear stream

This local unicast example needs no CAM server:

```bash
tsdecrypt --input-passthrough \
  --input 127.0.0.1:15000 --output 127.0.0.1:15001 \
  --input-shift 500 --input-shift-memory 8388608 \
  --input-shift-status /dev/shm/tsdecrypt-clear.json
```

Start a raw MPEG-TS UDP source sending to `127.0.0.1:15000` and a receiver on
port 15001. Each shifted UDP payload must contain up to seven complete 188-byte
TS packets. `--input -` and `--output -` use stdin/stdout. An unpaced file can
fill the queue much faster than a live source.

At EOF, queued complete packets drain. SIGINT/SIGTERM stop promptly. Queue
exhaustion or malformed input causes an explicit failure; a supervisor must
handle restart if required. Reading a status file needs no extra stream receiver:

```bash
python3 -m json.tool /dev/shm/tsdecrypt-clear.json
```

The [detailed guide](docs/RAM_INPUT_SHIFT.md) covers limits, memory accounting,
RTP framing, overflow behavior, source files and all counters.

## Tests

```bash
make test
./tests/run-cs378x-control-test.sh --check-upstream
```

Tests use synthetic streams and protocol frames, without cards, DVB adapters,
real credentials or external servers. They check `0x50` reply ordering, bounded
RAM accounting, input timing, ECM delay, byte-preserving passthrough, partial
reads, input silence, EOF and shutdown. The optional upstream regression check
uses the original commit already present in the fork history; a GitHub source
archive can run `make test` but lacks that Git history.

## License and documentation

GPL v2; see [COPYING](COPYING). Original author notices and the bundled libraries'
MIT licenses are preserved. OpenSSL and libdvbcsa are distribution dependencies.
See [source provenance](docs/PROVENANCE.md), the legacy [README](README),
`tsdecrypt --help`, and `man tsdecrypt` for the full inherited command reference.
