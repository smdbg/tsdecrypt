# Source provenance

This is a fork of [gfto/tsdecrypt](https://github.com/gfto/tsdecrypt), originally by
Georgi Chorbadzhiyski. The original Git history and copyright notices are retained.
The integration is based on upstream revision `f4876e84cf1866645f84b93f830af67193c85f69`.

Standalone packaging on 2026-11-16 imports the native changes developed in
https://git.promet.ad/mitev/tsdecrypt at revision `525d6cca6a23db65213ad6929ca664059de74a11`.
See [CHANGELOG.md](../CHANGELOG.md) for the changes. Web management, deployment
configuration and real customer/card data are not part of this repository.

The original submodules are included as ordinary source directories, so GitHub
source archives and regular clones build without submodule downloads:

| Component | Original repository | Pinned revision | License |
| --- | --- | --- | --- |
| libfuncs | https://github.com/gfto/libfuncs | `48f7087fe79b3ff54c6c31e07dc18e0fdf5bf0f5` | MIT |
| libtsfuncs | https://github.com/gfto/libtsfuncs | `d3b56ef510583e164c538ef635fe556831bde120` | MIT |

The main program is distributed under GPL v2; see [COPYING](../COPYING).
Each bundled library retains its own `LICENSE-MIT.txt` and original notices.

The included FFdecsa sources retain their upstream notices. OpenSSL and
libdvbcsa are system dependencies and are not vendored.
