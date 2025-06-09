# Purpose
This file is a Makefile segment that conditionally compiles the `fd_ledger` binary. It checks for the presence of `ROCKSDB` and `SECP256K1` libraries, and if both are available, it proceeds with the build using specified dependencies. If either library is missing, it issues a warning indicating the build is disabled due to the absence of the respective library.
