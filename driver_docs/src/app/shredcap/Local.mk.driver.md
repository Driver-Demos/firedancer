# Purpose
This Makefile snippet conditionally compiles the `fd_shred_cap` binary using the `make-bin` function if the `FD_HAS_ROCKSDB` flag is defined, linking it with the `fd_flamenco`, `fd_ballet`, and `fd_util` libraries along with `ROCKSDB_LIBS`. If the flag is not defined, it issues a warning indicating that the build for the shredcap capture tool is disabled due to the absence of RocksDB.
