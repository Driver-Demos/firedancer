# Purpose
This file is a Makefile snippet used for conditional compilation. It checks for the presence of certain features or libraries, specifically `FD_HAS_INT128`, `FD_HAS_SSE`, and `FD_HAS_ROCKSDB`. If all conditions are met, it adds the object files `fd_backtest_tile` and `fd_discof` to the build; otherwise, it issues a warning that RocksDB is not installed and skips the backtest process.
