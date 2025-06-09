
## Files
- **[fd_backtest_tile.c](backtest/fd_backtest_tile.c.driver.md)**: The `fd_backtest_tile.c` file in the `firedancer` codebase implements a backtesting tile that utilizes RocksDB for data retrieval and processing, including functions for initializing, running, and managing playback of data shreds.
- **[Local.mk](backtest/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase is a makefile that conditionally adds objects for `fd_backtest_tile` and `fd_discof` based on the presence of `FD_HAS_INT128`, `FD_HAS_SSE`, and `FD_HAS_ROCKSDB`, and issues a warning if `rocksdb` is not installed.
