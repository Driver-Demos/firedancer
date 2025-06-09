
## Files
- **[fd_pcap_replay.c](pcap/fd_pcap_replay.c.driver.md)**: The `fd_pcap_replay.c` file in the `firedancer` codebase implements functionality to replay packets from a pcap file, handling flow control, diagnostics, and housekeeping tasks.
- **[fd_pcap_replay.h](pcap/fd_pcap_replay.h.driver.md)**: The `fd_pcap_replay.h` file in the `firedancer` codebase provides functionality for replaying packets from a pcap file into a tango fragment stream, including flow control diagnostics and configuration for reliable and unreliable consumers.
- **[fd_pcap_replay_tile.c](pcap/fd_pcap_replay_tile.c.driver.md)**: The `fd_pcap_replay_tile.c` file in the `firedancer` codebase implements a program that replays PCAP files using various command-line parameters and shared memory resources, with error handling and logging throughout the process.
- **[Local.mk](pcap/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, unit tests, and binary targets for the `fd_pcap_replay` component and its dependencies.
- **[test_pcap_replay.c](pcap/test_pcap_replay.c.driver.md)**: The `test_pcap_replay.c` file in the `firedancer` codebase implements a unit test for the PCAP replay functionality, including both transmission (TX) and reception (RX) tiles, with configuration and execution of the test environment.
