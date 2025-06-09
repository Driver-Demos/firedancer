## Folders
- **[generated](monitor/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a generated header file, `monitor_seccomp.h`, which defines a seccomp filter policy for monitoring system calls.

## Files
- **[helper.c](monitor/helper.c.driver.md)**: The `helper.c` file in the `firedancer` codebase provides utility functions for formatting and printing various types of data, such as time durations, error counts, and rates, as well as handling input from the standard input.
- **[helper.h](monitor/helper.h.driver.md)**: The `helper.h` file in the `firedancer` codebase provides a set of utility functions for formatted and color-coded terminal output, including functions for printing ages, heartbeats, signals, error conditions, sequences, rates, and percentages, as well as a non-blocking character read from stdin.
- **[monitor.c](monitor/monitor.c.driver.md)**: The `monitor.c` file in the `firedancer` codebase implements a terminal-based monitoring tool for observing the performance and metrics of a locally running Firedancer instance, including handling command-line arguments, permissions, and terminal interactions.
- **[monitor.h](monitor/monitor.h.driver.md)**: The `monitor.h` file in the `firedancer` codebase declares functions and an external action related to monitoring command arguments, permissions, and execution.
- **[monitor.seccomppolicy](monitor/monitor.seccomppolicy.driver.md)**: The `monitor.seccomppolicy` file defines security policies for the monitor binary in the Firedancer codebase, detailing how it handles logging, process supervision, and terminal interactions.
