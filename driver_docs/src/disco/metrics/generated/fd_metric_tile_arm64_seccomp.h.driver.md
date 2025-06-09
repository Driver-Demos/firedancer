# Purpose
This C header file is a generated source file that defines a seccomp (secure computing mode) filter policy for a specific architecture, namely ARM64. The file is not intended to be edited manually, as indicated by the comment at the top. It includes several Linux kernel headers related to auditing, capabilities, filtering, and seccomp, which are essential for defining and applying the seccomp filter. The primary function, [`populate_sock_filter_policy_fd_metric_tile_arm64`](#populate_sock_filter_policy_fd_metric_tile_arm64), initializes a Berkeley Packet Filter (BPF) program that enforces a security policy by allowing or denying specific system calls based on predefined conditions. The filter checks the architecture and syscall numbers, and it allows or denies syscalls like `write`, `fsync`, `accept4`, `read`, `sendto`, `close`, and `ppoll` based on the arguments passed to them.

The file is part of a broader system that likely involves monitoring or controlling system call access for security or performance metrics purposes. The seccomp filter is designed to kill the process if an unauthorized syscall is attempted, ensuring that only permitted operations are executed. This is achieved by using BPF statements and jumps to evaluate syscall numbers and their arguments, allowing only those that match the specified criteria. The file is structured to be included in other C source files, providing a reusable and architecture-specific seccomp policy that can be applied to processes running on ARM64 systems.
# Imports and Dependencies

---
- `../../../../src/util/fd_util_base.h`
- `linux/audit.h`
- `linux/capability.h`
- `linux/filter.h`
- `linux/seccomp.h`
- `linux/bpf.h`
- `sys/syscall.h`
- `signal.h`
- `stddef.h`


# Global Variables

---
### sock\_filter\_policy\_fd\_metric\_tile\_arm64\_instr\_cnt
- **Type**: `unsigned int`
- **Description**: The variable `sock_filter_policy_fd_metric_tile_arm64_instr_cnt` is a constant unsigned integer set to the value 45. It represents the number of instructions in a BPF (Berkeley Packet Filter) program used for seccomp filtering on ARM64 architecture.
- **Use**: This variable is used to ensure that the output buffer for the BPF program has sufficient space to hold all 45 instructions.


# Functions

---
### populate\_sock\_filter\_policy\_fd\_metric\_tile\_arm64<!-- {{#callable:populate_sock_filter_policy_fd_metric_tile_arm64}} -->
The function `populate_sock_filter_policy_fd_metric_tile_arm64` initializes a seccomp filter to enforce syscall policies for a specific architecture, allowing or killing processes based on syscall numbers and arguments.
- **Inputs**:
    - `out_cnt`: The number of elements in the output filter array, which must be at least 45.
    - `out`: A pointer to an array of `sock_filter` structures where the filter rules will be copied.
    - `logfile_fd`: The file descriptor for the logfile, used in syscall argument checks.
    - `metrics_socket_fd`: The file descriptor for the metrics socket, used in syscall argument checks.
- **Control Flow**:
    - Check if `out_cnt` is at least 45, ensuring the output array can hold the filter rules.
    - Define a `sock_filter` array with 45 elements to specify the seccomp filter rules.
    - Load the architecture from `seccomp_data` and compare it to the expected architecture; jump to kill process if they don't match.
    - Load the syscall number and check against allowed syscalls (write, fsync, accept4, read, sendto, close, ppoll).
    - For each allowed syscall, further check specific arguments (e.g., file descriptors) to determine if the syscall should be allowed or the process killed.
    - Copy the defined filter rules into the output array using `fd_memcpy`.
- **Output**: The function does not return a value; it populates the `out` array with the seccomp filter rules.


