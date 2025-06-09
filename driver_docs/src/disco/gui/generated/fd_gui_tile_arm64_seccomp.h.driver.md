# Purpose
This C header file, `fd_gui_tile_arm64_seccomp.h`, is a generated file that defines a seccomp (secure computing mode) filter policy for a specific architecture, namely ARM64. The primary purpose of this file is to provide a set of BPF (Berkeley Packet Filter) instructions that enforce security restrictions on system calls made by a process. The file includes necessary headers for working with seccomp and BPF, and it defines a function [`populate_sock_filter_policy_fd_gui_tile_arm64`](#populate_sock_filter_policy_fd_gui_tile_arm64) that initializes a `sock_filter` array with specific rules. These rules determine which system calls are allowed or denied based on the architecture and specific conditions, such as file descriptors for logging and GUI socket operations.

The file is not intended to be edited manually, as indicated by the comment at the top, and it is likely part of a larger system that uses seccomp to enhance security by limiting the system calls a process can make. The filter rules are designed to allow certain system calls like `write`, `fsync`, `accept4`, `read`, `sendto`, `close`, and `ppoll` under specific conditions, while any other calls result in the process being killed. This approach helps in mitigating the risk of exploits by reducing the attack surface of the application. The file is structured to be included in other C source files, providing a reusable security component for applications running on ARM64 architecture.
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
### sock\_filter\_policy\_fd\_gui\_tile\_arm64\_instr\_cnt
- **Type**: `unsigned int`
- **Description**: The variable `sock_filter_policy_fd_gui_tile_arm64_instr_cnt` is a constant unsigned integer that holds the value 45. This value represents the number of instructions in a socket filter policy specifically for the ARM64 architecture in a GUI tile context.
- **Use**: This variable is used to ensure that the output count in the `populate_sock_filter_policy_fd_gui_tile_arm64` function is sufficient to hold all 45 instructions of the filter policy.


# Functions

---
### populate\_sock\_filter\_policy\_fd\_gui\_tile\_arm64<!-- {{#callable:populate_sock_filter_policy_fd_gui_tile_arm64}} -->
The function `populate_sock_filter_policy_fd_gui_tile_arm64` initializes a seccomp filter to enforce a security policy for system calls on an ARM64 architecture.
- **Inputs**:
    - `out_cnt`: The number of elements in the output filter array, which must be at least 45.
    - `out`: A pointer to an array of `struct sock_filter` where the filter instructions will be copied.
    - `logfile_fd`: The file descriptor for the logfile, used in syscall checks.
    - `gui_socket_fd`: The file descriptor for the GUI socket, used in syscall checks.
- **Control Flow**:
    - The function begins by asserting that `out_cnt` is at least 45, ensuring the output array can hold the filter instructions.
    - A static array `filter` of 45 `struct sock_filter` elements is defined to hold the BPF instructions.
    - The filter starts by checking if the architecture of the running process matches the expected architecture (`ARCH_NR`), jumping to `RET_KILL_PROCESS` if not.
    - It then loads the syscall number and checks against a list of allowed syscalls (`write`, `fsync`, `accept4`, `read`, `sendto`, `close`, `ppoll`).
    - For each syscall, additional checks are performed on the syscall arguments, particularly checking if they match `logfile_fd` or `gui_socket_fd`.
    - If a syscall and its arguments match the allowed criteria, the filter jumps to `RET_ALLOW`; otherwise, it jumps to `RET_KILL_PROCESS`.
    - The filter instructions are copied to the output array `out` using `fd_memcpy`.
- **Output**: The function does not return a value; it populates the `out` array with the seccomp filter instructions.


