# Purpose
This C source code file implements a specialized wrapper program designed to facilitate debugging with Visual Studio Code (VS Code) by enabling the execution of a program with elevated capabilities, rather than root privileges. The primary challenge addressed by this code is the need to run a program with root-level capabilities for debugging purposes without actually running it as the root user, which is restricted by security policies and limitations in VS Code's debugging agent. The program achieves this by manipulating Linux capabilities, allowing the program to execute with all necessary permissions while maintaining compatibility with the VS Code debugging environment.

The code is structured to handle different execution paths based on the current capabilities of the process. It first checks if the process already has all capabilities; if not, it uses a fork-exec pattern to elevate its capabilities by invoking itself with `sudo` to set the necessary capabilities using extended attributes. Once the capabilities are set, the program re-executes itself to apply these capabilities and then raises them to ambient status, ensuring they persist across subsequent executions. Finally, it executes the GNU Debugger (GDB) with the provided arguments, allowing the debugging session to proceed with the required permissions. This approach circumvents the limitations of running as root while still providing the necessary environment for effective debugging.
# Imports and Dependencies

---
- `../../util/fd_util.h`
- `stdlib.h`
- `unistd.h`
- `string.h`
- `stdio.h`
- `sys/types.h`
- `sys/prctl.h`
- `sys/syscall.h`
- `sys/xattr.h`
- `sys/wait.h`
- `linux/limits.h`
- `linux/capability.h`


# Data Structures

---
### vfs\_cap\_data
- **Type**: `struct`
- **Members**:
    - `magic_etc`: A 32-bit little-endian integer used to store magic number and other flags.
    - `data`: An array of two elements, each containing a structure with 32-bit little-endian integers for permitted and inheritable capabilities.
- **Description**: The `vfs_cap_data` structure is used to represent capability data for a file in a Linux system, specifically for setting file capabilities using extended attributes. It contains a magic number and flags in `magic_etc`, and an array `data` that holds two sets of capability information, each with `permitted` and `inheritable` fields, allowing the specification of which capabilities are allowed and can be inherited by child processes.


# Functions

---
### has\_all\_capabilities<!-- {{#callable:has_all_capabilities}} -->
The `has_all_capabilities` function checks if the current process has all possible capabilities set.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `__user_cap_header_struct` and an array of two `__user_cap_data_struct` to hold capability data.
    - Set the capability version to `_LINUX_CAPABILITY_VERSION_3` and the process ID to 0 in `capheader`.
    - Use the `syscall` function with `SYS_capget` to retrieve the current capabilities into `capdata`.
    - Check if the first element of `capdata` has all bits set in the `permitted` field (i.e., `0xFFFFFFFF`).
    - Check if the `permitted` field of the second element of `capdata` has the lower 9 bits set (i.e., `0x000001FF`).
    - Return true if both conditions are met, indicating all capabilities are set; otherwise, return false.
- **Output**: The function returns an integer, 1 if the process has all capabilities set, and 0 otherwise.


---
### raise\_all\_capabilities<!-- {{#callable:raise_all_capabilities}} -->
The `raise_all_capabilities` function elevates the process's capabilities to the maximum possible level and ensures they are ambiently available.
- **Inputs**: None
- **Control Flow**:
    - Initialize `capheader` and `capdata` structures to interact with Linux capabilities.
    - Set the `capheader` version to `_LINUX_CAPABILITY_VERSION_3` and target the current process by setting `capheader.pid` to 0.
    - Retrieve the current capabilities using `syscall(SYS_capget, &capheader, &capdata)` and ensure the call is successful with `FD_TEST`.
    - Set all effective and inheritable capabilities in `capdata` to `0xFFFFFFFF`, which represents all capabilities being enabled.
    - Apply the modified capabilities using `syscall(SYS_capset, &capheader, &capdata)` and ensure the call is successful with `FD_TEST`.
    - Iterate over all possible capabilities from 0 to `CAP_LAST_CAP` and raise each one to ambient using `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)` and ensure each call is successful with `FD_TEST`.
- **Output**: The function does not return a value; it modifies the process's capabilities to be fully enabled and ambient.


---
### self\_exe<!-- {{#callable:self_exe}} -->
The `self_exe` function retrieves the absolute path of the currently running executable and stores it in the provided buffer.
- **Inputs**:
    - `path`: A character array where the function will store the absolute path of the currently running executable.
- **Control Flow**:
    - The function calls `readlink` with the path "/proc/self/exe" to get the absolute path of the current executable and stores it in the `path` buffer.
    - It checks if the number of bytes read is non-negative and less than `PATH_MAX` using `FD_TEST`.
    - If the check passes, it null-terminates the string in `path` at the position indicated by the number of bytes read.
- **Output**: The function does not return a value; it modifies the `path` buffer in place to contain the absolute path of the executable.


---
### main<!-- {{#callable:main}} -->
The `main` function manages the execution of a program with elevated capabilities, allowing it to run with all capabilities using a sequence of checks and operations involving setting capabilities, forking, and executing commands.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program with `fd_boot` using the command-line arguments.
    - Check if the first argument is '--setcap'; if so, set the capabilities of the current executable to have all capabilities using `setxattr`.
    - If '--setcap' is not provided, check if the program has all capabilities using [`has_all_capabilities`](#has_all_capabilities).
    - If the program lacks capabilities and '--withcap' is not provided, fork a child process to run `sudo` to set capabilities, wait for it to complete, and then re-execute itself with '--withcap'.
    - If the program has all capabilities, raise all capabilities using [`raise_all_capabilities`](#raise_all_capabilities), prepare arguments for `gdb`, and execute `gdb` with these arguments.
- **Output**: The function does not return a value; it either sets capabilities, re-executes itself, or executes `gdb` with the provided arguments.
- **Functions called**:
    - [`self_exe`](#self_exe)
    - [`has_all_capabilities`](#has_all_capabilities)
    - [`raise_all_capabilities`](#raise_all_capabilities)


