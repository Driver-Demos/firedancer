# Purpose
This C header file, `fd_sandbox.h`, is designed to provide a set of functions for managing and entering a secure sandbox environment on Linux systems. The primary purpose of this file is to define functions that facilitate the creation of a restricted execution environment, where a process has limited access to system resources and capabilities. The file includes functions such as [`fd_sandbox_requires_cap_sys_admin`](#fd_sandbox_requires_cap_sys_admin), which checks if administrative capabilities are needed to establish the sandbox, and [`fd_sandbox_enter`](#fd_sandbox_enter), which performs a series of operations to enter a sandboxed environment. These operations include clearing environment variables, managing file descriptors, setting user and group IDs, and applying security restrictions like seccomp-bpf filters and landlock restrictions. The file also provides utility functions like [`fd_sandbox_switch_uid_gid`](#fd_sandbox_switch_uid_gid) for changing user and group IDs, and [`fd_sandbox_getpid`](#fd_sandbox_getpid) and [`fd_sandbox_gettid`](#fd_sandbox_gettid) for retrieving the true process and thread IDs in the root PID namespace.

The header file is intended to be included in other C source files that require sandboxing functionality. It defines a narrow, specialized API focused on process isolation and security, particularly for applications that need to run in a constrained environment to minimize potential security risks. The functions are designed to be used in a Linux environment, as indicated by the conditional compilation directive `#if defined(__linux__)`. The file does not define a main function or executable code but rather provides an interface for other programs to implement sandboxing features. The use of capabilities and namespace manipulation suggests that the file is intended for advanced users who need to enforce strict security policies on their applications.
# Imports and Dependencies

---
- `../fd_util_base.h`
- `linux/filter.h`


# Function Declarations (Public API)

---
### fd\_sandbox\_requires\_cap\_sys\_admin<!-- {{#callable_declaration:fd_sandbox_requires_cap_sys_admin}} -->
Determine if CAP_SYS_ADMIN is required for sandboxing.
- **Description**: This function checks whether the current environment requires the CAP_SYS_ADMIN capability to fully establish a sandbox. It is particularly relevant for Linux distributions that restrict unprivileged user namespaces, such as certain versions of Ubuntu. The function should be called before attempting to create a user namespace to ensure that the necessary privileges are available. It evaluates system configurations and attempts to create a user namespace to determine if additional privileges are needed.
- **Inputs**:
    - `desired_uid`: The user ID that the process will switch to when entering the sandbox. It must be a valid user ID, and the function uses it to check if the namespace can be created unprivileged.
    - `desired_gid`: The group ID that the process will switch to when entering the sandbox. It must be a valid group ID, and the function uses it to check if the namespace can be created unprivileged.
- **Output**: Returns 1 if CAP_SYS_ADMIN is required to establish the sandbox, otherwise returns 0.
- **See also**: [`fd_sandbox_requires_cap_sys_admin`](fd_sandbox.c.driver.md#fd_sandbox_requires_cap_sys_admin)  (Implementation)


---
### fd\_sandbox\_enter<!-- {{#callable_declaration:fd_sandbox_enter}} -->
Enter a fully sandboxed execution environment with restricted system access.
- **Description**: This function transitions the current process into a highly restricted sandbox environment, limiting its system access to enhance security. It must be called when the process is single-threaded, and any errors during the sandboxing process will result in a fatal exit. The function requires certain capabilities, such as CAP_SETGID and CAP_SETUID, to switch user and group IDs, and potentially CAP_SYS_ADMIN on some Linux distributions to unshare user namespaces. The sandboxing process involves clearing environment variables, restricting file descriptors, modifying user and group IDs, and applying resource limits. Additionally, a seccomp-bpf filter is installed to restrict system calls. The caller must ensure the process is in its own PID namespace to prevent signal sending or tracing between processes.
- **Inputs**:
    - `desired_uid`: User ID to switch the process to inside the sandbox. Must be a valid user ID.
    - `desired_gid`: Group ID to switch the process to inside the sandbox. Must be a valid group ID.
    - `keep_host_networking`: If non-zero, the host networking namespace is retained; otherwise, it is unshared.
    - `allow_connect`: If non-zero, allows the connect(2) syscall via landlock; otherwise, it is restricted.
    - `keep_controlling_terminal`: If non-zero, the process remains connected to the controlling terminal; otherwise, it is disconnected.
    - `dumpable`: If non-zero, the process's dumpable attribute is retained; otherwise, it is cleared.
    - `rlimit_file_cnt`: Maximum number of open files allowed, set via setrlimit(RLIMIT_NOFILE). Must be a valid ulong value.
    - `rlimit_address_space`: Maximum address space size allowed, set via setrlimit(RLIMIT_AS). Must be a valid ulong value.
    - `rlimit_data`: Maximum data segment size allowed, set via setrlimit(RLIMIT_DATA). Must be a valid ulong value.
    - `allowed_file_descriptor_cnt`: Number of entries in the allowed_file_descriptor array. Must be a valid ulong value.
    - `allowed_file_descriptor`: Array of allowed file descriptors. Must not be null and should have allowed_file_descriptor_cnt entries.
    - `seccomp_filter_cnt`: Number of entries in the seccomp_filter array. Must not exceed USHORT_MAX.
    - `seccomp_filter`: Array of BPF instructions for the seccomp-bpf filter. Must not be null and should have seccomp_filter_cnt entries.
- **Output**: None
- **See also**: [`fd_sandbox_enter`](fd_sandbox.c.driver.md#fd_sandbox_enter)  (Implementation)


---
### fd\_sandbox\_switch\_uid\_gid<!-- {{#callable_declaration:fd_sandbox_switch_uid_gid}} -->
Switches the calling thread's user and group IDs to the specified values.
- **Description**: This function changes the effective, real, and saved-set user ID and group ID of the calling thread to the specified values, if they are not already set. It is designed to be used in multi-threaded processes, unlike some other sandboxing functions that require single-threaded execution. The function may require CAP_SETUID and CAP_SETGID capabilities if the IDs need to be changed. It also restores the dumpable bit to true after the switch, counteracting the Linux kernel's default behavior of clearing it for security reasons.
- **Inputs**:
    - `desired_uid`: The user ID to switch the calling thread to. Must be a valid user ID. The function requires CAP_SETUID capability if the current user ID is different from the desired one.
    - `desired_gid`: The group ID to switch the calling thread to. Must be a valid group ID. The function requires CAP_SETGID capability if the current group ID is different from the desired one.
- **Output**: None
- **See also**: [`fd_sandbox_switch_uid_gid`](fd_sandbox.c.driver.md#fd_sandbox_switch_uid_gid)  (Implementation)


---
### fd\_sandbox\_getpid<!-- {{#callable_declaration:fd_sandbox_getpid}} -->
Returns the true PID of the current process in the root PID namespace.
- **Description**: Use this function to obtain the actual process ID as seen in the root PID namespace, which is necessary for operations like sending signals with the correct PID. It should be called after entering a PID namespace but before entering a sandbox, as it cannot be used within a sandbox due to likely seccomp filter restrictions. The function will terminate the process with an error if it fails to read or parse the PID from the system.
- **Inputs**: None
- **Output**: The function returns the true PID of the current process as an unsigned long integer.
- **See also**: [`fd_sandbox_getpid`](fd_sandbox.c.driver.md#fd_sandbox_getpid)  (Implementation)


---
### fd\_sandbox\_gettid<!-- {{#callable_declaration:fd_sandbox_gettid}} -->
Returns the true TID of the current process in the root PID namespace.
- **Description**: Use this function to obtain the true thread ID (TID) of the current process as it appears in the root PID namespace of the system. This is particularly useful when working with processes inside PID namespaces, where the TID returned by `gettid(2)` may be renumbered. The function should be called after entering a PID namespace but before entering a sandbox, as it cannot be called from within the sandbox due to likely restrictions from the seccomp filter. The function will terminate the calling process with an error if it cannot read the TID or if the TID is malformed.
- **Inputs**: None
- **Output**: Returns the true TID of the current process as an unsigned long integer.
- **See also**: [`fd_sandbox_gettid`](fd_sandbox.c.driver.md#fd_sandbox_gettid)  (Implementation)


