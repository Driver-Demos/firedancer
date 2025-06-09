# Purpose
The provided C header file, `fd_sandbox_private.h`, is part of a sandboxing utility designed to enhance the security of a process by restricting its environment and capabilities. This file defines a set of private functions that are intended to be used internally within a larger software system, likely the Firedancer project, to implement various security measures. The functions focus on minimizing the risk of information leakage and unauthorized access by manipulating environment variables, file descriptors, user and group IDs, and system capabilities. The file also includes mechanisms to restrict resource limits, apply namespace restrictions, and enforce seccomp-bpf filters to control system call access.

The functions in this header file are specifically tailored to create a secure execution environment by clearing environment variables, checking and enforcing strict file descriptor policies, and managing user and group ID mappings within namespaces. Additionally, the file provides functions to deny the creation of new namespaces, pivot the root filesystem, and apply landlock restrictions to limit filesystem operations. The use of seccomp-bpf filters further enhances security by allowing only a predefined set of system calls. These functions collectively aim to provide a robust defense-in-depth strategy, ensuring that the process operates within a tightly controlled and secure environment.
# Imports and Dependencies

---
- `fd_sandbox.h`


# Function Declarations (Public API)

---
### fd\_sandbox\_private\_check\_exact\_file\_descriptors<!-- {{#callable_declaration:fd_sandbox_private_check_exact_file_descriptors}} -->
Verify that the current process's open file descriptors match a specified list.
- **Description**: Use this function to ensure that the open file descriptors in the current process exactly match a specified list of allowed file descriptors. This is crucial for maintaining the security of a sandboxed environment by preventing unauthorized access to sensitive files. The function will terminate the program with an error if there are discrepancies, such as unexpected open file descriptors or missing ones from the allowed list. It is important to ensure that the list of allowed file descriptors does not exceed 256 entries and contains no duplicates before calling this function.
- **Inputs**:
    - `allowed_file_descriptor_cnt`: Specifies the number of file descriptors in the allowed list. Must be between 0 and 256 inclusive. If this value exceeds 256, the function will terminate the program with an error.
    - `allowed_file_descriptor`: A pointer to an array of integers representing the allowed file descriptors. The array must contain exactly 'allowed_file_descriptor_cnt' entries. Each file descriptor must be non-negative and less than INT_MAX. The array must not contain duplicate entries, or the function will terminate the program with an error.
- **Output**: None
- **See also**: [`fd_sandbox_private_check_exact_file_descriptors`](fd_sandbox.c.driver.md#fd_sandbox_private_check_exact_file_descriptors)  (Implementation)


---
### fd\_sandbox\_private\_switch\_uid\_gid<!-- {{#callable_declaration:fd_sandbox_private_switch_uid_gid}} -->
Sets the user and group IDs for the calling thread to the specified values.
- **Description**: This function sets the real, effective, and saved set-user-ID and set-group-ID of the calling thread to the specified UID and GID, respectively. It is used when there is a need to change the credentials of a single thread rather than all threads in a process, which is contrary to the POSIX specification. The function requires the calling process to have both CAP_SETUID and CAP_SETGID capabilities; otherwise, it will log an error and terminate the process. If the IDs are changed, the function ensures that the dumpable bit is restored to its original state, so the caller does not need to handle this.
- **Inputs**:
    - `desired_uid`: The target user ID to set for the calling thread. Must be a valid user ID that the process has permission to switch to.
    - `desired_gid`: The target group ID to set for the calling thread. Must be a valid group ID that the process has permission to switch to.
- **Output**: None
- **See also**: [`fd_sandbox_private_switch_uid_gid`](fd_sandbox.c.driver.md#fd_sandbox_private_switch_uid_gid)  (Implementation)


---
### fd\_sandbox\_private\_write\_userns\_uid\_gid\_maps<!-- {{#callable_declaration:fd_sandbox_private_write_userns_uid_gid_maps}} -->
Maps user and group IDs in a user namespace to specified parent namespace IDs.
- **Description**: Use this function immediately after creating a user namespace to establish a mapping between the user and group IDs inside the namespace and those in the parent namespace. This is crucial for setting up the namespace correctly before performing any other operations within it. The function writes a single mapping where the UID and GID of '1' inside the namespace are mapped to the provided UID and GID in the parent namespace. It also writes 'deny' to /proc/self/setgroups as a required security measure. Ensure that the provided UID and GID match the effective UID and GID of the process that created the namespace.
- **Inputs**:
    - `uid_in_parent`: The UID in the parent namespace to which UID 1 in the user namespace will be mapped. Must be a valid user ID.
    - `gid_in_parent`: The GID in the parent namespace to which GID 1 in the user namespace will be mapped. Must be a valid group ID.
- **Output**: None
- **See also**: [`fd_sandbox_private_write_userns_uid_gid_maps`](fd_sandbox.c.driver.md#fd_sandbox_private_write_userns_uid_gid_maps)  (Implementation)


---
### fd\_sandbox\_private\_deny\_namespaces<!-- {{#callable_declaration:fd_sandbox_private_deny_namespaces}} -->
Restricts the creation of new namespaces within the sandbox.
- **Description**: This function is used to enhance security by limiting the ability to create new namespaces, which is a common vector for privilege escalation on Linux systems. It should be called within a nested user namespace to set the maximum allowed namespaces to zero, except for user namespaces where one additional namespace is permitted. This restriction ensures that the process cannot revert the denied namespaces back to allowed, as the limits are controlled by the parent user namespace where the process lacks permissions. This function is part of a defense-in-depth strategy, complementing other security measures like seccomp-bpf.
- **Inputs**: None
- **Output**: None
- **See also**: [`fd_sandbox_private_deny_namespaces`](fd_sandbox.c.driver.md#fd_sandbox_private_deny_namespaces)  (Implementation)


---
### fd\_sandbox\_private\_pivot\_root<!-- {{#callable_declaration:fd_sandbox_private_pivot_root}} -->
Changes the root filesystem to a new, empty directory.
- **Description**: This function is used to securely change the root filesystem of the current process to a new, empty directory, effectively isolating the process from the existing filesystem. It is more secure than using chroot(2) as it pivots the root mount of the filesystem to a new directory. This function creates a new mount namespace and performs the pivot within it, ensuring that all previous mounts are unmounted and not visible in the new directory. It should be called when a process needs to be sandboxed with no access to the original filesystem.
- **Inputs**: None
- **Output**: None
- **See also**: [`fd_sandbox_private_pivot_root`](fd_sandbox.c.driver.md#fd_sandbox_private_pivot_root)  (Implementation)


---
### fd\_sandbox\_private\_set\_rlimits<!-- {{#callable_declaration:fd_sandbox_private_set_rlimits}} -->
Restricts resource limits for the calling process.
- **Description**: This function sets resource limits (RLIMIT_*) for the calling process, restricting most resources to zero except for RLIMIT_NOFILE, RLIMIT_AS, and RLIMIT_DATA, which are set to the values provided by the caller. It is typically used to enforce strict resource usage policies within a sandboxed environment, ensuring that the process cannot exceed specified limits for open files, address space, and data segment size. This function should be called when resource constraints are necessary to maintain security or stability in a controlled execution environment.
- **Inputs**:
    - `rlimit_file_cnt`: Specifies the maximum number of open file descriptors allowed. Must be a non-negative unsigned long value. If invalid, the function logs an error and exits.
    - `rlimit_address_space`: Specifies the maximum size of the process's address space. Must be a non-negative unsigned long value. If invalid, the function logs an error and exits.
    - `rlimit_data`: Specifies the maximum size of the process's data segment. Must be a non-negative unsigned long value. If invalid, the function logs an error and exits.
- **Output**: None
- **See also**: [`fd_sandbox_private_set_rlimits`](fd_sandbox.c.driver.md#fd_sandbox_private_set_rlimits)  (Implementation)


---
### fd\_sandbox\_private\_read\_cap\_last\_cap<!-- {{#callable_declaration:fd_sandbox_private_read_cap_last_cap}} -->
Read the value of cap_last_cap from the system and return it.
- **Description**: This function retrieves the value of the last valid capability from the Linux kernel by reading the file "/proc/sys/kernel/cap_last_cap". It is used to determine the highest capability number that the kernel recognizes. The function should be called when there is a need to know the maximum capability supported by the kernel, typically for security or sandboxing purposes. It logs an error and exits the program if any issues occur during file access or data parsing, ensuring that the caller does not proceed with invalid capability information.
- **Inputs**: None
- **Output**: Returns the highest capability number recognized by the kernel as an unsigned long integer.
- **See also**: [`fd_sandbox_private_read_cap_last_cap`](fd_sandbox.c.driver.md#fd_sandbox_private_read_cap_last_cap)  (Implementation)


---
### fd\_sandbox\_private\_drop\_caps<!-- {{#callable_declaration:fd_sandbox_private_drop_caps}} -->
Drop all capabilities and set securebits to be maximally restrictive.
- **Description**: This function is used to enhance the security of a process by dropping all capabilities (effective, permitted, and inherited) and clearing the capability bounding set. It also sets the securebits flags to be maximally restrictive and clears ambient capabilities. This function should be called when you want to ensure that a process runs with the least privilege possible, minimizing the risk of privilege escalation. It is important to provide the correct value for `cap_last_cap`, which should be the highest capability known to the running Linux kernel, typically obtained from `/proc/sys/kernel/cap_last_cap`. This function is critical in sandboxing environments where security is a priority.
- **Inputs**:
    - `cap_last_cap`: The highest capability known to the running Linux kernel, typically obtained from `/proc/sys/kernel/cap_last_cap`. It must be a valid capability number, and the function will iterate over all capabilities up to this number to drop them.
- **Output**: None
- **See also**: [`fd_sandbox_private_drop_caps`](fd_sandbox.c.driver.md#fd_sandbox_private_drop_caps)  (Implementation)


---
### fd\_sandbox\_private\_landlock\_restrict\_self<!-- {{#callable_declaration:fd_sandbox_private_landlock_restrict_self}} -->
Apply a Landlock restriction to the current process.
- **Description**: This function applies a Landlock restriction to the current process, preventing most filesystem operations such as reads, writes, and execution, as well as network access. It serves as a defense-in-depth measure, complementing other security mechanisms like seccomp-bpf. The function will not report an error or terminate the program if the kernel does not support Landlock, allowing for graceful degradation of security features. It is typically used to enhance the security posture of a process by limiting its capabilities to interact with the filesystem and network.
- **Inputs**:
    - `allow_connect`: An integer flag indicating whether network connect operations should be allowed. If non-zero, the connect(2) syscall will be permitted; otherwise, it will be restricted. The caller retains ownership of this parameter, and it must be a valid integer.
- **Output**: None
- **See also**: [`fd_sandbox_private_landlock_restrict_self`](fd_sandbox.c.driver.md#fd_sandbox_private_landlock_restrict_self)  (Implementation)


---
### fd\_sandbox\_private\_set\_seccomp\_filter<!-- {{#callable_declaration:fd_sandbox_private_set_seccomp_filter}} -->
Install a seccomp-bpf filter to restrict syscalls.
- **Description**: Use this function to apply a seccomp-bpf filter to the current process, which restricts the syscalls that the process can make according to a specified whitelist. This is a security measure to prevent unauthorized syscalls, and it will terminate the process with SIGSYS if a disallowed syscall is attempted. The seccomp filter should be generated using the appropriate script and not constructed manually. Ensure that the no_new_privs bit is set before calling this function.
- **Inputs**:
    - `seccomp_filter_cnt`: The number of entries in the seccomp_filter array. It specifies the length of the BPF program and must accurately reflect the number of filter instructions provided.
    - `seccomp_filter`: A pointer to an array of struct sock_filter, representing the BPF program that defines the syscall whitelist. The caller retains ownership and must ensure it is correctly populated and valid.
- **Output**: None
- **See also**: [`fd_sandbox_private_set_seccomp_filter`](fd_sandbox.c.driver.md#fd_sandbox_private_set_seccomp_filter)  (Implementation)


---
### fd\_sandbox\_private\_enter\_no\_seccomp<!-- {{#callable_declaration:fd_sandbox_private_enter_no_seccomp}} -->
Enters a sandbox environment without applying seccomp-bpf filtering.
- **Description**: This function is used to enter a sandbox environment with various security restrictions applied, except for seccomp-bpf filtering, which is omitted. It is primarily intended for testing purposes, allowing verification of security properties without syscall restrictions. The function sets user and group IDs, manages namespaces, and applies resource limits. It must be called with valid user and group IDs, and a list of allowed file descriptors. The function assumes the caller has the necessary capabilities to change user and group IDs and manage namespaces. It is crucial to ensure that the list of allowed file descriptors is accurate to maintain sandbox security.
- **Inputs**:
    - `desired_uid`: The user ID to switch to within the sandbox. Must be a valid user ID that the process has permission to switch to.
    - `desired_gid`: The group ID to switch to within the sandbox. Must be a valid group ID that the process has permission to switch to.
    - `keep_host_networking`: If non-zero, retains access to the host's network namespace; otherwise, a new network namespace is created.
    - `allow_connect`: If non-zero, allows the connect(2) syscall within the sandbox, otherwise it is restricted.
    - `keep_controlling_terminal`: If non-zero, retains the controlling terminal; otherwise, the process detaches from it.
    - `dumpable`: Sets the dumpable attribute of the process, which affects core dump generation. Must be a valid integer value.
    - `rlimit_file_cnt`: The maximum number of file descriptors that can be opened by the process. Must be a non-negative integer.
    - `rlimit_address_space`: The maximum size of the process's address space. Must be a non-negative integer.
    - `rlimit_data`: The maximum size of the process's data segment. Must be a non-negative integer.
    - `allowed_file_descriptor_cnt`: The number of file descriptors in the allowed list. Must be between 0 and 256.
    - `allowed_file_descriptor`: A pointer to an array of allowed file descriptors. Must not be null and must contain allowed_file_descriptor_cnt entries.
- **Output**: None
- **See also**: [`fd_sandbox_private_enter_no_seccomp`](fd_sandbox.c.driver.md#fd_sandbox_private_enter_no_seccomp)  (Implementation)


