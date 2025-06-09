# Purpose
This C source file is designed to implement a sandboxing mechanism for Linux systems, providing a secure environment by restricting the capabilities and resources available to a process. The file includes functions to manage user and group IDs, set resource limits, manipulate namespaces, and apply security policies using Linux-specific features such as seccomp, Landlock, and capabilities. The code is structured to ensure that processes can be isolated from the host system, limiting their ability to perform potentially harmful operations. It achieves this by unsharing namespaces, pivoting the root filesystem, and applying seccomp filters to restrict system calls.

The file is not intended to be an executable on its own but rather a library to be included in other projects that require sandboxing capabilities. It defines several internal functions prefixed with `fd_sandbox_private_` to encapsulate specific tasks like switching user IDs, clearing environment variables, and setting resource limits. The main entry point for using this library is the [`fd_sandbox_enter`](#fd_sandbox_enter) function, which orchestrates the setup of the sandbox environment by calling these internal functions in a specific order to ensure security and functionality. The file also includes error handling to log and terminate the process if any operation fails, ensuring that the sandbox is only entered if all security measures are successfully applied.
# Imports and Dependencies

---
- `fd_sandbox_private.h`
- `../cstr/fd_cstr.h`
- `../log/fd_log.h`
- `fcntl.h`
- `stdlib.h`
- `errno.h`
- `unistd.h`
- `sched.h`
- `dirent.h`
- `sys/stat.h`
- `sys/wait.h`
- `sys/prctl.h`
- `sys/mount.h`
- `sys/random.h`
- `sys/syscall.h`
- `sys/resource.h`
- `linux/keyctl.h`
- `linux/seccomp.h`
- `linux/securebits.h`
- `linux/capability.h`


# Global Variables

---
### environ
- **Type**: `char **`
- **Description**: The `environ` variable is a global variable that is an array of strings, where each string is an environment variable in the form of 'key=value'. It is declared as an external variable, meaning it is defined elsewhere, typically by the system or runtime environment.
- **Use**: This variable is used to access and manipulate the environment variables of the process, such as clearing them in the `fd_sandbox_private_explicit_clear_environment_variables` function.


# Data Structures

---
### rlimit\_setting
- **Type**: `struct`
- **Members**:
    - `resource`: Specifies the resource type for which the limit is being set, using either `__rlimit_resource_t` for glibc or `int` for non-glibc systems.
    - `limit`: Defines the maximum allowable value for the specified resource.
- **Description**: The `rlimit_setting` structure is used to define resource limits for processes, specifically setting the type of resource and its corresponding limit. It is designed to be compatible with both glibc and non-glibc systems by conditionally using `__rlimit_resource_t` or `int` for the `resource` member. This structure is typically used in conjunction with system calls like `setrlimit` to enforce resource constraints on processes, such as limiting the number of open files or the maximum size of the process's address space.


---
### landlock\_ruleset\_attr
- **Type**: `struct`
- **Members**:
    - `handled_access_fs`: A 64-bit unsigned integer representing the file system access rights handled by the ruleset.
    - `handled_access_net`: A 64-bit unsigned integer representing the network access rights handled by the ruleset.
- **Description**: The `landlock_ruleset_attr` structure is used to define a set of access rights for a Landlock ruleset, which is a security feature in Linux that allows for the creation of security policies to restrict the actions of processes. This structure contains two members: `handled_access_fs` and `handled_access_net`, which specify the file system and network access rights, respectively, that the ruleset will manage. These access rights are represented as 64-bit unsigned integers, where each bit corresponds to a specific permission or capability that can be granted or denied.


# Functions

---
### check\_unshare\_eacces\_main<!-- {{#callable:check_unshare_eacces_main}} -->
The `check_unshare_eacces_main` function attempts to switch the user and group IDs, unshare the user namespace, and open the setgroups file, returning 255 if any operation fails with EACCES, or logs an error and exits otherwise.
- **Inputs**:
    - `_arg`: A pointer to an argument that is cast to an unsigned long, which encodes the desired user ID and group ID.
- **Control Flow**:
    - Cast the input argument `_arg` to an unsigned long `arg`.
    - Extract `desired_uid` from the lower 16 bits and `desired_gid` from bits 32 to 47 of `arg`.
    - Call [`fd_sandbox_private_switch_uid_gid`](#fd_sandbox_private_switch_uid_gid) to switch to the desired user and group IDs.
    - Attempt to unshare the user namespace using `unshare(CLONE_NEWUSER)`.
    - If `unshare` fails with `EACCES`, return 255; otherwise, log an error and exit if it fails for another reason.
    - Attempt to open `/proc/self/setgroups` with write permissions.
    - If opening fails with `EACCES`, return 255; otherwise, log an error and exit if it fails for another reason.
    - Return 0 if all operations succeed.
- **Output**: Returns 255 if any operation fails with EACCES, otherwise logs an error and exits if any operation fails for another reason, or returns 0 if all operations succeed.
- **Functions called**:
    - [`fd_sandbox_private_switch_uid_gid`](#fd_sandbox_private_switch_uid_gid)


---
### fd\_sandbox\_requires\_cap\_sys\_admin<!-- {{#callable:fd_sandbox_requires_cap_sys_admin}} -->
The function `fd_sandbox_requires_cap_sys_admin` checks if creating a user namespace requires the `CAP_SYS_ADMIN` capability based on system configurations and restrictions.
- **Inputs**:
    - `desired_uid`: The desired user ID for the namespace.
    - `desired_gid`: The desired group ID for the namespace.
- **Control Flow**:
    - Open the file `/proc/sys/kernel/unprivileged_userns_clone` to check if unprivileged user namespaces are restricted.
    - If the file exists, read its value to determine if unprivileged user namespaces are allowed (value 1) or not (value 0).
    - If unprivileged user namespaces are not allowed, return 1 indicating `CAP_SYS_ADMIN` is required.
    - If the file does not exist or unprivileged user namespaces are allowed, proceed to the next check.
    - Create a child process using `clone` with a new stack to check if creating a user namespace results in `EACCES`, indicating further restrictions.
    - Wait for the child process to complete and check its exit status.
    - If the child process exits with a status indicating `EACCES`, return 1.
    - If no restrictions are detected, return 0.
- **Output**: Returns 1 if creating a user namespace requires `CAP_SYS_ADMIN`, otherwise returns 0.


---
### fd\_sandbox\_private\_explicit\_clear\_environment\_variables<!-- {{#callable:FD_FN_SENSITIVE::fd_sandbox_private_explicit_clear_environment_variables}} -->
The function `fd_sandbox_private_explicit_clear_environment_variables` securely clears all environment variables by overwriting them with zeros and then attempts to clear the environment list.
- **Inputs**: None
- **Control Flow**:
    - Check if the global `environ` variable is non-null; if it is null, return immediately.
    - Iterate over each environment variable in `environ`.
    - For each environment variable, calculate its length using `strlen`.
    - Use `explicit_bzero` to overwrite the environment variable with zeros, ensuring the memory is cleared securely.
    - Call `clearenv` to remove all environment variables from the environment list.
    - If `clearenv` fails, log an error using `FD_LOG_ERR`.
- **Output**: The function does not return any value; it performs its operations directly on the global `environ` variable and logs errors if `clearenv` fails.


---
### fd\_sandbox\_private\_check\_exact\_file\_descriptors<!-- {{#callable:fd_sandbox_private_check_exact_file_descriptors}} -->
The function `fd_sandbox_private_check_exact_file_descriptors` verifies that the current process's open file descriptors match exactly with a specified list of allowed file descriptors.
- **Inputs**:
    - `allowed_file_descriptor_cnt`: The number of allowed file descriptors, which must not exceed 256.
    - `allowed_file_descriptor`: An array of integers representing the allowed file descriptors.
- **Control Flow**:
    - Check if `allowed_file_descriptor_cnt` exceeds 256 and log an error if it does.
    - Initialize an array `seen_fds` to track which allowed file descriptors have been seen.
    - Iterate over `allowed_file_descriptor` to ensure all values are valid (non-negative and not `INT_MAX`) and log an error if any are invalid.
    - Check for duplicate entries in `allowed_file_descriptor` and log an error if any are found.
    - Open the directory `/proc/self/fd` to read the current process's file descriptors.
    - Use `getdents64` syscall to read directory entries from `/proc/self/fd`.
    - Iterate over the directory entries, skipping `.` and `..`, and convert entry names to file descriptor numbers.
    - For each file descriptor, check if it matches any in `allowed_file_descriptor` and mark it as seen; log an error if a duplicate is found or if it is unexpected.
    - After processing all entries, verify that all allowed file descriptors have been seen and log an error if any are missing.
    - Close the directory file descriptor `dirfd`.
- **Output**: The function does not return a value but logs errors if any discrepancies are found between the current open file descriptors and the allowed list.


---
### fd\_sandbox\_private\_switch\_uid\_gid<!-- {{#callable:fd_sandbox_private_switch_uid_gid}} -->
The function `fd_sandbox_private_switch_uid_gid` switches the current process's user ID (UID) and group ID (GID) to the specified desired values, ensuring that the change is applied directly to the process without affecting other threads.
- **Inputs**:
    - `desired_uid`: The target user ID to switch to.
    - `desired_gid`: The target group ID to switch to.
- **Control Flow**:
    - Initialize a flag `changed` to track if any changes are made.
    - Retrieve the current real, effective, and saved group IDs using `getresgid`.
    - If the current group IDs do not match the desired GID, use the `syscall` function to directly invoke `setresgid` to change them, and set `changed` to 1.
    - Retrieve the current real, effective, and saved user IDs using `getresuid`.
    - If the current user IDs do not match the desired UID, use the `syscall` function to directly invoke `setresuid` to change them, and set `changed` to 1.
    - If any changes were made, use `prctl` to set the process's dumpable attribute to 1, allowing debugging and setting UID/GID maps in a user namespace.
- **Output**: The function does not return a value; it performs the UID and GID switch as a side effect.


---
### fd\_sandbox\_private\_write\_userns\_uid\_gid\_maps<!-- {{#callable:fd_sandbox_private_write_userns_uid_gid_maps}} -->
The function `fd_sandbox_private_write_userns_uid_gid_maps` writes user and group ID mappings to the user namespace for the current process.
- **Inputs**:
    - `uid_in_parent`: The user ID in the parent namespace to be mapped to the user namespace.
    - `gid_in_parent`: The group ID in the parent namespace to be mapped to the user namespace.
- **Control Flow**:
    - Open the "/proc/self/setgroups" file in write-only mode to disable group changes.
    - Write "deny" to the setgroups file to prevent group changes in the user namespace.
    - Close the setgroups file.
    - Define paths for UID and GID map files: "/proc/self/uid_map" and "/proc/self/gid_map".
    - Store the input UID and GID in an array for iteration.
    - Iterate over the UID and GID map paths.
    - For each path, open the file in write-only mode.
    - Format a mapping line as "1 <id> 1\n" where <id> is the corresponding UID or GID.
    - Write the mapping line to the file.
    - Close the file after writing.
- **Output**: The function does not return any value; it performs operations to set up UID and GID mappings in the user namespace.


---
### fd\_sandbox\_private\_deny\_namespaces<!-- {{#callable:fd_sandbox_private_deny_namespaces}} -->
The function `fd_sandbox_private_deny_namespaces` restricts the creation of various Linux namespaces by setting specific limits in the system's proc filesystem.
- **Inputs**: None
- **Control Flow**:
    - Define two static arrays, `SYSCTLS` and `VALUES`, containing paths to sysctl files and their corresponding values, respectively.
    - Iterate over each sysctl path in the `SYSCTLS` array.
    - For each path, open the file in write-only mode and check for errors.
    - Write the corresponding value from the `VALUES` array to the opened file and check for errors.
    - Close the file and check for errors.
- **Output**: The function does not return any value; it performs its operations directly on the system's proc filesystem.


---
### fd\_sandbox\_private\_pivot\_root<!-- {{#callable:fd_sandbox_private_pivot_root}} -->
The `fd_sandbox_private_pivot_root` function isolates the current process by creating a new mount namespace and changing the root directory to a newly created temporary directory, effectively jailing the process in an empty environment.
- **Inputs**: None
- **Control Flow**:
    - The function begins by unsharing the current mount namespace using `unshare(CLONE_NEWNS)` to create a new, private mount namespace.
    - It generates a random number using `getrandom()` to create a unique path for the new root directory.
    - A new directory is created at `/tmp/fd_sandbox_<random_number>` with `mkdir()`.
    - The root filesystem is remounted as a slave to prevent propagation of mount events using `mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL)`.
    - The new directory is bind-mounted onto itself to prepare it for becoming the new root using `mount(new_root_path, new_root_path, NULL, MS_BIND | MS_REC, NULL)`.
    - The current working directory is changed to the new root path using `chdir(new_root_path)`.
    - The `pivot_root` system call is used to make the new directory the root of the filesystem, effectively jailing the process in the new environment.
    - The old root is unmounted using `umount2(".", MNT_DETACH)` to detach it from the filesystem.
    - Finally, the working directory is changed to the new root using `chdir("/")`.
- **Output**: The function does not return any value; it modifies the process's environment by changing its root directory.


---
### fd\_sandbox\_private\_set\_rlimits<!-- {{#callable:fd_sandbox_private_set_rlimits}} -->
The `fd_sandbox_private_set_rlimits` function sets resource limits for various system resources using the `setrlimit` system call.
- **Inputs**:
    - `rlimit_file_cnt`: The maximum number of open file descriptors allowed.
    - `rlimit_address_space`: The maximum size of the process's address space.
    - `rlimit_data`: The maximum size of the process's data segment.
- **Control Flow**:
    - An array of `rlimit_setting` structures is initialized with specific resource limits, including `RLIMIT_NOFILE`, `RLIMIT_NICE`, `RLIMIT_AS`, `RLIMIT_CORE`, `RLIMIT_DATA`, `RLIMIT_MEMLOCK`, `RLIMIT_MSGQUEUE`, `RLIMIT_NPROC`, `RLIMIT_RTPRIO`, `RLIMIT_RTTIME`, `RLIMIT_SIGPENDING`, and `RLIMIT_STACK`, with most limits set to zero except for those specified by the input parameters.
    - A loop iterates over each element in the `rlimits` array.
    - For each resource, a `struct rlimit` is created with both `rlim_cur` and `rlim_max` set to the specified limit.
    - The `setrlimit` function is called to apply the limit for each resource.
    - If `setrlimit` fails, an error is logged using `FD_LOG_ERR`.
- **Output**: The function does not return a value; it sets system resource limits and logs an error if any `setrlimit` call fails.


---
### fd\_sandbox\_private\_drop\_caps<!-- {{#callable:fd_sandbox_private_drop_caps}} -->
The `fd_sandbox_private_drop_caps` function removes all capabilities from the process, ensuring it runs with minimal privileges.
- **Inputs**:
    - `cap_last_cap`: The highest capability index to be dropped, typically obtained from the system's capability list.
- **Control Flow**:
    - Set secure bits using `prctl` to lock capabilities and prevent privilege escalation.
    - Iterate over all capabilities from 0 to `cap_last_cap`, dropping each one using `prctl` with `PR_CAPBSET_DROP`.
    - Clear all capabilities using `syscall` with `SYS_capset` to set the capability data to zero.
    - Clear all ambient capabilities using `prctl` with `PR_CAP_AMBIENT_CLEAR_ALL`.
- **Output**: The function does not return a value; it modifies the process's capabilities to enhance security.


---
### fd\_sandbox\_private\_landlock\_restrict\_self<!-- {{#callable:fd_sandbox_private_landlock_restrict_self}} -->
The function `fd_sandbox_private_landlock_restrict_self` configures and applies a Landlock security ruleset to restrict the current process's filesystem and network access based on the specified ABI version and connection permissions.
- **Inputs**:
    - `allow_connect`: An integer flag indicating whether TCP connect operations should be allowed (non-zero) or restricted (zero).
- **Control Flow**:
    - Initialize a `landlock_ruleset_attr` structure with default filesystem and network access permissions.
    - If `allow_connect` is false, add the `LANDLOCK_ACCESS_NET_CONNECT_TCP` permission to the network access mask.
    - Attempt to retrieve the Landlock ABI version using `syscall` with `SYS_landlock_create_ruleset`.
    - If the syscall fails with `ENOSYS` or `EOPNOTSUPP`, exit the function as Landlock is not supported.
    - If the syscall fails for other reasons, log an error and exit.
    - Adjust the access permissions in `attr` based on the retrieved ABI version, removing unsupported permissions for older ABI versions.
    - Create a Landlock ruleset using `syscall` with `SYS_landlock_create_ruleset` and the configured `attr`.
    - If the ruleset creation fails, log an error and exit.
    - Apply the Landlock ruleset to the current process using `syscall` with `SYS_landlock_restrict_self`.
    - If applying the ruleset fails, log an error and exit.
- **Output**: The function does not return a value; it either successfully applies the Landlock restrictions or logs an error and exits if any step fails.


---
### fd\_sandbox\_private\_set\_seccomp\_filter<!-- {{#callable:fd_sandbox_private_set_seccomp_filter}} -->
The `fd_sandbox_private_set_seccomp_filter` function sets a seccomp filter for the current process to restrict system calls based on a provided filter program.
- **Inputs**:
    - `seccomp_filter_cnt`: The number of filter instructions in the seccomp filter program.
    - `seccomp_filter`: A pointer to an array of `sock_filter` structures that define the seccomp filter program.
- **Control Flow**:
    - A `sock_fprog` structure is initialized with the provided filter count and filter array.
    - The `syscall` function is called with `SYS_seccomp` to set the seccomp filter mode to `SECCOMP_SET_MODE_FILTER` using the `sock_fprog` structure.
    - If the syscall fails, an error is logged using `FD_LOG_ERR`.
- **Output**: The function does not return a value; it sets the seccomp filter for the process or logs an error if the operation fails.


---
### fd\_sandbox\_private\_read\_cap\_last\_cap<!-- {{#callable:fd_sandbox_private_read_cap_last_cap}} -->
The function `fd_sandbox_private_read_cap_last_cap` reads the last valid capability index from the Linux kernel's `/proc/sys/kernel/cap_last_cap` file and returns it as an unsigned long integer.
- **Inputs**: None
- **Control Flow**:
    - Open the file `/proc/sys/kernel/cap_last_cap` in read-only mode and check for errors.
    - Read the content of the file into a buffer and check for read errors or truncated data.
    - Convert the buffer content to an unsigned long integer using `strtoul` and validate the conversion.
    - Close the file and check for errors.
    - Validate the capability index to ensure it is within a valid range (greater than 0 and less than 64).
- **Output**: The function returns the last valid capability index as an unsigned long integer.


---
### fd\_sandbox\_private\_enter\_no\_seccomp<!-- {{#callable:fd_sandbox_private_enter_no_seccomp}} -->
The `fd_sandbox_private_enter_no_seccomp` function sets up a secure sandbox environment by configuring user and group IDs, namespaces, capabilities, and resource limits without using seccomp.
- **Inputs**:
    - `desired_uid`: The user ID to switch to within the sandbox.
    - `desired_gid`: The group ID to switch to within the sandbox.
    - `keep_host_networking`: A flag indicating whether to retain access to the host's network namespace.
    - `allow_connect`: A flag indicating whether network connections are allowed.
    - `keep_controlling_terminal`: A flag indicating whether to retain the controlling terminal.
    - `dumpable`: A flag indicating whether the process should be dumpable.
    - `rlimit_file_cnt`: The maximum number of open file descriptors allowed.
    - `rlimit_address_space`: The maximum size of the process's address space.
    - `rlimit_data`: The maximum size of the process's data segment.
    - `allowed_file_descriptor_cnt`: The number of file descriptors that are allowed to remain open.
    - `allowed_file_descriptor`: An array of file descriptors that are allowed to remain open.
- **Control Flow**:
    - Read the highest capability index from the kernel using [`fd_sandbox_private_read_cap_last_cap`](#fd_sandbox_private_read_cap_last_cap).
    - Clear environment variables and check allowed file descriptors using [`fd_sandbox_private_explicit_clear_environment_variables`](#FD_FN_SENSITIVEfd_sandbox_private_explicit_clear_environment_variables) and [`fd_sandbox_private_check_exact_file_descriptors`](#fd_sandbox_private_check_exact_file_descriptors).
    - Replace the session keyring with a new anonymous one using `syscall(SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING, NULL)`.
    - Detach from the controlling terminal if `keep_controlling_terminal` is false using `setsid()`.
    - Determine if CAP_SYS_ADMIN is required for user namespaces using [`fd_sandbox_requires_cap_sys_admin`](#fd_sandbox_requires_cap_sys_admin) and set `PR_SET_KEEPCAPS` if needed.
    - Switch to the desired UID and GID using [`fd_sandbox_private_switch_uid_gid`](#fd_sandbox_private_switch_uid_gid).
    - Check and warn if there are multiple supplementary groups using `getgroups()`.
    - Raise CAP_SYS_ADMIN again if needed using `syscall(SYS_capget)` and `syscall(SYS_capset)`.
    - Unshare the user namespace and write UID/GID maps using `unshare(CLONE_NEWUSER)` and [`fd_sandbox_private_write_userns_uid_gid_maps`](#fd_sandbox_private_write_userns_uid_gid_maps).
    - Unshare other namespaces based on flags and deny further namespace creation using `unshare` and [`fd_sandbox_private_deny_namespaces`](#fd_sandbox_private_deny_namespaces).
    - Clear `PR_SET_KEEPCAPS` and set `PR_SET_DUMPABLE` using `prctl`.
    - Pivot the root filesystem to restrict file access using [`fd_sandbox_private_pivot_root`](#fd_sandbox_private_pivot_root).
    - Apply landlock restrictions using [`fd_sandbox_private_landlock_restrict_self`](#fd_sandbox_private_landlock_restrict_self).
    - Set resource limits using [`fd_sandbox_private_set_rlimits`](#fd_sandbox_private_set_rlimits).
    - Drop all capabilities using [`fd_sandbox_private_drop_caps`](#fd_sandbox_private_drop_caps).
    - Set `PR_SET_NO_NEW_PRIVS` to prevent gaining new privileges using `prctl`.
- **Output**: The function does not return a value; it configures the process environment to be sandboxed.
- **Functions called**:
    - [`fd_sandbox_private_read_cap_last_cap`](#fd_sandbox_private_read_cap_last_cap)
    - [`FD_FN_SENSITIVE::fd_sandbox_private_explicit_clear_environment_variables`](#FD_FN_SENSITIVEfd_sandbox_private_explicit_clear_environment_variables)
    - [`fd_sandbox_private_check_exact_file_descriptors`](#fd_sandbox_private_check_exact_file_descriptors)
    - [`fd_sandbox_requires_cap_sys_admin`](#fd_sandbox_requires_cap_sys_admin)
    - [`fd_sandbox_private_switch_uid_gid`](#fd_sandbox_private_switch_uid_gid)
    - [`fd_sandbox_private_write_userns_uid_gid_maps`](#fd_sandbox_private_write_userns_uid_gid_maps)
    - [`fd_sandbox_private_deny_namespaces`](#fd_sandbox_private_deny_namespaces)
    - [`fd_sandbox_private_pivot_root`](#fd_sandbox_private_pivot_root)
    - [`fd_sandbox_private_landlock_restrict_self`](#fd_sandbox_private_landlock_restrict_self)
    - [`fd_sandbox_private_set_rlimits`](#fd_sandbox_private_set_rlimits)
    - [`fd_sandbox_private_drop_caps`](#fd_sandbox_private_drop_caps)


---
### fd\_sandbox\_enter<!-- {{#callable:fd_sandbox_enter}} -->
The `fd_sandbox_enter` function sets up a secure sandbox environment by configuring user and group IDs, network settings, file descriptor limits, and seccomp filters.
- **Inputs**:
    - `desired_uid`: The user ID to switch to within the sandbox.
    - `desired_gid`: The group ID to switch to within the sandbox.
    - `keep_host_networking`: Flag indicating whether to retain host networking capabilities.
    - `allow_connect`: Flag indicating whether to allow network connections.
    - `keep_controlling_terminal`: Flag indicating whether to retain the controlling terminal.
    - `dumpable`: Flag indicating whether the process should be dumpable.
    - `rlimit_file_cnt`: The maximum number of open file descriptors allowed.
    - `rlimit_address_space`: The maximum size of the process's address space.
    - `rlimit_data`: The maximum size of the process's data segment.
    - `allowed_file_descriptor_cnt`: The number of file descriptors that are allowed to remain open.
    - `allowed_file_descriptor`: Array of file descriptors that are allowed to remain open.
    - `seccomp_filter_cnt`: The number of seccomp filter instructions.
    - `seccomp_filter`: Array of seccomp filter instructions to apply.
- **Control Flow**:
    - Check if the number of seccomp filters exceeds USHORT_MAX and log an error if it does.
    - Call [`fd_sandbox_private_enter_no_seccomp`](#fd_sandbox_private_enter_no_seccomp) to set up the sandbox environment without seccomp filters, passing all relevant parameters.
    - Log an informational message indicating that the full sandbox is being enabled.
    - Call [`fd_sandbox_private_set_seccomp_filter`](#fd_sandbox_private_set_seccomp_filter) to apply the seccomp-bpf filter with the provided filter instructions.
- **Output**: The function does not return a value; it sets up the sandbox environment as a side effect.
- **Functions called**:
    - [`fd_sandbox_private_enter_no_seccomp`](#fd_sandbox_private_enter_no_seccomp)
    - [`fd_sandbox_private_set_seccomp_filter`](#fd_sandbox_private_set_seccomp_filter)


---
### fd\_sandbox\_switch\_uid\_gid<!-- {{#callable:fd_sandbox_switch_uid_gid}} -->
The `fd_sandbox_switch_uid_gid` function switches the user ID (UID) and group ID (GID) of the current process to the specified values and logs that the sandbox is disabled.
- **Inputs**:
    - `desired_uid`: The desired user ID to switch to.
    - `desired_gid`: The desired group ID to switch to.
- **Control Flow**:
    - Call the [`fd_sandbox_private_switch_uid_gid`](#fd_sandbox_private_switch_uid_gid) function with `desired_uid` and `desired_gid` to change the process's UID and GID.
    - Log the message 'sandbox: sandbox disabled' using `FD_LOG_INFO`.
- **Output**: This function does not return any value; it performs actions to change the process's UID and GID and logs a message.
- **Functions called**:
    - [`fd_sandbox_private_switch_uid_gid`](#fd_sandbox_private_switch_uid_gid)


---
### fd\_sandbox\_getpid<!-- {{#callable:fd_sandbox_getpid}} -->
The `fd_sandbox_getpid` function retrieves the process ID (PID) of the current process by reading the symbolic link `/proc/self` and converting it to an unsigned long integer.
- **Inputs**: None
- **Control Flow**:
    - Initialize a character array `pid` to store the PID as a string.
    - Use `readlink` to read the symbolic link `/proc/self` into the `pid` array.
    - Check if `readlink` failed or if the result is truncated, and log an error if so.
    - Convert the string in `pid` to an unsigned long integer using `strtoul`.
    - Check if the conversion was successful and if the result is within the valid range for a PID, logging an error if not.
    - Return the converted PID as an unsigned long integer.
- **Output**: The function returns the process ID of the current process as an unsigned long integer.


---
### fd\_sandbox\_gettid<!-- {{#callable:fd_sandbox_gettid}} -->
The `fd_sandbox_gettid` function retrieves the thread ID (TID) of the current thread by reading the symbolic link `/proc/thread-self` and parsing the result.
- **Inputs**: None
- **Control Flow**:
    - Initialize a character array `tid` to store the thread ID path with a size of 27 characters.
    - Use `readlink` to read the symbolic link `/proc/thread-self` into the `tid` array.
    - Check if `readlink` failed or if the result is truncated, and log an error if so.
    - Find the first '/' character in `tid` to locate the start of the task string.
    - Find the next '/' character in the task string to locate the start of the actual TID.
    - Convert the substring after the second '/' to an unsigned long using `strtoul`.
    - Check if the conversion was successful and if the TID is within the valid range (<= INT_MAX), logging an error if not.
    - Return the parsed TID as an unsigned long.
- **Output**: The function returns the thread ID (TID) of the current thread as an unsigned long.


# Function Declarations (Public API)

---
### fd\_sandbox\_private\_switch\_uid\_gid<!-- {{#callable_declaration:fd_sandbox_private_switch_uid_gid}} -->
Switches the process's user and group IDs to the specified values.
- **Description**: This function changes the user ID (UID) and group ID (GID) of the calling process to the specified desired values. It is typically used in development environments where processes need to switch to a specific UID and GID for privilege management. The function directly invokes system calls to change the credentials, bypassing the usual glibc behavior that synchronizes UID and GID changes across all threads. This approach is suitable when all threads are expected to switch to the target UID and GID independently. The function also ensures that the process remains dumpable if the UID or GID is changed, which is necessary for debugging and setting UID/GID maps in user namespaces.
- **Inputs**:
    - `desired_uid`: The target user ID to switch to. It must be a valid user ID on the system. The function will log an error if the switch fails.
    - `desired_gid`: The target group ID to switch to. It must be a valid group ID on the system. The function will log an error if the switch fails.
- **Output**: None
- **See also**: [`fd_sandbox_private_switch_uid_gid`](#fd_sandbox_private_switch_uid_gid)  (Implementation)


