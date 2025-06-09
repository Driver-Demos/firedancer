# Purpose
This C source code file is a comprehensive test suite designed to validate various sandboxing and security features in a Unix-like operating system environment. The file includes a series of test functions that assess the behavior and enforcement of security mechanisms such as environment variable management, file descriptor checks, namespace restrictions, user and group ID switching, capability dropping, resource limit settings, and seccomp (secure computing mode) policies. The code is structured to execute these tests in isolated processes using the `fork` system call, ensuring that each test runs independently and does not interfere with others.

The file imports several headers, including custom ones like "fd_sandbox.h" and "fd_sandbox_private.h", which likely define the sandboxing functions being tested. It also includes system headers for handling processes, file descriptors, and capabilities. The test functions utilize macros like `TEST_FORK_EXIT_CODE` and `TEST_FORK_SIGNAL` to manage process creation and result verification. The main function orchestrates the execution of these tests, logging the results and skipping certain tests if the necessary privileges (such as root access) are not available. This file is intended to be compiled and executed as a standalone program to verify the robustness and correctness of the sandboxing features implemented in the associated library or application.
# Imports and Dependencies

---
- `fd_sandbox.h`
- `fd_sandbox_private.h`
- `../fd_util.h`
- `generated/test_sandbox_seccomp.h`
- `sys/file.h`
- `stdlib.h`
- `fcntl.h`
- `errno.h`
- `unistd.h`
- `sched.h`
- `dirent.h`
- `net/if.h`
- `sys/wait.h`
- `sys/stat.h`
- `sys/mman.h`
- `sys/prctl.h`
- `sys/syscall.h`
- `sys/resource.h`
- `linux/securebits.h`
- `linux/capability.h`


# Global Variables

---
### environ
- **Type**: `char **`
- **Description**: `environ` is a global variable that is an array of strings, where each string is an environment variable in the format 'KEY=VALUE'. It is declared as an external variable, meaning it is defined elsewhere, typically by the operating system or runtime environment.
- **Use**: `environ` is used to access and manipulate the environment variables of the process, allowing the program to read or modify the environment settings.


# Data Structures

---
### rlimit\_setting
- **Type**: `struct`
- **Members**:
    - `resource`: Specifies the resource type for which the limit is being set, using either __rlimit_resource_t for glibc or int for non-glibc systems.
    - `limit`: Defines the maximum allowable value for the specified resource.
- **Description**: The `rlimit_setting` structure is used to define resource limits for processes, specifying both the type of resource and the limit value. It is designed to be compatible with both glibc and non-glibc systems by conditionally using different types for the `resource` member. This structure is typically used in conjunction with system calls that manage resource limits, such as `setrlimit` and `getrlimit`, to control the allocation of system resources like file descriptors, memory, and CPU time.


---
### landlock\_ruleset\_attr
- **Type**: `struct`
- **Members**:
    - `handled_access_fs`: A 64-bit unsigned integer representing the file system access rights handled by the ruleset.
- **Description**: The `landlock_ruleset_attr` structure is used to define attributes for a Landlock ruleset, specifically focusing on the file system access rights that the ruleset is designed to handle. This structure is part of the Landlock security module, which provides a way to restrict the actions that processes can perform, enhancing security by limiting access to certain resources. The `handled_access_fs` member specifies the types of file system operations that the ruleset will manage, allowing for fine-grained control over file system access.


# Functions

---
### test\_clear\_environment<!-- {{#callable:test_clear_environment}} -->
The `test_clear_environment` function tests the clearing and resetting of environment variables, ensuring that memory is zeroed after clearing.
- **Inputs**: None
- **Control Flow**:
    - The function begins by calling `clearenv()` to clear all environment variables and checks if `environ` is null using `FD_TEST`.
    - It sets three environment variables using `setenv()` and verifies their presence and values in `environ`.
    - The function then calls `fd_sandbox_private_explicit_clear_environment_variables()` to explicitly clear environment variables and checks if `environ` is null again.
    - It verifies that the memory for the environment variables has been zeroed by iterating over each character in the strings and checking if they are zero.
- **Output**: The function does not return any value; it uses assertions to verify the correctness of environment variable operations.


---
### test\_check\_file\_descriptors\_inner<!-- {{#callable:test_check_file_descriptors_inner}} -->
The function `test_check_file_descriptors_inner` tests the behavior of the [`fd_sandbox_private_check_exact_file_descriptors`](fd_sandbox.c.driver.md#fd_sandbox_private_check_exact_file_descriptors) function with various sets of allowed file descriptors and expected exit codes.
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `allow_fds` with file descriptors {0, 1, 2, 3}.
    - Use `TEST_FORK_EXIT_CODE` to check if [`fd_sandbox_private_check_exact_file_descriptors`](fd_sandbox.c.driver.md#fd_sandbox_private_check_exact_file_descriptors) with 4 file descriptors and `allow_fds` exits with code 0.
    - Repeat the above step with different numbers of file descriptors and different arrays of allowed file descriptors, expecting different exit codes (0 or 1) based on the test case.
    - Use `dup2` to duplicate file descriptor 3 to 4 and test again with `allow_fds` and `allow_fds2`.
    - Create an array `too_many_fds` with 257 elements, each initialized to its index value, and duplicate file descriptor 3 to indices 5 through 256.
    - Test [`fd_sandbox_private_check_exact_file_descriptors`](fd_sandbox.c.driver.md#fd_sandbox_private_check_exact_file_descriptors) with 256 and 257 file descriptors using `too_many_fds`, expecting exit codes 0 and 1 respectively.
- **Output**: The function does not return any value; it performs tests and asserts expected behavior using `FD_TEST` and `TEST_FORK_EXIT_CODE` macros.
- **Functions called**:
    - [`fd_sandbox_private_check_exact_file_descriptors`](fd_sandbox.c.driver.md#fd_sandbox_private_check_exact_file_descriptors)


---
### test\_check\_file\_descriptors<!-- {{#callable:test_check_file_descriptors}} -->
The `test_check_file_descriptors` function tests the behavior of file descriptor checks by executing the [`test_check_file_descriptors_inner`](#test_check_file_descriptors_inner) function in a forked process and verifying it exits with a status code of 0.
- **Inputs**: None
- **Control Flow**:
    - The function calls the macro `TEST_FORK_EXIT_CODE` with `test_check_file_descriptors_inner()` as the child process and 0 as the expected exit code.
    - The `TEST_FORK_EXIT_CODE` macro forks the process, and in the child process, it executes `test_check_file_descriptors_inner()`.
    - In the parent process, it waits for the child process to terminate and checks if it exited normally with the expected exit code of 0.
- **Output**: The function does not return a value; it verifies the exit status of the child process executing [`test_check_file_descriptors_inner`](#test_check_file_descriptors_inner).
- **Functions called**:
    - [`test_check_file_descriptors_inner`](#test_check_file_descriptors_inner)


---
### test\_deny\_namespaces\_inner<!-- {{#callable:test_deny_namespaces_inner}} -->
The `test_deny_namespaces_inner` function tests the ability to deny the creation of new namespaces by modifying system control settings and verifying the changes.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the current user and group IDs using `getuid()` and `getgid()`.
    - Attempt to unshare the user namespace with `unshare(CLONE_NEWUSER)` and verify success.
    - Write the user and group ID maps using [`fd_sandbox_private_write_userns_uid_gid_maps`](fd_sandbox.c.driver.md#fd_sandbox_private_write_userns_uid_gid_maps).
    - Define an array of system control paths related to various namespace limits.
    - Iterate over each system control path, open the file, read its value, and verify that the value is greater than 1.
    - Call `fd_sandbox_private_deny_namespaces()` to apply namespace restrictions.
    - Iterate over each system control path again, open the file, read its value, and verify that the values match expected limits (1 for user namespaces, 2 for mount namespaces, and 0 for others).
    - Use `TEST_FORK_EXIT_CODE` to verify that attempts to unshare various namespaces (network, cgroup, IPC, PID, UTS) fail, while attempts to unshare the mount namespace succeed.
- **Output**: The function does not return a value; it performs tests and assertions to verify namespace restrictions.
- **Functions called**:
    - [`fd_sandbox_private_write_userns_uid_gid_maps`](fd_sandbox.c.driver.md#fd_sandbox_private_write_userns_uid_gid_maps)
    - [`fd_sandbox_private_deny_namespaces`](fd_sandbox.c.driver.md#fd_sandbox_private_deny_namespaces)


---
### test\_deny\_namespaces<!-- {{#callable:test_deny_namespaces}} -->
The `test_deny_namespaces` function executes the [`test_deny_namespaces_inner`](#test_deny_namespaces_inner) function in a forked process and checks for a successful exit code of 0.
- **Inputs**: None
- **Control Flow**:
    - The function calls the macro `TEST_FORK_EXIT_CODE` with `test_deny_namespaces_inner()` as the child process and 0 as the expected exit code.
    - The `TEST_FORK_EXIT_CODE` macro forks the current process.
    - In the parent process, it waits for the child process to terminate and checks the exit status to ensure it exited normally with the expected code.
    - In the child process, it executes `test_deny_namespaces_inner()` and exits with `EXIT_SUCCESS`.
- **Output**: The function does not return any value; it performs a test to ensure [`test_deny_namespaces_inner`](#test_deny_namespaces_inner) completes successfully with an exit code of 0.
- **Functions called**:
    - [`test_deny_namespaces_inner`](#test_deny_namespaces_inner)


---
### test\_switch\_uid\_gid1<!-- {{#callable:test_switch_uid_gid1}} -->
The `test_switch_uid_gid1` function tests the switching of user and group IDs and verifies the changes using assertions.
- **Inputs**:
    - `check_uid`: The user ID to switch to and verify.
    - `check_gid`: The group ID to switch to and verify.
- **Control Flow**:
    - Call [`fd_sandbox_private_switch_uid_gid`](fd_sandbox.c.driver.md#fd_sandbox_private_switch_uid_gid) to switch the user and group IDs to `check_uid` and `check_gid` respectively.
    - Retrieve the real, effective, and saved user IDs using `getresuid` and assert that they match `check_uid`.
    - Retrieve the real, effective, and saved group IDs using `getresgid` and assert that they match `check_gid`.
    - Assert that the process is in a dumpable state using `prctl` with `PR_GET_DUMPABLE`.
- **Output**: The function does not return a value; it uses assertions to verify the correctness of the UID and GID switching.
- **Functions called**:
    - [`fd_sandbox_private_switch_uid_gid`](fd_sandbox.c.driver.md#fd_sandbox_private_switch_uid_gid)


---
### test\_switch\_uid\_gid<!-- {{#callable:test_switch_uid_gid}} -->
The `test_switch_uid_gid` function tests the ability to switch user and group IDs by forking processes and verifying the switch using various UID and GID combinations.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the current user ID (UID) and group ID (GID) using `getuid()` and `getgid()` respectively.
    - Invoke `TEST_FORK_EXIT_CODE` macro multiple times with [`test_switch_uid_gid1`](#test_switch_uid_gid1) function and different UID and GID pairs to test the switching functionality.
    - Each invocation of `TEST_FORK_EXIT_CODE` forks a new process, runs [`test_switch_uid_gid1`](#test_switch_uid_gid1) with the specified UID and GID, and checks if the process exits with code 0, indicating success.
    - The final test uses the original UID and GID to ensure the switch back to the original user and group is successful.
- **Output**: The function does not return any value; it performs tests and logs errors if any test fails.
- **Functions called**:
    - [`test_switch_uid_gid1`](#test_switch_uid_gid1)


---
### test\_pivot\_root\_inner<!-- {{#callable:test_pivot_root_inner}} -->
The `test_pivot_root_inner` function tests the behavior of the pivot_root operation in a sandboxed environment by verifying the accessibility of certain directories and ensuring the current working directory remains consistent.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the current user and group IDs using `getuid()` and `getgid()`.
    - Unshare the user namespace using `unshare(CLONE_NEWUSER)` and map the user and group IDs to the new namespace.
    - Open the `/mnt` and `/proc` directories to ensure they are accessible, then close them.
    - Invoke `fd_sandbox_private_pivot_root()` to change the root filesystem.
    - Attempt to reopen `/mnt` and `/proc` to verify they are no longer accessible, expecting `ENOENT` errors.
    - Open the root directory `/` and iterate over its entries using `getdents64`, ensuring only `.` and `..` are present.
    - Close the root directory file descriptor.
    - Verify the current working directory is `/` using `getcwd()` and ensure it remains `/` after attempting to change to the parent directory with `chdir("..")`.
- **Output**: The function does not return any value but uses assertions (`FD_TEST`) to validate the expected behavior of the pivot_root operation and directory accessibility.
- **Functions called**:
    - [`fd_sandbox_private_write_userns_uid_gid_maps`](fd_sandbox.c.driver.md#fd_sandbox_private_write_userns_uid_gid_maps)
    - [`fd_sandbox_private_pivot_root`](fd_sandbox.c.driver.md#fd_sandbox_private_pivot_root)


---
### test\_pivot\_root<!-- {{#callable:test_pivot_root}} -->
The `test_pivot_root` function tests the [`test_pivot_root_inner`](#test_pivot_root_inner) function by forking a process and checking if it exits with a status code of 0.
- **Inputs**: None
- **Control Flow**:
    - The function calls the macro `TEST_FORK_EXIT_CODE` with `test_pivot_root_inner()` as the child process and 0 as the expected exit code.
    - The `TEST_FORK_EXIT_CODE` macro forks a new process.
    - In the parent process, it waits for the child process to exit and checks the exit status.
    - If the child process exits with a status code different from 0, an error is logged.
    - In the child process, `test_pivot_root_inner()` is executed, and the process exits with `EXIT_SUCCESS`.
- **Output**: The function does not return a value; it logs an error if the child process does not exit with the expected status code.
- **Functions called**:
    - [`test_pivot_root_inner`](#test_pivot_root_inner)


---
### test\_drop\_caps\_inner<!-- {{#callable:test_drop_caps_inner}} -->
The `test_drop_caps_inner` function tests the process of dropping capabilities in a Linux environment by manipulating user and group IDs, checking and setting capabilities, and verifying secure bits.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the current user ID (uid) and group ID (gid) using `getuid()` and `getgid()`.
    - Unshare the user namespace using `unshare(CLONE_NEWUSER)` and map the current uid and gid to the new namespace using [`fd_sandbox_private_write_userns_uid_gid_maps`](fd_sandbox.c.driver.md#fd_sandbox_private_write_userns_uid_gid_maps).
    - Retrieve the current secure bits using `prctl(PR_GET_SECUREBITS)` and ensure they are not set.
    - Iterate over all capabilities up to `cap_last_cap` (40) and check if they are set in the bounding set and ambient set using `prctl`.
    - Initialize capability structures `capheader` and `capdata` and retrieve current capabilities using `syscall(SYS_capget)`.
    - Verify the effective, permitted, and inheritable capabilities in `capdata` match expected values.
    - Set the inheritable capabilities in `capdata` and apply them using `syscall(SYS_capset)`.
    - Verify the capabilities again to ensure they have been set correctly.
    - Call [`fd_sandbox_private_drop_caps`](fd_sandbox.c.driver.md#fd_sandbox_private_drop_caps) to drop capabilities up to `cap_last_cap`.
    - Retrieve and verify the secure bits again to ensure they match expected locked values.
    - Iterate over all capabilities up to `cap_last_cap` and ensure they are not set in the bounding set and ambient set using `prctl`.
    - Retrieve the capabilities again using `syscall(SYS_capget)` and verify that all capabilities are now zeroed out.
- **Output**: The function does not return a value; it uses assertions to verify that capabilities are correctly dropped and secure bits are set as expected.
- **Functions called**:
    - [`fd_sandbox_private_write_userns_uid_gid_maps`](fd_sandbox.c.driver.md#fd_sandbox_private_write_userns_uid_gid_maps)
    - [`fd_sandbox_private_drop_caps`](fd_sandbox.c.driver.md#fd_sandbox_private_drop_caps)


---
### test\_drop\_caps<!-- {{#callable:test_drop_caps}} -->
The `test_drop_caps` function tests the [`test_drop_caps_inner`](#test_drop_caps_inner) function to ensure it executes successfully and exits with a status code of 0.
- **Inputs**: None
- **Control Flow**:
    - The function `test_drop_caps` is called, which in turn calls the macro `TEST_FORK_EXIT_CODE`.
    - `TEST_FORK_EXIT_CODE` forks the process and runs [`test_drop_caps_inner`](#test_drop_caps_inner) in the child process.
    - The child process executes [`test_drop_caps_inner`](#test_drop_caps_inner) and exits with `EXIT_SUCCESS`.
    - The parent process waits for the child process to finish and checks the exit status.
    - If the child process exits with a status code of 0, the test is considered successful.
- **Output**: The function does not return a value; it verifies that [`test_drop_caps_inner`](#test_drop_caps_inner) exits with a status code of 0.
- **Functions called**:
    - [`test_drop_caps_inner`](#test_drop_caps_inner)


---
### test\_resource\_limits\_inner<!-- {{#callable:test_resource_limits_inner}} -->
The `test_resource_limits_inner` function tests the enforcement of resource limits in a sandboxed environment by setting various resource limits to zero and verifying their effects.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the current user ID and group ID using `getuid()` and `getgid()`.
    - Unshare the user namespace using `unshare(CLONE_NEWUSER)` and map the user and group IDs using [`fd_sandbox_private_write_userns_uid_gid_maps`](fd_sandbox.c.driver.md#fd_sandbox_private_write_userns_uid_gid_maps).
    - Define an array of `rlimit_setting` structures with various resource limits set to zero.
    - Open the root directory and verify the file descriptor is valid, then close it.
    - Allocate and deallocate memory using `mmap` and `munmap`, and test memory locking and unlocking with `mlock` and `munlock`.
    - Fork a process to test exit code using `TEST_FORK_EXIT_CODE`.
    - Set resource limits using [`fd_sandbox_private_set_rlimits`](fd_sandbox.c.driver.md#fd_sandbox_private_set_rlimits).
    - Iterate over the `rlimits` array, retrieve current limits using `getrlimit`, and verify they match the expected zero limits.
    - Attempt to open the root directory again and verify it fails with `EMFILE` error due to file descriptor limit.
    - Attempt to allocate memory again and verify it fails with `ENOMEM` error due to address space limit.
    - Attempt to lock memory again and verify it fails with `EPERM` error due to memory lock limit.
    - If not running as root, attempt to fork a process and verify it fails with `EAGAIN` error due to process limit.
- **Output**: The function does not return a value; it performs tests and assertions to verify resource limits are enforced as expected.
- **Functions called**:
    - [`fd_sandbox_private_write_userns_uid_gid_maps`](fd_sandbox.c.driver.md#fd_sandbox_private_write_userns_uid_gid_maps)
    - [`fd_sandbox_private_set_rlimits`](fd_sandbox.c.driver.md#fd_sandbox_private_set_rlimits)


---
### test\_resource\_limits<!-- {{#callable:test_resource_limits}} -->
The `test_resource_limits` function tests the enforcement of resource limits by executing the [`test_resource_limits_inner`](#test_resource_limits_inner) function in a forked process and verifying it exits with code 0.
- **Inputs**: None
- **Control Flow**:
    - The function calls the macro `TEST_FORK_EXIT_CODE` with `test_resource_limits_inner()` as the child process and `0` as the expected exit code.
    - The `TEST_FORK_EXIT_CODE` macro forks the current process.
    - In the parent process, it waits for the child process to terminate and checks the exit status to ensure it exited normally with the expected code.
    - In the child process, it executes `test_resource_limits_inner()` and exits with `EXIT_SUCCESS`.
- **Output**: The function does not return a value; it verifies the child process exits with code 0, indicating successful enforcement of resource limits.
- **Functions called**:
    - [`test_resource_limits_inner`](#test_resource_limits_inner)


---
### test\_landlock\_inner<!-- {{#callable:test_landlock_inner}} -->
The `test_landlock_inner` function tests the creation and enforcement of a Landlock ruleset to restrict filesystem access.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `landlock_ruleset_attr` structure with no filesystem access permissions.
    - Attempt to create a Landlock ruleset using the `syscall` function with `SYS_landlock_create_ruleset`.
    - Check if the syscall failed due to lack of support (`ENOSYS`), log a warning, and return if so.
    - Verify that the Landlock ruleset file descriptor is valid and close it.
    - Open the root directory (`/`) with read-only access and verify the file descriptor is valid, then close it.
    - Call [`fd_sandbox_private_landlock_restrict_self`](fd_sandbox.c.driver.md#fd_sandbox_private_landlock_restrict_self) to apply the Landlock restrictions to the current process.
    - Attempt to open the root directory again and log the result, expecting a failure with `EPERM` error due to the applied restrictions.
- **Output**: The function does not return any value; it performs tests and logs results, using assertions to verify expected behavior.
- **Functions called**:
    - [`fd_sandbox_private_landlock_restrict_self`](fd_sandbox.c.driver.md#fd_sandbox_private_landlock_restrict_self)


---
### test\_landlock<!-- {{#callable:test_landlock}} -->
The `test_landlock` function tests the Landlock security feature by creating a ruleset with no access permissions and verifying that access to the root directory is denied.
- **Inputs**: None
- **Control Flow**:
    - The function `test_landlock` calls `TEST_FORK_EXIT_CODE` macro with `test_landlock_inner()` as the child process and `0` as the expected exit code.
    - The `TEST_FORK_EXIT_CODE` macro forks a new process and runs `test_landlock_inner()` in the child process.
    - In the child process, `test_landlock_inner()` attempts to create a Landlock ruleset with no access permissions using the `syscall` function.
    - If the syscall returns `-1` with `errno` set to `ENOSYS`, it logs a warning and returns, indicating that Landlock is not supported.
    - If the ruleset is successfully created, it closes the file descriptor and attempts to open the root directory with read-only access.
    - The function then calls `fd_sandbox_private_landlock_restrict_self` to apply the Landlock restrictions to the current process.
    - It attempts to open the root directory again, expecting the operation to fail with `EPERM` (permission denied).
- **Output**: The function does not return a value; it uses assertions to verify that the Landlock ruleset is correctly applied and logs warnings if Landlock is not supported.
- **Functions called**:
    - [`test_landlock_inner`](#test_landlock_inner)


---
### test\_read\_last\_cap<!-- {{#callable:test_read_last_cap}} -->
The `test_read_last_cap` function verifies that the last capability read by [`fd_sandbox_private_read_cap_last_cap`](fd_sandbox.c.driver.md#fd_sandbox_private_read_cap_last_cap) is equal to 40.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_sandbox_private_read_cap_last_cap()` to retrieve the last capability value.
    - It uses the `FD_TEST` macro to assert that the returned value is equal to 40UL.
- **Output**: The function does not return any value; it performs an assertion check.
- **Functions called**:
    - [`fd_sandbox_private_read_cap_last_cap`](fd_sandbox.c.driver.md#fd_sandbox_private_read_cap_last_cap)


---
### test\_seccomp<!-- {{#callable:test_seccomp}} -->
The `test_seccomp` function tests the application of a seccomp filter to restrict system calls and verifies the behavior of various system calls under this filter.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `sock_filter` array with 128 elements to hold the seccomp filter instructions.
    - Call [`populate_sock_filter_policy_test_sandbox`](generated/test_sandbox_seccomp.h.driver.md#populate_sock_filter_policy_test_sandbox) to populate the seccomp filter with a predefined policy.
    - Define two macros, `TEST_FORK_SECCOMP_SIGNAL` and `TEST_FORK_SECCOMP_EXIT_CODE`, to test system calls under the seccomp filter in a forked process, checking for specific signals or exit codes.
    - Apply the seccomp filter using `fd_sandbox_private_set_seccomp_filter` and test various system calls like `getpid`, `fsync`, `alarm`, `fork`, `kill`, and `mkdir` to ensure they behave as expected under the filter.
    - Use `TEST_FORK_SECCOMP_EXIT_CODE` to verify that allowed operations exit with code 0, and `TEST_FORK_SECCOMP_SIGNAL` to verify that restricted operations are terminated with `SIGSYS`.
- **Output**: The function does not return any value; it performs tests and logs results to verify the behavior of system calls under a seccomp filter.
- **Functions called**:
    - [`populate_sock_filter_policy_test_sandbox`](generated/test_sandbox_seccomp.h.driver.md#populate_sock_filter_policy_test_sandbox)


---
### test\_undumpable\_inner<!-- {{#callable:test_undumpable_inner}} -->
The `test_undumpable_inner` function tests the sandboxing environment to ensure that the process is not dumpable and that user and group IDs are set to 1.
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `allow_fds` with file descriptors 0, 1, 2, and 3.
    - Call [`fd_sandbox_private_enter_no_seccomp`](fd_sandbox.c.driver.md#fd_sandbox_private_enter_no_seccomp) with the current user and group IDs, and the `allow_fds` array to enter a sandbox environment without seccomp.
    - Check that the process is not dumpable using `prctl(PR_GET_DUMPABLE)` and assert the result is false.
    - Check that the process does not keep capabilities using `prctl(PR_GET_KEEPCAPS)` and assert the result is false.
    - Retrieve the real, effective, and saved user IDs using `getresuid` and assert they are all set to 1.
    - Retrieve the real, effective, and saved group IDs using `getresgid` and assert they are all set to 1.
- **Output**: The function does not return any value; it performs assertions to validate the sandbox environment's properties.
- **Functions called**:
    - [`fd_sandbox_private_enter_no_seccomp`](fd_sandbox.c.driver.md#fd_sandbox_private_enter_no_seccomp)


---
### test\_undumpable<!-- {{#callable:test_undumpable}} -->
The `test_undumpable` function tests the behavior of a process when it is set to be undumpable by executing the [`test_undumpable_inner`](#test_undumpable_inner) function in a forked process and checking for a successful exit code.
- **Inputs**: None
- **Control Flow**:
    - The function calls the macro `TEST_FORK_EXIT_CODE` with `test_undumpable_inner()` as the child process and `0` as the expected exit code.
    - The `TEST_FORK_EXIT_CODE` macro forks the current process.
    - In the parent process, it waits for the child process to terminate and checks the exit status to ensure it exited normally with the expected exit code.
    - In the child process, it executes `test_undumpable_inner()` and then exits with `EXIT_SUCCESS`.
- **Output**: The function does not return any value; it performs a test and relies on assertions to validate behavior.
- **Functions called**:
    - [`test_undumpable_inner`](#test_undumpable_inner)


---
### test\_controlling\_terminal\_inner<!-- {{#callable:test_controlling_terminal_inner}} -->
The function `test_controlling_terminal_inner` tests the behavior of session IDs before and after entering a sandbox environment without seccomp restrictions.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the session ID of the current process using `getsid(0)` and store it in `sid1`.
    - Assert that `sid1` is not -1, indicating a valid session ID was retrieved.
    - Define an array `allow_fds` containing file descriptors 0, 1, 2, and 3.
    - Enter a sandbox environment without seccomp restrictions using [`fd_sandbox_private_enter_no_seccomp`](fd_sandbox.c.driver.md#fd_sandbox_private_enter_no_seccomp), passing the current user and group IDs, and the `allow_fds` array.
    - Retrieve the session ID of the process using `getsid(1)` and store it in `sid2`.
    - Assert that `sid2` is not -1, indicating a valid session ID was retrieved.
    - Assert that `sid1` is not equal to `sid2`, indicating that the session ID has changed after entering the sandbox.
- **Output**: The function does not return any value; it performs assertions to validate the behavior of session IDs in a sandbox environment.
- **Functions called**:
    - [`fd_sandbox_private_enter_no_seccomp`](fd_sandbox.c.driver.md#fd_sandbox_private_enter_no_seccomp)


---
### test\_controlling\_terminal<!-- {{#callable:test_controlling_terminal}} -->
The `test_controlling_terminal` function tests whether a process can change its controlling terminal by forking and executing [`test_controlling_terminal_inner`](#test_controlling_terminal_inner).
- **Inputs**: None
- **Control Flow**:
    - The function calls the macro `TEST_FORK_EXIT_CODE` with `test_controlling_terminal_inner()` as the child process code and `0` as the expected exit code.
    - The `TEST_FORK_EXIT_CODE` macro forks the process, creating a child process.
    - In the parent process, it waits for the child process to terminate and checks the exit status to ensure it exited normally with the expected code.
    - In the child process, it executes `test_controlling_terminal_inner()` and then exits with `EXIT_SUCCESS`.
- **Output**: The function does not return any value; it performs a test and logs the result.
- **Functions called**:
    - [`test_controlling_terminal_inner`](#test_controlling_terminal_inner)


---
### test\_netns\_inner<!-- {{#callable:test_netns_inner}} -->
The `test_netns_inner` function tests the behavior of network namespace isolation by checking the availability of network interfaces before and after entering a sandbox environment without seccomp restrictions.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the list of network interfaces using `if_nameindex()` and assert that the second interface name is not NULL.
    - Define an array `allow_fds` containing file descriptors 0, 1, 2, and 3.
    - Enter a sandbox environment without seccomp restrictions using [`fd_sandbox_private_enter_no_seccomp`](fd_sandbox.c.driver.md#fd_sandbox_private_enter_no_seccomp) with the current user and group IDs and the `allow_fds` array.
    - Retrieve the list of network interfaces again using `if_nameindex()` and assert that the result is NULL, indicating no interfaces are available.
- **Output**: The function does not return any value; it uses assertions to validate the expected behavior of network namespace isolation.
- **Functions called**:
    - [`fd_sandbox_private_enter_no_seccomp`](fd_sandbox.c.driver.md#fd_sandbox_private_enter_no_seccomp)


---
### test\_netns<!-- {{#callable:test_netns}} -->
The `test_netns` function executes the [`test_netns_inner`](#test_netns_inner) function in a forked process and checks if it exits with a status code of 0.
- **Inputs**: None
- **Control Flow**:
    - The function `test_netns` calls the macro `TEST_FORK_EXIT_CODE` with `test_netns_inner()` as the child process and 0 as the expected exit code.
    - The `TEST_FORK_EXIT_CODE` macro forks the current process.
    - In the parent process, it waits for the child process to terminate and checks the exit status.
    - If the child process does not exit normally or the exit status is not 0, it logs an error.
    - In the child process, it executes `test_netns_inner()` and exits with `EXIT_SUCCESS`.
- **Output**: The function does not return any value; it logs an error if the child process does not exit with the expected status code.
- **Functions called**:
    - [`test_netns_inner`](#test_netns_inner)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment and sequentially runs a series of security and sandboxing tests, logging the results and skipping certain tests if not run as root.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with `argc` and `argv`.
    - Log a notice and call [`test_clear_environment`](#test_clear_environment) to test environment clearing.
    - Log a notice and call [`test_check_file_descriptors`](#test_check_file_descriptors) to test file descriptor checks.
    - Log a notice and conditionally call [`test_switch_uid_gid`](#test_switch_uid_gid) if running as root, otherwise log a warning.
    - Log a notice and call [`test_deny_namespaces`](#test_deny_namespaces) to test namespace denial.
    - Log a notice and call [`test_pivot_root`](#test_pivot_root) to test pivot root functionality.
    - Log a notice and call [`test_drop_caps`](#test_drop_caps) to test capability dropping.
    - Log a notice and call [`test_resource_limits`](#test_resource_limits) to test resource limits.
    - Log a notice and call [`test_landlock`](#test_landlock) to test landlock functionality.
    - Log a notice and call [`test_read_last_cap`](#test_read_last_cap) to test reading the last capability.
    - Log a notice and call [`test_seccomp`](#test_seccomp) to test seccomp functionality.
    - Log a notice and conditionally call [`test_undumpable`](#test_undumpable) if running as root, otherwise log a warning.
    - Log a notice and conditionally call [`test_netns`](#test_netns) if running as root, otherwise log a warning.
    - Log a notice indicating all tests passed.
    - Call `fd_halt` to clean up and exit the program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_clear_environment`](#test_clear_environment)
    - [`test_check_file_descriptors`](#test_check_file_descriptors)
    - [`test_switch_uid_gid`](#test_switch_uid_gid)
    - [`test_deny_namespaces`](#test_deny_namespaces)
    - [`test_pivot_root`](#test_pivot_root)
    - [`test_drop_caps`](#test_drop_caps)
    - [`test_resource_limits`](#test_resource_limits)
    - [`test_landlock`](#test_landlock)
    - [`test_read_last_cap`](#test_read_last_cap)
    - [`test_seccomp`](#test_seccomp)
    - [`test_undumpable`](#test_undumpable)
    - [`test_netns`](#test_netns)


