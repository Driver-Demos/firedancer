# Purpose
This C source code file provides utility functions for system-level operations, primarily focusing on user and process management. The file includes functions to exit a process group, perform a nanosleep, retrieve the login username, and convert a username to user and group IDs. The [`fd_sys_util_exit_group`](#fd_sys_util_exit_group) function uses a system call to terminate all threads in a process group, ensuring a clean exit. The [`fd_sys_util_nanosleep`](#fd_sys_util_nanosleep) function provides a wrapper around the `nanosleep` system call, handling interruptions and allowing for precise sleep durations. The [`fd_sys_util_login_user`](#fd_sys_util_login_user) function attempts to determine the current user's login name by checking various environment variables and falling back to the `getlogin` function if necessary. The [`fd_sys_util_user_to_uid`](#fd_sys_util_user_to_uid) function is more complex, involving a forked process to safely call `getpwnam_r` without leaving file descriptors open, which is a known issue with certain glibc implementations. This function maps a username to its corresponding user ID (UID) and group ID (GID), handling potential errors and edge cases.

Overall, the file provides a narrow set of functionalities related to system utilities, specifically targeting user and process management tasks. It is designed to be part of a larger codebase, likely serving as a utility module that can be imported and used by other components. The functions defined here do not expose a public API but rather offer internal utilities that can be leveraged by other parts of the software to perform low-level system operations reliably and efficiently.
# Imports and Dependencies

---
- `fd_sys_util.h`
- `pwd.h`
- `errno.h`
- `stdlib.h`
- `time.h`
- `unistd.h`
- `sys/syscall.h`
- `sys/mman.h`
- `sys/wait.h`


# Functions

---
### fd\_sys\_util\_exit\_group<!-- {{#callable:fd_sys_util_exit_group}} -->
The `fd_sys_util_exit_group` function terminates all threads in the calling process with a specified exit code using a system call.
- **Inputs**:
    - `code`: An integer representing the exit code to be used when terminating the process.
- **Control Flow**:
    - The function calls the `syscall` function with `SYS_exit_group` and the provided `code` to terminate all threads in the process.
    - After the syscall, the function enters an infinite loop to ensure it never returns, as indicated by the `noreturn` attribute.
- **Output**: This function does not return any value as it is marked with the `noreturn` attribute, indicating that it will not return to the caller.


---
### fd\_sys\_util\_nanosleep<!-- {{#callable:fd_sys_util_nanosleep}} -->
The `fd_sys_util_nanosleep` function attempts to pause the execution of the program for a specified number of seconds and nanoseconds, handling interruptions by retrying the remaining time.
- **Inputs**:
    - `secs`: The number of seconds to sleep.
    - `nanos`: The number of nanoseconds to sleep.
- **Control Flow**:
    - Initialize a `timespec` structure `ts` with the provided seconds and nanoseconds.
    - Enter a loop that calls `nanosleep` with `ts` and a `rem` structure to store remaining time if interrupted.
    - If `nanosleep` returns -1 and `errno` is `EINTR`, update `ts` with `rem` to retry the sleep with the remaining time.
    - If `nanosleep` fails for any other reason, return -1 to indicate an error.
    - If `nanosleep` completes successfully, exit the loop and return 0.
- **Output**: Returns 0 on successful sleep completion, or -1 if an error occurs other than interruption.


---
### fd\_sys\_util\_login\_user<!-- {{#callable:fd_sys_util_login_user}} -->
The `fd_sys_util_login_user` function retrieves the current user's login name by checking various environment variables and system calls.
- **Inputs**: None
- **Control Flow**:
    - Attempt to retrieve the user's name from the 'SUDO_USER' environment variable; if found, return it.
    - If 'SUDO_USER' is not set, check the 'LOGNAME' environment variable; if found, return it.
    - If 'LOGNAME' is not set, check the 'USER' environment variable; if found, return it.
    - If 'USER' is not set, check the 'LNAME' environment variable; if found, return it.
    - If 'LNAME' is not set, check the 'USERNAME' environment variable; if found, return it.
    - If none of the environment variables are set, call `getlogin()` to retrieve the login name from the system.
    - If `getlogin()` fails due to specific errors (ENXIO or ENOTTY), return NULL.
    - If `getlogin()` fails for other reasons, log an error and return the result of `getlogin()`.
- **Output**: Returns a pointer to a string containing the user's login name, or NULL if it cannot be determined.


---
### fd\_sys\_util\_user\_to\_uid<!-- {{#callable:fd_sys_util_user_to_uid}} -->
The `fd_sys_util_user_to_uid` function retrieves the user ID (UID) and group ID (GID) for a given username by forking a process to safely call `getpwnam_r` and handling potential file descriptor issues.
- **Inputs**:
    - `user`: A constant character pointer representing the username for which the UID and GID are to be retrieved.
    - `uid`: A pointer to an unsigned integer where the retrieved user ID will be stored.
    - `gid`: A pointer to an unsigned integer where the retrieved group ID will be stored.
- **Control Flow**:
    - Allocate a shared memory region using `mmap` to store the results (UID and GID).
    - Check if `mmap` failed and return -1 if it did.
    - Initialize the results array with `UINT_MAX` to indicate uninitialized values.
    - Fork a new process to safely call `getpwnam_r` to avoid file descriptor issues with glibc.
    - In the child process, call `getpwnam_r` to retrieve the password entry for the given username.
    - If `getpwnam_r` fails or the user does not exist, log a warning and exit the child process with an error code.
    - If successful, store the retrieved UID and GID in the shared memory and exit the child process with a success code.
    - In the parent process, wait for the child process to complete using `waitpid`.
    - Check the exit status of the child process and handle any errors or signals that may have occurred.
    - If the results are still uninitialized (`UINT_MAX`), set `errno` to `ENOENT` and return -1.
    - Copy the retrieved UID and GID from the shared memory to the provided pointers.
    - Unmap the shared memory region and return 0 to indicate success.
- **Output**: Returns 0 on success, with the UID and GID stored in the provided pointers, or -1 on failure, with `errno` set to indicate the error.
- **Functions called**:
    - [`fd_sys_util_exit_group`](#fd_sys_util_exit_group)


