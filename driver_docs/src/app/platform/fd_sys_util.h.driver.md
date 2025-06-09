# Purpose
This C header file, `fd_sys_util.h`, provides declarations for utility functions that facilitate system-level operations. It includes functions such as [`fd_sys_util_exit_group`](#fd_sys_util_exit_group), which immediately terminates the calling process using the `exit_group` system call, bypassing standard exit handlers. The [`fd_sys_util_nanosleep`](#fd_sys_util_nanosleep) function allows a thread to sleep for a specified duration in nanoseconds, ensuring the sleep continues even if interrupted. Additionally, [`fd_sys_util_login_user`](#fd_sys_util_login_user) attempts to retrieve the username of the currently logged-in user, and [`fd_sys_util_user_to_uid`](#fd_sys_util_user_to_uid) converts a username to its corresponding user ID (UID) and group ID (GID). These utilities are designed to provide more direct or robust alternatives to standard C library functions, particularly in scenarios where precise control over process behavior and user information is required.
# Imports and Dependencies

---
- `../../util/fd_util.h`


# Global Variables

---
### fd\_sys\_util\_login\_user
- **Type**: `function`
- **Description**: The `fd_sys_util_login_user` function is designed to return a string representing the best guess of the currently logged-in user. It returns a pointer to a constant character string, which has a static lifetime, meaning the string is not dynamically allocated and persists for the duration of the program. If the function fails to determine the logged-in user, it returns NULL.
- **Use**: This function is used to retrieve the username of the currently logged-in user, which may differ from the user running the process.


# Function Declarations (Public API)

---
### fd\_sys\_util\_exit\_group<!-- {{#callable_declaration:fd_sys_util_exit_group}} -->
Exit the calling process immediately with the specified exit code.
- **Description**: Use this function to terminate the calling process immediately with a specific exit code. It is a direct wrapper around the exit_group system call, bypassing any normal exit handlers or atexit functions that the C runtime might have installed. This function is useful when you need to ensure that the process exits without executing any additional cleanup code. It must be noted that this function does not return, as it terminates the process.
- **Inputs**:
    - `code`: The exit code with which the process should terminate. This is an integer value that will be returned to the operating system to indicate the termination status of the process.
- **Output**: None
- **See also**: [`fd_sys_util_exit_group`](fd_sys_util.c.driver.md#fd_sys_util_exit_group)  (Implementation)


---
### fd\_sys\_util\_nanosleep<!-- {{#callable_declaration:fd_sys_util_nanosleep}} -->
Sleeps the calling thread for a specified duration in seconds and nanoseconds.
- **Description**: Use this function to pause the execution of the calling thread for a precise duration specified in seconds and nanoseconds. It ensures that the sleep duration is completed even if the thread is interrupted, by resuming the remaining sleep time. This function is useful in scenarios where precise timing is required, such as in real-time applications or when implementing delays. It returns zero on successful completion of the sleep duration, and -1 if an error occurs, with errno set to indicate the error.
- **Inputs**:
    - `secs`: The number of seconds to sleep. It is an unsigned integer and should represent a non-negative duration.
    - `nanos`: The number of additional nanoseconds to sleep. It is an unsigned integer and should be less than 1,000,000,000 to represent a valid nanosecond duration.
- **Output**: Returns 0 on success, or -1 on failure with errno set to indicate the error.
- **See also**: [`fd_sys_util_nanosleep`](fd_sys_util.c.driver.md#fd_sys_util_nanosleep)  (Implementation)


---
### fd\_sys\_util\_login\_user<!-- {{#callable_declaration:fd_sys_util_login_user}} -->
Returns the best guess at the currently logged-in user.
- **Description**: Use this function to obtain the username of the currently logged-in user, which may differ from the user running the process. It attempts to retrieve the username from several environment variables in a specific order, and if none are set, it falls back to using the system's login name. The function returns a pointer to a string with static lifetime, meaning the caller should not attempt to modify or free it. If it fails to determine the username, it returns NULL.
- **Inputs**: None
- **Output**: Returns a pointer to a string containing the username, or NULL if the username cannot be determined.
- **See also**: [`fd_sys_util_login_user`](fd_sys_util.c.driver.md#fd_sys_util_login_user)  (Implementation)


---
### fd\_sys\_util\_user\_to\_uid<!-- {{#callable_declaration:fd_sys_util_user_to_uid}} -->
Converts a username to its corresponding UID and GID.
- **Description**: Use this function to retrieve the user ID (UID) and group ID (GID) associated with a given username. It is useful when you need to perform operations that require user identity verification or manipulation based on username. The function must be called with valid pointers for UID and GID to store the results. It handles errors by returning -1 and setting errno appropriately, such as when the username does not exist or if there are system call failures. This function may fork a new process to safely retrieve the user information, ensuring that any system resources are properly managed.
- **Inputs**:
    - `user`: A pointer to a null-terminated string representing the username to be converted. Must not be null.
    - `uid`: A pointer to an unsigned integer where the function will store the user's UID. Must not be null.
    - `gid`: A pointer to an unsigned integer where the function will store the user's GID. Must not be null.
- **Output**: Returns 0 on success, with UID and GID written to the provided pointers. Returns -1 on failure, with errno set to indicate the error.
- **See also**: [`fd_sys_util_user_to_uid`](fd_sys_util.c.driver.md#fd_sys_util_user_to_uid)  (Implementation)


