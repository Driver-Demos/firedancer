# Purpose
The provided C source code file is a comprehensive logging utility designed for use in a multi-threaded, multi-process environment. It is intended to be integrated into larger applications to provide detailed logging capabilities, including the ability to log messages with various severity levels, manage log files, and handle logging across different threads and processes. The code is structured to support both POSIX and non-POSIX environments, with conditional compilation directives to include necessary headers and define platform-specific behavior.

Key components of the code include functions for setting and retrieving application, thread, host, and user identifiers, which are used to tag log messages with contextual information. The code also includes mechanisms for deduplicating log messages to reduce redundancy, formatting timestamps, and handling signals to log backtraces in the event of a crash. The logging utility supports colorized output for terminal displays and can be configured via environment variables or command-line arguments. Additionally, the code provides APIs for bootstrapping and halting the logging system, ensuring that resources are properly initialized and cleaned up. This file is not an executable on its own but is intended to be included in other projects to provide logging functionality.
# Imports and Dependencies

---
- `fd_log.h`
- `stdio.h`
- `stdlib.h`
- `stdarg.h`
- `ctype.h`
- `errno.h`
- `fcntl.h`
- `unistd.h`
- `signal.h`
- `sched.h`
- `time.h`
- `syscall.h`
- `sys/mman.h`
- `execinfo.h`
- `sys/stat.h`
- `../tile/fd_tile_private.h`
- `../../app/fdctl/version.h`
- `sys/resource.h`


# Global Variables

---
### fd\_log\_build\_info
- **Type**: ``char const``
- **Description**: The `fd_log_build_info` is a constant character array initialized with a single null character. It is aligned to a 1-byte boundary using the `__attribute__((aligned(1)))` attribute. This variable is used to store build information for logging purposes, but defaults to an empty string if no build information is provided.
- **Use**: This variable is used to store and provide build information for logging, defaulting to an empty string if no build information is available.


# Functions

---
### fd\_log\_private\_app\_id\_set<!-- {{#callable:fd_log_private_app_id_set}} -->
Sets the private application ID for logging.
- **Inputs**:
    - `app_id`: An unsigned long integer representing the application ID to be set.
- **Control Flow**:
    - The function directly assigns the provided `app_id` to the static variable `fd_log_private_app_id`.
    - No conditional logic or loops are present in the function.
- **Output**: The function does not return a value; it modifies the internal state by setting the application ID.


---
### fd\_log\_app\_id<!-- {{#callable:fd_log_app_id}} -->
Returns the application logical ID for logging.
- **Inputs**:
    - `void`: This function does not take any input parameters.
- **Control Flow**:
    - The function directly returns the value of the static variable `fd_log_private_app_id`.
- **Output**: Returns the current application logical ID as an unsigned long integer.


---
### fd\_log\_private\_app\_set<!-- {{#callable:fd_log_private_app_set}} -->
Sets the application name for logging.
- **Inputs**:
    - `app`: A constant character pointer representing the application name to be set.
- **Control Flow**:
    - Checks if the input `app` is NULL; if so, assigns it a default value of '[app]'.
    - Compares the provided `app` with the current application name stored in `fd_log_private_app`.
    - If the new `app` is different from the current one, it initializes a new string and appends the new application name to it, ensuring it does not exceed the maximum allowed length.
- **Output**: The function does not return a value; it modifies the internal state by updating the application name used for logging.


---
### fd\_log\_app<!-- {{#callable:fd_log_app}} -->
Returns a pointer to the private application log string.
- **Inputs**:
    - `void`: This function does not take any input parameters.
- **Control Flow**:
    - The function directly returns the value of the static variable `fd_log_private_app`.
- **Output**: Returns a constant character pointer to the application log string stored in `fd_log_private_app`.


---
### fd\_log\_private\_thread\_id\_next<!-- {{#callable:fd_log_private_thread_id_next}} -->
The `fd_log_private_thread_id_next` function atomically increments and retrieves the next thread ID.
- **Inputs**: None
- **Control Flow**:
    - The function calls `FD_ATOMIC_FETCH_AND_ADD` with the address of `fd_log_private_thread_id_ctr` and the value 1UL.
    - This operation atomically increments the counter and returns the previous value before the increment.
- **Output**: The function returns the previous value of the thread ID counter before it was incremented.


---
### fd\_log\_private\_thread\_id\_set<!-- {{#callable:fd_log_private_thread_id_set}} -->
Sets the private thread ID for logging purposes.
- **Inputs**:
    - `thread_id`: An unsigned long integer representing the thread ID to be set.
- **Control Flow**:
    - The function directly assigns the provided `thread_id` to the static variable `fd_log_private_thread_id`.
    - It also sets the static variable `fd_log_private_thread_id_init` to 1, indicating that the thread ID has been initialized.
- **Output**: This function does not return a value; it modifies internal state variables to store the thread ID.


---
### fd\_log\_thread\_id<!-- {{#callable:fd_log_thread_id}} -->
Retrieves the thread ID for logging purposes.
- **Inputs**:
    - `void`: This function does not take any input arguments.
- **Control Flow**:
    - Checks if threading is enabled using the `FD_HAS_THREADS` macro.
    - If threading is enabled and the thread ID has not been initialized, it calls [`fd_log_private_thread_id_set`](#fd_log_private_thread_id_set) to set the thread ID using [`fd_log_private_thread_id_next`](#fd_log_private_thread_id_next).
    - If threading is not enabled, it performs a memory fence operation using `FD_COMPILER_MFENCE()`.
    - Finally, it returns the current thread ID stored in `fd_log_private_thread_id`.
- **Output**: Returns the current thread ID as an unsigned long integer.
- **Functions called**:
    - [`fd_log_private_thread_id_set`](#fd_log_private_thread_id_set)
    - [`fd_log_private_thread_id_next`](#fd_log_private_thread_id_next)


---
### fd\_log\_private\_thread\_default<!-- {{#callable:fd_log_private_thread_default}} -->
Initializes the `name` string with the current thread ID.
- **Inputs**:
    - `name`: A pointer to a character array where the thread ID will be stored as a string.
- **Control Flow**:
    - Calls `fd_log_thread_id()` to retrieve the current thread ID.
    - Uses `sprintf` to format the thread ID as a string and store it in the `name` array.
- **Output**: The function does not return a value; it modifies the `name` array in place to contain the thread ID as a string.
- **Functions called**:
    - [`fd_log_thread_id`](#fd_log_thread_id)


---
### fd\_log\_thread\_set<!-- {{#callable:fd_log_thread_set}} -->
Sets the current thread's name for logging purposes.
- **Inputs**:
    - `thread`: A constant character pointer representing the name of the thread to be set.
- **Control Flow**:
    - Checks if the input `thread` is NULL or an empty string.
    - If `thread` is NULL or empty, it calls [`fd_log_private_thread_default`](#fd_log_private_thread_default) to set a default thread name.
    - If `thread` is not the same as the current thread name, it appends the new thread name to the existing one using `fd_cstr_append_cstr_safe`.
    - Sets the `fd_log_private_thread_init` flag to indicate that the thread name has been initialized.
- **Output**: The function does not return a value; it modifies the internal state to reflect the current thread's name.
- **Functions called**:
    - [`fd_log_private_thread_default`](#fd_log_private_thread_default)


---
### fd\_log\_thread<!-- {{#callable:fd_log_thread}} -->
Retrieves the current thread's log name, initializing it if necessary.
- **Inputs**:
    - `None`: The function does not take any input arguments.
- **Control Flow**:
    - Checks if the thread's log name has been initialized using the `FD_UNLIKELY` macro.
    - If not initialized, it calls [`fd_log_thread_set`](#fd_log_thread_set) with a NULL argument to set a default thread name.
    - Returns the current thread's log name stored in `fd_log_private_thread`.
- **Output**: Returns a constant string representing the name of the current thread for logging purposes.
- **Functions called**:
    - [`fd_log_thread_set`](#fd_log_thread_set)


---
### fd\_log\_private\_host\_id\_set<!-- {{#callable:fd_log_private_host_id_set}} -->
Sets the private host ID for logging.
- **Inputs**:
    - `host_id`: An unsigned long integer representing the host ID to be set.
- **Control Flow**:
    - The function directly assigns the provided `host_id` to the static variable `fd_log_private_host_id`.
    - There are no conditional statements or loops; the assignment is straightforward.
- **Output**: The function does not return a value; it modifies the internal state by setting the `fd_log_private_host_id`.


---
### fd\_log\_host\_id<!-- {{#callable:fd_log_host_id}} -->
The `fd_log_host_id` function retrieves the current host ID.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the static variable `fd_log_private_host_id`.
- **Output**: Returns the current host ID as an unsigned long integer.


---
### fd\_log\_host<!-- {{#callable:fd_log_host}} -->
Returns a pointer to the private host string used for logging.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the static variable `fd_log_private_host`.
- **Output**: Returns a constant character pointer to the private host string.


---
### fd\_log\_private\_host\_set<!-- {{#callable:fd_log_private_host_set}} -->
Sets the private host identifier for logging.
- **Inputs**:
    - `host`: A constant character pointer representing the host name to be set.
- **Control Flow**:
    - Checks if the input `host` is NULL or an empty string; if so, it assigns a default value of '[host]'.
    - Compares the new `host` with the current private host; if they are different, it updates the private host using `fd_cstr_append_cstr_safe` and `fd_cstr_fini` to manage memory safely.
- **Output**: The function does not return a value; it modifies the internal state of the logging system by updating the private host identifier.


---
### fd\_log\_private\_cpu\_id\_default<!-- {{#callable:fd_log_private_cpu_id_default}} -->
Retrieves the CPU ID of the first CPU scheduled to run on, or returns ULONG_MAX on failure.
- **Inputs**: None
- **Control Flow**:
    - Declares a CPU set variable `cpu_set` to hold the CPU affinity.
    - Calls `fd_cpuset_getaffinity` to retrieve the CPU affinity for the current process (PID 0). If this call fails, it returns `ULONG_MAX`.
    - Uses `fd_cpuset_first` to get the index of the first CPU in the `cpu_set`.
    - Checks if the index is less than `FD_TILE_MAX`, if so, it assigns the index to `idx`, otherwise assigns `ULONG_MAX`.
- **Output**: Returns the index of the first CPU in the CPU set or `ULONG_MAX` if an error occurs.


---
### fd\_log\_private\_cpu\_id\_set<!-- {{#callable:fd_log_private_cpu_id_set}} -->
Sets the private CPU ID for logging purposes.
- **Inputs**:
    - `cpu_id`: An unsigned long integer representing the CPU ID to be set.
- **Control Flow**:
    - The function assigns the provided `cpu_id` to the static variable `fd_log_private_cpu_id`.
    - It also sets the static variable `fd_log_private_cpu_id_init` to 1, indicating that the CPU ID has been initialized.
- **Output**: The function does not return a value; it modifies internal state variables to reflect the new CPU ID.


---
### fd\_log\_cpu\_id<!-- {{#callable:fd_log_cpu_id}} -->
Retrieves the CPU ID for logging purposes, initializing it if necessary.
- **Inputs**: None
- **Control Flow**:
    - Checks if the CPU ID has been initialized using `fd_log_private_cpu_id_init`.
    - If not initialized, it calls [`fd_log_private_cpu_id_set`](#fd_log_private_cpu_id_set) with the result of `fd_log_private_cpu_id_default()` to set the CPU ID.
    - Finally, it returns the current CPU ID stored in `fd_log_private_cpu_id`.
- **Output**: Returns the current CPU ID as an unsigned long integer.
- **Functions called**:
    - [`fd_log_private_cpu_id_set`](#fd_log_private_cpu_id_set)
    - [`fd_log_private_cpu_id_default`](#fd_log_private_cpu_id_default)


---
### fd\_log\_private\_cpu\_default<!-- {{#callable:fd_log_private_cpu_default}} -->
Initializes a CPU name based on the current CPU affinity.
- **Inputs**:
    - `name`: A pointer to a character array where the CPU name will be stored.
- **Control Flow**:
    - Declares a CPU set to hold the current CPU affinity.
    - Calls `fd_cpuset_getaffinity` to retrieve the CPU affinity for the current process.
    - If an error occurs while retrieving the CPU affinity, it formats the error code into the `name` string and returns.
    - Counts the number of CPUs in the set using `fd_cpuset_cnt`.
    - If the count is not within the valid range (greater than 0 and less than or equal to `FD_TILE_MAX`), it formats an error code into the `name` string and returns.
    - Retrieves the index of the first CPU in the set using `fd_cpuset_first`.
    - Formats the CPU index into the `name` string, using a different format if there is more than one CPU.
- **Output**: The function does not return a value; instead, it modifies the `name` string to reflect the CPU index or an error code.


---
### fd\_log\_cpu\_set<!-- {{#callable:fd_log_cpu_set}} -->
Sets the CPU identifier for logging purposes.
- **Inputs**:
    - `cpu`: A string representing the CPU identifier to be set.
- **Control Flow**:
    - Checks if the input `cpu` is NULL or an empty string.
    - If `cpu` is NULL or empty, it calls [`fd_log_private_cpu_default`](#fd_log_private_cpu_default) to set a default CPU identifier.
    - If `cpu` is not NULL or empty and is different from the current CPU identifier, it updates the CPU identifier using `fd_cstr_append_cstr_safe` and initializes it.
- **Output**: The function does not return a value; it modifies the internal state to reflect the new CPU identifier.
- **Functions called**:
    - [`fd_log_private_cpu_default`](#fd_log_private_cpu_default)


---
### fd\_log\_cpu<!-- {{#callable:fd_log_cpu}} -->
The `fd_log_cpu` function retrieves the current CPU identifier used for logging.
- **Inputs**:
    - `void`: This function does not take any input arguments.
- **Control Flow**:
    - The function first checks if the `fd_log_private_cpu_init` flag is set to indicate whether the CPU logging has been initialized.
    - If the initialization flag is not set, it calls the [`fd_log_cpu_set`](#fd_log_cpu_set) function with a NULL argument to initialize the CPU logging.
    - Finally, it returns the value of `fd_log_private_cpu`, which holds the current CPU identifier.
- **Output**: The function returns a constant string pointer to the current CPU identifier used for logging.
- **Functions called**:
    - [`fd_log_cpu_set`](#fd_log_cpu_set)


---
### fd\_log\_private\_group\_id\_set<!-- {{#callable:fd_log_private_group_id_set}} -->
Sets the private group ID for logging.
- **Inputs**:
    - `group_id`: An unsigned long integer representing the group ID to be set for logging.
- **Control Flow**:
    - The function directly assigns the provided `group_id` to the static variable `fd_log_private_group_id`.
    - There are no conditional statements or loops; the assignment is straightforward.
- **Output**: The function does not return a value; it modifies the internal state by setting the `fd_log_private_group_id`.


---
### fd\_log\_group\_id<!-- {{#callable:fd_log_group_id}} -->
The `fd_log_group_id` function retrieves the current logging group ID.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the static variable `fd_log_private_group_id`.
- **Output**: Returns the current logging group ID as an unsigned long integer.


---
### fd\_log\_group<!-- {{#callable:fd_log_group}} -->
Returns the current logging group identifier.
- **Inputs**:
    - `void`: This function does not take any input arguments.
- **Control Flow**:
    - The function directly returns the value of the static variable `fd_log_private_group`.
- **Output**: Returns a constant character pointer to the current logging group name stored in `fd_log_private_group`.


---
### fd\_log\_private\_group\_set<!-- {{#callable:fd_log_private_group_set}} -->
Sets the private logging group name.
- **Inputs**:
    - `group`: A constant character pointer representing the name of the logging group.
- **Control Flow**:
    - Checks if the input `group` is NULL or an empty string; if so, assigns it a default value of '[group]'.
    - Compares the provided `group` with the current private group name; if they are different, it updates the private group name.
- **Output**: The function does not return a value; it modifies the internal state of the logging system by updating the private group name.


---
### fd\_log\_private\_tid\_default<!-- {{#callable:fd_log_private_tid_default}} -->
Retrieves the thread ID or process ID depending on the operating system.
- **Inputs**: None
- **Control Flow**:
    - Checks if the code is being compiled on a Linux system.
    - If on Linux, it retrieves the thread ID using `syscall(SYS_gettid)`.
    - If not on Linux, it retrieves the process ID using `getpid()`.
    - Returns the thread ID or process ID if it is greater than 0, otherwise returns `ULONG_MAX`.
- **Output**: Returns the thread ID as an unsigned long integer, or `ULONG_MAX` if the retrieval fails.


---
### fd\_log\_private\_tid\_set<!-- {{#callable:fd_log_private_tid_set}} -->
Sets the private thread ID and marks it as initialized.
- **Inputs**:
    - `tid`: The thread ID to be set, represented as an unsigned long integer.
- **Control Flow**:
    - The function assigns the provided `tid` to the static variable `fd_log_private_tid`.
    - It then sets the static variable `fd_log_private_tid_init` to 1, indicating that the thread ID has been initialized.
- **Output**: This function does not return a value; it modifies the internal state of the logging system by setting the thread ID.


---
### fd\_log\_tid<!-- {{#callable:fd_log_tid}} -->
Retrieves the thread ID, initializing it if necessary.
- **Inputs**: None
- **Control Flow**:
    - Checks if the thread ID has been initialized using `fd_log_private_tid_init`.
    - If not initialized, it calls [`fd_log_private_tid_set`](#fd_log_private_tid_set) with the default thread ID obtained from `fd_log_private_tid_default()`.
    - Returns the current thread ID stored in `fd_log_private_tid`.
- **Output**: Returns the current thread ID as an unsigned long integer.
- **Functions called**:
    - [`fd_log_private_tid_set`](#fd_log_private_tid_set)
    - [`fd_log_private_tid_default`](#fd_log_private_tid_default)


---
### fd\_log\_private\_user\_id\_default<!-- {{#callable:fd_log_private_user_id_default}} -->
Returns the user ID of the calling process.
- **Inputs**: None
- **Control Flow**:
    - Calls `getuid()` to retrieve the user ID of the calling process.
    - Casts the result of `getuid()` to `ulong` and returns it.
- **Output**: Returns the user ID as an unsigned long integer.


---
### fd\_log\_private\_user\_id\_set<!-- {{#callable:fd_log_private_user_id_set}} -->
Sets the private user ID for logging.
- **Inputs**:
    - `user_id`: A `ulong` representing the user ID to be set for logging.
- **Control Flow**:
    - The function assigns the provided `user_id` to the static variable `fd_log_private_user_id`.
    - It then sets the static variable `fd_log_private_user_id_init` to 1, indicating that the user ID has been initialized.
- **Output**: This function does not return a value; it modifies the internal state of the logging system by setting the user ID.


---
### fd\_log\_user\_id<!-- {{#callable:fd_log_user_id}} -->
The `fd_log_user_id` function retrieves the current user ID, initializing it if it has not been set.
- **Inputs**: None
- **Control Flow**:
    - Checks if the static variable `fd_log_private_user_id_init` is false, indicating that the user ID has not been initialized.
    - If not initialized, it calls `fd_log_private_user_id_default()` to set `fd_log_private_user_id` to the current user ID and marks `fd_log_private_user_id_init` as initialized.
    - Returns the value of `fd_log_private_user_id`.
- **Output**: Returns the current user ID as an unsigned long integer.
- **Functions called**:
    - [`fd_log_private_user_id_default`](#fd_log_private_user_id_default)


---
### fd\_log\_user<!-- {{#callable:fd_log_user}} -->
Returns a pointer to the private user string.
- **Inputs**:
    - `void`: This function does not take any input arguments.
- **Control Flow**:
    - The function directly returns the value of the static variable `fd_log_private_user`.
- **Output**: Returns a constant character pointer to the private user string, which is expected to be set by other functions in the logging system.


---
### fd\_log\_private\_user\_set<!-- {{#callable:fd_log_private_user_set}} -->
Sets the private user identifier for logging.
- **Inputs**:
    - `user`: A constant character pointer representing the user identifier to be set.
- **Control Flow**:
    - Checks if the `user` pointer is NULL or points to an empty string; if so, it assigns a default value of '[user]'.
    - Compares the new `user` value with the current private user identifier; if they are different, it updates the private user identifier.
- **Output**: The function does not return a value; it modifies the internal state of the logging system by updating the private user identifier.


---
### fd\_log\_group\_id\_query<!-- {{#callable:fd_log_group_id_query}} -->
Queries the status of a process group identified by its group ID.
- **Inputs**:
    - `group_id`: The group ID of the process group to query, represented as an unsigned long.
- **Control Flow**:
    - Checks if the provided `group_id` is equal to the current log group's ID, returning `FD_LOG_GROUP_ID_QUERY_LIVE` if true.
    - Casts `group_id` to a `pid_t` type and checks for validity, returning `FD_LOG_GROUP_ID_QUERY_INVAL` if invalid.
    - Uses the `kill` function to send a signal to the process group identified by `group_id` to check if it is alive.
    - If the `kill` call returns 0, it indicates the process is alive, returning `FD_LOG_GROUP_ID_QUERY_LIVE`.
    - If `errno` is set to `ESRCH`, it indicates the process does not exist, returning `FD_LOG_GROUP_ID_QUERY_DEAD`.
    - If `errno` is set to `EPERM`, it indicates permission was denied, returning `FD_LOG_GROUP_ID_QUERY_PERM`.
    - If none of the above conditions are met, it returns `FD_LOG_GROUP_ID_QUERY_FAIL`.
- **Output**: Returns an integer indicating the status of the process group: live, dead, invalid, permission denied, or failure.
- **Functions called**:
    - [`fd_log_group_id`](#fd_log_group_id)


---
### fd\_log\_wallclock<!-- {{#callable:fd_log_wallclock}} -->
The `fd_log_wallclock` function retrieves the current wall clock time in nanoseconds.
- **Inputs**: None
- **Control Flow**:
    - A `struct timespec` variable is declared to hold the time.
    - The `clock_gettime` function is called with `CLOCK_REALTIME` to fill the `timespec` structure with the current time.
    - The total time in nanoseconds is calculated by converting seconds to nanoseconds and adding the nanoseconds part.
- **Output**: The function returns the current wall clock time as a `long` value representing the number of nanoseconds since the epoch.


---
### fd\_log\_wallclock\_cstr<!-- {{#callable:fd_log_wallclock_cstr}} -->
`fd_log_wallclock_cstr` formats a given timestamp into a human-readable string representation of the wall clock time.
- **Inputs**:
    - `now`: A `long` integer representing the current time in nanoseconds since the epoch.
    - `buf`: A pointer to a character buffer where the formatted time string will be stored.
- **Control Flow**:
    - The function first checks if the provided `now` timestamp is close to a reference timestamp; if so, it reuses previously calculated date and time components.
    - If `now` is not close to the reference, it calculates the date and time components from `now` using `localtime_r` to convert the timestamp into a `struct tm`.
    - If `localtime_r` fails, it falls back to formatting the timestamp as a raw UNIX time string.
    - The function then appends the formatted date and time components to the provided buffer `buf` using various helper functions.
- **Output**: Returns a pointer to the `buf` containing the formatted wall clock time string.


---
### fd\_log\_sleep<!-- {{#callable:fd_log_sleep}} -->
`fd_log_sleep` pauses execution for a specified duration in nanoseconds.
- **Inputs**:
    - `dt`: A long integer representing the duration to sleep in nanoseconds.
- **Control Flow**:
    - If `dt` is less than 1, the function yields the processor and returns 0.
    - The function calculates `ns_dt`, which is the minimum of `dt` and a maximum limit (2^31 * 1e9).
    - It then reduces `dt` by `ns_dt`.
    - A `timespec` structure is populated with seconds and nanoseconds derived from `ns_dt`.
    - The function attempts to sleep for the specified duration using `nanosleep`.
    - If `nanosleep` is interrupted by a signal (indicated by `errno` being `EINTR`), it adds the remaining time to `dt`.
- **Output**: Returns the remaining duration in nanoseconds after the sleep, which may be less than the original `dt` if interrupted.


---
### fd\_log\_wait\_until<!-- {{#callable:fd_log_wait_until}} -->
The `fd_log_wait_until` function blocks execution until the specified time is reached.
- **Inputs**:
    - `then`: A long integer representing the target time in nanoseconds since the epoch.
- **Control Flow**:
    - The function enters an infinite loop, continuously checking the current wall clock time.
    - It calculates the remaining time by subtracting the current time from the target time.
    - If the remaining time is less than or equal to zero, the loop breaks, indicating the wait is over.
    - If the remaining time exceeds one second, it calls [`fd_log_sleep`](#fd_log_sleep) to sleep for a duration slightly less than the remaining time.
    - If the remaining time is greater than 0.1 seconds, it yields the processor to allow other threads to run.
    - If the remaining time is greater than 1 microsecond, it performs a spin pause to avoid busy waiting.
    - For very short waits, it continues to spin on the wall clock until the target time is reached.
- **Output**: Returns the current time in nanoseconds since the epoch when the wait is over.
- **Functions called**:
    - [`fd_log_wallclock`](#fd_log_wallclock)
    - [`fd_log_sleep`](#fd_log_sleep)


---
### fd\_log\_flush<!-- {{#callable:fd_log_flush}} -->
Flushes the log file to ensure all buffered data is written to disk.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the current log file descriptor from `fd_log_private_fileno` using `FD_VOLATILE_CONST`.
    - Check if the log file descriptor is valid (not equal to -1) using `FD_LIKELY`.
    - If valid, call `fsync` on the log file descriptor to flush the file's contents to disk.
- **Output**: The function does not return a value; it performs a side effect of flushing the log file.


---
### fd\_log\_colorize<!-- {{#callable:fd_log_colorize}} -->
The `fd_log_colorize` function retrieves the current colorization mode for logging.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of `fd_log_private_colorize` using `FD_VOLATILE_CONST` to ensure the value is read from memory.
    - No conditional logic or loops are present in the function.
- **Output**: The function returns an integer representing the current colorization mode for logging, which indicates whether colored output is enabled or disabled.


---
### fd\_log\_level\_logfile<!-- {{#callable:fd_log_level_logfile}} -->
Retrieves the current logging level for the log file.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of `fd_log_private_level_logfile`.
    - It uses the `FD_VOLATILE_CONST` macro to ensure that the value is read in a thread-safe manner.
- **Output**: Returns an integer representing the logging level for the log file.


---
### fd\_log\_level\_stderr<!-- {{#callable:fd_log_level_stderr}} -->
Returns the current logging level for standard error output.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of `fd_log_private_level_stderr`.
    - The value is wrapped with `FD_VOLATILE_CONST` to ensure it is read as a volatile constant.
- **Output**: An integer representing the logging level for standard error output.


---
### fd\_log\_level\_flush<!-- {{#callable:fd_log_level_flush}} -->
The `fd_log_level_flush` function retrieves the current logging flush level.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of `fd_log_private_level_flush` using the `FD_VOLATILE_CONST` macro.
- **Output**: The function returns an integer representing the current flush level for logging.


---
### fd\_log\_level\_core<!-- {{#callable:fd_log_level_core}} -->
The `fd_log_level_core` function retrieves the current logging level for core logs.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of `fd_log_private_level_core`.
    - It uses the `FD_VOLATILE_CONST` macro to ensure that the value is read in a thread-safe manner.
- **Output**: The output is an integer representing the current logging level for core logs.


---
### fd\_log\_colorize\_set<!-- {{#callable:fd_log_colorize_set}} -->
Sets the colorization mode for logging.
- **Inputs**:
    - `mode`: An integer representing the desired colorization mode for logging.
- **Control Flow**:
    - The function assigns the input `mode` to the volatile variable `fd_log_private_colorize`.
    - This operation ensures that the colorization setting is updated in a thread-safe manner.
- **Output**: The function does not return a value; it modifies the internal state related to logging colorization.


---
### fd\_log\_level\_logfile\_set<!-- {{#callable:fd_log_level_logfile_set}} -->
Sets the logging level for the log file.
- **Inputs**:
    - `level`: An integer representing the desired logging level to be set for the log file.
- **Control Flow**:
    - The function uses `FD_VOLATILE` to ensure that the assignment to `fd_log_private_level_logfile` is not optimized away by the compiler.
    - The input `level` is directly assigned to `fd_log_private_level_logfile`, which is a static variable that holds the current log level for the log file.
- **Output**: This function does not return a value; it modifies the internal state by setting the log level for the log file.


---
### fd\_log\_level\_stderr\_set<!-- {{#callable:fd_log_level_stderr_set}} -->
Sets the logging level for standard error output.
- **Inputs**:
    - `level`: An integer representing the desired logging level for standard error output.
- **Control Flow**:
    - The function uses the `FD_VOLATILE` macro to set the value of `fd_log_private_level_stderr` to the provided `level`.
    - This ensures that the assignment is treated as a volatile operation, which may be necessary for multi-threaded environments.
- **Output**: The function does not return a value; it modifies the internal logging level for standard error output.


---
### fd\_log\_level\_flush\_set<!-- {{#callable:fd_log_level_flush_set}} -->
Sets the logging level for flushing log messages.
- **Inputs**:
    - `level`: An integer representing the log level to set for flushing log messages.
- **Control Flow**:
    - The function directly assigns the provided `level` to the volatile variable `fd_log_private_level_flush`.
    - This assignment ensures that the log level for flushing is updated atomically, reflecting the new level immediately.
- **Output**: The function does not return a value; it modifies the internal state of the logging system by setting the flush log level.


---
### fd\_log\_level\_core\_set<!-- {{#callable:fd_log_level_core_set}} -->
Sets the core logging level for the application.
- **Inputs**:
    - `level`: An integer representing the desired logging level to be set for core logging.
- **Control Flow**:
    - The function directly assigns the input `level` to the volatile variable `fd_log_private_level_core`.
    - This assignment is done using the `FD_VOLATILE` macro to ensure that the compiler does not optimize away the assignment, which is important for multi-threaded environments.
- **Output**: The function does not return a value; it modifies the internal state of the logging system by setting the core log level.


---
### fd\_log\_private\_logfile\_fd<!-- {{#callable:fd_log_private_logfile_fd}} -->
The `fd_log_private_logfile_fd` function retrieves the file descriptor for the private log file.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of `fd_log_private_fileno`, which is expected to be a file descriptor.
    - The `FD_VOLATILE_CONST` macro is used to ensure that the value is read in a way that prevents compiler optimizations that could cache the value.
- **Output**: The function returns an integer representing the file descriptor for the private log file, or -1 if the log file is not open.


---
### fd\_log\_enable\_unclean\_exit<!-- {{#callable:fd_log_enable_unclean_exit}} -->
Enables logging for uncaught exits by setting a flag.
- **Inputs**: None
- **Control Flow**:
    - The function directly sets the global variable `fd_log_private_unclean_exit` to 1.
- **Output**: The function does not return any value; it modifies a global state to indicate that uncaught exits should be logged.


---
### fd\_log\_private\_fprintf\_0<!-- {{#callable:fd_log_private_fprintf_0}} -->
`fd_log_private_fprintf_0` writes formatted log messages to a specified file descriptor while managing concurrency.
- **Inputs**:
    - `fd`: An integer representing the file descriptor to which the log message will be written.
    - `fmt`: A format string that specifies how to format the log message, followed by a variable number of arguments.
- **Control Flow**:
    - Initializes a buffer `msg` to hold the formatted log message.
    - Uses `va_list` to handle a variable number of arguments for formatting the message.
    - Calls `vsnprintf` to format the message into `msg`, ensuring it does not exceed the buffer size.
    - Acquires a shared lock to ensure that concurrent writes to the same file descriptor are managed correctly.
    - Calls `fd_io_write` to write the formatted message to the specified file descriptor.
    - Releases the shared lock after the write operation.
- **Output**: The function does not return a value; it writes the formatted log message directly to the specified file descriptor.


---
### fd\_log\_private\_fprintf\_nolock\_0<!-- {{#callable:fd_log_private_fprintf_nolock_0}} -->
Logs formatted messages to a specified file descriptor without acquiring a lock.
- **Inputs**:
    - `fd`: An integer representing the file descriptor to which the log message will be written.
    - `fmt`: A format string that specifies how to format the log message, followed by a variable number of arguments.
- **Control Flow**:
    - Initializes a character array `msg` to hold the formatted log message.
    - Uses `va_list` to handle a variable number of arguments for formatting the message.
    - Calls `vsnprintf` to format the message into `msg`, ensuring it does not exceed the buffer size.
    - Checks the length of the formatted message and adjusts it if necessary to fit within the buffer.
    - Calls `fd_io_write` to write the formatted message to the specified file descriptor, ignoring any errors.
- **Output**: The function does not return a value; it writes the formatted log message directly to the specified file descriptor.


---
### fd\_log\_private\_0<!-- {{#callable:fd_log_private_0}} -->
Formats a log message using a variable argument list and stores it in a static buffer.
- **Inputs**:
    - `fmt`: A format string that specifies how to format the subsequent arguments.
- **Control Flow**:
    - Initializes a variable argument list using `va_start` with the provided format string.
    - Calls `vsnprintf` to format the log message into a static buffer, ensuring it does not exceed the buffer size.
    - Checks if the formatted length is negative or exceeds the buffer size, adjusting it accordingly.
    - Null-terminates the formatted string in the buffer.
    - Cleans up the variable argument list with `va_end`.
    - Returns a pointer to the static buffer containing the formatted log message.
- **Output**: Returns a pointer to the static buffer containing the formatted log message.


---
### fd\_log\_private\_hexdump\_msg<!-- {{#callable:fd_log_private_hexdump_msg}} -->
Logs a hexdump of a memory region with an optional description.
- **Inputs**:
    - `descr`: A string description of the memory blob being dumped, or NULL for a default message.
    - `mem`: A pointer to the memory region to be hexdumped.
    - `sz`: The size in bytes of the memory region to be dumped.
- **Control Flow**:
    - Checks if the description is NULL or exceeds the maximum length, and formats the hexdump header accordingly.
    - If the size is zero, it returns immediately after logging the header.
    - If the memory pointer is NULL, it logs a message indicating unreadable memory and returns.
    - Iterates through the memory region, formatting each byte as hexadecimal and building an ASCII representation.
    - Handles line breaks after a specified number of bytes and logs any omitted bytes if the size exceeds the maximum allowed.
- **Output**: Returns a pointer to the log message buffer containing the formatted hexdump.


---
### fd\_log\_private\_1<!-- {{#callable:fd_log_private_1}} -->
Logs a message with a specified severity level, deduplicating consecutive identical messages.
- **Inputs**:
    - `level`: An integer representing the severity level of the log message.
    - `now`: A long integer representing the current time in nanoseconds.
    - `file`: A string representing the name of the source file where the log is generated.
    - `line`: An integer representing the line number in the source file.
    - `func`: A string representing the name of the function where the log is generated.
    - `msg`: A string containing the log message to be recorded.
- **Control Flow**:
    - The function first checks if the log level is below the configured threshold for logging to the file; if so, it returns immediately.
    - It initializes thread-specific variables for thread ID, CPU, and other logging context information.
    - It checks if logging to a file or standard error is enabled based on the log level.
    - If deduplication is enabled, it computes a hash of the log message and checks if it is a duplicate of the previous message within a specified time interval.
    - If the message is a duplicate, it increments a counter and may log a message indicating the end of duplicate messages.
    - If the message is not a duplicate, it logs the message to the appropriate output (file or stderr) with a timestamp and context information.
    - Finally, if the log level requires flushing, it calls the flush function to ensure all log data is written out.
- **Output**: The function does not return a value but writes the log message to the appropriate output (log file or stderr) based on the severity level and deduplication logic.
- **Functions called**:
    - [`fd_log_level_logfile`](#fd_log_level_logfile)
    - [`fd_log_thread`](#fd_log_thread)
    - [`fd_log_cpu`](#fd_log_cpu)
    - [`fd_log_tid`](#fd_log_tid)
    - [`fd_log_level_stderr`](#fd_log_level_stderr)
    - [`fd_log_wallclock_cstr`](#fd_log_wallclock_cstr)
    - [`fd_log_private_fprintf_0`](#fd_log_private_fprintf_0)
    - [`fd_log_group_id`](#fd_log_group_id)
    - [`fd_log_user`](#fd_log_user)
    - [`fd_log_host`](#fd_log_host)
    - [`fd_log_app`](#fd_log_app)
    - [`fd_log_group`](#fd_log_group)
    - [`fd_log_level_flush`](#fd_log_level_flush)
    - [`fd_log_flush`](#fd_log_flush)


---
### fd\_log\_private\_2<!-- {{#callable:fd_log_private_2}} -->
Logs a message at a specified log level and handles termination based on the log level.
- **Inputs**:
    - `level`: An integer representing the log level of the message.
    - `now`: A long integer representing the current time, typically in nanoseconds.
    - `file`: A string representing the name of the source file where the log is generated.
    - `line`: An integer representing the line number in the source file.
    - `func`: A string representing the name of the function where the log is generated.
    - `msg`: A string containing the log message to be recorded.
- **Control Flow**:
    - Calls [`fd_log_private_1`](#fd_log_private_1) to log the message with the provided details.
    - Checks if the log level is less than the core log level.
    - If the log level is less than the core level, it checks if unclean exit is enabled on Linux and calls `syscall` to exit the group if true.
    - If not on Linux or unclean exit is not enabled, it calls `exit(1)` to terminate the program.
    - If the log level is not less than the core level, it calls `abort()` to terminate the program immediately.
- **Output**: The function does not return a value; instead, it logs the message and may terminate the program based on the log level.
- **Functions called**:
    - [`fd_log_private_1`](#fd_log_private_1)
    - [`fd_log_level_core`](#fd_log_level_core)


---
### fd\_log\_private\_raw\_2<!-- {{#callable:fd_log_private_raw_2}} -->
Logs a message with file, line, function context and terminates the program.
- **Inputs**:
    - `file`: A string representing the source file name where the log is generated.
    - `line`: An integer representing the line number in the source file.
    - `func`: A string representing the name of the function where the log is generated.
    - `msg`: A string containing the message to be logged.
- **Control Flow**:
    - Calls [`fd_log_private_fprintf_nolock_0`](#fd_log_private_fprintf_nolock_0) to log the message to standard error without acquiring a lock.
    - If the platform is Linux, it invokes `syscall` with `SYS_exit_group` to terminate the process.
    - If not on Linux, it calls `exit(1)` to terminate the program.
    - Finally, it calls `abort()` to ensure the program is terminated.
- **Output**: The function does not return a value; it terminates the program after logging the message.
- **Functions called**:
    - [`fd_log_private_fprintf_nolock_0`](#fd_log_private_fprintf_nolock_0)


---
### fd\_log\_private\_cleanup<!-- {{#callable:fd_log_private_cleanup}} -->
Cleans up logging resources and ensures proper logging state before program termination.
- **Inputs**: None
- **Control Flow**:
    - The function is protected by a `FD_ONCE_BEGIN` block to ensure it executes only once per program run.
    - It retrieves the current log file descriptor from `fd_log_private_fileno`.
    - If the log file descriptor is -1, it logs 'No log' to `STDERR_FILENO`.
    - If the log path is set to '-', it logs 'Log to stdout' to `STDERR_FILENO`.
    - If there are multiple threads using the log, it waits briefly to allow them to finish logging before closing the log file.
    - It then sets the log file descriptor to -1 to indicate that logging is disabled.
    - Finally, it flushes the log file and logs the final log path to `STDERR_FILENO`.
- **Output**: The function does not return a value but performs logging operations and resource cleanup.
- **Functions called**:
    - [`fd_log_private_fprintf_0`](#fd_log_private_fprintf_0)


---
### fd\_log\_private\_sig\_abort<!-- {{#callable:fd_log_private_sig_abort}} -->
The `fd_log_private_sig_abort` function handles the logging of a signal received by the process, including capturing a backtrace if available.
- **Inputs**:
    - `sig`: An integer representing the signal number that was caught.
    - `info`: A pointer to a `siginfo_t` structure containing information about the signal.
    - `context`: A pointer to a context structure that provides additional information about the signal.
- **Control Flow**:
    - The function begins by ignoring the `info` and `context` parameters.
    - It checks if backtrace functionality is enabled via the `FD_HAS_BACKTRACE` macro.
    - If backtrace is enabled, it captures the backtrace into an array and logs it to both the specified log file and standard error.
    - If backtrace is not enabled, it simply logs the caught signal to the log file and standard error without a backtrace.
    - After logging, it calls [`fd_log_private_cleanup`](#fd_log_private_cleanup) to perform any necessary cleanup operations.
    - The function then sleeps for one second to allow any logging streams to drain before raising the caught signal again.
- **Output**: The function does not return a value; it performs logging and cleanup operations based on the caught signal.
- **Functions called**:
    - [`fd_log_private_fprintf_0`](#fd_log_private_fprintf_0)
    - [`fd_log_private_cleanup`](#fd_log_private_cleanup)


---
### fd\_log\_private\_sig\_trap<!-- {{#callable:fd_log_private_sig_trap}} -->
Sets a signal handler for a specified signal to log an abort.
- **Inputs**:
    - `sig`: An integer representing the signal number to be handled.
- **Control Flow**:
    - Creates a `sigaction` structure to define the new signal handler.
    - Sets the `sa_sigaction` field to point to the `fd_log_private_sig_abort` function.
    - Initializes the signal mask to be empty using `sigemptyset`.
    - Sets the flags for the signal action to include `SA_SIGINFO` and `SA_RESETHAND`.
    - Calls `sigaction` to register the new signal handler for the specified signal, logging an error if it fails.
- **Output**: No return value; the function modifies the signal handling behavior for the specified signal.


---
### fd\_log\_private\_open\_path<!-- {{#callable:fd_log_private_open_path}} -->
The `fd_log_private_open_path` function opens a log file at a specified path or generates a default log path if none is provided.
- **Inputs**:
    - `cmdline`: An integer flag indicating if the function is called from the command line.
    - `log_path`: A string representing the path where the log file should be created or opened.
- **Control Flow**:
    - Calculate the size of the `log_path` string, defaulting to a generated path if it is not provided.
    - If the `log_path` is empty, generate a default log path using the current wall clock time and application version information.
    - If the `log_path` is specified but empty, set the log path to an empty string to disable logging.
    - If the `log_path` exceeds the maximum allowed size, log an error and exit.
    - Open the log file with appropriate permissions and handle errors if the file cannot be opened.
    - Return the file descriptor of the opened log file or -1 if logging is disabled.
- **Output**: Returns the file descriptor of the opened log file, or -1 if logging is disabled.
- **Functions called**:
    - [`fd_log_wallclock_cstr`](#fd_log_wallclock_cstr)
    - [`fd_log_wallclock`](#fd_log_wallclock)
    - [`fd_log_group_id`](#fd_log_group_id)
    - [`fd_log_user`](#fd_log_user)
    - [`fd_log_host`](#fd_log_host)
    - [`fd_log_private_fprintf_0`](#fd_log_private_fprintf_0)


---
### fd\_log\_private\_boot<!-- {{#callable:fd_log_private_boot}} -->
Initializes logging parameters and configurations for the application.
- **Inputs**:
    - `pargc`: Pointer to an integer representing the count of command line arguments.
    - `pargv`: Pointer to an array of strings representing the command line arguments.
- **Control Flow**:
    - Sets up a shared lock for logging.
    - Initializes application logical IDs by parsing command line arguments.
    - Sets application physical IDs, including host, CPU, and user IDs, using command line arguments or system calls.
    - Configures logging options such as deduplication, colorization, and log levels based on command line arguments.
    - Hooks up signal handlers for various signals to manage logging during abnormal terminations.
    - Opens the log file and sets the file descriptor for logging.
    - Logs the boot information and configuration settings.
- **Output**: No return value; the function configures the logging system and prepares it for use.
- **Functions called**:
    - [`fd_log_private_app_id_set`](#fd_log_private_app_id_set)
    - [`fd_log_private_app_set`](#fd_log_private_app_set)
    - [`fd_log_private_thread_id_next`](#fd_log_private_thread_id_next)
    - [`fd_log_private_thread_id_set`](#fd_log_private_thread_id_set)
    - [`fd_log_thread_set`](#fd_log_thread_set)
    - [`fd_log_private_host_id_set`](#fd_log_private_host_id_set)
    - [`fd_log_private_host_set`](#fd_log_private_host_set)
    - [`fd_log_private_cpu_id_set`](#fd_log_private_cpu_id_set)
    - [`fd_log_private_cpu_id_default`](#fd_log_private_cpu_id_default)
    - [`fd_log_cpu_set`](#fd_log_cpu_set)
    - [`fd_log_private_group_id_set`](#fd_log_private_group_id_set)
    - [`fd_log_private_group_set`](#fd_log_private_group_set)
    - [`fd_log_private_tid_set`](#fd_log_private_tid_set)
    - [`fd_log_private_tid_default`](#fd_log_private_tid_default)
    - [`fd_log_private_user_id_set`](#fd_log_private_user_id_set)
    - [`fd_log_private_user_id_default`](#fd_log_private_user_id_default)
    - [`fd_log_private_user_set`](#fd_log_private_user_set)
    - [`fd_log_colorize_set`](#fd_log_colorize_set)
    - [`fd_log_level_logfile_set`](#fd_log_level_logfile_set)
    - [`fd_log_level_stderr_set`](#fd_log_level_stderr_set)
    - [`fd_log_level_flush_set`](#fd_log_level_flush_set)
    - [`fd_log_level_core_set`](#fd_log_level_core_set)
    - [`fd_log_private_fprintf_0`](#fd_log_private_fprintf_0)
    - [`fd_log_private_sig_trap`](#fd_log_private_sig_trap)
    - [`fd_log_private_open_path`](#fd_log_private_open_path)
    - [`fd_log_colorize`](#fd_log_colorize)
    - [`fd_log_level_logfile`](#fd_log_level_logfile)
    - [`fd_log_level_stderr`](#fd_log_level_stderr)
    - [`fd_log_level_flush`](#fd_log_level_flush)
    - [`fd_log_level_core`](#fd_log_level_core)
    - [`fd_log_app_id`](#fd_log_app_id)
    - [`fd_log_app`](#fd_log_app)
    - [`fd_log_thread_id`](#fd_log_thread_id)
    - [`fd_log_thread`](#fd_log_thread)
    - [`fd_log_host_id`](#fd_log_host_id)
    - [`fd_log_host`](#fd_log_host)
    - [`fd_log_cpu_id`](#fd_log_cpu_id)
    - [`fd_log_cpu`](#fd_log_cpu)
    - [`fd_log_group_id`](#fd_log_group_id)
    - [`fd_log_group`](#fd_log_group)
    - [`fd_log_tid`](#fd_log_tid)
    - [`fd_log_user_id`](#fd_log_user_id)
    - [`fd_log_user`](#fd_log_user)


---
### fd\_log\_private\_boot\_custom<!-- {{#callable:fd_log_private_boot_custom}} -->
The `fd_log_private_boot_custom` function initializes logging parameters for an application during its boot process.
- **Inputs**:
    - `lock`: A pointer to an integer used for shared locking during logging.
    - `app_id`: An unsigned long representing the application identifier.
    - `app`: A constant character pointer to the application name.
    - `thread_id`: An unsigned long representing the thread identifier.
    - `thread`: A constant character pointer to the thread name.
    - `host_id`: An unsigned long representing the host identifier.
    - `host`: A constant character pointer to the host name.
    - `cpu_id`: An unsigned long representing the CPU identifier.
    - `cpu`: A constant character pointer to the CPU name.
    - `group_id`: An unsigned long representing the group identifier.
    - `group`: A constant character pointer to the group name.
    - `tid`: An unsigned long representing the thread ID.
    - `user_id`: An unsigned long representing the user identifier.
    - `user`: A constant character pointer to the user name.
    - `dedup`: An integer indicating whether to enable log message deduplication.
    - `colorize`: An integer indicating whether to enable colored log output.
    - `level_logfile`: An integer representing the logging level for the log file.
    - `level_stderr`: An integer representing the logging level for standard error output.
    - `level_flush`: An integer representing the logging level for flushing logs.
    - `level_core`: An integer representing the logging level for core dumps.
    - `log_fd`: An integer representing the file descriptor for the log file.
    - `log_path`: A constant character pointer to the path where logs should be written.
- **Control Flow**:
    - The function begins by setting the shared lock for logging using the provided `lock` pointer.
    - It then sets various application, thread, host, CPU, group, and user identifiers using their respective setter functions.
    - The deduplication and colorization settings are configured based on the provided parameters.
    - Logging levels for logfile, stderr, flush, and core are set according to the input parameters.
    - If a valid log file descriptor (`log_fd`) is provided, it is used directly; otherwise, a new log file is opened using the specified `log_path`.
    - Finally, the function logs the boot information and configuration settings to the log.
- **Output**: The function does not return a value but configures the logging system and outputs boot information to the log.
- **Functions called**:
    - [`fd_log_private_app_id_set`](#fd_log_private_app_id_set)
    - [`fd_log_private_app_set`](#fd_log_private_app_set)
    - [`fd_log_private_thread_id_set`](#fd_log_private_thread_id_set)
    - [`fd_log_thread_set`](#fd_log_thread_set)
    - [`fd_log_private_host_id_set`](#fd_log_private_host_id_set)
    - [`fd_log_private_host_set`](#fd_log_private_host_set)
    - [`fd_log_private_cpu_id_set`](#fd_log_private_cpu_id_set)
    - [`fd_log_cpu_set`](#fd_log_cpu_set)
    - [`fd_log_private_group_id_set`](#fd_log_private_group_id_set)
    - [`fd_log_private_group_set`](#fd_log_private_group_set)
    - [`fd_log_private_tid_set`](#fd_log_private_tid_set)
    - [`fd_log_private_user_id_set`](#fd_log_private_user_id_set)
    - [`fd_log_private_user_set`](#fd_log_private_user_set)
    - [`fd_log_colorize_set`](#fd_log_colorize_set)
    - [`fd_log_level_logfile_set`](#fd_log_level_logfile_set)
    - [`fd_log_level_stderr_set`](#fd_log_level_stderr_set)
    - [`fd_log_level_flush_set`](#fd_log_level_flush_set)
    - [`fd_log_level_core_set`](#fd_log_level_core_set)
    - [`fd_log_private_open_path`](#fd_log_private_open_path)
    - [`fd_log_colorize`](#fd_log_colorize)
    - [`fd_log_level_logfile`](#fd_log_level_logfile)
    - [`fd_log_level_stderr`](#fd_log_level_stderr)
    - [`fd_log_level_flush`](#fd_log_level_flush)
    - [`fd_log_level_core`](#fd_log_level_core)
    - [`fd_log_app_id`](#fd_log_app_id)
    - [`fd_log_app`](#fd_log_app)
    - [`fd_log_thread_id`](#fd_log_thread_id)
    - [`fd_log_thread`](#fd_log_thread)
    - [`fd_log_host_id`](#fd_log_host_id)
    - [`fd_log_host`](#fd_log_host)
    - [`fd_log_cpu_id`](#fd_log_cpu_id)
    - [`fd_log_cpu`](#fd_log_cpu)
    - [`fd_log_group_id`](#fd_log_group_id)
    - [`fd_log_group`](#fd_log_group)
    - [`fd_log_tid`](#fd_log_tid)
    - [`fd_log_user_id`](#fd_log_user_id)
    - [`fd_log_user`](#fd_log_user)


---
### fd\_log\_private\_halt<!-- {{#callable:fd_log_private_halt}} -->
The `fd_log_private_halt` function halts the logging system and cleans up all associated resources.
- **Inputs**: None
- **Control Flow**:
    - Logs an informational message indicating that the logging system is halting.
    - Calls [`fd_log_private_cleanup`](#fd_log_private_cleanup) to perform necessary cleanup operations.
    - Resets various private logging state variables to their initial values.
    - Checks if the shared lock is not the local lock and attempts to unmap it, handling any errors that may occur.
- **Output**: The function does not return a value; it modifies global state to disable logging and free resources.
- **Functions called**:
    - [`fd_log_private_cleanup`](#fd_log_private_cleanup)
    - [`fd_log_private_fprintf_0`](#fd_log_private_fprintf_0)


---
### fd\_log\_private\_main\_stack\_sz<!-- {{#callable:fd_log_private_main_stack_sz}} -->
The `fd_log_private_main_stack_sz` function retrieves the current stack size limit for the main thread.
- **Inputs**: None
- **Control Flow**:
    - The function starts by declaring a `struct rlimit` to hold the stack limits.
    - It calls `getrlimit` with `RLIMIT_STACK` to retrieve the current and maximum stack size.
    - If `getrlimit` fails, it logs a warning and returns 0.
    - It checks if the current stack size exceeds the maximum, is infinite, or has unexpected values, logging a warning if any of these conditions are true.
    - Finally, it returns the current stack size.
- **Output**: The function returns the current stack size limit as an unsigned long integer, or 0 if an error occurs.


---
### fd\_log\_private\_stack\_discover<!-- {{#callable:fd_log_private_stack_discover}} -->
Discovers the memory region of the caller's stack based on the expected stack size.
- **Inputs**:
    - `stack_sz`: The expected size of the stack in bytes.
    - `_stack0`: A pointer to store the starting address of the discovered stack region.
    - `_stack1`: A pointer to store the ending address of the discovered stack region.
- **Control Flow**:
    - If `stack_sz` is zero, both `_stack0` and `_stack1` are set to zero and the function returns.
    - A local variable is created to ensure the stack address can be determined.
    - The function attempts to open the `/proc/self/maps` file to read the memory mappings of the current process.
    - If the file cannot be opened, a warning is logged, and both `_stack0` and `_stack1` are set to zero.
    - The function reads the memory mappings line by line, looking for the range that contains the stack address.
    - If a matching memory region is found, it checks if the size matches the expected `stack_sz`.
    - If the size does not match, it checks if the current thread is the main thread and adjusts the stack addresses accordingly.
    - If no matching region is found, a warning is logged indicating the failure to find the stack size.
- **Output**: The function sets `_stack0` and `_stack1` to the discovered stack region's start and end addresses, respectively.
- **Functions called**:
    - [`fd_log_group_id`](#fd_log_group_id)
    - [`fd_log_tid`](#fd_log_tid)


