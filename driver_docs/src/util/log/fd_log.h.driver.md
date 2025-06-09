# Purpose
The provided C header file, `fd_log.h`, is part of a logging utility designed to facilitate detailed logging for applications. It defines a comprehensive logging system that supports multiple log levels, such as DEBUG, INFO, NOTICE, WARNING, ERR, CRIT, ALERT, and EMERG, which mirror the Linux syslog levels. The system is capable of producing two types of log streams: an ephemeral log stream (typically directed to stderr) and a permanent log stream (written to a log file). The logging functions are designed to handle concurrent log messages from different threads quasi-atomically, ensuring that log entries remain coherent and are not interleaved.

The file provides a variety of macros and functions for logging messages and hexdumps at different severity levels, as well as for managing application and thread identifiers. It includes functionality to retrieve and set logical and physical identifiers for applications, threads, hosts, CPUs, and user groups, which are used to enrich log messages with contextual information. Additionally, the file offers utilities for time management, such as reading the wall clock, sleeping, and waiting until a specific time. The logging system is highly configurable, allowing runtime adjustments to log levels and colorization settings. The header also includes internal functions for managing the logging system's state and behavior, although these are intended for use within the logging system itself rather than by external code.
# Imports and Dependencies

---
- `../env/fd_env.h`
- `../io/fd_io.h`


# Global Variables

---
### fd\_log\_app
- **Type**: `function pointer`
- **Description**: The `fd_log_app` is a function that returns a constant pointer to a constant character string. This string describes the application to which the caller belongs. The function is designed to be efficient after the first call, and the lifetime of the returned string is infinite from the caller's perspective.
- **Use**: This function is used to retrieve a descriptive string of the application context for logging purposes.


---
### fd\_log\_thread
- **Type**: `function`
- **Description**: The `fd_log_thread` function returns a constant character pointer to a string that describes the current thread. This string is intended to provide a human-readable identifier for the thread, which can be used in logging and debugging. The description is determined at the thread's startup and can be explicitly set by the caller.
- **Use**: This function is used to obtain a descriptive string for the current thread, which can be used in log messages to identify the thread.


---
### fd\_log\_host
- **Type**: ``char const *``
- **Description**: The `fd_log_host` function returns a constant pointer to a C-style string (cstr) that describes the host on which the caller is running. This string is typically the hostname or a user-provided identifier at startup. The function is designed to be efficient after the first call, and the lifetime of the returned string is considered infinite from the caller's perspective.
- **Use**: This variable is used to obtain a descriptive string of the host for logging purposes, ensuring that log messages can include host-specific information.


---
### fd\_log\_cpu
- **Type**: `function`
- **Description**: `fd_log_cpu` is a function that returns a constant character pointer to a string describing the CPU on which the caller is running. This description is determined when the function is first called by a thread or during the boot process if the caller is the one that booted the system. The returned string is intended to provide a target-specific default description of the CPU.
- **Use**: This function is used to obtain a descriptive string of the CPU for logging or informational purposes, ensuring that the description is consistent and efficiently retrievable after the first call.


---
### fd\_log\_group
- **Type**: `function pointer`
- **Description**: The `fd_log_group` is a function that returns a constant pointer to a character string (const char*). This string describes the thread group to which the caller belongs, and it is intended to be a non-null pointer with a lifetime that is infinite from the caller's perspective.
- **Use**: This function is used to retrieve a description of the thread group for logging purposes, ensuring that all threads in the group have a consistent identifier.


---
### fd\_log\_user
- **Type**: `function pointer`
- **Description**: The `fd_log_user` function returns a constant pointer to a constant character string that describes the user who created the thread group to which the caller belongs. This string is typically the login name of the user who started the process, and its lifetime is infinite from the caller's perspective.
- **Use**: This function is used to retrieve a descriptive string of the user associated with the current thread group for logging purposes.


---
### fd\_log\_build\_info
- **Type**: ``char const fd_log_build_info[]``
- **Description**: The `fd_log_build_info` is a global constant character array that contains a C-style string with information about the environment in which the calling code was built. This string is aligned to a 1-byte boundary and is intended to provide build information such as the last time the build info file was generated. If no build information is available, it defaults to an empty string.
- **Use**: This variable is used to store and provide access to build environment information for the application.


---
### fd\_log\_build\_info\_sz
- **Type**: `ulong`
- **Description**: `fd_log_build_info_sz` is a global constant variable of type `ulong` that represents the size of the build information string, `fd_log_build_info`, including the null terminator. This size is calculated as the length of the string plus one.
- **Use**: It is used to determine the total size of the build information string for memory allocation or processing purposes.


---
### fd\_log\_wallclock\_cstr
- **Type**: `function`
- **Description**: The `fd_log_wallclock_cstr` function is designed to convert a wallclock time, represented as a long integer, into a human-readable string format. It formats the time as 'YYYY-MM-DD hh:mm:ss.nnnnnnnnn GMT+TZ' or 'ssssssssss.nnnnnnnnn s UNIX' if conversion is not practical. The function requires a buffer of at least 37 bytes to store the resulting string.
- **Use**: This function is used to format and return a string representation of a given wallclock time for logging purposes.


---
### fd\_log\_private\_0
- **Type**: `function pointer`
- **Description**: `fd_log_private_0` is a function pointer that points to a function taking a format string and a variable number of arguments, similar to `printf`. It is used to format log messages with type checking of the format string at compile time.
- **Use**: This function is used internally to format log messages before they are processed by other logging functions.


---
### fd\_log\_private\_hexdump\_msg
- **Type**: `function pointer`
- **Description**: `fd_log_private_hexdump_msg` is a function pointer that takes a tag, a memory region, and its size as arguments, and returns a constant character pointer. It is used to format and return a string representation of a memory region in a hexdump format for logging purposes.
- **Use**: This function is used internally to generate a hexdump message for logging memory regions at various log levels.


# Function Declarations (Public API)

---
### fd\_log\_app\_id<!-- {{#callable_declaration:fd_log_app_id}} -->
Returns the application ID.
- **Description**: This function retrieves the unique application ID associated with the current application context. It is important to call this function after the logging system has been initialized, as it relies on the internal state of the logging system. The application ID is intended to uniquely identify all concurrently running applications within the same enterprise. The first call to this function may involve some overhead, but subsequent calls will be optimized for performance.
- **Inputs**: None
- **Output**: Returns a `ulong` representing the application ID. This value is guaranteed to be consistent across calls after the first invocation.
- **See also**: [`fd_log_app_id`](fd_log.c.driver.md#fd_log_app_id)  (Implementation)


---
### fd\_log\_app<!-- {{#callable_declaration:fd_log_app}} -->
Returns a pointer to a string describing the application.
- **Description**: This function provides a way to retrieve a constant string that identifies the application to which the caller belongs. It is important to call this function after the application has been initialized, as it relies on the application context being set up correctly. The returned string has an infinite lifetime from the caller's perspective, meaning it remains valid for the duration of the application. However, the length of the string is constrained to be within the range of 1 to FD_LOG_NAME_MAX, and it is guaranteed to be non-null.
- **Inputs**: None
- **Output**: Returns a non-null pointer to a constant string (cstr) that describes the application. The length of the string is guaranteed to be in the range [1, FD_LOG_NAME_MAX).
- **See also**: [`fd_log_app`](fd_log.c.driver.md#fd_log_app)  (Implementation)


---
### fd\_log\_thread\_id<!-- {{#callable_declaration:fd_log_thread_id}} -->
Returns the caller's thread ID.
- **Description**: This function retrieves the unique thread ID for the calling thread, which is essential for identifying and managing threads within an application. It should be called after the logging system has been initialized, as it relies on internal state that is set up during initialization. The function is designed to be efficient, providing the thread ID quickly after the first call. If called before the logging system is properly initialized, the behavior is undefined.
- **Inputs**:
    - `None`: This function does not take any parameters.
- **Output**: Returns the unique thread ID as an unsigned long integer, which can be used to identify the calling thread within the application.
- **See also**: [`fd_log_thread_id`](fd_log.c.driver.md#fd_log_thread_id)  (Implementation)


---
### fd\_log\_thread<!-- {{#callable_declaration:fd_log_thread}} -->
Returns a pointer to a string describing the current thread.
- **Description**: This function should be called to retrieve a description of the current thread, which is useful for logging and debugging purposes. It is important to note that this function must be called after the logging system has been initialized, as it relies on internal state that is set up during initialization. The returned string is valid until the thread's description is changed or the thread terminates. If the logging system is not properly initialized, the behavior is undefined.
- **Inputs**:
    - `None`: This function does not take any parameters.
- **Output**: Returns a non-NULL pointer to a constant string that describes the current thread. The string's length is guaranteed to be within the range [1, FD_LOG_NAME_MAX).
- **See also**: [`fd_log_thread`](fd_log.c.driver.md#fd_log_thread)  (Implementation)


---
### fd\_log\_thread\_set<!-- {{#callable_declaration:fd_log_thread_set}} -->
Sets the caller's thread description.
- **Description**: This function is used to set a description for the calling thread, which can be useful for logging purposes. It should be called after the logging system has been initialized. If the provided description is NULL or an empty string, the function resets the thread description to a default value. If a valid description is provided, it will be truncated to a maximum length defined by `FD_LOG_NAME_MAX - 1`. The function does not retain ownership of the provided string, and it is the caller's responsibility to ensure that the string remains valid for the duration of the call.
- **Inputs**:
    - `thread`: A pointer to a constant string that describes the thread. It must not be NULL or empty if a specific description is desired. If NULL or an empty string is passed, the function resets to a default description. The function does not retain ownership of this string after the call.
- **Output**: The function does not return a value and does not mutate any inputs.
- **See also**: [`fd_log_thread_set`](fd_log.c.driver.md#fd_log_thread_set)  (Implementation)


---
### fd\_log\_host\_id<!-- {{#callable_declaration:fd_log_host_id}} -->
Returns the host ID of the current host.
- **Description**: This function retrieves the unique identifier for the host on which the calling thread is executing. It is important to call this function only after the logging system has been properly initialized, as it relies on the internal state of the logging system. The function is designed to be efficient, returning the host ID quickly after the first call. It is safe to call this function multiple times, as subsequent calls will return the cached value.
- **Inputs**: None
- **Output**: Returns a unique unsigned long integer representing the host ID. This value is intended to uniquely identify the host across an enterprise.
- **See also**: [`fd_log_host_id`](fd_log.c.driver.md#fd_log_host_id)  (Implementation)


---
### fd\_log\_host<!-- {{#callable_declaration:fd_log_host}} -->
Returns a pointer to a string describing the host.
- **Description**: This function should be called to obtain a description of the host on which the application is running. It is important to note that this function must be called after the system has been booted, as it relies on the initialization of the logging system. The returned string is intended to be a constant character string that remains valid for the lifetime of the application, ensuring that the caller can safely use it without worrying about its validity. If the logging system is not properly initialized, the behavior of this function is undefined.
- **Inputs**: None
- **Output**: Returns a non-NULL pointer to a constant string (cstr) that describes the host. The length of the string is guaranteed to be in the range [1, FD_LOG_NAME_MAX).
- **See also**: [`fd_log_host`](fd_log.c.driver.md#fd_log_host)  (Implementation)


---
### fd\_log\_cpu\_id<!-- {{#callable_declaration:fd_log_cpu_id}} -->
Returns the CPU ID of the calling thread.
- **Description**: This function retrieves the CPU ID that corresponds to the CPU on which the calling thread was allowed to run. It is important to call this function after the logging system has been initialized, as it relies on internal state that is set up during initialization. The first call to this function will set the CPU ID, and subsequent calls will return the cached value, making it efficient. If the function is called before initialization, it may lead to undefined behavior.
- **Inputs**: None
- **Output**: Returns an unsigned long representing the CPU ID. This ID is intended to uniquely identify a CPU on the host.
- **See also**: [`fd_log_cpu_id`](fd_log.c.driver.md#fd_log_cpu_id)  (Implementation)


---
### fd\_log\_cpu<!-- {{#callable_declaration:fd_log_cpu}} -->
Returns a description of the CPU on which the caller is running.
- **Description**: This function should be called after the logging system has been initialized, as it retrieves a string that describes the CPU architecture currently in use. The returned string is non-null and remains valid for the lifetime of the application, allowing it to be used for logging or diagnostic purposes. If the logging system has not been properly initialized, the behavior is undefined.
- **Inputs**:
    - `void`: No parameters are required for this function.
- **Output**: Returns a non-NULL pointer to a constant string (cstr) that describes the CPU. The string is guaranteed to be valid for the lifetime of the application.
- **See also**: [`fd_log_cpu`](fd_log.c.driver.md#fd_log_cpu)  (Implementation)


---
### fd\_log\_cpu\_set<!-- {{#callable_declaration:fd_log_cpu_set}} -->
Sets the description of the CPU on which the caller is running.
- **Description**: This function is used to set a human-readable description of the CPU that the calling thread is currently executing on. It should be called after the logging system has been initialized and can be used to provide context in log messages. If the provided description is NULL or an empty string, the function will reset the CPU description to a default value. The function does not retain ownership of the provided string, and it will truncate the description to a maximum length defined by `FD_LOG_NAME_MAX-1` if it exceeds this limit.
- **Inputs**:
    - `cpu`: A pointer to a null-terminated string representing the CPU description. This string must not be NULL or empty unless you intend to reset the description. The function does not retain ownership of this string, and it is the caller's responsibility to ensure that it remains valid for the duration of the function call.
- **Output**: The function does not return a value and does not mutate any inputs.
- **See also**: [`fd_log_cpu_set`](fd_log.c.driver.md#fd_log_cpu_set)  (Implementation)


---
### fd\_log\_group\_id<!-- {{#callable_declaration:fd_log_group_id}} -->
Returns the thread group ID.
- **Description**: This function retrieves the thread group ID associated with the calling thread. It is essential to call this function after the logging system has been initialized, as it relies on the internal state of the logging system. The returned ID is intended to be unique across all thread groups on the host, and it is typically equivalent to the OS process ID in simple cases. Note that the function is designed to be efficient, and subsequent calls will not incur significant overhead.
- **Inputs**: None
- **Output**: Returns a `ulong` representing the thread group ID. The value is expected to be at least 2, as IDs less than or equal to 1 are reserved for special cases.
- **See also**: [`fd_log_group_id`](fd_log.c.driver.md#fd_log_group_id)  (Implementation)


---
### fd\_log\_group<!-- {{#callable_declaration:fd_log_group}} -->
Returns a pointer to the thread group's description.
- **Description**: This function retrieves a constant string that describes the thread group to which the caller belongs. It is important to call this function after the application has been initialized, as it relies on the application context being set up correctly. The returned string is valid for the lifetime of the application and is shared among all threads in the same group, ensuring consistency in the description across threads.
- **Inputs**: None
- **Output**: Returns a non-NULL pointer to a constant string (cstr) that describes the thread group. The string is guaranteed to be valid for the lifetime of the application.
- **See also**: [`fd_log_group`](fd_log.c.driver.md#fd_log_group)  (Implementation)


---
### fd\_log\_tid<!-- {{#callable_declaration:fd_log_tid}} -->
Returns the caller's thread group thread ID.
- **Description**: This function should be called to retrieve the unique thread group thread ID for the calling thread. It is important to note that this function must be called after the logging system has been initialized, as it relies on internal state that is set up during initialization. The function is designed to be efficient, returning the thread ID quickly after the first call. If the logging system is not properly initialized, the behavior of this function is undefined.
- **Inputs**: None
- **Output**: Returns the thread group thread ID as an unsigned long integer. This ID is intended to be unique among all threads within the same thread group.
- **See also**: [`fd_log_tid`](fd_log.c.driver.md#fd_log_tid)  (Implementation)


---
### fd\_log\_user\_id<!-- {{#callable_declaration:fd_log_user_id}} -->
Returns the user ID of the thread group.
- **Description**: This function retrieves the user ID associated with the thread group to which the caller belongs. It is intended to be called after the application has been initialized, as it relies on the context established during startup. The user ID is typically the operating system user ID of the process running the caller, and it is designed to be unique across users on the host. This function is efficient and can be called multiple times without significant overhead.
- **Inputs**:
    - `None`: This function does not take any parameters.
- **Output**: Returns the user ID as an unsigned long integer, which uniquely identifies the user on the host.
- **See also**: [`fd_log_user_id`](fd_log.c.driver.md#fd_log_user_id)  (Implementation)


---
### fd\_log\_user<!-- {{#callable_declaration:fd_log_user}} -->
Returns a pointer to the user description string.
- **Description**: This function retrieves a constant string that describes the user who created the thread group to which the caller belongs. It is important to call this function after the application has been booted, as it relies on the initialization of the logging system. The returned string is guaranteed to be non-null and has an infinite lifetime from the caller's perspective, meaning it remains valid for the duration of the application. However, the length of the string is limited to a maximum of `FD_LOG_NAME_MAX` characters.
- **Inputs**: None
- **Output**: Returns a non-NULL pointer to a constant string (cstr) that describes the user. The length of the string is in the range [1, FD_LOG_NAME_MAX).
- **See also**: [`fd_log_user`](fd_log.c.driver.md#fd_log_user)  (Implementation)


---
### fd\_log\_group\_id\_query<!-- {{#callable_declaration:fd_log_group_id_query}} -->
Queries the status of a thread group identified by its group ID.
- **Description**: This function is used to determine the status of a thread group based on its group ID. It should be called with a valid group ID that represents a thread group on the host. The function will return a status code indicating whether the group is live, dead, or if there was an error in the query. It is important to ensure that the group ID is valid and corresponds to a process ID on the host; otherwise, the function may return an invalid status code.
- **Inputs**:
    - `group_id`: The group ID of the thread group to query. It must be a valid process ID on the host. If the group ID does not correspond to a valid process, the function will return an error code indicating invalid input.
- **Output**: Returns an integer status code: 1 if the group is live, 0 if it is dead, -1 if the group ID is invalid, -2 if the caller lacks permissions, and -3 for an unknown failure.
- **See also**: [`fd_log_group_id_query`](fd_log.c.driver.md#fd_log_group_id_query)  (Implementation)


---
### fd\_log\_wallclock<!-- {{#callable_declaration:fd_log_wallclock}} -->
Reads the host's wallclock as nanoseconds since the UNIX epoch.
- **Description**: This function retrieves the current wallclock time from the host system, expressed in nanoseconds since the UNIX epoch (January 1, 1970). It is intended to be used for timestamping log messages or other time-sensitive operations. It should be called after the logging system has been initialized, as it provides a timestamp that is crucial for accurate logging. The function is designed to be efficient, but it may involve system calls, which can introduce some latency.
- **Inputs**: None
- **Output**: Returns the current wallclock time in nanoseconds as a long integer.
- **See also**: [`fd_log_wallclock`](fd_log.c.driver.md#fd_log_wallclock)  (Implementation)


---
### fd\_log\_wallclock\_cstr<!-- {{#callable_declaration:fd_log_wallclock_cstr}} -->
Formats a wall clock timestamp into a string.
- **Description**: This function is used to convert a given timestamp in nanoseconds since the UNIX epoch into a human-readable string format. The formatted string will represent the date and time in the format 'YYYY-MM-DD hh:mm:ss.nnnnnnnnn GMT+TZ'. It is important to ensure that the provided buffer is large enough to hold the resulting string, which should be at least FD_LOG_WALLCLOCK_CSTR_BUF_SZ bytes. If the timestamp is not valid or cannot be converted, the function will return a string representation of the timestamp in seconds since the epoch followed by 's UNIX'.
- **Inputs**:
    - `now`: A long integer representing the timestamp in nanoseconds since the UNIX epoch. This value should be a valid timestamp; otherwise, the function may return a fallback string.
    - `buf`: A pointer to a character buffer where the formatted string will be stored. This buffer must not be null and must be at least FD_LOG_WALLCLOCK_CSTR_BUF_SZ bytes in size to ensure it can hold the resulting string.
- **Output**: Returns a pointer to the buffer containing the formatted timestamp string.
- **See also**: [`fd_log_wallclock_cstr`](fd_log.c.driver.md#fd_log_wallclock_cstr)  (Implementation)


---
### fd\_log\_sleep<!-- {{#callable_declaration:fd_log_sleep}} -->
Puts the calling thread to sleep for a specified duration.
- **Description**: This function is used to pause the execution of the calling thread for a specified duration in nanoseconds. If the duration is less than or equal to zero, the function will yield the processor instead of sleeping. It is important to note that if the sleep is interrupted, the function will return the remaining time that was not slept. This function should be called when a thread needs to wait for a certain period without consuming CPU resources.
- **Inputs**:
    - `dt`: The duration for which the thread should sleep, specified in nanoseconds. It must be greater than zero to sleep for a specific duration; otherwise, it will yield the processor. If the value is negative or zero, the function will not sleep and will return immediately.
- **Output**: Returns the remaining sleep time in nanoseconds if the sleep was interrupted; otherwise, it returns zero if the sleep completed successfully.
- **See also**: [`fd_log_sleep`](fd_log.c.driver.md#fd_log_sleep)  (Implementation)


---
### fd\_log\_wait\_until<!-- {{#callable_declaration:fd_log_wait_until}} -->
Waits until the specified time is reached.
- **Description**: This function is designed to block the calling thread until the wall clock time reaches or exceeds the specified `then` value, which should be a timestamp in nanoseconds since the UNIX epoch. It is important to call this function only after the logging system has been properly initialized. The function employs various strategies to manage CPU usage during the wait, adapting its behavior based on the remaining time until the target is reached. For very short waits, it will spin, while for longer waits, it will yield or sleep to be more CPU-friendly. The return value is the actual wall clock time when the wait ended, which will always be at least equal to `then`.
- **Inputs**:
    - `then`: A long integer representing the target wall clock time in nanoseconds since the UNIX epoch. This value must be greater than the current wall clock time when the function is called; otherwise, the function will return immediately without waiting.
- **Output**: Returns the wall clock time in nanoseconds when the wait ended, which will be at least equal to the input parameter `then`.
- **See also**: [`fd_log_wait_until`](fd_log.c.driver.md#fd_log_wait_until)  (Implementation)


---
### fd\_log\_flush<!-- {{#callable_declaration:fd_log_flush}} -->
Manually flushes the log.
- **Description**: This function is used to ensure that any buffered log messages are written out to the log file. It should be called when there is a need to guarantee that all log messages, especially low-priority ones, are persisted before proceeding with further operations. It is important to note that this function must be called after the logging system has been initialized, as it relies on the log file being set up correctly. If the log file is not available or has not been initialized, the function will not perform any action.
- **Inputs**: None
- **Output**: None
- **See also**: [`fd_log_flush`](fd_log.c.driver.md#fd_log_flush)  (Implementation)


---
### fd\_log\_colorize<!-- {{#callable_declaration:fd_log_colorize}} -->
Returns the colorization mode of the ephemeral log.
- **Description**: This function retrieves the current colorization mode for the ephemeral log output. It should be called after the logging system has been initialized, as it relies on the internal state of the logging configuration. The function returns an integer value where a return value of zero indicates that colorization is disabled, while any non-zero value indicates that colorization is enabled. It is important to note that calling this function before the logging system is properly set up may lead to undefined behavior.
- **Inputs**:
    - `None`: This function does not take any parameters.
- **Output**: Returns an integer indicating the colorization mode; zero for no colorization and non-zero for colorization enabled.
- **See also**: [`fd_log_colorize`](fd_log.c.driver.md#fd_log_colorize)  (Implementation)


---
### fd\_log\_level\_logfile<!-- {{#callable_declaration:fd_log_level_logfile}} -->
Returns the current log level for the log file.
- **Description**: This function retrieves the current log level that is set for the log file. It is important to call this function after the logging system has been initialized, as it relies on the internal state of the logging configuration. The log level determines the severity of messages that will be recorded in the log file, and it can be useful for debugging or monitoring the application's logging behavior.
- **Inputs**: None
- **Output**: Returns an integer representing the current log level for the log file. The log level is typically defined by constants that correspond to different severity levels.
- **See also**: [`fd_log_level_logfile`](fd_log.c.driver.md#fd_log_level_logfile)  (Implementation)


---
### fd\_log\_level\_stderr<!-- {{#callable_declaration:fd_log_level_stderr}} -->
Returns the current log level for stderr.
- **Description**: This function retrieves the log level that is currently set for the stderr output stream. It is important to call this function after the logging system has been initialized, as it relies on the internal state of the logging configuration. The returned log level can be used to determine the verbosity of log messages that will be output to stderr, which can be useful for debugging or monitoring the application's behavior.
- **Inputs**: None
- **Output**: Returns an integer representing the current log level for stderr. The log levels are typically defined as constants, with higher values indicating more severe log levels.
- **See also**: [`fd_log_level_stderr`](fd_log.c.driver.md#fd_log_level_stderr)  (Implementation)


---
### fd\_log\_level\_flush<!-- {{#callable_declaration:fd_log_level_flush}} -->
Flushes the log level settings.
- **Description**: This function should be called to ensure that any changes made to the log level settings are applied immediately. It is particularly useful after modifying log level configurations to ensure that the logging behavior reflects the most current settings. The function does not take any parameters and should be called after the logging system has been initialized.
- **Inputs**: None
- **Output**: Returns an integer indicating the result of the flush operation. A successful flush will return a value that indicates the current log level flush state.
- **See also**: [`fd_log_level_flush`](fd_log.c.driver.md#fd_log_level_flush)  (Implementation)


---
### fd\_log\_level\_core<!-- {{#callable_declaration:fd_log_level_core}} -->
Returns the core log level.
- **Description**: This function retrieves the current log level for core logging. It is essential to call this function after the logging system has been initialized, as it relies on the internal state of the logging system. The log level determines the severity of messages that will be logged, and it is crucial for controlling the verbosity of log output. If the logging system is not properly initialized, the behavior of this function is undefined.
- **Inputs**: None
- **Output**: Returns an integer representing the current core log level. The log level is typically defined by constants that indicate the severity of log messages.
- **See also**: [`fd_log_level_core`](fd_log.c.driver.md#fd_log_level_core)  (Implementation)


---
### fd\_log\_colorize\_set<!-- {{#callable_declaration:fd_log_colorize_set}} -->
Sets the colorization mode for log output.
- **Description**: This function is used to configure the colorization mode of the ephemeral log output. It should be called after the logging system has been initialized, as it relies on the logging infrastructure being set up correctly. The mode parameter determines whether colorization is enabled or disabled for log messages sent to the ephemeral log. If an invalid mode is provided, the function will not change the current colorization setting.
- **Inputs**:
    - `mode`: An integer representing the desired colorization mode. A value of zero indicates no colorization, while any non-zero value indicates that colorization should be enabled. The function does not validate the range of the mode, so it is the caller's responsibility to ensure that the value is appropriate.
- **Output**: None
- **See also**: [`fd_log_colorize_set`](fd_log.c.driver.md#fd_log_colorize_set)  (Implementation)


---
### fd\_log\_level\_logfile\_set<!-- {{#callable_declaration:fd_log_level_logfile_set}} -->
Sets the log level for the log file.
- **Description**: This function is used to configure the verbosity of log messages written to the log file. It should be called after the logging system has been initialized, and before any logging occurs to ensure that the desired log level is applied. The log level determines which messages are recorded in the log file, with higher levels typically indicating more severe messages. Invalid log levels may not be handled gracefully, so it is important to use predefined log level constants.
- **Inputs**:
    - `level`: An integer representing the desired log level for the log file. Valid values are typically defined as constants (e.g., FD_LOG_DEBUG, FD_LOG_INFO, etc.). The caller retains ownership of the value passed in. If an invalid level is provided, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_log_level_logfile_set`](fd_log.c.driver.md#fd_log_level_logfile_set)  (Implementation)


---
### fd\_log\_level\_stderr\_set<!-- {{#callable_declaration:fd_log_level_stderr_set}} -->
Sets the log level for stderr output.
- **Description**: This function is used to configure the verbosity of log messages that are sent to the standard error stream (stderr). It should be called after the logging system has been initialized, and before any logging occurs to ensure that the desired log level is applied. The log level determines which messages are displayed based on their severity, with higher levels indicating more critical messages. Invalid log levels may not be handled gracefully, so it is important to use defined log levels.
- **Inputs**:
    - `level`: An integer representing the desired log level for stderr output. Valid values correspond to predefined log levels, typically ranging from 0 (lowest severity) to 7 (highest severity). The caller retains ownership of this value, and it must not be null. If an invalid level is provided, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_log_level_stderr_set`](fd_log.c.driver.md#fd_log_level_stderr_set)  (Implementation)


---
### fd\_log\_level\_flush\_set<!-- {{#callable_declaration:fd_log_level_flush_set}} -->
Sets the log level for flushing log messages.
- **Description**: This function is used to configure the log level for flushing log messages, which determines the severity of messages that will trigger a flush of the log output. It must be called after the logging system has been initialized, and the level should correspond to one of the predefined log levels. If an invalid level is provided, the function will not perform any action, and the log level will remain unchanged.
- **Inputs**:
    - `level`: An integer representing the log level to set for flushing. Valid values typically range from 0 to 7, corresponding to different log severity levels. The caller retains ownership of the value, and passing an invalid level will result in no changes to the current log level.
- **Output**: None
- **See also**: [`fd_log_level_flush_set`](fd_log.c.driver.md#fd_log_level_flush_set)  (Implementation)


---
### fd\_log\_level\_core\_set<!-- {{#callable_declaration:fd_log_level_core_set}} -->
Sets the core log level.
- **Description**: This function is used to configure the core log level for the logging system. It must be called after the logging system has been initialized, and it allows the user to specify the verbosity of log messages that will be recorded. The log level can affect the output of log messages to both the ephemeral log (stderr) and the permanent log (log file). It is important to ensure that the provided log level is within the valid range, as invalid values may lead to undefined behavior.
- **Inputs**:
    - `level`: An integer representing the desired log level. Valid values are typically defined by the logging system, and the caller should ensure that the level is appropriate. The function does not perform validation on the input, so providing an invalid level may result in unexpected logging behavior.
- **Output**: None
- **See also**: [`fd_log_level_core_set`](fd_log.c.driver.md#fd_log_level_core_set)  (Implementation)


---
### fd\_log\_enable\_unclean\_exit<!-- {{#callable_declaration:fd_log_enable_unclean_exit}} -->
Enables logging for unclean exits.
- **Description**: This function should be called to enable logging specifically for unclean exit scenarios, allowing the application to capture relevant log messages when it terminates unexpectedly. It is important to invoke this function after the logging system has been initialized and before any potential unclean exit occurs. The function does not take any parameters and does not return a value.
- **Inputs**:
    - `None`: This function does not take any parameters.
- **Output**: None
- **See also**: [`fd_log_enable_unclean_exit`](fd_log.c.driver.md#fd_log_enable_unclean_exit)  (Implementation)


---
### fd\_log\_private\_fprintf\_0<!-- {{#callable_declaration:fd_log_private_fprintf_0}} -->
Writes formatted log messages to a specified file descriptor.
- **Description**: This function is intended for logging messages to a specified file descriptor, typically used for logging purposes in applications. It should be called after the logging system has been properly initialized, and it is designed to handle formatted strings similar to printf. The function ensures that log messages are written in a quasi-atomic manner to prevent interleaving from concurrent threads. It is important to note that the function is not async-signal safe, and should not be called from signal handlers.
- **Inputs**:
    - `fd`: The file descriptor to which the log message will be written. It must be a valid file descriptor that is open for writing. If an invalid file descriptor is provided, the behavior is undefined.
    - `fmt`: A format string that specifies how subsequent arguments are converted for output. It must not be NULL. The function expects a valid format string similar to those used in printf. If the format string is invalid, the behavior is undefined.
    - `...`: Additional arguments that are formatted according to the format string. The number and types of these arguments must match the format specifiers in the format string. If the arguments do not match the format, the behavior is undefined.
- **Output**: The function does not return a value and does not mutate any inputs. It writes the formatted log message directly to the specified file descriptor.
- **See also**: [`fd_log_private_fprintf_0`](fd_log.c.driver.md#fd_log_private_fprintf_0)  (Implementation)


---
### fd\_log\_private\_fprintf\_nolock\_0<!-- {{#callable_declaration:fd_log_private_fprintf_nolock_0}} -->
Writes a formatted message to a specified file descriptor without locking.
- **Description**: This function is intended for logging messages directly to a file descriptor, such as standard output. It should be used when you need to log messages without the overhead of locking mechanisms, making it suitable for performance-sensitive contexts. The function takes a format string followed by a variable number of arguments, similar to `printf`. It is important to ensure that the file descriptor is valid and open before calling this function, as it does not perform any checks on the validity of the file descriptor. If the formatted message exceeds the buffer size, it will be truncated.
- **Inputs**:
    - `fd`: The file descriptor to which the message will be written. It must be a valid, open file descriptor. If the descriptor is invalid, the behavior is undefined.
    - `fmt`: A format string that specifies how subsequent arguments are converted for output. This string must not be null. The function expects a variable number of arguments following this format string.
- **Output**: None
- **See also**: [`fd_log_private_fprintf_nolock_0`](fd_log.c.driver.md#fd_log_private_fprintf_nolock_0)  (Implementation)


---
### fd\_log\_private\_0<!-- {{#callable_declaration:fd_log_private_0}} -->
Formats a log message and returns it.
- **Description**: This function is used to create a formatted log message based on a specified format string and a variable number of arguments. It should be called when logging messages, and it is important to ensure that the logging system has been properly initialized before invoking this function. The formatted message is stored in a predefined buffer, and the function guarantees that the message will be null-terminated. If the formatted message exceeds the buffer size, it will be truncated to fit. Note that this function is not thread-safe and should not be called from signal handlers.
- **Inputs**:
    - `fmt`: A format string that specifies how to format the log message. It must not be null and should follow the standard printf format conventions.
- **Output**: Returns a pointer to the formatted log message stored in a static buffer. The content of this buffer is overwritten with each call to the function.
- **See also**: [`fd_log_private_0`](fd_log.c.driver.md#fd_log_private_0)  (Implementation)


---
### fd\_log\_private\_1<!-- {{#callable_declaration:fd_log_private_1}} -->
Logs a message with a specified severity level.
- **Description**: This function is used to log messages at various severity levels, including DEBUG, INFO, NOTICE, WARNING, ERR, CRIT, ALERT, and EMERG. It should be called after the logging system has been initialized and is typically used to provide runtime diagnostics or error reporting. The function checks the current logging level and only logs messages that meet or exceed the specified level. It also handles deduplication of messages to avoid flooding the logs with repeated entries. If the logging level is below the threshold for either the log file or stderr, the message will not be logged.
- **Inputs**:
    - `level`: The severity level of the log message, which must be in the range of 0 to 7, corresponding to DEBUG through EMERG. If the level is less than the current logging level for the log file, the message will not be logged.
    - `now`: The current time in nanoseconds since the UNIX epoch. This value is used for timestamping the log message.
    - `file`: A string representing the source file name where the log call is made. This must not be null.
    - `line`: An integer representing the line number in the source file where the log call is made. This must be a valid line number.
    - `func`: A string representing the name of the function where the log call is made. This must not be null.
    - `msg`: A string containing the log message to be recorded. This must not be null.
- **Output**: None
- **See also**: [`fd_log_private_1`](fd_log.c.driver.md#fd_log_private_1)  (Implementation)


---
### fd\_log\_private\_2<!-- {{#callable_declaration:fd_log_private_2}} -->
Logs a message and handles critical error conditions.
- **Description**: This function is intended for logging messages at various severity levels, specifically for error and critical conditions. It should be called when a significant issue occurs that requires immediate attention, such as an error that leads to program termination. The function expects to be called after the logging system has been initialized, and it will log the provided message along with contextual information such as the file name, line number, and function name. If the logging level is below the core logging level, the program will terminate with an error code, and if the logging level is critical or higher, the program will abort after logging a backtrace if possible.
- **Inputs**:
    - `level`: An integer representing the severity level of the log message. Valid values are typically in the range of 0 to 7, corresponding to different log levels (e.g., debug, info, notice, warning, error, critical, alert, emergency). Must not be less than the core logging level; otherwise, the program will terminate.
    - `now`: A long integer representing the current time in nanoseconds since the UNIX epoch. This value is typically obtained from a wall clock function and is used for timestamping the log message.
    - `file`: A constant character pointer to a string representing the source file name where the log call is made. This should not be null.
    - `line`: An integer representing the line number in the source file where the log call is made. This should be a positive integer.
    - `func`: A constant character pointer to a string representing the name of the function where the log call is made. This should not be null.
    - `msg`: A constant character pointer to a string containing the log message to be recorded. This should not be null.
- **Output**: This function does not return a value. It may terminate the program or abort it based on the severity level of the log message.
- **See also**: [`fd_log_private_2`](fd_log.c.driver.md#fd_log_private_2)  (Implementation)


---
### fd\_log\_private\_raw\_2<!-- {{#callable_declaration:fd_log_private_raw_2}} -->
Logs a message and terminates the program.
- **Description**: This function is intended for logging critical error messages that require immediate attention. It should be called when a fatal error occurs, providing context about the error through the parameters. The function logs the message to the standard error stream in a specific format that includes the file name, line number, function name, and the message itself. After logging, it terminates the program with an exit code of 1, ensuring that the error is reported and the program does not continue execution. It is important to note that this function does not return; it will either exit or abort the program.
- **Inputs**:
    - `file`: A string representing the name of the source file where the error occurred. Must not be null.
    - `line`: An integer representing the line number in the source file where the error occurred. Must be a positive integer.
    - `func`: A string representing the name of the function where the error occurred. Must not be null.
    - `msg`: A string containing the error message to be logged. Must not be null.
- **Output**: This function does not return a value and will terminate the program.
- **See also**: [`fd_log_private_raw_2`](fd_log.c.driver.md#fd_log_private_raw_2)  (Implementation)


---
### fd\_log\_private\_hexdump\_msg<!-- {{#callable_declaration:fd_log_private_hexdump_msg}} -->
Logs a hexdump of a memory region.
- **Description**: This function is used to log a hexdump of a specified memory region, which can be useful for debugging and analyzing binary data. It should be called when there is a need to visualize the contents of a memory area, especially when dealing with raw data structures or network packets. The function expects a description string, a pointer to the memory to be dumped, and the size of the memory region. If the size is zero or the memory pointer is null, it will log a message indicating unreadable memory. The description string can be null or empty, and if it exceeds a certain length, it will be truncated for logging purposes.
- **Inputs**:
    - `descr`: A human-readable description of the memory region. It can be null or an empty string. If it exceeds 32 characters, it will be truncated.
    - `mem`: A pointer to the memory region to be hexdumped. Must not be null if the size is greater than zero.
    - `sz`: The size in bytes of the memory region to be logged. Must be a non-negative value. If zero, a specific message will be logged indicating no data to dump.
- **Output**: Returns a pointer to the log message that was generated. If the memory size is zero or the memory pointer is null, the log will indicate unreadable memory.
- **See also**: [`fd_log_private_hexdump_msg`](fd_log.c.driver.md#fd_log_private_hexdump_msg)  (Implementation)


---
### fd\_log\_private\_boot<!-- {{#callable_declaration:fd_log_private_boot}} -->
Initializes logging for the application.
- **Description**: This function must be called to set up the logging environment for the application before any logging can occur. It processes command-line arguments to configure various logging parameters such as application ID, thread ID, host ID, CPU ID, and user ID. It also sets up signal handlers and prepares the log file for writing. If any command-line arguments are invalid or not provided, default values will be used. The function should be called at the start of the application, and it is essential that the logging system is properly initialized before any logging operations are performed.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments. Must not be null.
    - `pargv`: A pointer to an array of strings (character pointers) representing the command-line arguments. Must not be null.
- **Output**: None
- **See also**: [`fd_log_private_boot`](fd_log.c.driver.md#fd_log_private_boot)  (Implementation)


---
### fd\_log\_private\_boot\_custom<!-- {{#callable_declaration:fd_log_private_boot_custom}} -->
Configures logging parameters for the application.
- **Description**: This function is intended to be called during the boot process of an application to set up various logging parameters, including application identifiers, thread information, host and CPU details, and logging levels. It must be called after the logging system has been initialized and before any logging occurs. The function also handles the configuration of log file descriptors and paths, ensuring that logging can proceed correctly. If invalid parameters are provided, the function may not behave as expected, and it is the caller's responsibility to ensure that all pointers are valid and that the logging levels are set appropriately.
- **Inputs**:
    - `lock`: A pointer to an integer used for locking during logging operations. Must not be null.
    - `app_id`: An unsigned long representing the application identifier. Should be a unique identifier for the application.
    - `app`: A constant character pointer to a string describing the application. Must not be null.
    - `thread_id`: An unsigned long representing the thread identifier. Should be unique within the application.
    - `thread`: A constant character pointer to a string describing the thread. Must not be null.
    - `host_id`: An unsigned long representing the host identifier. Should uniquely identify the host.
    - `host`: A constant character pointer to a string describing the host. Must not be null.
    - `cpu_id`: An unsigned long representing the CPU identifier. Should uniquely identify the CPU.
    - `cpu`: A constant character pointer to a string describing the CPU. Must not be null.
    - `group_id`: An unsigned long representing the group identifier. Should uniquely identify the thread group.
    - `group`: A constant character pointer to a string describing the group. Must not be null.
    - `tid`: An unsigned long representing the thread group thread identifier. Should be unique within the thread group.
    - `user_id`: An unsigned long representing the user identifier. Should uniquely identify the user.
    - `user`: A constant character pointer to a string describing the user. Must not be null.
    - `dedup`: An integer indicating whether to deduplicate log messages. Valid values are typically 0 (no deduplication) or 1 (enable deduplication).
    - `colorize`: An integer indicating whether to colorize log output. Valid values are typically 0 (no colorization) or 1 (enable colorization).
    - `level_logfile`: An integer representing the logging level for the log file. Should be set to a valid log level.
    - `level_stderr`: An integer representing the logging level for standard error output. Should be set to a valid log level.
    - `level_flush`: An integer representing the logging level for flushing logs. Should be set to a valid log level.
    - `level_core`: An integer representing the logging level for core dumps. Should be set to a valid log level.
    - `log_fd`: An integer representing the file descriptor for logging. Should be set to a valid file descriptor or -1 if not used.
    - `log_path`: A constant character pointer to a string representing the log file path. Must not be null.
- **Output**: None
- **See also**: [`fd_log_private_boot_custom`](fd_log.c.driver.md#fd_log_private_boot_custom)  (Implementation)


---
### fd\_log\_private\_halt<!-- {{#callable_declaration:fd_log_private_halt}} -->
Halts the logging system.
- **Description**: This function is intended to be called when the logging system needs to be stopped and cleaned up. It should only be invoked after the logging system has been initialized and is currently active. The function performs necessary cleanup operations to ensure that all logging resources are released and that the logging state is reset. It is important to note that once this function is called, the logging system will be offline, and any subsequent logging attempts will not be processed. Additionally, care should be taken to ensure that this function is not called from signal handlers, as it may lead to deadlocks or corruption of the logging state.
- **Inputs**:
    - `None`: This function does not take any parameters.
- **Output**: This function does not return a value and does not mutate any inputs.
- **See also**: [`fd_log_private_halt`](fd_log.c.driver.md#fd_log_private_halt)  (Implementation)


---
### fd\_log\_private\_main\_stack\_sz<!-- {{#callable_declaration:fd_log_private_main_stack_sz}} -->
Returns the current stack size limit.
- **Description**: This function retrieves the current stack size limit for the calling process, as defined by the operating system. It should be called when the application needs to know the maximum stack size available for threads, particularly before creating new threads or allocating large stack-based data structures. The function will return 0 if it encounters an error while retrieving the limit, such as if the `getrlimit` call fails or if the retrieved limits are not reasonable. It is important to note that the function should be called in an environment where the stack size has been properly initialized.
- **Inputs**:
    - `None`: This function does not take any parameters.
- **Output**: Returns the current stack size limit in bytes, or 0 if an error occurs.
- **See also**: [`fd_log_private_main_stack_sz`](fd_log.c.driver.md#fd_log_private_main_stack_sz)  (Implementation)


---
### fd\_log\_private\_tid\_default<!-- {{#callable_declaration:fd_log_private_tid_default}} -->
Returns the default thread ID.
- **Description**: This function retrieves the default thread ID for the calling thread. It is intended to be used in contexts where the thread ID is needed for logging or identification purposes. The function should be called after the logging system has been initialized, as it relies on system calls to obtain the thread ID. If the thread ID cannot be determined, the function will return `ULONG_MAX`.
- **Inputs**: None
- **Output**: Returns the thread ID as an unsigned long integer. If the thread ID is not valid, it returns `ULONG_MAX`.
- **See also**: [`fd_log_private_tid_default`](fd_log.c.driver.md#fd_log_private_tid_default)  (Implementation)


---
### fd\_log\_private\_cpu\_id\_default<!-- {{#callable_declaration:fd_log_private_cpu_id_default}} -->
Returns the default CPU ID for the calling thread.
- **Description**: This function retrieves the default CPU ID that the calling thread is allowed to run on. It must be called after the logging system has been initialized, as it relies on the CPU affinity settings of the process. If the function encounters an error while retrieving the CPU affinity, it will return `ULONG_MAX`. The returned CPU ID will be clamped to a maximum value defined by `FD_TILE_MAX`, ensuring that it remains within valid bounds.
- **Inputs**:
    - `None`: This function does not take any parameters.
- **Output**: Returns the CPU ID as an unsigned long integer. If an error occurs, it returns `ULONG_MAX`.
- **See also**: [`fd_log_private_cpu_id_default`](fd_log.c.driver.md#fd_log_private_cpu_id_default)  (Implementation)


---
### fd\_log\_private\_stack\_discover<!-- {{#callable_declaration:fd_log_private_stack_discover}} -->
Discovers the caller's stack memory region.
- **Description**: This function is used to determine the memory region allocated for the caller's stack, which is essential for logging and debugging purposes. It should be called with a valid stack size, and it will populate the provided pointers with the start and end addresses of the stack region. If the stack size is zero or if the function encounters an error while accessing the memory map, both output pointers will be set to zero. It is important to ensure that the function is called in a context where the stack size is known and valid.
- **Inputs**:
    - `stack_sz`: The expected size of the stack in bytes. Must be greater than zero; otherwise, the function will set the output pointers to zero.
    - `_stack0`: A pointer to a ulong where the start address of the caller's stack will be stored. Caller retains ownership and must ensure it is not null.
    - `_stack1`: A pointer to a ulong where the end address of the caller's stack will be stored. Caller retains ownership and must ensure it is not null.
- **Output**: The function does not return a value. Instead, it populates the memory locations pointed to by `_stack0` and `_stack1` with the start and end addresses of the caller's stack region, respectively. If an error occurs or if the stack size is zero, both addresses will be set to zero.
- **See also**: [`fd_log_private_stack_discover`](fd_log.c.driver.md#fd_log_private_stack_discover)  (Implementation)


---
### fd\_log\_private\_app\_id\_set<!-- {{#callable_declaration:fd_log_private_app_id_set}} -->
Sets the application ID for logging.
- **Description**: This function is used to set the application ID that will be associated with log messages produced by the logging system. It should be called after the logging system has been initialized and before any logging occurs to ensure that the application ID is correctly associated with the log entries. The application ID is expected to be a unique identifier for the application, and it is important to ensure that it is set appropriately to avoid confusion in log entries. There are no specific constraints on the value of the application ID, but it should be a valid unsigned long integer.
- **Inputs**:
    - `app_id`: The application ID to be set for logging. It must be a valid unsigned long integer. The caller retains ownership of the value, and it should not be null.
- **Output**: None
- **See also**: [`fd_log_private_app_id_set`](fd_log.c.driver.md#fd_log_private_app_id_set)  (Implementation)


---
### fd\_log\_private\_thread\_id\_set<!-- {{#callable_declaration:fd_log_private_thread_id_set}} -->
Sets the private thread ID for logging.
- **Description**: This function is used to set the private thread ID that will be associated with log messages generated by the application. It should be called after the logging system has been initialized and before any logging occurs to ensure that the correct thread ID is recorded in the logs. The function does not perform any validation on the input value, so it is the caller's responsibility to ensure that the provided thread ID is valid and meaningful within the context of the application.
- **Inputs**:
    - `thread_id`: The thread ID to be set for logging. It is expected to be a valid unsigned long integer representing the unique identifier for the thread. The function does not take ownership of this value, and it must be a valid thread ID as per the application's context.
- **Output**: None
- **See also**: [`fd_log_private_thread_id_set`](fd_log.c.driver.md#fd_log_private_thread_id_set)  (Implementation)


---
### fd\_log\_private\_host\_id\_set<!-- {{#callable_declaration:fd_log_private_host_id_set}} -->
Sets the private host ID for logging.
- **Description**: This function is used to set the private host ID that will be associated with log messages. It should be called after the logging system has been initialized and before any logging occurs to ensure that the correct host ID is used in log entries. The host ID is expected to be a unique identifier for the host in the logging context.
- **Inputs**:
    - `host_id`: The host ID to be set for logging. It is expected to be a valid unsigned long integer. The function does not perform validation on the value of host_id, so it is the caller's responsibility to ensure that it is appropriate for the logging context.
- **Output**: None
- **See also**: [`fd_log_private_host_id_set`](fd_log.c.driver.md#fd_log_private_host_id_set)  (Implementation)


---
### fd\_log\_private\_cpu\_id\_set<!-- {{#callable_declaration:fd_log_private_cpu_id_set}} -->
Sets the private CPU identifier.
- **Description**: This function is used to set the private CPU identifier for logging purposes. It should be called after the logging system has been initialized to ensure that the identifier is correctly associated with the current logging context. The function does not perform any validation on the input value, so it is the caller's responsibility to ensure that the `cpu_id` is a valid identifier. Calling this function with an invalid or inappropriate value may lead to undefined behavior in the logging system.
- **Inputs**:
    - `cpu_id`: The CPU identifier to be set. It is expected to be a valid unsigned long integer. The function does not take ownership of this value, and it must not be null.
- **Output**: None
- **See also**: [`fd_log_private_cpu_id_set`](fd_log.c.driver.md#fd_log_private_cpu_id_set)  (Implementation)


---
### fd\_log\_private\_group\_id\_set<!-- {{#callable_declaration:fd_log_private_group_id_set}} -->
Sets the private group ID for logging.
- **Description**: This function is used to set the private group ID that will be associated with log messages. It should be called after the logging system has been initialized and before any logging occurs to ensure that the correct group ID is used in log entries. The group ID must be a valid unsigned long integer, and there are no specific constraints on its value, but it is recommended to use meaningful identifiers to maintain clarity in log records.
- **Inputs**:
    - `group_id`: The group ID to be set for logging. It is an unsigned long integer. The caller retains ownership of the value, and it must not be null. If an invalid value is provided, the function will still set the group ID without any error handling.
- **Output**: None
- **See also**: [`fd_log_private_group_id_set`](fd_log.c.driver.md#fd_log_private_group_id_set)  (Implementation)


---
### fd\_log\_private\_tid\_set<!-- {{#callable_declaration:fd_log_private_tid_set}} -->
Sets the private thread ID for logging.
- **Description**: This function should be called to set the private thread ID used for logging purposes. It is essential to invoke this function after the logging system has been initialized to ensure that the correct thread ID is associated with log messages. The function does not perform any validation on the input value, so it is the caller's responsibility to ensure that the provided thread ID is valid.
- **Inputs**:
    - `tid`: The thread ID to be set for logging. It should be a valid unsigned long integer. The function does not check for the validity of this value, so the caller must ensure it is appropriate.
- **Output**: None
- **See also**: [`fd_log_private_tid_set`](fd_log.c.driver.md#fd_log_private_tid_set)  (Implementation)


---
### fd\_log\_private\_user\_id\_set<!-- {{#callable_declaration:fd_log_private_user_id_set}} -->
Sets the private user ID for logging.
- **Description**: This function should be called to set the user ID that will be associated with log messages generated by the application. It is important to invoke this function after the logging system has been initialized, as it establishes the user context for subsequent log entries. The user ID is expected to be a valid unsigned long integer, and it will be stored for use in logging operations. If this function is called multiple times, the most recent user ID will be retained.
- **Inputs**:
    - `user_id`: The user ID to be set for logging. It must be a valid unsigned long integer. The function does not take ownership of the value, and the caller is responsible for ensuring that the value is appropriate for logging purposes.
- **Output**: None
- **See also**: [`fd_log_private_user_id_set`](fd_log.c.driver.md#fd_log_private_user_id_set)  (Implementation)


---
### fd\_log\_private\_app\_set<!-- {{#callable_declaration:fd_log_private_app_set}} -->
Sets the application identifier for logging.
- **Description**: This function is used to specify the application name that will be associated with log messages. It should be called after the logging system has been initialized and before any logging occurs. If the provided application name is `NULL`, it defaults to a placeholder string "[app]". The function ensures that the application name is updated only if it differs from the current value, preventing unnecessary updates. It is important to note that this function is not thread-safe, so it should be called in a single-threaded context or protected by appropriate synchronization mechanisms.
- **Inputs**:
    - `app`: A pointer to a constant string representing the application name. This string must not be null if you want to set a specific application name; otherwise, it defaults to "[app]". The length of the string should be less than FD_LOG_NAME_MAX (40 characters). The function does not retain ownership of the string, and it is the caller's responsibility to ensure the string remains valid for the duration of its use.
- **Output**: The function does not return a value and does not mutate any inputs.
- **See also**: [`fd_log_private_app_set`](fd_log.c.driver.md#fd_log_private_app_set)  (Implementation)


---
### fd\_log\_private\_host\_set<!-- {{#callable_declaration:fd_log_private_host_set}} -->
Sets the host description for logging.
- **Description**: This function is used to set the description of the host for logging purposes. It should be called after the logging system has been initialized, and it allows the user to specify a custom host name that will be included in log messages. If the provided host name is NULL or an empty string, a default placeholder '[host]' will be used. The function does not retain ownership of the provided string, and it is the caller's responsibility to ensure that the string remains valid for the duration of its use.
- **Inputs**:
    - `host`: A pointer to a constant string representing the host description. It must not be NULL or empty; otherwise, a default value will be used. The caller retains ownership of the string and must ensure it remains valid for the duration of its use.
- **Output**: None
- **See also**: [`fd_log_private_host_set`](fd_log.c.driver.md#fd_log_private_host_set)  (Implementation)


---
### fd\_log\_private\_group\_set<!-- {{#callable_declaration:fd_log_private_group_set}} -->
Sets the private group identifier for logging.
- **Description**: This function is used to set the private group identifier that will be used in log messages. It should be called after the logging system has been initialized, and it allows the user to specify a custom group name for better log organization. If the provided group name is NULL or an empty string, a default value of "[group]" will be used. The function does not retain ownership of the provided string, and it is the caller's responsibility to ensure that the string remains valid for the duration of its use.
- **Inputs**:
    - `group`: A pointer to a constant string representing the group name. It must not be NULL or empty; otherwise, a default value will be used. The caller retains ownership of the string and must ensure it remains valid for the duration of its use.
- **Output**: None
- **See also**: [`fd_log_private_group_set`](fd_log.c.driver.md#fd_log_private_group_set)  (Implementation)


---
### fd\_log\_private\_user\_set<!-- {{#callable_declaration:fd_log_private_user_set}} -->
Sets the user description for logging.
- **Description**: This function is used to set the user description that will be associated with log messages. It should be called after the logging system has been initialized, and it allows the user to specify a custom user name for logging purposes. If the provided user name is NULL or an empty string, a default value of "[user]" will be used. The function does not retain ownership of the user name string after the call, and it is important to ensure that the string remains valid for the duration of its use.
- **Inputs**:
    - `user`: A pointer to a constant string representing the user description. This string must not be NULL or empty; if it is, a default value will be used. The caller retains ownership of the string and must ensure it remains valid for the duration of its use.
- **Output**: None
- **See also**: [`fd_log_private_user_set`](fd_log.c.driver.md#fd_log_private_user_set)  (Implementation)


---
### fd\_log\_private\_logfile\_fd<!-- {{#callable_declaration:fd_log_private_logfile_fd}} -->
Returns the file descriptor for the log file.
- **Description**: This function should be called after the logging system has been initialized to retrieve the file descriptor associated with the log file. It is useful for scenarios where direct manipulation of the log file is required, such as for custom logging or monitoring purposes. The function does not take any parameters and will return a valid file descriptor if the logging system is properly set up; otherwise, it may return an invalid descriptor.
- **Inputs**: None
- **Output**: Returns an integer representing the file descriptor for the log file. A valid file descriptor indicates that the log file is open and ready for writing.
- **See also**: [`fd_log_private_logfile_fd`](fd_log.c.driver.md#fd_log_private_logfile_fd)  (Implementation)


