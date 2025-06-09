# Purpose
This C header file, `fd_log_collector.h`, defines a logging system for a software component, likely part of a larger application or framework. The primary purpose of this file is to provide a structured way to collect, format, and store log messages, which are essential for debugging and monitoring the execution of programs. The file includes both internal functions and public APIs for initializing, managing, and deleting log collectors, as well as for logging messages in various formats. The logging system is designed to handle messages of different sizes and formats, including those that require serialization into a protocol buffer-like format. It also provides mechanisms to handle log truncation and to ensure that logs do not exceed predefined size limits.

The file is organized into several sections, each focusing on different aspects of logging. The internal functions, marked as not to be used directly, handle the low-level details of message serialization and storage. The public API functions provide higher-level interfaces for initializing log collectors, logging messages, and managing log buffers. The file also includes specialized functions for logging messages in specific contexts, such as program invocation, success, and failure, which are tailored to the needs of the application. Additionally, the file provides debugging utilities to inspect and print the contents of log buffers, aiding in the development and testing of the logging system. Overall, this header file is a comprehensive component of a logging framework, designed to be integrated into a larger system for effective log management and analysis.
# Imports and Dependencies

---
- `fd_log_collector_base.h`
- `../runtime/context/fd_exec_instr_ctx.h`
- `../runtime/context/fd_exec_txn_ctx.h`
- `../../ballet/base58/fd_base58.h`
- `../../ballet/base64/fd_base64.h`
- `stdio.h`
- `stdarg.h`


# Functions

---
### fd\_log\_collector\_private\_push<!-- {{#callable:fd_log_collector_private_push}} -->
The `fd_log_collector_private_push` function serializes a log message into a buffer with a specific format, updating the buffer size accordingly.
- **Inputs**:
    - `log`: A pointer to an `fd_log_collector_t` structure, which contains the buffer and its current size.
    - `msg`: A constant character pointer to the message string to be logged.
    - `msg_sz`: An unsigned long integer representing the size of the message to be logged.
- **Control Flow**:
    - Retrieve the buffer and its current size from the `log` structure.
    - Determine if the message size requires more than one byte for storage (i.e., if `msg_sz` is greater than 127).
    - Store a protocol tag and the message size in the buffer, using one or two bytes for the size depending on its value.
    - Calculate the starting position for the message in the buffer, accounting for the tag and size bytes.
    - Copy the message into the buffer starting at the calculated position.
    - Update the buffer size in the `log` structure to reflect the new total size after adding the message.
- **Output**: The function does not return a value; it modifies the `log` structure's buffer and size in place.


---
### fd\_log\_collector\_init<!-- {{#callable:fd_log_collector_init}} -->
The `fd_log_collector_init` function initializes a log collector by setting its buffer size, log size, warning flag, and enabling or disabling it based on the input parameter.
- **Inputs**:
    - `log`: A pointer to an `fd_log_collector_t` structure that represents the log collector to be initialized.
    - `enabled`: An integer flag indicating whether the log collector should be enabled (non-zero) or disabled (zero).
- **Control Flow**:
    - Set the `buf_sz` field of the `log` structure to 0, indicating an empty buffer.
    - Set the `log_sz` field of the `log` structure to 0, indicating no logs have been collected yet.
    - Set the `warn` field of the `log` structure to 0, indicating no warnings have been issued.
    - Set the `disabled` field of the `log` structure to the negation of the `enabled` parameter, effectively enabling or disabling the log collector.
- **Output**: The function does not return a value; it modifies the `fd_log_collector_t` structure pointed to by `log`.


---
### fd\_log\_collector\_check\_and\_truncate<!-- {{#callable:fd_log_collector_check_and_truncate}} -->
The `fd_log_collector_check_and_truncate` function checks if adding a new log message would exceed the maximum allowed log size and truncates the log if necessary, issuing a warning if truncation occurs.
- **Inputs**:
    - `log`: A pointer to an `fd_log_collector_t` structure representing the log collector.
    - `msg_sz`: The size of the message to be added to the log, in bytes.
- **Control Flow**:
    - Calculate the total bytes that would be written by adding `msg_sz` to the current log size using `fd_ulong_sat_add`.
    - Check if the calculated `bytes_written` exceeds `FD_LOG_COLLECTOR_MAX`.
    - If the log size exceeds the maximum and a warning has not been issued (`log->warn` is false), set `log->warn` to true and push a 'Log truncated' message using [`fd_log_collector_private_push`](#fd_log_collector_private_push).
    - Return `ULONG_MAX` if the log was truncated, otherwise return the calculated `bytes_written`.
- **Output**: Returns the total bytes written if the log is not truncated, or `ULONG_MAX` if truncation occurs.
- **Functions called**:
    - [`fd_log_collector_private_push`](#fd_log_collector_private_push)


---
### fd\_log\_collector\_delete<!-- {{#callable:fd_log_collector_delete}} -->
The `fd_log_collector_delete` function is a placeholder for deleting a log collector, but currently performs no operations.
- **Inputs**:
    - `log`: A constant pointer to an `fd_log_collector_t` structure, representing the log collector to be deleted.
- **Control Flow**:
    - The function takes a single argument, `log`, which is a pointer to a log collector structure.
    - The function body contains a single statement that casts the `log` argument to void, effectively ignoring it.
    - No other operations or logic are performed within the function.
- **Output**: The function does not produce any output or perform any actions.


---
### fd\_log\_collector\_msg<!-- {{#callable:fd_log_collector_msg}} -->
The `fd_log_collector_msg` function logs a message of a specified size to a log collector, ensuring it is not disabled and that the message size does not exceed the maximum allowed.
- **Inputs**:
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure, which contains the transaction context and log collector.
    - `msg`: A constant character pointer to the message to be logged.
    - `msg_sz`: An unsigned long integer representing the size of the message to be logged.
- **Control Flow**:
    - Retrieve the log collector from the transaction context within `ctx`.
    - Check if the log collector is disabled; if so, return immediately without logging.
    - Call [`fd_log_collector_check_and_truncate`](#fd_log_collector_check_and_truncate) to determine the number of bytes that can be written without exceeding the maximum log size.
    - If the number of bytes that can be written is less than `ULONG_MAX`, update the log size and push the message to the log using [`fd_log_collector_private_push`](#fd_log_collector_private_push).
- **Output**: The function does not return a value; it performs logging operations as a side effect.
- **Functions called**:
    - [`fd_log_collector_check_and_truncate`](#fd_log_collector_check_and_truncate)
    - [`fd_log_collector_private_push`](#fd_log_collector_private_push)


---
### fd\_log\_collector\_msg\_many<!-- {{#callable:fd_log_collector_msg_many}} -->
The `fd_log_collector_msg_many` function logs multiple message buffers by concatenating them and storing them in a log collector, handling potential overflow and serialization.
- **Inputs**:
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure, which contains the transaction context and log collector.
    - `num_buffers`: An integer representing the number of message buffer pairs (each consisting of a message and its size) to be logged.
    - `...`: A variadic list of arguments consisting of pairs of `char const *` (message) and `ulong` (size of the message) for each buffer to be logged.
- **Control Flow**:
    - Check if the log collector is disabled; if so, return immediately.
    - Initialize a variable argument list to process the message buffers.
    - Iterate over the number of buffers to calculate the total message size, using `fd_ulong_sat_add` to handle potential overflow.
    - Check if the total message size can be accommodated in the log collector using [`fd_log_collector_check_and_truncate`](#fd_log_collector_check_and_truncate); if not, return.
    - If the message can be logged, update the log size and prepare the buffer for storing the message, including a tag and size serialization.
    - Restart the variable argument list and iterate over the buffers again to copy each message into the log buffer, updating the buffer size accordingly.
- **Output**: The function does not return a value; it modifies the log collector's buffer and size to include the concatenated messages if logging is successful.
- **Functions called**:
    - [`fd_log_collector_check_and_truncate`](#fd_log_collector_check_and_truncate)


---
### fd\_log\_collector\_printf\_dangerous\_max\_127<!-- {{#callable:fd_log_collector_printf_dangerous_max_127}} -->
The function `fd_log_collector_printf_dangerous_max_127` logs a formatted message to a buffer, ensuring the message size does not exceed 127 bytes, and handles potential truncation.
- **Inputs**:
    - `ctx`: A pointer to `fd_exec_instr_ctx_t`, which contains the execution context including the log collector.
    - `fmt`: A constant character pointer representing the format string for the message to be logged.
    - `...`: A variable number of arguments that correspond to the format specifiers in the format string.
- **Control Flow**:
    - Check if the log collector is disabled; if so, return immediately.
    - Initialize a buffer pointer and buffer size from the log collector context.
    - Use `vsnprintf` to format the message into the buffer starting at an offset, ensuring it does not exceed the maximum allowed size (127 bytes).
    - Check if the message was truncated using a custom test macro; if truncated, report an error.
    - Determine the size of the message and check if it can be added to the log without exceeding the maximum log size using [`fd_log_collector_check_and_truncate`](#fd_log_collector_check_and_truncate).
    - If the message can be added, update the log size, store a tag and message size in the buffer, and update the buffer size.
- **Output**: The function does not return a value; it modifies the log collector's buffer and state to include the new log message if conditions are met.
- **Functions called**:
    - [`fd_log_collector_check_and_truncate`](#fd_log_collector_check_and_truncate)


---
### fd\_log\_collector\_printf\_dangerous\_128\_to\_2k<!-- {{#callable:fd_log_collector_printf_dangerous_128_to_2k}} -->
The function `fd_log_collector_printf_dangerous_128_to_2k` logs a formatted message into a buffer if the message size is between 128 and 2000 bytes, ensuring it does not exceed buffer limits.
- **Inputs**:
    - `ctx`: A pointer to `fd_exec_instr_ctx_t`, which contains the execution context including the transaction context and log collector.
    - `fmt`: A constant character pointer representing the format string for the message to be logged.
    - `...`: A variable number of arguments that are formatted according to the `fmt` string.
- **Control Flow**:
    - Check if the log collector is disabled; if so, return immediately.
    - Initialize a buffer pointer and buffer size from the log collector within the context.
    - Use `vsnprintf` to format the message into the buffer starting at an offset, ensuring it does not exceed the maximum size of 2000 bytes.
    - Check if the formatted message size is within the expected range (128 to 2000 bytes) using a custom test macro.
    - Determine the number of bytes that can be written without exceeding the log collector's maximum size using [`fd_log_collector_check_and_truncate`](#fd_log_collector_check_and_truncate).
    - If the message can be written, store a tag and the message size in the buffer, then update the buffer size.
- **Output**: The function does not return a value; it modifies the log collector's buffer and size if the message is successfully logged.
- **Functions called**:
    - [`fd_log_collector_check_and_truncate`](#fd_log_collector_check_and_truncate)


---
### fd\_log\_collector\_printf\_inefficient\_max\_512<!-- {{#callable:fd_log_collector_printf_inefficient_max_512}} -->
The function `fd_log_collector_printf_inefficient_max_512` logs a formatted message with a maximum size of 512 bytes using a temporary buffer.
- **Inputs**:
    - `ctx`: A pointer to `fd_exec_instr_ctx_t`, which provides the execution context for the log message.
    - `fmt`: A constant character pointer representing the format string for the message to be logged.
    - `...`: A variable number of arguments that correspond to the format specifiers in the format string.
- **Control Flow**:
    - Declare a character array `msg` of size 512 to hold the formatted message.
    - Initialize a `va_list` variable `ap` to handle the variable arguments.
    - Use `va_start` to initialize `ap` with the variable arguments starting after `fmt`.
    - Call `vsnprintf` to format the message into `msg` using `fmt` and `ap`, and store the size of the formatted message in `msg_sz`.
    - End the use of `ap` with `va_end`.
    - Check if `msg_sz` is non-negative and less than the size of `msg` using `FD_TEST_CUSTOM`, and log an error if the message was truncated.
    - Call [`fd_log_collector_msg`](#fd_log_collector_msg) to log the message using the context `ctx`, the message `msg`, and its size `msg_sz`.
- **Output**: The function does not return a value; it logs a formatted message to the log collector.
- **Functions called**:
    - [`fd_log_collector_msg`](#fd_log_collector_msg)


---
### fd\_log\_collector\_program\_invoke<!-- {{#callable:fd_log_collector_program_invoke}} -->
The `fd_log_collector_program_invoke` function logs the invocation of a program by encoding its program ID to Base58 and printing a formatted log message.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context for the instruction, including transaction context and program details.
- **Control Flow**:
    - Check if the log collector is disabled in the transaction context; if so, return immediately.
    - Retrieve the program ID public key from the transaction context's account keys using the program ID from the instruction context.
    - Encode the program ID public key to a Base58 string and store it in the `program_id_base58` field of the context.
    - Log a message using [`fd_log_collector_printf_dangerous_max_127`](#fd_log_collector_printf_dangerous_max_127), indicating the program invocation with the Base58 encoded program ID and the current depth of invocation.
- **Output**: The function does not return any value; it performs logging as a side effect.
- **Functions called**:
    - [`fd_log_collector_printf_dangerous_max_127`](#fd_log_collector_printf_dangerous_max_127)


---
### fd\_log\_collector\_program\_log<!-- {{#callable:fd_log_collector_program_log}} -->
The `fd_log_collector_program_log` function logs a message prefixed with 'Program log: ' using the log collector context.
- **Inputs**:
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure, which contains the execution context including the transaction context and log collector.
    - `msg`: A constant character pointer to the message string that needs to be logged.
    - `msg_sz`: An unsigned long integer representing the size of the message to be logged.
- **Control Flow**:
    - The function calls [`fd_log_collector_msg_many`](#fd_log_collector_msg_many) with the execution context, the number of message parts (2), and the message parts themselves ('Program log: ' and the provided message).
- **Output**: The function does not return any value; it performs logging as a side effect.
- **Functions called**:
    - [`fd_log_collector_msg_many`](#fd_log_collector_msg_many)


---
### fd\_log\_collector\_program\_return<!-- {{#callable:fd_log_collector_program_return}} -->
The `fd_log_collector_program_return` function logs the return data of a program in base64 format if logging is enabled.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context including transaction context and program ID.
- **Control Flow**:
    - Check if logging is disabled by evaluating `ctx->txn_ctx->log_collector.disabled`; if true, return immediately.
    - Calculate the base64 representation of the return data stored in `ctx->txn_ctx->return_data.data` and store it in `return_base64`.
    - Determine the size of the log message by adding the lengths of the program ID and the base64-encoded return data.
    - If the message size is less than or equal to 127, use [`fd_log_collector_printf_dangerous_max_127`](#fd_log_collector_printf_dangerous_max_127) to log the message; otherwise, use [`fd_log_collector_printf_dangerous_128_to_2k`](#fd_log_collector_printf_dangerous_128_to_2k).
- **Output**: The function does not return a value; it logs a message containing the program ID and base64-encoded return data if logging is enabled.
- **Functions called**:
    - [`fd_log_collector_printf_dangerous_max_127`](#fd_log_collector_printf_dangerous_max_127)
    - [`fd_log_collector_printf_dangerous_128_to_2k`](#fd_log_collector_printf_dangerous_128_to_2k)


---
### fd\_log\_collector\_program\_success<!-- {{#callable:fd_log_collector_program_success}} -->
The `fd_log_collector_program_success` function logs a success message for a program identified by its Base58 encoded ID.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context including the program's Base58 encoded ID.
- **Control Flow**:
    - The function constructs a log message indicating the success of a program using its Base58 encoded ID from the context.
    - It calls [`fd_log_collector_printf_dangerous_max_127`](#fd_log_collector_printf_dangerous_max_127) to log the message, ensuring the message size is within safe limits for this logging method.
- **Output**: The function does not return any value; it performs logging as a side effect.
- **Functions called**:
    - [`fd_log_collector_printf_dangerous_max_127`](#fd_log_collector_printf_dangerous_max_127)


---
### fd\_log\_collector\_program\_failure<!-- {{#callable:fd_log_collector_program_failure}} -->
The `fd_log_collector_program_failure` function logs a failure message for a program execution, detailing the error type and message if logging is enabled.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains the execution context including transaction context and program ID.
- **Control Flow**:
    - Check if logging is disabled using `FD_LIKELY`; if so, return immediately.
    - Declare external functions for error string retrieval: `fd_vm_ebpf_strerror`, `fd_vm_syscall_strerror`, and `fd_executor_instr_strerror`.
    - Initialize a buffer `custom_err` for custom error messages and set `err` to point to it.
    - Retrieve the transaction context from `ctx`.
    - Check if `txn_ctx->custom_err` is not `UINT_MAX`; if true, format a custom error message into `custom_err`.
    - If `txn_ctx->exec_err` is set, determine the error kind and retrieve the appropriate error message using the external functions.
    - Check if the error message `err` is not empty; if it is not, proceed to log the error message.
    - Format the error prefix with the program ID and check if the formatting was successful.
    - Log the complete error message using [`fd_log_collector_msg_many`](#fd_log_collector_msg_many) with the error prefix and error message.
- **Output**: The function does not return a value; it logs an error message if applicable.
- **Functions called**:
    - [`fd_log_collector_msg_many`](#fd_log_collector_msg_many)


---
### fd\_log\_collector\_program\_consumed<!-- {{#callable:fd_log_collector_program_consumed}} -->
The `fd_log_collector_program_consumed` function logs a message indicating the amount of compute units consumed by a program.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which contains context information for the execution instruction, including the program ID.
    - `consumed`: An unsigned long integer representing the number of compute units consumed by the program.
    - `total`: An unsigned long integer representing the total number of compute units available.
- **Control Flow**:
    - The function constructs a log message using the program ID from the context and the consumed and total compute units values.
    - It calls [`fd_log_collector_printf_dangerous_max_127`](#fd_log_collector_printf_dangerous_max_127) to log the message, ensuring the message size is less than 127 bytes.
- **Output**: The function does not return a value; it performs logging as a side effect.
- **Functions called**:
    - [`fd_log_collector_printf_dangerous_max_127`](#fd_log_collector_printf_dangerous_max_127)


---
### fd\_log\_collector\_debug\_get\_msg\_sz<!-- {{#callable:fd_log_collector_debug_get_msg_sz}} -->
The function `fd_log_collector_debug_get_msg_sz` calculates the size of a message from a buffer and updates the buffer pointer accordingly.
- **Inputs**:
    - `buf`: A pointer to a pointer to an unsigned char array, representing the buffer from which the message size is to be extracted.
- **Control Flow**:
    - Retrieve the first byte of the message size from the buffer and store it in `msg0`.
    - Retrieve the second byte of the message size from the buffer and store it in `msg1`.
    - Determine if the message size requires two bytes by checking if `msg0` is greater than 0x7F.
    - Calculate the message size using a conditional operation: if two bytes are needed, combine `msg1` and `msg0` to form the size; otherwise, use `msg0` as the size.
    - Update the buffer pointer to point to the next message by adding 2 plus the number of bytes used for the message size.
    - Return the calculated message size.
- **Output**: The function returns a `ushort` representing the size of the message extracted from the buffer.


---
### fd\_log\_collector\_debug\_len<!-- {{#callable:fd_log_collector_debug_len}} -->
The `fd_log_collector_debug_len` function calculates the number of log messages stored in a log collector's buffer.
- **Inputs**:
    - `log`: A pointer to a constant `fd_log_collector_t` structure, which contains the log buffer and its size.
- **Control Flow**:
    - Initialize a variable `len` to zero to keep track of the number of log messages.
    - Set a pointer `cur` to the start of the log buffer.
    - Iterate over the buffer until `cur` reaches the end of the buffer (`log->buf + log->buf_sz`).
    - In each iteration, call [`fd_log_collector_debug_get_msg_sz`](#fd_log_collector_debug_get_msg_sz) to get the size of the current log message and update `cur` to point to the next message.
    - Increment `len` for each message processed.
    - Return the total count of messages stored in `len`.
- **Output**: The function returns an `ulong` representing the number of log messages in the buffer.
- **Functions called**:
    - [`fd_log_collector_debug_get_msg_sz`](#fd_log_collector_debug_get_msg_sz)


---
### fd\_log\_collector\_debug\_get<!-- {{#callable:fd_log_collector_debug_get}} -->
The `fd_log_collector_debug_get` function retrieves a specific log message from a log collector buffer based on the log number provided.
- **Inputs**:
    - `log`: A pointer to a constant `fd_log_collector_t` structure representing the log collector from which the log message is to be retrieved.
    - `log_num`: An unsigned long integer representing the index of the log message to retrieve from the log collector.
    - `msg`: A pointer to a pointer to an unsigned char, which will be set to point to the start of the retrieved log message if not NULL.
    - `msg_sz`: A pointer to an unsigned long, which will be set to the size of the retrieved log message if not NULL.
- **Control Flow**:
    - Initialize `cur` to point to the start of the log buffer and `cur_sz` to 0.
    - Retrieve the size of the first log message using [`fd_log_collector_debug_get_msg_sz`](#fd_log_collector_debug_get_msg_sz) and update `cur` accordingly.
    - Iterate while `log_num` is greater than 0, moving `cur` to the next log message and updating `cur_sz` with the size of the current message, decrementing `log_num` each time.
    - If `msg` is not NULL, set it to point to the current log message.
    - If `msg_sz` is not NULL, set it to the size of the current log message.
    - Return a pointer to the start of the current log message.
- **Output**: A pointer to the start of the log message corresponding to the specified `log_num` in the log collector buffer.
- **Functions called**:
    - [`fd_log_collector_debug_get_msg_sz`](#fd_log_collector_debug_get_msg_sz)


---
### fd\_log\_collector\_debug\_sprintf<!-- {{#callable:fd_log_collector_debug_sprintf}} -->
The `fd_log_collector_debug_sprintf` function formats and outputs log messages from a log collector buffer into a string, optionally filtering out null characters.
- **Inputs**:
    - `log`: A pointer to a `fd_log_collector_t` structure containing the log buffer and its size.
    - `out`: A character array where the formatted log messages will be stored.
    - `filter_zero`: An integer flag indicating whether to filter out null characters (non-zero value) or not (zero value).
- **Control Flow**:
    - Initialize `out_sz` to 0 to track the size of the output string.
    - Set `pos` to 0 and `buf` to the start of the log buffer.
    - Enter a loop that continues while `pos` is less than the size of the log buffer.
    - Within the loop, read the size of the current log message using [`fd_log_collector_debug_get_msg_sz`](#fd_log_collector_debug_get_msg_sz).
    - If `filter_zero` is true, copy non-null characters from the log message to `out`, incrementing `out_sz` for each character.
    - If `filter_zero` is false, use `fd_memcpy` to copy the entire log message to `out`, updating `out_sz` accordingly.
    - Append a newline character to `out` and increment `out_sz`.
    - Advance `buf` by the size of the current log message and update `pos`.
    - After the loop, remove the last newline character by decrementing `out_sz` if it is non-zero.
    - Terminate the output string with a null character and return `out_sz`.
- **Output**: The function returns the size of the formatted output string, excluding the terminating null character.
- **Functions called**:
    - [`fd_log_collector_debug_get_msg_sz`](#fd_log_collector_debug_get_msg_sz)


---
### fd\_log\_collector\_private\_debug<!-- {{#callable:fd_log_collector_private_debug}} -->
The `fd_log_collector_private_debug` function formats and prints all logs from a log collector to the warning log output.
- **Inputs**:
    - `log`: A pointer to a constant `fd_log_collector_t` structure, which contains the logs to be formatted and printed.
- **Control Flow**:
    - Declare a character array `out` with a size of `FD_LOG_COLLECTOR_MAX + FD_LOG_COLLECTOR_EXTRA`.
    - Call [`fd_log_collector_debug_sprintf`](#fd_log_collector_debug_sprintf) with `log`, `out`, and `1` as arguments to format the logs into the `out` buffer, filtering out zero bytes.
    - Use `FD_LOG_WARNING` to print the formatted logs enclosed within '-----' lines to the warning log output.
- **Output**: The function does not return any value; it outputs the formatted logs to the warning log.
- **Functions called**:
    - [`fd_log_collector_debug_sprintf`](#fd_log_collector_debug_sprintf)


# Function Declarations (Public API)

---
### fd\_log\_collector\_private\_debug<!-- {{#callable_declaration:fd_log_collector_private_debug}} -->
Prints all logs from the log collector.
- **Description**: This function is used to print all logs collected in a log collector instance. It is intended for internal use only and should not be called directly by external code. The function formats the logs into a string and outputs them with warning log level. It is typically used for debugging purposes to inspect the contents of the log collector.
- **Inputs**:
    - `log`: A pointer to a constant fd_log_collector_t structure. It must not be null, and the caller retains ownership of the log collector. The function assumes the log collector has been properly initialized and contains valid log data.
- **Output**: None
- **See also**: [`fd_log_collector_private_debug`](#fd_log_collector_private_debug)  (Implementation)


