# Purpose
This C header file, `monitor_helper.h`, provides a collection of utility functions and macros designed for terminal output formatting and diagnostics in a monitoring application. It includes macros for terminal text manipulation, such as hiding and showing the cursor, erasing lines, and applying color codes to text for enhanced readability. The file defines several `printf_*` functions that format and print various types of diagnostic information, such as time intervals, heartbeats, signals, error conditions, sequence numbers, and rates, all with specific width and color coding for clarity. Additionally, it includes a function for non-blocking character input from the standard input stream. The header is intended to facilitate quick and visually distinct output in terminal-based monitoring tools, though it acknowledges the need for more robust solutions in the future.
# Imports and Dependencies

---
- `../../../../util/fd_util.h`


# Global Variables

---
### sig\_color
- **Type**: `function`
- **Description**: The `sig_color` function is a global function that takes an unsigned long integer `sig` as an argument and returns a constant character pointer. This function is likely used to determine the color representation of a signal based on its value, as suggested by its name and the context of the surrounding code, which involves color-coded output.
- **Use**: This function is used to obtain a color code string for a given signal value, which can be used in color-coded terminal output.


# Function Declarations (Public API)

---
### printf\_age<!-- {{#callable_declaration:printf_age}} -->
Prints a formatted representation of a time duration to stdout.
- **Description**: This function is used to print a time duration, specified in nanoseconds, to the standard output in a human-readable format. The output is always exactly 10 characters wide, ensuring consistent alignment in text displays. The function handles various time units, from nanoseconds to weeks, and rounds the duration towards zero when necessary. It is important to note that negative durations are considered invalid and will result in the output 'invalid'. This function is useful for displaying time intervals in a clear and concise manner, especially in monitoring or logging applications.
- **Inputs**:
    - `buf`: A pointer to a character buffer pointer, which is not used in this function. The caller retains ownership.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer, which is not used in this function. The caller retains ownership.
    - `_dt`: A long integer representing the time duration in nanoseconds. Must be non-negative; negative values are treated as invalid and result in the output 'invalid'.
- **Output**: None
- **See also**: [`printf_age`](helper.c.driver.md#printf_age)  (Implementation)


---
### printf\_stale<!-- {{#callable_declaration:printf_stale}} -->
Prints the age in a color-coded format if it exceeds a specified expiration threshold.
- **Description**: Use this function to conditionally print an age value in a visually distinct format when it exceeds a given expiration threshold. This is useful for monitoring scenarios where only significant age values should be highlighted to reduce visual clutter. The function outputs a 10-character wide, color-coded string to standard output, using yellow for ages exceeding the threshold and green for those that do not. Ensure that the buffer and its size are correctly managed by the caller, as they are passed by reference.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted output may be stored. The caller retains ownership and must ensure it is valid.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer. The caller retains ownership and must ensure it is valid.
    - `age`: A long integer representing the age to be printed. It is compared against the expiration threshold.
    - `expire`: A long integer representing the expiration threshold. If the age exceeds this value, it will be printed in a highlighted format.
- **Output**: None
- **See also**: [`printf_stale`](helper.c.driver.md#printf_stale)  (Implementation)


---
### printf\_heart<!-- {{#callable_declaration:printf_heart}} -->
Prints a color-coded heartbeat status to stdout.
- **Description**: This function is used to print a visual representation of a heartbeat status to the standard output. It determines whether a heartbeat is detected, not detected, or reset by comparing two heartbeat timestamps. The output is exactly 5 characters wide and uses color coding to indicate the status: green for detected, red for none, and blue for reset. This function is useful for monitoring applications where visual feedback on heartbeat status is required. It does not modify the input parameters or return any value.
- **Inputs**:
    - `buf`: A pointer to a character buffer, which is not used in this function. The caller retains ownership and it can be null.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer, which is not used in this function. The caller retains ownership and it can be null.
    - `hb_now`: A long integer representing the current heartbeat timestamp. It is used to determine the heartbeat status.
    - `hb_then`: A long integer representing the previous heartbeat timestamp. It is used to determine the heartbeat status.
- **Output**: None
- **See also**: [`printf_heart`](helper.c.driver.md#printf_heart)  (Implementation)


---
### sig\_color<!-- {{#callable_declaration:sig_color}} -->
Returns a terminal color code string based on the signal value.
- **Description**: Use this function to obtain a terminal color code string that corresponds to a specific signal value, which can be used for color-coding terminal output. The function maps predefined signal constants to specific color codes, providing a visual representation of different signal states. If the signal value does not match any known signal, a default normal text color code is returned. This function is useful for applications that need to visually differentiate between various operational states using terminal colors.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signal value. It should correspond to one of the predefined signal constants (e.g., FD_CNC_SIGNAL_BOOT, FD_CNC_SIGNAL_HALT, FD_CNC_SIGNAL_RUN, FD_CNC_SIGNAL_FAIL). If the value does not match any known signal, the function returns a normal text color code.
- **Output**: A constant character pointer to a string representing the terminal color code associated with the given signal. If the signal is unknown, it returns the normal text color code.
- **See also**: [`sig_color`](helper.c.driver.md#sig_color)  (Implementation)


---
### printf\_sig<!-- {{#callable_declaration:printf_sig}} -->
Prints the current and previous CNC signal values to stdout.
- **Description**: This function is used to display the current and previous values of a CNC signal in a color-coded format, ensuring that the output is exactly 10 characters wide. It is useful for monitoring changes in signal values over time. The function does not modify the input parameters or return any value, and it is expected to be called when the signal values need to be logged or displayed for diagnostic purposes.
- **Inputs**:
    - `buf`: A pointer to a character buffer pointer, which is not used or modified by this function. The caller retains ownership.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer, which is not used or modified by this function. The caller retains ownership.
    - `sig_now`: An unsigned long representing the current signal value. It must be a valid signal value for proper color coding.
    - `sig_then`: An unsigned long representing the previous signal value. It must be a valid signal value for proper color coding.
- **Output**: None
- **See also**: [`printf_sig`](helper.c.driver.md#printf_sig)  (Implementation)


---
### printf\_err\_bool<!-- {{#callable_declaration:printf_err_bool}} -->
Prints a color-coded error status comparison to stdout.
- **Description**: This function is used to display a boolean error status for two different time points, 'now' and 'then', in a color-coded format. It prints a 12-character wide output to the standard output, where each status is represented as 'err' in red if an error is present, or '-' in green if no error is detected. This function is useful for monitoring and debugging purposes, providing a quick visual indication of error states over time. It should be called when you need to compare and display the error status at two different instances.
- **Inputs**:
    - `buf`: A pointer to a character buffer, which is not used in this function. The caller retains ownership.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer, which is not used in this function. The caller retains ownership.
    - `err_now`: An unsigned long representing the current error status. A non-zero value indicates an error, while zero indicates no error.
    - `err_then`: An unsigned long representing the previous error status. A non-zero value indicates an error, while zero indicates no error.
- **Output**: None
- **See also**: [`printf_err_bool`](helper.c.driver.md#printf_err_bool)  (Implementation)


---
### printf\_err\_cnt<!-- {{#callable_declaration:printf_err_cnt}} -->
Prints the current and previous error counts with color-coded changes.
- **Description**: Use this function to display the current and previous error counts in a color-coded format to indicate changes. It is useful for monitoring error count trends over time. The function prints the current count and the difference between the current and previous counts, using different colors to represent no change, an increase, a decrease, or a reset in the error count. This function is intended for use in environments where visual feedback on error trends is beneficial.
- **Inputs**:
    - `buf`: A pointer to a character buffer, which is not used in this function. The caller retains ownership.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer, which is not used in this function. The caller retains ownership.
    - `cnt_now`: The current error count as an unsigned long. It represents the latest error count to be displayed.
    - `cnt_then`: The previous error count as an unsigned long. It represents the error count from a prior time to compare against the current count.
- **Output**: None
- **See also**: [`printf_err_cnt`](helper.c.driver.md#printf_err_cnt)  (Implementation)


---
### printf\_seq<!-- {{#callable_declaration:printf_seq}} -->
Prints a 64-bit sequence number and its change to stdout.
- **Description**: This function is used to display a 64-bit sequence number and the difference between its current and previous values, formatted to be exactly 25 characters wide and color-coded for easy visual interpretation. It is useful for monitoring sequence number changes in applications where such tracking is necessary. The function should be called with valid sequence numbers, and it will handle cases where the sequence number has not changed, has increased, decreased, or reset, by using different colors to indicate each state.
- **Inputs**:
    - `buf`: A pointer to a character buffer pointer, which is not used in this function. The caller retains ownership.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer, which is not used in this function. The caller retains ownership.
    - `seq_now`: The current sequence number as an unsigned long. It should be a valid 64-bit sequence number.
    - `seq_then`: The previous sequence number as an unsigned long. It should be a valid 64-bit sequence number.
- **Output**: None
- **See also**: [`printf_seq`](helper.c.driver.md#printf_seq)  (Implementation)


---
### printf\_rate<!-- {{#callable_declaration:printf_rate}} -->
Prints a calculated rate to stdout with engineering suffixes.
- **Description**: This function calculates a rate based on the provided conversion factor, overhead, and count differences over a time interval, and prints it to stdout using engineering notation with appropriate suffixes (e.g., K, M, G). It is intended for diagnostic purposes where a wide dynamic range is needed. The function expects valid input values, such as a positive conversion factor and time interval, and a non-negative overhead. If the input values are invalid or result in an overflow, the function will print an error message and return without performing further operations.
- **Inputs**:
    - `buf`: A pointer to a buffer pointer, which is not used in this function. The caller retains ownership.
    - `buf_sz`: A pointer to a buffer size, which is not used in this function. The caller retains ownership.
    - `cvt`: A double representing the conversion factor. Must be greater than 0 and less than or equal to DBL_MAX. Invalid values will cause the function to print an error and return.
    - `overhead`: A double representing the overhead. Must be non-negative and less than or equal to DBL_MAX. Invalid values will cause the function to print an error and return.
    - `cnt_now`: An unsigned long representing the current count. Must be greater than or equal to cnt_then. Invalid values will cause the function to print an error and return.
    - `cnt_then`: An unsigned long representing the previous count. Must be less than or equal to cnt_now.
    - `dt`: A long representing the time interval. Must be positive. Invalid values will cause the function to print an error and return.
- **Output**: None
- **See also**: [`printf_rate`](helper.c.driver.md#printf_rate)  (Implementation)


---
### printf\_pct<!-- {{#callable_declaration:printf_pct}} -->
Prints the percentage change between two values to stdout.
- **Description**: This function calculates and prints the percentage change between two sets of values, `num_now` and `num_then` for the numerator, and `den_now` and `den_then` for the denominator, to the standard output. It is used when you need to display the percentage change in a formatted manner. The function checks for valid input ranges and handles potential overflow conditions. If the percentage is valid and within the range of 0 to 999.999, it prints the percentage with three decimal places; otherwise, it prints '>999.999'. The function does not modify the input parameters or return any value.
- **Inputs**:
    - `buf`: A pointer to a character buffer. This parameter is not used in the function, but it is part of the function signature. The caller retains ownership.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer. This parameter is not used in the function, but it is part of the function signature. The caller retains ownership.
    - `num_now`: An unsigned long representing the current numerator value. Must be greater than or equal to `num_then`.
    - `num_then`: An unsigned long representing the previous numerator value. Used to calculate the change in the numerator.
    - `lhopital_num`: A double representing an adjustment to the numerator. Must be between 0 and DBL_MAX inclusive.
    - `den_now`: An unsigned long representing the current denominator value. Must be greater than or equal to `den_then`.
    - `den_then`: An unsigned long representing the previous denominator value. Used to calculate the change in the denominator.
    - `lhopital_den`: A double representing an adjustment to the denominator. Must be greater than 0 and less than or equal to DBL_MAX.
- **Output**: None
- **See also**: [`printf_pct`](helper.c.driver.md#printf_pct)  (Implementation)


---
### fd\_getchar<!-- {{#callable_declaration:fd_getchar}} -->
Perform a non-blocking read of one byte from stdin.
- **Description**: Use this function to attempt reading a single byte from the standard input without blocking the execution. It is useful in scenarios where you need to check for user input availability without pausing the program flow. The function should be called when you want to handle input asynchronously or in a non-blocking manner. It returns a value indicating the result of the read operation, which can be used to determine if input was available or if the read was unsuccessful.
- **Inputs**: None
- **Output**: Returns an integer representing the byte read from stdin in the range [1, 256) if successful. Returns 0 if stdin is not ready for reading or if a null byte is read.
- **See also**: [`fd_getchar`](helper.c.driver.md#fd_getchar)  (Implementation)


