# Purpose
This C source code file provides a collection of utility functions primarily focused on formatted output and signal handling, likely intended for use in a larger system that involves monitoring or logging activities. The file includes functions for printing formatted representations of time intervals ([`printf_age`](#printf_age)), signal states ([`printf_sig`](#printf_sig)), error counts ([`printf_err_cnt`](#printf_err_cnt)), and other metrics such as rates ([`printf_rate`](#printf_rate)) and percentages ([`printf_pct`](#printf_pct)). These functions utilize a macro `PRINT` to safely format and append strings to a buffer, ensuring that the buffer is not overflowed or truncated. The code also includes a function [`fd_getchar`](#fd_getchar) that reads a character from standard input using non-blocking I/O, which is useful for interactive applications that need to handle user input without pausing execution.

The file imports several headers, including system headers for time and I/O operations, as well as custom headers that suggest integration with a larger framework or application (e.g., `fd_sys_util.h`, `fd_cnc.h`). The functions in this file are designed to be used as part of a broader application, providing specific utilities for formatting and displaying data in a human-readable form, with color-coded output to indicate different states or conditions. This suggests that the file is part of a diagnostic or monitoring toolset, where clear and concise output is crucial for understanding system behavior. The use of color codes and formatted output indicates a focus on user-friendly presentation of data, likely for debugging or operational monitoring purposes.
# Imports and Dependencies

---
- `helper.h`
- `../../../platform/fd_sys_util.h`
- `../../../../tango/cnc/fd_cnc.h`
- `sys/time.h`
- `sys/select.h`
- `stdio.h`
- `errno.h`
- `unistd.h`


# Functions

---
### printf\_age<!-- {{#callable:printf_age}} -->
The `printf_age` function formats a given time duration in nanoseconds into a human-readable string representation, adjusting the units from nanoseconds up to weeks as necessary.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted string will be written.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `_dt`: A long integer representing the time duration in nanoseconds to be formatted.
- **Control Flow**:
    - Check if the input duration `_dt` is negative; if so, print 'invalid' and return.
    - Check if `_dt` is zero; if so, print '0s' and return.
    - Convert `_dt` to an unsigned long `rem` and calculate the remainder in nanoseconds, microseconds, milliseconds, seconds, minutes, hours, days, and weeks, adjusting `rem` accordingly at each step.
    - For each unit, if the remaining time `rem` is zero, print the formatted string for that unit and return.
    - If the duration is greater than 99 weeks, print the formatted string for weeks and days.
- **Output**: The function outputs a formatted string representing the time duration in the most appropriate unit, written to the buffer pointed to by `buf`.


---
### printf\_stale<!-- {{#callable:printf_stale}} -->
The `printf_stale` function formats and prints a message indicating whether a given age is stale compared to an expiration threshold, using color-coded text.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted output will be written.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `age`: A long integer representing the age to be compared against the expiration threshold.
    - `expire`: A long integer representing the expiration threshold.
- **Control Flow**:
    - Check if the age is greater than the expiration threshold using `FD_UNLIKELY` for branch prediction optimization.
    - If the age is greater than the expiration threshold, print the age in yellow text using the [`printf_age`](#printf_age) function and reset the text color to normal.
    - If the age is not greater than the expiration threshold, print a green dash to indicate that the age is not stale.
- **Output**: The function does not return a value; it writes formatted output to the provided buffer.
- **Functions called**:
    - [`printf_age`](#printf_age)


---
### printf\_heart<!-- {{#callable:printf_heart}} -->
The `printf_heart` function formats and appends a status message to a buffer based on the difference between two heartbeat timestamps.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted message will be appended.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `hb_now`: A long integer representing the current heartbeat timestamp.
    - `hb_then`: A long integer representing the previous heartbeat timestamp.
- **Control Flow**:
    - Calculate the difference `dt` between `hb_now` and `hb_then`.
    - Use a ternary operator to determine the status message based on the value of `dt`:
    - If `dt` is greater than 0, append a green "-" to the buffer.
    - If `dt` is equal to 0, append a red "NONE" to the buffer.
    - If `dt` is less than 0, append a blue "RESET" to the buffer.
    - Use the `PRINT` macro to format and append the message to the buffer, updating the buffer pointer and size accordingly.
- **Output**: The function does not return a value; it modifies the buffer in place to include the formatted status message.


---
### sig\_color<!-- {{#callable:sig_color}} -->
The `sig_color` function returns a color code string based on the provided signal value.
- **Inputs**:
    - `sig`: An unsigned long integer representing a signal value.
- **Control Flow**:
    - The function uses a switch statement to determine the color code based on the signal value.
    - If the signal is `FD_CNC_SIGNAL_BOOT`, it returns `TEXT_BLUE`.
    - If the signal is `FD_CNC_SIGNAL_HALT`, it returns `TEXT_YELLOW`.
    - If the signal is `FD_CNC_SIGNAL_RUN`, it returns `TEXT_GREEN`.
    - If the signal is `FD_CNC_SIGNAL_FAIL`, it returns `TEXT_RED`.
    - For any other signal value, it defaults to returning `TEXT_NORMAL`.
- **Output**: A constant character pointer to a string representing the color code associated with the signal.


---
### printf\_sig<!-- {{#callable:printf_sig}} -->
The `printf_sig` function formats and appends a colored string representation of two signal states to a buffer.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted string will be appended.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `sig_now`: An unsigned long representing the current signal state.
    - `sig_then`: An unsigned long representing the previous signal state.
- **Control Flow**:
    - Declare two character arrays, `buf0` and `buf1`, each with a size of `FD_CNC_SIGNAL_CSTR_BUF_MAX`.
    - Use the `PRINT` macro to format a string that includes the colored current and previous signal states, and append it to the buffer pointed to by `buf`.
    - The [`sig_color`](#sig_color) function is used to determine the color associated with each signal state, and `fd_cnc_signal_cstr` is used to convert the signal states to string representations.
- **Output**: The function does not return a value; it modifies the buffer pointed to by `buf` to include the formatted string.
- **Functions called**:
    - [`sig_color`](#sig_color)


---
### printf\_err\_bool<!-- {{#callable:printf_err_bool}} -->
The `printf_err_bool` function formats and appends a string to a buffer indicating the error status of two boolean values, using color-coded text for visual distinction.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted string will be appended.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `err_now`: An unsigned long representing the current error status, where a non-zero value indicates an error.
    - `err_then`: An unsigned long representing the previous error status, where a non-zero value indicates an error.
- **Control Flow**:
    - The function uses a macro `PRINT` to format a string based on the values of `err_now` and `err_then`.
    - If `err_now` is non-zero, it appends 'err' in red text to the buffer; otherwise, it appends '-' in green text.
    - If `err_then` is non-zero, it appends 'err' in red text to the buffer; otherwise, it appends '-' in green text.
    - The formatted string is appended to the buffer, and the buffer pointer and size are updated accordingly.
- **Output**: The function does not return a value; it modifies the buffer in place to include the formatted error status string.


---
### printf\_err\_cnt<!-- {{#callable:printf_err_cnt}} -->
The `printf_err_cnt` function formats and prints the current error count and its change from a previous count, using color coding to indicate the nature of the change.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted output will be written.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `cnt_now`: The current error count as an unsigned long.
    - `cnt_then`: The previous error count as an unsigned long.
- **Control Flow**:
    - Calculate the difference `delta` between `cnt_now` and `cnt_then` as a signed long.
    - Determine the color for the output based on the value of `delta`: green for no change, red for an increase, yellow for a decrease, and blue for a reset.
    - Check if `delta` is greater than 99999 or less than -99999, and print the current count with a capped delta value and the appropriate color.
    - If `delta` is within the range of -99999 to 99999, print the current count with the actual delta value and the appropriate color.
- **Output**: The function outputs a formatted string to the buffer, indicating the current error count and its change, with color coding to represent the nature of the change.


---
### printf\_seq<!-- {{#callable:printf_seq}} -->
The `printf_seq` function formats and prints the current sequence number and its change from a previous sequence number, using color coding to indicate the nature of the change.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted output will be written.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `seq_now`: The current sequence number as an unsigned long.
    - `seq_then`: The previous sequence number as an unsigned long.
- **Control Flow**:
    - Calculate the difference `delta` between `seq_now` and `seq_then`.
    - Determine the color for the output based on the value of `delta`: yellow for no change, green for an increase, red for a decrease, and blue for a reset.
    - Check if `delta` is greater than 99999 or less than -99999, and print the sequence number with a corresponding message if so.
    - If `delta` is within the range of -99999 to 99999, print the sequence number and the delta value with the appropriate color.
- **Output**: The function outputs a formatted string to the buffer, indicating the current sequence number and its change from the previous number, with color coding to represent the change type.


---
### printf\_rate<!-- {{#callable:printf_rate}} -->
The `printf_rate` function calculates and formats a rate based on input parameters and prints it with appropriate units.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted output will be written.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `cvt`: A double representing the conversion factor for the rate calculation.
    - `overhead`: A double representing the overhead to be added to the rate calculation.
    - `cnt_now`: An unsigned long representing the current count value.
    - `cnt_then`: An unsigned long representing the previous count value.
    - `dt`: A long representing the time difference over which the rate is calculated.
- **Control Flow**:
    - Check if the input parameters are valid; if not, print 'invalid' and return.
    - Calculate the rate using the formula `cvt * (overhead + (cnt_now - cnt_then)) / dt`.
    - Check if the calculated rate is valid; if not, print 'overflow' and return.
    - Format the rate with appropriate units (e.g., '', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y') based on its magnitude and print it.
    - If the rate exceeds 9999.9Y, print '>9999.9Y'.
- **Output**: The function does not return a value; it writes the formatted rate to the provided buffer.


---
### printf\_pct<!-- {{#callable:printf_pct}} -->
The `printf_pct` function calculates and prints the percentage change between two sets of numbers, with additional adjustments, while handling potential errors and overflow conditions.
- **Inputs**:
    - `buf`: A pointer to a character buffer where the formatted output will be written.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer.
    - `num_now`: The current numerator value as an unsigned long.
    - `num_then`: The previous numerator value as an unsigned long.
    - `lhopital_num`: A double representing an adjustment to the numerator, used in L'Hôpital's rule.
    - `den_now`: The current denominator value as an unsigned long.
    - `den_then`: The previous denominator value as an unsigned long.
    - `lhopital_den`: A double representing an adjustment to the denominator, used in L'Hôpital's rule.
- **Control Flow**:
    - Check if any of the following conditions are true: `num_now` is less than `num_then`, `den_now` is less than `den_then`, `lhopital_num` is not between 0 and `DBL_MAX`, or `lhopital_den` is not between 0 and `DBL_MAX`. If any condition is true, print 'invalid' in red text and return.
    - Calculate the percentage change using the formula: `100 * (((double)(num_now - num_then) + lhopital_num) / ((double)(den_now - den_then) + lhopital_den))`.
    - Check if the calculated percentage is not between 0 and `DBL_MAX`. If true, print 'overflow' in red text and return.
    - If the percentage is less than or equal to 999.999, print the percentage formatted to three decimal places.
    - If the percentage is greater than 999.999, print '>999.999'.
- **Output**: The function does not return a value; it writes formatted output to the provided buffer.


---
### fd\_getchar<!-- {{#callable:fd_getchar}} -->
The `fd_getchar` function attempts to read a single character from the standard input without blocking.
- **Inputs**: None
- **Control Flow**:
    - Initialize a file descriptor set `read_fds` and `except_fds` to monitor standard input for readability and exceptional conditions.
    - Set a zero timeout for the `select` call to ensure non-blocking behavior.
    - Call `select` to check if standard input is ready for reading or has an exceptional condition, logging an error if `select` fails.
    - If standard input is ready or has an exceptional condition, attempt to read one character from it into `ch`.
    - Log an error if the `read` call fails, or exit the process if `read` returns zero, indicating EOF.
    - Return the character read from standard input, or zero if no character was read.
- **Output**: The function returns the character read from standard input as an integer, or zero if no character was available.


