# Purpose
This C source code file is designed to monitor and display performance metrics for an AWS-F1 FPGA system, likely in a network or data processing context. The code includes functionality to read and display various hardware counters, which are used to track data rates and other performance indicators. The file includes several key components: a `state_t` structure to maintain the state of the monitoring process, functions to handle timing and signal interruptions, and a thread function [`mon_thread`](#mon_thread) that periodically updates and displays the performance metrics. The code uses ANSI escape codes to format the output in the terminal, providing a visual representation of the data flow and performance statistics.

The file is not a standalone executable but rather a component of a larger system, as indicated by the inclusion of external headers and the use of external functions like [`_wd_read_32`](#_wd_read_32). It defines internal functions and structures that are likely used by other parts of the system to facilitate monitoring and debugging. The code is focused on providing a real-time, text-based interface for observing the performance of the FPGA and associated components, making it a specialized tool for system administrators or developers working with AWS-F1 FPGA instances.
# Imports and Dependencies

---
- `string.h`
- `stdio.h`
- `stdlib.h`
- `sys/mman.h`
- `time.h`
- `signal.h`
- `unistd.h`
- `pthread.h`
- `wd_f1_mon.h`


# Global Variables

---
### keepRunning
- **Type**: `int`
- **Description**: The `keepRunning` variable is a static volatile integer initialized to 1. It is used as a flag to control the execution of a loop or process, indicating whether it should continue running or not.
- **Use**: This variable is used to signal the termination of a process or loop when set to 0, typically in response to an interrupt or signal handler.


---
### \_state\_p
- **Type**: `state_t*`
- **Description**: The variable `_state_p` is a pointer to a `state_t` structure, which contains various fields such as counters for received and sent data, running status flags, a slot identifier, and a workspace structure `wd_wksp_t`. This structure is likely used to manage and track the state of a system or process, particularly in a context involving data transmission and reception.
- **Use**: This variable is used to access and manipulate the state information of the system, including counters and status flags, within various functions in the program.


---
### ascii\_chart
- **Type**: `char*[]`
- **Description**: The `ascii_chart` variable is a global array of strings, where each string represents a line of an ASCII art diagram. This diagram visually represents the architecture and data flow of an AWS-F1 FPGA and x86 system, including components like Scheduler, SHA-MOD, Parser, Sigverify, and Reorder, among others.
- **Use**: This variable is used to store and display an ASCII representation of the system architecture and data flow in the program.


---
### cnt\_data
- **Type**: `uint32_t[][]`
- **Description**: The `cnt_data` variable is a two-dimensional array of unsigned 32-bit integers, where each row represents a set of parameters for a specific counter or rate measurement. Each row contains seven elements that specify details such as line and column positions, counter type, color, print width, hardware counter index, and PCIe slot.
- **Use**: This variable is used to store and manage configuration data for various counters and rates, which are then processed and displayed in a formatted manner.


# Data Structures

---
### state\_t
- **Type**: `struct`
- **Members**:
    - `recv_cnt`: An array of two 64-bit unsigned integers to track received counts.
    - `send_cnt`: A 64-bit unsigned integer to track the sent count.
    - `running`: A 32-bit unsigned integer indicating if the state is currently running.
    - `running_recv`: A 32-bit unsigned integer indicating if the receiving process is running.
    - `slot`: A 32-bit unsigned integer representing a slot identifier.
    - `wd`: A wd_wksp_t type representing a workspace or context for operations.
- **Description**: The `state_t` structure is designed to maintain the state of a system, particularly in a context involving data transmission and reception. It includes counters for tracking the number of received and sent data packets, flags to indicate the running status of the system and its receiving process, and a slot identifier for managing different operational contexts. Additionally, it contains a `wd_wksp_t` member, which likely serves as a workspace or context for managing operations related to the system's functionality.


# Functions

---
### tiff<!-- {{#callable:tiff}} -->
The `tiff` function calculates the time difference in seconds between two `timespec` structures.
- **Inputs**:
    - `t0`: A `struct timespec` representing the starting time.
    - `t1`: A `struct timespec` representing the ending time.
- **Control Flow**:
    - Calculate the difference in seconds between `t1` and `t0` by subtracting `t0.tv_sec` from `t1.tv_sec`.
    - Calculate the difference in nanoseconds between `t1` and `t0` by subtracting `t0.tv_nsec` from `t1.tv_nsec`.
    - Convert the nanoseconds difference to seconds by multiplying by `1e-9` and add it to the seconds difference.
    - Return the total time difference as a `double`.
- **Output**: A `double` representing the time difference in seconds between `t0` and `t1`.


---
### print\_counters<!-- {{#callable:print_counters}} -->
The `print_counters` function iterates over a set of counters and prints their values using a formatted string.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure, which represents the workspace containing the counters to be printed.
- **Control Flow**:
    - The function enters a for loop that iterates 16 times, corresponding to the indices of the counters.
    - In each iteration, it calls `wd_rd_cntr` to read the counter value at the current index `i` from the workspace `wd` and the slot specified in the global `_state_p` structure.
    - It then prints the counter index and its value in a formatted string using `wd_zprintf`.
- **Output**: The function does not return a value; it outputs formatted counter information to the standard output.


---
### intHandler<!-- {{#callable:intHandler}} -->
The `intHandler` function is a signal handler that stops the running state of a process and prints diagnostic information.
- **Inputs**:
    - `dummy`: An integer parameter that is not used in the function body, typically used to match the signature required for signal handlers.
- **Control Flow**:
    - The function begins by casting the input parameter 'dummy' to void to indicate it is unused.
    - A newline character is printed to the console.
    - The function [`print_counters`](#print_counters) is called with a pointer to the `wd` field of the global `_state_p` structure, which prints hardware counters.
    - The global variable `keepRunning` is set to 0, indicating that the process should stop running.
    - The `running` field of the global `_state_p` structure is set to 0, indicating that the process is no longer running.
- **Output**: The function does not return any value as it is a void function.
- **Functions called**:
    - [`print_counters`](#print_counters)


---
### ascii\_move\_to<!-- {{#callable:ascii_move_to}} -->
The `ascii_move_to` function moves the cursor position in a terminal from a starting coordinate to a target coordinate using ANSI escape codes.
- **Inputs**:
    - `from`: An array of two uint32_t values representing the starting row and column coordinates.
    - `to`: An array of two uint32_t values representing the target row and column coordinates.
- **Control Flow**:
    - Check if the starting row (from[0]) is less than the target row (to[0]); if true, move the cursor down by the difference using the ANSI escape code for moving down (\033[%dB).
    - If the starting row is greater than the target row, move the cursor up by the difference using the ANSI escape code for moving up (\033[%dA).
    - Check if the starting column (from[1]) is less than the target column (to[1]); if true, move the cursor right by the difference using the ANSI escape code for moving right (\033[%dC).
    - If the starting column is greater than the target column, move the cursor left by the difference using the ANSI escape code for moving left (\033[%dD).
- **Output**: The function does not return a value; it outputs ANSI escape codes to the terminal to move the cursor.


---
### ascii\_color<!-- {{#callable:ascii_color}} -->
The `ascii_color` function sets the terminal text color based on a given color code using ANSI escape sequences.
- **Inputs**:
    - `col`: A 32-bit unsigned integer representing the color code to set the terminal text color.
- **Control Flow**:
    - The function uses a switch statement to determine the action based on the value of `col`.
    - If `col` is 0, it resets the text color to default using `\033[0m`.
    - If `col` is 1, it sets the text color to green using `\033[32m`.
    - If `col` is 2, it sets the text color to yellow using `\033[33m`.
    - If `col` is 3, it sets the text color to red using `\033[31m`.
    - If `col` is 4, it sets the text color to magenta using `\033[35m`.
- **Output**: The function does not return a value; it directly affects the terminal output by changing the text color.


---
### pretty\_num<!-- {{#callable:pretty_num}} -->
The `pretty_num` function formats a given count into a human-readable string with appropriate suffixes (e.g., K, M, G) based on its magnitude and returns a selection index indicating the format used.
- **Inputs**:
    - `st`: A character pointer to a buffer where the formatted string will be stored.
    - `cnt`: A 64-bit unsigned integer representing the count to be formatted.
    - `suffix`: A character pointer to a string that will be appended to the formatted count.
- **Control Flow**:
    - Initialize the selection index `sel` to 0.
    - Check if `cnt` is 0; if true, format the string as "<0> suffix" and set `sel` to 0.
    - If `cnt` is less than 1,000, format the string as "cnt suffix" and set `sel` to 0.
    - If `cnt` is less than 1,000,000, format the string as "cnt/1000K suffix" and set `sel` to 0.
    - If `cnt` is less than 10,000,000, format the string as "cnt/MILLION_FM suffix" and set `sel` to 1.
    - If `cnt` is less than 1,000,000,000, format the string as "cnt/MILLIONM suffix" and set `sel` to 2.
    - If `cnt` is less than 10,000,000,000, format the string as "cnt/BILLION_FG suffix" and set `sel` to 3.
    - If none of the above, format the string as "cnt/BILLIONG suffix" and set `sel` to 4.
    - Return the selection index `sel`.
- **Output**: An integer representing the selection index, which indicates the format used for the count.


---
### mon\_thread<!-- {{#callable:mon_thread}} -->
The `mon_thread` function monitors hardware counters and updates a visual ASCII chart with the current state of various metrics in a loop until a stop condition is met.
- **Inputs**:
    - `arg`: A pointer to a `wd_mon_state_t` structure that contains the state information for the monitoring thread.
- **Control Flow**:
    - Initialize local variables including counters, strings for formatted output, and timing variables.
    - Enter a loop that continues while the `running` flag in the state is true and `running_recv` is false.
    - Sleep for a specified interval (400ms) to control the monitoring frequency.
    - Calculate the time elapsed since the last cycle and adjust the inverse of the milliseconds interval accordingly.
    - If not the first iteration, move the cursor position in the ASCII chart to the start position.
    - Snapshot hardware counters using `wd_snp_cntrs` for two slots.
    - Iterate over `cnt_data` to read and store current counter values from hardware or state variables into `cnts[1]`.
    - Calculate the delta of counters between the current and previous readings, handling potential overflow, and update `cnts[0]`.
    - Format the counter values into strings with appropriate units and colors based on the type of counter, storing results in `cnt_st` and updating `cnt_data` with color and width information.
    - Iterate over each line of the ASCII chart, updating it with the formatted counter values, applying colors, and printing the result to the console.
    - Flush the standard output to ensure all data is printed.
    - Exit the loop and return `0` when the `running` flag is false.
- **Output**: Returns a `void*` which is always `0`, indicating the thread has completed execution.
- **Functions called**:
    - [`get_tsc_ticks_ns`](wd_f1_mon.h.driver.md#get_tsc_ticks_ns)
    - [`ascii_move_to`](#ascii_move_to)
    - [`pretty_num`](#pretty_num)
    - [`ascii_color`](#ascii_color)


# Function Declarations (Public API)

---
### \_wd\_read\_32<!-- {{#callable_declaration:_wd_read_32}} -->
Reads a 32-bit value from a specified address on a PCI device.
- **Description**: This function retrieves a 32-bit value from a given address on a PCI device specified by the `pci` parameter. It is typically used to access hardware registers or memory-mapped I/O on the device. The function assumes that the PCI device has been properly initialized and is accessible. If the read operation fails, an error is logged, but the function still returns the value read, which may be undefined in case of an error. This function should be used in contexts where the caller can handle potential read errors gracefully.
- **Inputs**:
    - `pci`: A pointer to a `wd_pci_t` structure representing the PCI device. Must not be null, and the device should be properly initialized and accessible.
    - `addr`: A 32-bit unsigned integer representing the address to read from on the PCI device. The address should be valid and within the range supported by the device.
- **Output**: Returns the 32-bit value read from the specified address. If the read operation fails, the returned value may be undefined.
- **See also**: [`_wd_read_32`](../c/wd_f1.c.driver.md#_wd_read_32)  (Implementation)


