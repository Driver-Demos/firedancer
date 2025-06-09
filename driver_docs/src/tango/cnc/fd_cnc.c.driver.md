# Purpose
This C source code file provides a set of functions for managing and interacting with a control and command (CNC) structure, which is likely used for coordinating processes or threads in a shared memory environment. The file includes functions to create, join, leave, and delete a CNC instance, as well as to open a command session with it. The functions ensure proper alignment and memory footprint calculations, handle potential errors, and manage the state of the CNC through signals. The code also includes mechanisms for handling concurrency and ensuring that only one process can hold a command session at a time, using atomic operations and process signaling.

The file defines a public API for interacting with the CNC structure, including functions like [`fd_cnc_new`](#fd_cnc_new), [`fd_cnc_join`](#fd_cnc_join), [`fd_cnc_open`](#fd_cnc_open), and [`fd_cnc_wait`](#fd_cnc_wait). These functions are designed to be used by other parts of a program to manage the lifecycle and state of CNC instances. The code also includes error handling and logging to provide feedback on operations, and it uses compiler and memory fences to ensure proper memory ordering in concurrent environments. Additionally, the file provides utility functions for converting between string representations and signal values, enhancing the usability of the API. Overall, this file is a critical component for managing process synchronization and communication in a system that uses CNC structures.
# Imports and Dependencies

---
- `fd_cnc.h`
- `errno.h`
- `signal.h`
- `sched.h`


# Functions

---
### fd\_cnc\_align<!-- {{#callable:fd_cnc_align}} -->
The `fd_cnc_align` function returns a predefined constant alignment value for CNC operations.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return a constant value `FD_CNC_ALIGN`.
- **Output**: The function returns an unsigned long integer representing the alignment value `FD_CNC_ALIGN`.


---
### fd\_cnc\_footprint<!-- {{#callable:fd_cnc_footprint}} -->
The `fd_cnc_footprint` function calculates the memory footprint required for a CNC (Command and Control) structure based on the application size, ensuring it does not exceed a maximum allowable size.
- **Inputs**:
    - `app_sz`: The size of the application for which the CNC footprint is being calculated, specified as an unsigned long integer.
- **Control Flow**:
    - Check if the provided application size `app_sz` is greater than `ULONG_MAX - 191UL` using the `FD_UNLIKELY` macro to handle unlikely conditions.
    - If the condition is true, indicating a potential overflow, return 0UL to signal an error.
    - If the condition is false, call the `FD_CNC_FOOTPRINT` macro with `app_sz` to compute and return the required memory footprint.
- **Output**: Returns the calculated memory footprint as an unsigned long integer, or 0UL if the input size would cause an overflow.


---
### fd\_cnc\_new<!-- {{#callable:fd_cnc_new}} -->
The `fd_cnc_new` function initializes a new control structure in shared memory for a CNC (Command and Control) application, setting up its initial state and validating input parameters.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the CNC structure will be initialized.
    - `app_sz`: The size of the application-specific data to be accommodated in the CNC structure.
    - `type`: An unsigned long integer representing the type of the CNC structure.
    - `now`: A long integer representing the current time, used to initialize the heartbeat fields.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_cnc_t` pointer named `cnc`.
    - Check if `shmem` is NULL; if so, log a warning and return NULL.
    - Check if `shmem` is properly aligned using [`fd_cnc_align`](#fd_cnc_align); if not, log a warning and return NULL.
    - Calculate the footprint using [`fd_cnc_footprint`](#fd_cnc_footprint) with `app_sz`; if the footprint is zero, log a warning and return NULL.
    - Clear the memory at `cnc` using `fd_memset` with the calculated footprint.
    - Initialize the `cnc` structure fields: `app_sz`, `type`, `heartbeat0`, `heartbeat`, `lock`, and `signal`.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before setting the `magic` field.
    - Set the `magic` field to `FD_CNC_MAGIC` using a volatile store to ensure visibility across threads.
    - Return the initialized `cnc` pointer cast to a `void *`.
- **Output**: A pointer to the initialized `fd_cnc_t` structure, or NULL if initialization fails due to invalid inputs or alignment issues.
- **Functions called**:
    - [`fd_cnc_align`](#fd_cnc_align)
    - [`fd_cnc_footprint`](#fd_cnc_footprint)


---
### fd\_cnc\_join<!-- {{#callable:fd_cnc_join}} -->
The `fd_cnc_join` function validates and returns a pointer to a `fd_cnc_t` structure if the provided shared memory pointer is correctly aligned and initialized.
- **Inputs**:
    - `shcnc`: A pointer to shared memory that is expected to contain a `fd_cnc_t` structure.
- **Control Flow**:
    - Check if `shcnc` is NULL; if so, log a warning and return NULL.
    - Check if `shcnc` is aligned according to [`fd_cnc_align`](#fd_cnc_align); if not, log a warning and return NULL.
    - Cast `shcnc` to a `fd_cnc_t` pointer and store it in `cnc`.
    - Check if `cnc->magic` equals `FD_CNC_MAGIC`; if not, log a warning and return NULL.
    - Return the `cnc` pointer.
- **Output**: A pointer to a `fd_cnc_t` structure if successful, otherwise NULL.
- **Functions called**:
    - [`fd_cnc_align`](#fd_cnc_align)


---
### fd\_cnc\_leave<!-- {{#callable:fd_cnc_leave}} -->
The `fd_cnc_leave` function checks if a given `fd_cnc_t` pointer is non-null and returns it after casting away its constness.
- **Inputs**:
    - `cnc`: A constant pointer to an `fd_cnc_t` structure, representing a CNC (Command and Control) object.
- **Control Flow**:
    - Check if the input `cnc` is NULL using `FD_UNLIKELY`; if it is, log a warning and return NULL.
    - If `cnc` is not NULL, return the `cnc` pointer after casting away its constness.
- **Output**: Returns a non-const pointer to the `fd_cnc_t` structure if `cnc` is non-null, otherwise returns NULL.


---
### fd\_cnc\_delete<!-- {{#callable:fd_cnc_delete}} -->
The `fd_cnc_delete` function validates and deletes a CNC (Command and Control) object by resetting its magic number to zero, effectively marking it as deleted.
- **Inputs**:
    - `shcnc`: A pointer to the shared CNC object to be deleted.
- **Control Flow**:
    - Check if the input `shcnc` is NULL; if so, log a warning and return NULL.
    - Check if `shcnc` is properly aligned using [`fd_cnc_align`](#fd_cnc_align); if not, log a warning and return NULL.
    - Cast `shcnc` to a `fd_cnc_t` pointer named `cnc`.
    - Verify if the `magic` field of `cnc` matches `FD_CNC_MAGIC`; if not, log a warning and return NULL.
    - Use memory fences to ensure memory operations are completed before and after setting `cnc->magic` to 0.
    - Return the `cnc` pointer cast back to a `void *`.
- **Output**: Returns a pointer to the deleted CNC object if successful, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_cnc_align`](#fd_cnc_align)


---
### fd\_cnc\_open<!-- {{#callable:fd_cnc_open}} -->
The `fd_cnc_open` function attempts to open a command session on a CNC (Command and Control) structure but returns an unsupported error for the current build target.
- **Inputs**:
    - `cnc`: A pointer to an `fd_cnc_t` structure, which represents the Command and Control structure to be opened.
- **Control Flow**:
    - The function takes a single argument, `cnc`, which is a pointer to an `fd_cnc_t` structure.
    - The function does not perform any operations on the `cnc` argument, as indicated by the cast to void.
    - A warning is logged indicating that the operation is unsupported for the current build target.
    - The function returns the error code `FD_CNC_ERR_UNSUP`, indicating that the operation is unsupported.
- **Output**: The function returns an integer error code `FD_CNC_ERR_UNSUP`, indicating that the operation is unsupported for the current build target.


---
### fd\_cnc\_wait<!-- {{#callable:fd_cnc_wait}} -->
The `fd_cnc_wait` function waits for a signal change in a CNC (Command and Control) structure or until a specified timeout is reached, returning the observed signal.
- **Inputs**:
    - `cnc`: A pointer to a constant `fd_cnc_t` structure representing the CNC to be monitored.
    - `test`: An unsigned long integer representing the signal value to test against.
    - `dt`: A long integer representing the maximum duration to wait in wall clock time.
    - `_opt_now`: An optional pointer to a long integer where the current wall clock time will be stored if provided.
- **Control Flow**:
    - Initialize `then` and `now` with the current wall clock time using `fd_log_wallclock()`.
    - Enter an infinite loop to repeatedly query the current signal from the CNC using `fd_cnc_signal_query(cnc)`.
    - Calculate `done` as true if the observed signal `obs` is not equal to `test` or if the elapsed time exceeds `dt`.
    - Use `FD_COMPILER_FORGET(done)` to prevent compiler optimizations that might misinterpret the loop's purpose.
    - If `done` is true, break out of the loop; otherwise, yield the processor with `FD_YIELD()` and update `now` with the current wall clock time.
    - If `_opt_now` is not null, store the current time `now` in the location pointed to by `_opt_now`.
- **Output**: Returns the observed signal as an unsigned long integer.
- **Functions called**:
    - [`fd_cnc_signal_query`](fd_cnc.h.driver.md#fd_cnc_signal_query)


---
### fd\_cnc\_strerror<!-- {{#callable:fd_cnc_strerror}} -->
The `fd_cnc_strerror` function returns a human-readable string describing a given error code related to CNC operations.
- **Inputs**:
    - `err`: An integer representing the error code for which a descriptive string is needed.
- **Control Flow**:
    - The function uses a switch statement to match the input error code `err` against predefined error codes.
    - If `err` matches `FD_CNC_SUCCESS`, it returns the string "success".
    - If `err` matches `FD_CNC_ERR_UNSUP`, it returns the string "unsupported here".
    - If `err` matches `FD_CNC_ERR_INVAL`, it returns the string "bad inputs".
    - If `err` matches `FD_CNC_ERR_AGAIN`, it returns the string "try again later".
    - If `err` matches `FD_CNC_ERR_FAIL`, it returns the string "app thread failed".
    - If `err` does not match any predefined error codes, it returns the string "unknown---possibly not a cnc error code".
- **Output**: A constant character pointer to a string that describes the error code.


---
### fd\_cstr\_to\_cnc\_signal<!-- {{#callable:fd_cstr_to_cnc_signal}} -->
The `fd_cstr_to_cnc_signal` function converts a string representation of a CNC signal to its corresponding numeric signal code.
- **Inputs**:
    - `cstr`: A constant character pointer representing the string to be converted to a CNC signal code.
- **Control Flow**:
    - Check if the input string `cstr` is NULL; if so, return `FD_CNC_SIGNAL_RUN`.
    - Compare the input string `cstr` case-insensitively with "run"; if they match, return `FD_CNC_SIGNAL_RUN`.
    - Compare the input string `cstr` case-insensitively with "boot"; if they match, return `FD_CNC_SIGNAL_BOOT`.
    - Compare the input string `cstr` case-insensitively with "fail"; if they match, return `FD_CNC_SIGNAL_FAIL`.
    - Compare the input string `cstr` case-insensitively with "halt"; if they match, return `FD_CNC_SIGNAL_HALT`.
    - If none of the above conditions are met, convert the string to an unsigned long using `fd_cstr_to_ulong` and return the result.
- **Output**: Returns an unsigned long representing the CNC signal code corresponding to the input string, or the result of converting the string to an unsigned long if it doesn't match any predefined signal strings.


---
### fd\_cnc\_signal\_cstr<!-- {{#callable:fd_cnc_signal_cstr}} -->
The `fd_cnc_signal_cstr` function converts a CNC signal code into its corresponding string representation and stores it in a provided buffer.
- **Inputs**:
    - `signal`: An unsigned long integer representing the CNC signal code to be converted.
    - `buf`: A character buffer where the string representation of the signal will be stored.
- **Control Flow**:
    - Check if the buffer `buf` is not NULL using `FD_LIKELY` macro.
    - Use a switch statement to match the `signal` with predefined signal codes: `FD_CNC_SIGNAL_RUN`, `FD_CNC_SIGNAL_BOOT`, `FD_CNC_SIGNAL_FAIL`, and `FD_CNC_SIGNAL_HALT`.
    - For each matched case, copy the corresponding string ('run', 'boot', 'fail', 'halt') into `buf` using `strcpy`.
    - If the signal does not match any predefined cases, use `fd_cstr_printf` to format the signal as a string and store it in `buf`.
- **Output**: Returns the pointer to the buffer `buf` containing the string representation of the signal.


