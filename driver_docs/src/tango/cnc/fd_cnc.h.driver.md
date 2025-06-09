# Purpose
The provided C header file, `fd_cnc.h`, defines a command-and-control (CNC) interface for managing out-of-band communication between high-performance application threads and control or monitoring threads. This interface is designed to facilitate the coordination and control of application threads through a state machine model, which includes states such as BOOT, RUN, USER, HALT, and FAIL. The CNC interface allows for the sending and receiving of signals to manage the lifecycle and behavior of application threads, including starting, stopping, and handling user-defined signals. The file defines several macros, data structures, and functions to support these operations, including alignment and footprint specifications, signal definitions, error codes, and functions for creating, joining, leaving, and deleting CNC objects.

The header file provides a comprehensive API for interacting with CNC objects, including functions for querying and updating the state and heartbeat of application threads, managing command sessions, and converting between signal values and their string representations. The `fd_cnc_t` structure is defined as an opaque handle to encapsulate the CNC object, with details exposed to allow inlining of operations for performance-critical paths. The file also includes detailed documentation on the expected behavior and usage of the CNC interface, making it a crucial component for developers implementing high-performance applications that require robust command-and-control capabilities.
# Imports and Dependencies

---
- `../fd_tango_base.h`


# Global Variables

---
### fd\_cnc\_new
- **Type**: `function`
- **Description**: The `fd_cnc_new` function is responsible for initializing a memory region to be used as a command-and-control (cnc) object. It takes a pointer to a shared memory region, the size of the application-specific region, a type identifier, and an initial heartbeat value as parameters. The function returns the pointer to the initialized memory region on success or NULL on failure.
- **Use**: This function is used to set up a cnc object in a specified memory region, preparing it for use in managing command-and-control signals for high-performance application threads.


---
### fd\_cnc\_join
- **Type**: `fd_cnc_t *`
- **Description**: The `fd_cnc_join` function is a global function that returns a pointer to an `fd_cnc_t` structure. This function is used to join a caller to a command-and-control (CNC) object, which is a shared memory region used for out-of-band communication between high-performance application threads and command/control or monitoring threads.
- **Use**: This function is used to obtain a local pointer to a CNC object, allowing the caller to interact with the CNC for command and control operations.


---
### fd\_cnc\_leave
- **Type**: `function pointer`
- **Description**: The `fd_cnc_leave` is a function that takes a constant pointer to an `fd_cnc_t` structure and returns a pointer to a void. This function is used to leave a current local join of a command-and-control (CNC) object, which is part of a system for managing out-of-band command-and-control signals for high-performance application threads.
- **Use**: This function is used to safely leave a CNC session, returning a pointer to the underlying shared memory region on success.


---
### fd\_cnc\_delete
- **Type**: `function pointer`
- **Description**: `fd_cnc_delete` is a function that unformats a memory region used as a command-and-control (cnc) object. It assumes that no threads are currently joined to the cnc region and returns a pointer to the underlying shared memory region or NULL if there is an error.
- **Use**: This function is used to clean up and reclaim the memory region previously formatted for cnc usage, transferring ownership back to the caller.


---
### fd\_cnc\_strerror
- **Type**: `FD_FN_CONST char const *`
- **Description**: The `fd_cnc_strerror` function is a global function that converts error codes related to command-and-control (CNC) operations into human-readable strings. It takes an integer error code as input and returns a constant character pointer to a string that describes the error. The returned string is non-NULL and has an infinite lifetime.
- **Use**: This function is used to provide human-readable descriptions of error codes returned by CNC operations, aiding in debugging and error handling.


---
### fd\_cnc\_signal\_cstr
- **Type**: `function`
- **Description**: The `fd_cnc_signal_cstr` function is designed to convert a command-and-control (CNC) signal value into a human-readable C string representation. It takes a signal of type `ulong` and a character buffer `buf` as parameters.
- **Use**: This function is used to pretty print a CNC signal value into a provided buffer, ensuring the buffer contains a proper null-terminated C string representation of the signal.


# Data Structures

---
### fd\_cnc\_private
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity of the structure, expected to be FD_CNC_MAGIC.
    - `app_sz`: The size of the application-specific region within the structure.
    - `type`: An application-defined type field to distinguish between different types of command-and-control signals.
    - `heartbeat0`: The initial heartbeat value assigned when the structure is created.
    - `heartbeat`: A value used to track the current heartbeat of the application, indicating its operational status.
    - `lock`: A field used to manage access control, ensuring that only one thread can modify the structure at a time.
    - `signal`: A field used to store the current signal or command being processed by the application.
- **Description**: The `fd_cnc_private` structure is a core component of the command-and-control (CNC) system used to manage out-of-band signals for high-performance application threads. It includes fields for managing the state and communication between application and control threads, such as a magic number for integrity checks, application-specific size, type identifiers, heartbeat tracking for monitoring application status, and a lock for synchronization. The structure is aligned to `FD_CNC_ALIGN` to optimize memory access and includes padding to ensure proper alignment of the application region.


---
### fd\_cnc\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, expected to be FD_CNC_MAGIC.
    - `app_sz`: The size of the application-specific region within the structure.
    - `type`: An application-defined type field to distinguish supported signals.
    - `heartbeat0`: The initial heartbeat value assigned when the structure is created.
    - `heartbeat`: The current heartbeat value, used for monitoring the app thread's status.
    - `lock`: A lock field used to manage access to the structure.
    - `signal`: The current signal value, indicating the state or command for the app thread.
- **Description**: The `fd_cnc_t` structure is a command-and-control object used to manage out-of-band signals for high-performance application threads. It facilitates communication between application threads and command/control or monitoring threads, allowing for state transitions such as BOOT, RUN, USER, HALT, and FAIL. The structure includes fields for managing the state, type, and heartbeat of the application, as well as a lock and signal field for synchronization and command signaling. The structure is aligned to mitigate false sharing and includes an application-specific region for additional data.


# Functions

---
### fd\_cnc\_app\_sz<!-- {{#callable:fd_cnc_app_sz}} -->
The `fd_cnc_app_sz` function returns the size of the application region of a command-and-control object (`fd_cnc_t`).
- **Inputs**:
    - `cnc`: A pointer to a constant `fd_cnc_t` structure, representing a command-and-control object.
- **Control Flow**:
    - The function accesses the `app_sz` field of the `fd_cnc_t` structure pointed to by `cnc`.
    - It returns the value of the `app_sz` field.
- **Output**: The function returns an `ulong` representing the size of the application region of the `fd_cnc_t` object.


---
### fd\_cnc\_app\_laddr<!-- {{#callable:fd_cnc_app_laddr}} -->
The `fd_cnc_app_laddr` function returns the local address of the application region within a `fd_cnc_t` structure.
- **Inputs**:
    - `cnc`: A pointer to an `fd_cnc_t` structure, representing a command-and-control object.
- **Control Flow**:
    - The function takes a pointer to an `fd_cnc_t` structure as input.
    - It casts the pointer to an unsigned long integer and adds 64 to it, which is the offset to the application region within the structure.
    - The result is then cast back to a `void *` pointer, which is returned as the local address of the application region.
- **Output**: A `void *` pointer to the local address of the application region within the `fd_cnc_t` structure.


---
### fd\_cnc\_app\_laddr\_const<!-- {{#callable:fd_cnc_app_laddr_const}} -->
The `fd_cnc_app_laddr_const` function returns a constant pointer to the local address of the application region within a `fd_cnc_t` structure.
- **Inputs**:
    - `cnc`: A constant pointer to an `fd_cnc_t` structure, representing a command-and-control object.
- **Control Flow**:
    - The function takes a constant pointer to an `fd_cnc_t` structure as input.
    - It calculates the address of the application region by adding 64 bytes to the base address of the `fd_cnc_t` structure.
    - The function returns this calculated address as a constant pointer.
- **Output**: A constant pointer to the local address of the application region within the `fd_cnc_t` structure.


---
### fd\_cnc\_type<!-- {{#callable:fd_cnc_type}} -->
The `fd_cnc_type` function retrieves the application-defined type of a command-and-control (cnc) object.
- **Inputs**:
    - `cnc`: A pointer to a constant `fd_cnc_t` structure, representing a command-and-control object.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It takes a single argument, `cnc`, which is a pointer to a constant `fd_cnc_t` structure.
    - The function directly accesses the `type` field of the `fd_cnc_t` structure pointed to by `cnc` and returns its value.
- **Output**: The function returns an `ulong` value representing the application-defined type of the cnc object.


---
### fd\_cnc\_heartbeat0<!-- {{#callable:fd_cnc_heartbeat0}} -->
The `fd_cnc_heartbeat0` function returns the initial heartbeat value assigned to a command-and-control (cnc) object when it was created.
- **Inputs**:
    - `cnc`: A pointer to a constant `fd_cnc_t` structure representing the command-and-control object.
- **Control Flow**:
    - The function accesses the `heartbeat0` member of the `fd_cnc_t` structure pointed to by `cnc`.
    - It returns the value of `heartbeat0`.
- **Output**: The function returns a `long` integer representing the initial heartbeat value of the cnc object.


---
### fd\_cnc\_heartbeat\_query<!-- {{#callable:fd_cnc_heartbeat_query}} -->
The `fd_cnc_heartbeat_query` function retrieves the current heartbeat value from a `fd_cnc_t` structure, ensuring memory consistency with compiler memory fences.
- **Inputs**:
    - `cnc`: A pointer to a constant `fd_cnc_t` structure from which the heartbeat value is to be queried.
- **Control Flow**:
    - The function begins by executing a compiler memory fence to ensure memory operations are completed before proceeding.
    - It reads the `heartbeat` field from the `cnc` structure using a volatile read to prevent compiler optimizations that might reorder operations.
    - Another compiler memory fence is executed to ensure that subsequent operations do not begin until the read is complete.
    - The function returns the value read from the `heartbeat` field.
- **Output**: The function returns a `long` integer representing the heartbeat value of the `fd_cnc_t` structure at the time of the query.


---
### fd\_cnc\_heartbeat<!-- {{#callable:fd_cnc_heartbeat}} -->
The `fd_cnc_heartbeat` function updates the heartbeat value of a command-and-control object to the current time, ensuring memory consistency with compiler memory fences.
- **Inputs**:
    - `cnc`: A pointer to an `fd_cnc_t` structure representing the command-and-control object whose heartbeat is to be updated.
    - `now`: A `long` integer representing the current time or heartbeat value to be set.
- **Control Flow**:
    - A compiler memory fence (`FD_COMPILER_MFENCE`) is executed to ensure memory operations are completed before updating the heartbeat.
    - The `heartbeat` field of the `fd_cnc_t` structure pointed to by `cnc` is updated to the value of `now` using a volatile write to ensure visibility across threads.
    - Another compiler memory fence is executed to ensure the heartbeat update is visible to other threads.
- **Output**: The function does not return a value; it updates the `heartbeat` field of the `fd_cnc_t` structure in place.


---
### fd\_cnc\_signal\_query<!-- {{#callable:fd_cnc_signal_query}} -->
The `fd_cnc_signal_query` function retrieves the current signal value from a command-and-control (CNC) object, ensuring memory consistency through compiler memory fences.
- **Inputs**:
    - `cnc`: A pointer to a constant `fd_cnc_t` structure, representing the CNC object from which the signal is to be queried.
- **Control Flow**:
    - A compiler memory fence (`FD_COMPILER_MFENCE`) is executed to ensure memory operations are completed before reading the signal.
    - The signal value is read from the `signal` field of the `fd_cnc_t` structure using `FD_VOLATILE_CONST` to ensure the read operation is not optimized away by the compiler.
    - Another compiler memory fence is executed to ensure memory operations are completed after reading the signal.
    - The function returns the signal value.
- **Output**: The function returns an `ulong` representing the current signal value of the CNC object at the time of the query.


---
### fd\_cnc\_signal<!-- {{#callable:fd_cnc_signal}} -->
The `fd_cnc_signal` function atomically updates the signal field of a `fd_cnc_t` structure to a specified value, ensuring memory consistency with compiler memory fences.
- **Inputs**:
    - `cnc`: A pointer to an `fd_cnc_t` structure representing the command-and-control object whose signal field is to be updated.
    - `s`: An unsigned long integer representing the new signal value to be set in the `cnc` structure.
- **Control Flow**:
    - A memory fence is issued to ensure all previous memory operations are completed before updating the signal.
    - The signal field of the `cnc` structure is updated to the new value `s` using a volatile write to ensure visibility across threads.
    - Another memory fence is issued to ensure the signal update is visible before any subsequent memory operations.
- **Output**: The function does not return a value; it performs an in-place update of the signal field in the `fd_cnc_t` structure.


---
### fd\_cnc\_close<!-- {{#callable:fd_cnc_close}} -->
The `fd_cnc_close` function ends the current command session on a command-and-control object by releasing its lock.
- **Inputs**:
    - `cnc`: A pointer to an `fd_cnc_t` structure representing the command-and-control object whose session is to be closed.
- **Control Flow**:
    - The function begins by executing a memory fence to ensure memory operations are completed before proceeding.
    - It sets the `lock` field of the `cnc` structure to `0UL`, indicating the release of the lock.
    - Another memory fence is executed to ensure the lock release is visible to other threads.
- **Output**: The function does not return a value; it performs its operation directly on the `cnc` object.


# Function Declarations (Public API)

---
### fd\_cnc\_align<!-- {{#callable_declaration:fd_cnc_align}} -->
Return the required alignment for a command-and-control object.
- **Description**: This function provides the alignment requirement for a memory region to be used as a command-and-control (CNC) object. It is useful for ensuring that memory allocations for CNC objects meet the necessary alignment constraints, which is a power of 2 and recommended to be at least double the cache line size to mitigate false sharing. This function should be called when setting up memory for CNC objects to ensure proper alignment.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer.
- **See also**: [`fd_cnc_align`](fd_cnc.c.driver.md#fd_cnc_align)  (Implementation)


---
### fd\_cnc\_footprint<!-- {{#callable_declaration:fd_cnc_footprint}} -->
Calculate the memory footprint required for a command-and-control object.
- **Description**: This function computes the memory footprint needed for a command-and-control (CNC) object based on the specified application size. It is useful for determining the amount of memory to allocate for a CNC object. The function should be called with a valid application size, and it will return zero if the calculated footprint would exceed the maximum allowable size, indicating an overflow condition.
- **Inputs**:
    - `app_sz`: The size of the application-specific region in bytes. It must be a value such that the total footprint does not exceed ULONG_MAX. If the value is too large, the function returns zero to indicate an overflow.
- **Output**: Returns the calculated memory footprint in bytes, or zero if the footprint calculation overflows.
- **See also**: [`fd_cnc_footprint`](fd_cnc.c.driver.md#fd_cnc_footprint)  (Implementation)


---
### fd\_cnc\_new<!-- {{#callable_declaration:fd_cnc_new}} -->
Formats a memory region for use as a command-and-control object.
- **Description**: This function initializes a memory region to be used as a command-and-control (CNC) object, which facilitates communication between high-performance application threads and control or monitoring threads. It should be called with a properly aligned and sized memory region, and it sets up the CNC with a specified application size, type, and initial heartbeat. The function returns a pointer to the initialized CNC object or NULL if the initialization fails due to invalid input parameters, such as a NULL or misaligned memory region, or an invalid application size.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a CNC. Must not be NULL and must be aligned according to fd_cnc_align(). The caller retains ownership.
    - `app_sz`: The size of the application-specific region within the CNC. Must be a valid size that does not result in a footprint larger than ULONG_MAX.
    - `type`: An application-defined type identifier for the CNC. Should be within the range [0, UINT_MAX].
    - `now`: The initial heartbeat value for the CNC. Typically represents the current time or a starting counter value.
- **Output**: Returns a pointer to the initialized CNC object on success, or NULL on failure, with details logged.
- **See also**: [`fd_cnc_new`](fd_cnc.c.driver.md#fd_cnc_new)  (Implementation)


---
### fd\_cnc\_join<!-- {{#callable_declaration:fd_cnc_join}} -->
Joins the caller to a command-and-control object.
- **Description**: This function is used to join a caller to a command-and-control (CNC) object, which facilitates communication between application threads and control or monitoring threads. It should be called with a valid pointer to the shared memory region backing the CNC. The function checks for null pointers, proper alignment, and a valid magic number to ensure the memory region is correctly formatted as a CNC. If any of these checks fail, the function logs a warning and returns NULL. A successful join should be followed by a corresponding leave to properly manage resources.
- **Inputs**:
    - `shcnc`: A pointer to the first byte of the memory region backing the CNC in the caller's address space. It must not be null, must be properly aligned according to fd_cnc_align(), and must point to a region with a valid CNC magic number. If these conditions are not met, the function returns NULL and logs a warning.
- **Output**: Returns a pointer to the CNC object on success, or NULL on failure.
- **See also**: [`fd_cnc_join`](fd_cnc.c.driver.md#fd_cnc_join)  (Implementation)


---
### fd\_cnc\_leave<!-- {{#callable_declaration:fd_cnc_leave}} -->
Leaves a current local join of a command-and-control object.
- **Description**: This function is used to leave a current local join of a command-and-control (cnc) object, which is part of a system for managing out-of-band signals in high-performance applications. It should be called when the caller no longer needs to interact with the cnc object, ensuring that resources are properly released. The function returns a pointer to the underlying shared memory region on success, allowing the caller to manage the memory as needed. It is important to ensure that the cnc parameter is not null before calling this function, as passing a null pointer will result in a logged warning and a null return value.
- **Inputs**:
    - `cnc`: A pointer to a constant fd_cnc_t object representing the current local join. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the underlying shared memory region on success, or null if the cnc parameter is null.
- **See also**: [`fd_cnc_leave`](fd_cnc.c.driver.md#fd_cnc_leave)  (Implementation)


---
### fd\_cnc\_delete<!-- {{#callable_declaration:fd_cnc_delete}} -->
Unformats a memory region used as a command-and-control object.
- **Description**: This function is used to unformat a memory region that was previously formatted for use as a command-and-control (cnc) object. It should be called when the cnc is no longer needed, and it is assumed that no threads are currently joined to the cnc. The function returns a pointer to the underlying shared memory region, transferring ownership of the memory back to the caller. If the provided pointer does not point to a valid cnc, the function logs a warning and returns NULL.
- **Inputs**:
    - `shcnc`: A pointer to the memory region that was used as a cnc. It must be aligned according to fd_cnc_align() and must not be NULL. If the pointer is NULL, misaligned, or does not point to a valid cnc, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or NULL if the input is invalid.
- **See also**: [`fd_cnc_delete`](fd_cnc.c.driver.md#fd_cnc_delete)  (Implementation)


---
### fd\_cnc\_wait<!-- {{#callable_declaration:fd_cnc_wait}} -->
Waits for a CNC signal to change from a specified value or until a timeout occurs.
- **Description**: This function is used to wait for a command-and-control (CNC) signal to transition from a specified value, `test`, to any other value, or until a specified timeout, `dt`, is reached. It is useful in scenarios where a thread needs to wait for a state change in a CNC object, such as transitioning from a RUN state to a HALT state. The function is designed to be OS-friendly, meaning it will not block other threads that might be running on the same core. It can perform a blocking wait if `dt` is set to `LONG_MAX`, or a single poll if `dt` is less than or equal to zero. If `_opt_now` is provided, it will be updated with the wallclock time just before the last CNC query, allowing the caller to know the exact time of the last check.
- **Inputs**:
    - `cnc`: A pointer to a constant `fd_cnc_t` object representing the CNC to be monitored. It must not be null and should be a valid, joined CNC object.
    - `test`: An unsigned long value representing the CNC signal to test against. The function waits for the CNC signal to differ from this value.
    - `dt`: A long integer specifying the maximum time to wait in nanoseconds. A value of `LONG_MAX` indicates a blocking wait, while a value less than or equal to zero indicates a single poll.
    - `_opt_now`: An optional pointer to a long integer where the function will store the wallclock time observed just before the last CNC query. Can be null if this information is not needed.
- **Output**: Returns the last observed CNC signal as an unsigned long, which indicates the result of the wait operation.
- **See also**: [`fd_cnc_wait`](fd_cnc.c.driver.md#fd_cnc_wait)  (Implementation)


---
### fd\_cnc\_strerror<!-- {{#callable_declaration:fd_cnc_strerror}} -->
Convert an error code to a human-readable string.
- **Description**: Use this function to obtain a human-readable description of an error code returned by other CNC API functions. This is useful for logging or displaying error messages to users. The function accepts an error code and returns a constant string describing the error. It handles all defined error codes and provides a default message for unknown codes.
- **Inputs**:
    - `err`: An integer representing the error code to be converted. Valid values are FD_CNC_SUCCESS, FD_CNC_ERR_UNSUP, FD_CNC_ERR_INVAL, FD_CNC_ERR_AGAIN, and FD_CNC_ERR_FAIL. If an unknown error code is provided, the function returns a default message indicating the code might not be a CNC error code.
- **Output**: A constant string describing the error code. The string is always non-NULL and has an infinite lifetime.
- **See also**: [`fd_cnc_strerror`](fd_cnc.c.driver.md#fd_cnc_strerror)  (Implementation)


---
### fd\_cstr\_to\_cnc\_signal<!-- {{#callable_declaration:fd_cstr_to_cnc_signal}} -->
Converts a string representation of a CNC signal to its corresponding signal value.
- **Description**: Use this function to translate a string representation of a command-and-control (CNC) signal into its corresponding numeric signal value. This is useful when interpreting user input or configuration files that specify CNC signals as strings. The function recognizes the strings "run", "boot", "fail", and "halt", returning their respective predefined signal values. If the input string does not match any of these, the function attempts to convert it to an unsigned long integer. If the input is null, the function defaults to returning the signal value for "run".
- **Inputs**:
    - `cstr`: A pointer to a null-terminated string representing a CNC signal. Valid strings are "run", "boot", "fail", and "halt". If the string does not match any of these, it is interpreted as an unsigned long integer. If null, the function returns the signal value for "run".
- **Output**: Returns the corresponding CNC signal value as an unsigned long integer. If the input string is null, returns the signal value for "run". If the string does not match a predefined signal, returns the result of converting the string to an unsigned long integer.
- **See also**: [`fd_cstr_to_cnc_signal`](fd_cnc.c.driver.md#fd_cstr_to_cnc_signal)  (Implementation)


---
### fd\_cnc\_signal\_cstr<!-- {{#callable_declaration:fd_cnc_signal_cstr}} -->
Converts a CNC signal value to a human-readable string.
- **Description**: This function is used to convert a given CNC signal value into a human-readable string representation. It is useful for logging or debugging purposes where understanding the current state or signal of a CNC is necessary. The function requires a buffer to store the resulting string, which must be large enough to hold the longest possible string representation of a signal, including a null terminator. The function always returns the provided buffer, and if the buffer is non-null, it will contain a valid null-terminated string on return.
- **Inputs**:
    - `signal`: The CNC signal value to be converted. It can be one of the predefined signals (e.g., FD_CNC_SIGNAL_RUN, FD_CNC_SIGNAL_BOOT) or a user-defined signal value.
    - `buf`: A pointer to a character buffer where the resulting string will be stored. The buffer must have at least FD_CNC_SIGNAL_CSTR_BUF_MAX bytes available. If buf is null, the function will not perform any conversion.
- **Output**: Returns the buf pointer. If buf is non-null, it will contain a null-terminated string representing the signal.
- **See also**: [`fd_cnc_signal_cstr`](fd_cnc.c.driver.md#fd_cnc_signal_cstr)  (Implementation)


