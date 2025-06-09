# Purpose
This C header file defines a public API for managing a "key switch" mechanism, which is used for out-of-band switching of a validator's key. The file provides a structured approach to handle the state transitions of a keyswitch, which is crucial in systems where secure and controlled key management is necessary. The header defines constants for memory alignment and footprint, as well as several states that a keyswitch can be in, such as unlocked, locked, switch pending, unhalt pending, failed, and completed. These states are used to manage the lifecycle and transitions of the keyswitch.

The file includes function prototypes for creating, joining, leaving, and deleting a keyswitch, as well as querying and setting its state. The [`fd_keyswitch_new`](#fd_keyswitch_new) function initializes a memory region for use as a keyswitch, while [`fd_keyswitch_join`](#fd_keyswitch_join) and [`fd_keyswitch_leave`](#fd_keyswitch_leave) manage the association of a keyswitch with a caller. The [`fd_keyswitch_delete`](#fd_keyswitch_delete) function is used to unformat a memory region previously used as a keyswitch. Additionally, inline functions are provided to query the current state and parameters of a keyswitch, and to atomically transition its state. This header file is intended to be included in other C source files, providing a consistent interface for managing keyswitches in a shared memory environment.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Global Variables

---
### fd\_keyswitch\_new
- **Type**: `function pointer`
- **Description**: The `fd_keyswitch_new` function is a global function that initializes a memory region for use as a keyswitch. It takes a pointer to a memory region (`shmem`) and a state (`state`) as parameters, and returns a pointer to the initialized memory region or NULL on failure.
- **Use**: This function is used to format a memory region for keyswitch operations, setting its initial state.


---
### fd\_keyswitch\_join
- **Type**: `fd_keyswitch_t *`
- **Description**: The `fd_keyswitch_join` function is a global function that returns a pointer to an `fd_keyswitch_t` structure. It is used to join the caller to a keyswitch, which is a mechanism for managing the state of a validator's key in a shared memory region.
- **Use**: This function is used to obtain a local pointer to a keyswitch structure from a shared memory region, allowing the caller to interact with the keyswitch.


---
### fd\_keyswitch\_leave
- **Type**: `function pointer`
- **Description**: The `fd_keyswitch_leave` is a function that takes a constant pointer to an `fd_keyswitch_t` structure and returns a pointer to a void type. It is used to leave a current local join of a keyswitch, effectively ending the association with the keyswitch in the local address space.
- **Use**: This function is used to safely leave a keyswitch join, returning a pointer to the underlying shared memory region or NULL on failure.


---
### fd\_keyswitch\_delete
- **Type**: `function pointer`
- **Description**: The `fd_keyswitch_delete` is a function that unformats a memory region used as a keyswitch. It assumes that no one is currently joined to the region and returns a pointer to the underlying shared memory region or NULL if used incorrectly.
- **Use**: This function is used to delete a keyswitch by unformatting its memory region, transferring ownership of the memory back to the caller.


# Data Structures

---
### fd\_keyswitch\_private
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to identify the structure, expected to be FD_KEYSWITCH_MAGIC.
    - `state`: Represents the current state of the keyswitch, with predefined state values.
    - `result`: Stores the result of the keyswitch operation.
    - `param`: Holds additional parameters related to the keyswitch operation.
    - `bytes`: A byte array of size 64 used for additional data or padding.
- **Description**: The `fd_keyswitch_private` structure is a data structure used to manage the state and parameters of a keyswitch operation in a system. It includes a magic number for identification, a state field to track the current status of the keyswitch, a result field for operation outcomes, a param field for additional parameters, and a byte array for extra data or alignment purposes. The structure is aligned to `FD_KEYSWITCH_ALIGN` to ensure proper memory alignment.


---
### fd\_keyswitch\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity and version of the keyswitch structure.
    - `state`: Represents the current state of the keyswitch, with predefined constants for various states.
    - `result`: Stores the result of the last operation performed on the keyswitch.
    - `param`: Holds additional parameters or data related to the keyswitch operation.
    - `bytes`: A byte array used for additional data storage, padded to align with FD_KEYSWITCH_ALIGN.
- **Description**: The `fd_keyswitch_t` structure is a private data structure used to manage the state and operations of a keyswitch, which is a mechanism for out-of-band switching of a validator's key. It includes fields for maintaining the current state, operation results, and additional parameters, along with a magic number for integrity checks. The structure is aligned to a specific boundary to ensure efficient memory access and is designed to be used in shared memory contexts, allowing for atomic state transitions and queries.


# Functions

---
### fd\_keyswitch\_state\_query<!-- {{#callable:fd_keyswitch_state_query}} -->
The `fd_keyswitch_state_query` function retrieves the current state of a keyswitch in a thread-safe manner using memory fences.
- **Inputs**:
    - `ks`: A pointer to a `fd_keyswitch_t` structure representing the keyswitch whose state is to be queried.
- **Control Flow**:
    - A memory fence is executed to ensure memory operations are completed before reading the state.
    - The state of the keyswitch is read from the `state` field of the `fd_keyswitch_t` structure using a volatile read to prevent compiler optimizations that could reorder operations.
    - Another memory fence is executed to ensure the read operation is completed before any subsequent operations.
- **Output**: The function returns the current state of the keyswitch as an unsigned long integer.


---
### fd\_keyswitch\_param\_query<!-- {{#callable:fd_keyswitch_param_query}} -->
The `fd_keyswitch_param_query` function retrieves the current parameter value from a keyswitch structure, ensuring memory consistency with compiler fences.
- **Inputs**:
    - `ks`: A pointer to a constant `fd_keyswitch_t` structure, representing a keyswitch that is currently joined locally.
- **Control Flow**:
    - A memory fence is executed to ensure memory operations are completed before accessing the parameter.
    - The parameter value from the `ks` structure is read using a volatile access to ensure the most recent value is retrieved.
    - Another memory fence is executed to ensure subsequent memory operations occur after the parameter is read.
    - The retrieved parameter value is returned.
- **Output**: The function returns an `ulong` representing the current parameter value of the keyswitch.


---
### fd\_keyswitch\_state<!-- {{#callable:fd_keyswitch_state}} -->
The `fd_keyswitch_state` function sets the state of a keyswitch to a specified value with memory fencing to ensure proper ordering of operations.
- **Inputs**:
    - `ks`: A pointer to an `fd_keyswitch_t` structure representing the keyswitch whose state is to be set.
    - `s`: An unsigned long integer representing the new state to be set for the keyswitch.
- **Control Flow**:
    - A memory fence (`FD_COMPILER_MFENCE`) is executed to ensure memory operations are completed before setting the state.
    - The state of the keyswitch (`ks->state`) is set to the new value `s` using a volatile write to ensure the operation is not optimized away by the compiler.
    - Another memory fence (`FD_COMPILER_MFENCE`) is executed to ensure the state change is visible to other threads or processors.
- **Output**: This function does not return a value; it performs an in-place update of the keyswitch state.


# Function Declarations (Public API)

---
### fd\_keyswitch\_align<!-- {{#callable_declaration:fd_keyswitch_align}} -->
Return the required memory alignment for a keyswitch.
- **Description**: This function provides the alignment requirement for a memory region to be used as a keyswitch. It is essential to call this function when allocating memory for a keyswitch to ensure that the memory is correctly aligned, which is necessary for the proper functioning of the keyswitch operations. The function is constant and does not depend on any input parameters, making it straightforward to use whenever the alignment requirement is needed.
- **Inputs**: None
- **Output**: Returns the constant alignment value required for a keyswitch, which is 128 bytes.
- **See also**: [`fd_keyswitch_align`](fd_keyswitch.c.driver.md#fd_keyswitch_align)  (Implementation)


---
### fd\_keyswitch\_footprint<!-- {{#callable_declaration:fd_keyswitch_footprint}} -->
Return the memory footprint required for a keyswitch.
- **Description**: Use this function to determine the size of the memory region needed to store a keyswitch. This is useful when allocating memory for a keyswitch, ensuring that the allocated region is of the correct size. The function does not require any parameters and can be called at any time to retrieve the constant footprint value.
- **Inputs**: None
- **Output**: Returns the constant size in bytes required for a keyswitch, which is 128 bytes.
- **See also**: [`fd_keyswitch_footprint`](fd_keyswitch.c.driver.md#fd_keyswitch_footprint)  (Implementation)


---
### fd\_keyswitch\_new<!-- {{#callable_declaration:fd_keyswitch_new}} -->
Formats a memory region for use as a keyswitch.
- **Description**: This function initializes a specified memory region to be used as a keyswitch, setting its initial state. It should be called with a non-null pointer to a memory region that has the required alignment and footprint for a keyswitch. The function returns the pointer to the formatted memory region on success, or NULL if the memory region is invalid, logging a warning in such cases. This function does not join the caller to the keyswitch, and the caller must ensure that the memory region is not in use by any other process.
- **Inputs**:
    - `shmem`: A non-null pointer to a memory region that will be formatted as a keyswitch. The memory must be aligned to FD_KEYSWITCH_ALIGN and have a footprint of at least FD_KEYSWITCH_FOOTPRINT bytes. If the pointer is null or misaligned, the function returns NULL and logs a warning.
    - `state`: The initial state to set for the keyswitch. It should be a valid state value, typically within the range of defined state constants (e.g., FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED, etc.).
- **Output**: Returns a pointer to the formatted keyswitch memory region on success, or NULL on failure.
- **See also**: [`fd_keyswitch_new`](fd_keyswitch.c.driver.md#fd_keyswitch_new)  (Implementation)


---
### fd\_keyswitch\_join<!-- {{#callable_declaration:fd_keyswitch_join}} -->
Joins the caller to a keyswitch.
- **Description**: This function is used to join the caller to a keyswitch, allowing interaction with the keyswitch's state and parameters. It should be called with a pointer to the memory region backing the keyswitch, which must be properly aligned and initialized. The function returns a pointer to the keyswitch structure on success, or NULL if the provided pointer is invalid, misaligned, or if the keyswitch's magic number does not match the expected value. Each successful join should be paired with a corresponding leave to ensure proper resource management.
- **Inputs**:
    - `shks`: A pointer to the first byte of the memory region backing the keyswitch in the caller's address space. It must be non-NULL, properly aligned according to fd_keyswitch_align(), and point to a memory region initialized as a keyswitch. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the keyswitch structure on success, or NULL on failure.
- **See also**: [`fd_keyswitch_join`](fd_keyswitch.c.driver.md#fd_keyswitch_join)  (Implementation)


---
### fd\_keyswitch\_leave<!-- {{#callable_declaration:fd_keyswitch_leave}} -->
Leaves a current local join to a keyswitch.
- **Description**: Use this function to leave a current local join to a keyswitch, which is necessary to properly manage the lifecycle of a keyswitch join. It should be called after a successful join to ensure that resources are correctly released. This function returns a pointer to the underlying shared memory region on success, allowing further operations on the memory if needed. If the provided keyswitch pointer is NULL, the function logs a warning and returns NULL, indicating failure.
- **Inputs**:
    - `ks`: A pointer to a `fd_keyswitch_t` structure representing the current local join to a keyswitch. Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the input is invalid.
- **See also**: [`fd_keyswitch_leave`](fd_keyswitch.c.driver.md#fd_keyswitch_leave)  (Implementation)


---
### fd\_keyswitch\_delete<!-- {{#callable_declaration:fd_keyswitch_delete}} -->
Unformats a memory region used as a keyswitch.
- **Description**: Use this function to unformat a memory region that was previously formatted as a keyswitch, assuming no threads are currently joined to it. This function should be called when the keyswitch is no longer needed, and it transfers ownership of the memory region back to the caller. It is important to ensure that the provided pointer is correctly aligned and points to a valid keyswitch; otherwise, the function will return NULL and log a warning.
- **Inputs**:
    - `shkc`: A pointer to the memory region that is currently formatted as a keyswitch. It must be non-NULL, properly aligned according to fd_keyswitch_align(), and point to a valid keyswitch structure. If these conditions are not met, the function returns NULL and logs a warning.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the input is invalid.
- **See also**: [`fd_keyswitch_delete`](fd_keyswitch.c.driver.md#fd_keyswitch_delete)  (Implementation)


