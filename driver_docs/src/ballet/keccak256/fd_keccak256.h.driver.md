# Purpose
This C header file defines the interface for a Keccak256 hashing implementation, which is a cryptographic hash function. It provides macros and function prototypes for managing the memory alignment and footprint required for the hashing state, as well as for initializing, appending data to, and finalizing a Keccak256 hash calculation. The file includes a structure definition for `fd_keccak256_t`, which represents the internal state of the hash calculation, and ensures proper memory alignment for performance optimization. The functions [`fd_keccak256_init`](#fd_keccak256_init), [`fd_keccak256_append`](#fd_keccak256_append), and [`fd_keccak256_fini`](#fd_keccak256_fini) are used to perform the hashing process, while [`fd_keccak256_hash`](#fd_keccak256_hash) offers a convenience function to compute the hash in a single call. This header is designed to be used in conjunction with other source files that implement the actual hashing logic.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_keccak256\_new
- **Type**: `function pointer`
- **Description**: The `fd_keccak256_new` is a function that initializes a new Keccak256 hashing state in a given shared memory region. It is part of the Keccak256 hashing API, which provides functions for creating, managing, and finalizing Keccak256 hash calculations.
- **Use**: This function is used to allocate and initialize a new Keccak256 hashing state in a specified shared memory region, preparing it for subsequent hashing operations.


---
### fd\_keccak256\_join
- **Type**: `fd_keccak256_t *`
- **Description**: The `fd_keccak256_join` function returns a pointer to a `fd_keccak256_t` structure, which represents the state of a Keccak256 hashing operation. This function is used to join a shared memory region that holds the state of a Keccak256 calculation, allowing the caller to interact with the hashing state.
- **Use**: This variable is used to manage and access the state of a Keccak256 hashing operation by joining a shared memory region.


---
### fd\_keccak256\_leave
- **Type**: `void *`
- **Description**: The `fd_keccak256_leave` function is a global function that takes a pointer to a `fd_keccak256_t` structure, which represents the state of a Keccak256 hashing operation. This function is part of the API for managing the lifecycle of a Keccak256 hashing state, specifically for leaving or detaching from the current hashing state.
- **Use**: This function is used to leave or detach from a Keccak256 hashing state, effectively ending the current session with the hashing state.


---
### fd\_keccak256\_delete
- **Type**: `function pointer`
- **Description**: `fd_keccak256_delete` is a function pointer that is used to delete or clean up a Keccak256 hashing state. It takes a single argument, `shsha`, which is a pointer to the memory region holding the Keccak256 state, and returns a pointer to the same memory region after deletion.
- **Use**: This function is used to properly dispose of a Keccak256 hashing state, ensuring that any resources allocated for the hashing process are released.


---
### fd\_keccak256\_init
- **Type**: `fd_keccak256_t *`
- **Description**: The `fd_keccak256_init` function initializes a Keccak256 hashing calculation state. It takes a pointer to a `fd_keccak256_t` structure, which represents the state of the hashing process, and prepares it for a new hashing operation by discarding any preexisting state.
- **Use**: This function is used to start a new Keccak256 hashing operation by initializing the state structure.


---
### fd\_keccak256\_append
- **Type**: `function pointer`
- **Description**: The `fd_keccak256_append` is a function that appends a specified number of bytes from a data source to an in-progress Keccak256 hash calculation. It takes a pointer to a `fd_keccak256_t` structure, a pointer to the data to be appended, and the size of the data in bytes.
- **Use**: This function is used to update the state of a Keccak256 hash calculation by adding more data to it.


---
### fd\_keccak256\_fini
- **Type**: `function pointer`
- **Description**: The `fd_keccak256_fini` is a function that completes a Keccak256 hashing operation. It takes a pointer to a `fd_keccak256_t` structure, which represents the state of the hashing operation, and a pointer to a memory region where the resulting 32-byte hash will be stored.
- **Use**: This function is used to finalize the Keccak256 hash calculation and store the result in the provided memory location.


---
### fd\_keccak256\_hash
- **Type**: `function`
- **Description**: The `fd_keccak256_hash` function is a convenience function for performing a complete Keccak256 hash calculation on a given data input. It initializes a Keccak256 state, appends the data to the state, and finalizes the hash calculation, storing the result in the provided hash buffer.
- **Use**: This function is used to compute the Keccak256 hash of a data block in a single call, simplifying the process of hashing by encapsulating initialization, data appending, and finalization steps.


# Data Structures

---
### fd\_keccak256\_private
- **Type**: `struct`
- **Members**:
    - `state`: An array of 25 unsigned long integers representing the internal state of the Keccak256 hashing algorithm.
    - `magic`: A constant value used to verify the integrity of the structure, set to FD_KECCAK256_MAGIC.
    - `padding_start`: Indicates the number of buffered bytes, ranging from 0 to FD_KECCAK256_BUF_MAX.
- **Description**: The `fd_keccak256_private` structure is a data structure used to maintain the state of a Keccak256 hashing operation. It is aligned to 128 bytes for performance reasons and contains an array `state` to hold the internal state of the hashing algorithm, a `magic` number for integrity verification, and a `padding_start` field to track the number of bytes buffered during the hashing process. This structure is designed to be used internally within the Keccak256 hashing API to manage the state and progress of hash calculations.


---
### fd\_keccak256\_t
- **Type**: `struct`
- **Members**:
    - `state`: An array of 25 unsigned long integers representing the internal state of the Keccak256 hashing algorithm.
    - `magic`: A unique identifier set to FD_KECCAK256_MAGIC to verify the integrity of the structure.
    - `padding_start`: Indicates the number of buffered bytes, ranging from 0 to FD_KECCAK256_BUF_MAX.
- **Description**: The `fd_keccak256_t` structure is a private data structure used to maintain the state of a Keccak256 hashing operation. It is aligned to 128 bytes to optimize memory access and reduce false sharing. The structure contains an internal state array, a magic number for validation, and a padding_start field to track buffered bytes. This structure is designed to be opaque to users, providing a handle for managing the hashing process through various API functions.


# Function Declarations (Public API)

---
### fd\_keccak256\_align<!-- {{#callable_declaration:fd_keccak256_align}} -->
Returns the alignment requirement for a Keccak256 hashing state.
- **Description**: Use this function to obtain the alignment requirement for memory regions intended to hold a Keccak256 hashing state. This is useful for ensuring that memory allocations are correctly aligned to meet the requirements of the Keccak256 implementation, which can help avoid performance penalties or incorrect behavior due to misalignment. The alignment value is a constant and is a power of 2, suitable for use in compile-time declarations.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the alignment requirement in bytes.
- **See also**: [`fd_keccak256_align`](fd_keccak256.c.driver.md#fd_keccak256_align)  (Implementation)


---
### fd\_keccak256\_footprint<!-- {{#callable_declaration:fd_keccak256_footprint}} -->
Returns the memory footprint required for a Keccak256 hashing state.
- **Description**: Use this function to determine the size of the memory region required to hold a Keccak256 hashing state. This is useful for allocating memory when setting up a Keccak256 hashing operation. The function does not require any parameters and can be called at any time to retrieve the constant footprint size.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the memory footprint size in bytes needed for a Keccak256 hashing state.
- **See also**: [`fd_keccak256_footprint`](fd_keccak256.c.driver.md#fd_keccak256_footprint)  (Implementation)


---
### fd\_keccak256\_new<!-- {{#callable_declaration:fd_keccak256_new}} -->
Initialize a new Keccak256 hashing state in shared memory.
- **Description**: This function sets up a new Keccak256 hashing state in the provided shared memory region. It should be called when you need to start a new hashing operation and have a memory region prepared for this purpose. The memory region must be properly aligned and of sufficient size as specified by the alignment and footprint requirements. If the memory is null or misaligned, the function will return null and log a warning. This function is typically used in environments where memory management is critical, such as embedded systems or high-performance applications.
- **Inputs**:
    - `shmem`: A pointer to a memory region where the Keccak256 state will be initialized. The memory must be aligned to FD_KECCAK256_ALIGN and have a size of at least FD_KECCAK256_FOOTPRINT. The caller retains ownership of this memory. If the pointer is null or the memory is misaligned, the function returns null.
- **Output**: A pointer to the initialized Keccak256 state, or null if the input memory is null or misaligned.
- **See also**: [`fd_keccak256_new`](fd_keccak256.c.driver.md#fd_keccak256_new)  (Implementation)


---
### fd\_keccak256\_join<!-- {{#callable_declaration:fd_keccak256_join}} -->
Joins a shared memory region to a Keccak256 hashing state.
- **Description**: This function is used to associate a shared memory region with a Keccak256 hashing state, allowing further operations on the hashing state. It should be called when you have a shared memory region that has been properly initialized and aligned for Keccak256 operations. The function checks for null pointers, proper alignment, and a valid magic number to ensure the memory region is correctly set up. If any of these checks fail, the function returns NULL, indicating an error. This function is typically used in conjunction with other Keccak256 functions to perform hashing operations.
- **Inputs**:
    - `shsha`: A pointer to a shared memory region intended to hold a Keccak256 hashing state. It must not be null, must be aligned according to fd_keccak256_align(), and must contain a valid magic number (FD_KECCAK256_MAGIC). The caller retains ownership of the memory.
- **Output**: Returns a pointer to a fd_keccak256_t structure if successful, or NULL if the input is invalid or checks fail.
- **See also**: [`fd_keccak256_join`](fd_keccak256.c.driver.md#fd_keccak256_join)  (Implementation)


---
### fd\_keccak256\_leave<!-- {{#callable_declaration:fd_keccak256_leave}} -->
Leaves a Keccak256 hashing state.
- **Description**: Use this function to leave a Keccak256 hashing state that was previously joined. It should be called when the hashing operation is complete, and no further operations on the state are needed. This function is essential for managing the lifecycle of a Keccak256 state, ensuring that resources are properly released or transitioned. It must be called with a valid pointer to a `fd_keccak256_t` structure that represents a current local join to a Keccak256 calculation state. If the provided pointer is null, the function will log a warning and return null.
- **Inputs**:
    - `sha`: A pointer to a `fd_keccak256_t` structure representing a Keccak256 calculation state. Must not be null. If null, a warning is logged and null is returned.
- **Output**: Returns a void pointer to the `fd_keccak256_t` structure if successful, or null if the input was null.
- **See also**: [`fd_keccak256_leave`](fd_keccak256.c.driver.md#fd_keccak256_leave)  (Implementation)


---
### fd\_keccak256\_delete<!-- {{#callable_declaration:fd_keccak256_delete}} -->
Deletes a Keccak256 hashing state object.
- **Description**: Use this function to safely delete a Keccak256 hashing state object that was previously created. It should be called when the hashing state is no longer needed to ensure proper cleanup. The function checks for a valid, aligned, and initialized state object before deletion. It is important to ensure that the pointer provided is not null, is properly aligned according to the required alignment, and has a valid magic number indicating a correctly initialized state. If any of these conditions are not met, the function will log a warning and return null.
- **Inputs**:
    - `shsha`: A pointer to the Keccak256 hashing state object to be deleted. It must not be null, must be aligned according to FD_KECCAK256_ALIGN, and must have a valid magic number. If these conditions are not met, the function will return null and log a warning.
- **Output**: Returns the pointer to the deleted state object if successful, or null if the input was invalid.
- **See also**: [`fd_keccak256_delete`](fd_keccak256.c.driver.md#fd_keccak256_delete)  (Implementation)


---
### fd\_keccak256\_init<!-- {{#callable_declaration:fd_keccak256_init}} -->
Initialize a Keccak256 hashing state.
- **Description**: Use this function to start a new Keccak256 hashing operation. It prepares the provided hashing state for a new calculation by resetting any existing state. This function must be called before appending data or finalizing the hash. Ensure that the `sha` parameter is a valid, locally joined Keccak256 calculation state with no concurrent modifications during execution.
- **Inputs**:
    - `sha`: A pointer to a `fd_keccak256_t` structure representing the Keccak256 calculation state. It must be a valid, locally joined state with no concurrent operations modifying it. The caller retains ownership and must ensure it is properly aligned and allocated.
- **Output**: Returns the initialized `fd_keccak256_t` pointer, ready for appending data and finalizing the hash.
- **See also**: [`fd_keccak256_init`](fd_keccak256.c.driver.md#fd_keccak256_init)  (Implementation)


---
### fd\_keccak256\_append<!-- {{#callable_declaration:fd_keccak256_append}} -->
Appends data to an in-progress Keccak256 hash calculation.
- **Description**: Use this function to add data to an ongoing Keccak256 hash computation. It should be called after initializing the hash state with `fd_keccak256_init` and before finalizing the hash with `fd_keccak256_fini`. The function updates the hash state with the provided data, and it is optimized for appending large chunks of data at once, preferably in multiples of 64 bytes for better performance. The function assumes that the `sha` parameter is a valid, locally joined Keccak256 state with no concurrent modifications, and that the `data` pointer is valid if `sz` is non-zero.
- **Inputs**:
    - `sha`: A pointer to a `fd_keccak256_t` structure representing the current state of the Keccak256 calculation. Must be a valid, locally joined state with no concurrent modifications.
    - `data`: A pointer to the data to be appended to the hash. Can be `NULL` if `sz` is zero. The data is not modified by the function, and no reference is retained after the function returns.
    - `sz`: The size in bytes of the data to append. If zero, the function does nothing and returns immediately.
- **Output**: Returns the updated `fd_keccak256_t` pointer, representing the state of the in-progress hash calculation.
- **See also**: [`fd_keccak256_append`](fd_keccak256.c.driver.md#fd_keccak256_append)  (Implementation)


---
### fd\_keccak256\_fini<!-- {{#callable_declaration:fd_keccak256_fini}} -->
Completes a Keccak256 hash calculation and stores the result.
- **Description**: This function finalizes an in-progress Keccak256 hash calculation and writes the resulting 32-byte hash to the specified memory location. It should be called after all data has been appended to the hash state using `fd_keccak256_append`. The function assumes that `sha` is a valid, locally joined Keccak256 calculation state with no concurrent modifications, and `hash` is a pointer to a memory region of at least 32 bytes where the hash result will be stored. After execution, the calculation state in `sha` is no longer in progress.
- **Inputs**:
    - `sha`: A pointer to a `fd_keccak256_t` structure representing the current state of a Keccak256 calculation. Must be a valid local join with no concurrent modifications.
    - `hash`: A pointer to a memory region of at least 32 bytes where the resulting hash will be stored. Must not be null.
- **Output**: Returns the `hash` pointer, with the 32-byte hash result written to the memory location it points to.
- **See also**: [`fd_keccak256_fini`](fd_keccak256.c.driver.md#fd_keccak256_fini)  (Implementation)


---
### fd\_keccak256\_hash<!-- {{#callable_declaration:fd_keccak256_hash}} -->
Computes the Keccak256 hash of the given data.
- **Description**: Use this function to compute the Keccak256 hash of a specified data buffer. It is a convenience function that initializes a hashing state, processes the input data, and finalizes the hash computation, storing the result in the provided output buffer. This function is useful when you need a quick and straightforward way to hash data without managing the hashing state manually. Ensure that the output buffer is at least 32 bytes in size to accommodate the hash result.
- **Inputs**:
    - `_data`: Pointer to the data to be hashed. Must not be null if sz is greater than 0. The caller retains ownership and the data is not modified.
    - `sz`: The size in bytes of the data to be hashed. Can be zero, in which case _data can be null.
    - `_hash`: Pointer to a memory region where the 32-byte hash result will be stored. Must not be null and must have at least 32 bytes available.
- **Output**: Returns the pointer to the hash buffer, which contains the 32-byte Keccak256 hash of the input data.
- **See also**: [`fd_keccak256_hash`](fd_keccak256.c.driver.md#fd_keccak256_hash)  (Implementation)


