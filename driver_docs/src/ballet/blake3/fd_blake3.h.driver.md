# Purpose
This C header file, `fd_blake3.h`, provides a set of APIs for performing BLAKE3 hashing operations. It defines the necessary structures, constants, and function prototypes to facilitate the use of BLAKE3, a cryptographic hash function known for its speed and security. The file includes definitions for memory alignment and footprint requirements, ensuring that the data structures used for hashing are optimally aligned in memory to enhance performance and reduce false sharing. The core data structure, `fd_blake3_t`, is treated as an opaque handle to maintain abstraction and encapsulation of the hashing state.

The file offers a comprehensive suite of functions to manage the lifecycle of a BLAKE3 hashing operation, including initialization ([`fd_blake3_init`](#fd_blake3_init)), data appending ([`fd_blake3_append`](#fd_blake3_append)), and finalization ([`fd_blake3_fini`](#fd_blake3_fini), [`fd_blake3_fini_512`](#fd_blake3_fini_512), [`fd_blake3_fini_varlen`](#fd_blake3_fini_varlen)). These functions allow users to compute hash values of varying lengths, including the standard 256-bit, 512-bit, and variable-length outputs. The header file is designed to be included in other C source files, providing a public API for BLAKE3 hashing operations, and it relies on the underlying `blake3.h` for the core hashing logic. This modular design allows for easy integration and use in larger software projects that require cryptographic hashing capabilities.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `blake3.h`


# Global Variables

---
### fd\_blake3\_new
- **Type**: `function pointer`
- **Description**: The `fd_blake3_new` is a function that initializes a new BLAKE3 hashing state in a given shared memory region. It returns a pointer to the initialized memory region, which is expected to be aligned and have sufficient footprint as defined by `FD_BLAKE3_ALIGN` and `FD_BLAKE3_FOOTPRINT`. This function is part of a suite of functions for managing BLAKE3 hashing states.
- **Use**: This function is used to allocate and initialize a new BLAKE3 hashing state in shared memory.


---
### fd\_blake3\_join
- **Type**: `fd_blake3_t *`
- **Description**: The `fd_blake3_join` function returns a pointer to a `fd_blake3_t` structure, which represents a handle to a BLAKE3 hashing calculation state. This function is used to join a shared memory region that holds the state of a BLAKE3 hash calculation.
- **Use**: This variable is used to manage and access the state of a BLAKE3 hash calculation by joining a shared memory region.


---
### fd\_blake3\_leave
- **Type**: `function pointer`
- **Description**: The `fd_blake3_leave` is a function that takes a pointer to a `fd_blake3_t` structure, which represents a BLAKE3 hashing state, and returns a void pointer. This function is part of the API for managing the lifecycle of a BLAKE3 hashing operation, specifically for leaving or detaching from a BLAKE3 hashing state.
- **Use**: This function is used to leave or detach from a BLAKE3 hashing state, effectively ending the current session with the hashing state.


---
### fd\_blake3\_delete
- **Type**: `function pointer`
- **Description**: The `fd_blake3_delete` is a function that takes a pointer to a BLAKE3 hashing state and deletes or cleans up the associated resources. It is part of a suite of functions designed to manage the lifecycle of a BLAKE3 hashing operation, including initialization, appending data, and finalizing the hash.
- **Use**: This function is used to properly release resources associated with a BLAKE3 hashing state after its use is complete.


---
### fd\_blake3\_init
- **Type**: `fd_blake3_t *`
- **Description**: The `fd_blake3_init` function initializes a BLAKE3 hashing calculation state. It takes a pointer to a `fd_blake3_t` structure, which represents the state of a BLAKE3 hash calculation, and prepares it for a new hashing operation.
- **Use**: This function is used to reset or initialize the hashing state to start a new BLAKE3 hash calculation.


---
### fd\_blake3\_append
- **Type**: `function pointer`
- **Description**: The `fd_blake3_append` is a function pointer that represents a function used to add a specified number of bytes to an in-progress BLAKE3 hash calculation. It takes a pointer to a `fd_blake3_t` structure, a pointer to the data to be appended, and the size of the data in bytes. The function updates the hash state with the new data and returns the updated `fd_blake3_t` pointer.
- **Use**: This function is used to append data to an ongoing BLAKE3 hash calculation, updating the hash state with the new data.


---
### fd\_blake3\_fini
- **Type**: `function`
- **Description**: The `fd_blake3_fini` function is used to complete a BLAKE3 hashing operation. It takes a pointer to a `fd_blake3_t` structure, which represents the current state of the hash calculation, and a pointer to a memory region where the resulting 32-byte hash will be stored. Upon completion, the function returns the pointer to the hash memory region, and the hash calculation state is reset.
- **Use**: This function is used to finalize a BLAKE3 hash calculation and store the result in a specified memory location.


---
### fd\_blake3\_fini\_512
- **Type**: `function pointer`
- **Description**: The `fd_blake3_fini_512` is a function that finalizes a BLAKE3 hashing operation and returns a 512-bit hash value. It takes a pointer to a `fd_blake3_t` structure, which represents the current state of the BLAKE3 calculation, and a pointer to a memory region where the resulting 512-bit hash will be stored.
- **Use**: This function is used to complete a BLAKE3 hashing operation and obtain a 512-bit hash from the provided calculation state.


---
### fd\_blake3\_fini\_varlen
- **Type**: `function`
- **Description**: The `fd_blake3_fini_varlen` function is a variant of the `fd_blake3_fini` function that finalizes a BLAKE3 hashing operation and writes the resulting hash to a specified memory location. Unlike `fd_blake3_fini`, which produces a fixed 256-bit hash, `fd_blake3_fini_varlen` allows the caller to specify the length of the hash output via the `hash_len` parameter.
- **Use**: This function is used to complete a BLAKE3 hashing operation and obtain a hash of a specified length.


# Data Structures

---
### fd\_blake3\_private
- **Type**: `struct`
- **Members**:
    - `hasher`: A `blake3_hasher` object that holds the state of the BLAKE3 hashing process.
    - `magic`: A `ulong` value set to `FD_BLAKE3_MAGIC` to verify the integrity and version of the structure.
- **Description**: The `fd_blake3_private` structure is a custom data type used to encapsulate the state of a BLAKE3 hashing operation. It includes a `blake3_hasher` object to manage the hashing process and a `magic` number to ensure the structure's integrity and compatibility with the expected version. This structure is aligned according to `FD_BLAKE3_ALIGN` to optimize memory access and prevent false sharing, making it suitable for high-performance cryptographic operations.


---
### fd\_blake3\_t
- **Type**: `struct`
- **Members**:
    - `hasher`: A `blake3_hasher` object that holds the state of the BLAKE3 hashing process.
    - `magic`: A `ulong` value set to `FD_BLAKE3_MAGIC` to verify the integrity and version of the structure.
- **Description**: The `fd_blake3_t` structure is an opaque handle used to manage the state of a BLAKE3 hashing operation. It contains a `blake3_hasher` to maintain the hashing state and a `magic` number for integrity checks. The structure is aligned according to `FD_BLAKE3_ALIGN` to optimize memory access and is used in conjunction with various functions to initialize, update, and finalize BLAKE3 hash calculations.


# Function Declarations (Public API)

---
### fd\_blake3\_align<!-- {{#callable_declaration:fd_blake3_align}} -->
Returns the alignment requirement for a BLAKE3 hashing state.
- **Description**: Use this function to obtain the alignment requirement for memory regions intended to hold a BLAKE3 hashing state. This is useful for ensuring that memory allocations are correctly aligned to meet the requirements of the BLAKE3 implementation, which can help avoid performance penalties due to misalignment. The alignment value is a power of 2 and is recommended to be at least double the cache line size to mitigate false sharing issues.
- **Inputs**: None
- **Output**: Returns an unsigned long integer representing the alignment requirement for a BLAKE3 hashing state.
- **See also**: [`fd_blake3_align`](fd_blake3.c.driver.md#fd_blake3_align)  (Implementation)


---
### fd\_blake3\_footprint<!-- {{#callable_declaration:fd_blake3_footprint}} -->
Returns the memory footprint required for a BLAKE3 hashing state.
- **Description**: Use this function to determine the size of the memory region required to store a BLAKE3 hashing state. This is useful for allocating memory when setting up a BLAKE3 hashing operation. The function does not require any parameters and can be called at any time to retrieve the constant footprint size.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the memory footprint size in bytes needed for a BLAKE3 hashing state.
- **See also**: [`fd_blake3_footprint`](fd_blake3.c.driver.md#fd_blake3_footprint)  (Implementation)


---
### fd\_blake3\_new<!-- {{#callable_declaration:fd_blake3_new}} -->
Initialize a BLAKE3 hashing state in shared memory.
- **Description**: This function initializes a BLAKE3 hashing state in a provided shared memory region. It should be called when you need to set up a new BLAKE3 hashing context. The shared memory must be properly aligned and have sufficient footprint as defined by FD_BLAKE3_ALIGN and FD_BLAKE3_FOOTPRINT. If the memory is null or misaligned, the function will return null and log a warning. This function prepares the memory for use with other BLAKE3 operations, ensuring the state is correctly initialized.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region where the BLAKE3 state will be initialized. The memory must be aligned to FD_BLAKE3_ALIGN and have a size of at least FD_BLAKE3_FOOTPRINT. The caller retains ownership of the memory. If null or misaligned, the function returns null.
- **Output**: Returns a pointer to the initialized BLAKE3 state on success, or null if the input memory is null or misaligned.
- **See also**: [`fd_blake3_new`](fd_blake3.c.driver.md#fd_blake3_new)  (Implementation)


---
### fd\_blake3\_join<!-- {{#callable_declaration:fd_blake3_join}} -->
Joins a shared BLAKE3 state for local use.
- **Description**: This function is used to join a shared BLAKE3 hashing state, allowing it to be used locally. It should be called with a pointer to a memory region that has been properly aligned and initialized for BLAKE3 operations. The function checks for null pointers, proper alignment, and a valid magic number to ensure the integrity of the BLAKE3 state. If any of these checks fail, the function returns NULL, indicating an error. This function is typically used after creating a new BLAKE3 state with `fd_blake3_new` and before performing hashing operations.
- **Inputs**:
    - `shsha`: A pointer to a memory region representing a shared BLAKE3 state. It must not be null, must be aligned according to `fd_blake3_align()`, and must contain a valid BLAKE3 state with the correct magic number. If these conditions are not met, the function returns NULL.
- **Output**: Returns a pointer to a `fd_blake3_t` structure if successful, or NULL if the input is invalid.
- **See also**: [`fd_blake3_join`](fd_blake3.c.driver.md#fd_blake3_join)  (Implementation)


---
### fd\_blake3\_leave<!-- {{#callable_declaration:fd_blake3_leave}} -->
Leaves a BLAKE3 hashing state.
- **Description**: This function is used to leave a BLAKE3 hashing state, effectively ending the current session with the given hashing state. It should be called when the hashing operations on the state are complete, and no further operations will be performed on it. This function must be called with a valid pointer to a `fd_blake3_t` structure that represents a current local join to a BLAKE3 calculation state. If the provided pointer is null, the function will log a warning and return null, indicating that the operation was not successful.
- **Inputs**:
    - `sha`: A pointer to a `fd_blake3_t` structure representing a BLAKE3 calculation state. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a void pointer to the `fd_blake3_t` structure if successful, or null if the input was invalid.
- **See also**: [`fd_blake3_leave`](fd_blake3.c.driver.md#fd_blake3_leave)  (Implementation)


---
### fd\_blake3\_delete<!-- {{#callable_declaration:fd_blake3_delete}} -->
Deletes a BLAKE3 hashing state object.
- **Description**: Use this function to safely delete a BLAKE3 hashing state object that was previously created. It should be called when the hashing state is no longer needed, ensuring that resources are properly released. The function checks if the provided pointer is non-null, properly aligned, and has a valid magic number before proceeding with the deletion. If any of these checks fail, a warning is logged and the function returns NULL. This function must be called only on objects that were successfully initialized and not concurrently accessed by other operations.
- **Inputs**:
    - `shsha`: A pointer to the BLAKE3 hashing state object to be deleted. It must not be null, must be aligned according to fd_blake3_align(), and must have a valid magic number. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns the original pointer if the deletion is successful, or NULL if the input is invalid.
- **See also**: [`fd_blake3_delete`](fd_blake3.c.driver.md#fd_blake3_delete)  (Implementation)


---
### fd\_blake3\_init<!-- {{#callable_declaration:fd_blake3_init}} -->
Initialize a BLAKE3 hashing calculation state.
- **Description**: This function initializes a BLAKE3 hashing calculation state, preparing it for a new hashing operation. It should be called when starting a new hash calculation, ensuring that any previous state is discarded. The function assumes that the provided `sha` is a valid, locally joined BLAKE3 calculation state with no concurrent modifications. After calling this function, the `sha` will be in a state ready for appending data to the hash calculation.
- **Inputs**:
    - `sha`: A pointer to a `fd_blake3_t` structure representing the BLAKE3 calculation state. It must be a valid, locally joined state with no concurrent operations modifying it. The caller retains ownership and responsibility for ensuring its validity.
- **Output**: Returns the same `fd_blake3_t` pointer passed in, now initialized for a new BLAKE3 hash calculation.
- **See also**: [`fd_blake3_init`](fd_blake3.c.driver.md#fd_blake3_init)  (Implementation)


---
### fd\_blake3\_append<!-- {{#callable_declaration:fd_blake3_append}} -->
Appends data to an in-progress BLAKE3 hash calculation.
- **Description**: Use this function to add data to an ongoing BLAKE3 hash computation. It should be called after initializing the hash state with `fd_blake3_init` and before finalizing the hash with `fd_blake3_fini` or its variants. The function updates the hash state with the provided data, and it is safe to call with `data` as `NULL` if `sz` is `0`. For optimal performance, append as much data as possible at once, ideally in multiples of 64 bytes, except for the final append which should be less than 56 bytes if possible.
- **Inputs**:
    - `sha`: A pointer to a `fd_blake3_t` structure representing the current hash state. Must be a valid local join to a BLAKE3 calculation state with no concurrent modifications.
    - `data`: A pointer to the data to be hashed. Can be `NULL` if `sz` is `0`. The data is not modified and no reference is retained after the function returns.
    - `sz`: The number of bytes to append from `data`. Must be `0` if `data` is `NULL`.
- **Output**: Returns the updated `fd_blake3_t` pointer, representing the hash state after appending the data.
- **See also**: [`fd_blake3_append`](fd_blake3.c.driver.md#fd_blake3_append)  (Implementation)


---
### fd\_blake3\_fini<!-- {{#callable_declaration:fd_blake3_fini}} -->
Completes a BLAKE3 hash calculation and stores the result.
- **Description**: This function finalizes an in-progress BLAKE3 hash calculation and writes the resulting 256-bit hash to the specified memory location. It should be called after all data has been appended to the hash state using `fd_blake3_append`. The function assumes that `sha` is a valid, locally joined BLAKE3 calculation state with no concurrent modifications, and that `hash` points to a valid 32-byte memory region. After execution, the hash state will no longer have an in-progress calculation, and the provided buffer will contain the hash result.
- **Inputs**:
    - `sha`: A pointer to a `fd_blake3_t` structure representing the BLAKE3 calculation state. It must be a valid local join with no concurrent modifications.
    - `hash`: A pointer to a 32-byte memory region where the 256-bit hash result will be stored. The pointer must be valid and point to a writable memory area.
- **Output**: Returns the `hash` pointer, now containing the 256-bit hash result.
- **See also**: [`fd_blake3_fini`](fd_blake3.c.driver.md#fd_blake3_fini)  (Implementation)


---
### fd\_blake3\_fini\_512<!-- {{#callable_declaration:fd_blake3_fini_512}} -->
Completes a BLAKE3 hashing operation and returns a 512-bit hash.
- **Description**: This function finalizes an in-progress BLAKE3 hashing operation and writes the resulting 512-bit hash to the specified memory location. It should be called after all data has been appended to the hash state using `fd_blake3_append`. The function assumes that `sha` is a valid, locally joined BLAKE3 calculation state with no concurrent modifications, and that `hash` points to a memory region of at least 64 bytes where the hash result will be stored. After execution, the hash state will no longer have an in-progress calculation.
- **Inputs**:
    - `sha`: A pointer to a `fd_blake3_t` structure representing the current BLAKE3 calculation state. Must be a valid local join with no concurrent modifications.
    - `hash`: A pointer to a memory region of at least 64 bytes where the 512-bit hash result will be stored. The caller must ensure this memory is valid and writable.
- **Output**: Returns the `hash` pointer, which now contains the 512-bit hash result.
- **See also**: [`fd_blake3_fini_512`](fd_blake3.c.driver.md#fd_blake3_fini_512)  (Implementation)


---
### fd\_blake3\_fini\_varlen<!-- {{#callable_declaration:fd_blake3_fini_varlen}} -->
Completes a BLAKE3 hash calculation and writes a variable-length hash.
- **Description**: Use this function to finalize a BLAKE3 hash calculation and obtain a hash of a specified length. It should be called after initializing and appending data to the hash state using the appropriate functions. The function requires a valid BLAKE3 calculation state and a memory region to store the resulting hash. The length of the hash is specified by the caller, and the function will write the hash to the provided memory region. Ensure that the memory region is large enough to accommodate the requested hash length.
- **Inputs**:
    - `sha`: A pointer to a valid fd_blake3_t structure representing the current BLAKE3 calculation state. It must be a local join with no concurrent modifications.
    - `hash`: A pointer to a memory region where the resulting hash will be stored. The region must be large enough to hold 'hash_len' bytes.
    - `hash_len`: The number of bytes to write to the hash memory region. It specifies the desired length of the hash output.
- **Output**: Returns the pointer to the hash memory region, now containing the calculated hash of the specified length.
- **See also**: [`fd_blake3_fini_varlen`](fd_blake3.c.driver.md#fd_blake3_fini_varlen)  (Implementation)


