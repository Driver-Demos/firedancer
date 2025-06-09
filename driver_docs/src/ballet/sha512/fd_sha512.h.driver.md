# Purpose
The provided C header file defines a comprehensive API for performing SHA-512 and SHA-384 cryptographic hash operations. It includes definitions for the necessary data structures, constants, and function prototypes required to initialize, update, and finalize hash computations. The file specifies memory alignment and footprint requirements for the hash state structures, ensuring efficient memory usage and performance optimization, particularly in multi-threaded environments where false sharing might be a concern. The API is designed to be flexible, allowing for both single and batched hash computations, with optimizations for different hardware capabilities such as AVX and AVX-512 instruction sets.

The header file defines several key components, including the `fd_sha512_t` and `fd_sha384_t` types, which represent the state of an ongoing hash computation. It provides functions to manage the lifecycle of these states, such as [`fd_sha512_new`](#fd_sha512_new), [`fd_sha512_join`](#fd_sha512_join), [`fd_sha512_leave`](#fd_sha512_leave), and [`fd_sha512_delete`](#fd_sha512_delete), which handle memory allocation and deallocation. The core hashing operations are encapsulated in functions like [`fd_sha512_init`](#fd_sha512_init), [`fd_sha512_append`](#fd_sha512_append), and [`fd_sha512_fini`](#fd_sha512_fini), which initialize the hash state, append data to be hashed, and finalize the hash computation, respectively. Additionally, the file includes batch processing capabilities, allowing multiple hash computations to be processed simultaneously, leveraging SIMD instructions for performance gains. This makes the API suitable for high-performance applications requiring secure and efficient hash computations.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_sha512\_new
- **Type**: `function pointer`
- **Description**: The `fd_sha512_new` function is a global function pointer that initializes a memory region to hold a SHA-512 calculation state. It takes a pointer to a memory region (`shmem`) as an argument and returns the same pointer on success or `NULL` on failure.
- **Use**: This function is used to format a memory region with the necessary alignment and footprint for SHA-512 hashing operations.


---
### fd\_sha512\_join
- **Type**: `fd_sha512_t *`
- **Description**: The `fd_sha512_join` function is a global function that returns a pointer to a `fd_sha512_t` structure. This function is used to join a caller to a SHA-512 calculation state, which is represented by the `fd_sha512_t` structure.
- **Use**: This function is used to obtain a local handle to a SHA-512 calculation state by providing a pointer to the memory region holding the state.


---
### fd\_sha512\_leave
- **Type**: `function`
- **Description**: The `fd_sha512_leave` function is used to leave a current local join to a SHA-512 calculation state. It takes a pointer to a `fd_sha512_t` structure, which represents the SHA-512 calculation state, and returns a pointer to the memory region holding the state on success or NULL on failure.
- **Use**: This function is used to disassociate a caller from a SHA-512 calculation state, effectively ending the caller's interaction with that state.


---
### fd\_sha512\_delete
- **Type**: `function pointer`
- **Description**: `fd_sha512_delete` is a function pointer that points to a function designed to unformat a memory region holding a SHA-512 calculation state. It takes a pointer to the memory region as an argument and returns a pointer to the memory region on success or NULL on failure.
- **Use**: This function is used to release or reset the memory region associated with a SHA-512 calculation state, ensuring that the caller regains ownership of the memory.


---
### fd\_sha512\_init
- **Type**: `fd_sha512_t *`
- **Description**: The `fd_sha512_init` function initializes a SHA-512 calculation state. It takes a pointer to an `fd_sha512_t` structure, which represents the state of a SHA-512 hash calculation, and prepares it for a new hashing operation.
- **Use**: This function is used to start a new SHA-512 hashing process by resetting the state of the provided `fd_sha512_t` structure.


---
### fd\_sha384\_init
- **Type**: `fd_sha512_t *`
- **Description**: The `fd_sha384_init` function is a global function that initializes a SHA-384 hashing calculation state. It takes a pointer to a `fd_sha512_t` structure, which represents the internal state of the SHA-512 calculation, and prepares it for a new SHA-384 hashing operation.
- **Use**: This function is used to reset or initialize the state of a SHA-384 hashing operation, discarding any previous state and preparing it for a new calculation.


---
### fd\_sha512\_append
- **Type**: `fd_sha512_t *`
- **Description**: The `fd_sha512_append` function is a global function that appends a specified number of bytes from a data buffer to an in-progress SHA-512 hash calculation. It takes a pointer to a SHA-512 calculation state, a pointer to the data to be appended, and the size of the data in bytes.
- **Use**: This function is used to update the state of an ongoing SHA-512 hash calculation by adding new data to it.


---
### fd\_sha512\_fini
- **Type**: `function`
- **Description**: The `fd_sha512_fini` function is used to complete a SHA-512 hashing operation. It takes a pointer to a SHA-512 calculation state (`fd_sha512_t * sha`) and a pointer to a memory region (`void * hash`) where the resulting 64-byte hash will be stored. Upon completion, the function returns the `hash` pointer, and the SHA-512 calculation state is no longer in progress.
- **Use**: This function is used to finalize a SHA-512 hash calculation and store the result in a specified memory location.


---
### fd\_sha384\_fini
- **Type**: `function`
- **Description**: The `fd_sha384_fini` function is used to complete a SHA-384 hashing operation. It takes a pointer to a SHA-384 calculation state (`fd_sha384_t *sha`) and a pointer to a memory region (`void *hash`) where the resulting hash will be stored. The function finalizes the hash calculation and populates the provided memory region with the 48-byte hash result.
- **Use**: This function is used to finalize a SHA-384 hash calculation and store the result in a specified memory location.


---
### fd\_sha512\_hash
- **Type**: `function pointer`
- **Description**: `fd_sha512_hash` is a function that performs a SHA-512 hash computation on a given data input. It initializes a SHA-512 calculation state, appends the data to it, and finalizes the hash computation, storing the result in the provided hash buffer.
- **Use**: This function is used to compute the SHA-512 hash of a data block in a streamlined manner, optimizing for small messages by reducing overhead.


---
### fd\_sha384\_hash
- **Type**: `function pointer`
- **Description**: `fd_sha384_hash` is a function that computes the SHA-384 hash of a given data input. It takes three parameters: a pointer to the data to be hashed, the size of the data, and a pointer to a memory location where the resulting hash will be stored. The function returns a pointer to the hash.
- **Use**: This function is used to perform a SHA-384 hash operation on a block of data, storing the result in the provided hash memory location.


# Data Structures

---
### fd\_sha512\_private
- **Type**: `struct`
- **Members**:
    - `buf`: Buffered message bytes that have not been added to the hash yet, indexed [0,buf_used).
    - `state`: Current state of the hash.
    - `magic`: A constant value equal to FD_SHA512_MAGIC, used for validation.
    - `buf_used`: Number of buffered bytes, in the range [0,FD_SHA512_PRIVATE_BUF_MAX).
    - `bit_cnt_lo`: Lower 64 bits of the total number of bits appended.
    - `bit_cnt_hi`: Upper 64 bits of the total number of bits appended.
- **Description**: The `fd_sha512_private` structure is a data structure used to maintain the state of a SHA-512 hashing operation. It includes a buffer for message bytes that have not yet been processed, the current state of the hash, and counters for the number of bits processed. The structure is aligned to 128 bytes to optimize performance and reduce false sharing in multi-threaded environments. It also contains a magic number for validation purposes.


---
### fd\_sha512\_t
- **Type**: `struct`
- **Members**:
    - `buf`: Buffered message bytes that have not been added to the hash yet.
    - `state`: Current state of the hash.
    - `magic`: Magic number to identify the structure, set to FD_SHA512_MAGIC.
    - `buf_used`: Number of buffered bytes currently in use.
    - `bit_cnt_lo`: Lower 64 bits of the total number of bits appended.
    - `bit_cnt_hi`: Upper 64 bits of the total number of bits appended.
- **Description**: The `fd_sha512_t` structure is an opaque handle representing the state of a SHA-512 hash calculation. It contains a buffer for message bytes that have not yet been processed, the current state of the hash, a magic number for validation, and counters for the number of bits processed. This structure is aligned to 128 bytes to optimize performance and mitigate false sharing in multi-threaded environments.


---
### fd\_sha384\_t
- **Type**: `typedef struct fd_sha512_private fd_sha384_t;`
- **Members**:
    - `buf`: Buffered message bytes that have not been added to the hash yet.
    - `state`: Current state of the hash.
    - `magic`: Magic number to identify the structure.
    - `buf_used`: Number of buffered bytes currently in use.
    - `bit_cnt_lo`: Lower 64 bits of the total number of bits appended.
    - `bit_cnt_hi`: Upper 64 bits of the total number of bits appended.
- **Description**: The `fd_sha384_t` is a typedef for the `fd_sha512_private` structure, which is used to maintain the state of a SHA-384 hashing operation. It includes a buffer for message bytes, a state array for the hash computation, a magic number for structure identification, and counters for the number of buffered bytes and total bits processed. The structure is aligned to 128 bytes to optimize performance and reduce false sharing.


---
### fd\_sha512\_private\_batch
- **Type**: `struct`
- **Members**:
    - `data`: An array of pointers to the data to be hashed, aligned for AVX-512.
    - `sz`: An array of sizes corresponding to each data block, aligned for AVX-512.
    - `hash`: An array of pointers where the resulting hashes will be stored, aligned for AVX-512.
    - `cnt`: A counter indicating the number of data blocks currently in the batch.
- **Description**: The `fd_sha512_private_batch` structure is designed to facilitate batch processing of SHA-512 hashes using AVX-512 instructions. It holds arrays of data pointers, sizes, and hash result pointers, all aligned for optimal performance with AVX-512. The `cnt` member keeps track of how many data blocks are currently being processed in the batch, allowing for efficient handling of multiple hash computations in parallel.


---
### fd\_sha512\_batch\_t
- **Type**: `struct`
- **Members**:
    - `data`: An array of pointers to the data to be hashed, aligned for AVX or AVX-512.
    - `sz`: An array of sizes corresponding to each data block, aligned for AVX or AVX-512.
    - `hash`: An array of pointers where the resulting hashes will be stored, aligned for AVX or AVX-512.
    - `cnt`: A counter indicating the number of data blocks currently in the batch.
- **Description**: The `fd_sha512_batch_t` structure is designed to facilitate the batching of SHA-512 hash computations, optimized for different levels of SIMD acceleration (AVX or AVX-512). It contains arrays for storing pointers to data blocks, their sizes, and the resulting hash outputs, along with a counter to track the number of data blocks in the current batch. This structure allows for efficient processing of multiple hash computations in parallel, leveraging hardware acceleration to improve performance.


# Functions

---
### fd\_sha512\_clear<!-- {{#callable:fd_sha512_clear}} -->
The `fd_sha512_clear` function resets a SHA-512 calculation state and securely clears its internal buffer.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` structure representing the SHA-512 calculation state to be cleared.
- **Control Flow**:
    - The function begins by calling [`fd_sha512_init`](fd_sha512.c.driver.md#fd_sha512_init) on the `sha` pointer to reset the SHA-512 calculation state.
    - It then calls `fd_memset_explicit` to fill the `buf` array within the `sha` structure with zeros, ensuring the buffer is securely cleared.
- **Output**: The function does not return a value; it operates directly on the provided `fd_sha512_t` structure.
- **Functions called**:
    - [`fd_sha512_init`](fd_sha512.c.driver.md#fd_sha512_init)


---
### fd\_sha512\_batch\_align<!-- {{#callable:fd_sha512_batch_align}} -->
The `fd_sha512_batch_align` function returns the alignment requirement for a memory region to hold a `fd_sha512_batch_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests the compiler to inline it for performance.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_sha512_batch_t` type.
    - The function returns the result of the `alignof` operator, which is the alignment requirement.
- **Output**: The function returns an `ulong` representing the alignment requirement for a `fd_sha512_batch_t` structure.


---
### fd\_sha512\_batch\_footprint<!-- {{#callable:fd_sha512_batch_footprint}} -->
The `fd_sha512_batch_footprint` function returns the size in bytes of the `fd_sha512_batch_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests that the compiler should attempt to embed the function's code at the call site to reduce function call overhead.
    - The function is marked with `FD_FN_CONST`, indicating that it does not read or write any global memory and its return value depends only on its parameters, which in this case are none.
    - The function simply returns the result of the `sizeof` operator applied to `fd_sha512_batch_t`, which is a type defined elsewhere in the code.
- **Output**: The function returns an `ulong` representing the size in bytes of the `fd_sha512_batch_t` structure.


---
### fd\_sha512\_batch\_init<!-- {{#callable:fd_sha512_batch_init}} -->
The `fd_sha512_batch_init` function initializes a SHA-512 batch processing structure by setting its count to zero.
- **Inputs**:
    - `mem`: A pointer to a memory region where the SHA-512 batch structure will be initialized.
- **Control Flow**:
    - Cast the input memory pointer `mem` to a `fd_sha512_batch_t` pointer and assign it to `batch`.
    - Set the `cnt` field of the `batch` structure to 0UL, indicating that no data has been added to the batch yet.
    - Return the initialized `batch` pointer.
- **Output**: A pointer to the initialized `fd_sha512_batch_t` structure.


---
### fd\_sha512\_batch\_add<!-- {{#callable:fd_sha512_batch_add}} -->
The `fd_sha512_batch_add` function adds a new data item to a SHA-512 batch for hashing, and processes the batch if it reaches its maximum size.
- **Inputs**:
    - `batch`: A pointer to an `fd_sha512_batch_t` structure representing the current batch of data to be hashed.
    - `data`: A pointer to the data to be added to the batch.
    - `sz`: The size of the data in bytes.
    - `hash`: A pointer to the memory location where the resulting hash will be stored.
- **Control Flow**:
    - Retrieve the current count of items in the batch from `batch->cnt`.
    - Store the `data`, `sz`, and `hash` pointers in the respective arrays at the current batch count index.
    - Increment the batch count.
    - Check if the batch count has reached `FD_SHA512_BATCH_MAX`.
    - If the batch count equals `FD_SHA512_BATCH_MAX`, call [`fd_sha512_private_batch_avx512`](fd_sha512_batch_avx512.c.driver.md#fd_sha512_private_batch_avx512) to process the batch and reset the batch count to 0.
    - Update the batch's count with the new batch count value.
    - Return the updated batch pointer.
- **Output**: Returns a pointer to the updated `fd_sha512_batch_t` structure.
- **Functions called**:
    - [`fd_sha512_private_batch_avx512`](fd_sha512_batch_avx512.c.driver.md#fd_sha512_private_batch_avx512)


---
### fd\_sha512\_batch\_fini<!-- {{#callable:fd_sha512_batch_fini}} -->
The `fd_sha512_batch_fini` function finalizes a batch of SHA-512 hash computations using AVX-512 acceleration if there are any pending computations in the batch.
- **Inputs**:
    - `batch`: A pointer to an `fd_sha512_batch_t` structure representing the batch of SHA-512 computations to be finalized.
- **Control Flow**:
    - Retrieve the current count of pending computations in the batch from `batch->cnt`.
    - Check if there are any pending computations using `FD_LIKELY(batch_cnt)`.
    - If there are pending computations, call [`fd_sha512_private_batch_avx512`](fd_sha512_batch_avx512.c.driver.md#fd_sha512_private_batch_avx512) to process them using AVX-512 acceleration.
    - Return the `batch` pointer cast to a `void *`.
- **Output**: Returns a `void *` pointer to the `fd_sha512_batch_t` structure, indicating the batch has been finalized.
- **Functions called**:
    - [`fd_sha512_private_batch_avx512`](fd_sha512_batch_avx512.c.driver.md#fd_sha512_private_batch_avx512)


---
### fd\_sha512\_batch\_abort<!-- {{#callable:fd_sha512_batch_abort}} -->
The `fd_sha512_batch_abort` function returns a pointer to the given SHA-512 batch object, effectively aborting any ongoing batch operation without performing any additional operations.
- **Inputs**:
    - `batch`: A pointer to an `fd_sha512_batch_t` object, representing the SHA-512 batch operation to be aborted.
- **Control Flow**:
    - The function takes a single argument, `batch`, which is a pointer to an `fd_sha512_batch_t` object.
    - It casts the `batch` pointer to a `void *` type and returns it immediately without any further processing.
- **Output**: A `void *` pointer to the `fd_sha512_batch_t` object passed as input, indicating the batch operation has been aborted.


# Function Declarations (Public API)

---
### fd\_sha512\_align<!-- {{#callable_declaration:fd_sha512_align}} -->
Returns the required memory alignment for a SHA-512 calculation state.
- **Description**: Use this function to determine the alignment requirement for memory regions intended to hold a SHA-512 calculation state. This is useful for ensuring that memory allocations are correctly aligned, which is necessary for optimal performance and to avoid potential issues with memory access. The function is particularly relevant when declaring memory regions or using functions like aligned_alloc or fd_alloca to allocate memory for SHA-512 operations.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement, which is a power of 2.
- **See also**: [`fd_sha512_align`](fd_sha512.c.driver.md#fd_sha512_align)  (Implementation)


---
### fd\_sha512\_footprint<!-- {{#callable_declaration:fd_sha512_footprint}} -->
Returns the memory footprint required for a SHA-512 calculation state.
- **Description**: Use this function to determine the size of the memory region needed to hold a SHA-512 calculation state. This is useful for allocating memory with the correct footprint for SHA-512 operations. The function is constant and does not depend on any input parameters, ensuring consistent behavior across calls.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the memory footprint in bytes required for a SHA-512 calculation state.
- **See also**: [`fd_sha512_footprint`](fd_sha512.c.driver.md#fd_sha512_footprint)  (Implementation)


---
### fd\_sha512\_new<!-- {{#callable_declaration:fd_sha512_new}} -->
Initialize a memory region for SHA-512 calculation state.
- **Description**: This function prepares a memory region to hold the state of a SHA-512 calculation. It should be called with a pointer to a memory region that the caller owns, which must be properly aligned and have sufficient footprint as defined by `fd_sha512_align` and `fd_sha512_footprint`. The function returns a pointer to the initialized memory region on success, or `NULL` if the input is invalid, logging a warning in such cases. The caller retains ownership of the memory region, and it is not joined upon return.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be initialized. It must not be null, must be aligned according to `fd_sha512_align`, and must have a size of at least `fd_sha512_footprint`. If these conditions are not met, the function returns `NULL` and logs a warning.
- **Output**: Returns a pointer to the initialized memory region on success, or `NULL` on failure.
- **See also**: [`fd_sha512_new`](fd_sha512.c.driver.md#fd_sha512_new)  (Implementation)


---
### fd\_sha512\_join<!-- {{#callable_declaration:fd_sha512_join}} -->
Joins a caller to a SHA-512 calculation state.
- **Description**: This function is used to join a caller to an existing SHA-512 calculation state, allowing the caller to perform operations on the state. It should be called with a pointer to a memory region that holds a valid SHA-512 state. The memory region must be properly aligned and initialized with the correct magic number. If the memory region is null, misaligned, or has an incorrect magic number, the function will return null and log a warning. This function is typically used after initializing or creating a SHA-512 state with the appropriate setup functions.
- **Inputs**:
    - `shsha`: A pointer to the memory region holding the SHA-512 calculation state. It must not be null, must be aligned according to fd_sha512_align(), and must contain the correct magic number (FD_SHA512_MAGIC). If these conditions are not met, the function returns null.
- **Output**: Returns a pointer to the local handle of the SHA-512 calculation state on success, or null on failure.
- **See also**: [`fd_sha512_join`](fd_sha512.c.driver.md#fd_sha512_join)  (Implementation)


---
### fd\_sha512\_leave<!-- {{#callable_declaration:fd_sha512_leave}} -->
Leaves the current local join to a SHA-512 calculation state.
- **Description**: This function is used to leave a previously joined SHA-512 calculation state, effectively ending the caller's association with that state. It should be called when the caller no longer needs to interact with the SHA-512 state, allowing for cleanup or reuse of resources. The function returns a pointer to the memory region holding the state, which can be used for further operations or deallocation. It is important to ensure that the `sha` parameter is not null before calling this function, as passing a null pointer will result in a warning and a null return value.
- **Inputs**:
    - `sha`: A pointer to a `fd_sha512_t` structure representing the current local join to a SHA-512 calculation state. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the memory region holding the SHA-512 calculation state on success, or null if the input was invalid.
- **See also**: [`fd_sha512_leave`](fd_sha512.c.driver.md#fd_sha512_leave)  (Implementation)


---
### fd\_sha512\_delete<!-- {{#callable_declaration:fd_sha512_delete}} -->
Unformats a memory region holding a SHA-512 calculation state.
- **Description**: Use this function to unformat a memory region that was previously formatted to hold a SHA-512 calculation state. It should be called when the memory region is no longer needed for SHA-512 calculations and the caller wishes to reclaim ownership of the memory. The function assumes that the provided pointer is aligned according to the requirements of a SHA-512 state and that no other operations are currently joined to this state. It returns the pointer to the memory region on success, allowing the caller to manage the memory further, or NULL if the input is invalid or the state is corrupted.
- **Inputs**:
    - `shsha`: A pointer to the first byte of the memory region holding the SHA-512 state. Must not be null, must be properly aligned, and must point to a valid SHA-512 state. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the memory region on success, or NULL on failure.
- **See also**: [`fd_sha512_delete`](fd_sha512.c.driver.md#fd_sha512_delete)  (Implementation)


---
### fd\_sha512\_init<!-- {{#callable_declaration:fd_sha512_init}} -->
Initializes a SHA-512 calculation state.
- **Description**: Use this function to start a new SHA-512 hashing operation. It must be called on a valid `fd_sha512_t` object that represents a current local join to a SHA-512 calculation state. This function resets any existing state, discarding any in-progress or completed calculations, and prepares the object for a new hashing operation. Ensure no concurrent operations modify the state while this function is executing.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` object representing a SHA-512 calculation state. It must be a valid local join with no concurrent modifications. The caller retains ownership and responsibility for ensuring the pointer is not null.
- **Output**: Returns the same `fd_sha512_t` pointer passed in, now initialized for a new SHA-512 calculation.
- **See also**: [`fd_sha512_init`](fd_sha512.c.driver.md#fd_sha512_init)  (Implementation)


---
### fd\_sha384\_init<!-- {{#callable_declaration:fd_sha384_init}} -->
Initializes a SHA-384 calculation state.
- **Description**: Use this function to initialize a SHA-384 calculation state before starting a new hash computation. It sets up the internal state of the provided `fd_sha512_t` structure to begin a SHA-384 hash operation. This function must be called before any data is appended to the hash state. It discards any preexisting state, so it should not be used on a state that is currently in use for another calculation.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` structure that will hold the SHA-384 calculation state. Must not be null. The caller retains ownership of the memory, and it should be properly aligned and allocated according to `FD_SHA512_ALIGN` and `FD_SHA512_FOOTPRINT`.
- **Output**: Returns the same `fd_sha512_t` pointer passed in, now initialized for a new SHA-384 calculation.
- **See also**: [`fd_sha384_init`](fd_sha512.c.driver.md#fd_sha384_init)  (Implementation)


---
### fd\_sha512\_append<!-- {{#callable_declaration:fd_sha512_append}} -->
Appends data to an in-progress SHA-512 calculation.
- **Description**: Use this function to add data to an ongoing SHA-512 hash calculation. It should be called after initializing the SHA-512 state with `fd_sha512_init` and before finalizing the hash with `fd_sha512_fini`. The function updates the internal state of the SHA-512 calculation with the provided data. It is optimized for appending large blocks of data, and performance is best when the size of the data is a multiple of 128 bytes, except for the last append which should ideally be less than 112 bytes. The function handles cases where no data is provided by simply returning the current state without modification.
- **Inputs**:
    - `sha`: A pointer to a `fd_sha512_t` structure representing the current state of the SHA-512 calculation. Must be a valid, initialized state with no concurrent modifications.
    - `data`: A pointer to the data to be appended. The data should remain unmodified during the function execution and can be null if `sz` is zero.
    - `sz`: The size in bytes of the data to append. Must be non-negative. If zero, the function will return immediately without modifying the state.
- **Output**: Returns the updated `fd_sha512_t` pointer, reflecting the new state of the SHA-512 calculation.
- **See also**: [`fd_sha512_append`](fd_sha512.c.driver.md#fd_sha512_append)  (Implementation)


---
### fd\_sha512\_fini<!-- {{#callable_declaration:fd_sha512_fini}} -->
Completes a SHA-512 hash calculation and stores the result.
- **Description**: This function finalizes an in-progress SHA-512 hash calculation and writes the resulting hash to the specified memory location. It should be called after all data has been appended to the SHA-512 state using the appropriate append function. The function assumes that the SHA-512 state is valid and that no other concurrent operations are modifying it. The provided hash buffer must be large enough to store the 64-byte hash result. After this function is called, the SHA-512 state will no longer have an in-progress calculation.
- **Inputs**:
    - `sha`: A pointer to a valid fd_sha512_t structure representing the SHA-512 calculation state. It must be a local join to a SHA-512 state with no concurrent modifications.
    - `_hash`: A pointer to a memory region where the 64-byte hash result will be stored. The caller must ensure this buffer is large enough to hold the result.
- **Output**: Returns the pointer to the hash buffer provided by the caller, now containing the 64-byte SHA-512 hash result.
- **See also**: [`fd_sha512_fini`](fd_sha512.c.driver.md#fd_sha512_fini)  (Implementation)


---
### fd\_sha384\_fini<!-- {{#callable_declaration:fd_sha384_fini}} -->
Completes a SHA-384 hash calculation and stores the result.
- **Description**: This function finalizes an in-progress SHA-384 hash calculation and writes the resulting hash to the specified memory location. It should be called after all data has been appended to the SHA-384 calculation state. The function assumes that the SHA-384 calculation state is valid and that no other concurrent operations are modifying it. The caller must ensure that the provided memory location for the hash is valid and has enough space to store a 48-byte hash.
- **Inputs**:
    - `sha`: A pointer to a valid fd_sha384_t structure representing the SHA-384 calculation state. It must be a local join to an in-progress calculation with no concurrent modifications.
    - `_hash`: A pointer to a memory location where the 48-byte SHA-384 hash result will be stored. The caller must ensure this memory is valid and writable.
- **Output**: Returns the pointer to the memory location where the hash result is stored.
- **See also**: [`fd_sha384_fini`](fd_sha512.c.driver.md#fd_sha384_fini)  (Implementation)


---
### fd\_sha512\_hash<!-- {{#callable_declaration:fd_sha512_hash}} -->
Computes the SHA-512 hash of the given data.
- **Description**: This function computes the SHA-512 hash of a given data buffer and stores the result in a specified memory location. It is designed for efficiency, particularly for small messages, by minimizing overhead associated with function calls and data handling. The function should be used when a complete SHA-512 hash of a data block is needed in a single operation. It is important to ensure that the output buffer is properly allocated to hold the 64-byte hash result before calling this function.
- **Inputs**:
    - `data`: A pointer to the data to be hashed. This must not be null if sz is greater than zero. The caller retains ownership and the data is not modified.
    - `sz`: The size of the data in bytes. It can be zero, in which case the function will compute the hash of an empty input.
    - `hash`: A pointer to a memory region where the 64-byte hash result will be stored. This must not be null and must be properly allocated to hold at least 64 bytes.
- **Output**: Returns a pointer to the hash buffer, which contains the 64-byte SHA-512 hash of the input data.
- **See also**: [`fd_sha512_hash`](fd_sha512.c.driver.md#fd_sha512_hash)  (Implementation)


---
### fd\_sha384\_hash<!-- {{#callable_declaration:fd_sha384_hash}} -->
Computes the SHA-384 hash of the given data.
- **Description**: This function computes the SHA-384 hash for a given block of data and stores the result in the provided hash buffer. It is designed for efficiency, particularly for small messages, by eliminating overheads associated with incremental hashing. The function should be used when a complete message is available for hashing in one go. It is important to ensure that the hash buffer is large enough to hold the 48-byte SHA-384 hash result.
- **Inputs**:
    - `_data`: Pointer to the data to be hashed. Must not be null if sz is greater than zero. The caller retains ownership and the data is not modified.
    - `sz`: The size of the data in bytes. Can be zero, in which case the function will compute the hash of an empty input.
    - `_hash`: Pointer to a buffer where the 48-byte SHA-384 hash will be stored. Must not be null and must be large enough to hold the hash result. The caller retains ownership.
- **Output**: Returns a pointer to the hash buffer containing the computed SHA-384 hash.
- **See also**: [`fd_sha384_hash`](fd_sha512.c.driver.md#fd_sha384_hash)  (Implementation)


---
### fd\_sha512\_private\_batch\_avx<!-- {{#callable_declaration:fd_sha512_private_batch_avx}} -->
Processes a batch of messages using SHA-512 with AVX acceleration.
- **Description**: This function computes SHA-512 hashes for a batch of messages using AVX acceleration, which is suitable for processing multiple messages in parallel for improved performance. It should be used when you have multiple messages to hash and your system supports AVX instructions. The function requires that the number of messages (`batch_cnt`) is between 1 and the maximum batch size defined by `FD_SHA512_BATCH_MAX`. If `batch_cnt` is less than 2, it processes each message individually using a non-batched approach. The function does not return a value but writes the computed hashes to the provided output locations.
- **Inputs**:
    - `batch_cnt`: The number of messages in the batch to be processed. Must be between 1 and FD_SHA512_BATCH_MAX. If less than 2, messages are processed individually.
    - `_batch_data`: A pointer to an array of pointers, each pointing to the data of a message to be hashed. The array must have at least `batch_cnt` valid entries. The data for each message must be aligned as required by the implementation.
    - `batch_sz`: A pointer to an array of unsigned long integers, each representing the size in bytes of the corresponding message in `_batch_data`. The array must have at least `batch_cnt` valid entries.
    - `_batch_hash`: A pointer to an array of pointers, each pointing to a memory location where the hash of the corresponding message should be stored. The array must have at least `batch_cnt` valid entries, and each location must be large enough to store a SHA-512 hash (64 bytes).
- **Output**: None
- **See also**: [`fd_sha512_private_batch_avx`](fd_sha512_batch_avx.c.driver.md#fd_sha512_private_batch_avx)  (Implementation)


---
### fd\_sha512\_private\_batch\_avx512<!-- {{#callable_declaration:fd_sha512_private_batch_avx512}} -->
Processes a batch of messages using SHA-512 with AVX-512 acceleration.
- **Description**: This function is used to compute SHA-512 hashes for a batch of messages using AVX-512 acceleration, which is suitable for high-performance environments. It should be called when you have multiple messages to hash and the batch count is at least 5. If the batch count is less than 5, it delegates the processing to a different function optimized for smaller batches. This function is designed to handle up to 8 messages in a single batch, leveraging AVX-512 instructions for efficient processing.
- **Inputs**:
    - `batch_cnt`: The number of messages in the batch to be processed. Must be between 1 and 8 inclusive. If less than 5, a different function is used.
    - `_batch_data`: A pointer to an array of pointers, each pointing to the data of a message to be hashed. The array must have at least 'batch_cnt' valid entries. The data for each message must be aligned to 64 bytes.
    - `batch_sz`: A pointer to an array of unsigned long integers, each representing the size in bytes of the corresponding message in '_batch_data'. The array must have at least 'batch_cnt' valid entries.
    - `_batch_hash`: A pointer to an array of pointers, each pointing to a memory location where the resulting hash of the corresponding message will be stored. The array must have at least 'batch_cnt' valid entries, and each location must be able to hold a 64-byte hash.
- **Output**: None
- **See also**: [`fd_sha512_private_batch_avx512`](fd_sha512_batch_avx512.c.driver.md#fd_sha512_private_batch_avx512)  (Implementation)


