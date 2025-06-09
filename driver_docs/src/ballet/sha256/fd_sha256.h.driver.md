# Purpose
This C header file defines the interface for a SHA-256 hashing library, providing both single and batch processing capabilities. It includes definitions for memory alignment and footprint requirements, constants for hash and block sizes, and an opaque structure `fd_sha256_t` to manage the state of SHA-256 calculations. The file declares functions for initializing, appending data to, and finalizing SHA-256 hash computations, as well as a streamlined function for hashing small messages. Additionally, it outlines a batch processing API that supports different implementations based on available hardware acceleration (AVX or AVX-512), allowing for efficient parallel processing of multiple SHA-256 calculations. The header ensures compatibility and performance optimization by specifying alignment and footprint requirements, and it provides flexibility for high-performance computing contexts by omitting input validation in batch operations.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_sha256\_new
- **Type**: `function pointer`
- **Description**: `fd_sha256_new` is a function that initializes a new SHA-256 calculation state in a given shared memory region. It returns a pointer to the initialized memory region, which is aligned and has the necessary footprint to hold a `fd_sha256_t` structure.
- **Use**: This function is used to allocate and initialize memory for a new SHA-256 hashing operation.


---
### fd\_sha256\_join
- **Type**: `fd_sha256_t *`
- **Description**: The `fd_sha256_join` function is a global function that returns a pointer to an `fd_sha256_t` structure. This function is used to join a SHA-256 calculation state from a shared memory region, allowing further operations on the SHA-256 state.
- **Use**: This function is used to obtain a pointer to a SHA-256 calculation state from a shared memory region for further processing.


---
### fd\_sha256\_leave
- **Type**: `function pointer`
- **Description**: `fd_sha256_leave` is a function that takes a pointer to an `fd_sha256_t` structure and returns a void pointer. This function is part of the SHA-256 hashing API and is used to manage the lifecycle of a SHA-256 calculation state.
- **Use**: This function is used to leave or detach from a SHA-256 calculation state, effectively ending the current session with the state object.


---
### fd\_sha256\_delete
- **Type**: `function pointer`
- **Description**: `fd_sha256_delete` is a function pointer that takes a single argument, a void pointer `shsha`, and returns a void pointer. It is part of the SHA-256 API provided by the library, which deals with the deletion or cleanup of SHA-256 calculation states.
- **Use**: This function is used to delete or clean up a SHA-256 calculation state, freeing any resources associated with it.


---
### fd\_sha256\_init
- **Type**: `fd_sha256_t *`
- **Description**: The `fd_sha256_init` function initializes a SHA-256 calculation state. It takes a pointer to an `fd_sha256_t` structure, which represents the state of a SHA-256 calculation, and prepares it for a new hashing operation.
- **Use**: This function is used to reset or initialize the SHA-256 state to begin a new hashing process, discarding any previous state.


---
### fd\_sha256\_append
- **Type**: `fd_sha256_t *`
- **Description**: The `fd_sha256_append` function is a global function that appends a specified number of bytes from a data buffer to an in-progress SHA-256 hash calculation. It takes a pointer to a SHA-256 calculation state, a pointer to the data to be appended, and the size of the data in bytes. The function updates the SHA-256 state with the new data and returns the updated state.
- **Use**: This function is used to incrementally add data to a SHA-256 hash calculation, allowing for the hash to be computed over multiple calls.


---
### fd\_sha256\_fini
- **Type**: `function`
- **Description**: The `fd_sha256_fini` function is used to complete a SHA-256 hashing operation. It takes a pointer to a SHA-256 calculation state (`fd_sha256_t * sha`) and a pointer to a memory region (`void * hash`) where the resulting hash will be stored. The function assumes that the SHA-256 calculation is in progress and finalizes it by writing the 32-byte hash result to the specified memory region.
- **Use**: This function is used to finalize a SHA-256 hash calculation and store the result in a provided memory location.


---
### fd\_sha256\_hash
- **Type**: `function pointer`
- **Description**: `fd_sha256_hash` is a function that performs a SHA-256 hash calculation on a given data buffer. It takes three parameters: a pointer to the data to be hashed, the size of the data, and a pointer to a memory location where the resulting hash will be stored.
- **Use**: This function is used to compute the SHA-256 hash of a data buffer in a streamlined manner, optimizing for small messages by reducing overhead.


---
### fd\_sha256\_hash\_32
- **Type**: `function pointer`
- **Description**: `fd_sha256_hash_32` is a function that computes the SHA-256 hash of a given data input and stores the result in a provided memory location. It is a streamlined implementation designed to efficiently handle small messages by reducing overheads such as function calls and data marshalling.
- **Use**: This function is used to compute a 32-byte SHA-256 hash of the input data and store it in the specified hash buffer.


---
### fd\_sha256\_batch\_init
- **Type**: `fd_sha256_batch_t *`
- **Description**: The `fd_sha256_batch_init` function initializes a new batch of SHA-256 calculations. It returns a handle to the in-progress batch calculation, which is represented by a pointer to `fd_sha256_batch_t`. The function requires a memory region with appropriate alignment and footprint to hold the state of the calculations.
- **Use**: This variable is used to manage and track the state of a batch of SHA-256 calculations, allowing for efficient processing of multiple hash computations simultaneously.


---
### fd\_sha256\_batch\_add
- **Type**: `fd_sha256_batch_t *`
- **Description**: The `fd_sha256_batch_add` function is a global function that adds a message to an in-progress batch of SHA-256 calculations. It takes a batch handle, a pointer to the data, the size of the data, and a pointer to where the hash result should be stored.
- **Use**: This function is used to add messages to a batch for SHA-256 hashing, storing the result in the specified hash location.


---
### fd\_sha256\_batch\_fini
- **Type**: `function pointer`
- **Description**: `fd_sha256_batch_fini` is a function that completes a set of SHA-256 calculations for a batch of messages. It takes a pointer to a `fd_sha256_batch_t` structure, which represents the state of the in-progress batch calculation, and returns a pointer to the memory region used to hold the calculation state, with the contents being undefined after the operation.
- **Use**: This function is used to finalize the batch processing of SHA-256 hashes, ensuring that all hash memory regions are populated with the corresponding message hashes.


---
### fd\_sha256\_batch\_abort
- **Type**: `function pointer`
- **Description**: The `fd_sha256_batch_abort` is a function pointer that is used to abort an in-progress set of SHA-256 calculations. It is part of the SHA-256 batch API, which allows for the processing of multiple SHA-256 hash calculations simultaneously. The function returns a pointer to the memory region used to hold the calculation state, and the contents of this memory region are undefined after the abort operation.
- **Use**: This function is used to terminate a batch of SHA-256 calculations prematurely, without guaranteeing which individual messages had their hashes computed.


# Data Structures

---
### fd\_sha256\_private
- **Type**: `struct`
- **Members**:
    - `buf`: A buffer array of unsigned characters with a maximum size defined by FD_SHA256_PRIVATE_BUF_MAX.
    - `state`: An array of unsigned integers representing the current state of the SHA-256 hash, sized according to FD_SHA256_HASH_SZ.
    - `magic`: A magic number used to verify the integrity of the SHA-256 state, expected to be FD_SHA256_MAGIC.
    - `buf_used`: An unsigned long indicating the number of bytes currently buffered, ranging from 0 to FD_SHA256_BUF_MAX.
    - `bit_cnt`: An unsigned long tracking the total number of bits that have been appended to the hash.
- **Description**: The `fd_sha256_private` structure is a data structure used to maintain the state of an ongoing SHA-256 hash computation. It includes a buffer for storing data to be hashed, a state array for the hash computation, and several fields for tracking the progress and integrity of the hash operation. The structure is aligned to 128 bytes to optimize performance and reduce false sharing in concurrent environments. The `magic` field is used to ensure the structure's integrity, while `buf_used` and `bit_cnt` track the amount of data processed.


---
### fd\_sha256\_t
- **Type**: `struct`
- **Members**:
    - `buf`: An internal buffer used by the SHA-256 computation object, with a size defined by FD_SHA256_PRIVATE_BUF_MAX.
    - `state`: An array representing the current state of the SHA-256 hash computation, with a size of FD_SHA256_HASH_SZ divided by the size of a uint.
    - `magic`: A magic number used to identify the structure, set to FD_SHA256_MAGIC.
    - `buf_used`: The number of bytes currently buffered, ranging from 0 to FD_SHA256_BUF_MAX.
    - `bit_cnt`: The total number of bits that have been appended to the hash computation.
- **Description**: The `fd_sha256_t` structure is an opaque handle representing the state of a SHA-256 hash computation. It is aligned to 128 bytes and contains an internal buffer, a state array for the hash computation, a magic number for identification, and counters for the number of buffered bytes and total bits processed. This structure is used in conjunction with various functions to perform SHA-256 hashing operations.


---
### fd\_sha256\_batch\_t
- **Type**: `struct`
- **Members**:
    - `data`: An array of pointers to the data for each SHA-256 calculation in the batch.
    - `sz`: An array of sizes corresponding to each data element in the batch.
    - `hash`: An array of pointers where the resulting hashes will be stored.
    - `cnt`: A counter indicating the number of SHA-256 calculations currently in the batch.
- **Description**: The `fd_sha256_batch_t` structure is designed to handle a batch of SHA-256 hash calculations efficiently, particularly in high-performance computing contexts. It contains arrays to manage multiple data inputs, their sizes, and the locations where the resulting hashes will be stored. The structure also includes a counter to track the number of calculations in progress, allowing for optimized processing using AVX or AVX-512 instructions depending on the implementation. This batching approach is intended to improve performance by processing multiple hash calculations simultaneously.


---
### fd\_sha256\_private\_batch
- **Type**: `struct`
- **Members**:
    - `data`: An array of pointers to the data to be hashed, aligned for AVX.
    - `sz`: An array of sizes corresponding to each data element, aligned for AVX.
    - `hash`: An array of pointers where the resulting hashes will be stored, aligned for AVX.
    - `cnt`: A counter indicating the number of elements currently in the batch.
- **Description**: The `fd_sha256_private_batch` structure is designed to facilitate batch processing of SHA-256 hash calculations using AVX or AVX-512 instructions for performance optimization. It holds arrays of data pointers, sizes, and hash result pointers, all aligned for efficient vectorized operations. The `cnt` member tracks the number of data elements currently being processed in the batch, allowing for efficient management and execution of hash calculations in high-performance computing contexts.


# Functions

---
### fd\_sha256\_batch\_align<!-- {{#callable:fd_sha256_batch_align}} -->
The `fd_sha256_batch_align` function returns the alignment requirement for a memory region to hold the state of an in-progress set of SHA-256 calculations.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests that the compiler should attempt to embed the function's code at the call site to reduce function call overhead.
    - The function returns the alignment requirement by using the `alignof` operator on the `fd_sha256_batch_t` type, which is a type alias for a structure representing a batch of SHA-256 calculations.
- **Output**: The function returns an `ulong` representing the alignment requirement for a `fd_sha256_batch_t`.


---
### fd\_sha256\_batch\_footprint<!-- {{#callable:fd_sha256_batch_footprint}} -->
The `fd_sha256_batch_footprint` function returns the memory footprint size required to hold a `fd_sha256_batch_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests that the function body is small and should be inlined by the compiler.
    - The function returns the size of the `fd_sha256_batch_t` type using the `sizeof` operator.
- **Output**: The function returns an `ulong` representing the size in bytes of the `fd_sha256_batch_t` structure.


---
### fd\_sha256\_batch\_init<!-- {{#callable:fd_sha256_batch_init}} -->
The `fd_sha256_batch_init` function initializes a new SHA-256 batch calculation by setting the count of messages in the batch to zero.
- **Inputs**:
    - `mem`: A pointer to a memory region where the SHA-256 batch calculation state will be stored.
- **Control Flow**:
    - Cast the input memory pointer `mem` to a `fd_sha256_batch_t` pointer and assign it to `batch`.
    - Set the `cnt` field of `batch` to 0, indicating no messages are currently in the batch.
    - Return the `batch` pointer.
- **Output**: A pointer to the initialized `fd_sha256_batch_t` structure, which represents the state of the in-progress batch calculation.


---
### fd\_sha256\_batch\_add<!-- {{#callable:fd_sha256_batch_add}} -->
The `fd_sha256_batch_add` function adds a message to a batch of SHA-256 calculations and processes the batch if it reaches its maximum size.
- **Inputs**:
    - `batch`: A pointer to the `fd_sha256_batch_t` structure representing the current batch of SHA-256 calculations.
    - `data`: A pointer to the data to be hashed, which is added to the batch.
    - `sz`: The size in bytes of the data to be hashed.
    - `hash`: A pointer to the memory location where the resulting hash will be stored.
- **Control Flow**:
    - Retrieve the current count of messages in the batch from `batch->cnt`.
    - Store the `data`, `sz`, and `hash` pointers in the respective arrays at the current batch count index.
    - Increment the batch count.
    - Check if the batch count has reached `FD_SHA256_BATCH_MAX`.
    - If the batch count equals `FD_SHA256_BATCH_MAX`, call [`fd_sha256_private_batch_avx512`](fd_sha256_batch_avx512.c.driver.md#fd_sha256_private_batch_avx512) to process the batch and reset the batch count to 0.
    - Update `batch->cnt` with the new batch count.
- **Output**: Returns a pointer to the updated `fd_sha256_batch_t` structure, which represents the batch of SHA-256 calculations.
- **Functions called**:
    - [`fd_sha256_private_batch_avx512`](fd_sha256_batch_avx512.c.driver.md#fd_sha256_private_batch_avx512)


---
### fd\_sha256\_batch\_fini<!-- {{#callable:fd_sha256_batch_fini}} -->
The `fd_sha256_batch_fini` function finalizes a batch of SHA-256 calculations, processing any remaining messages in the batch and returning a pointer to the batch state.
- **Inputs**:
    - `batch`: A pointer to an `fd_sha256_batch_t` structure representing the batch of SHA-256 calculations to be finalized.
- **Control Flow**:
    - Retrieve the current count of messages in the batch from `batch->cnt`.
    - Check if there are any messages left to process in the batch using `FD_LIKELY(batch_cnt)`.
    - If there are messages to process, call [`fd_sha256_private_batch_avx512`](fd_sha256_batch_avx512.c.driver.md#fd_sha256_private_batch_avx512) to process the remaining messages in the batch.
    - Return a pointer to the batch state, cast to `void *`.
- **Output**: A pointer to the memory region used to hold the calculation state, cast to `void *`, with the contents being undefined after the operation.
- **Functions called**:
    - [`fd_sha256_private_batch_avx512`](fd_sha256_batch_avx512.c.driver.md#fd_sha256_private_batch_avx512)


---
### fd\_sha256\_batch\_abort<!-- {{#callable:fd_sha256_batch_abort}} -->
The `fd_sha256_batch_abort` function aborts an in-progress set of SHA-256 calculations and returns a pointer to the memory region used to hold the calculation state.
- **Inputs**:
    - `batch`: A pointer to an `fd_sha256_batch_t` structure representing the in-progress batch of SHA-256 calculations.
- **Control Flow**:
    - The function takes a single argument, `batch`, which is a pointer to an `fd_sha256_batch_t` structure.
    - It simply returns the `batch` pointer cast to a `void *`, indicating that the batch operation is aborted and the memory can be reused or freed.
- **Output**: A `void *` pointer to the memory region used to hold the calculation state, with contents undefined after the abort.


# Function Declarations (Public API)

---
### fd\_sha256\_align<!-- {{#callable_declaration:fd_sha256_align}} -->
Returns the alignment requirement for SHA-256 operations.
- **Description**: This function provides the alignment requirement for memory regions used in SHA-256 operations. It is useful for ensuring that memory allocations meet the necessary alignment constraints for optimal performance and correctness. This function should be called when setting up memory for SHA-256 operations to ensure that the memory is aligned according to the defined standard.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement, which is a positive integer power of 2.
- **See also**: [`fd_sha256_align`](fd_sha256.c.driver.md#fd_sha256_align)  (Implementation)


---
### fd\_sha256\_footprint<!-- {{#callable_declaration:fd_sha256_footprint}} -->
Returns the memory footprint required for a SHA-256 calculation state.
- **Description**: Use this function to determine the size of the memory region needed to store a SHA-256 calculation state. This is useful for allocating memory when setting up a SHA-256 hashing operation. The function does not require any parameters and can be called at any time to retrieve the footprint size.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the size in bytes of the memory footprint required for a SHA-256 calculation state.
- **See also**: [`fd_sha256_footprint`](fd_sha256.c.driver.md#fd_sha256_footprint)  (Implementation)


---
### fd\_sha256\_new<!-- {{#callable_declaration:fd_sha256_new}} -->
Initialize a SHA-256 computation state in shared memory.
- **Description**: This function sets up a new SHA-256 computation state in a provided shared memory region. It should be called when you need to start a new SHA-256 hashing operation. The memory region must be properly aligned and have sufficient size as defined by the SHA-256 alignment and footprint requirements. If the provided memory is null or misaligned, the function will return null and log a warning. This function prepares the memory for use in subsequent SHA-256 operations.
- **Inputs**:
    - `shmem`: A pointer to a memory region where the SHA-256 state will be initialized. The memory must be aligned to the value returned by fd_sha256_align() and have a size of at least fd_sha256_footprint(). The caller retains ownership of this memory. If the pointer is null or the memory is misaligned, the function returns null.
- **Output**: Returns a pointer to the initialized SHA-256 state on success, or null if the input memory is null or misaligned.
- **See also**: [`fd_sha256_new`](fd_sha256.c.driver.md#fd_sha256_new)  (Implementation)


---
### fd\_sha256\_join<!-- {{#callable_declaration:fd_sha256_join}} -->
Joins a shared SHA-256 calculation state to the local address space.
- **Description**: This function is used to access a SHA-256 calculation state that has been previously allocated in shared memory. It should be called when you need to perform operations on a SHA-256 state that is shared across different parts of a program or between different programs. The function checks that the provided pointer is not null, is properly aligned, and that the memory region contains a valid SHA-256 state by verifying a magic number. If any of these checks fail, the function returns null, indicating an error.
- **Inputs**:
    - `shsha`: A pointer to the shared memory region containing the SHA-256 state. Must not be null, must be aligned to the value returned by fd_sha256_align(), and must contain a valid SHA-256 state with the correct magic number. If these conditions are not met, the function returns null.
- **Output**: Returns a pointer to the local representation of the SHA-256 state if successful, or null if the input is invalid.
- **See also**: [`fd_sha256_join`](fd_sha256.c.driver.md#fd_sha256_join)  (Implementation)


---
### fd\_sha256\_leave<!-- {{#callable_declaration:fd_sha256_leave}} -->
Leaves a SHA-256 calculation state.
- **Description**: This function is used to leave a SHA-256 calculation state, effectively marking the end of the current usage of the SHA-256 state object. It should be called when the SHA-256 state is no longer needed, allowing for any necessary cleanup or state transition. The function must be called with a valid SHA-256 state object that was previously joined. If the provided state object is null, the function will log a warning and return null.
- **Inputs**:
    - `sha`: A pointer to a fd_sha256_t object representing the SHA-256 calculation state. Must not be null. If null, a warning is logged and null is returned.
- **Output**: Returns a void pointer to the SHA-256 state object if successful, or null if the input was invalid.
- **See also**: [`fd_sha256_leave`](fd_sha256.c.driver.md#fd_sha256_leave)  (Implementation)


---
### fd\_sha256\_delete<!-- {{#callable_declaration:fd_sha256_delete}} -->
Deletes a SHA-256 calculation state.
- **Description**: Use this function to safely delete a SHA-256 calculation state that was previously initialized and joined. It should be called when the SHA-256 calculation is no longer needed, ensuring that the memory region is properly invalidated. The function checks for null pointers, proper alignment, and a valid magic number to ensure the integrity of the state before deletion. If any of these checks fail, a warning is logged and the function returns NULL.
- **Inputs**:
    - `shsha`: A pointer to the SHA-256 calculation state to be deleted. It must not be null, must be properly aligned according to fd_sha256_align(), and must have a valid magic number. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the deleted SHA-256 calculation state if successful, or NULL if the input was invalid.
- **See also**: [`fd_sha256_delete`](fd_sha256.c.driver.md#fd_sha256_delete)  (Implementation)


---
### fd\_sha256\_init<!-- {{#callable_declaration:fd_sha256_init}} -->
Initialize a SHA-256 calculation state.
- **Description**: Use this function to start a new SHA-256 calculation. It initializes the provided SHA-256 state structure, preparing it for hashing operations. This function should be called before any data is appended to the SHA-256 state. It discards any preexisting state, so it is suitable for reinitializing a state structure for a new calculation. Ensure that the `sha` parameter is a valid pointer to a `fd_sha256_t` structure and that no concurrent operations modify the state during execution.
- **Inputs**:
    - `sha`: A pointer to a `fd_sha256_t` structure representing the SHA-256 calculation state. Must not be null and should be a valid local join to a SHA-256 calculation state with no concurrent modifications.
- **Output**: Returns the initialized `fd_sha256_t` pointer, ready for use in subsequent SHA-256 operations.
- **See also**: [`fd_sha256_init`](fd_sha256.c.driver.md#fd_sha256_init)  (Implementation)


---
### fd\_sha256\_append<!-- {{#callable_declaration:fd_sha256_append}} -->
Appends data to an in-progress SHA-256 calculation.
- **Description**: Use this function to add data to an ongoing SHA-256 hash computation. It is essential that the `sha` parameter is a valid, locally joined SHA-256 calculation state with no concurrent modifications. The function can handle appending data in any size, but for optimal performance, it is recommended to append large chunks of data, ideally in multiples of 64 bytes, except for the final append which should be less than 56 bytes if possible. The function updates the internal state of the SHA-256 calculation and returns the updated state.
- **Inputs**:
    - `sha`: A pointer to a valid `fd_sha256_t` structure representing the current state of the SHA-256 calculation. Must be a local join with no concurrent modifications.
    - `data`: A pointer to the data to be appended. The data should remain unmodified during the function execution. It can be `NULL` if `sz` is 0.
    - `sz`: The size in bytes of the data to append. Must be non-negative. If 0, the function returns immediately without modifying the state.
- **Output**: Returns a pointer to the updated `fd_sha256_t` structure, reflecting the new state of the SHA-256 calculation.
- **See also**: [`fd_sha256_append`](fd_sha256.c.driver.md#fd_sha256_append)  (Implementation)


---
### fd\_sha256\_fini<!-- {{#callable_declaration:fd_sha256_fini}} -->
Completes a SHA-256 hash calculation and stores the result.
- **Description**: This function finalizes an in-progress SHA-256 hash calculation and stores the resulting hash in the provided memory location. It should be called after all data has been appended to the SHA-256 state using the appropriate append function. The function assumes that the SHA-256 state is valid and that no other concurrent operations are modifying it. The provided hash buffer must be a valid memory region of at least 32 bytes where the final hash will be stored. After this function is called, the SHA-256 state will no longer have an in-progress calculation.
- **Inputs**:
    - `sha`: A pointer to a valid fd_sha256_t structure representing the SHA-256 calculation state. It must be a local join to a calculation state with no concurrent modifications.
    - `hash`: A pointer to a memory region of at least 32 bytes where the resulting SHA-256 hash will be stored. The caller must ensure this memory is valid and writable.
- **Output**: Returns the pointer to the hash buffer, now containing the 32-byte SHA-256 hash result.
- **See also**: [`fd_sha256_fini`](fd_sha256.c.driver.md#fd_sha256_fini)  (Implementation)


---
### fd\_sha256\_hash<!-- {{#callable_declaration:fd_sha256_hash}} -->
Computes the SHA-256 hash of the given data.
- **Description**: Use this function to compute the SHA-256 hash of a given data buffer in a single step. It is suitable for hashing small messages efficiently by avoiding the overhead of incremental hashing. The function requires a buffer to store the resulting 32-byte hash. Ensure that the data pointer is valid and the hash buffer is appropriately allocated before calling this function.
- **Inputs**:
    - `data`: A pointer to the data to be hashed. It must not be null if sz is greater than zero. The caller retains ownership and the data is not modified.
    - `sz`: The size of the data in bytes. It can be zero, in which case the function will compute the hash of an empty input.
    - `hash`: A pointer to a memory region where the 32-byte hash result will be stored. This must be a valid, writable memory location of at least 32 bytes.
- **Output**: Returns a pointer to the hash buffer containing the 32-byte SHA-256 hash of the input data.
- **See also**: [`fd_sha256_hash`](fd_sha256.c.driver.md#fd_sha256_hash)  (Implementation)


---
### fd\_sha256\_hash\_32<!-- {{#callable_declaration:fd_sha256_hash_32}} -->
Computes the SHA-256 hash of a 32-byte data block.
- **Description**: This function computes the SHA-256 hash of a fixed-size 32-byte data block and stores the result in the provided hash buffer. It is designed for scenarios where the data size is known to be exactly 32 bytes, allowing for optimized performance by eliminating overheads associated with incremental hashing. The function must be called with valid pointers for both the data and hash parameters, and it assumes that the hash buffer is large enough to hold the 32-byte hash result.
- **Inputs**:
    - `data`: A pointer to the 32-byte data block to be hashed. Must not be null and must point to a valid memory region of at least 32 bytes.
    - `hash`: A pointer to a memory region where the 32-byte hash result will be stored. Must not be null and must point to a valid memory region of at least 32 bytes.
- **Output**: Returns a pointer to the hash buffer containing the 32-byte SHA-256 hash result.
- **See also**: [`fd_sha256_hash_32`](fd_sha256.c.driver.md#fd_sha256_hash_32)  (Implementation)


---
### fd\_sha256\_private\_batch\_avx<!-- {{#callable_declaration:fd_sha256_private_batch_avx}} -->
Computes SHA-256 hashes for a batch of messages using AVX acceleration.
- **Description**: This function processes a batch of messages to compute their SHA-256 hashes using AVX acceleration for improved performance. It is designed to handle multiple messages in parallel, which can be more efficient than processing each message individually, especially for larger batch sizes. The function requires a minimum batch size to utilize the batched implementation effectively. If the batch size is below this threshold, it defaults to processing each message sequentially. This function is intended for use in high-performance computing contexts and assumes that the input parameters are valid and properly aligned.
- **Inputs**:
    - `batch_cnt`: The number of messages in the batch. Must be at least 1 and not exceed the maximum batch size defined by FD_SHA256_BATCH_MAX.
    - `_batch_data`: A pointer to an array of pointers, each pointing to the data of a message to be hashed. The data for each message must be properly aligned and accessible.
    - `batch_sz`: A pointer to an array of unsigned long integers, each representing the size in bytes of the corresponding message in the batch.
    - `_batch_hash`: A pointer to an array of pointers, each pointing to a 32-byte memory region where the resulting hash of the corresponding message will be stored. The memory regions must be properly aligned and accessible.
- **Output**: None
- **See also**: [`fd_sha256_private_batch_avx`](fd_sha256_batch_avx.c.driver.md#fd_sha256_private_batch_avx)  (Implementation)


---
### fd\_sha256\_private\_batch\_avx512<!-- {{#callable_declaration:fd_sha256_private_batch_avx512}} -->
Computes SHA-256 hashes for a batch of messages using AVX-512 acceleration.
- **Description**: This function is used to compute SHA-256 hashes for a batch of messages, leveraging AVX-512 acceleration for improved performance. It is designed to handle multiple messages in parallel, making it suitable for high-performance computing contexts where batch processing is beneficial. The function requires that the number of messages in the batch is within a specific range, and it will automatically fall back to a narrower implementation if the batch size is too small. This function does not perform input validation, so it is the caller's responsibility to ensure that all inputs are valid and properly aligned as required.
- **Inputs**:
    - `batch_cnt`: The number of messages in the batch. Must be between 1 and FD_SHA256_BATCH_MAX inclusive. If the count is less than the minimum required for AVX-512, a fallback implementation is used.
    - `_batch_data`: A pointer to an array of pointers, each pointing to the data of a message to be hashed. The data pointers must be aligned as required by the implementation.
    - `batch_sz`: A pointer to an array of unsigned long integers, each representing the size in bytes of the corresponding message in the batch. The sizes must be valid and correspond to the data provided.
    - `_batch_hash`: A pointer to an array of pointers, each pointing to a 32-byte memory region where the resulting hash of the corresponding message will be stored. The hash pointers must be aligned as required by the implementation.
- **Output**: None
- **See also**: [`fd_sha256_private_batch_avx512`](fd_sha256_batch_avx512.c.driver.md#fd_sha256_private_batch_avx512)  (Implementation)


