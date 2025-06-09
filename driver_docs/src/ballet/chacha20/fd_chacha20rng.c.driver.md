# Purpose
This C source code file provides functionality for managing and utilizing a ChaCha20-based random number generator (RNG). The code defines several functions that handle the lifecycle of an `fd_chacha20rng_t` object, which represents the state of the RNG. The primary operations include creating a new RNG instance ([`fd_chacha20rng_new`](#fd_chacha20rng_new)), initializing it with a key ([`fd_chacha20rng_init`](#fd_chacha20rng_init)), and managing its memory alignment and footprint. The code also includes functions for joining and leaving shared RNG instances, as well as deleting them, ensuring proper memory management and alignment checks.

The file is structured to support both sequential and AVX-optimized refilling of the RNG buffer, with conditional compilation directives to select the appropriate method based on the availability of AVX instructions. The [`fd_chacha20rng_refill_seq`](#fd_chacha20rng_refill_seq) function is responsible for refilling the RNG buffer using the ChaCha20 block function, ensuring that the buffer is adequately filled for random number generation. This code is likely part of a larger library, as it includes header files and defines functions that could be used by other components. It does not define a public API directly but provides essential building blocks for RNG operations, focusing on memory management, initialization, and buffer refilling.
# Imports and Dependencies

---
- `fd_chacha20rng.h`


# Functions

---
### fd\_chacha20rng\_align<!-- {{#callable:fd_chacha20rng_align}} -->
The `fd_chacha20rng_align` function returns the alignment requirement of the `fd_chacha20rng_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function calls the `alignof` operator on the `fd_chacha20rng_t` type to determine its alignment requirement.
    - The function returns the result of the `alignof` operation.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_chacha20rng_t` type.


---
### fd\_chacha20rng\_footprint<!-- {{#callable:fd_chacha20rng_footprint}} -->
The function `fd_chacha20rng_footprint` returns the memory footprint size of the `fd_chacha20rng_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the result of the `sizeof` operator applied to `fd_chacha20rng_t`.
- **Output**: The function outputs an `ulong` representing the size in bytes of the `fd_chacha20rng_t` structure.


---
### fd\_chacha20rng\_new<!-- {{#callable:fd_chacha20rng_new}} -->
The `fd_chacha20rng_new` function initializes a new ChaCha20 random number generator in shared memory with a specified mode.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the ChaCha20 RNG state will be initialized.
    - `mode`: An integer representing the mode of operation for the RNG, which must be either `FD_CHACHA20RNG_MODE_MOD` or `FD_CHACHA20RNG_MODE_SHIFT`.
- **Control Flow**:
    - Check if `shmem` is NULL and log a warning if true, then return NULL.
    - Check if `shmem` is properly aligned to the alignment requirements of `fd_chacha20rng_t` and log a warning if not, then return NULL.
    - Initialize the memory pointed to by `shmem` to zero using `memset`.
    - Check if `mode` is valid (either `FD_CHACHA20RNG_MODE_MOD` or `FD_CHACHA20RNG_MODE_SHIFT`), log a warning if not, then return NULL.
    - Set the `mode` field of the `fd_chacha20rng_t` structure in `shmem` to the provided `mode`.
    - Return the `shmem` pointer.
- **Output**: Returns a pointer to the initialized shared memory if successful, or NULL if any checks fail.


---
### fd\_chacha20rng\_join<!-- {{#callable:fd_chacha20rng_join}} -->
The `fd_chacha20rng_join` function converts a shared memory pointer to a `fd_chacha20rng_t` pointer after checking for nullity.
- **Inputs**:
    - `shrng`: A pointer to shared memory that is expected to be of type `fd_chacha20rng_t`.
- **Control Flow**:
    - Check if the input `shrng` is NULL using `FD_UNLIKELY`; if it is, log a warning and return NULL.
    - If `shrng` is not NULL, cast it to a `fd_chacha20rng_t` pointer and return it.
- **Output**: Returns a pointer to `fd_chacha20rng_t` if `shrng` is not NULL; otherwise, returns NULL.


---
### fd\_chacha20rng\_leave<!-- {{#callable:fd_chacha20rng_leave}} -->
The `fd_chacha20rng_leave` function checks if the given ChaCha20 RNG context is non-null and returns it as a void pointer, logging a warning if it is null.
- **Inputs**:
    - `rng`: A pointer to an `fd_chacha20rng_t` structure representing the ChaCha20 RNG context to be left.
- **Control Flow**:
    - Check if the `rng` pointer is null using `FD_UNLIKELY`.
    - If `rng` is null, log a warning message 'NULL rng' and return `NULL`.
    - If `rng` is not null, cast it to a `void *` and return it.
- **Output**: Returns the `rng` pointer cast to a `void *`, or `NULL` if `rng` is null.


---
### fd\_chacha20rng\_delete<!-- {{#callable:fd_chacha20rng_delete}} -->
The `fd_chacha20rng_delete` function securely deletes a ChaCha20 random number generator state by zeroing out its memory.
- **Inputs**:
    - `shrng`: A pointer to the ChaCha20 random number generator state to be deleted.
- **Control Flow**:
    - Check if the input pointer `shrng` is NULL using `FD_UNLIKELY`; if so, log a warning and return NULL.
    - Use `memset` to zero out the memory of the ChaCha20 random number generator state pointed to by `shrng`.
    - Return the pointer `shrng` after zeroing out its memory.
- **Output**: Returns the pointer to the zeroed-out ChaCha20 random number generator state, or NULL if the input was NULL.


---
### fd\_chacha20rng\_init<!-- {{#callable:fd_chacha20rng_init}} -->
The `fd_chacha20rng_init` function initializes a ChaCha20 random number generator state with a given key and prepares it for use by refilling its buffer.
- **Inputs**:
    - `rng`: A pointer to an `fd_chacha20rng_t` structure that represents the ChaCha20 random number generator state to be initialized.
    - `key`: A constant pointer to the key data used to initialize the ChaCha20 random number generator; it should be of size `FD_CHACHA20_KEY_SZ`.
- **Control Flow**:
    - Copy the provided key into the `key` field of the `rng` structure using `memcpy`.
    - Set the `buf_off` field of the `rng` structure to 0, indicating the starting offset of the buffer.
    - Set the `buf_fill` field of the `rng` structure to 0, indicating that the buffer is initially empty.
    - Call the `fd_chacha20rng_private_refill` function to fill the buffer with initial random data.
    - Return the pointer to the initialized `fd_chacha20rng_t` structure.
- **Output**: Returns a pointer to the initialized `fd_chacha20rng_t` structure.


---
### fd\_chacha20rng\_refill\_seq<!-- {{#callable:fd_chacha20rng_refill_seq}} -->
The function `fd_chacha20rng_refill_seq` refills the buffer of a ChaCha20-based random number generator until a specified target is reached.
- **Inputs**:
    - `rng`: A pointer to an `fd_chacha20rng_t` structure, which represents the state of the ChaCha20 random number generator.
- **Control Flow**:
    - Calculate the target buffer fill level as the buffer size minus the block size.
    - Enter a loop that continues until the available buffer space is less than the target fill level.
    - Within the loop, calculate the index for the nonce based on the current buffer fill level.
    - Call `fd_chacha20_block` to generate a block of random data using the current key and nonce, storing it in the buffer at the current fill position.
    - Increment the buffer fill level by the block size after each block is generated.
- **Output**: The function does not return a value; it modifies the state of the `fd_chacha20rng_t` structure pointed to by `rng` by refilling its buffer with random data.


# Function Declarations (Public API)

---
### fd\_chacha20rng\_refill\_avx<!-- {{#callable_declaration:fd_chacha20rng_refill_avx}} -->
Refills the ChaCha20 random number generator buffer using AVX instructions.
- **Description**: Use this function to refill the buffer of a ChaCha20 random number generator when it is empty. It is designed to be called only when the buffer is completely depleted, as indicated by the buffer offset equaling the buffer fill level. This function utilizes AVX instructions to efficiently generate random data and update the internal buffer of the generator. Ensure that the random number generator has been properly initialized before calling this function.
- **Inputs**:
    - `rng`: A pointer to an fd_chacha20rng_t structure representing the ChaCha20 random number generator. The pointer must not be null, and the structure should be properly initialized and aligned. The function assumes the buffer is empty before it is called.
- **Output**: None
- **See also**: [`fd_chacha20rng_refill_avx`](fd_chacha20_avx.c.driver.md#fd_chacha20rng_refill_avx)  (Implementation)


