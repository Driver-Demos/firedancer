# Purpose
The provided C header file, `fd_chacha20rng.h`, defines a set of APIs for a ChaCha20-based random number generator (RNG) specifically used within the Solana protocol. This file is part of a larger codebase and is intended to be included in other C source files that require ChaCha20 RNG functionality. The header outlines the structure and functions necessary to initialize, manage, and utilize a ChaCha20 RNG object. It includes definitions for memory alignment and footprint requirements, as well as functions for creating, joining, leaving, and deleting RNG objects. The file also provides mechanisms for generating random numbers, including a method for generating unbiased random integers within a specified range using rejection sampling.

The header file defines a private structure, `fd_chacha20rng_private`, which encapsulates the state of the RNG, including the encryption key, a buffer for pre-generated random data, and operational mode settings. The file supports two modes of operation, `MODE_MOD` and `MODE_SHIFT`, which dictate how random numbers are generated and mapped to a specified range. The file also includes conditional compilation directives to optimize performance based on the availability of AVX instructions and 128-bit integer support. Additionally, the file provides internal functions for refilling the RNG buffer and a debug logging mechanism to aid in development and troubleshooting. Overall, this header file is a specialized component designed to integrate ChaCha20 RNG capabilities into applications that require cryptographic randomness, particularly within the context of the Solana blockchain protocol.
# Imports and Dependencies

---
- `fd_chacha20.h`
- `../../util/bits/fd_uwide.h`


# Global Variables

---
### fd\_chacha20rng\_new
- **Type**: `function pointer`
- **Description**: `fd_chacha20rng_new` is a function that initializes a memory region to hold a ChaCha20-based random number generator (RNG) object. It takes a pointer to a memory region (`shmem`) and an integer (`mode`) that specifies the mode of operation for the RNG.
- **Use**: This function is used to format a memory region for a ChaCha20 RNG object, returning the memory region pointer on success or NULL on failure.


---
### fd\_chacha20rng\_join
- **Type**: `fd_chacha20rng_t *`
- **Description**: The `fd_chacha20rng_join` is a function that returns a pointer to a `fd_chacha20rng_t` structure. This function is used to join a caller to a ChaCha20-based random number generator (RNG) object, which is stored in a shared memory region.
- **Use**: This function is used to obtain a local handle to a ChaCha20 RNG object from a shared memory region, allowing the caller to interact with the RNG.


---
### fd\_chacha20rng\_leave
- **Type**: `function pointer`
- **Description**: `fd_chacha20rng_leave` is a function that allows a caller to leave their current local join to a ChaCha20 RNG object. It returns a pointer to the memory region holding the object on success, or NULL on failure.
- **Use**: This function is used to disassociate a caller from a ChaCha20 RNG object, effectively ending their session with the RNG.


---
### fd\_chacha20rng\_delete
- **Type**: `function pointer`
- **Description**: `fd_chacha20rng_delete` is a function that unformats a memory region holding a ChaCha20 RNG object. It assumes that the memory region is not currently joined by any process and returns a pointer to the memory region on success, or NULL on failure.
- **Use**: This function is used to clean up and reclaim the memory region previously allocated for a ChaCha20 RNG object, ensuring that the caller regains ownership of the memory.


---
### fd\_chacha20rng\_init
- **Type**: `fd_chacha20rng_t *`
- **Description**: The `fd_chacha20rng_init` function initializes a ChaCha20-based random number generator (RNG) stream. It takes a pointer to an `fd_chacha20rng_t` structure, which represents the RNG state, and a constant pointer to a 32-byte key used for seeding the RNG.
- **Use**: This function is used to start a new ChaCha20 RNG stream by setting up the initial state with a given key.


# Data Structures

---
### fd\_chacha20rng\_private
- **Type**: `struct`
- **Members**:
    - `key`: An array of 32 unsigned characters representing the ChaCha20 encryption key, aligned to 32 bytes.
    - `buf`: A ring buffer of pre-generated ChaCha20 random number generator data, aligned to the ChaCha20 block size.
    - `buf_off`: A counter representing the total number of bytes consumed from the buffer.
    - `buf_fill`: A counter representing the total number of bytes produced in the buffer, always aligned by the ChaCha20 block size.
    - `mode`: An integer indicating the mode of operation for the random number generation, such as MODE_MOD or MODE_SHIFT.
- **Description**: The `fd_chacha20rng_private` structure is a data structure used to implement a ChaCha20-based random number generator (RNG) in the Solana protocol. It contains a 32-byte encryption key, a buffer for storing pre-generated random data, and counters to track the consumption and production of data within the buffer. The structure also includes a mode field to specify the method of random number generation, which can affect the distribution of generated numbers. This structure is aligned to 32 bytes to optimize performance on modern processors.


---
### fd\_chacha20rng\_t
- **Type**: `struct`
- **Members**:
    - `key`: A 32-byte array representing the ChaCha20 encryption key, aligned to 32 bytes.
    - `buf`: A ring buffer of pre-generated ChaCha20 RNG data, aligned to the ChaCha20 block size.
    - `buf_off`: A counter for the total number of bytes consumed from the buffer.
    - `buf_fill`: A counter for the total number of bytes produced in the buffer, always aligned by the ChaCha20 block size.
    - `mode`: An integer indicating the mode of operation for generating random numbers, either MODE_MOD or MODE_SHIFT.
- **Description**: The `fd_chacha20rng_t` structure is a private data structure used to implement a ChaCha20-based random number generator (RNG) for the Solana protocol. It contains a 32-byte encryption key for the ChaCha20 algorithm, a buffer for storing pre-generated random data, and counters to track the consumption and production of data within the buffer. The structure also includes a mode field to determine the method of mapping random numbers to a specified range, supporting different operational modes such as MODE_MOD and MODE_SHIFT. This structure is aligned to 32 bytes to optimize performance on modern hardware architectures.


# Functions

---
### fd\_chacha20rng\_avail<!-- {{#callable:fd_chacha20rng_avail}} -->
The `fd_chacha20rng_avail` function calculates the number of available bytes in the ChaCha20 RNG buffer that have not yet been consumed.
- **Inputs**:
    - `rng`: A pointer to a constant `fd_chacha20rng_t` structure representing the ChaCha20 RNG state.
- **Control Flow**:
    - The function accesses the `buf_fill` and `buf_off` fields of the `fd_chacha20rng_t` structure pointed to by `rng`.
    - It calculates the difference between `buf_fill` and `buf_off`, which represents the number of bytes available in the buffer that have not been consumed.
- **Output**: The function returns an `ulong` representing the number of available bytes in the buffer.


---
### fd\_chacha20rng\_ulong<!-- {{#callable:fd_chacha20rng_ulong}} -->
The `fd_chacha20rng_ulong` function retrieves a 64-bit unsigned long integer from a ChaCha20-based random number generator buffer, refilling the buffer if necessary.
- **Inputs**:
    - `rng`: A pointer to an `fd_chacha20rng_t` structure, which represents the state of the ChaCha20-based random number generator.
- **Control Flow**:
    - Check if the available bytes in the RNG buffer are less than the size of an unsigned long integer.
    - If the buffer has insufficient bytes, call `fd_chacha20rng_private_refill` to refill the buffer.
    - Load a 64-bit unsigned long integer from the buffer at the current buffer offset, adjusted by the buffer size.
    - Increment the buffer offset by 8 bytes to account for the consumed unsigned long integer.
    - Return the loaded unsigned long integer.
- **Output**: A 64-bit unsigned long integer from the RNG buffer.
- **Functions called**:
    - [`fd_chacha20rng_avail`](#fd_chacha20rng_avail)


---
### fd\_chacha20rng\_ulong\_roll<!-- {{#callable:fd_chacha20rng_ulong_roll}} -->
The `fd_chacha20rng_ulong_roll` function generates a uniformly distributed random unsigned long integer in the range [0, n) using a rejection sampling method based on the ChaCha20 random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_chacha20rng_t` structure, which represents the state of the ChaCha20 random number generator.
    - `n`: An unsigned long integer representing the upper bound of the range [0, n) for the random number generation.
- **Control Flow**:
    - Calculate the 'zone' value based on the mode of the RNG (either MODE_MOD or MODE_SHIFT) to determine the valid range for rejection sampling.
    - Enter an infinite loop to repeatedly generate random numbers until a valid one is found.
    - Generate a random unsigned long integer 'v' using the [`fd_chacha20rng_ulong`](#fd_chacha20rng_ulong) function.
    - If 128-bit integer support is available, multiply 'v' by 'n' using a single instruction to get 'res', then extract the high and low parts of the result.
    - If 128-bit integer support is not available, use the `fd_uwide_mul` function to perform the multiplication and extract the high and low parts.
    - If debugging is enabled, log the attempt details including 'n', 'zone', 'v', 'lo', and 'hi'.
    - Check if the low part 'lo' is less than or equal to 'zone'; if true, return the high part 'hi' as the result.
- **Output**: Returns a uniformly distributed random unsigned long integer in the range [0, n).
- **Functions called**:
    - [`fd_chacha20rng_ulong`](#fd_chacha20rng_ulong)


# Function Declarations (Public API)

---
### fd\_chacha20rng\_align<!-- {{#callable_declaration:fd_chacha20rng_align}} -->
Returns the required memory alignment for a ChaCha20-based RNG object.
- **Description**: Use this function to determine the memory alignment needed for allocating a region suitable for a ChaCha20-based random number generator (RNG) object. This is essential when setting up memory for the RNG to ensure proper alignment, which can affect performance and correctness. This function does not require any prior initialization and can be called at any time.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes for a ChaCha20-based RNG object.
- **See also**: [`fd_chacha20rng_align`](fd_chacha20rng.c.driver.md#fd_chacha20rng_align)  (Implementation)


---
### fd\_chacha20rng\_footprint<!-- {{#callable_declaration:fd_chacha20rng_footprint}} -->
Returns the memory footprint required for a ChaCha20-based RNG object.
- **Description**: Use this function to determine the size of memory needed to store a ChaCha20-based random number generator object. This is useful when allocating memory for such an object, ensuring that the allocated space is sufficient to hold the entire structure. This function does not perform any operations on the RNG object itself and can be called at any time.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the number of bytes required to store a ChaCha20-based RNG object.
- **See also**: [`fd_chacha20rng_footprint`](fd_chacha20rng.c.driver.md#fd_chacha20rng_footprint)  (Implementation)


---
### fd\_chacha20rng\_new<!-- {{#callable_declaration:fd_chacha20rng_new}} -->
Initialize a memory region for a ChaCha20-based RNG object.
- **Description**: This function prepares a memory region to hold a ChaCha20-based random number generator (RNG) object. It should be called with a pointer to a memory region that the caller owns and that is suitably aligned for a `fd_chacha20rng_t` object. The `mode` parameter specifies the RNG mode and must be one of the predefined constants `FD_CHACHA20RNG_MODE_MOD` or `FD_CHACHA20RNG_MODE_SHIFT`. The function returns the pointer to the initialized memory region on success, or `NULL` if the input is invalid, logging a warning in such cases. The caller retains ownership of the memory region, but it is formatted for use by the RNG object upon successful return.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be initialized. It must not be null and must be aligned according to `fd_chacha20rng_t` requirements. The caller retains ownership of this memory.
    - `mode`: An integer specifying the RNG mode. It must be either `FD_CHACHA20RNG_MODE_MOD` or `FD_CHACHA20RNG_MODE_SHIFT`. Invalid values result in a logged warning and a `NULL` return.
- **Output**: Returns the pointer to the initialized memory region on success, or `NULL` on failure.
- **See also**: [`fd_chacha20rng_new`](fd_chacha20rng.c.driver.md#fd_chacha20rng_new)  (Implementation)


---
### fd\_chacha20rng\_join<!-- {{#callable_declaration:fd_chacha20rng_join}} -->
Joins the caller to a ChaCha20 RNG object.
- **Description**: This function is used to join the caller to a ChaCha20-based random number generator (RNG) object. It should be called with a pointer to the memory region that holds the RNG object. This function is typically used after the memory region has been properly initialized and formatted to hold a ChaCha20 RNG object. If the provided pointer is null, the function will log a warning and return null, indicating failure to join.
- **Inputs**:
    - `shrng`: A pointer to the first byte of the memory region holding the ChaCha20 RNG object. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a local handle to the joined ChaCha20 RNG object on success, or null on failure.
- **See also**: [`fd_chacha20rng_join`](fd_chacha20rng.c.driver.md#fd_chacha20rng_join)  (Implementation)


---
### fd\_chacha20rng\_leave<!-- {{#callable_declaration:fd_chacha20rng_leave}} -->
Leaves the caller's current local join to a ChaCha20 RNG object.
- **Description**: This function is used to leave a current local join to a ChaCha20 RNG object, effectively ending the caller's association with the RNG object. It should be called when the caller no longer needs to interact with the RNG object. The function returns a pointer to the memory region holding the RNG object, which can be used for further operations such as deletion. It is important to ensure that the `rng` parameter is not null before calling this function, as passing a null pointer will result in a warning and a null return value.
- **Inputs**:
    - `rng`: A pointer to the `fd_chacha20rng_t` object representing the current local join to a ChaCha20 RNG. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the memory region holding the RNG object on success, or null if the input was invalid.
- **See also**: [`fd_chacha20rng_leave`](fd_chacha20rng.c.driver.md#fd_chacha20rng_leave)  (Implementation)


---
### fd\_chacha20rng\_delete<!-- {{#callable_declaration:fd_chacha20rng_delete}} -->
Unformats a memory region holding a ChaCha20 RNG object.
- **Description**: Use this function to safely unformat and zero out a memory region that was previously formatted to hold a ChaCha20 RNG object. It should be called when the RNG object is no longer needed, and it is important to ensure that no other operations are joined to the RNG object at the time of calling. This function will log a warning and return NULL if the provided pointer is NULL, otherwise it will zero out the memory and return the pointer to the caller, who regains ownership of the memory region.
- **Inputs**:
    - `shrng`: A pointer to the first byte of the memory region holding the ChaCha20 RNG object. Must not be NULL. If NULL, the function logs a warning and returns NULL. The caller regains ownership of the memory region on successful return.
- **Output**: Returns a pointer to the memory region on success, or NULL if the input was NULL.
- **See also**: [`fd_chacha20rng_delete`](fd_chacha20rng.c.driver.md#fd_chacha20rng_delete)  (Implementation)


---
### fd\_chacha20rng\_init<!-- {{#callable_declaration:fd_chacha20rng_init}} -->
Initializes a ChaCha20 RNG stream with a given key.
- **Description**: This function initializes a ChaCha20-based random number generator (RNG) using a specified key. It should be called when setting up a new RNG stream, ensuring that the `rng` parameter is a valid, locally joined ChaCha20 RNG object with no concurrent modifications. The function discards any preexisting state, starting a new RNG stream with the provided key. This is particularly useful in contexts where a ChaCha20 RNG is required, such as in the Solana protocol, although other RNGs might be preferable in different scenarios.
- **Inputs**:
    - `rng`: A pointer to an `fd_chacha20rng_t` object representing the ChaCha20 RNG to initialize. Must be a valid, locally joined object with no concurrent modifications.
    - `key`: A pointer to a 32-byte array containing the seed key for the RNG. The caller retains ownership, and the key must not be null.
- **Output**: Returns a pointer to the initialized `fd_chacha20rng_t` object, representing the RNG with the new state.
- **See also**: [`fd_chacha20rng_init`](fd_chacha20rng.c.driver.md#fd_chacha20rng_init)  (Implementation)


---
### fd\_chacha20rng\_refill\_avx<!-- {{#callable_declaration:fd_chacha20rng_refill_avx}} -->
Refills the ChaCha20 RNG buffer using AVX instructions.
- **Description**: This function refills the internal buffer of a ChaCha20-based random number generator using AVX instructions. It should be called only when the buffer is empty, as indicated by the buffer offset being equal to the buffer fill. This function is part of the internal workings of the RNG and is not intended for direct use in application code. It ensures that the buffer is populated with new random data, ready for subsequent random number generation requests.
- **Inputs**:
    - `rng`: A pointer to an fd_chacha20rng_t structure representing the ChaCha20 RNG state. The buffer within this structure must be empty (buf_off must equal buf_fill) before calling this function. The caller retains ownership of the structure, and it must not be null.
- **Output**: None
- **See also**: [`fd_chacha20rng_refill_avx`](fd_chacha20_avx.c.driver.md#fd_chacha20rng_refill_avx)  (Implementation)


---
### fd\_chacha20rng\_refill\_seq<!-- {{#callable_declaration:fd_chacha20rng_refill_seq}} -->
Refills the ChaCha20 RNG buffer with new random data.
- **Description**: This function is used to replenish the internal buffer of a ChaCha20-based random number generator with new random data. It should be called when the available random data in the buffer is insufficient for the required operations. The function ensures that the buffer is filled up to a target level, maintaining the necessary alignment and size constraints. It is important to ensure that the RNG object is properly initialized and that no concurrent operations are modifying the state of the RNG while this function is executing.
- **Inputs**:
    - `rng`: A pointer to an fd_chacha20rng_t object representing the ChaCha20 RNG. The pointer must not be null, and the RNG must be properly initialized and not concurrently modified by other operations.
- **Output**: None
- **See also**: [`fd_chacha20rng_refill_seq`](fd_chacha20rng.c.driver.md#fd_chacha20rng_refill_seq)  (Implementation)


