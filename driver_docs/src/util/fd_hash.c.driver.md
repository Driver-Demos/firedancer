# Purpose
This C source code file provides a specialized implementation of a hashing algorithm, specifically a cleaner version of the xxHash algorithm (version r39), which is known for its speed and efficiency. The file defines two primary functions: [`fd_hash`](#fd_hash) and [`fd_hash_memcpy`](#fd_hash_memcpy). The [`fd_hash`](#fd_hash) function computes a hash value for a given buffer of data, using a seed value to initialize the hash computation. It processes the data in blocks, applying a series of bitwise operations and multiplications with predefined constants to ensure a good distribution of hash values. The [`fd_hash_memcpy`](#fd_hash_memcpy) function extends this functionality by not only computing the hash of the source data but also copying the data to a destination buffer, effectively combining the operations of hashing and memory copying.

The code is structured to handle data of varying sizes, with specific optimizations for processing data in blocks of 32 bytes, and additional logic to handle any remaining bytes. The use of constants and bitwise rotations is central to the algorithm's design, ensuring that the hash values are well-distributed and resistant to collisions. This file is likely intended to be part of a larger library or application where fast and reliable hashing is required, such as in data integrity checks, hash tables, or other data structures that rely on hashing. The inclusion of `fd_util_base.h` suggests that this file is part of a broader utility library, and the functions defined here could be used as part of a public API for hashing operations.
# Imports and Dependencies

---
- `fd_util_base.h`


# Functions

---
### fd\_hash<!-- {{#callable:fd_hash}} -->
The `fd_hash` function computes a hash value for a given buffer using a variant of the xxHash algorithm.
- **Inputs**:
    - `seed`: An initial seed value of type `ulong` used to start the hash computation.
    - `buf`: A pointer to the buffer (of type `void const *`) containing the data to be hashed.
    - `sz`: The size of the buffer in bytes, of type `ulong`.
- **Control Flow**:
    - Initialize pointers `p` and `stop` to the start and end of the buffer, respectively.
    - If the buffer size `sz` is less than 32, initialize the hash `h` with `seed + C5`.
    - If the buffer size `sz` is 32 or more, initialize variables `w`, `x`, `y`, and `z` with different values derived from `seed` and constants `C1` and `C2`.
    - Iterate over complete 32-byte blocks of the buffer, updating `w`, `x`, `y`, and `z` with transformed values from the buffer and constants `C1` and `C2`.
    - Combine `w`, `x`, `y`, and `z` into the hash `h` using bitwise rotations and additions.
    - Process remaining complete 8-byte blocks, updating `h` with transformed values from the buffer.
    - Process any remaining complete 4-byte block, updating `h` with transformed values from the buffer.
    - Process any remaining bytes one by one, updating `h` with transformed values from the buffer.
    - Perform a final avalanche step on `h` using bitwise shifts and multiplications with constants `C2` and `C3`.
- **Output**: The function returns a `ulong` representing the computed hash value of the input buffer.


---
### fd\_hash\_memcpy<!-- {{#callable:fd_hash_memcpy}} -->
The `fd_hash_memcpy` function computes a hash of a memory block while simultaneously copying it from a source to a destination buffer.
- **Inputs**:
    - `seed`: An initial hash value used to start the hash computation.
    - `dst`: A pointer to the destination buffer where the source data will be copied.
    - `src`: A pointer to the source buffer containing the data to be hashed and copied.
    - `sz`: The size in bytes of the data to be hashed and copied.
- **Control Flow**:
    - Initialize pointers for source and destination buffers and calculate the stop pointer.
    - If the size is less than 32 bytes, initialize the hash with a constant added to the seed.
    - For sizes 32 bytes or more, process the data in blocks of 32 bytes, updating the hash and copying data to the destination buffer.
    - After processing full 32-byte blocks, update the hash with the remaining data in chunks of 8 bytes, 4 bytes, and finally 1 byte, copying each to the destination buffer.
    - Perform a final avalanche step to mix the hash thoroughly before returning it.
- **Output**: The function returns a `ulong` representing the computed hash of the source data.


