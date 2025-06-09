# Purpose
This C source code file implements a batch processing function for the SHA-512 cryptographic hash algorithm, optimized for AVX-512 SIMD (Single Instruction, Multiple Data) instructions. The primary function, [`fd_sha512_private_batch_avx512`](#fd_sha512_private_batch_avx512), processes multiple messages in parallel, leveraging the AVX-512 capabilities to enhance performance. The function handles up to eight messages simultaneously, as indicated by the `FD_SHA512_BATCH_MAX` constant, and switches to a less parallelized AVX implementation if the batch count is less than five. The code includes detailed handling of message padding and tail block processing, which are critical for the SHA-512 algorithm's integrity and performance.

The file is part of a larger library, as suggested by the inclusion of headers like "fd_sha512.h" and "../../util/simd/fd_avx512.h", and it is not intended to be a standalone executable. Instead, it provides specialized functionality for high-performance cryptographic operations, likely to be used in systems requiring efficient data integrity checks or secure hashing. The code does not define public APIs or external interfaces directly but rather serves as an internal component optimized for specific hardware capabilities, focusing on the computationally intensive parts of the SHA-512 algorithm.
# Imports and Dependencies

---
- `fd_sha512.h`
- `../../util/simd/fd_avx512.h`


# Functions

---
### fd\_sha512\_private\_batch\_avx512<!-- {{#callable:fd_sha512_private_batch_avx512}} -->
The `fd_sha512_private_batch_avx512` function computes SHA-512 hashes for a batch of messages using AVX-512 SIMD instructions, optimizing for batches of five or more messages.
- **Inputs**:
    - `batch_cnt`: The number of messages in the batch to be processed.
    - `_batch_data`: A pointer to the data of the messages to be hashed.
    - `batch_sz`: An array of sizes for each message in the batch, indicating the length of each message.
    - `_batch_hash`: An array of pointers where the resulting hashes for each message will be stored.
- **Control Flow**:
    - Check if the batch count is less than 5; if so, delegate to [`fd_sha512_private_batch_avx`](fd_sha512_batch_avx.c.driver.md#fd_sha512_private_batch_avx) and return.
    - Initialize arrays for tail data and remaining data sizes, and allocate scratch space for processing.
    - Iterate over each message in the batch to prepare tail blocks, including padding and appending the message size in bits.
    - Initialize SHA-512 state variables and constants for processing.
    - Enter a loop to process each block of the message, switching to tail blocks when necessary.
    - Load and transpose message blocks, compute SHA-512 state updates using SIMD operations, and update the state variables.
    - Advance to the next message segment blocks and repeat until all blocks are processed.
    - Store the computed hashes in the provided output pointers, handling up to 8 messages.
- **Output**: The function does not return a value but writes the computed SHA-512 hashes to the locations pointed to by `_batch_hash`.
- **Functions called**:
    - [`fd_sha512_private_batch_avx`](fd_sha512_batch_avx.c.driver.md#fd_sha512_private_batch_avx)


# Function Declarations (Public API)

---
### fd\_sha512\_private\_batch\_avx<!-- {{#callable_declaration:fd_sha512_private_batch_avx}} -->
Computes SHA-512 hashes for a batch of messages using AVX instructions.
- **Description**: This function computes the SHA-512 hash for each message in a batch using AVX instructions for optimization. It is designed to handle multiple messages simultaneously, improving performance for batch processing. The function should be used when you have multiple messages to hash and want to leverage AVX for performance gains. It requires that the number of messages (`batch_cnt`) is at least 1. If `batch_cnt` is less than 2, it processes each message individually without AVX optimization. The function writes the resulting hashes to the provided output locations. Ensure that all input pointers are valid and that the output locations have enough space to store the resulting hashes.
- **Inputs**:
    - `batch_cnt`: The number of messages to process. Must be at least 1. If less than 2, the function processes messages without AVX optimization.
    - `batch_data`: A pointer to an array of pointers, each pointing to a message to be hashed. The caller retains ownership and must ensure the data is valid for the duration of the call.
    - `batch_sz`: A pointer to an array of sizes, each representing the size of the corresponding message in `batch_data`. Each size must be valid and correspond to the actual size of the message.
    - `batch_hash`: A pointer to an array of pointers, each pointing to a location where the resulting hash will be stored. Each location must have enough space to store a SHA-512 hash (64 bytes). The caller retains ownership.
- **Output**: None
- **See also**: [`fd_sha512_private_batch_avx`](fd_sha512_batch_avx.c.driver.md#fd_sha512_private_batch_avx)  (Implementation)


