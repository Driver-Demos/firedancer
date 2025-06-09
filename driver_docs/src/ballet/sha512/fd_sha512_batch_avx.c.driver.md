# Purpose
This C source code file implements a batch processing function for computing SHA-512 hashes using AVX (Advanced Vector Extensions) SIMD (Single Instruction, Multiple Data) instructions. The function [`fd_sha512_private_batch_avx`](#fd_sha512_private_batch_avx) is designed to efficiently compute the SHA-512 hash for multiple data inputs simultaneously, leveraging the parallel processing capabilities of AVX to enhance performance. The code is structured to handle up to four data inputs in a batch, as indicated by the `FD_SHA512_BATCH_MAX` constant, and it includes optimizations for processing the tail blocks of each message, which are necessary for the SHA-512 padding scheme.

The function begins by checking if the batch count is less than two, in which case it falls back to a simpler, non-batch processing method. For larger batch sizes, the function prepares the data by aligning and padding it according to the SHA-512 specification, then processes the data in blocks using AVX instructions. The core of the function involves loading data into AVX registers, performing the SHA-512 state update operations, and finally storing the computed hash values. The use of AVX allows the function to perform operations on multiple data elements in parallel, significantly speeding up the hash computation process. This file is part of a larger library, as indicated by the inclusion of headers like `fd_sha512.h` and `fd_avx.h`, and it is intended to be used as an internal implementation detail rather than a public API, as suggested by the function's naming convention and the lack of external interface definitions.
# Imports and Dependencies

---
- `fd_sha512.h`
- `../../util/simd/fd_avx.h`


# Functions

---
### fd\_sha512\_private\_batch\_avx<!-- {{#callable:fd_sha512_private_batch_avx}} -->
The `fd_sha512_private_batch_avx` function computes SHA-512 hashes for a batch of messages using AVX instructions, optimizing for cases where the batch size is greater than one.
- **Inputs**:
    - `batch_cnt`: The number of messages in the batch to be hashed.
    - `_batch_data`: A pointer to the array of message data to be hashed.
    - `batch_sz`: An array of sizes for each message in the batch, indicating the length of each message.
    - `_batch_hash`: A pointer to the array where the resulting hashes will be stored.
- **Control Flow**:
    - Check if the batch count is less than 2; if so, process each message individually using [`fd_sha512_hash`](fd_sha512.c.driver.md#fd_sha512_hash) and return.
    - Initialize variables for tail data and scratch space, and set up zero vectors for clearing memory.
    - Iterate over each message in the batch to allocate and populate tail blocks, handling message padding and size encoding.
    - Set up initial SHA-512 state vectors and constants for processing.
    - Enter a loop to process message blocks, switching to tail blocks when necessary, and perform SHA-512 state updates using AVX instructions.
    - After processing all blocks, store the computed hash results in the provided output array.
- **Output**: The function does not return a value but writes the computed SHA-512 hashes to the provided output array `_batch_hash`.
- **Functions called**:
    - [`fd_sha512_hash`](fd_sha512.c.driver.md#fd_sha512_hash)


