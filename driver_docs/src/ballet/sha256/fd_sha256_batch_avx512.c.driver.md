# Purpose
This C source code file implements a high-performance SHA-256 hashing function optimized for batch processing using AVX and AVX-512 SIMD (Single Instruction, Multiple Data) instructions. The primary function, [`fd_sha256_private_batch_avx512`](#fd_sha256_private_batch_avx512), is designed to compute SHA-256 hashes for multiple data blocks simultaneously, leveraging the parallel processing capabilities of modern CPUs. The code includes logic to handle different batch sizes, with a fallback to a narrower AVX implementation for smaller batches, ensuring efficient processing across various input sizes. The use of SIMD instructions allows the function to process multiple data streams in parallel, significantly improving throughput compared to a scalar implementation.

The file is part of a larger library, as indicated by the inclusion of headers like "fd_sha256.h" and SIMD utility headers. It does not define a public API directly but rather provides an internal implementation detail for batch processing of SHA-256 hashes. The code is highly optimized, with careful attention to memory alignment and efficient data handling, including the use of precomputed constants and bitwise operations to perform the core SHA-256 transformations. The implementation also includes mechanisms to handle message padding and length encoding, which are essential components of the SHA-256 algorithm. Overall, this file is a specialized component focused on delivering high-performance cryptographic hashing for applications that require processing large volumes of data efficiently.
# Imports and Dependencies

---
- `fd_sha256.h`
- `../../util/simd/fd_avx512.h`
- `../../util/simd/fd_avx.h`


# Functions

---
### fd\_sha256\_private\_batch\_avx512<!-- {{#callable:fd_sha256_private_batch_avx512}} -->
The `fd_sha256_private_batch_avx512` function computes SHA-256 hashes for a batch of messages using AVX-512 SIMD instructions for parallel processing.
- **Inputs**:
    - `batch_cnt`: The number of messages in the batch to be hashed.
    - `_batch_data`: A pointer to the data of the messages to be hashed.
    - `batch_sz`: An array of sizes for each message in the batch.
    - `_batch_hash`: An array of pointers where the resulting hashes will be stored.
- **Control Flow**:
    - Check if the batch count is below a minimum threshold and use a narrower implementation if so.
    - Initialize arrays for tail data and remaining data sizes, and allocate scratch space for processing.
    - Iterate over each message in the batch to prepare tail blocks by aligning and padding the data as per SHA-256 requirements.
    - Initialize SHA-256 state variables and constants for processing.
    - Enter a loop to process each block of data, switching to tail blocks when necessary, and compute SHA-256 state updates using SIMD operations.
    - After processing all blocks, store the computed hash results in the provided output locations.
- **Output**: The function outputs the SHA-256 hash of each message in the batch, stored in the locations pointed to by `_batch_hash`.
- **Functions called**:
    - [`fd_sha256_private_batch_avx`](fd_sha256_batch_avx.c.driver.md#fd_sha256_private_batch_avx)


# Function Declarations (Public API)

---
### fd\_sha256\_private\_batch\_avx<!-- {{#callable_declaration:fd_sha256_private_batch_avx}} -->
Computes SHA-256 hashes for a batch of data using AVX instructions.
- **Description**: This function processes a batch of data to compute SHA-256 hashes using AVX instructions for optimization. It is designed to handle multiple data inputs in parallel, making it suitable for applications that require hashing of large datasets efficiently. The function should be called with a batch size that meets or exceeds a minimum threshold for optimal performance. It is important to ensure that the input data and sizes are correctly specified, and that the output pointers are valid and capable of storing the resulting hashes.
- **Inputs**:
    - `batch_cnt`: The number of data items in the batch. Must be at least 2 for the function to use the batched implementation; otherwise, it processes each item sequentially.
    - `batch_data`: A pointer to an array of pointers, each pointing to a data buffer to be hashed. The caller retains ownership and must ensure the data is valid and accessible.
    - `batch_sz`: A pointer to an array of unsigned long integers, each representing the size of the corresponding data buffer in bytes. Must be valid and match the number of items specified by batch_cnt.
    - `batch_hash`: A pointer to an array of pointers, each pointing to a buffer where the resulting hash will be stored. Each buffer must be large enough to hold a SHA-256 hash (32 bytes). The caller retains ownership and must ensure the buffers are valid and writable.
- **Output**: None
- **See also**: [`fd_sha256_private_batch_avx`](fd_sha256_batch_avx.c.driver.md#fd_sha256_private_batch_avx)  (Implementation)


