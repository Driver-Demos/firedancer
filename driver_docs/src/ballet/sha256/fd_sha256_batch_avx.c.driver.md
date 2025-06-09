# Purpose
This C source code file implements a batch processing function for computing SHA-256 hashes using AVX (Advanced Vector Extensions) instructions, specifically optimized for handling multiple data inputs simultaneously. The function [`fd_sha256_private_batch_avx`](#fd_sha256_private_batch_avx) is designed to process a batch of data inputs, compute their SHA-256 hashes, and store the results. The code is structured to handle up to eight data inputs in parallel, leveraging SIMD (Single Instruction, Multiple Data) capabilities to enhance performance. The function includes logic to decide whether to process the data sequentially or in parallel based on the batch size and the availability of SHA-NI (SHA New Instructions) for further optimization.

The code is part of a larger library, as indicated by the inclusion of headers like "fd_sha256.h" and "../../util/simd/fd_avx.h", suggesting it is intended to be used as a component within a broader system. The function is not a standalone executable but rather a utility function that can be called by other parts of the software. It does not define a public API or external interface directly but provides a specialized implementation detail for SHA-256 hashing. The code includes various optimizations, such as memory alignment and efficient data handling, to maximize the throughput of hash computations, making it suitable for high-performance applications where processing multiple data streams concurrently is beneficial.
# Imports and Dependencies

---
- `fd_sha256.h`
- `../../util/simd/fd_avx.h`


# Functions

---
### fd\_sha256\_private\_batch\_avx<!-- {{#callable:fd_sha256_private_batch_avx}} -->
The `fd_sha256_private_batch_avx` function computes SHA-256 hashes for a batch of messages using AVX instructions, optimizing for performance based on batch size and available hardware features.
- **Inputs**:
    - `batch_cnt`: The number of messages in the batch to be hashed.
    - `_batch_data`: A pointer to the array of message data to be hashed.
    - `batch_sz`: An array of sizes for each message in the batch, indicating the length of each message.
    - `_batch_hash`: A pointer to the array where the resulting hashes will be stored.
- **Control Flow**:
    - Check if the batch size is below a minimum threshold; if so, process each message sequentially using [`fd_sha256_hash`](fd_sha256.c.driver.md#fd_sha256_hash).
    - Align and prepare tail blocks for each message, including padding and appending the message size in bits.
    - Initialize SHA-256 state variables and prepare SIMD vectors for processing.
    - Iterate over message blocks, processing each block using AVX instructions and updating the SHA-256 state.
    - Switch to processing tail blocks when the end of the message is reached.
    - Store the final hash results for each message in the provided output array.
- **Output**: The function does not return a value but writes the computed SHA-256 hashes to the provided `_batch_hash` array.
- **Functions called**:
    - [`fd_sha256_hash`](fd_sha256.c.driver.md#fd_sha256_hash)


