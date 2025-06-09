# Purpose
This C source code file implements a function, [`fd_chacha20rng_refill_avx`](#fd_chacha20rng_refill_avx), which is part of a random number generator based on the ChaCha20 algorithm, optimized for AVX (Advanced Vector Extensions) instructions. The function is designed to refill a buffer with random data when it is empty, using the ChaCha20 stream cipher. The code leverages SIMD (Single Instruction, Multiple Data) operations to perform parallel processing, enhancing performance on processors that support AVX. The function uses a series of bitwise operations and permutations to transform the input key and initial vectors into a stream of pseudo-random numbers, which are then stored in the buffer of the `fd_chacha20rng_t` structure.

The code is highly specialized, focusing on the efficient generation of random numbers using the ChaCha20 algorithm. It includes several technical components such as inline functions for bit rotation and macros for the quarter-round operations, which are central to the ChaCha20 algorithm. The use of AVX instructions indicates that this code is intended for high-performance applications where speed and efficiency are critical. The file does not define a public API or external interfaces directly; instead, it provides a specific implementation detail that would be part of a larger library or application dealing with cryptographic operations or random number generation.
# Imports and Dependencies

---
- `fd_chacha20rng.h`
- `../../util/simd/fd_avx.h`
- `assert.h`


# Functions

---
### wu\_rol8<!-- {{#callable:wu_rol8}} -->
The `wu_rol8` function performs an 8-byte rotation on a 256-bit vector using a predefined shuffle mask.
- **Inputs**:
    - `x`: A 256-bit vector of type `wu_t` that is to be rotated.
- **Control Flow**:
    - Define a constant shuffle mask using the `wb` function, which specifies the byte positions for the rotation.
    - Use the `_mm256_shuffle_epi8` intrinsic to apply the shuffle mask to the input vector `x`, effectively rotating its bytes.
- **Output**: A 256-bit vector of type `wu_t` with its bytes rotated according to the predefined mask.


---
### fd\_chacha20rng\_refill\_avx<!-- {{#callable:fd_chacha20rng_refill_avx}} -->
The `fd_chacha20rng_refill_avx` function refills a ChaCha20-based random number generator buffer using AVX instructions when the buffer is empty.
- **Inputs**:
    - `rng`: A pointer to an `fd_chacha20rng_t` structure representing the ChaCha20 random number generator state, including its key and buffer.
- **Control Flow**:
    - Assert that the buffer is empty by checking if `rng->buf_off` equals `rng->buf_fill`.
    - Initialize constants `iv0`, `iv1`, `iv2`, and `iv3` with specific values used in the ChaCha20 algorithm.
    - Load the key from `rng->key` and split it into two parts, `key_lo` and `key_hi`, using AVX permutation instructions.
    - Shuffle the key parts to create `k0` to `k7`, which are used in the ChaCha20 state matrix.
    - Calculate the block index `idx` and create a vector `idxs` for the ChaCha20 state matrix.
    - Initialize the ChaCha20 state matrix with constants, key parts, and index values.
    - Perform 20 rounds of the ChaCha20 quarter-round function using a loop and the `QUARTER_ROUND` macro.
    - Add the initial state values back to the state matrix to finalize the ChaCha20 block.
    - Transpose the state matrix to prepare it for output.
    - Store the transposed state matrix into the random number generator's buffer.
    - Update the buffer fill level by adding the size of the newly generated blocks.
- **Output**: The function does not return a value but updates the `rng` structure's buffer with new random data and adjusts the buffer fill level.


