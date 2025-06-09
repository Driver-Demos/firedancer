# Purpose
This assembly source code file implements an optimized version of the AES-GCM (Galois/Counter Mode) cryptographic algorithm for x86_64 CPUs that support VAES (vector AES), VPCLMULQDQ (vector carryless multiplication), and either AVX512 or AVX10 instruction sets. The code is designed to leverage these advanced vector instructions to enhance the performance of AES-GCM operations, which are critical for secure data encryption and decryption. The file includes functions for precomputing necessary cryptographic keys, updating encryption and decryption processes, and finalizing the authentication tag, all while utilizing vectorized operations to maximize throughput on compatible hardware.

The code is structured to provide both 256-bit and 512-bit vector implementations, allowing it to adapt to different CPU capabilities. The 512-bit vector functions are intended for CPUs that can handle such operations without significant performance penalties, requiring specific CPU features like AVX512BW, AVX512VL, or AVX10/512. The 256-bit vector functions are more broadly applicable, requiring a slightly different set of CPU features. The implementation uses the "System V" ABI and is not compatible with the Windows ABI, focusing on Unix-like systems.

Key technical components include macros for setting vector lengths, performing GHASH multiplication steps, and handling AES encryption rounds. The file also contains detailed comments explaining the mathematical operations involved in GHASH, a critical part of the GCM mode that ensures data integrity. The code is dual-licensed under the Apache License 2.0 and BSD-2-Clause, allowing for flexible use and distribution. This implementation is particularly suited for high-performance applications where cryptographic operations are a bottleneck, such as secure communications and data storage systems.
# Subroutines

---
### aes\_gcm\_precompute\_vaes\_avx10\_256
The `aes_gcm_precompute_vaes_avx10_256` function precomputes the GHASH subkey and initializes the powers of the hash key for AES-GCM encryption using 256-bit vectors on x86_64 CPUs with VAES and VPCLMULQDQ support.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_avx10` structure containing the expanded AES key and space for storing GHASH key powers.
- **Control Flow**:
    - The function begins by setting up the vector length to 32 bytes (256 bits) and defining register aliases for the YMM registers.
    - It calculates the pointer to the lowest set of key powers in the key structure.
    - An all-zero block is encrypted using the AES key to derive the raw GHASH subkey.
    - The bytes of the raw hash subkey are reflected using a shuffle mask.
    - The first key power, H^1, is preprocessed by reflecting its bytes and multiplying it by x^-1 mod the GHASH polynomial, which involves a left shift and conditional XOR operation.
    - The GHASH polynomial constant is loaded into a register for use in subsequent multiplications.
    - The first key power is squared to obtain H^2, and both H^1 and H^2 are stored in YMM registers for further processing.
    - If the vector length is 64 bytes (512 bits), additional key powers are computed and stored in ZMM registers.
    - The lowest set of key powers is stored in the key structure, and the remaining key powers are computed and stored in a loop, multiplying the current powers by precomputed increments.
    - The function ends by zeroing the upper parts of the YMM or ZMM registers to avoid performance penalties.
- **Output**: The function does not return a value but initializes the `ghash_key_powers` array in the `aes_gcm_key_avx10` structure with precomputed powers of the GHASH subkey.


---
### aes\_gcm\_enc\_update\_vaes\_avx10\_256
The `aes_gcm_enc_update_vaes_avx10_256` function performs AES-GCM encryption on a data segment using VAES and VPCLMULQDQ instructions optimized for AVX10 with 256-bit vectors, updating the GHASH accumulator and producing encrypted output.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_avx10` structure containing the expanded AES key and precomputed GHASH key powers.
    - `le_ctr`: A pointer to a 4-element array of 32-bit unsigned integers representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer that holds the current GHASH accumulator state.
    - `src`: A pointer to the source data buffer to be encrypted.
    - `dst`: A pointer to the destination buffer where the encrypted data will be written.
    - `datalen`: An integer representing the length of the data to be encrypted, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load constants and initialize registers for AES and GHASH operations.
    - Load the GHASH accumulator and the starting counter from memory.
    - Load the AES key length and determine the last round key pointer based on the key length.
    - Initialize the counter increment vector and adjust the counter for the first set of blocks.
    - Check if the data length is sufficient for processing in 4*VL byte chunks; if not, skip to processing smaller chunks.
    - Load powers of the hash key for GHASH operations.
    - Enter the main loop to process 4*VL bytes of data at a time, interleaving AES encryption of counter blocks with GHASH updates of ciphertext blocks.
    - For encryption, encrypt the first set of plaintext blocks and store the resulting ciphertext for GHASH.
    - Cache additional AES round keys for performance optimization.
    - In the main loop, perform AES encryption on counter blocks and update GHASH with ciphertext blocks, interleaving operations for performance.
    - If the data length is not a multiple of 4*VL, process the remaining data in smaller chunks, handling masking for the last partial vector if necessary.
    - Perform a final GHASH reduction and store the updated GHASH accumulator back to memory.
- **Output**: The function outputs the encrypted data to the `dst` buffer and updates the `ghash_acc` buffer with the new GHASH state.


---
### aes\_gcm\_dec\_update\_vaes\_avx10\_256
The `aes_gcm_dec_update_vaes_avx10_256` function performs AES-GCM decryption and updates the GHASH accumulator using VAES and VPCLMULQDQ instructions optimized for AVX10 with 256-bit vectors.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing the expanded AES key and precomputed GHASH key powers.
    - `le_ctr`: A pointer to a 4-element array of 32-bit unsigned integers representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer that holds the current GHASH accumulator value.
    - `src`: A pointer to the source data buffer containing the ciphertext to be decrypted.
    - `dst`: A pointer to the destination buffer where the decrypted data will be written.
    - `datalen`: An integer representing the length of the data to be processed, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load constants and initialize registers for byte swapping and GHASH polynomial.
    - Load the GHASH accumulator and the starting counter from memory.
    - Load the AES key length and calculate the pointer to the last AES round key.
    - Initialize the counter increment vector and adjust the data length for loop processing.
    - Enter a loop to process data in chunks of 4*VL bytes, interleaving AES encryption of counter blocks with GHASH updates of ciphertext blocks.
    - For each chunk, perform AES encryption on counter blocks, XOR with source data, and update GHASH with ciphertext blocks.
    - If the remaining data is less than 4*VL bytes, process it one vector at a time, handling any partial vectors with masking.
    - Perform a final GHASH reduction and store the updated GHASH accumulator back to memory.
- **Output**: The function outputs the decrypted data to the destination buffer and updates the GHASH accumulator in place.


---
### aes\_gcm\_precompute\_vaes\_avx10\_512
The `aes_gcm_precompute_vaes_avx10_512` function precomputes and initializes the GHASH key powers for AES-GCM encryption using 512-bit vectors on x86_64 CPUs with VAES and VPCLMULQDQ support.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_avx10` structure containing the expanded AES key.
- **Control Flow**:
    - The function begins by setting up the vector length to 64 bytes (512 bits) using the `_set_veclen` macro.
    - It calculates the pointer to the lowest set of key powers in the key structure.
    - An all-zero block is encrypted using the AES key to derive the raw GHASH subkey.
    - The bytes of the raw hash subkey are reflected using a shuffle mask.
    - The first key power, H^1, is preprocessed by reflecting its bytes and multiplying it by x^-1 mod the GHASH polynomial.
    - The GHASH polynomial constant is loaded into a register for further calculations.
    - The function squares H^1 to compute H^2 and constructs vectors for H_CUR and H_INC.
    - For VL=64, it further computes H^4 and constructs vectors for H_CUR and H_INC with four elements each.
    - The lowest set of key powers is stored in memory.
    - A loop computes and stores the remaining key powers by repeatedly multiplying the current powers by H^2 or H^4, depending on the vector length.
    - The function ends by zeroing the upper parts of the YMM or ZMM registers to avoid performance penalties.
- **Output**: The function outputs the initialized GHASH key powers stored in the `ghash_key_powers` field of the `aes_gcm_key_avx10` structure.


---
### aes\_gcm\_enc\_update\_vaes\_avx10\_512
The `aes_gcm_enc_update_vaes_avx10_512` function performs AES-GCM encryption and updates the GHASH accumulator using 512-bit vector operations on x86_64 CPUs with VAES and VPCLMULQDQ support.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing the expanded AES key and precomputed GHASH key powers.
    - `le_ctr`: A pointer to a 4-element array of 32-bit integers representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer holding the current GHASH accumulator value.
    - `src`: A pointer to the source data buffer to be encrypted.
    - `dst`: A pointer to the destination buffer where the encrypted data will be written.
    - `datalen`: An integer representing the length of the data to be encrypted, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load constants and initialize registers for byte swapping and GHASH polynomial.
    - Load the GHASH accumulator and the starting counter from memory.
    - Load the AES key length and calculate the pointer to the last AES round key.
    - Initialize the counter increment vector based on the vector length (VL).
    - Check if the data length is sufficient for processing in 4*VL byte chunks and enter the main loop if so.
    - In the main loop, interleave AES encryption of counter blocks with GHASH update of ciphertext blocks for performance optimization.
    - For encryption, process the first set of plaintext blocks, encrypt them, and store the ciphertext for GHASH processing.
    - Cache additional AES round keys for use in the main loop.
    - Process 4 vectors of data at a time, updating the GHASH accumulator and storing the encrypted data to the destination buffer.
    - If the data length is not a multiple of 4*VL, process the remaining data one vector at a time, using masking for the last iteration if necessary.
    - Perform a final GHASH reduction and store the updated GHASH accumulator back to memory.
- **Output**: The function outputs the encrypted data to the destination buffer and updates the GHASH accumulator in place.


---
### aes\_gcm\_dec\_update\_vaes\_avx10\_512
The `aes_gcm_dec_update_vaes_avx10_512` function performs AES-GCM decryption and updates the GHASH accumulator using 512-bit vector operations on x86_64 CPUs with VAES and VPCLMULQDQ support.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing the expanded AES key and precomputed GHASH key powers.
    - `le_ctr`: A pointer to a 4-element array of 32-bit unsigned integers representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer holding the current GHASH accumulator state.
    - `src`: A pointer to the source buffer containing the ciphertext data to be decrypted.
    - `dst`: A pointer to the destination buffer where the decrypted data will be written.
    - `datalen`: An integer representing the length of the data to be processed, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load constants and initialize registers for AES and GHASH operations.
    - Load the GHASH accumulator and the starting counter from memory.
    - Load the AES key length and calculate the pointer to the last AES round key.
    - Initialize the counter increment vector and adjust the counter for processing.
    - Check if the data length is sufficient for processing in 4*VL byte chunks and enter the main loop if so.
    - In the main loop, interleave AES encryption of counter blocks with GHASH updates of ciphertext blocks for performance optimization.
    - For decryption, load ciphertext blocks into GHASH data registers and start AES encryption of counter blocks.
    - Perform AES encryption rounds and update GHASH with ciphertext blocks, interleaving operations to optimize CPU resource usage.
    - Store decrypted data to the destination buffer and update pointers and counters.
    - If data length is not a multiple of 4*VL, process remaining data in VL byte chunks, using masking for the last partial vector if necessary.
    - Perform final GHASH reduction and store the updated GHASH accumulator back to memory.
    - Return from the function.
- **Output**: The function outputs the decrypted data in the destination buffer and updates the GHASH accumulator with the processed ciphertext.


---
### aes\_gcm\_aad\_update\_vaes\_avx10
The `aes_gcm_aad_update_vaes_avx10` function updates the GHASH accumulator with additional authenticated data (AAD) using AES-GCM with VAES and VPCLMULQDQ optimizations on x86_64 architecture.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_avx10` structure containing the precomputed GHASH key powers.
    - `ghash_acc`: A pointer to a 16-byte buffer that holds the current GHASH accumulator state, which should be all zeroes on the first call.
    - `aad`: A pointer to the additional authenticated data (AAD) to be processed.
    - `aadlen`: An integer representing the length of the AAD in bytes, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load the GHASH accumulator from the provided pointer.
    - Subtract 32 from `aadlen` to prepare for processing in 32-byte chunks.
    - Check if `aadlen` is less than 32; if so, skip the main loop.
    - Load the first two powers of the GHASH key from the key structure.
    - Enter a loop to process 32 bytes of AAD at a time, updating the GHASH accumulator using GHASH multiplication.
    - If there are remaining bytes (1 <= `aadlen` < 32), prepare a mask for the remaining bytes and process them, updating the GHASH accumulator.
    - Store the updated GHASH accumulator back to the provided memory location.
- **Output**: The function updates the GHASH accumulator with the processed AAD, modifying the state in the provided `ghash_acc` buffer.


---
### aes\_gcm\_enc\_final\_vaes\_avx10
The `aes_gcm_enc_final_vaes_avx10` function finalizes the AES-GCM encryption process by computing the authentication tag using the GHASH accumulator and encrypting it with the AES key.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing the expanded AES key and precomputed GHASH key powers.
    - `le_ctr`: A pointer to a 4-element array representing the counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer holding the current GHASH accumulator state.
    - `total_aadlen`: The total length of the additional authenticated data in bytes.
    - `total_datalen`: The total length of the encrypted data in bytes.
- **Control Flow**:
    - Load constants for GF(2^128) polynomial and byte swap mask.
    - Load AES key length and set up the counter block for tag encryption.
    - Build the lengths block from total AAD and data lengths, convert to bits, and XOR with GHASH accumulator.
    - Load the first hash key power (H^1) for GHASH multiplication.
    - Perform AES encryption on the counter block, interleaving with GHASH multiplication to improve performance.
    - Undo byte reflection on the GHASH accumulator and perform the final AES round to compute the authentication tag.
    - Store the computed authentication tag in the GHASH accumulator buffer.
- **Output**: The function outputs the computed 16-byte authentication tag by storing it in the `ghash_acc` buffer.


---
### aes\_gcm\_dec\_final\_vaes\_avx10
The `aes_gcm_dec_final_vaes_avx10` function finalizes the AES-GCM decryption process by computing and verifying the authentication tag.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure, which contains the expanded AES key and precomputed GHASH key powers.
    - `le_ctr`: A pointer to a 4-element array of 32-bit integers representing the counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer containing the current GHASH accumulator state.
    - `total_aadlen`: A 64-bit integer representing the total length of the additional authenticated data in bytes.
    - `total_datalen`: A 64-bit integer representing the total length of the decrypted data in bytes.
    - `tag`: A pointer to a 16-byte buffer containing the expected authentication tag.
    - `taglen`: An integer specifying the length of the tag to compare, between 4 and 16 bytes.
- **Control Flow**:
    - Load constants and initialize local variables for AES key length, GHASH accumulator, and counter block.
    - Build the lengths block from total AAD and data lengths, convert to bits, and XOR with the GHASH accumulator.
    - Load the first hash key power (H^1) and prepare a mask for the tag length.
    - Set up the counter block for encrypting the authentication tag and perform AES encryption on it.
    - Interleave AES encryption with GHASH multiplication to improve performance.
    - Undo byte reflection on the GHASH accumulator and perform the last AES round to compute the authentication tag.
    - Compare the computed tag with the expected tag using constant-time operations and return the result.
- **Output**: Returns a boolean value indicating whether the computed authentication tag matches the expected tag.


# Macros

---
### \_set\_veclen
The `_set_veclen` macro sets the vector length in bytes and defines register aliases for the appropriate vector registers based on the specified vector length.
- **Inputs**:
    - `vl`: The desired vector length in bytes, which can be either 32 or 64.
- **Control Flow**:
    - The macro begins by setting the `VL` variable to the specified vector length `vl`.
    - It iterates over a range of indices from 0 to 31 using the `.irp` directive.
    - For each index `i`, it checks if `VL` is equal to 32 or 64.
    - If `VL` is 32, it sets the alias `V\i` to the corresponding YMM register `%ymm\i`.
    - If `VL` is 64, it sets the alias `V\i` to the corresponding ZMM register `%zmm\i`.
    - If `VL` is neither 32 nor 64, it triggers an error with the message "Unsupported vector length".
- **Output**: The macro does not produce a direct output but sets up the environment by defining register aliases for vector operations based on the specified vector length.


---
### \_ghash\_mul\_step
The `_ghash_mul_step` macro performs one step of GHASH multiplication of 128-bit lanes of two inputs, `\a` and `\b`, storing the reduced products in `\dst` using temporary registers `\t0`, `\t1`, and `\t2`.
- **Inputs**:
    - `i`: Specifies the step number (0 through 9) of the GHASH multiplication process.
    - `a`: The first 128-bit input operand for the GHASH multiplication.
    - `b`: The second 128-bit input operand for the GHASH multiplication.
    - `dst`: The destination register where the reduced product is stored.
    - `gfpoly`: The reducing polynomial used in the GHASH multiplication.
    - `t0`: A temporary register used during the multiplication process.
    - `t1`: A temporary register used during the multiplication process.
    - `t2`: A temporary register used during the multiplication process.
- **Control Flow**:
    - If `\i` is 0, perform carryless multiplication of the low 64 bits of `\a` and `\b`, storing the result in `\t0`, and multiply the low 64 bits of `\a` with the high 64 bits of `\b`, storing in `\t1`.
    - If `\i` is 1, multiply the high 64 bits of `\a` with the low 64 bits of `\b`, storing in `\t2`.
    - If `\i` is 2, XOR `\t2` with `\t1` to consolidate the middle product.
    - If `\i` is 3, multiply the low half of `\t0` with `\gfpoly`, storing in `\t2`.
    - If `\i` is 4, swap the halves of `\t0`.
    - If `\i` is 5, use `vpternlogd` to fold `\t0` into `\t1`.
    - If `\i` is 6, multiply the high 64 bits of `\a` and `\b`, storing in `\dst`.
    - If `\i` is 7, multiply the low half of `\t1` with `\gfpoly`, storing in `\t0`.
    - If `\i` is 8, swap the halves of `\t1`.
    - If `\i` is 9, use `vpternlogd` to fold `\t1` into `\dst`.
- **Output**: The macro outputs the reduced product of the GHASH multiplication in the `\dst` register.


---
### \_ghash\_mul
The `_ghash_mul` macro performs GHASH multiplication of 128-bit lanes of two inputs, `a` and `b`, and stores the reduced products in `dst` using a series of steps that involve carryless multiplication and reduction in the finite field GF(2^128).
- **Inputs**:
    - `a`: The first 128-bit input operand for the GHASH multiplication.
    - `b`: The second 128-bit input operand for the GHASH multiplication.
    - `dst`: The destination register where the reduced product of the GHASH multiplication is stored.
    - `gfpoly`: The polynomial used for reduction in the finite field GF(2^128).
    - `t0`: A temporary register used during the multiplication and reduction process.
    - `t1`: A temporary register used during the multiplication and reduction process.
    - `t2`: A temporary register used during the multiplication and reduction process.
- **Control Flow**:
    - The macro iterates over a sequence of 10 steps using the `_ghash_mul_step` macro to perform the GHASH multiplication and reduction.
    - In steps 0 to 2, it calculates the low (LO), middle (MI), and high (HI) parts of the carryless multiplication of `a` and `b`.
    - In steps 3 to 5, it performs the first reduction by folding the LO part into the MI part using the polynomial `gfpoly`.
    - In steps 6 to 9, it performs the second reduction by folding the MI part into the HI part, resulting in the final reduced product stored in `dst`.
- **Output**: The macro outputs the reduced product of the GHASH multiplication in the `dst` register.


---
### \_ghash\_mul\_noreduce
The `_ghash_mul_noreduce` macro performs GHASH multiplication of 128-bit lanes of two inputs without reducing the result, storing the intermediate products in three separate registers.
- **Inputs**:
    - `a`: The first 128-bit input operand for the GHASH multiplication.
    - `b`: The second 128-bit input operand for the GHASH multiplication.
    - `lo`: Register to store the low part of the intermediate product.
    - `mi`: Register to store the middle part of the intermediate product.
    - `hi`: Register to store the high part of the intermediate product.
    - `t0`: Temporary register used during the computation.
    - `t1`: Temporary register used during the computation.
    - `t2`: Temporary register used during the computation.
    - `t3`: Temporary register used during the computation.
- **Control Flow**:
    - Perform carryless multiplication of the low 64 bits of `a` and `b`, storing the result in `t0`.
    - Perform carryless multiplication of the low 64 bits of `a` and the high 64 bits of `b`, storing the result in `t1`.
    - Perform carryless multiplication of the high 64 bits of `a` and the low 64 bits of `b`, storing the result in `t2`.
    - Perform carryless multiplication of the high 64 bits of `a` and `b`, storing the result in `t3`.
    - XOR the result in `t0` with `lo` and store it back in `lo`.
    - XOR the results in `t1` and `t2` using a three-argument XOR operation and store the result in `mi`.
    - XOR the result in `t3` with `hi` and store it back in `hi`.
- **Output**: The macro outputs the intermediate products of the GHASH multiplication in the `lo`, `mi`, and `hi` registers, which are not reduced to 128 bits.


---
### \_ghash\_reduce
The `_ghash_reduce` macro reduces unreduced GHASH products from 256-bit to 128-bit using a specific polynomial.
- **Inputs**:
    - `lo`: The lower 128 bits of the unreduced product.
    - `mi`: The middle 128 bits of the unreduced product.
    - `hi`: The higher 128 bits of the unreduced product.
    - `gfpoly`: The polynomial used for reduction.
    - `t0`: A temporary register used during the reduction process.
- **Control Flow**:
    - Perform a carryless multiplication of the lower 128 bits (`lo`) with the polynomial (`gfpoly`) and store the result in `t0`.
    - Shuffle the `lo` register to swap its halves.
    - XOR the result of the previous step with `mi` to fold `lo` into `mi`.
    - Perform a carryless multiplication of the updated `mi` with the polynomial (`gfpoly`) and store the result in `t0`.
    - Shuffle the `mi` register to swap its halves.
    - XOR the result of the previous step with `hi` to fold `mi` into `hi`.
- **Output**: The `hi` register contains the 128-bit reduced product.


---
### \_aes\_gcm\_precompute
The `_aes_gcm_precompute` macro initializes the GHASH subkey and precomputes powers of it for AES-GCM encryption using VAES and VPCLMULQDQ instructions on x86_64 CPUs.
- **Inputs**:
    - `KEY`: A pointer to the AES-GCM key structure, which contains the expanded AES key and will be used to store the precomputed GHASH key powers.
- **Control Flow**:
    - Set up local variables and register aliases for temporary storage and operations.
    - Load the pointer to the lowest set of key powers in the key structure.
    - Encrypt an all-zeroes block using the AES key to derive the raw GHASH subkey.
    - Reflect the bytes of the raw hash subkey and zeroize padding blocks in the key structure.
    - Preprocess the first key power (H^1) by reflecting its bytes and multiplying by x^-1 mod the GHASH polynomial.
    - Load the GHASH polynomial constant into a register for use in multiplication.
    - Square the first key power to compute the second key power (H^2).
    - Create vectors for the current and incremented key powers, filling them with H^2 and H^1.
    - Store the lowest set of key powers in the key structure.
    - Compute and store the remaining key powers by repeatedly multiplying the current powers by the incremented powers.
    - Use a loop to handle different vector lengths (VL=32 or VL=64) and store the computed powers in the key structure.
    - Zero upper bits of registers to clean up after using YMM or ZMM registers.
- **Output**: The macro outputs the precomputed GHASH key powers stored in the AES-GCM key structure, ready for use in AES-GCM encryption operations.


---
### \_horizontal\_xor
The `_horizontal_xor` macro performs a horizontal XOR operation on the 128-bit lanes of a source vector and stores the result in a destination vector, with support for both 256-bit and 512-bit vector lengths.
- **Inputs**:
    - `src`: The source vector register containing the data to be XORed.
    - `src_xmm`: The lower 128-bit lane of the source vector.
    - `dst_xmm`: The destination register where the result of the XOR operation will be stored.
    - `t0_xmm`: A temporary register used for intermediate calculations.
    - `t1_xmm`: A temporary register used for intermediate calculations, only used if VL is 64.
    - `t2_xmm`: A temporary register used for intermediate calculations, only used if VL is 64.
- **Control Flow**:
    - Extract the second 128-bit lane from the source vector into `t0_xmm`.
    - If the vector length (VL) is 32, XOR `t0_xmm` with `src_xmm` and store the result in `dst_xmm`.
    - If the vector length (VL) is 64, extract the third and fourth 128-bit lanes into `t1_xmm` and `t2_xmm`, respectively.
    - Perform a three-way XOR using `vpternlogd` on `t1_xmm`, `t2_xmm`, and the result of the XOR between `t0_xmm` and `src_xmm`, storing the final result in `dst_xmm`.
- **Output**: The result of the horizontal XOR operation is stored in the `dst_xmm` register, with all other lanes zeroized.


---
### \_ghash\_step\_4x
The `_ghash_step_4x` macro performs one step of the GHASH update for data blocks using vectorized operations on 128-bit lanes, interleaving computation to optimize performance.
- **Inputs**:
    - `i`: Specifies the step to perform, ranging from 0 to 9.
- **Control Flow**:
    - If `i == 0`, byte-reflects GHASHDATA0, XORs it with GHASH_ACC, and byte-reflects GHASHDATA1 and GHASHDATA2.
    - If `i == 1`, byte-reflects GHASHDATA3 and performs carryless multiplication to compute LO parts for GHASHDATA0 to GHASHDATA2.
    - If `i == 2`, XORs GHASHTMP0 with GHASH_ACC, computes LO_3, and sums LO parts using vpternlogd.
    - If `i == 3`, performs carryless multiplication to compute MI parts for GHASHDATA0 to GHASHDATA2 and sums MI parts using vpternlogd.
    - If `i == 4`, continues MI computation and sums MI parts, then computes MI_7.
    - If `i == 5`, sums MI parts, performs carryless multiplication for LO_L, and computes MI_7.
    - If `i == 6`, swaps halves of LO, performs carryless multiplication for HI parts for GHASHDATA0 to GHASHDATA2.
    - If `i == 7`, folds LO into MI, performs carryless multiplication for HI_3, and sums HI parts using vpternlogd.
    - If `i == 8`, XORs GHASHDATA3 with GHASHDATA0, swaps halves of MI, and folds MI into HI.
    - If `i == 9`, performs a horizontal XOR to finalize the GHASH_ACC_XMM.
- **Output**: The macro updates the GHASH_ACC_XMM with the result of the GHASH operation for the current step.


---
### \_vaesenc\_4x
The `_vaesenc_4x` macro performs one non-final round of AES encryption on four vectors of counter blocks using a specified round key.
- **Inputs**:
    - `round_key`: The AES round key that has been broadcast to all 128-bit lanes, used for the encryption of the counter blocks.
- **Control Flow**:
    - The macro applies the `vaesenc` instruction to each of the four vectors (V0, V1, V2, V3) using the provided `round_key`.
    - Each vector undergoes the AES encryption operation, which is a single round of the AES algorithm, excluding the final round.
- **Output**: The output is the four vectors (V0, V1, V2, V3) that have been encrypted with the specified round key, ready for further AES rounds or finalization.


---
### \_ctr\_begin\_4x
The `_ctr_begin_4x` macro initializes and prepares four vectors of counter blocks for AES encryption by incrementing a little-endian counter, converting it to big-endian, and XORing with the zero-th round key.
- **Inputs**:
    - `LE_CTR`: A vector register containing the current little-endian counter blocks.
    - `LE_CTR_INC`: A vector register containing the increment value for the counter blocks.
    - `BSWAP_MASK`: A shuffle mask used to convert little-endian to big-endian format.
    - `RNDKEY0`: The zero-th AES round key used for the initial XOR operation.
- **Control Flow**:
    - Increment the little-endian counter in `LE_CTR` four times, storing each incremented value back into `LE_CTR`.
    - Convert each incremented counter block from little-endian to big-endian using `BSWAP_MASK` and store the results in vector registers V0 to V3.
    - XOR each of the big-endian counter blocks in V0 to V3 with the zero-th round key `RNDKEY0`.
- **Output**: Four vectors of counter blocks prepared for AES encryption, stored in vector registers V0 to V3.


---
### \_aes\_gcm\_update
The `_aes_gcm_update` macro performs AES-GCM encryption or decryption update by processing data blocks, updating the GHASH accumulator, and handling counter increments using vectorized operations.
- **Inputs**:
    - `enc`: A flag indicating whether the operation is encryption (1) or decryption (0).
- **Control Flow**:
    - Initialize function arguments and local variables, including pointers and registers for AES key length, round keys, and GHASH data.
    - Load constants such as the byte swap mask and GHASH polynomial into vector registers.
    - Load the GHASH accumulator and starting counter from memory.
    - Determine the AES key length and set the pointer to the last AES round key.
    - Initialize the counter increment vector based on the vector length (VL).
    - Check if the data length is sufficient for processing in blocks of 4*VL bytes, and if so, enter the main loop for processing these blocks.
    - In the main loop, interleave AES encryption of counter blocks with GHASH updates of ciphertext blocks to optimize performance.
    - For encryption, encrypt the first set of plaintext blocks and store the resulting ciphertext for GHASH processing.
    - Cache additional AES round keys for use in the main loop.
    - Process data in blocks of 4*VL bytes, updating the GHASH accumulator and storing encrypted or decrypted data to the destination buffer.
    - If the data length is not a multiple of 4*VL, process the remaining data in smaller blocks, handling masking for the last iteration if necessary.
    - Perform a final GHASH reduction and store the updated GHASH accumulator back to memory.
    - Return from the macro.
- **Output**: The macro outputs the updated GHASH accumulator and the encrypted or decrypted data written to the destination buffer.


---
### \_aes\_gcm\_final
The `_aes_gcm_final` macro finalizes the AES-GCM encryption or decryption process by updating the GHASH with the lengths block, encrypting the GHASH accumulator, and either storing the computed authentication tag or verifying it against a provided tag.
- **Inputs**:
    - `enc`: A flag indicating whether the function is for encryption (1) or decryption (0).
- **Control Flow**:
    - Load constants for GF(2^128) polynomial and byte swap mask.
    - Load AES key length and set up counter block for authentication tag encryption.
    - Build lengths block from total AAD and data lengths, convert to bits, and XOR with GHASH accumulator.
    - Load first hash key power (H^1) for GHASH multiplication.
    - For decryption, prepare a mask of TAGLEN one bits for constant-time comparison.
    - Set pointer to last AES round key based on key length.
    - Start AES encryption of counter block, interleaving with GHASH multiplication for performance.
    - Complete AES encryption and multiply GHASH_ACC by H^1, interleaving operations.
    - Undo byte reflection of GHASH accumulator and perform last AES round.
    - For encryption, store computed authentication tag; for decryption, compare computed and transmitted tags in constant time.
- **Output**: For encryption, the computed authentication tag is stored in `ghash_acc`; for decryption, a boolean is returned indicating whether the computed tag matches the provided tag.


