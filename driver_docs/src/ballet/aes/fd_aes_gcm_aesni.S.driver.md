# Purpose
This assembly source code file implements an optimized version of the AES-GCM (Galois/Counter Mode) cryptographic algorithm for x86_64 CPUs that support AES-NI (Advanced Encryption Standard New Instructions). The file provides two implementations: one utilizing AVX (Advanced Vector Extensions) and another without it. The primary purpose of this code is to enhance the performance of AES-GCM operations by leveraging specific CPU instructions that accelerate encryption and decryption processes. The code is structured to handle both encryption and decryption, as well as the computation of authentication tags, which are crucial for ensuring data integrity and authenticity in secure communications.

The technical components of this file include macros for various cryptographic operations, such as AES encryption rounds, GHASH multiplication, and handling of partial data blocks. The code is designed to efficiently manage CPU registers and memory operations, using techniques like Karatsuba multiplication to optimize GHASH computations. The file also includes mechanisms to handle different data lengths and ensure that operations are performed in a constant-time manner to prevent timing attacks. The use of macros allows for code reuse and reduces redundancy, making the implementation both efficient and maintainable.

Overall, this file is a specialized collection of cryptographic functions focused on providing high-performance AES-GCM operations on x86_64 architectures. It is designed to be used in environments where secure and efficient data encryption and authentication are required, such as in network security protocols and secure data storage solutions. The dual-licensed nature of the file under Apache License 2.0 and BSD-2-Clause allows for flexible integration into various projects, ensuring broad applicability and compliance with open-source licensing standards.
# Subroutines

---
### aes\_gcm\_precompute\_aesni
The `aes_gcm_precompute_aesni` function derives the GHASH subkey and initializes the GHASH-related fields in the AES-GCM key structure using AES-NI instructions.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_aesni` structure which contains the expanded AES key and will be updated with GHASH-related fields.
- **Control Flow**:
    - The function begins by setting up the necessary registers and pointers for the AES key and GHASH subkey calculations.
    - It encrypts an all-zero block using the AES key to derive the raw GHASH subkey, processing it to operate on GHASH's bit-reflected values directly.
    - The function reflects the bytes of the raw hash subkey, multiplies it by x^-1, and stores the result as H^1 in the key structure.
    - It computes H^1 * x^64 and stores it in the key structure.
    - The function computes and stores the halves of H^1 XOR'd together in the key structure.
    - It iteratively computes and stores the remaining key powers H^2 through H^8 and their XOR'd halves in the key structure.
    - The function concludes by returning control to the caller.
- **Output**: The function updates the `aes_gcm_key_aesni` structure with the derived GHASH subkey and precomputed GHASH-related fields.


---
### aes\_gcm\_aad\_update\_aesni
The `aes_gcm_aad_update_aesni` function updates the GHASH accumulator with additional authenticated data (AAD) using AES-GCM with AES-NI instructions.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_aesni` structure containing the precomputed GHASH key powers.
    - `ghash_acc`: A 16-byte array representing the current state of the GHASH accumulator, which should be all zeroes on the first call.
    - `aad`: A pointer to the additional authenticated data to be processed.
    - `aadlen`: An integer representing the length of the AAD, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load the byte swap mask and the GHASH accumulator from memory.
    - Load the precomputed GHASH key powers H^1 and H^1 * x^64 from the key structure.
    - Iterate over the AAD in 16-byte blocks, byte-reflect each block, XOR it with the GHASH accumulator, and perform a GHASH multiplication using the precomputed key powers.
    - If there is a partial block at the end, load and zero-pad it, then perform the GHASH multiplication.
    - Store the updated GHASH accumulator back to memory.
- **Output**: The function updates the GHASH accumulator with the processed AAD, modifying the `ghash_acc` array in place.


---
### aes\_gcm\_enc\_update\_aesni
The `aes_gcm_enc_update_aesni` function performs AES-GCM encryption by computing the CTR keystream, XORing it with input data, and updating the GHASH accumulator with the ciphertext.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_aesni` structure containing the AES key and precomputed GHASH subkeys.
    - `le_ctr`: A pointer to a 4-element array of 32-bit integers representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer holding the current GHASH accumulator value.
    - `src`: A pointer to the source data buffer to be encrypted.
    - `dst`: A pointer to the destination buffer where the encrypted data will be stored.
    - `datalen`: An integer representing the length of the data to be processed, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load the AES key length and the last round key pointer from the `key` structure.
    - Initialize the byte swap mask and load the GHASH accumulator and counter values from memory.
    - Check if the data length is sufficient for processing in blocks of 8*16 bytes; if so, enter the main loop.
    - In the main loop, generate 8 counter blocks, perform AES encryption rounds, and update the GHASH accumulator using Karatsuba multiplication.
    - If encrypting, XOR the plaintext with the keystream and store the result in the destination buffer.
    - Continue processing in blocks of 8*16 bytes until the remaining data length is less than 8*16 bytes.
    - For the remaining data, process one block at a time, updating the GHASH accumulator and performing AES encryption.
    - If there is a partial block, handle it separately by loading, zero-padding, and processing it.
    - Finally, reduce the GHASH accumulator and store the updated value back to memory.
- **Output**: The function outputs the encrypted data in the `dst` buffer and updates the `ghash_acc` with the new GHASH value.


---
### aes\_gcm\_dec\_update\_aesni
The `aes_gcm_dec_update_aesni` function performs AES-GCM decryption by computing the CTR keystream, XORing it with the input data, and updating the GHASH accumulator with the decrypted data.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing precomputed values for decryption.
    - `le_ctr`: A pointer to a 4-element array representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer holding the current GHASH accumulator value.
    - `src`: A pointer to the source data buffer containing the ciphertext to be decrypted.
    - `dst`: A pointer to the destination buffer where the decrypted data will be stored.
    - `datalen`: An integer representing the length of the data to be processed, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load the GHASH accumulator and counter values from memory.
    - Check if the data length is sufficient for processing in blocks of 8*16 bytes.
    - If encrypting, generate the first set of 8 counter blocks and encrypt the first 8 plaintext blocks.
    - Enter the main loop to process data in blocks of 8*16 bytes, interleaving AES encryption and GHASH updates.
    - For each block, generate the next set of counter blocks, perform AES encryption, and update the GHASH accumulator.
    - If encrypting, handle the last set of 8 ciphertext blocks separately to update the GHASH accumulator.
    - If there is remaining data less than 8*16 bytes, process it one block at a time, updating the GHASH accumulator as needed.
    - If there is a partial block at the end, process it separately, ensuring proper zero-padding for GHASH.
    - Perform the final GHASH reduction and store the updated GHASH accumulator back to memory.
- **Output**: The function updates the destination buffer with decrypted data and modifies the GHASH accumulator in place.


---
### aes\_gcm\_enc\_final\_aesni
The `aes_gcm_enc_final_aesni` function finalizes the AES-GCM encryption process by computing the authentication tag using the GHASH accumulator and the total lengths of the additional authenticated data and encrypted data.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing precomputed values for encryption.
    - `le_ctr`: A pointer to a 4-element array representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer holding the current GHASH accumulator value.
    - `total_aadlen`: A 64-bit integer representing the total length of the additional authenticated data in bytes.
    - `total_datalen`: A 64-bit integer representing the total length of the encrypted data in bytes.
- **Control Flow**:
    - Load the byte swap mask and AES key length from the key structure.
    - Set up a counter block with 1 in the low 32-bit word to produce the ciphertext needed to encrypt the authentication tag.
    - Build the lengths block using total_aadlen and total_datalen, convert them to bits, and XOR it into the GHASH accumulator.
    - Load the precomputed hash key powers and perform GHASH multiplication to update the GHASH accumulator with the lengths block.
    - Encrypt the counter block using the AES key schedule to produce the final keystream block.
    - XOR the final keystream block with the GHASH accumulator to produce the authentication tag.
    - Store the computed authentication tag back to the ghash_acc buffer.
- **Output**: The function outputs the computed 16-byte authentication tag, which is stored in the ghash_acc buffer.


---
### aes\_gcm\_dec\_final\_aesni
The `aes_gcm_dec_final_aesni` function finalizes the decryption process in AES-GCM mode by computing and verifying the authentication tag against the expected tag.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing precomputed values for decryption.
    - `le_ctr`: A pointer to a 4-element array representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer containing the current GHASH accumulator state.
    - `total_aadlen`: The total length of the additional authenticated data in bytes.
    - `total_datalen`: The total length of the decrypted data in bytes.
    - `tag`: A pointer to a 16-byte buffer containing the expected authentication tag.
    - `taglen`: The length of the tag to be verified, between 4 and 16 bytes.
- **Control Flow**:
    - Load the byte swap mask and AES key length from the key structure.
    - Set up a counter block with 1 in the low 32-bit word for tag encryption.
    - Build the lengths block from total AAD and data lengths, convert to bits, and XOR with the GHASH accumulator.
    - Load precomputed hash key powers and perform AES encryption on the counter block while updating GHASH with the lengths block.
    - Undo byte reflection on the GHASH accumulator and encrypt it to produce the computed authentication tag.
    - XOR the computed tag with the expected tag and verify the first taglen bytes in constant time using ptest.
    - Return true if the tags match, otherwise false.
- **Output**: Returns a boolean indicating whether the computed authentication tag matches the expected tag.


---
### aes\_gcm\_precompute\_aesni\_avx
The `aes_gcm_precompute_aesni_avx` function precomputes the GHASH subkey and initializes related fields in the AES-GCM key structure using AES-NI and AVX instructions.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_aesni` structure which contains the expanded AES key and will be updated with precomputed GHASH values.
- **Control Flow**:
    - The function begins by setting up the necessary registers and pointers for the AES key and GHASH subkey calculations.
    - It encrypts an all-zero block using the AES key to derive the raw GHASH subkey.
    - The raw GHASH subkey is byte-reflected and multiplied by x^-1 to prepare it for GHASH operations.
    - The precomputed GHASH subkey (H^1) is stored in the key structure.
    - The function computes H^1 * x^64 and stores it in the key structure.
    - It computes and stores the XOR of the halves of H^1 in the key structure.
    - The function iteratively computes and stores the powers of the GHASH subkey (H^2 to H^8) and their XOR'd halves in the key structure.
    - The function concludes by returning control to the caller.
- **Output**: The function updates the `aes_gcm_key_aesni` structure with precomputed GHASH subkey values and related fields for efficient AES-GCM operations.


---
### aes\_gcm\_aad\_update\_aesni\_avx
The `aes_gcm_aad_update_aesni_avx` function processes Additional Authenticated Data (AAD) in GCM mode, updating the GHASH accumulator using AES-NI and AVX instructions.
- **Inputs**:
    - `key`: A pointer to the `aes_gcm_key_aesni` structure containing the precomputed GHASH key powers and other necessary AES key information.
    - `ghash_acc`: A 16-byte buffer representing the current state of the GHASH accumulator, which must be all zeroes on the first call.
    - `aad`: A pointer to the Additional Authenticated Data (AAD) to be processed.
    - `aadlen`: An integer representing the length of the AAD in bytes, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load the byte-swap mask and the current GHASH accumulator state from memory.
    - Load the precomputed hash key powers H^1 and H^1 * x^64 from the key structure.
    - Iterate over the AAD in 16-byte blocks, byte-reflecting each block and XORing it with the GHASH accumulator.
    - Perform GHASH multiplication using the precomputed hash key powers and update the GHASH accumulator.
    - If there is a partial block at the end, load and process it similarly, ensuring zero-padding for the remaining bytes.
    - Store the updated GHASH accumulator back to memory.
- **Output**: The function updates the GHASH accumulator with the processed AAD, storing the result back in the provided `ghash_acc` buffer.


---
### aes\_gcm\_enc\_update\_aesni\_avx
The `aes_gcm_enc_update_aesni_avx` function performs AES-GCM encryption using AES-NI and AVX instructions, updating the GHASH accumulator and processing data in blocks.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing precomputed values for encryption.
    - `le_ctr`: A pointer to a 4-element array representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer holding the current GHASH accumulator value.
    - `src`: A pointer to the source data to be encrypted.
    - `dst`: A pointer to the destination buffer where the encrypted data will be stored.
    - `datalen`: An integer representing the length of the data to be processed, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Initialize local variables and load the GHASH accumulator and counter values.
    - Check if the data length is sufficient for processing in 8-block chunks; if so, enter the main loop.
    - In the main loop, generate counter blocks, perform AES encryption, and update the GHASH accumulator using Karatsuba multiplication for efficiency.
    - If encrypting, XOR the plaintext with the keystream to produce ciphertext; if decrypting, XOR the ciphertext with the keystream to recover plaintext.
    - Handle any remaining data that does not fit into 8-block chunks by processing one block at a time, updating the GHASH accumulator as needed.
    - Perform a final GHASH reduction to ensure the accumulator is correctly updated.
    - Store the updated GHASH accumulator back to memory.
- **Output**: The function outputs the encrypted data in the destination buffer and updates the GHASH accumulator in place.


---
### aes\_gcm\_dec\_update\_aesni\_avx
The `aes_gcm_dec_update_aesni_avx` function performs AES-GCM decryption using AES-NI and AVX instructions, updating the GHASH accumulator with the decrypted data.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing precomputed values for decryption.
    - `le_ctr`: A pointer to a 4-element array representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer holding the current GHASH accumulator value.
    - `src`: A pointer to the source data buffer containing the ciphertext to be decrypted.
    - `dst`: A pointer to the destination buffer where the decrypted data will be stored.
    - `datalen`: An integer representing the length of the data to be processed, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load the GHASH accumulator and counter values from memory.
    - Check if the data length is sufficient for processing in blocks of 8*16 bytes; if so, enter the main loop.
    - In the main loop, generate 8 counter blocks, perform AES encryption on them, and XOR with the source data to produce decrypted data.
    - Update the GHASH accumulator with the decrypted data using Karatsuba multiplication for efficiency.
    - If the data length is less than 8*16 bytes, process the remaining data one block at a time, updating the GHASH accumulator accordingly.
    - Handle any partial block at the end by zero-padding and updating the GHASH accumulator.
    - Store the updated GHASH accumulator back to memory.
- **Output**: The function updates the GHASH accumulator with the decrypted data and writes the decrypted output to the destination buffer.


---
### aes\_gcm\_enc\_final\_aesni\_avx
The `aes_gcm_enc_final_aesni_avx` function finalizes the AES-GCM encryption process by computing the authentication tag using the GHASH accumulator and the total lengths of the additional authenticated data and encrypted data.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing the expanded AES key and precomputed GHASH subkeys.
    - `le_ctr`: A pointer to a 4-element array representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer containing the current GHASH accumulator value.
    - `total_aadlen`: The total length of the additional authenticated data in bytes.
    - `total_datalen`: The total length of the encrypted data in bytes.
- **Control Flow**:
    - Load the byte swap mask and AES key length from the key structure.
    - Set up a counter block with 1 in the low 32-bit word to produce the ciphertext needed to encrypt the authentication tag.
    - Build the lengths block using the total AAD and data lengths, convert them to bits, and XOR it into the GHASH accumulator.
    - Load the precomputed GHASH subkeys H^1 and H^1 * x^64 from the key structure.
    - Perform AES encryption on the counter block while interleaving GHASH multiplication steps to improve performance.
    - Undo the byte reflection of the GHASH accumulator and encrypt it to produce the final authentication tag.
    - Store the computed authentication tag back to the GHASH accumulator buffer.
- **Output**: The function outputs the computed 16-byte authentication tag, which is stored in the `ghash_acc` buffer.


---
### aes\_gcm\_dec\_final\_aesni\_avx
The `aes_gcm_dec_final_aesni_avx` function finalizes the AES-GCM decryption process by computing and verifying the authentication tag using AES-NI and AVX instructions.
- **Inputs**:
    - `key`: A pointer to the AES-GCM key structure containing precomputed values for decryption.
    - `le_ctr`: A pointer to a 4-element array representing the current counter in little-endian format.
    - `ghash_acc`: A pointer to a 16-byte buffer containing the current GHASH accumulator state.
    - `total_aadlen`: The total length of the additional authenticated data in bytes.
    - `total_datalen`: The total length of the decrypted data in bytes.
    - `tag`: A pointer to a 16-byte buffer containing the expected authentication tag.
    - `taglen`: The length of the tag to verify, between 4 and 16 bytes.
- **Control Flow**:
    - Load the byte swap mask and AES key length from the key structure.
    - Set up a counter block with 1 in the low 32-bit word to produce the ciphertext needed for the authentication tag.
    - Build the lengths block from `total_aadlen` and `total_datalen`, convert them to bits, and XOR with the GHASH accumulator.
    - Load the precomputed hash key powers and perform GHASH multiplication to update the GHASH accumulator.
    - Encrypt the counter block using AES to produce the keystream block for the authentication tag.
    - XOR the keystream block with the GHASH accumulator to produce the computed authentication tag.
    - Load the expected tag and compare it with the computed tag in constant time using the `ptest` instruction.
    - Return true if the tags match, otherwise return false.
- **Output**: Returns a boolean value indicating whether the computed authentication tag matches the expected tag.


# Macros

---
### \_vpclmulqdq
The `_vpclmulqdq` macro performs a carry-less multiplication of two 64-bit operands using the `vpclmulqdq` instruction if AVX is available, otherwise it falls back to using `movdqa` and `pclmulqdq` instructions.
- **Inputs**:
    - `imm`: An immediate value specifying the control byte for the carry-less multiplication.
    - `src1`: The first source operand, which is an xmm register.
    - `src2`: The second source operand, which is an xmm register.
    - `dst`: The destination operand, which is an xmm register where the result is stored.
- **Control Flow**:
    - Check if AVX is enabled using the `USE_AVX` flag.
    - If AVX is enabled, execute the `vpclmulqdq` instruction with the given immediate, source operands, and destination.
    - If AVX is not enabled, move the second source operand to the destination using `movdqa`.
    - Perform the carry-less multiplication using `pclmulqdq` with the given immediate and the first source operand, storing the result in the destination.
- **Output**: The result of the carry-less multiplication is stored in the `dst` xmm register.


---
### \_vpshufb
The `_vpshufb` macro performs a byte-wise shuffle of a source register using a shuffle mask, utilizing AVX instructions if available, or falling back to SSE instructions if not.
- **Inputs**:
    - `src1`: The source register containing the data to be shuffled.
    - `src2`: The register containing the shuffle mask.
    - `dst`: The destination register where the shuffled result will be stored.
- **Control Flow**:
    - Check if AVX is enabled using the `USE_AVX` flag.
    - If AVX is enabled, execute the `vpshufb` instruction with `src1`, `src2`, and `dst`.
    - If AVX is not enabled, move `src2` to `dst` using `movdqa`, then execute `pshufb` with `src1` and `dst`.
- **Output**: The output is the `dst` register containing the shuffled bytes from `src1` according to the mask in `src2`.


---
### \_vpand
The `_vpand` macro performs a bitwise AND operation between two source operands and stores the result in a destination operand, using AVX instructions if available, or falling back to SSE instructions otherwise.
- **Inputs**:
    - `src1`: The first source operand for the AND operation.
    - `src2`: The second source operand for the AND operation.
    - `dst`: The destination operand where the result of the AND operation is stored.
- **Control Flow**:
    - Check if AVX is enabled using the `USE_AVX` flag.
    - If AVX is enabled, execute the `vpand` instruction with `src1`, `src2`, and `dst`.
    - If AVX is not enabled, move `src1` to `dst` using `movdqu`, then perform the `pand` instruction with `src2` and `dst`.
- **Output**: The result of the bitwise AND operation is stored in the `dst` operand.


---
### \_xor\_mem\_to\_reg
The `_xor_mem_to_reg` macro performs an XOR operation between an unaligned memory operand and an xmm register, using a temporary xmm register if AVX is not available.
- **Inputs**:
    - `mem`: The unaligned memory operand to be XORed with the xmm register.
    - `reg`: The xmm register that will be XORed with the memory operand.
    - `tmp`: A temporary xmm register used when AVX is not available.
- **Control Flow**:
    - Check if AVX is available using the `USE_AVX` flag.
    - If AVX is available, perform the XOR operation directly between the memory operand and the xmm register using `vpxor`.
    - If AVX is not available, load the memory operand into the temporary xmm register using `movdqu`.
    - Perform the XOR operation between the temporary xmm register and the xmm register using `pxor`.
- **Output**: The xmm register `reg` is updated with the result of the XOR operation with the memory operand.


---
### \_test\_mem
The `_test_mem` macro tests an unaligned memory operand against an xmm register, using AVX instructions if available, or falling back to SSE instructions otherwise.
- **Inputs**:
    - `mem`: The unaligned memory operand to be tested against the xmm register.
    - `reg`: The xmm register against which the memory operand is tested.
    - `tmp`: A temporary xmm register used in the fallback path when AVX is not available.
- **Control Flow**:
    - Check if AVX is available using the `USE_AVX` flag.
    - If AVX is available, use the `vptest` instruction to test the memory operand against the xmm register.
    - If AVX is not available, move the memory operand into the temporary xmm register using `movdqu`, then use the `ptest` instruction to test the temporary register against the xmm register.
- **Output**: The result of the test is not directly output by the macro, but the status flags are set based on the comparison, which can be used for conditional branching in subsequent instructions.


---
### \_load\_partial\_block
The `_load_partial_block` macro loads a specified number of bytes (1 to 15) from a source pointer into an xmm register, zeroing out any remaining bytes.
- **Inputs**:
    - `src`: The pointer to the source memory location from which bytes are to be loaded.
    - `dst`: The xmm register where the loaded bytes will be stored.
    - `tmp64`: A temporary 64-bit register used for intermediate calculations.
    - `tmp32`: A temporary 32-bit register used for intermediate calculations.
- **Control Flow**:
    - Subtract 8 from %ecx to determine if the length is greater than 8.
    - If length is greater than 8, load the first 8 bytes into `dst` and the last 8 bytes into %rax, then adjust %rax to discard overlapping bytes and insert it into `dst`.
    - If length is between 4 and 8, load the first 4 bytes into %eax and the last 4 bytes into `tmp32`, then combine them into %rax and move to `dst`.
    - If length is between 1 and 3, load the first byte into %eax and the last 2 bytes into `tmp32`, then combine them into %rax and move to `dst`.
    - Zeroize any remaining bytes in the xmm register.
- **Output**: The xmm register `dst` contains the loaded bytes from the source, with any remaining bytes zeroed out.


---
### \_store\_partial\_block
The `_store_partial_block` macro stores a specified number of bytes from an XMM register to a memory location, handling cases where the number of bytes is less than a full block.
- **Inputs**:
    - `src`: The XMM register containing the data to be stored.
    - `dst`: The memory location where the data will be stored.
- **Control Flow**:
    - Subtract 8 from ECX to determine if the length is less than 8 bytes.
    - If length is 8 or more, store the last LEN - 8 bytes and the first 8 bytes separately.
    - If length is less than 8, adjust ECX to determine if it is less than 4 bytes.
    - For lengths between 4 and 7, store the last LEN - 4 bytes and the first 4 bytes separately.
    - For lengths between 1 and 3, store each byte individually.
- **Output**: The specified number of bytes from the XMM register are stored in the memory location pointed to by `dst`, with any remaining bytes in the block being ignored.


---
### \_ghash\_mul\_step
The `_ghash_mul_step` macro performs one step of the GHASH multiplication by combining parts of two inputs, `a` and `b`, using polynomial multiplication and reduction with a Galois field polynomial.
- **Inputs**:
    - `i`: The step index, ranging from 0 to 9, indicating which part of the multiplication and reduction process to execute.
    - `a`: The first input operand for the GHASH multiplication, representing a polynomial.
    - `a_times_x64`: The precomputed value of `a` multiplied by x^64, used in the multiplication process.
    - `b`: The second input operand for the GHASH multiplication, representing a polynomial.
    - `gfpoly`: The Galois field polynomial used for reduction in the multiplication process.
    - `t0`: A temporary register used for intermediate calculations.
    - `t1`: Another temporary register used for intermediate calculations.
- **Control Flow**:
    - If `i` is 0, perform a polynomial multiplication of the lower halves of `a` and `b` and store the result in `t0`.
    - If `i` is 1, perform a polynomial multiplication of the lower half of `a_times_x64` and `b` and store the result in `t1`.
    - If `i` is 2, XOR `t1` into `t0` to combine the results of the previous steps.
    - If `i` is 3, perform a polynomial multiplication of the upper halves of `a` and `b` and store the result in `t1`.
    - If `i` is 4, perform a polynomial multiplication of the upper half of `a_times_x64` and `b` and store the result in `b`.
    - If `i` is 5, XOR `t1` into `b` to combine the results of the previous steps.
    - If `i` is 6, shuffle the halves of `t0` and store the result in `t1`.
    - If `i` is 7, perform a polynomial multiplication of the lower half of `gfpoly` and `t0` and store the result in `t0`.
    - If `i` is 8, XOR `t1` into `b` to combine the results of the previous steps.
    - If `i` is 9, XOR `t0` into `b` to finalize the result.
- **Output**: The macro modifies the `b` register to contain the reduced product of the GHASH multiplication step.


---
### \_ghash\_mul
The `_ghash_mul` macro performs a GHASH multiplication of two operands, `a` and `b`, using Karatsuba multiplication and stores the reduced product in `b`.
- **Inputs**:
    - `a`: The first operand for the GHASH multiplication.
    - `a_times_x64`: The precomputed value of `a` multiplied by x^64, used in the multiplication process.
    - `b`: The second operand for the GHASH multiplication, which will also store the result.
    - `gfpoly`: The polynomial used for reduction in the GHASH multiplication.
    - `t0`: A temporary register used during the multiplication process.
    - `t1`: Another temporary register used during the multiplication process.
- **Control Flow**:
    - The macro iterates over a sequence of steps (0 to 9) to perform the GHASH multiplication using Karatsuba method.
    - In step 0, it calculates the middle intermediate (MI) by multiplying the lower half of `a` with the higher half of `b`.
    - In step 1, it calculates another part of MI by multiplying the lower half of `a_times_x64` with the lower half of `b`.
    - In step 2, it combines the results of the previous two steps using XOR to complete the MI calculation.
    - In steps 3 to 5, it calculates the higher intermediate (HI) by multiplying the higher halves of `a` and `b`, and another part using `a_times_x64`.
    - In steps 6 to 9, it folds MI into HI using polynomial reduction with `gfpoly`, completing the GHASH multiplication.
- **Output**: The reduced product of the GHASH multiplication is stored in the `b` operand.


---
### \_ghash\_mul\_noreduce
The `_ghash_mul_noreduce` macro performs a GHASH multiplication using Karatsuba multiplication without reducing the result, storing the intermediate results in three separate registers.
- **Inputs**:
    - `a`: The first operand for the GHASH multiplication.
    - `a_xored`: The two halves of 'a' XOR'd together, i.e., a_L + a_H.
    - `b`: The second operand for the GHASH multiplication, which is clobbered during the operation.
    - `lo`: Register to accumulate the low part of the unreduced product, initially zero.
    - `mi`: Register to accumulate the middle part of the unreduced product, initially zero.
    - `hi`: Register to accumulate the high part of the unreduced product, initially zero.
    - `t0`: A temporary register used during the multiplication process.
- **Control Flow**:
    - Perform the low part of the multiplication by multiplying the low halves of 'a' and 'b' and XOR the result into 'lo'.
    - Calculate the sum of the low and high halves of 'b' and store it in 't0'.
    - Perform the high part of the multiplication by multiplying the high halves of 'a' and 'b' and XOR the result into 'hi'.
    - Perform the middle part of the multiplication by multiplying the XOR of the halves of 'a' and the sum of the halves of 'b', then XOR the result into 'mi'.
- **Output**: The macro does not produce a final reduced output; instead, it accumulates the intermediate results in the 'lo', 'mi', and 'hi' registers for later reduction.


---
### \_ghash\_reduce
The `_ghash_reduce` macro reduces the product of a GHASH multiplication from three parts (low, middle, and high) into a single result stored in a destination register.
- **Inputs**:
    - `lo`: The low part of the unreduced product from a GHASH multiplication.
    - `mi`: The middle part of the unreduced product from a GHASH multiplication.
    - `hi`: The high part of the unreduced product from a GHASH multiplication.
    - `dst`: The destination register where the reduced product will be stored.
    - `t0`: A temporary register used during the reduction process.
- **Control Flow**:
    - Load the Galois field polynomial constant into the temporary register `t0`.
    - XOR the low part `lo` and the high part `hi` into the middle part `mi`.
    - Shuffle the low part `lo` and XOR it into the middle part `mi`.
    - Multiply the shuffled low part `lo` by the Galois field polynomial and XOR the result into the middle part `mi`.
    - Shuffle the middle part `mi` and XOR it into the high part `hi`.
    - Multiply the shuffled middle part `mi` by the Galois field polynomial and XOR the result into the high part `hi`.
    - Store the final reduced result in the destination register `dst`.
- **Output**: The output is the reduced GHASH product stored in the destination register `dst`.


---
### \_ghash\_update\_begin\_8x
The `_ghash_update_begin_8x` macro initializes the GHASH update process for a set of 8 ciphertext blocks by performing the first step of unreduced multiplication and setting up necessary registers.
- **Inputs**:
    - `enc`: A flag indicating whether the operation is encryption (1) or decryption (0).
- **Control Flow**:
    - Initialize the inner block counter by zeroing the EAX register.
    - Load the highest hash key power, H^8, into the TMP0 register.
    - Load the first ciphertext block into TMP1, using DST if encrypting or SRC if decrypting, and byte-reflect it using the BSWAP_MASK.
    - Add the GHASH accumulator to the ciphertext block to form the block 'b' for multiplication with the hash key power 'a'.
    - Compute b_L + b_H and store the result in MI.
    - Perform the Karatsuba multiplication step: calculate LO as a_L * b_L, HI as a_H * b_H, and MI as (a_L + a_H) * (b_L + b_H) using the precomputed XOR'd halves of the hash key powers.
- **Output**: The macro sets up the registers LO, MI, and GHASH_ACC (HI) with the initial unreduced product of the first ciphertext block and the highest hash key power, ready for further processing in the GHASH update.


---
### \_ghash\_update\_continue\_8x
The `_ghash_update_continue_8x` macro continues the GHASH update process for a set of 8 ciphertext blocks by performing an unreduced multiplication of the next ciphertext block with the next lowest key power and accumulating the result into intermediate registers.
- **Inputs**:
    - `enc`: A flag indicating whether the operation is encryption (1) or decryption (0).
- **Control Flow**:
    - Increment the inner block counter by 8.
    - Load the next lowest key power from the key structure using the updated counter.
    - Load the next ciphertext block from either the source or destination, depending on the encryption flag, and byte-reflect it using a shuffle mask.
    - Perform a polynomial multiplication of the lower halves of the key power and ciphertext block, accumulate the result into the low part of the product.
    - Compute the sum of the lower and higher halves of the ciphertext block, store it in a temporary register.
    - Perform a polynomial multiplication of the higher halves of the key power and ciphertext block, accumulate the result into the high part of the product.
    - Perform a polynomial multiplication of the XOR of the halves of the key power and the sum of the halves of the ciphertext block, accumulate the result into the middle part of the product.
- **Output**: The macro updates the intermediate registers `LO`, `MI`, and `GHASH_ACC` (also known as `HI`) with the results of the polynomial multiplications, which are used in the GHASH calculation.


---
### \_ghash\_update\_end\_8x\_step
The `_ghash_update_end_8x_step` macro performs the final reduction step in the GHASH update process for a set of 8 ciphertext blocks, using Karatsuba multiplication to optimize the reduction of intermediate GHASH values.
- **Inputs**:
    - `i`: An iteration index that determines which part of the reduction process to execute.
- **Control Flow**:
    - If `i` is 0, load the polynomial constant into TMP1, XOR LO with MI, and XOR GHASH_ACC with MI.
    - Shuffle LO and store the result in TMP2, perform a polynomial multiplication of LO with TMP1, and XOR TMP2 with MI.
    - XOR the result of the polynomial multiplication with MI.
    - If `i` is 1, shuffle MI and store the result in TMP2, perform a polynomial multiplication of MI with TMP1, and XOR TMP2 with GHASH_ACC.
    - XOR the result of the polynomial multiplication with GHASH_ACC.
- **Output**: The macro updates the GHASH_ACC register with the reduced GHASH value after processing 8 blocks.


---
### \_aes\_gcm\_precompute
The `_aes_gcm_precompute` macro initializes the GHASH subkey and related fields in the AES-GCM key structure by encrypting an all-zero block with the AES key and precomputing necessary values for GHASH operations.
- **Inputs**:
    - `KEY`: A pointer to the `aes_gcm_key_aesni` structure, which contains the expanded AES key and where the GHASH-related fields will be initialized.
- **Control Flow**:
    - Load the AES key length from the key structure and calculate the pointer to the last round key.
    - Encrypt an all-zero block using the AES key to derive the raw GHASH subkey.
    - Reflect the bytes of the raw hash subkey and multiply it by x^1 to preprocess it for GHASH operations.
    - Store the preprocessed hash subkey as H^1 in the key structure.
    - Compute and store H^1 * x^64 and the XOR of the halves of H^1 in the key structure.
    - Iteratively compute and store the powers H^2 through H^8 and their XOR'd halves in the key structure using the `_ghash_mul` macro.
    - Return from the macro.
- **Output**: The macro outputs the precomputed GHASH subkey and related fields stored in the `aes_gcm_key_aesni` structure, ready for use in AES-GCM operations.


---
### \_aes\_gcm\_aad\_update
The `_aes_gcm_aad_update` macro processes Additional Authenticated Data (AAD) in GCM mode by updating the GHASH accumulator using the provided key, AAD, and its length.
- **Inputs**:
    - `KEY`: A pointer to the AES-GCM key structure containing precomputed hash key powers.
    - `GHASH_ACC_PTR`: A pointer to the GHASH accumulator, which must be all zeroes on the first call.
    - `AAD`: A pointer to the Additional Authenticated Data to be processed.
    - `AADLEN`: The length of the AAD, which must be a multiple of 16 except on the last call.
- **Control Flow**:
    - Load the byte swap mask and the GHASH accumulator from memory.
    - Load the precomputed hash key powers H^1 and H^1 * x^64 from the key structure.
    - Process the AAD in blocks of 16 bytes, updating the GHASH accumulator with each block using the GHASH multiplication macro.
    - If there is a partial block at the end, load and process it, updating the GHASH accumulator accordingly.
    - Store the updated GHASH accumulator back to memory.
- **Output**: The updated GHASH accumulator is stored back to the memory location pointed to by `GHASH_ACC_PTR`.


---
### \_ctr\_begin\_8x
The `_ctr_begin_8x` macro initializes and processes eight AES counter blocks for encryption or decryption by incrementing a counter, converting it to big-endian, and XORing it with the AES round key.
- **Inputs**:
    - `LE_CTR`: A little-endian counter value used to generate counter blocks.
    - `KEY`: The zero-th AES round key used for XORing with the counter blocks.
    - `AESDATA0 to AESDATA7`: Registers to store the processed counter blocks.
    - `TMP0`: A temporary register used for incrementing the counter.
    - `TMP1`: A temporary register used for storing the zero-th AES round key.
- **Control Flow**:
    - Load the constant value 1 into TMP0 for incrementing the counter.
    - Load the zero-th AES round key into TMP1.
    - Iterate over 8 blocks (0 to 7) to process each counter block.
    - For each block, shuffle the bytes of LE_CTR to convert it to big-endian and store the result in AESDATA[i].
    - XOR the big-endian counter block with TMP1 (the zero-th AES round key).
    - Increment the LE_CTR by 1 using paddd with TMP0.
- **Output**: The output is eight processed AES counter blocks stored in AESDATA0 to AESDATA7, ready for further AES encryption rounds.


---
### \_aesenc\_8x
The `_aesenc_8x` macro performs a non-final AES encryption round on eight blocks of data simultaneously using a specified round key.
- **Inputs**:
    - `round_key`: The AES round key used for the encryption round.
- **Control Flow**:
    - Iterates over eight data blocks, labeled AESDATA0 to AESDATA7.
    - For each block, performs the AES encryption round using the provided round key.
- **Output**: The eight data blocks are updated in place with the result of the AES encryption round.


---
### \_aesenclast\_8x
The `_aesenclast_8x` macro performs the last round of AES encryption on eight blocks of data using a specified round key.
- **Inputs**:
    - `round_key`: The AES round key used for the last round of encryption.
- **Control Flow**:
    - Iterates over eight data blocks (AESDATA0 to AESDATA7).
    - For each block, applies the `aesenclast` instruction with the provided `round_key`.
- **Output**: The eight data blocks (AESDATA0 to AESDATA7) are transformed by the last round of AES encryption using the specified round key.


---
### \_xor\_data\_8x
The `_xor_data_8x` macro XORs eight blocks of data from a source with precomputed keystream blocks and stores the result in a destination.
- **Inputs**:
    - `SRC`: The source memory location containing the data blocks to be XORed with the keystream.
    - `DST`: The destination memory location where the XORed result will be stored.
- **Control Flow**:
    - Iterate over eight blocks of data, each 16 bytes in size.
    - For each block, use the `_xor_mem_to_reg` macro to XOR the data from the source with the corresponding keystream block stored in an xmm register.
    - Store the XORed result back to the destination using `movdqu`.
- **Output**: The result of XORing the source data blocks with the keystream blocks is stored in the destination memory location.


---
### \_aes\_gcm\_update
The `_aes_gcm_update` macro performs AES-GCM encryption or decryption by computing the CTR keystream, XORing it with data, and updating the GHASH accumulator with ciphertext blocks.
- **Inputs**:
    - `enc`: A flag indicating whether the operation is encryption (1) or decryption (0).
- **Control Flow**:
    - Initialize variables and load key and counter values.
    - Check if data length is sufficient for processing in 8-block chunks; if so, enter the main loop.
    - In the main loop, generate counter blocks, perform AES encryption, and update GHASH with ciphertext blocks using Karatsuba multiplication.
    - If encrypting, XOR plaintext with keystream to produce ciphertext; if decrypting, XOR ciphertext with keystream to produce plaintext.
    - Handle any remaining data less than 8 blocks by processing one block at a time, updating GHASH accordingly.
    - Perform final GHASH reduction and store the updated GHASH accumulator.
- **Output**: The macro updates the GHASH accumulator and produces encrypted or decrypted data in the destination buffer.


---
### \_aes\_gcm\_final
The `_aes_gcm_final` macro finalizes the AES-GCM encryption or decryption process by computing the authentication tag and optionally verifying it against a provided tag.
- **Inputs**:
    - `enc`: A flag indicating whether the operation is encryption (1) or decryption (0).
- **Control Flow**:
    - Initialize local variables and load necessary data such as the byte swap mask and AES key length.
    - Set up a counter block with a specific value to produce the ciphertext needed for the authentication tag.
    - Build the lengths block from total AAD and data lengths, convert them to bits, and XOR it into the GHASH accumulator.
    - Load the precomputed hash key powers and perform AES encryption on the counter block while interleaving GHASH multiplication steps to optimize performance.
    - Undo byte reflection on the GHASH accumulator and encrypt it to finalize the authentication tag.
    - For encryption, store the computed authentication tag; for decryption, compare the computed tag with the provided tag in constant time and return a boolean indicating the match.
- **Output**: For encryption, the computed authentication tag is stored in the GHASH accumulator; for decryption, a boolean is returned indicating whether the computed tag matches the provided tag.


