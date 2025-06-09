# Purpose
This assembly source code file is a highly specialized implementation of the Advanced Encryption Standard (AES) using the AES New Instructions (AES-NI) set available on x86_64 architectures. The code is part of the OpenSSL project and is designed to provide accelerated encryption and decryption operations by leveraging hardware support for AES, which significantly enhances performance compared to software-only implementations. The file includes functions for both encryption and decryption in various modes, such as ECB (Electronic Codebook) and CTR (Counter) modes, as well as functions for setting encryption and decryption keys.

The most important technical components of this file are the functions that perform AES encryption and decryption using AES-NI instructions. These functions include `fd_aesni_encrypt`, `fd_aesni_decrypt`, `fd_aesni_ecb_encrypt`, and `fd_aesni_ctr32_encrypt_blocks`, among others. Each function is carefully crafted to utilize the AES-NI instructions, which are specific to Intel processors, to perform the AES transformations directly in hardware. This results in a significant speedup over traditional software implementations. The file also contains key expansion routines, which are crucial for preparing the encryption keys used in the AES algorithm.

Overall, this code is a collection of components that share the common theme of providing efficient AES encryption and decryption capabilities. The use of AES-NI instructions is a key feature, as it allows the code to perform cryptographic operations at a much higher speed than would be possible with a purely software-based approach. This makes the code particularly suitable for applications that require high-throughput encryption, such as secure communications and data storage systems.
# Global Variables

---
### \.Lbswap\_mask
- **Type**: ``.Lbswap_mask``
- **Description**: The `.Lbswap_mask` is a global variable defined as a sequence of bytes in a specific order. It is used to facilitate byte swapping operations, which are often necessary in cryptographic algorithms to ensure data is in the correct byte order for processing.
- **Use**: This variable is used in AES encryption and decryption routines to perform byte swapping operations on data blocks.


---
### \.Lincrement32
- **Type**: `.long`
- **Description**: The variable `.Lincrement32` is a global variable defined as a sequence of four 32-bit integers. It is initialized with the values 6, 6, 6, and 0.
- **Use**: This variable is likely used to increment a 128-bit counter or value by a specific pattern, possibly in cryptographic operations.


---
### \.Lincrement64
- **Type**: `.long`
- **Description**: The variable `.Lincrement64` is a global variable defined as a 128-bit integer, represented by four 32-bit long integers. It is initialized with the values `1, 0, 0, 0`, which effectively represents the number 1 in a 128-bit space.
- **Use**: This variable is used to increment a 128-bit counter by 1, typically in cryptographic operations such as AES in counter mode.


---
### \.Lincrement1
- **Type**: `.byte`
- **Description**: The variable `.Lincrement1` is a byte array initialized with 15 zero bytes followed by a single byte with the value 1. This pattern is often used in assembly code to represent a small increment value, typically for loop counters or similar operations.
- **Use**: This variable is used to increment a value by 1, likely in a loop or iterative process within the assembly code.


---
### \.Lkey\_rotate
- **Type**: ``.long``
- **Description**: The variable `.Lkey_rotate` is a global variable defined as a sequence of four 32-bit long integers. Each integer in the sequence is set to the hexadecimal value `0x0c0f0e0d`. This pattern is used in the AES key expansion process to assist in the rotation of key bytes during the generation of round keys.
- **Use**: This variable is used in the AES key expansion process to facilitate the rotation of key bytes, which is a critical step in generating round keys for encryption and decryption.


---
### \.Lkey\_rotate192
- **Type**: ``.long``
- **Description**: The variable `.Lkey_rotate192` is a constant array of four 32-bit integers, each with the value `0x04070605`. This array is used in the AES key expansion process for 192-bit keys.
- **Use**: It is used to assist in the rotation of key bytes during the AES key expansion for 192-bit encryption.


---
### \.Lkey\_rcon1
- **Type**: ``.long``
- **Description**: The variable `.Lkey_rcon1` is a global variable defined as a sequence of four 32-bit integers, each with the value 1. It is used in the AES key expansion process, specifically as part of the round constant (Rcon) values that are applied during the key schedule.
- **Use**: This variable is used in the AES key expansion process to provide round constants for the key schedule.


---
### \.Lkey\_rcon1b
- **Type**: `.long`
- **Description**: The variable `.Lkey_rcon1b` is a global constant defined in the assembly code as a 32-bit integer array with four elements, each set to the hexadecimal value `0x1b`. This value is commonly used in AES (Advanced Encryption Standard) key expansion as part of the round constant (Rcon) values.
- **Use**: This variable is used in the AES key expansion process to assist in generating the round keys for encryption and decryption.


# Subroutines

---
### fd\_aesni\_encrypt
The `fd_aesni_encrypt` function performs AES encryption using the AES-NI instruction set for hardware acceleration.
- **Inputs**:
    - `%rdi`: Pointer to the input data to be encrypted.
    - `%rsi`: Pointer to the output buffer where the encrypted data will be stored.
    - `%rdx`: Pointer to the AES key schedule.
- **Control Flow**:
    - Load the input data from the address in %rdi into the xmm2 register.
    - Load the number of rounds from the key schedule at offset 240 into the eax register.
    - Load the first two round keys from the key schedule into xmm0 and xmm1.
    - Advance the key schedule pointer by 32 bytes.
    - Perform an XOR operation between xmm0 and xmm2 to apply the first round key.
    - Enter a loop that continues until the number of rounds (eax) is decremented to zero.
    - Within the loop, perform the AES encryption round using the AESENC instruction (represented by the byte sequence 102,15,56,220,209).
    - Load the next round key into xmm1 and advance the key schedule pointer by 16 bytes.
    - Repeat the loop until all rounds are completed.
    - Perform a final AES encryption round using the AESENCLAST instruction (represented by the byte sequence 102,15,56,221,209).
    - Clear the xmm0 and xmm1 registers using PXOR to zero them out.
    - Store the encrypted data from xmm2 into the output buffer at the address in %rsi.
    - Clear the xmm2 register using PXOR to zero it out.
    - Return from the function.
- **Output**: The function outputs the encrypted data in the buffer pointed to by %rsi.


---
### fd\_aesni\_decrypt
The `fd_aesni_decrypt` function performs AES decryption using the AES-NI instruction set for hardware-accelerated decryption.
- **Inputs**:
    - `%rdi`: Pointer to the input data to be decrypted.
    - `%rsi`: Pointer to the output buffer where the decrypted data will be stored.
    - `%rdx`: Pointer to the AES key schedule used for decryption.
- **Control Flow**:
    - Load the input data from the address pointed to by %rdi into the xmm2 register.
    - Load the number of rounds from the key schedule at offset 240 into the eax register.
    - Load the first two round keys from the key schedule into xmm0 and xmm1 registers.
    - Advance the key schedule pointer by 32 bytes to point to the next round key.
    - Perform an initial XOR of the input data with the first round key using the xorps instruction.
    - Enter a loop (Loop_dec1_2) that performs the AES decryption rounds using the AES-NI instruction aesdec, decrementing the round counter each time.
    - Load the next round key into xmm1 and advance the key schedule pointer by 16 bytes.
    - Continue looping until the round counter reaches zero.
    - Perform the final AES decryption round using the AES-NI instruction aesdeclast.
    - Clear the xmm0 and xmm1 registers using pxor to zero them out.
    - Store the decrypted data from xmm2 into the output buffer pointed to by %rsi.
    - Clear the xmm2 register using pxor to zero it out.
    - Return from the function.
- **Output**: The function outputs the decrypted data into the buffer pointed to by %rsi.


---
### fd\_aesni\_ecb\_encrypt
The `fd_aesni_ecb_encrypt` function performs AES encryption or decryption in ECB mode using AES-NI instructions for acceleration.
- **Inputs**:
    - `%rdi`: Pointer to the input data to be encrypted or decrypted.
    - `%rsi`: Pointer to the output buffer where the encrypted or decrypted data will be stored.
    - `%rdx`: Length of the data to be processed, in bytes.
    - `%rcx`: Pointer to the AES key schedule.
    - `%r8d`: Flag indicating whether to encrypt (non-zero) or decrypt (zero).
- **Control Flow**:
    - Align the data length to a multiple of 16 bytes and check if it is zero, returning if so.
    - Load the AES key schedule and determine the number of rounds from the key schedule.
    - Check the encryption/decryption flag to decide the operation mode.
    - For encryption, process data in blocks of 128 bytes using a loop, calling `_aesni_encrypt8` for each block, and handle any remaining data with smaller block sizes.
    - For decryption, process data similarly in blocks of 128 bytes using `_aesni_decrypt8`, and handle remaining data with smaller block sizes.
    - Use a series of conditional jumps to handle different tail sizes for both encryption and decryption.
    - Return after processing all data.
- **Output**: The function outputs the encrypted or decrypted data in the buffer pointed to by %rsi.


---
### fd\_aesni\_ctr32\_encrypt\_blocks
The `fd_aesni_ctr32_encrypt_blocks` function performs AES encryption in CTR mode using AES-NI instructions for 32-bit counter blocks.
- **Inputs**:
    - `%rdi`: Pointer to the input data to be encrypted.
    - `%rsi`: Pointer to the output buffer where encrypted data will be stored.
    - `%rdx`: Number of 128-bit blocks to be encrypted.
    - `%rcx`: Pointer to the AES key schedule.
    - `%r8`: Pointer to the counter block.
- **Control Flow**:
    - Check if the number of blocks is not equal to 1 and jump to bulk processing if true.
    - Load the counter block and input data into XMM registers and perform initial XOR with the key.
    - Enter a loop to perform AES rounds using AES-NI instructions, decrementing the round counter each time.
    - After rounds, XOR the result with the input data and store it in the output buffer.
    - For bulk processing, prepare multiple counter blocks and perform similar operations in a loop for multiple blocks at once.
    - Handle remaining blocks in a tail processing section if the number of blocks is not a multiple of 8.
    - Clear sensitive data from registers and restore stack before returning.
- **Output**: The function outputs the encrypted data in the buffer pointed to by %rsi.


---
### fd\_aesni\_set\_decrypt\_key
The `fd_aesni_set_decrypt_key` function sets up the AES decryption key schedule using AES-NI instructions by reversing the encryption key schedule.
- **Inputs**:
    - `rdx`: Pointer to the memory location where the encryption key schedule is stored.
    - `rsi`: The number of 32-bit words in the key, multiplied by 4.
- **Control Flow**:
    - The function begins by calling `__aesni_set_encrypt_key` to set up the encryption key schedule.
    - It checks if the call to `__aesni_set_encrypt_key` was successful by testing the return value in `eax`.
    - If the call was unsuccessful, it jumps to the return label `Ldec_key_ret`.
    - If successful, it calculates the pointer `rdi` to the end of the key schedule using `rdx` and `rsi`.
    - It swaps the first two 128-bit blocks of the key schedule using `movups` instructions.
    - The function enters a loop labeled `Ldec_key_inverse` to reverse the order of the remaining key schedule blocks.
    - Within the loop, it loads two 128-bit blocks from `rdx` and `rdi`, applies the `aesimc` instruction to each, and swaps them.
    - The loop continues until `rdx` and `rdi` meet, at which point the last block is processed and the function exits the loop.
    - The function then returns, restoring the stack pointer.
- **Output**: The function outputs the AES decryption key schedule in the memory location pointed to by `rdx`, with the key schedule reversed and transformed for decryption.


---
### fd\_aesni\_set\_encrypt\_key
The `fd_aesni_set_encrypt_key` function sets up the AES encryption key schedule using AES-NI instructions for hardware-accelerated encryption.
- **Inputs**:
    - `%rdi`: Pointer to the user-provided key.
    - `%rdx`: Pointer to the location where the expanded key schedule will be stored.
    - `%esi`: The size of the key in bits (128, 192, or 256).
- **Control Flow**:
    - The function begins by checking if the key or the key schedule pointer is null, returning immediately if so.
    - It loads the user-provided key into the xmm0 register and initializes xmm4 to zero.
    - The function checks the key size and branches to the appropriate key expansion routine for 128, 192, or 256-bit keys.
    - For 128-bit keys, it performs 10 rounds of key expansion using the AESKEYGENASSIST instruction and stores the expanded keys.
    - For 192-bit keys, it performs 12 rounds of key expansion, handling the additional key material appropriately.
    - For 256-bit keys, it performs 14 rounds of key expansion, using two 128-bit blocks of the key.
    - If the key size is invalid, it sets the return value to -2.
    - The function clears sensitive data from the xmm registers before returning.
- **Output**: The function outputs the expanded key schedule in the memory location pointed to by %rdx, and returns 0 on success or -1/-2 on error.


