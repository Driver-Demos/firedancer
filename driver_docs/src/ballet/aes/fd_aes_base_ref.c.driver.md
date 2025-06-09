# Purpose
The provided C source code file, `fd_aes_ref.c`, is a reference implementation of the Advanced Encryption Standard (AES) algorithm, originally derived from the OpenSSL project. This file contains functions that implement the core operations of AES encryption and decryption, including key expansion, substitution, permutation, and mixing of columns, which are essential components of the AES cipher. The code is structured to handle different key sizes (128, 192, and 256 bits) and includes both encryption and decryption routines. The functions [`fd_aes_ref_set_encrypt_key`](#fd_aes_ref_set_encrypt_key) and [`fd_aes_ref_set_decrypt_key`](#fd_aes_ref_set_decrypt_key) are responsible for setting up the encryption and decryption key schedules, respectively, while [`fd_aes_ref_encrypt_core`](#fd_aes_ref_encrypt_core) and [`fd_aes_ref_decrypt_core`](#fd_aes_ref_decrypt_core) perform the actual encryption and decryption of data blocks.

The file is designed to be part of a larger cryptographic library, providing a specific implementation of AES that can be integrated into other software systems. It includes low-level operations such as [`SubWord`](#SubWord), [`ShiftRows`](#ShiftRows), [`MixColumns`](#MixColumns), and their inverse functions, which are fundamental to the AES algorithm's security and efficiency. The code is optimized for performance and includes detailed bitwise operations to achieve the necessary transformations. This implementation is intended to be used as a reference or for educational purposes, offering a clear and detailed example of how AES can be implemented in C. The file does not define a public API directly but provides the core functionality that can be wrapped or extended by other components of a cryptographic library.
# Imports and Dependencies

---
- `assert.h`
- `stdlib.h`
- `fd_aes_gcm_ref.h`


# Data Structures

---
### uni
- **Type**: `union`
- **Members**:
    - `b`: An array of 8 unsigned characters (bytes).
    - `w`: An array of 2 unsigned integers.
    - `d`: An unsigned long integer.
- **Description**: The `uni` data structure is a union that allows for the storage of data in multiple formats within the same memory space. It can store an array of 8 bytes, an array of 2 unsigned integers, or a single unsigned long integer. This flexibility is useful in cryptographic operations, such as those found in AES encryption, where data may need to be accessed or manipulated in different formats without changing the underlying memory layout.


# Functions

---
### XtimeWord<!-- {{#callable:XtimeWord}} -->
The `XtimeWord` function performs a multiplication of a 32-bit word by the polynomial x in the finite field GF(2^8), modulo the polynomial x^8 + x^4 + x^3 + x + 1.
- **Inputs**:
    - `w`: A pointer to a 32-bit unsigned integer that represents the word to be multiplied by x in the finite field.
- **Control Flow**:
    - Retrieve the value pointed to by `w` and store it in `a`.
    - Calculate `b` as the bitwise AND of `a` with the constant `0x80808080u`.
    - XOR `a` with `b` to clear the highest bit of each byte in `a`.
    - Subtract `b` right-shifted by 7 from `b` itself to prepare for conditional addition of the polynomial constant.
    - AND `b` with the constant `0x1B1B1B1Bu` to apply the polynomial reduction conditionally.
    - XOR `b` with `a` left-shifted by 1 to complete the multiplication by x.
    - Store the result back into the location pointed to by `w`.
- **Output**: The function modifies the input word in place, so it does not return a value but updates the value pointed to by `w`.


---
### XtimeLong<!-- {{#callable:XtimeLong}} -->
The `XtimeLong` function performs a multiplication of a 64-bit unsigned integer by a fixed polynomial in a finite field, specifically used in AES encryption.
- **Inputs**:
    - `w`: A pointer to a 64-bit unsigned integer (ulong) that will be modified in place.
- **Control Flow**:
    - Retrieve the value pointed to by `w` and store it in `a`.
    - Compute `b` as the bitwise AND of `a` and the constant `0x8080808080808080`.
    - XOR `a` with `b` to clear the most significant bits of each byte in `a`.
    - Subtract `b` right-shifted by 7 from `b` itself, effectively performing a conditional subtraction based on the most significant bit of each byte.
    - AND `b` with the constant `0x1B1B1B1B1B1B1B1B` to apply a polynomial reduction.
    - XOR `b` with `a` left-shifted by 1 to complete the multiplication by the polynomial.
    - Store the result back into the location pointed to by `w`.
- **Output**: The function modifies the input 64-bit unsigned integer in place, effectively performing a multiplication by a polynomial in a finite field.


---
### SubWord<!-- {{#callable:SubWord}} -->
The `SubWord` function performs a complex transformation on a 32-bit word, typically used in AES encryption, involving bitwise operations and substitutions.
- **Inputs**:
    - `w`: A pointer to a 32-bit unsigned integer (uint) that represents the word to be transformed.
- **Control Flow**:
    - Initialize local variables x, y, a1, a2, a3, a4, a5, and a6.
    - Assign the value pointed to by w to x.
    - Perform a series of bitwise operations and shifts on x and y, involving masks and XOR operations, to transform the word.
    - Use intermediate variables a1 to a6 to store results of transformations and further manipulate the bits of x.
    - Apply a final XOR operation with a constant value to x.
    - Store the transformed value back into the location pointed to by w.
- **Output**: The function modifies the input word in place, transforming it according to the AES S-box substitution and bitwise operations.


---
### SubLong<!-- {{#callable:SubLong}} -->
The `SubLong` function performs a complex bitwise transformation on a 64-bit unsigned long integer, likely as part of an AES-like encryption process.
- **Inputs**:
    - `w`: A pointer to a 64-bit unsigned long integer that will be transformed in place.
- **Control Flow**:
    - Initialize local variables `x`, `y`, `a1`, `a2`, `a3`, `a4`, `a5`, and `a6`.
    - Assign the value pointed to by `w` to `x`.
    - Perform a series of bitwise operations on `x` and `y`, including shifts and masks, to transform the value.
    - Use intermediate variables `a1` to `a6` to store results of transformations and further manipulate `x`.
    - Apply a series of XOR operations and bit shifts to `x` and `y` to achieve the final transformation.
    - Store the transformed value back into the location pointed to by `w`.
- **Output**: The function modifies the input value in place, storing the transformed 64-bit unsigned long integer back into the location pointed to by `w`.


---
### InvSubLong<!-- {{#callable:InvSubLong}} -->
The `InvSubLong` function performs an inverse substitution transformation on a 64-bit word as part of the AES decryption process.
- **Inputs**:
    - `w`: A pointer to a 64-bit unsigned long integer that represents the word to be transformed.
- **Control Flow**:
    - Initialize local variables x, y, a1, a2, a3, a4, a5, and a6.
    - Load the value pointed to by w into x and apply an initial XOR with a constant.
    - Perform a series of bitwise operations and shifts on x and y to transform the word, involving multiple XORs with constants and bitwise shifts.
    - Use intermediate variables a1 to a6 to further manipulate the bits of x through a series of logical operations, including AND, XOR, and shifts.
    - Apply a final series of transformations on x using y and several constants to complete the inverse substitution.
    - Store the transformed value back into the location pointed to by w.
- **Output**: The function modifies the input word in place, so it does not return a value but updates the word pointed to by the input pointer.


---
### ShiftRows<!-- {{#callable:ShiftRows}} -->
The `ShiftRows` function performs a cyclic shift on the rows of a 4x4 matrix representation of the AES state.
- **Inputs**:
    - `state`: A pointer to an array of unsigned long integers representing the AES state, which is treated as a 4x4 matrix of bytes.
- **Control Flow**:
    - The function casts the `state` pointer to a byte pointer `s0`.
    - It iterates over each row index `r` from 0 to 3.
    - For each row, it extracts the bytes from the `state` corresponding to the current row into a temporary array `s`.
    - It then performs a cyclic shift on the elements of `s` and writes them back to the `state` in the same row positions.
- **Output**: The function modifies the `state` in place, performing a cyclic shift on each row of the 4x4 matrix representation of the AES state.


---
### InvShiftRows<!-- {{#callable:InvShiftRows}} -->
The `InvShiftRows` function performs the inverse row shifting operation on a state matrix in the AES decryption process.
- **Inputs**:
    - `state`: A pointer to an array of unsigned long integers representing the state matrix to be modified.
- **Control Flow**:
    - The function begins by declaring a temporary array `s` of 4 unsigned characters and a pointer `s0` to unsigned characters, which is initialized to point to the `state` array.
    - A loop iterates over each row index `r` from 0 to 3.
    - Within the loop, the elements of the `r`-th column of the state matrix are copied into the temporary array `s`.
    - The elements of `s` are then rearranged and written back to the `r`-th column of the state matrix, effectively performing a circular right shift by `r` positions.
- **Output**: The function modifies the input `state` in place, performing the inverse row shift operation required in the AES decryption process.


---
### MixColumns<!-- {{#callable:MixColumns}} -->
The `MixColumns` function performs a transformation on the state array as part of the AES encryption process, specifically implementing the MixColumns step of the AES algorithm.
- **Inputs**:
    - `state`: A pointer to an array of unsigned long integers representing the current state of the AES block.
- **Control Flow**:
    - Initialize two union variables `s1` and `s` to hold intermediate state values.
    - Iterate over the first two elements of the `state` array.
    - For each element, copy its value into `s1.d` and `s.d`.
    - Perform bitwise operations on `s.d` to mix the columns, including shifts and XORs with itself and `s1.d`.
    - Call [`XtimeLong`](#XtimeLong) on `s1.d` to perform a multiplication in the Galois Field.
    - Further modify `s.d` by XORing with `s1.d` and specific bytes of `s1.b`.
    - Store the modified value back into the `state` array.
- **Output**: The function modifies the `state` array in place, transforming its columns according to the AES MixColumns step.
- **Functions called**:
    - [`XtimeLong`](#XtimeLong)


---
### InvMixColumns<!-- {{#callable:InvMixColumns}} -->
The `InvMixColumns` function performs the inverse MixColumns transformation on a state array as part of the AES decryption process.
- **Inputs**:
    - `state`: A pointer to an array of unsigned long integers representing the state to be transformed.
- **Control Flow**:
    - Initialize two union variables `s1` and `s` to hold intermediate state values.
    - Iterate over two columns of the state array (since AES operates on 4x4 matrices, each column is represented by a 64-bit unsigned long).
    - For each column, copy the current state value into `s1` and `s`.
    - Perform a series of bitwise operations and shifts on `s` to reverse the MixColumns transformation, including XOR operations and shifts by 16 and 8 bits.
    - Call [`XtimeLong`](#XtimeLong) on `s1.d` to perform a multiplication in the Galois Field, and XOR the result with `s.d`.
    - Perform additional XOR operations on the byte-level elements of `s` using the byte-level elements of `s1`.
    - Call [`XtimeLong`](#XtimeLong) again on `s1.d` and perform further bitwise operations to complete the inverse transformation.
    - Store the transformed value back into the state array.
- **Output**: The function modifies the input state array in place, applying the inverse MixColumns transformation to each column.
- **Functions called**:
    - [`XtimeLong`](#XtimeLong)


---
### AddRoundKey<!-- {{#callable:AddRoundKey}} -->
The `AddRoundKey` function performs a bitwise XOR operation between the state and a round key in the AES encryption process.
- **Inputs**:
    - `state`: A pointer to an array of two unsigned long integers representing the current state of the AES encryption.
    - `w`: A pointer to an array of two unsigned long integers representing the round key to be XORed with the state.
- **Control Flow**:
    - The function takes two pointers, `state` and `w`, each pointing to an array of two unsigned long integers.
    - It performs a bitwise XOR operation between the first element of `state` and the first element of `w`, storing the result back in the first element of `state`.
    - It performs a bitwise XOR operation between the second element of `state` and the second element of `w`, storing the result back in the second element of `state`.
- **Output**: The function modifies the `state` array in place by XORing it with the `w` array, and it does not return any value.


---
### Cipher<!-- {{#callable:Cipher}} -->
The `Cipher` function performs AES encryption on a single block of data using a specified number of rounds and a key schedule.
- **Inputs**:
    - `in`: A pointer to the input data block (16 bytes) to be encrypted.
    - `out`: A pointer to the output buffer where the encrypted data will be stored (16 bytes).
    - `w`: A pointer to the expanded key schedule used for encryption.
    - `nr`: The number of rounds to perform in the encryption process.
- **Control Flow**:
    - Initialize the state array by copying 16 bytes from the input data block.
    - Apply the initial round key to the state using the [`AddRoundKey`](#AddRoundKey) function.
    - Iterate over the number of rounds minus one, performing the following operations in each round:
    - - Apply the [`SubLong`](#SubLong) transformation to each half of the state.
    - - Perform the [`ShiftRows`](#ShiftRows) transformation on the state.
    - - Execute the [`MixColumns`](#MixColumns) transformation on the state.
    - - Add the round key to the state using [`AddRoundKey`](#AddRoundKey).
    - After the loop, perform the final round without the [`MixColumns`](#MixColumns) transformation:
    - - Apply the [`SubLong`](#SubLong) transformation to each half of the state.
    - - Perform the [`ShiftRows`](#ShiftRows) transformation on the state.
    - - Add the final round key to the state using [`AddRoundKey`](#AddRoundKey).
    - Copy the final state to the output buffer.
- **Output**: The function outputs the encrypted data block in the buffer pointed to by `out`.
- **Functions called**:
    - [`AddRoundKey`](#AddRoundKey)
    - [`SubLong`](#SubLong)
    - [`ShiftRows`](#ShiftRows)
    - [`MixColumns`](#MixColumns)


---
### InvCipher<!-- {{#callable:InvCipher}} -->
The `InvCipher` function performs the decryption of a single block of data using the AES algorithm by applying the inverse of the AES encryption transformations.
- **Inputs**:
    - `in`: A pointer to the input data block (16 bytes) to be decrypted.
    - `out`: A pointer to the output buffer where the decrypted data block will be stored (16 bytes).
    - `w`: A pointer to the expanded key schedule used for decryption.
    - `nr`: The number of rounds to be performed, which depends on the key size (10, 12, or 14 rounds for 128, 192, or 256-bit keys respectively).
- **Control Flow**:
    - Copy the input data block into the `state` array.
    - Apply the [`AddRoundKey`](#AddRoundKey) transformation using the last round key from the key schedule.
    - Iterate over the number of rounds minus one, performing the following steps in each iteration:
    - - Apply the [`InvShiftRows`](#InvShiftRows) transformation to the `state`.
    - - Apply the [`InvSubLong`](#InvSubLong) transformation to each half of the `state`.
    - - Apply the [`AddRoundKey`](#AddRoundKey) transformation using the current round key from the key schedule.
    - - Apply the [`InvMixColumns`](#InvMixColumns) transformation to the `state`.
    - After the loop, perform the final round transformations:
    - - Apply the [`InvShiftRows`](#InvShiftRows) transformation to the `state`.
    - - Apply the [`InvSubLong`](#InvSubLong) transformation to each half of the `state`.
    - - Apply the [`AddRoundKey`](#AddRoundKey) transformation using the first round key from the key schedule.
    - Copy the `state` array to the output buffer.
- **Output**: The function outputs the decrypted data block into the `out` buffer, which is 16 bytes in size.
- **Functions called**:
    - [`AddRoundKey`](#AddRoundKey)
    - [`InvShiftRows`](#InvShiftRows)
    - [`InvSubLong`](#InvSubLong)
    - [`InvMixColumns`](#InvMixColumns)


---
### RotWord<!-- {{#callable:RotWord}} -->
The `RotWord` function rotates the bytes in a 32-bit word to the left by one position.
- **Inputs**:
    - `x`: A pointer to a 32-bit unsigned integer (uint) that represents the word to be rotated.
- **Control Flow**:
    - Cast the input pointer `x` to a pointer to an unsigned char, `w0`, to access individual bytes.
    - Store the first byte of `w0` in a temporary variable `tmp`.
    - Shift the second byte of `w0` to the first position.
    - Shift the third byte of `w0` to the second position.
    - Shift the fourth byte of `w0` to the third position.
    - Move the byte stored in `tmp` to the fourth position of `w0`.
- **Output**: The function modifies the input word in place, rotating its bytes to the left by one position.


---
### KeyExpansion<!-- {{#callable:KeyExpansion}} -->
The `KeyExpansion` function generates the key schedule for AES encryption by expanding the initial cipher key into a series of round keys.
- **Inputs**:
    - `key`: A pointer to the initial cipher key, represented as an array of unsigned characters.
    - `w`: A pointer to an array of unsigned long integers where the expanded key schedule will be stored.
    - `nr`: An integer representing the number of rounds in the AES encryption process.
    - `nk`: An integer representing the number of 32-bit words in the cipher key.
- **Control Flow**:
    - Copy the initial key into the beginning of the expanded key array `w`.
    - Initialize the round constant `rcon` to 1.
    - Calculate `n` as half of `nk`, which determines the number of 64-bit words in the initial key.
    - Set `prev.d` to the last 64-bit word of the initial key.
    - Iterate over the range from `n` to `(nr+1)*2`, expanding the key schedule.
    - For each iteration, set `temp` to the second 32-bit word of `prev`.
    - If the current index `i` is a multiple of `n`, perform a key schedule core operation: rotate `temp`, substitute bytes in `temp`, XOR `temp` with `rcon`, and update `rcon` using [`XtimeWord`](#XtimeWord).
    - If `nk` is greater than 6 and `i` is even, substitute bytes in `temp`.
    - Update `prev.d` to the 64-bit word `n` positions before the current index in `w`.
    - XOR the first 32-bit word of `prev` with `temp`, then XOR the second 32-bit word of `prev` with the first.
    - Store the updated `prev.d` in the current position of `w`.
- **Output**: The function outputs the expanded key schedule in the array `w`, which is used for AES encryption.
- **Functions called**:
    - [`RotWord`](#RotWord)
    - [`SubWord`](#SubWord)
    - [`XtimeWord`](#XtimeWord)


---
### fd\_aes\_ref\_set\_encrypt\_key<!-- {{#callable:fd_aes_ref_set_encrypt_key}} -->
The `fd_aes_ref_set_encrypt_key` function initializes the encryption key schedule for AES encryption based on the provided user key and key size.
- **Inputs**:
    - `userKey`: A pointer to the user-provided key, which is used to generate the encryption key schedule.
    - `bits`: The size of the key in bits, which must be either 128, 192, or 256.
    - `key`: A pointer to an `fd_aes_key_ref_t` structure where the generated encryption key schedule will be stored.
- **Control Flow**:
    - Check if `userKey` or `key` is NULL, returning -1 if either is NULL.
    - Check if `bits` is not one of the valid AES key sizes (128, 192, 256), returning -2 if invalid.
    - Cast the `rd_key` field of the `key` structure to a `ulong` pointer `rk`.
    - Set the number of rounds in the `key` structure based on the key size: 10 for 128 bits, 12 for 192 bits, and 14 for 256 bits.
    - Call [`KeyExpansion`](#KeyExpansion) to generate the encryption key schedule using `userKey`, `rk`, the number of rounds, and the number of 32-bit words in the key.
    - Return 0 to indicate successful key schedule generation.
- **Output**: Returns 0 on success, -1 if `userKey` or `key` is NULL, and -2 if `bits` is not a valid AES key size.
- **Functions called**:
    - [`KeyExpansion`](#KeyExpansion)


---
### fd\_aes\_ref\_set\_decrypt\_key<!-- {{#callable:fd_aes_ref_set_decrypt_key}} -->
The `fd_aes_ref_set_decrypt_key` function sets up the decryption key schedule for AES by calling the encryption key setup function.
- **Inputs**:
    - `userKey`: A pointer to the user's key, which is a sequence of bytes used for AES encryption/decryption.
    - `bits`: The length of the key in bits, which must be either 128, 192, or 256.
    - `key`: A pointer to an `fd_aes_key_ref_t` structure where the key schedule will be stored.
- **Control Flow**:
    - The function directly calls [`fd_aes_ref_set_encrypt_key`](#fd_aes_ref_set_encrypt_key) with the same parameters it received.
    - No additional logic or processing is performed within this function.
- **Output**: The function returns the result of [`fd_aes_ref_set_encrypt_key`](#fd_aes_ref_set_encrypt_key), which is 0 on success, -1 if the userKey or key is NULL, and -2 if the bits value is invalid.
- **Functions called**:
    - [`fd_aes_ref_set_encrypt_key`](#fd_aes_ref_set_encrypt_key)


---
### fd\_aes\_ref\_encrypt\_core<!-- {{#callable:fd_aes_ref_encrypt_core}} -->
The `fd_aes_ref_encrypt_core` function encrypts a single block of data using the AES algorithm with a specified key.
- **Inputs**:
    - `in`: A pointer to the input data block to be encrypted.
    - `out`: A pointer to the output buffer where the encrypted data will be stored.
    - `key`: A pointer to the AES key structure containing the encryption key and the number of rounds.
- **Control Flow**:
    - The function begins by asserting that the input, output, and key pointers are not null.
    - It retrieves the round keys from the key structure using a type punning technique.
    - The [`Cipher`](#Cipher) function is called with the input data, output buffer, round keys, and the number of rounds to perform the encryption.
- **Output**: The function does not return a value; it outputs the encrypted data in the buffer pointed to by `out`.
- **Functions called**:
    - [`Cipher`](#Cipher)


---
### fd\_aes\_ref\_decrypt\_core<!-- {{#callable:fd_aes_ref_decrypt_core}} -->
The `fd_aes_ref_decrypt_core` function decrypts a single block of data using the AES algorithm with a given decryption key.
- **Inputs**:
    - `in`: A pointer to the input data block to be decrypted.
    - `out`: A pointer to the output buffer where the decrypted data will be stored.
    - `key`: A pointer to the AES key structure containing the decryption key and the number of rounds.
- **Control Flow**:
    - The function begins by asserting that the input, output, and key pointers are not null.
    - It retrieves the round keys from the key structure using a type punning technique.
    - The [`InvCipher`](#InvCipher) function is called with the input data, output buffer, round keys, and the number of rounds to perform the decryption.
- **Output**: The function does not return a value; it outputs the decrypted data directly into the provided output buffer.
- **Functions called**:
    - [`InvCipher`](#InvCipher)


