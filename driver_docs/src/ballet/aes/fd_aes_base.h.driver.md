# Purpose
This C header file, `fd_aes.h`, provides an interface for AES (Advanced Encryption Standard) encryption and decryption functionalities. It defines both reference and AES-NI (Advanced Encryption Standard New Instructions) based implementations for setting encryption and decryption keys, as well as performing the core encryption and decryption operations. The file includes conditional compilation directives to select between the portable reference implementation and the optimized AES-NI implementation, depending on the availability of AES-NI support on the target platform. The file defines a structure `fd_aes_key_ref_t` to store the AES key and the number of rounds, which is used by both implementations.

The header file also includes inline functions that serve as the public API for setting keys and performing encryption and decryption. These functions utilize memory sanitization checks to ensure the integrity and safety of the operations, leveraging the `fd_msan` utility. The file is designed to be included in other C source files, providing a consistent and efficient interface for AES operations, with the flexibility to leverage hardware acceleration when available. The use of macros and typedefs allows for seamless switching between implementations, ensuring that the most appropriate method is used based on the compilation environment.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `../../util/sanitize/fd_msan.h`


# Data Structures

---
### fd\_aes\_key\_ref
- **Type**: `struct`
- **Members**:
    - `rd_key`: An array of 60 unsigned integers used to store the round keys for AES encryption or decryption.
    - `rounds`: An integer representing the number of rounds in the AES encryption or decryption process.
- **Description**: The `fd_aes_key_ref` structure is used to store the key schedule for AES encryption and decryption operations. It contains an array `rd_key` which holds the round keys necessary for the AES algorithm, and an integer `rounds` which specifies the number of rounds to be performed based on the key size. This structure is integral to the implementation of AES encryption and decryption functions, providing the necessary data for the cryptographic transformations.


---
### fd\_aes\_key\_ref\_t
- **Type**: `struct`
- **Members**:
    - `rd_key`: An array of 60 unsigned integers used to store the round keys for AES encryption or decryption.
    - `rounds`: An integer representing the number of rounds used in the AES encryption or decryption process.
- **Description**: The `fd_aes_key_ref_t` structure is used to store the key schedule for AES encryption and decryption operations. It contains an array `rd_key` to hold the round keys and an integer `rounds` to specify the number of rounds, which depends on the key size used in the AES algorithm. This structure is essential for both setting up the encryption/decryption keys and performing the cryptographic operations.


# Functions

---
### fd\_aes\_set\_encrypt\_key<!-- {{#callable:fd_aes_set_encrypt_key}} -->
The `fd_aes_set_encrypt_key` function initializes an AES encryption key structure using a user-provided key and key size.
- **Inputs**:
    - `user_key`: A pointer to the user-provided key, which is an array of unsigned characters.
    - `bits`: The size of the key in bits, which determines the length of the key.
    - `key`: A pointer to the `fd_aes_key_t` structure where the encryption key will be stored.
- **Control Flow**:
    - The function first checks the memory safety of the `user_key` by verifying that it is accessible for `bits/8` bytes using `fd_msan_check`.
    - It then marks the memory region pointed to by `key` as unpoisoned for the size of `fd_aes_key_t` using `fd_msan_unpoison`.
    - Finally, it calls `fd_aes_private_set_encrypt_key` to set the encryption key using the provided `user_key`, `bits`, and `key`.
- **Output**: The function does not return a value; it modifies the `key` structure in place to store the encryption key.


---
### fd\_aes\_set\_decrypt\_key<!-- {{#callable:fd_aes_set_decrypt_key}} -->
The `fd_aes_set_decrypt_key` function initializes an AES decryption key structure using a user-provided key and key length.
- **Inputs**:
    - `user_key`: A pointer to the user-provided key, which is an array of unsigned characters.
    - `bits`: The length of the key in bits, which determines the size of the key.
    - `key`: A pointer to an `fd_aes_key_t` structure where the decryption key will be stored.
- **Control Flow**:
    - The function first checks the memory safety of the `user_key` by verifying that it is accessible for `bits/8` bytes using `fd_msan_check`.
    - It then marks the memory region pointed to by `key` as unpoisoned for the size of `fd_aes_key_t` using `fd_msan_unpoison`.
    - Finally, it calls `fd_aes_private_set_decrypt_key` to set the decryption key using the provided `user_key`, `bits`, and `key`.
- **Output**: The function does not return a value; it modifies the `key` structure in place to store the decryption key.


---
### fd\_aes\_encrypt<!-- {{#callable:fd_aes_encrypt}} -->
The `fd_aes_encrypt` function performs AES encryption on a 16-byte input block using a specified encryption key.
- **Inputs**:
    - `in`: A pointer to the 16-byte input data block to be encrypted.
    - `out`: A pointer to the 16-byte output buffer where the encrypted data will be stored.
    - `key`: A pointer to the `fd_aes_key_t` structure containing the encryption key.
- **Control Flow**:
    - The function first checks the memory safety of the `key` and `in` pointers using `fd_msan_check` to ensure they are valid and initialized.
    - It then marks the `out` buffer as unpoisoned using `fd_msan_unpoison`, indicating that it will be written to and should not be considered uninitialized.
    - Finally, it calls `fd_aes_private_encrypt` to perform the actual encryption of the input data using the provided key, storing the result in the output buffer.
- **Output**: The function does not return a value; it outputs the encrypted data directly into the `out` buffer.


---
### fd\_aes\_decrypt<!-- {{#callable:fd_aes_decrypt}} -->
The `fd_aes_decrypt` function decrypts a 16-byte block of data using a specified AES key.
- **Inputs**:
    - `in`: A pointer to the 16-byte input data block to be decrypted.
    - `out`: A pointer to the 16-byte output buffer where the decrypted data will be stored.
    - `key`: A pointer to the AES key structure used for decryption.
- **Control Flow**:
    - The function first checks the memory safety of the `key` and `in` pointers using `fd_msan_check` to ensure they are valid and accessible.
    - It then marks the `out` buffer as unpoisoned using `fd_msan_unpoison`, indicating that it will be written to and should not be considered uninitialized.
    - Finally, it calls `fd_aes_private_decrypt` to perform the actual decryption of the input data block using the provided key, storing the result in the output buffer.
- **Output**: The function does not return a value; it outputs the decrypted data directly into the `out` buffer.


# Function Declarations (Public API)

---
### fd\_aes\_ref\_set\_encrypt\_key<!-- {{#callable_declaration:fd_aes_ref_set_encrypt_key}} -->
Sets the encryption key for AES operations.
- **Description**: This function initializes an AES key structure for encryption using the specified user key and key size. It must be called before performing any encryption operations with the key. The function supports key sizes of 128, 192, or 256 bits. If the provided key size is not one of these values, or if any of the input pointers are null, the function will return an error code.
- **Inputs**:
    - `user_key`: A pointer to the user-provided key data. It must not be null and should point to a buffer of appropriate size for the specified key length (16 bytes for 128 bits, 24 bytes for 192 bits, 32 bytes for 256 bits).
    - `bits`: The size of the key in bits. Valid values are 128, 192, or 256. If an invalid value is provided, the function returns an error.
    - `key`: A pointer to an fd_aes_key_ref_t structure where the initialized key will be stored. It must not be null.
- **Output**: Returns 0 on success. Returns -1 if user_key or key is null, and -2 if bits is not a valid key size.
- **See also**: [`fd_aes_ref_set_encrypt_key`](fd_aes_base_ref.c.driver.md#fd_aes_ref_set_encrypt_key)  (Implementation)


---
### fd\_aes\_ref\_set\_decrypt\_key<!-- {{#callable_declaration:fd_aes_ref_set_decrypt_key}} -->
Sets the decryption key for AES operations.
- **Description**: This function initializes an AES decryption key structure using the provided user key and key size in bits. It is essential to call this function before performing any decryption operations with the AES algorithm. The function expects a valid user key and key size, and it will configure the key structure accordingly. Ensure that the key size is appropriate for AES (e.g., 128, 192, or 256 bits).
- **Inputs**:
    - `user_key`: A pointer to the user-provided key, which must not be null. The key should be of a length corresponding to the specified number of bits divided by 8.
    - `bits`: The size of the key in bits, typically 128, 192, or 256. Values outside these typical sizes may result in undefined behavior.
    - `key`: A pointer to an fd_aes_key_ref_t structure where the decryption key will be stored. This must not be null, and the caller retains ownership of the memory.
- **Output**: Returns an integer status code, typically 0 on success. Non-zero values may indicate an error in setting the key.
- **See also**: [`fd_aes_ref_set_decrypt_key`](fd_aes_base_ref.c.driver.md#fd_aes_ref_set_decrypt_key)  (Implementation)


---
### fd\_aes\_ref\_encrypt\_core<!-- {{#callable_declaration:fd_aes_ref_encrypt_core}} -->
Encrypts a 16-byte block of data using the specified AES key.
- **Description**: This function encrypts a single 16-byte block of data using the AES encryption algorithm with the provided key. It is essential to ensure that the input data block, output buffer, and key are all valid and properly initialized before calling this function. The function does not perform any checks on the validity of the key beyond ensuring it is not null, so the key must be set up correctly using an appropriate key setup function prior to encryption. The function does not return a value, and the encrypted data is written directly to the output buffer.
- **Inputs**:
    - `in`: A pointer to a 16-byte block of data to be encrypted. Must not be null.
    - `out`: A pointer to a buffer where the encrypted data will be written. Must not be null and must have space for at least 16 bytes.
    - `key`: A pointer to a constant fd_aes_key_ref_t structure containing the encryption key. Must not be null and must be properly initialized.
- **Output**: None
- **See also**: [`fd_aes_ref_encrypt_core`](fd_aes_base_ref.c.driver.md#fd_aes_ref_encrypt_core)  (Implementation)


---
### fd\_aes\_ref\_decrypt\_core<!-- {{#callable_declaration:fd_aes_ref_decrypt_core}} -->
Decrypts a 16-byte block of data using the specified AES key.
- **Description**: This function decrypts a single 16-byte block of data using the AES decryption key provided. It is intended for use in applications where AES decryption is required. The function must be called with valid pointers for the input data, output buffer, and the AES key structure. The key must be properly initialized with the decryption key before calling this function. The function does not perform any internal validation of the input data size, so it is the caller's responsibility to ensure that the input and output buffers are at least 16 bytes in size.
- **Inputs**:
    - `in`: A pointer to a 16-byte block of data to be decrypted. Must not be null.
    - `out`: A pointer to a buffer where the decrypted 16-byte block will be stored. Must not be null and must have space for at least 16 bytes.
    - `key`: A pointer to an initialized fd_aes_key_ref_t structure containing the decryption key. Must not be null and must be initialized with fd_aes_ref_set_decrypt_key.
- **Output**: None
- **See also**: [`fd_aes_ref_decrypt_core`](fd_aes_base_ref.c.driver.md#fd_aes_ref_decrypt_core)  (Implementation)


