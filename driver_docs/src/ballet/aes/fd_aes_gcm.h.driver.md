# Purpose
This C header file defines the interface and implementation details for AES-GCM (Galois/Counter Mode) encryption and decryption, which is a widely used cryptographic algorithm that provides both confidentiality and authentication. The file is part of a larger library, as indicated by the inclusion of a base header file, and it is designed to be compatible with protocols like TLS 1.3 and QUIC. The primary functionality provided by this file is the authenticated encryption and decryption of messages using AES-GCM, which includes the ability to detect tampering with the ciphertext and to protect additional unencrypted data. The file defines several structures and macros to support different backend implementations, including reference, AES-NI, and AVX10, which are selected based on the available hardware capabilities.

The file provides a public API for initializing AES-GCM contexts and performing encryption and decryption operations. The API is designed to be used in a straightforward manner, with functions for initializing the encryption context ([`fd_aes_128_gcm_init`](#fd_aes_128_gcm_init)), encrypting data ([`fd_aes_gcm_encrypt`](#fd_aes_gcm_encrypt)), and decrypting data ([`fd_aes_gcm_decrypt`](#fd_aes_gcm_decrypt)). The implementation supports an "all-in-one" approach, where the entire plaintext is processed in a single call, and it is optimized for performance by leveraging hardware acceleration when available. The file also defines constants for alignment and tag sizes, ensuring that the data structures are correctly aligned for efficient processing on various architectures. Overall, this header file is a critical component for applications requiring secure and efficient message encryption and authentication.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `fd_aes_gcm_ref.h`


# Data Structures

---
### fd\_aes\_gcm\_aesni\_key
- **Type**: `struct`
- **Members**:
    - `key_enc`: An array of 240 unsigned characters used for encryption key storage.
    - `key_dec`: An array of 240 unsigned characters used for decryption key storage.
    - `key_sz`: An unsigned integer representing the size of the key, set to 16.
- **Description**: The `fd_aes_gcm_aesni_key` structure is designed to store encryption and decryption keys for AES-GCM operations using AES-NI instructions. It contains two arrays, `key_enc` and `key_dec`, each with a size of 240 bytes, to hold the encryption and decryption keys respectively. The `key_sz` member indicates the size of the key, which is fixed at 16 bytes, aligning with the standard AES key size for 128-bit encryption. This structure is integral to the AES-GCM implementation, facilitating secure and efficient cryptographic operations.


---
### fd\_aes\_gcm\_aesni\_key\_t
- **Type**: `struct`
- **Members**:
    - `key_enc`: An array of 240 unsigned characters used for encryption key storage.
    - `key_dec`: An array of 240 unsigned characters used for decryption key storage.
    - `key_sz`: An unsigned integer representing the size of the key, typically 16.
- **Description**: The `fd_aes_gcm_aesni_key_t` structure is designed to store the encryption and decryption keys for AES-GCM operations using the AES-NI instruction set. It contains two arrays, `key_enc` and `key_dec`, each with a size of 240 bytes, to hold the encryption and decryption keys respectively. The `key_sz` member indicates the size of the key, which is typically 16 bytes, aligning with the standard AES key size. This structure is integral to the AES-GCM implementation, facilitating secure and efficient cryptographic operations.


---
### fd\_aes\_gcm\_aesni\_state
- **Type**: `struct`
- **Members**:
    - `key`: Holds the encryption and decryption keys and their size.
    - `pad1`: A 12-byte padding array for alignment purposes.
    - `gcm`: A 208-byte array used for Galois/Counter Mode (GCM) operations.
    - `iv`: A 12-byte array for storing the initialization vector.
    - `pad2`: A 52-byte padding array for alignment purposes.
- **Description**: The `fd_aes_gcm_aesni_state` structure is designed to support AES-GCM encryption and decryption using AES-NI instructions. It contains a key structure for storing encryption and decryption keys, along with padding arrays to ensure proper memory alignment. The structure also includes a GCM array for cryptographic operations and an initialization vector (IV) array, which is essential for the encryption process. This structure is optimized for use with AES-NI, providing efficient and secure encryption capabilities.


---
### fd\_aes\_gcm\_aesni\_t
- **Type**: `struct`
- **Members**:
    - `key`: Holds the encryption and decryption keys for AES operations.
    - `pad1`: Padding to align the structure in memory.
    - `gcm`: Stores the Galois/Counter Mode (GCM) state for encryption.
    - `iv`: Holds the initialization vector for AES-GCM operations.
    - `pad2`: Additional padding to align the structure in memory.
- **Description**: The `fd_aes_gcm_aesni_t` structure is designed to support AES-GCM encryption and decryption using the AES-NI instruction set. It contains a key structure for managing encryption and decryption keys, a GCM state for handling the encryption process, and an initialization vector for ensuring unique encryption outputs. The structure includes padding to ensure proper memory alignment, which is critical for performance and compatibility with low-level assembly implementations. This structure is part of a larger API that provides authenticated encryption, compatible with protocols like TLS 1.3 and QUIC, and is optimized for performance on systems supporting AES-NI.


---
### fd\_aes\_gcm\_avx10\_state
- **Type**: `struct`
- **Members**:
    - `key`: Holds the AES-NI key used for encryption and decryption.
    - `pad1`: Padding to align the structure, consisting of 28 bytes.
    - `gcm`: Buffer of 320 bytes used for Galois/Counter Mode (GCM) operations.
    - `iv`: 12-byte initialization vector used in encryption processes.
    - `pad2`: Padding to align the structure, consisting of 52 bytes.
- **Description**: The `fd_aes_gcm_avx10_state` structure is designed to support AES-GCM encryption and decryption operations using the AVX10 backend. It includes a key for AES-NI operations, a buffer for GCM operations, and an initialization vector, with additional padding to ensure proper alignment. This structure is optimized for high-performance cryptographic operations, particularly in environments that support AVX512, GFNI, and AESNI instructions.


---
### fd\_aes\_gcm\_avx10\_t
- **Type**: `struct`
- **Members**:
    - `key`: An instance of fd_aes_gcm_aesni_key_t, storing encryption and decryption keys.
    - `pad1`: A padding array of 28 unsigned characters.
    - `gcm`: An array of 320 unsigned characters used for GCM state.
    - `iv`: An array of 12 unsigned characters used for the initialization vector.
    - `pad2`: A padding array of 52 unsigned characters.
- **Description**: The fd_aes_gcm_avx10_t structure is designed for AES-GCM encryption and decryption using the AVX10 backend, optimized for parallel processing of AES blocks. It includes key storage, padding for alignment, and arrays for GCM state and initialization vector, ensuring efficient and secure cryptographic operations.


