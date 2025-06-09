# Purpose
This C code file defines a macro-based implementation of the HMAC (Hash-based Message Authentication Code) algorithm, which is a mechanism for message authentication using cryptographic hash functions. The file is designed to be flexible and reusable with different hash algorithms by requiring the user to define specific macros: `HASH_ALG`, `HASH_SZ`, and `HASH_BLOCK_SZ`. These macros specify the hash algorithm to be used (e.g., SHA-256), the size of the hash output, and the internal block size of the hash function, respectively. The code uses these macros to dynamically generate function names and manage the HMAC computation process, ensuring that it can be adapted to various hash functions that follow a similar naming convention.

The core functionality of the file is encapsulated in a single function, which performs the HMAC computation by first compressing and padding the key, then executing the inner and outer hash calculations as specified by the HMAC standard (RFC 2104). The function is designed to be efficient, using aligned memory for key storage and leveraging existing hash function operations (init, append, and fini) to perform the necessary cryptographic transformations. This file does not define a public API or external interface directly but rather provides a template for generating HMAC functions tailored to specific hash algorithms, making it a versatile component in cryptographic libraries.
# Functions

---
### HMAC\_FN<!-- {{#callable:HMAC_FN}} -->
The `HMAC_FN` function implements the HMAC (Hash-based Message Authentication Code) algorithm using a specified hash function to authenticate a message with a given key.
- **Inputs**:
    - `data`: A pointer to the data (message) to be authenticated.
    - `data_sz`: The size of the data in bytes.
    - `_key`: A pointer to the key used for the HMAC operation.
    - `key_sz`: The size of the key in bytes.
    - `hash`: A pointer to the buffer where the resulting HMAC will be stored.
- **Control Flow**:
    - Initialize a buffer `key` with zeros and align it to 32 bytes.
    - If the key size is greater than the hash block size, hash the key and store the result in `key`, updating `key_sz` to the hash size; otherwise, copy the key into `key`.
    - Initialize `key_ipad` and `key_opad` with specific padding values (0x36 and 0x5c respectively) and XOR them with the `key`.
    - Create a new hash context `sha` and initialize it for the inner hash calculation.
    - Append `key_ipad` and the data to the hash context, finalize the hash, and store the result in `hash`.
    - Reinitialize the hash context for the outer hash calculation.
    - Append `key_opad` and the previously computed hash to the hash context, finalize the hash, and store the result in `hash`.
- **Output**: A pointer to the buffer containing the computed HMAC.


