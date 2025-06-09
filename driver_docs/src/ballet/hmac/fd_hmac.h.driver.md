# Purpose
This C header file defines an interface for computing HMAC (Hash-based Message Authentication Code) using various SHA (Secure Hash Algorithm) functions, specifically SHA-256, SHA-384, and SHA-512. It includes a function pointer type `fd_hmac_fn_t` for general HMAC computation and declares three functions: [`fd_hmac_sha256`](#fd_hmac_sha256), [`fd_hmac_sha384`](#fd_hmac_sha384), and [`fd_hmac_sha512`](#fd_hmac_sha512), each designed to compute the HMAC digest for a given message and key using the respective SHA algorithm. The file ensures that the necessary base definitions are included from `fd_ballet_base.h` and uses include guards to prevent multiple inclusions. This header is part of a larger library focused on cryptographic operations, providing essential APIs for message authentication.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_hmac\_sha256
- **Type**: `function pointer`
- **Description**: `fd_hmac_sha256` is a function that computes the HMAC-SHA256 digest for a given key and message. It takes pointers to the data and key, along with their respective sizes, and stores the resulting 32-byte digest in the provided hash memory region.
- **Use**: This function is used to generate a secure hash-based message authentication code using the SHA-256 algorithm.


---
### fd\_hmac\_sha384
- **Type**: `function pointer`
- **Description**: `fd_hmac_sha384` is a function that computes the HMAC-SHA384 digest for a given message and key. It takes pointers to the data and key, along with their respective sizes, and stores the resulting digest in the provided hash memory region.
- **Use**: This function is used to perform HMAC-SHA384 hashing for message authentication.


---
### fd\_hmac\_sha512
- **Type**: `function pointer`
- **Description**: `fd_hmac_sha512` is a function pointer that computes the HMAC-SHA512 digest for a given message and key. It takes pointers to the data and key, along with their respective sizes, and a pointer to a memory region where the resulting hash will be stored.
- **Use**: This function is used to perform HMAC-SHA512 hashing for message authentication.


