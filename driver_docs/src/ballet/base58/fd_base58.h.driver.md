# Purpose
This C header file, `fd_base58.h`, provides function prototypes and macros for encoding and decoding data between binary format and base58, a text-based encoding scheme. It defines constants for the maximum lengths and sizes of base58-encoded strings derived from 32-byte and 64-byte binary inputs, which are particularly useful for applications like encoding Solana account addresses and transaction signatures. The file includes macros to facilitate the initialization of output buffers for encoding operations, ensuring they are correctly sized to accommodate the encoded data and its null terminator. The functions [`fd_base58_encode_32`](#fd_base58_encode_32) and [`fd_base58_encode_64`](#fd_base58_encode_64) convert binary data to base58 strings, while [`fd_base58_decode_32`](#fd_base58_decode_32) and [`fd_base58_decode_64`](#fd_base58_decode_64) perform the reverse operation, converting base58 strings back to binary format. The header emphasizes high performance in these operations, although it notes that base58 is inherently slower compared to other encoding formats, advising against its use in performance-critical scenarios unless necessary.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_base58\_encode\_32
- **Type**: `function pointer`
- **Description**: The `fd_base58_encode_32` is a function that converts a 32-byte binary input into a Base58 encoded string. It interprets the input bytes as a large big-endian integer and produces a null-terminated Base58 string of 32 to 44 characters in length, excluding the null terminator.
- **Use**: This function is used to encode 32-byte binary data into a Base58 string, suitable for applications like printing Solana account addresses.


---
### fd\_base58\_encode\_64
- **Type**: `function pointer`
- **Description**: The `fd_base58_encode_64` is a function that converts a 64-byte binary input into a base58 encoded string. It interprets the input bytes as a large big-endian integer and produces a null-terminated base58 string of 64 to 88 characters in length, excluding the null terminator. The function also optionally returns the length of the encoded string through the `opt_len` parameter.
- **Use**: This function is used to encode 64-byte binary data into a base58 string, suitable for applications like printing Solana transaction signatures.


---
### fd\_base58\_decode\_32
- **Type**: `function pointer`
- **Description**: The `fd_base58_decode_32` is a function that decodes a base58 encoded string into a 32-byte number, storing the result in a provided output buffer. It returns a pointer to the output buffer on success or NULL if the input string is invalid.
- **Use**: This function is used to convert base58 encoded strings back into their original 32-byte binary form.


---
### fd\_base58\_decode\_64
- **Type**: `function pointer`
- **Description**: The `fd_base58_decode_64` is a function that decodes a base58 encoded string into a 64-byte number, storing the result in a provided output buffer. It returns a pointer to the output buffer on success or NULL if the input string is invalid.
- **Use**: This function is used to convert base58 encoded strings back into their original 64-byte binary form, typically for processing Solana transaction signatures.


