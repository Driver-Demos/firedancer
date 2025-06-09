# Purpose
This C header file, `fd_hex.h`, provides functionality for encoding and decoding data between binary and hexadecimal formats. It defines two primary functions: [`fd_hex_decode`](#fd_hex_decode), which converts a hex-encoded string into its binary form, and [`fd_hex_encode`](#fd_hex_encode), which performs the reverse operation by converting binary data into a hex-encoded string. The encoding process represents each byte as two hexadecimal characters, while decoding is case-insensitive, accepting both lowercase and uppercase hex digits. The file includes a dependency on `fd_ballet_base.h`, suggesting it is part of a larger library or framework. This header is essential for applications requiring data representation transformations between binary and human-readable hexadecimal formats.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_hex\_encode
- **Type**: `function`
- **Description**: The `fd_hex_encode` function is a utility for converting binary data into a hexadecimal string representation. It takes a destination buffer `dst`, a source buffer `src`, and the size `sz` of the source data to encode. The function encodes each byte of the source into two hexadecimal characters, storing the result in the destination buffer.
- **Use**: This function is used to encode binary data into a human-readable hexadecimal format.


# Function Declarations (Public API)

---
### fd\_hex\_decode<!-- {{#callable_declaration:fd_hex_decode}} -->
Decodes a hex-encoded string into a binary buffer.
- **Description**: Use this function to convert a hex-encoded string into its binary representation. It reads up to `sz*2` characters from the source string and writes up to `sz` decoded bytes into the destination buffer. The function is case-insensitive and handles both lowercase and uppercase hex digits. It returns the number of bytes successfully decoded or the index at which decoding failed if an invalid character is encountered. Ensure that the destination buffer is large enough to hold `sz` bytes and that the source string contains at least `sz*2` characters.
- **Inputs**:
    - `dst`: A pointer to the destination buffer where the decoded bytes will be stored. Must not be null and should have space for at least `sz` bytes. The caller retains ownership.
    - `src`: A pointer to the null-terminated string containing the hex-encoded data. Must not be null and should contain at least `sz*2` characters. The caller retains ownership.
    - `sz`: The number of bytes to decode from the source string. Must be a non-negative value.
- **Output**: Returns the number of bytes successfully decoded. If decoding fails due to an invalid character, it returns the index of the byte at which the failure occurred.
- **See also**: [`fd_hex_decode`](fd_hex.c.driver.md#fd_hex_decode)  (Implementation)


---
### fd\_hex\_encode<!-- {{#callable_declaration:fd_hex_encode}} -->
Encodes binary data into a hexadecimal string.
- **Description**: This function converts a binary data buffer into a hexadecimal string representation. It encodes each byte of the input data into two hexadecimal characters, using lowercase letters for values 10 to 15. The function is typically used when a human-readable representation of binary data is needed, such as for logging or debugging. The caller must ensure that the destination buffer is large enough to hold the resulting hexadecimal string, which will be twice the size of the input data. The function does not append a null terminator to the output string.
- **Inputs**:
    - `dst`: A pointer to the destination buffer where the hexadecimal string will be written. The buffer must be large enough to hold at least 2 * sz characters. The caller retains ownership and must ensure the buffer is valid.
    - `_src`: A pointer to the source buffer containing the binary data to be encoded. The data is treated as an array of unsigned characters. The caller retains ownership and must ensure the buffer is valid and contains at least sz bytes.
    - `sz`: The number of bytes to read from the source buffer and encode. Must be a non-negative value.
- **Output**: Returns a pointer to the end of the encoded string in the destination buffer, which is dst + 2 * sz.
- **See also**: [`fd_hex_encode`](fd_hex.c.driver.md#fd_hex_encode)  (Implementation)


