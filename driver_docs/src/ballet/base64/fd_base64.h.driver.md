# Purpose
This C header file, `fd_base64.h`, provides functionality for encoding and decoding data using the Base64 encoding scheme, as specified in RFC 4648. It defines macros for calculating the size of the encoded and decoded data, `FD_BASE64_ENC_SZ` and `FD_BASE64_DEC_SZ`, which are useful for memory allocation and buffer management. The file declares three main functions: [`fd_base64_encode`](#fd_base64_encode), which encodes binary data into Base64 format; [`fd_cstr_append_base64`](#fd_cstr_append_base64), a static inline function that appends Base64 encoded data to a given string; and [`fd_base64_decode`](#fd_base64_decode), which decodes Base64 encoded data back into its original binary form. The header ensures compatibility with C by not including null terminators in the encoded output and supports compile-time evaluation for size calculations, making it efficient for use in various applications requiring Base64 encoding and decoding.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Functions

---
### fd\_cstr\_append\_base64<!-- {{#callable:fd_cstr_append_base64}} -->
The `fd_cstr_append_base64` function appends Base64 encoded data to a given character buffer.
- **Inputs**:
    - `p`: A pointer to a character buffer where the Base64 encoded data will be appended. It must have enough space for at least FD_BASE64_ENC_SZ(sz) characters and a final terminating '\0'.
    - `s`: A pointer to the input data (as an array of unsigned characters) that needs to be Base64 encoded.
    - `sz`: The size of the input data in bytes. If this is zero, the function performs no operation and returns the original pointer.
- **Control Flow**:
    - Check if the size `sz` is zero using the `FD_UNLIKELY` macro; if true, return the pointer `p` immediately as no operation is needed.
    - Call the [`fd_base64_encode`](fd_base64.c.driver.md#fd_base64_encode) function to encode the input data `s` of size `sz` into Base64 format, storing the result in the buffer pointed to by `p`.
    - Calculate the number of characters written by [`fd_base64_encode`](fd_base64.c.driver.md#fd_base64_encode) and store it in `n`.
    - Return the pointer `p` incremented by `n`, which points to the position right after the last written character in the buffer.
- **Output**: The function returns a pointer to the position in the buffer `p` immediately following the last character of the newly appended Base64 encoded data.
- **Functions called**:
    - [`fd_base64_encode`](fd_base64.c.driver.md#fd_base64_encode)


# Function Declarations (Public API)

---
### fd\_base64\_encode<!-- {{#callable_declaration:fd_base64_encode}} -->
Encodes binary data into Base64 format.
- **Description**: This function encodes a given block of binary data into Base64 format using the standard Base64 alphabet as specified in RFC 4648, including padding. It writes the encoded result to the provided output buffer but does not append a null terminator, so the output will not be a valid C string. The function returns the number of characters written to the output buffer. It is important to ensure that the output buffer is large enough to hold the encoded data, which can be calculated using the FD_BASE64_ENC_SZ macro. This function should be used when you need to convert binary data into a Base64 encoded string for transmission or storage.
- **Inputs**:
    - `out`: A pointer to a character array where the Base64 encoded output will be written. The caller must ensure this buffer is large enough to hold the encoded data, which can be determined using FD_BASE64_ENC_SZ(in_sz). The buffer must not be null.
    - `in`: A pointer to the binary data to be encoded. The data is treated as a constant and will not be modified. The pointer must not be null.
    - `in_sz`: The size in bytes of the binary data to be encoded. It must be a non-negative value.
- **Output**: Returns the number of Base64 characters written to the output buffer.
- **See also**: [`fd_base64_encode`](fd_base64.c.driver.md#fd_base64_encode)  (Implementation)


---
### fd\_base64\_decode<!-- {{#callable_declaration:fd_base64_decode}} -->
Decodes Base64 encoded data into binary format.
- **Description**: This function decodes a Base64 encoded input string into its binary representation, writing the result to the specified output buffer. It should be used when you need to convert Base64 data back to its original binary form. The input length must be a multiple of 4, as Base64 encoding represents data in 4-character blocks. The function handles standard Base64 padding, but will return an error if the input is improperly padded or contains invalid characters. It is important to ensure that the output buffer is large enough to hold the decoded data, which can be calculated using the FD_BASE64_DEC_SZ macro.
- **Inputs**:
    - `out`: A pointer to the buffer where the decoded binary data will be written. The buffer must be large enough to hold the decoded data, which can be determined using FD_BASE64_DEC_SZ(in_sz). The caller retains ownership and must ensure the buffer is valid.
    - `in`: A pointer to the Base64 encoded input string. The string must be properly padded and contain only valid Base64 characters. The caller retains ownership and the string must be null-terminated.
    - `in_sz`: The length of the Base64 encoded input string. It must be a multiple of 4, as Base64 encoding uses 4-character blocks. If this condition is not met, the function will return an error.
- **Output**: Returns the number of bytes written to the output buffer on success, or -1L if the input is invalid or improperly padded.
- **See also**: [`fd_base64_decode`](fd_base64.c.driver.md#fd_base64_decode)  (Implementation)


