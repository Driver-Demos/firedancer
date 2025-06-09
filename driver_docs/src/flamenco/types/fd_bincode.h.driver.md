# Purpose
The provided C header file, `fd_bincode.h`, is part of a utility library designed for encoding and decoding binary data. It defines a set of macros and inline functions that facilitate the serialization and deserialization of primitive data types and more complex structures using a binary encoding scheme. The file includes context structures for encoding (`fd_bincode_encode_ctx_t`) and decoding (`fd_bincode_decode_ctx_t`), which manage the current position and boundaries within a data buffer. This ensures that operations do not exceed the buffer limits, preventing overflow and underflow errors.

The file provides a series of macros, such as `FD_BINCODE_PRIMITIVE_STUBS`, to generate functions for encoding and decoding various primitive types like `uint8`, `uint16`, `uint32`, `uint64`, and `double`. It also includes specialized functions for handling boolean values, byte arrays, and compact and variable-length integer encodings. The header defines error codes for common issues encountered during encoding and decoding, such as buffer overflows and invalid encodings. Additionally, it offers convenience macros for decoding data into specific memory regions, such as a scratch space or a spad (a specialized memory allocator), ensuring efficient memory management during the serialization process. Overall, this header file is a comprehensive tool for binary data manipulation, providing a robust API for developers working with binary serialization in C.
# Imports and Dependencies

---
- `../../util/fd_util.h`
- `../../util/valloc/fd_valloc.h`


# Data Structures

---
### fd\_bincode\_encode\_ctx
- **Type**: `struct`
- **Members**:
    - `data`: A pointer to the current position in the data buffer.
    - `dataend`: A pointer to the end of the data buffer.
    - `wksp`: A pointer to a workspace structure, likely used for memory management.
- **Description**: The `fd_bincode_encode_ctx` structure is used as a context for encoding operations, providing pointers to the current position and end of a data buffer, as well as a workspace for managing memory. This context is essential for ensuring that encoding operations do not exceed buffer boundaries and for managing the memory space used during encoding.


---
### fd\_bincode\_encode\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `data`: A pointer to the current position in the data buffer for encoding.
    - `dataend`: A pointer to the end of the data buffer, marking the limit for encoding operations.
    - `wksp`: A pointer to a workspace structure used during encoding operations.
- **Description**: The `fd_bincode_encode_ctx_t` structure is used as a context for encoding operations, providing pointers to the current position and end of a data buffer, as well as a workspace pointer. This context is essential for managing the state and boundaries of the buffer during encoding processes, ensuring that data is written correctly and efficiently without exceeding buffer limits.


---
### fd\_bincode\_decode\_ctx
- **Type**: `struct`
- **Members**:
    - `data`: A pointer to the current position in the data buffer being decoded.
    - `dataend`: A pointer to the end of the data buffer, marking the limit for decoding operations.
- **Description**: The `fd_bincode_decode_ctx` structure is used as a context for decoding operations in a binary encoding/decoding system. It maintains pointers to the current position and the end of a data buffer, allowing functions to safely decode data without exceeding buffer boundaries. This structure is essential for managing the state of the decoding process, ensuring that data is read correctly and efficiently from the buffer.


---
### fd\_bincode\_decode\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `data`: A pointer to the current position in the data buffer for decoding.
    - `dataend`: A pointer to the end of the data buffer, marking the limit for decoding operations.
- **Description**: The `fd_bincode_decode_ctx_t` structure is used as a context for decoding operations, providing pointers to the current position and the end of a data buffer. This context is essential for managing the state during the decoding process, ensuring that data is read correctly and within bounds. It is part of a larger framework for encoding and decoding binary data, facilitating operations like reading primitive types and handling errors such as buffer underflow.


# Functions

---
### fd\_bincode\_bool\_decode<!-- {{#callable:fd_bincode_bool_decode}} -->
The `fd_bincode_bool_decode` function decodes a boolean value from a binary data stream, ensuring the data is valid and updating the context to reflect the new data position.
- **Inputs**:
    - `self`: A pointer to an unsigned character where the decoded boolean value will be stored.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that contains the current position and end of the data buffer for decoding.
- **Control Flow**:
    - Initialize a pointer `ptr` to the current data position in the context `ctx`.
    - Check if there is at least one byte available in the data buffer; if not, return `FD_BINCODE_ERR_UNDERFLOW`.
    - Check if the byte at `ptr` is a valid boolean encoding (i.e., it should be either 0 or 1); if not, return `FD_BINCODE_ERR_ENCODING`.
    - Store the value at `ptr` into `self` and advance the data position in `ctx` by one byte.
    - Return `FD_BINCODE_SUCCESS` to indicate successful decoding.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on success, `FD_BINCODE_ERR_UNDERFLOW` if there is not enough data, or `FD_BINCODE_ERR_ENCODING` if the data is not a valid boolean encoding.


---
### fd\_bincode\_bool\_decode\_footprint<!-- {{#callable:fd_bincode_bool_decode_footprint}} -->
The `fd_bincode_bool_decode_footprint` function checks if a boolean value can be decoded from the current position in the data buffer without actually decoding it, updating the context to reflect the footprint of the operation.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bincode_decode_ctx_t` structure, which contains the current position in the data buffer and the end of the buffer.
- **Control Flow**:
    - Convert the current data position in the context to a `uchar` pointer named `ptr`.
    - Check if there is at least one byte available in the buffer by comparing `ptr + 1` with `ctx->dataend`; if not, return `FD_BINCODE_ERR_UNDERFLOW`.
    - Check if the byte at `ptr` is a valid boolean encoding (i.e., it should be either 0 or 1); if not, return `FD_BINCODE_ERR_ENCODING`.
    - Update the context's data position to `ptr + 1` to reflect the footprint of reading a boolean value.
    - Return `FD_BINCODE_SUCCESS` to indicate the operation was successful.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on success, `FD_BINCODE_ERR_UNDERFLOW` if there is not enough data, or `FD_BINCODE_ERR_ENCODING` if the data is not a valid boolean encoding.


---
### fd\_bincode\_bool\_decode\_unsafe<!-- {{#callable:fd_bincode_bool_decode_unsafe}} -->
The `fd_bincode_bool_decode_unsafe` function decodes a boolean value from a binary context without performing safety checks.
- **Inputs**:
    - `self`: A pointer to an unsigned character where the decoded boolean value will be stored.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that contains the current position and end of the data buffer for decoding.
- **Control Flow**:
    - The function calls `fd_bincode_uint8_decode_unsafe` with the provided `self` and `ctx` arguments.
    - No additional logic or safety checks are performed within this function.
- **Output**: The function does not return a value; it modifies the data at the location pointed to by `self`.


---
### fd\_bincode\_bool\_encode<!-- {{#callable:fd_bincode_bool_encode}} -->
The `fd_bincode_bool_encode` function encodes a boolean value into a binary format and updates the encoding context.
- **Inputs**:
    - `self`: A `uchar` representing the boolean value to be encoded, where any non-zero value is considered `true`.
    - `ctx`: A pointer to `fd_bincode_encode_ctx_t`, which contains the current position in the data buffer and the end of the buffer.
- **Control Flow**:
    - Convert the boolean `self` to a binary representation using `!!self`, which results in `1` for true and `0` for false.
    - Check if there is enough space in the buffer to write one byte by comparing the current position plus one with the end of the buffer.
    - If there is not enough space, return `FD_BINCODE_ERR_OVERFLOW`.
    - If there is enough space, write the binary representation of the boolean to the current position in the buffer.
    - Update the current position in the buffer to point to the next byte.
    - Return `FD_BINCODE_SUCCESS` to indicate successful encoding.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on success or `FD_BINCODE_ERR_OVERFLOW` if there is not enough space in the buffer.


---
### fd\_bincode\_bytes\_decode<!-- {{#callable:fd_bincode_bytes_decode}} -->
The `fd_bincode_bytes_decode` function decodes a specified number of bytes from a data buffer into a destination buffer, updating the context to reflect the new position in the data buffer.
- **Inputs**:
    - `self`: A pointer to the destination buffer where the decoded bytes will be stored.
    - `len`: The number of bytes to decode from the data buffer.
    - `ctx`: A pointer to the `fd_bincode_decode_ctx_t` structure, which contains the current position and end of the data buffer.
- **Control Flow**:
    - Retrieve the current position in the data buffer from `ctx->data` and store it in `ptr`.
    - Check if the remaining bytes in the data buffer are less than `len` using a wrap-around safe comparison; if true, return `FD_BINCODE_ERR_UNDERFLOW`.
    - Copy `len` bytes from `ptr` to `self` using `fd_memcpy`.
    - Update the current position in the data buffer by advancing `ctx->data` by `len` bytes.
    - Return `FD_BINCODE_SUCCESS` to indicate successful decoding.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on success or `FD_BINCODE_ERR_UNDERFLOW` if there are not enough bytes in the buffer to decode.


---
### fd\_bincode\_bytes\_decode\_footprint<!-- {{#callable:fd_bincode_bytes_decode_footprint}} -->
The `fd_bincode_bytes_decode_footprint` function checks if a specified number of bytes can be safely read from a data buffer without exceeding its bounds and updates the buffer's current position if successful.
- **Inputs**:
    - `len`: The number of bytes to check for availability in the buffer.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure, which contains the current position and end of the data buffer.
- **Control Flow**:
    - Convert the current data position in the context to a `uchar` pointer `ptr`.
    - Check if the remaining bytes in the buffer (from `ptr` to `dataend`) are less than `len`.
    - If the check fails, return `FD_BINCODE_ERR_UNDERFLOW` indicating an underflow error.
    - If the check passes, update the current data position in the context by adding `len` to `ptr`.
    - Return `FD_BINCODE_SUCCESS` indicating successful operation.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` if the operation is successful, or `FD_BINCODE_ERR_UNDERFLOW` if there is not enough data to read.


---
### fd\_bincode\_bytes\_decode\_unsafe<!-- {{#callable:fd_bincode_bytes_decode_unsafe}} -->
The `fd_bincode_bytes_decode_unsafe` function copies a specified number of bytes from a decoding context's data buffer to a destination buffer without performing any safety checks.
- **Inputs**:
    - `self`: A pointer to the destination buffer where the decoded bytes will be copied.
    - `len`: The number of bytes to copy from the context's data buffer to the destination buffer.
    - `ctx`: A pointer to the `fd_bincode_decode_ctx_t` structure, which contains the current position in the data buffer and the end of the buffer.
- **Control Flow**:
    - Retrieve the current position in the data buffer from the context and store it in a local pointer `ptr`.
    - Use `fd_memcpy` to copy `len` bytes from `ptr` to the destination buffer `self`.
    - Update the context's data pointer to point to the position immediately after the copied bytes.
- **Output**: This function does not return a value; it performs the copy operation directly on the provided buffers.


---
### fd\_bincode\_bytes\_encode<!-- {{#callable:fd_bincode_bytes_encode}} -->
The `fd_bincode_bytes_encode` function encodes a byte array into a buffer, ensuring it does not exceed the buffer's capacity.
- **Inputs**:
    - `self`: A pointer to the byte array to be encoded.
    - `len`: The length of the byte array to be encoded.
    - `ctx`: A pointer to the encoding context, which contains the current position in the data buffer and the end of the buffer.
- **Control Flow**:
    - The function first checks the memory safety of the input byte array using `fd_msan_check`.
    - It then calculates the pointer to the current position in the data buffer from the context.
    - The function checks if adding the byte array to the current position would exceed the buffer's end; if so, it returns an overflow error.
    - If there is enough space, it copies the byte array into the buffer at the current position.
    - The context's data pointer is updated to point to the new position after the copied data.
    - Finally, the function returns a success code.
- **Output**: The function returns an integer status code, `FD_BINCODE_SUCCESS` on success or `FD_BINCODE_ERR_OVERFLOW` if the buffer is exceeded.


---
### fd\_bincode\_compact\_u16\_decode<!-- {{#callable:fd_bincode_compact_u16_decode}} -->
The `fd_bincode_compact_u16_decode` function decodes a compactly encoded 16-bit unsigned integer from a data buffer, updating the buffer context and handling potential errors.
- **Inputs**:
    - `self`: A pointer to a `ushort` where the decoded value will be stored.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that contains the current position and end of the data buffer.
- **Control Flow**:
    - Check if the data pointer in the context is NULL, returning an underflow error if true.
    - Attempt to decode a single-byte value if the next byte is within bounds and its most significant bit is not set, updating the context and returning success if successful.
    - Attempt to decode a two-byte value if the next two bytes are within bounds and the second byte's most significant bit is not set, checking for non-minimal encoding, updating the context, and returning success if successful.
    - Attempt to decode a three-byte value if the next three bytes are within bounds and the third byte's most significant bits are not set, checking for non-minimal encoding, updating the context, and returning success if successful.
    - Return an underflow error if none of the above conditions are met.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on successful decoding, `FD_BINCODE_ERR_UNDERFLOW` if the buffer is too small, or `FD_BINCODE_ERR_ENCODING` if a non-minimal encoding is detected.


---
### fd\_bincode\_compact\_u16\_decode\_unsafe<!-- {{#callable:fd_bincode_compact_u16_decode_unsafe}} -->
The function `fd_bincode_compact_u16_decode_unsafe` decodes a compactly encoded unsigned 16-bit integer from a data buffer without performing safety checks.
- **Inputs**:
    - `self`: A pointer to a `ushort` where the decoded value will be stored.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that contains the current position in the data buffer.
- **Control Flow**:
    - The function retrieves a pointer to the current position in the data buffer from `ctx->data`.
    - It checks if the most significant bit of the first byte is not set; if true, it assigns the first byte to `*self` and advances the data pointer by one byte.
    - If the first byte's most significant bit is set, it checks the second byte's most significant bit; if not set, it decodes the value using the first two bytes, assigns it to `*self`, and advances the data pointer by two bytes.
    - If both the first and second bytes have their most significant bits set, it decodes the value using the first three bytes, assigns it to `*self`, and advances the data pointer by three bytes.
- **Output**: The function does not return a value; it modifies the `self` and `ctx` parameters to store the decoded value and update the data buffer position, respectively.


---
### fd\_bincode\_compact\_u16\_encode<!-- {{#callable:fd_bincode_compact_u16_encode}} -->
The `fd_bincode_compact_u16_encode` function encodes a 16-bit unsigned integer into a compact binary format, adjusting the number of bytes used based on the value's size.
- **Inputs**:
    - `self`: A pointer to the 16-bit unsigned integer (ushort) to be encoded.
    - `ctx`: A pointer to the `fd_bincode_encode_ctx_t` structure, which contains the current position in the data buffer and the end of the buffer.
- **Control Flow**:
    - The function starts by casting the current data position in the context to a uchar pointer and dereferencing the input ushort value into a ulong variable.
    - It checks if the value is less than 0x80UL; if true, it ensures there is enough space in the buffer for 1 byte, writes the value as a single byte, updates the context's data pointer, and returns success.
    - If the value is not less than 0x80UL but less than 0x4000UL, it checks for space for 2 bytes, writes the value in a two-byte format with the first byte's most significant bit set, updates the context's data pointer, and returns success.
    - If the value is 0x4000UL or greater, it checks for space for 3 bytes, writes the value in a three-byte format with the first two bytes' most significant bits set, updates the context's data pointer, and returns success.
    - If at any point there is insufficient space in the buffer, the function returns an overflow error.
- **Output**: The function returns an integer status code: `FD_BINCODE_SUCCESS` on successful encoding or `FD_BINCODE_ERR_OVERFLOW` if there is insufficient space in the buffer.


---
### fd\_bincode\_compact\_u16\_size<!-- {{#callable:fd_bincode_compact_u16_size}} -->
The `fd_bincode_compact_u16_size` function calculates the number of bytes required to encode a 16-bit unsigned integer in a compact format.
- **Inputs**:
    - `self`: A pointer to a 16-bit unsigned integer (`ushort`) whose compact encoding size is to be determined.
- **Control Flow**:
    - Retrieve the value of the 16-bit unsigned integer pointed to by `self`.
    - Check if the value is less than 0x80 (128 in decimal); if true, return 1 as the size.
    - If the value is not less than 0x80, check if it is less than 0x4000 (16384 in decimal); if true, return 2 as the size.
    - If the value is not less than 0x4000, return 3 as the size.
- **Output**: The function returns an `ulong` representing the number of bytes required to encode the given 16-bit unsigned integer in a compact format.


---
### fd\_bincode\_varint\_decode<!-- {{#callable:fd_bincode_varint_decode}} -->
The `fd_bincode_varint_decode` function decodes a variable-length integer from a buffer using the serde_varint algorithm.
- **Inputs**:
    - `self`: A pointer to an unsigned long where the decoded integer will be stored.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that contains the current position and end of the data buffer.
- **Control Flow**:
    - Initialize `out` to 0 and `shift` to 0.
    - Enter a loop that continues while `shift` is less than 64.
    - Check if the current data position in `ctx` is at or beyond the end of the buffer; if so, return `FD_BINCODE_ERR_UNDERFLOW`.
    - Read a byte from the current data position, increment the data position, and update `out` by OR-ing the byte (masked with 0x7F) shifted left by `shift`.
    - If the most significant bit of the byte is 0, check for encoding errors and, if none, store `out` in `self` and return `FD_BINCODE_SUCCESS`.
    - Increment `shift` by 7 and continue the loop.
    - If the loop exits without returning, return `FD_BINCODE_ERR_ENCODING`.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on successful decoding, `FD_BINCODE_ERR_UNDERFLOW` if the buffer ends prematurely, or `FD_BINCODE_ERR_ENCODING` if the encoding is invalid.


---
### fd\_bincode\_varint\_decode\_footprint<!-- {{#callable:fd_bincode_varint_decode_footprint}} -->
The `fd_bincode_varint_decode_footprint` function calculates the footprint of a variable-length integer encoded using the serde_varint algorithm without actually decoding the integer.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bincode_decode_ctx_t` structure, which contains the current position and end of the data buffer for decoding.
- **Control Flow**:
    - Initialize `out` to 0 and `shift` to 0.
    - Enter a loop that continues while `shift` is less than 64.
    - Check if the current data position is at or beyond the end of the buffer; if so, return `FD_BINCODE_ERR_UNDERFLOW`.
    - Read a byte from the current data position and advance the data pointer by one byte.
    - Update `out` by OR-ing it with the byte value (masked with 0x7F) shifted left by `shift`.
    - Check if the most significant bit of the byte is 0; if so, perform additional checks:
    - - Verify that the shifted `out` value matches the byte value; if not, return `FD_BINCODE_ERR_ENCODING`.
    - - Check for invalid encoding conditions (e.g., zero byte with non-zero shift or non-zero `out`); if found, return `FD_BINCODE_ERR_ENCODING`.
    - If all checks pass, return `FD_BINCODE_SUCCESS`.
    - Increment `shift` by 7 and continue the loop.
    - If the loop exits without returning, return `FD_BINCODE_ERR_ENCODING`.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on success, `FD_BINCODE_ERR_UNDERFLOW` if the buffer is exhausted, or `FD_BINCODE_ERR_ENCODING` if an encoding error is detected.


---
### fd\_bincode\_varint\_decode\_unsafe<!-- {{#callable:fd_bincode_varint_decode_unsafe}} -->
The `fd_bincode_varint_decode_unsafe` function decodes a variable-length integer from a data buffer without performing any safety checks.
- **Inputs**:
    - `self`: A pointer to an unsigned long where the decoded integer will be stored.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that contains the current position in the data buffer and the end of the buffer.
- **Control Flow**:
    - Initialize `out` to 0 and `shift` to 0.
    - Enter an infinite loop to process each byte of the encoded integer.
    - Read a byte from the current position in the data buffer pointed to by `ctx->data`.
    - Advance the data pointer by one byte.
    - Combine the lower 7 bits of the byte with `out`, shifted left by `shift` bits.
    - Check if the most significant bit of the byte is 0, indicating the end of the encoded integer.
    - If the end is reached, store the result in `self` and return.
    - If not, increase `shift` by 7 to process the next byte.
- **Output**: The function outputs the decoded integer by storing it in the location pointed to by `self`.


---
### fd\_bincode\_varint\_encode<!-- {{#callable:fd_bincode_varint_encode}} -->
The `fd_bincode_varint_encode` function encodes an unsigned long integer into a variable-length format and writes it to a buffer, ensuring it does not exceed the buffer's end.
- **Inputs**:
    - `val`: An unsigned long integer to be encoded.
    - `ctx`: A pointer to a `fd_bincode_encode_ctx_t` structure, which contains the current position in the data buffer and the end of the buffer.
- **Control Flow**:
    - Initialize a pointer `ptr` to the current position in the data buffer from `ctx`.
    - Enter an infinite loop to encode the integer `val`.
    - Check if writing another byte would exceed the buffer's end (`ctx->dataend`); if so, return `FD_BINCODE_ERR_OVERFLOW`.
    - If `val` is less than 0x80, write it directly to the buffer, update the buffer position in `ctx`, and return `FD_BINCODE_SUCCESS`.
    - Otherwise, write the lower 7 bits of `val` ORed with 0x80 to indicate more bytes follow, then shift `val` right by 7 bits.
    - Repeat the loop until `val` is fully encoded.
- **Output**: Returns `FD_BINCODE_SUCCESS` on successful encoding, or `FD_BINCODE_ERR_OVERFLOW` if the buffer is exceeded.


---
### fd\_bincode\_varint\_size<!-- {{#callable:fd_bincode_varint_size}} -->
The `fd_bincode_varint_size` function calculates the number of bytes required to encode a given unsigned long integer using a variable-length encoding scheme.
- **Inputs**:
    - `val`: An unsigned long integer representing the value to be encoded.
- **Control Flow**:
    - Initialize a variable `sz` to 0 to keep track of the size in bytes.
    - Enter an infinite loop to process the value `val`.
    - Check if `val` is less than 0x80 (128 in decimal).
    - If true, return `sz + 1` as the size, since the value can be represented in a single byte.
    - If false, increment `sz` by 1 and right-shift `val` by 7 bits to process the next 7 bits in the next iteration.
- **Output**: The function returns an unsigned long integer representing the number of bytes required to encode the input value using the variable-length encoding.


---
### fd\_archive\_encode\_setup\_length<!-- {{#callable:fd_archive_encode_setup_length}} -->
The `fd_archive_encode_setup_length` function prepares a buffer for encoding by reserving space for a length field and updating the context's data pointer.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bincode_encode_ctx_t` structure, which contains the current position and end of the data buffer for encoding.
    - `offset_out`: A pointer to a `void*` where the function will store the current position in the data buffer, which is the location where the length will be written later.
- **Control Flow**:
    - Cast the `ctx->data` pointer to an `uchar*` and store it in `ptr`.
    - Check if there is enough space in the buffer to accommodate a `uint` by comparing `ptr + sizeof(uint)` with `ctx->dataend`.
    - If there is not enough space, return `FD_BINCODE_ERR_OVERFLOW`.
    - Store the current position `ptr` in `offset_out` to mark where the length will be written later.
    - Advance the `ctx->data` pointer by `sizeof(uint)` to reserve space for the length field.
    - Return `FD_BINCODE_SUCCESS` to indicate successful setup.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on success or `FD_BINCODE_ERR_OVERFLOW` if there is not enough space in the buffer.


---
### fd\_archive\_encode\_set\_length<!-- {{#callable:fd_archive_encode_set_length}} -->
The `fd_archive_encode_set_length` function calculates and sets the length of encoded data in a buffer by computing the difference between the current data position and a given offset, then stores this length at the offset location.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bincode_encode_ctx_t` structure, which contains the current position in the data buffer.
    - `offset`: A pointer to a memory location where the length of the encoded data will be stored.
- **Control Flow**:
    - Calculate the length of the encoded data by subtracting the sum of the offset and the size of a `uint` from the current data position in the context.
    - Store the calculated length as a `uint` at the memory location pointed to by `offset`.
    - Return `FD_BINCODE_SUCCESS` to indicate successful execution.
- **Output**: The function returns `FD_BINCODE_SUCCESS`, indicating that the length was successfully set.


---
### fd\_archive\_decode\_setup\_length<!-- {{#callable:fd_archive_decode_setup_length}} -->
The `fd_archive_decode_setup_length` function prepares the decoding context by skipping over a length field and updating the context's data pointer.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bincode_decode_ctx_t` structure, which contains the current position and end of the data buffer for decoding.
    - `offset_out`: A pointer to a `void*` where the function will store the current position of the data pointer before skipping the length field.
- **Control Flow**:
    - Cast the `ctx->data` to an `uchar*` and store it in `ptr`.
    - Check if the data pointer plus the size of a `uint` exceeds the end of the data buffer (`ctx->dataend`).
    - If the check fails, return `FD_BINCODE_ERR_UNDERFLOW` indicating an underflow error.
    - Store the current data pointer (`ptr`) in `offset_out`.
    - Advance the `ctx->data` pointer by the size of a `uint` to skip over the length field.
    - Return `FD_BINCODE_SUCCESS` indicating successful setup.
- **Output**: Returns an integer status code: `FD_BINCODE_SUCCESS` on success or `FD_BINCODE_ERR_UNDERFLOW` if the data buffer is too small to contain a `uint`.


---
### fd\_archive\_decode\_check\_length<!-- {{#callable:fd_archive_decode_check_length}} -->
The `fd_archive_decode_check_length` function verifies if the length of a decoded data segment matches the expected length stored at a given offset.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure, which contains the current position and end of the data buffer being decoded.
    - `offset`: A pointer to a memory location where the expected length of the data segment is stored as a `uint`.
- **Control Flow**:
    - The function retrieves the expected length from the memory location pointed to by `offset` and compares it to the actual length of the data segment, calculated as the difference between the current data position in `ctx` and the position after the `uint` at `offset`.
    - If the lengths do not match, the function returns `FD_BINCODE_ERR_ENCODING` to indicate an encoding error.
    - If the lengths match, the function returns `FD_BINCODE_SUCCESS` to indicate successful verification.
- **Output**: The function returns an integer status code: `FD_BINCODE_SUCCESS` if the lengths match, or `FD_BINCODE_ERR_ENCODING` if they do not.


