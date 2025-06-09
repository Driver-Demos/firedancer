# Purpose
The provided C source code file, `pb_decode.c`, is part of a library designed to decode Protocol Buffers (protobuf) messages using minimal resources. This file implements the core functionality required to interpret and extract data from serialized protobuf messages. It includes functions for reading and decoding various protobuf wire types, such as varints, fixed-length integers, strings, and embedded messages. The code is structured to handle different field types, including optional, required, repeated, and oneof fields, as well as extensions. It also supports memory allocation for dynamic fields when the `PB_ENABLE_MALLOC` flag is enabled.

The file defines several static functions that are internal to the file, ensuring encapsulation and modularity. These functions are responsible for reading data from input streams, handling different wire types, and managing memory for dynamic fields. The code also includes mechanisms for error handling and validation, such as checking for integer overflows and ensuring that required fields are present. Additionally, the file provides support for extensions and submessages, allowing for flexible and extensible message structures. The use of compiler-specific attributes, such as `__attribute__((warn_unused_result))`, helps ensure that function return values are properly checked, enhancing the robustness of the decoding process. Overall, `pb_decode.c` is a critical component of a protobuf decoding library, providing efficient and reliable message parsing capabilities.
# Imports and Dependencies

---
- `pb_firedancer.h`
- `pb_decode.h`
- `pb_common.h`


# Data Structures

---
### pb\_fields\_seen\_t
- **Type**: `struct`
- **Members**:
    - `bitfield`: An array of 32-bit unsigned integers used to track seen fields, with size determined by the maximum number of required fields.
- **Description**: The `pb_fields_seen_t` structure is designed to keep track of which fields have been encountered during the decoding of a Protocol Buffers message. It uses a bitfield array to efficiently store this information, where each bit represents whether a specific field has been seen. The size of the bitfield array is calculated based on the maximum number of required fields (`PB_MAX_REQUIRED_FIELDS`), ensuring that there is enough space to represent each field with a bit. This structure is particularly useful in ensuring that all required fields are present in a message, as it allows for quick checks of field presence.


# Functions

---
### buf\_read<!-- {{#callable:checkreturn::buf_read}} -->
The `buf_read` function reads a specified number of bytes from a stream into a buffer and advances the stream's state.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which data is to be read.
    - `buf`: A pointer to a buffer of type `pb_byte_t` where the read bytes will be stored; can be NULL if the data is to be skipped.
    - `count`: The number of bytes to read from the stream.
- **Control Flow**:
    - The function retrieves the current state of the stream as a source pointer of type `pb_byte_t`.
    - It advances the stream's state by the number of bytes specified by `count`.
    - If the `buf` is not NULL, it copies `count` bytes from the source to the buffer using `memcpy`.
    - The function returns `true` to indicate successful execution.
- **Output**: The function returns a boolean value `true`, indicating successful reading and copying of bytes.


---
### pb\_read<!-- {{#callable:checkreturn::pb_read}} -->
The `pb_read` function reads a specified number of bytes from a protobuf input stream into a buffer, handling various conditions such as skipping bytes and checking for end-of-stream errors.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which bytes are to be read.
    - `buf`: A pointer to a buffer where the read bytes will be stored; can be NULL if bytes are to be skipped.
    - `count`: The number of bytes to read from the stream.
- **Control Flow**:
    - Check if `count` is zero, and return true immediately if so.
    - If `buf` is NULL and the stream's callback is not [`buf_read`](#checkreturnbuf_read), skip the specified number of bytes by reading them into a temporary buffer.
    - Check if the stream has fewer bytes left than `count`, and return an error if so.
    - Use the stream's callback to read the bytes into `buf`, or use [`buf_read`](#checkreturnbuf_read) if `PB_BUFFER_ONLY` is defined.
    - Adjust the `bytes_left` in the stream by subtracting `count`, or set it to zero if fewer bytes are left.
    - Return true if the operation is successful.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the read operation.
- **Functions called**:
    - [`checkreturn::buf_read`](#checkreturnbuf_read)


---
### pb\_readbyte<!-- {{#callable:checkreturn::pb_readbyte}} -->
The `pb_readbyte` function reads a single byte from a protobuf input stream and updates the stream state accordingly.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the byte is to be read.
    - `buf`: A pointer to a `pb_byte_t` where the read byte will be stored; it must not be NULL.
- **Control Flow**:
    - Check if the stream has any bytes left to read; if not, return an error indicating end-of-stream.
    - If the `PB_BUFFER_ONLY` macro is not defined, use the stream's callback function to read a byte into `buf`; if the callback fails, return an error indicating an I/O error.
    - If the `PB_BUFFER_ONLY` macro is defined, directly read a byte from the stream's state into `buf` and advance the stream's state pointer by one byte.
    - Decrement the `bytes_left` counter of the stream to reflect the byte that was read.
    - Return true to indicate successful reading of a byte.
- **Output**: Returns a boolean value `true` if a byte was successfully read, or `false` if an error occurred (e.g., end-of-stream or I/O error).


---
### pb\_istream\_from\_buffer<!-- {{#callable:pb_istream_from_buffer}} -->
The function `pb_istream_from_buffer` initializes a `pb_istream_t` structure from a given buffer and message length for reading protobuf data.
- **Inputs**:
    - `buf`: A pointer to a constant buffer of type `pb_byte_t` which contains the protobuf data to be read.
    - `msglen`: The length of the message in the buffer, specified as a `size_t`.
- **Control Flow**:
    - Declare a `pb_istream_t` variable named `stream` to hold the input stream structure.
    - Declare a union `state` to handle the buffer state, allowing for casting away the const qualifier from `buf`.
    - Set the `callback` function of `stream` to `buf_read` unless `PB_BUFFER_ONLY` is defined, in which case it is set to `NULL`.
    - Assign the `c_state` of the union to `buf` and then assign `state` to `stream.state`.
    - Set `stream.bytes_left` to `msglen` to track the remaining bytes in the stream.
    - If `PB_NO_ERRMSG` is not defined, initialize `stream.errmsg` to `NULL`.
    - Return the initialized `stream`.
- **Output**: A `pb_istream_t` structure initialized with the provided buffer and message length, ready for reading protobuf data.


---
### pb\_decode\_varint32\_eof<!-- {{#callable:checkreturn::pb_decode_varint32_eof}} -->
The `pb_decode_varint32_eof` function decodes a 32-bit varint from a protobuf input stream, handling end-of-file conditions and overflow errors.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the varint is to be decoded.
    - `dest`: A pointer to a `uint32_t` where the decoded varint value will be stored.
    - `eof`: A pointer to a `bool` that will be set to `true` if the end of the stream is reached, otherwise it remains unchanged.
- **Control Flow**:
    - Attempt to read a byte from the stream using [`pb_readbyte`](#checkreturnpb_readbyte); if unsuccessful and the stream is at EOF, set `eof` to true and return false.
    - Check if the byte indicates a single-byte varint (i.e., the most significant bit is 0); if so, store the byte as the result.
    - For multi-byte varints, initialize `result` with the lower 7 bits of the first byte and set `bitpos` to 7.
    - Enter a loop to read subsequent bytes while the most significant bit is set, updating `result` with the lower 7 bits of each byte shifted by `bitpos`.
    - Check for overflow conditions: if `bitpos` is 28, ensure the next byte's upper bits are valid; if `bitpos` is 32 or more, ensure valid sign extension or report overflow.
    - If a valid varint is decoded, store it in `dest` and return true.
- **Output**: Returns `true` if a varint is successfully decoded and stored in `dest`; returns `false` if an error occurs, such as EOF or overflow.
- **Functions called**:
    - [`checkreturn::pb_readbyte`](#checkreturnpb_readbyte)


---
### pb\_decode\_varint32<!-- {{#callable:checkreturn::pb_decode_varint32}} -->
The `pb_decode_varint32` function decodes a 32-bit varint from a protobuf input stream and stores the result in a destination variable.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the varint is to be decoded.
    - `dest`: A pointer to a `uint32_t` variable where the decoded varint value will be stored.
- **Control Flow**:
    - The function calls [`pb_decode_varint32_eof`](#checkreturnpb_decode_varint32_eof) with the `stream`, `dest`, and `NULL` for the `eof` parameter.
    - The [`pb_decode_varint32_eof`](#checkreturnpb_decode_varint32_eof) function reads bytes from the stream to decode the varint, handling both single-byte and multi-byte cases.
    - If the first byte indicates a single-byte varint, it is directly assigned to `result`.
    - For multi-byte varints, it reads additional bytes, shifting and combining them to form the complete varint value.
    - The function checks for overflow conditions and ensures the varint is valid.
    - The decoded varint is stored in the `dest` variable.
    - The function returns `true` if decoding is successful, otherwise `false`.
- **Output**: A boolean value indicating whether the decoding was successful (`true`) or not (`false`).
- **Functions called**:
    - [`checkreturn::pb_decode_varint32_eof`](#checkreturnpb_decode_varint32_eof)


---
### pb\_decode\_varint<!-- {{#callable:checkreturn::pb_decode_varint}} -->
The `pb_decode_varint` function decodes a variable-length integer from a protobuf input stream into a 64-bit unsigned integer.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the varint is to be decoded.
    - `dest`: A pointer to a `uint64_t` where the decoded varint will be stored.
- **Control Flow**:
    - Initialize a byte variable `byte`, a bit position counter `bitpos` to 0, and a result variable `result` to 0.
    - Enter a do-while loop that continues as long as the most significant bit of `byte` is set (indicating more bytes to read).
    - In each iteration, read a byte from the stream using [`pb_readbyte`](#checkreturnpb_readbyte); if reading fails, return false.
    - Check for overflow: if `bitpos` is 63 or more and the byte has bits set other than the least significant one, return an overflow error.
    - Update `result` by OR-ing it with the lower 7 bits of `byte` shifted left by `bitpos`.
    - Increment `bitpos` by 7 to prepare for the next byte.
    - Exit the loop when a byte is read with the most significant bit not set, indicating the end of the varint.
    - Store the decoded result in `dest` and return true.
- **Output**: Returns a boolean value: true if the varint was successfully decoded, false if an error occurred (e.g., end-of-stream or varint overflow).
- **Functions called**:
    - [`checkreturn::pb_readbyte`](#checkreturnpb_readbyte)


---
### pb\_skip\_varint<!-- {{#callable:checkreturn::pb_skip_varint}} -->
The `pb_skip_varint` function reads and skips over a varint from a protobuf input stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the varint is to be skipped.
- **Control Flow**:
    - Initialize a `pb_byte_t` variable `byte` to store each byte read from the stream.
    - Enter a do-while loop that continues as long as the most significant bit of `byte` is set (i.e., `byte & 0x80` is true).
    - Inside the loop, call [`pb_read`](#checkreturnpb_read) to read one byte from the stream into `byte`.
    - If [`pb_read`](#checkreturnpb_read) returns false, indicating a read error or end of stream, return false.
    - Exit the loop when a byte is read with the most significant bit not set, indicating the end of the varint.
    - Return true to indicate successful skipping of the varint.
- **Output**: Returns a boolean value: true if the varint was successfully skipped, false if there was an error reading from the stream.
- **Functions called**:
    - [`checkreturn::pb_read`](#checkreturnpb_read)


---
### pb\_skip\_string<!-- {{#callable:checkreturn::pb_skip_string}} -->
The `pb_skip_string` function skips over a string field in a protobuf input stream by reading its length and then advancing the stream by that length.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the string is to be skipped.
- **Control Flow**:
    - Call [`pb_decode_varint32`](#checkreturnpb_decode_varint32) to read the length of the string from the stream.
    - Check if the length is valid by comparing it to its casted size_t equivalent.
    - If the length is invalid, return an error using `PB_RETURN_ERROR`.
    - If the length is valid, call [`pb_read`](#checkreturnpb_read) to skip over the string in the stream by reading the specified number of bytes.
- **Output**: Returns `true` if the string was successfully skipped, otherwise returns `false` if an error occurred.
- **Functions called**:
    - [`checkreturn::pb_decode_varint32`](#checkreturnpb_decode_varint32)
    - [`checkreturn::pb_read`](#checkreturnpb_read)


---
### pb\_decode\_tag<!-- {{#callable:checkreturn::pb_decode_tag}} -->
The `pb_decode_tag` function decodes a protobuf tag from a stream, extracting the wire type and tag number, and indicates if the end of the stream is reached.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the tag is to be decoded.
    - `wire_type`: A pointer to a `pb_wire_type_t` variable where the decoded wire type will be stored.
    - `tag`: A pointer to a `uint32_t` variable where the decoded tag number will be stored.
    - `eof`: A pointer to a `bool` variable that will be set to `true` if the end of the stream is reached during decoding, otherwise `false`.
- **Control Flow**:
    - Initialize `eof` to `false`, `wire_type` to 0, and `tag` to 0.
    - Call [`pb_decode_varint32_eof`](#checkreturnpb_decode_varint32_eof) to decode a varint from the stream into a temporary variable `temp`, updating `eof` if the end of the stream is reached.
    - If [`pb_decode_varint32_eof`](#checkreturnpb_decode_varint32_eof) returns `false`, return `false` to indicate failure.
    - Extract the tag number by right-shifting `temp` by 3 bits and store it in `tag`.
    - Extract the wire type by masking the lower 3 bits of `temp` and store it in `wire_type`.
    - Return `true` to indicate successful decoding.
- **Output**: Returns `true` if the tag is successfully decoded, otherwise `false`.
- **Functions called**:
    - [`checkreturn::pb_decode_varint32_eof`](#checkreturnpb_decode_varint32_eof)


---
### pb\_skip\_field<!-- {{#callable:checkreturn::pb_skip_field}} -->
The `pb_skip_field` function skips over a field in a protobuf input stream based on its wire type.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the field is to be skipped.
    - `wire_type`: A `pb_wire_type_t` value indicating the wire type of the field to be skipped.
- **Control Flow**:
    - The function uses a switch statement to determine the action based on the `wire_type` argument.
    - If the `wire_type` is `PB_WT_VARINT`, it calls [`pb_skip_varint`](#checkreturnpb_skip_varint) to skip a varint field.
    - If the `wire_type` is `PB_WT_64BIT`, it calls [`pb_read`](#checkreturnpb_read) to skip 8 bytes.
    - If the `wire_type` is `PB_WT_STRING`, it calls [`pb_skip_string`](#checkreturnpb_skip_string) to skip a string field.
    - If the `wire_type` is `PB_WT_32BIT`, it calls [`pb_read`](#checkreturnpb_read) to skip 4 bytes.
    - If the `wire_type` is none of the above, it returns an error indicating an invalid wire type.
- **Output**: The function returns a boolean value indicating success (`true`) or failure (`false`) in skipping the field.
- **Functions called**:
    - [`checkreturn::pb_skip_varint`](#checkreturnpb_skip_varint)
    - [`checkreturn::pb_read`](#checkreturnpb_read)
    - [`checkreturn::pb_skip_string`](#checkreturnpb_skip_string)


---
### read\_raw\_value<!-- {{#callable:checkreturn::read_raw_value}} -->
The `read_raw_value` function reads a raw value from a protobuf input stream based on the specified wire type and stores it in a buffer, updating the size of the data read.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which data is read.
    - `wire_type`: A `pb_wire_type_t` value indicating the wire type of the data to be read (e.g., PB_WT_VARINT, PB_WT_64BIT, PB_WT_32BIT).
    - `buf`: A pointer to a buffer where the read data will be stored.
    - `size`: A pointer to a `size_t` variable that initially contains the maximum size of the buffer and is updated to reflect the actual size of the data read.
- **Control Flow**:
    - The function begins by storing the maximum size of the buffer in `max_size`.
    - A switch statement is used to handle different wire types:
    - For `PB_WT_VARINT`, it initializes `*size` to 0 and enters a loop to read bytes until a byte without the continuation bit (0x80) is found, checking for overflow and reading errors.
    - For `PB_WT_64BIT`, it sets `*size` to 8 and reads 8 bytes into the buffer.
    - For `PB_WT_32BIT`, it sets `*size` to 4 and reads 4 bytes into the buffer.
    - For `PB_WT_STRING`, it falls through to the default case, which returns an error indicating an invalid wire type.
    - If an invalid wire type is encountered, the function returns an error.
- **Output**: The function returns a boolean value indicating success (`true`) or failure (`false`) of the read operation.
- **Functions called**:
    - [`checkreturn::pb_read`](#checkreturnpb_read)


---
### pb\_make\_string\_substream<!-- {{#callable:checkreturn::pb_make_string_substream}} -->
The `pb_make_string_substream` function creates a substream from a parent stream by decoding a varint32 length and adjusting the byte limits accordingly.
- **Inputs**:
    - `stream`: A pointer to the parent `pb_istream_t` stream from which the substream is to be created.
    - `substream`: A pointer to a `pb_istream_t` stream where the substream will be stored.
- **Control Flow**:
    - The function begins by declaring a `uint32_t` variable `size` to hold the decoded length of the substream.
    - It calls [`pb_decode_varint32`](#checkreturnpb_decode_varint32) to decode a varint32 from the `stream` and store it in `size`.
    - If decoding fails, the function returns `false`.
    - The `substream` is initialized as a copy of the `stream`.
    - The function checks if `substream->bytes_left` is less than `size`; if true, it returns an error indicating the parent stream is too short.
    - It sets `substream->bytes_left` to `size` and reduces `stream->bytes_left` by `size`.
    - Finally, the function returns `true` indicating successful creation of the substream.
- **Output**: The function returns a boolean value: `true` if the substream is successfully created, or `false` if an error occurs during the process.
- **Functions called**:
    - [`checkreturn::pb_decode_varint32`](#checkreturnpb_decode_varint32)


---
### pb\_close\_string\_substream<!-- {{#callable:checkreturn::pb_close_string_substream}} -->
The `pb_close_string_substream` function finalizes a substream by ensuring all remaining bytes are read and updates the parent stream's state to match the substream's state.
- **Inputs**:
    - `stream`: A pointer to the parent `pb_istream_t` stream structure that will be updated with the substream's state.
    - `substream`: A pointer to the `pb_istream_t` substream structure that is being closed and whose state will be transferred to the parent stream.
- **Control Flow**:
    - Check if the substream has any bytes left to read.
    - If there are bytes left, attempt to read them using [`pb_read`](#checkreturnpb_read); if this fails, return false.
    - Update the parent stream's state to match the substream's state.
    - If error messages are enabled, update the parent stream's error message to match the substream's error message.
    - Return true to indicate successful closure of the substream.
- **Output**: Returns a boolean value: `true` if the substream was successfully closed and its state transferred, or `false` if there was an error reading the remaining bytes.
- **Functions called**:
    - [`checkreturn::pb_read`](#checkreturnpb_read)


---
### decode\_basic\_field<!-- {{#callable:checkreturn::decode_basic_field}} -->
The `decode_basic_field` function decodes a basic field from a protobuf input stream based on the field type and wire type, ensuring the correct wire type is used for each field type.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the field data is read.
    - `wire_type`: A `pb_wire_type_t` value indicating the wire type of the field being decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field iterator, which contains information about the field being decoded, such as its type and data location.
- **Control Flow**:
    - The function begins by switching on the logical type of the field (`PB_LTYPE(field->type)`).
    - For each case, it checks if the provided `wire_type` matches the expected wire type(s) for that field type.
    - If the wire type is incorrect, it returns an error using `PB_RETURN_ERROR`.
    - If the wire type is correct, it calls the appropriate decoding function for the field type, such as [`pb_dec_bool`](#checkreturnpb_dec_bool), [`pb_dec_varint`](#checkreturnpb_dec_varint), [`pb_decode_fixed32`](#pb_decode_fixed32), etc.
    - For `PB_LTYPE_FIXED64`, it includes conditional compilation to handle double-to-float conversion or 64-bit support.
    - If the field type is not recognized, it returns an error indicating an invalid field type.
- **Output**: The function returns a boolean value indicating success (`true`) or failure (`false`) of the decoding operation.
- **Functions called**:
    - [`checkreturn::pb_dec_bool`](#checkreturnpb_dec_bool)
    - [`checkreturn::pb_dec_varint`](#checkreturnpb_dec_varint)
    - [`pb_decode_fixed32`](#pb_decode_fixed32)
    - [`pb_decode_double_as_float`](#pb_decode_double_as_float)
    - [`pb_decode_fixed64`](#pb_decode_fixed64)
    - [`checkreturn::pb_dec_bytes`](#checkreturnpb_dec_bytes)
    - [`checkreturn::pb_dec_string`](#checkreturnpb_dec_string)
    - [`checkreturn::pb_dec_submessage`](#checkreturnpb_dec_submessage)
    - [`checkreturn::pb_dec_fixed_length_bytes`](#checkreturnpb_dec_fixed_length_bytes)


---
### decode\_static\_field<!-- {{#callable:checkreturn::decode_static_field}} -->
The `decode_static_field` function decodes a static field from a protobuf input stream based on its type and wire type, handling required, optional, repeated, and oneof field types.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the field is to be decoded.
    - `wire_type`: A `pb_wire_type_t` value indicating the wire type of the field being decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field iterator for the field to be decoded.
- **Control Flow**:
    - The function begins by switching on the field type using `PB_HTYPE(field->type)`.
    - For `PB_HTYPE_REQUIRED`, it directly calls [`decode_basic_field`](#checkreturndecode_basic_field) to decode the field.
    - For `PB_HTYPE_OPTIONAL`, it sets the field's presence flag to true if `pSize` is not NULL, then calls [`decode_basic_field`](#checkreturndecode_basic_field).
    - For `PB_HTYPE_REPEATED`, it checks if the field is a packed array (wire type is `PB_WT_STRING` and field type is packable), and if so, it creates a substream and decodes each element in a loop, updating the size and data pointers accordingly.
    - If the repeated field is not packed, it checks for array overflow and decodes a single element using [`decode_basic_field`](#checkreturndecode_basic_field).
    - For `PB_HTYPE_ONEOF`, it checks if the field is a submessage and if the current tag does not match the stored tag, it resets the field data and sets default values for submessage fields, then updates the tag and decodes the field using [`decode_basic_field`](#checkreturndecode_basic_field).
    - If the field type is invalid, it returns an error using `PB_RETURN_ERROR`.
- **Output**: The function returns a boolean value indicating success (`true`) or failure (`false`) of the decoding process.
- **Functions called**:
    - [`checkreturn::decode_basic_field`](#checkreturndecode_basic_field)
    - [`checkreturn::pb_make_string_substream`](#checkreturnpb_make_string_substream)
    - [`checkreturn::pb_close_string_substream`](#checkreturnpb_close_string_substream)
    - [`pb_field_iter_begin`](pb_common.c.driver.md#pb_field_iter_begin)
    - [`pb_message_set_to_defaults`](#pb_message_set_to_defaults)


---
### allocate\_field<!-- {{#callable:checkreturn::allocate_field}} -->
The `allocate_field` function allocates or reallocates memory for a field in a protobuf message, ensuring the requested size is valid and handling potential overflow issues.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure, used for error reporting.
    - `pData`: A pointer to a pointer where the allocated memory address will be stored.
    - `data_size`: The size of each element to be allocated.
    - `array_size`: The number of elements to allocate.
- **Control Flow**:
    - Check if `data_size` or `array_size` is zero and return an error if true.
    - For AVR platforms, adjust `data_size` to 2 if both `data_size` and `array_size` are 1 to avoid a known bug.
    - Check for potential multiplication overflow by comparing `data_size` and `array_size` against a calculated limit.
    - If the multiplication of `data_size` and `array_size` would overflow, return an error.
    - Attempt to allocate or reallocate memory using `pb_realloc` for the total size of `array_size * data_size`.
    - If memory allocation fails, return an error.
    - Store the allocated memory pointer in `pData` and return true on success.
- **Output**: Returns `true` if memory allocation is successful, otherwise returns `false` and sets an error message in the stream.


---
### initialize\_pointer\_field<!-- {{#callable:initialize_pointer_field}} -->
The `initialize_pointer_field` function initializes a pointer field in a protobuf message based on its type.
- **Inputs**:
    - `pItem`: A pointer to the item that needs to be initialized.
    - `field`: A pointer to a `pb_field_iter_t` structure that describes the field type and size.
- **Control Flow**:
    - Check if the field type is a string or bytes; if so, set the pointer at `pItem` to NULL.
    - Check if the field type is a submessage; if so, zero out the memory at `pItem` to ensure any callbacks are set to NULL.
- **Output**: The function does not return a value; it modifies the memory pointed to by `pItem`.


---
### decode\_pointer\_field<!-- {{#callable:checkreturn::decode_pointer_field}} -->
The `decode_pointer_field` function decodes a protobuf field that is stored as a pointer, handling memory allocation and initialization for various field types.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which data is being read.
    - `wire_type`: A `pb_wire_type_t` value indicating the wire type of the field being decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field iterator for the field being decoded.
- **Control Flow**:
    - If `PB_ENABLE_MALLOC` is not defined, the function returns an error indicating no malloc support.
    - The function checks the field type using `PB_HTYPE` and handles `REQUIRED`, `OPTIONAL`, and `ONEOF` types by releasing any existing allocation if the field is a submessage and setting the tag for `ONEOF` fields.
    - For `STRING` and `BYTES` types, it sets `pData` to `pField` and calls [`decode_basic_field`](#checkreturndecode_basic_field).
    - For other types, it allocates memory for the field, initializes it, and calls [`decode_basic_field`](#checkreturndecode_basic_field).
    - For `REPEATED` fields, it checks if the wire type is `PB_WT_STRING` and handles packed arrays by creating a substream and decoding each entry, reallocating memory as needed.
    - If the field is not packed, it allocates memory for a single entry, initializes it, and decodes it.
    - If the field type is invalid, it returns an error.
- **Output**: Returns a boolean indicating success (`true`) or failure (`false`) of the decoding process.
- **Functions called**:
    - [`pb_release_single_field`](#pb_release_single_field)
    - [`checkreturn::decode_basic_field`](#checkreturndecode_basic_field)
    - [`checkreturn::allocate_field`](#checkreturnallocate_field)
    - [`initialize_pointer_field`](#initialize_pointer_field)
    - [`checkreturn::pb_make_string_substream`](#checkreturnpb_make_string_substream)
    - [`checkreturn::pb_close_string_substream`](#checkreturnpb_close_string_substream)


---
### decode\_callback\_field<!-- {{#callable:checkreturn::decode_callback_field}} -->
The `decode_callback_field` function processes a protobuf field using a callback function, handling both string and scalar wire types.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which data is read.
    - `wire_type`: A `pb_wire_type_t` value indicating the wire type of the field being processed.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field iterator, which contains metadata about the field being processed.
- **Control Flow**:
    - Check if the field has a callback function; if not, skip the field using [`pb_skip_field`](#checkreturnpb_skip_field) and return the result.
    - If the wire type is `PB_WT_STRING`, create a substream using [`pb_make_string_substream`](#checkreturnpb_make_string_substream) and process it in a loop until all bytes are consumed or an error occurs.
    - Within the loop, call the field's callback function with the substream; if it fails, set an error message and return false.
    - After processing the substream, close it using [`pb_close_string_substream`](#checkreturnpb_close_string_substream) and return true if successful.
    - If the wire type is not `PB_WT_STRING`, read the raw value into a buffer using [`read_raw_value`](#checkreturnread_raw_value), create a substream from the buffer, and call the field's callback function with the substream.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the decoding process.
- **Functions called**:
    - [`checkreturn::pb_skip_field`](#checkreturnpb_skip_field)
    - [`checkreturn::pb_make_string_substream`](#checkreturnpb_make_string_substream)
    - [`checkreturn::pb_close_string_substream`](#checkreturnpb_close_string_substream)
    - [`checkreturn::read_raw_value`](#checkreturnread_raw_value)
    - [`pb_istream_from_buffer`](#pb_istream_from_buffer)


---
### decode\_field<!-- {{#callable:checkreturn::decode_field}} -->
The `decode_field` function decodes a protobuf field from a stream based on its type and wire type, handling static, pointer, and callback field types.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the field data is read.
    - `wire_type`: A `pb_wire_type_t` value indicating the wire type of the field being decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field iterator, which contains information about the field being decoded.
- **Control Flow**:
    - If `PB_ENABLE_MALLOC` is defined and the field is a oneof type, it checks and releases any old data associated with the field using [`pb_release_union_field`](#pb_release_union_field) before proceeding.
    - The function uses a switch statement to determine the field's allocation type (`PB_ATYPE`) and calls the appropriate decoding function: [`decode_static_field`](#checkreturndecode_static_field), [`decode_pointer_field`](#checkreturndecode_pointer_field), or [`decode_callback_field`](#checkreturndecode_callback_field).
    - If the field type is invalid, it returns an error using `PB_RETURN_ERROR`.
- **Output**: Returns a boolean value indicating success (`true`) or failure (`false`) of the decoding operation.
- **Functions called**:
    - [`pb_release_union_field`](#pb_release_union_field)
    - [`checkreturn::decode_static_field`](#checkreturndecode_static_field)
    - [`checkreturn::decode_pointer_field`](#checkreturndecode_pointer_field)
    - [`checkreturn::decode_callback_field`](#checkreturndecode_callback_field)


---
### default\_extension\_decoder<!-- {{#callable:checkreturn::default_extension_decoder}} -->
The `default_extension_decoder` function attempts to decode a protobuf extension field by checking its tag and wire type against the expected values and then decoding the field if they match.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the protobuf data is being read.
    - `extension`: A pointer to a `pb_extension_t` structure representing the extension field to be decoded.
    - `tag`: A `uint32_t` value representing the expected tag of the extension field.
    - `wire_type`: A `pb_wire_type_t` value representing the expected wire type of the extension field.
- **Control Flow**:
    - Initialize a `pb_field_iter_t` iterator to iterate over the fields of the extension.
    - Check if the extension field iterator can be initialized using [`pb_field_iter_begin_extension`](pb_common.c.driver.md#pb_field_iter_begin_extension); if not, return an error indicating an invalid extension.
    - Compare the tag of the iterator with the provided tag and check if the iterator's message is valid; if not, return `true` indicating no decoding is needed.
    - Set the `found` flag of the extension to `true` to indicate that the extension has been found.
    - Call [`decode_field`](#checkreturndecode_field) to decode the field using the provided stream, wire type, and iterator, and return the result.
- **Output**: Returns a `bool` indicating success (`true`) or failure (`false`) of the decoding process.
- **Functions called**:
    - [`pb_field_iter_begin_extension`](pb_common.c.driver.md#pb_field_iter_begin_extension)
    - [`checkreturn::decode_field`](#checkreturndecode_field)


---
### decode\_extension<!-- {{#callable:checkreturn::decode_extension}} -->
The `decode_extension` function attempts to decode an unknown field as an extension field by iterating through a linked list of extensions and using either a custom or default decoder for each.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which data is being read.
    - `tag`: A `uint32_t` representing the tag of the field to be decoded.
    - `wire_type`: A `pb_wire_type_t` representing the wire type of the field to be decoded.
    - `extension`: A pointer to a `pb_extension_t` structure representing the linked list of extensions to be checked for decoding the field.
- **Control Flow**:
    - Initialize `pos` to the current number of bytes left in the stream.
    - Enter a loop that continues as long as `extension` is not NULL and `pos` equals the current number of bytes left in the stream.
    - Within the loop, check if the extension has a custom decode function; if so, use it to attempt decoding the field, otherwise use the [`default_extension_decoder`](#checkreturndefault_extension_decoder).
    - If the decoding fails (status is false), return false immediately.
    - Move to the next extension in the linked list.
    - If the loop completes without returning false, return true indicating successful decoding.
- **Output**: Returns a boolean value indicating whether the decoding of the extension was successful (true) or not (false).
- **Functions called**:
    - [`checkreturn::default_extension_decoder`](#checkreturndefault_extension_decoder)


---
### pb\_field\_set\_to\_default<!-- {{#callable:pb_field_set_to_default}} -->
The `pb_field_set_to_default` function initializes a protobuf field to its default state based on its type and attributes.
- **Inputs**:
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field to be initialized to its default state.
- **Control Flow**:
    - Retrieve the type of the field from the `field` iterator.
    - Check if the field is an extension type using `PB_LTYPE(type) == PB_LTYPE_EXTENSION`.
    - If it is an extension, iterate over each extension and set its `found` flag to false, then recursively set its fields to defaults using [`pb_message_set_to_defaults`](#pb_message_set_to_defaults).
    - If the field is static (`PB_ATYPE(type) == PB_ATYPE_STATIC`), determine if the field needs initialization based on its type (optional, repeated, or oneof).
    - For optional fields, set the `has_field` flag to false but still initialize the field.
    - For repeated or oneof fields, set the array count or which_field to 0 and skip further initialization.
    - If initialization is needed, check if the field is a submessage with default values or callbacks, and initialize it using [`pb_message_set_to_defaults`](#pb_message_set_to_defaults).
    - If not a submessage, initialize the field data to zeros using `memset`.
    - If the field is a pointer type (`PB_ATYPE(type) == PB_ATYPE_POINTER`), set the pointer to NULL and initialize array count to 0 if applicable.
    - If the field is a callback type (`PB_ATYPE(type) == PB_ATYPE_CALLBACK`), do not overwrite the callback.
    - Return true to indicate successful initialization.
- **Output**: A boolean value indicating whether the field was successfully set to its default state (true) or not (false).
- **Functions called**:
    - [`pb_field_iter_begin_extension`](pb_common.c.driver.md#pb_field_iter_begin_extension)
    - [`pb_message_set_to_defaults`](#pb_message_set_to_defaults)
    - [`pb_field_iter_begin`](pb_common.c.driver.md#pb_field_iter_begin)


---
### pb\_message\_set\_to\_defaults<!-- {{#callable:pb_message_set_to_defaults}} -->
The `pb_message_set_to_defaults` function initializes all fields of a protobuf message to their default values, using a field iterator to traverse the message structure.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure, which is an iterator over the fields of a protobuf message.
- **Control Flow**:
    - Initialize a default input stream `defstream` and set initial values for `tag`, `wire_type`, and `eof`.
    - Check if the field descriptor has a default value; if so, create an input stream from the default value buffer and decode the first tag.
    - Iterate over each field using a do-while loop, setting each field to its default value using [`pb_field_set_to_default`](#pb_field_set_to_default).
    - If a default value is available for the current field, decode it from the `defstream` and update the field.
    - Continue to the next field using [`pb_field_iter_next`](pb_common.c.driver.md#pb_field_iter_next) until all fields are processed.
- **Output**: Returns `true` if all fields are successfully set to their default values, otherwise returns `false` if any operation fails.
- **Functions called**:
    - [`pb_istream_from_buffer`](#pb_istream_from_buffer)
    - [`checkreturn::pb_decode_tag`](#checkreturnpb_decode_tag)
    - [`pb_field_set_to_default`](#pb_field_set_to_default)
    - [`checkreturn::decode_field`](#checkreturndecode_field)
    - [`pb_field_iter_next`](pb_common.c.driver.md#pb_field_iter_next)


---
### pb\_decode\_inner<!-- {{#callable:checkreturn::pb_decode_inner}} -->
The `pb_decode_inner` function decodes a protobuf message from a stream into a destination structure, handling extensions, repeated fields, and required fields, while checking for errors and ensuring all required fields are present.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the protobuf message is being decoded.
    - `fields`: A pointer to a `pb_msgdesc_t` structure that describes the fields of the protobuf message to be decoded.
    - `dest_struct`: A pointer to the destination structure where the decoded message will be stored.
    - `flags`: An unsigned integer representing various decoding options, such as whether to initialize the message to default values or handle null-terminated messages.
- **Control Flow**:
    - Initialize variables for tracking extensions, repeated fields, and required fields.
    - Begin iterating over the fields using [`pb_field_iter_begin`](pb_common.c.driver.md#pb_field_iter_begin) and set defaults if the `PB_DECODE_NOINIT` flag is not set.
    - Enter a loop that continues while there are bytes left in the stream.
    - Decode the next tag and wire type from the stream using [`pb_decode_tag`](#checkreturnpb_decode_tag).
    - If the tag is zero and the `PB_DECODE_NULLTERMINATED` flag is set, break the loop; otherwise, return an error.
    - Attempt to find the field corresponding to the tag using [`pb_field_iter_find`](pb_common.c.driver.md#pb_field_iter_find).
    - If the field is not found or is an extension, attempt to decode it as an extension using [`decode_extension`](#checkreturndecode_extension).
    - If the field is found and is a repeated fixed count field, manage its size tracking variables.
    - If the field is required, mark it as seen in the `fields_seen` bitfield.
    - Decode the field using [`decode_field`](#checkreturndecode_field).
    - After the loop, check that all elements of the last decoded fixed count field were present.
    - Check that all required fields were present using the `fields_seen` bitfield.
    - Return true if decoding was successful, or false if any errors occurred.
- **Output**: Returns a boolean value indicating whether the decoding was successful (true) or if an error occurred (false).
- **Functions called**:
    - [`pb_field_iter_begin`](pb_common.c.driver.md#pb_field_iter_begin)
    - [`pb_message_set_to_defaults`](#pb_message_set_to_defaults)
    - [`checkreturn::pb_decode_tag`](#checkreturnpb_decode_tag)
    - [`pb_field_iter_find`](pb_common.c.driver.md#pb_field_iter_find)
    - [`pb_field_iter_find_extension`](pb_common.c.driver.md#pb_field_iter_find_extension)
    - [`checkreturn::decode_extension`](#checkreturndecode_extension)
    - [`checkreturn::pb_skip_field`](#checkreturnpb_skip_field)
    - [`checkreturn::decode_field`](#checkreturndecode_field)


---
### pb\_decode\_ex<!-- {{#callable:checkreturn::pb_decode_ex}} -->
The `pb_decode_ex` function decodes a Protocol Buffers message from an input stream into a destination structure, with optional handling for delimited messages and memory management.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the message is to be decoded.
    - `fields`: A pointer to a `pb_msgdesc_t` structure that describes the fields of the message to be decoded.
    - `dest_struct`: A pointer to the destination structure where the decoded message will be stored.
    - `flags`: An unsigned integer representing flags that modify the decoding behavior, such as `PB_DECODE_DELIMITED` for handling delimited messages.
- **Control Flow**:
    - Check if the `PB_DECODE_DELIMITED` flag is set.
    - If not set, call [`pb_decode_inner`](#checkreturnpb_decode_inner) to decode the message directly from the stream.
    - If set, create a substream using [`pb_make_string_substream`](#checkreturnpb_make_string_substream) to handle the delimited message.
    - Decode the message from the substream using [`pb_decode_inner`](#checkreturnpb_decode_inner).
    - Close the substream using [`pb_close_string_substream`](#checkreturnpb_close_string_substream).
    - If `PB_ENABLE_MALLOC` is defined and decoding fails, release allocated memory using [`pb_release`](#pb_release).
    - Return the status of the decoding operation.
- **Output**: Returns a boolean value indicating the success (`true`) or failure (`false`) of the decoding operation.
- **Functions called**:
    - [`checkreturn::pb_decode_inner`](#checkreturnpb_decode_inner)
    - [`checkreturn::pb_make_string_substream`](#checkreturnpb_make_string_substream)
    - [`checkreturn::pb_close_string_substream`](#checkreturnpb_close_string_substream)
    - [`pb_release`](#pb_release)


---
### pb\_decode<!-- {{#callable:checkreturn::pb_decode}} -->
The `pb_decode` function decodes a protobuf message from an input stream into a destination structure using a specified message descriptor.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the protobuf message is to be decoded.
    - `fields`: A pointer to a `pb_msgdesc_t` structure that describes the fields of the protobuf message to be decoded.
    - `dest_struct`: A pointer to the destination structure where the decoded message will be stored.
- **Control Flow**:
    - Call [`pb_decode_inner`](#checkreturnpb_decode_inner) with the provided stream, fields, and destination structure, along with a flag set to 0, to perform the actual decoding process.
    - If `PB_ENABLE_MALLOC` is defined and the decoding fails, call [`pb_release`](#pb_release) to release any allocated memory associated with the fields in the destination structure.
    - Return the status of the decoding process, which indicates success or failure.
- **Output**: A boolean value indicating whether the decoding was successful (`true`) or not (`false`).
- **Functions called**:
    - [`checkreturn::pb_decode_inner`](#checkreturnpb_decode_inner)
    - [`pb_release`](#pb_release)


---
### pb\_release\_union\_field<!-- {{#callable:pb_release_union_field}} -->
The `pb_release_union_field` function releases any previously stored data in a union field if the new data type differs from the old one.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure, representing the input stream for error reporting.
    - `field`: A pointer to a `pb_field_iter_t` structure, representing the current field in the protobuf message being processed.
- **Control Flow**:
    - Initialize `old_field` as a copy of the current `field` and retrieve the old and new tags from `field`.
    - If `old_tag` is zero, return true as there is no old data to release.
    - If `old_tag` is equal to `new_tag`, return true as the data types are the same and can be merged.
    - Attempt to find the old field using [`pb_field_iter_find`](pb_common.c.driver.md#pb_field_iter_find); if it fails, return an error using `PB_RETURN_ERROR`.
    - Call [`pb_release_single_field`](#pb_release_single_field) to release the old field data.
    - If the field type is a pointer, set the field's pointer and data to NULL to ensure they are valid even if an error occurs.
    - Return true after successfully releasing the old data.
- **Output**: Returns a boolean value indicating success (true) or failure (false) in releasing the old union field data.
- **Functions called**:
    - [`pb_field_iter_find`](pb_common.c.driver.md#pb_field_iter_find)
    - [`pb_release_single_field`](#pb_release_single_field)


---
### pb\_release\_single\_field<!-- {{#callable:pb_release_single_field}} -->
The [`pb_release_single_field`](#pb_release_single_field) function releases memory and resources associated with a single field in a protocol buffer message, handling various field types and structures.
- **Inputs**:
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field to be released.
- **Control Flow**:
    - Retrieve the field type from the `field` iterator.
    - Check if the field is part of a oneof union and if it is not the current field, return immediately.
    - If the field is an extension, iterate through all extensions and recursively release each one.
    - If the field is a submessage and not a callback, determine the number of elements to release based on whether it is repeated or not, and release each submessage.
    - If the field is a pointer type, handle releasing memory for repeated strings or bytes, set the size to 0 if repeated, and free the main pointer.
- **Output**: The function does not return a value; it performs memory release operations on the provided field.
- **Functions called**:
    - [`pb_field_iter_begin_extension`](pb_common.c.driver.md#pb_field_iter_begin_extension)
    - [`pb_release_single_field`](#pb_release_single_field)
    - [`pb_release`](#pb_release)


---
### pb\_release<!-- {{#callable:pb_release}} -->
The `pb_release` function is a placeholder for releasing resources associated with a protobuf message, but it does nothing unless `PB_ENABLE_MALLOC` is defined.
- **Inputs**:
    - `fields`: A pointer to a `pb_msgdesc_t` structure that describes the fields of the protobuf message.
    - `dest_struct`: A pointer to the destination structure where the protobuf message is stored.
- **Control Flow**:
    - The function checks if `PB_ENABLE_MALLOC` is defined.
    - If `PB_ENABLE_MALLOC` is not defined, the function does nothing and simply marks the input parameters as unused to avoid compiler warnings.
- **Output**: The function does not produce any output or return a value.


---
### pb\_decode\_bool<!-- {{#callable:pb_decode_bool}} -->
The `pb_decode_bool` function decodes a boolean value from a protobuf input stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the boolean value is to be decoded.
    - `dest`: A pointer to a boolean variable where the decoded boolean value will be stored.
- **Control Flow**:
    - Call [`pb_decode_varint32`](#checkreturnpb_decode_varint32) to decode a 32-bit varint from the input stream into a local variable `value`.
    - Check if [`pb_decode_varint32`](#checkreturnpb_decode_varint32) returns false, indicating a failure to decode, and return false in that case.
    - Cast the `dest` pointer to a boolean pointer and assign it the result of the expression `(value != 0)`, which evaluates to true if `value` is non-zero and false otherwise.
    - Return true to indicate successful decoding.
- **Output**: Returns a boolean value: true if the decoding was successful, false otherwise.
- **Functions called**:
    - [`checkreturn::pb_decode_varint32`](#checkreturnpb_decode_varint32)


---
### pb\_decode\_svarint<!-- {{#callable:pb_decode_svarint}} -->
The function `pb_decode_svarint` decodes a signed variable-length integer from a protobuf input stream and stores it in a destination variable.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the signed variable-length integer is to be decoded.
    - `dest`: A pointer to a `pb_int64_t` variable where the decoded signed variable-length integer will be stored.
- **Control Flow**:
    - Call [`pb_decode_varint`](#checkreturnpb_decode_varint) to decode an unsigned variable-length integer from the stream into `value`.
    - Check if the least significant bit of `value` is set (i.e., `value & 1`).
    - If the least significant bit is set, compute the signed integer by negating the right-shifted `value` and store it in `dest`.
    - If the least significant bit is not set, simply right-shift `value` and store it in `dest`.
    - Return `true` to indicate successful decoding.
- **Output**: Returns `true` if the signed variable-length integer is successfully decoded and stored in `dest`; otherwise, returns `false` if decoding fails.
- **Functions called**:
    - [`checkreturn::pb_decode_varint`](#checkreturnpb_decode_varint)


---
### pb\_decode\_fixed32<!-- {{#callable:pb_decode_fixed32}} -->
The `pb_decode_fixed32` function reads a 32-bit fixed-length integer from a protobuf input stream and stores it in a destination variable, handling endianness appropriately.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the 32-bit integer is to be read.
    - `dest`: A pointer to a memory location where the decoded 32-bit integer will be stored.
- **Control Flow**:
    - Declare a union `u` with a 32-bit integer and a 4-byte array to facilitate byte manipulation.
    - Attempt to read 4 bytes from the input stream into `u.bytes` using [`pb_read`](#checkreturnpb_read); return `false` if reading fails.
    - Check if the system is little-endian; if so, directly assign `u.fixed32` to the destination.
    - If not little-endian, manually construct the 32-bit integer from the byte array `u.bytes` by shifting and combining the bytes.
    - Return `true` to indicate successful decoding.
- **Output**: Returns a boolean value: `true` if the 32-bit integer was successfully read and decoded, `false` otherwise.
- **Functions called**:
    - [`checkreturn::pb_read`](#checkreturnpb_read)


---
### pb\_decode\_fixed64<!-- {{#callable:pb_decode_fixed64}} -->
The `pb_decode_fixed64` function reads an 8-byte fixed-length value from a protobuf input stream and stores it in a destination variable, handling both little-endian and non-little-endian systems.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the 8-byte fixed-length value is to be read.
    - `dest`: A pointer to a memory location where the decoded 8-byte fixed-length value will be stored.
- **Control Flow**:
    - Declare a union `u` with a `uint64_t` and an 8-byte array to facilitate reading the fixed64 value.
    - Call [`pb_read`](#checkreturnpb_read) to read 8 bytes from the `stream` into `u.bytes`; if this fails, return `false`.
    - Check if the system is little-endian using the `PB_LITTLE_ENDIAN_8BIT` macro.
    - If the system is little-endian, directly assign `u.fixed64` to the destination pointed by `dest`.
    - If the system is not little-endian, manually construct the `uint64_t` value from `u.bytes` by shifting and combining the bytes.
    - Return `true` to indicate successful decoding.
- **Output**: Returns a boolean value: `true` if the 8-byte fixed-length value was successfully read and stored, `false` otherwise.
- **Functions called**:
    - [`checkreturn::pb_read`](#checkreturnpb_read)


---
### pb\_dec\_bool<!-- {{#callable:checkreturn::pb_dec_bool}} -->
The `pb_dec_bool` function decodes a boolean value from a protobuf input stream and stores it in the specified field.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the boolean value is to be decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure that contains the field information where the decoded boolean value will be stored.
- **Control Flow**:
    - The function calls [`pb_decode_bool`](#pb_decode_bool), passing the input stream and the address of the boolean data field from the `field` structure.
    - The [`pb_decode_bool`](#pb_decode_bool) function reads a varint from the stream and interprets it as a boolean value, storing the result in the provided boolean pointer.
    - The result of [`pb_decode_bool`](#pb_decode_bool) is returned as the result of `pb_dec_bool`.
- **Output**: Returns a boolean value indicating success (`true`) or failure (`false`) of the decoding operation.
- **Functions called**:
    - [`pb_decode_bool`](#pb_decode_bool)


---
### pb\_dec\_varint<!-- {{#callable:checkreturn::pb_dec_varint}} -->
The `pb_dec_varint` function decodes a variable-length integer from a protobuf input stream and stores it in the appropriate field, handling both unsigned and signed varint types.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the varint is to be decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field metadata where the decoded varint will be stored.
- **Control Flow**:
    - Check if the field type is unsigned varint (`PB_LTYPE_UVARINT`).
    - If unsigned, decode the varint using [`pb_decode_varint`](#checkreturnpb_decode_varint) and store it in `value`.
    - Cast `value` to the appropriate field size (`pb_uint64_t`, `uint32_t`, `uint_least16_t`, or `uint_least8_t`) and store it in `field->pData`, checking for overflow.
    - If overflow occurs, return an error.
    - If the field type is signed varint (`PB_LTYPE_SVARINT`), decode using [`pb_decode_svarint`](#pb_decode_svarint) into `svalue`.
    - For other varint types, decode using [`pb_decode_varint`](#checkreturnpb_decode_varint) into `value` and cast to `svalue` as `pb_int64_t` or `int32_t` based on field size.
    - Cast `svalue` to the appropriate field size (`pb_int64_t`, `int32_t`, `int_least16_t`, or `int_least8_t`) and store it in `field->pData`, checking for overflow.
    - If overflow occurs, return an error.
    - Return true if decoding and storage are successful.
- **Output**: Returns a boolean value indicating success (`true`) or failure (`false`) of the decoding process.
- **Functions called**:
    - [`checkreturn::pb_decode_varint`](#checkreturnpb_decode_varint)
    - [`pb_decode_svarint`](#pb_decode_svarint)


---
### pb\_dec\_bytes<!-- {{#callable:checkreturn::pb_dec_bytes}} -->
The `pb_dec_bytes` function decodes a byte array from a protobuf input stream into a specified field, handling memory allocation if necessary.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which bytes are to be decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field where the decoded bytes will be stored.
- **Control Flow**:
    - The function begins by decoding a varint from the stream to determine the size of the byte array.
    - It checks if the size exceeds `PB_SIZE_MAX` and returns an error if it does.
    - The function calculates the allocation size using `PB_BYTES_ARRAY_T_ALLOCSIZE(size)` and checks if the size is greater than the allocation size, returning an error if true.
    - If the field type is a pointer and `PB_ENABLE_MALLOC` is defined, it checks if the stream has enough bytes left and attempts to allocate memory for the field, returning an error if allocation fails.
    - If the field type is not a pointer, it checks if the allocation size exceeds the field's data size, returning an error if true.
    - The function sets the size of the destination byte array and reads the specified number of bytes from the stream into the destination.
- **Output**: Returns `true` if the byte array is successfully decoded and stored in the field, otherwise returns `false` if any error occurs during the process.
- **Functions called**:
    - [`checkreturn::pb_decode_varint32`](#checkreturnpb_decode_varint32)
    - [`checkreturn::allocate_field`](#checkreturnallocate_field)
    - [`checkreturn::pb_read`](#checkreturnpb_read)


---
### pb\_dec\_string<!-- {{#callable:checkreturn::pb_dec_string}} -->
The `pb_dec_string` function decodes a string from a protobuf input stream and stores it in a specified field, handling memory allocation if necessary.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the string is to be decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field where the decoded string will be stored.
- **Control Flow**:
    - Attempt to decode a varint32 from the stream to determine the size of the string.
    - Check if the decoded size is valid and not too large.
    - Calculate the allocation size needed, including space for a null terminator.
    - If the field type is a pointer and malloc is enabled, allocate memory for the string; otherwise, check if the field has enough space to store the string.
    - Set the last byte of the destination to null to ensure the string is null-terminated.
    - Read the string from the stream into the destination buffer.
    - If UTF-8 validation is enabled, validate the decoded string to ensure it is valid UTF-8.
    - Return true if all operations are successful, otherwise return false.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the string decoding process.
- **Functions called**:
    - [`checkreturn::pb_decode_varint32`](#checkreturnpb_decode_varint32)
    - [`checkreturn::allocate_field`](#checkreturnallocate_field)
    - [`checkreturn::pb_read`](#checkreturnpb_read)
    - [`pb_validate_utf8`](pb_common.c.driver.md#pb_validate_utf8)


---
### pb\_dec\_submessage<!-- {{#callable:checkreturn::pb_dec_submessage}} -->
The `pb_dec_submessage` function decodes a submessage from a protobuf input stream, handling optional message-level callbacks and ensuring proper submessage initialization and closure.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the submessage is to be decoded.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field descriptor for the submessage, which includes information about the submessage type and data location.
- **Control Flow**:
    - Initialize status to true and submsg_consumed to false, and declare a substream variable.
    - Attempt to create a substream from the main stream using [`pb_make_string_substream`](#checkreturnpb_make_string_substream); return false if unsuccessful.
    - Check if the field's submessage descriptor is NULL; if so, return an error using `PB_RETURN_ERROR`.
    - If the field type indicates a submessage with a callback (`PB_LTYPE_SUBMSG_W_CB`), retrieve the callback and execute it if available, updating status and submsg_consumed accordingly.
    - If the submessage has not been consumed and status is true, decode the submessage contents using [`pb_decode_inner`](#checkreturnpb_decode_inner), with flags set to avoid reinitialization if the field is static and not repeated.
    - Close the substream using [`pb_close_string_substream`](#checkreturnpb_close_string_substream); return false if unsuccessful.
    - Return the final status indicating success or failure of the decoding process.
- **Output**: A boolean value indicating whether the submessage was successfully decoded (true) or if an error occurred (false).
- **Functions called**:
    - [`checkreturn::pb_make_string_substream`](#checkreturnpb_make_string_substream)
    - [`checkreturn::pb_decode_inner`](#checkreturnpb_decode_inner)
    - [`checkreturn::pb_close_string_substream`](#checkreturnpb_close_string_substream)


---
### pb\_dec\_fixed\_length\_bytes<!-- {{#callable:checkreturn::pb_dec_fixed_length_bytes}} -->
The function `pb_dec_fixed_length_bytes` decodes a fixed-length byte array from a protobuf input stream and verifies its size against the expected fixed length.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the bytes are to be read.
    - `field`: A pointer to a `pb_field_iter_t` structure that contains information about the field being decoded, including the expected fixed length and the destination buffer for the decoded bytes.
- **Control Flow**:
    - The function begins by attempting to decode a varint32 from the input stream to determine the size of the byte array.
    - If decoding the varint32 fails, the function returns false, indicating an error.
    - The function checks if the decoded size exceeds `PB_SIZE_MAX`, and if so, it returns an error indicating a bytes overflow.
    - If the size is zero, the function treats it as a special case by setting the destination buffer to all zeros and returns true.
    - The function checks if the decoded size matches the expected fixed length (`field->data_size`); if not, it returns an error indicating an incorrect fixed length bytes size.
    - If the size matches, the function reads the bytes from the stream into the destination buffer and returns the result of this read operation.
- **Output**: The function returns a boolean value indicating success (true) or failure (false) of the decoding operation.
- **Functions called**:
    - [`checkreturn::pb_decode_varint32`](#checkreturnpb_decode_varint32)
    - [`checkreturn::pb_read`](#checkreturnpb_read)


---
### pb\_decode\_double\_as\_float<!-- {{#callable:pb_decode_double_as_float}} -->
The function `pb_decode_double_as_float` decodes a 64-bit double-precision floating-point number from a protobuf stream and converts it to a 32-bit single-precision floating-point number.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the double value is read.
    - `dest`: A pointer to a float where the decoded and converted single-precision floating-point value will be stored.
- **Control Flow**:
    - Attempt to decode a 64-bit fixed-point number from the stream into `value`; return false if unsuccessful.
    - Extract the sign, exponent, and mantissa from the 64-bit `value`.
    - Adjust the exponent and mantissa to fit within the range of a 32-bit float, handling special cases like infinity and zero.
    - Round the mantissa and adjust the exponent if necessary to ensure the mantissa fits within the 23-bit limit of a float.
    - Combine the sign, adjusted exponent, and mantissa into a 32-bit float representation.
    - Store the resulting float in the location pointed to by `dest` and return true.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the decoding and conversion process.
- **Functions called**:
    - [`pb_decode_fixed64`](#pb_decode_fixed64)


# Function Declarations (Public API)

---
### buf\_read<!-- {{#callable_declaration:checkreturn::buf_read}} -->
Reads bytes from a protobuf input stream into a buffer.
- **Description**: Use this function to read a specified number of bytes from a protobuf input stream into a provided buffer. This function is typically used when decoding protobuf messages. It requires a valid input stream and can optionally write the read bytes into a buffer if provided. The function updates the stream's state to reflect the bytes read. It is important to ensure that the stream has enough bytes left to read the requested count to avoid errors.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which bytes are read. The stream must be properly initialized and have enough bytes left to read the specified count.
    - `buf`: A pointer to a buffer where the read bytes will be stored. This can be `NULL` if the bytes do not need to be stored, in which case the function will simply advance the stream's state.
    - `count`: The number of bytes to read from the stream. Must be a non-zero value and less than or equal to the number of bytes left in the stream.
- **Output**: Returns `true` if the bytes are successfully read from the stream, otherwise returns `false` if there is an error such as insufficient bytes in the stream.
- **See also**: [`checkreturn::buf_read`](#checkreturnbuf_read)  (Implementation)


---
### pb\_decode\_varint32\_eof<!-- {{#callable_declaration:checkreturn::pb_decode_varint32_eof}} -->
Decodes a 32-bit varint from a protobuf input stream.
- **Description**: This function reads a 32-bit varint from the provided protobuf input stream and stores the result in the destination variable. It is useful when decoding protobuf messages that contain varint-encoded fields. The function must be called with a valid input stream and a non-null destination pointer. If the end of the stream is reached without reading a complete varint, the function sets the eof flag to true if provided. The function returns false if it encounters an error, such as an overflow or an incomplete varint, and true on successful decoding.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the varint is to be decoded. The stream must be valid and properly initialized.
    - `dest`: A pointer to a uint32_t variable where the decoded varint will be stored. Must not be null.
    - `eof`: An optional pointer to a bool that will be set to true if the end of the stream is reached without reading a complete varint. Can be null if this information is not needed.
- **Output**: Returns true if a varint is successfully decoded and stored in dest, false otherwise. If eof is provided, it is set to true if the end of the stream is reached without a complete varint.
- **See also**: [`checkreturn::pb_decode_varint32_eof`](#checkreturnpb_decode_varint32_eof)  (Implementation)


---
### read\_raw\_value<!-- {{#callable_declaration:checkreturn::read_raw_value}} -->
Reads a raw value from a protobuf input stream.
- **Description**: This function reads a raw value from a protobuf input stream based on the specified wire type and stores it in the provided buffer. It is used to extract raw data for further processing or validation. The function must be called with a valid input stream and a buffer large enough to hold the expected data. It handles different wire types, including varint, 64-bit, and 32-bit, but not string types, which are considered an error. The function updates the size parameter to reflect the actual size of the data read. It returns false if an error occurs, such as an invalid wire type or if the stream cannot be read.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream. Must not be null and should be properly initialized before calling the function.
    - `wire_type`: A pb_wire_type_t value indicating the type of wire format to read. Valid values are PB_WT_VARINT, PB_WT_64BIT, and PB_WT_32BIT. PB_WT_STRING is considered an error.
    - `buf`: A pointer to a buffer where the read data will be stored. Must not be null and should have enough space to hold the data based on the wire type.
    - `size`: A pointer to a size_t variable that initially contains the maximum size of the buffer. It is updated to reflect the actual size of the data read. Must not be null.
- **Output**: Returns a boolean value: true if the data is successfully read, false if an error occurs (e.g., invalid wire type, buffer overflow, or read failure).
- **See also**: [`checkreturn::read_raw_value`](#checkreturnread_raw_value)  (Implementation)


---
### decode\_basic\_field<!-- {{#callable_declaration:checkreturn::decode_basic_field}} -->
Decodes a basic field from a protobuf input stream.
- **Description**: This function is used to decode a basic field from a protobuf input stream based on the specified wire type and field iterator. It should be called when you need to extract a field's value from a protobuf message. The function checks the wire type against the expected type for the field and returns an error if they do not match. It supports various field types such as boolean, varint, fixed32, fixed64, bytes, string, submessage, and fixed-length bytes. The function must be used with a valid input stream and field iterator, and it assumes that the stream is positioned at the start of the field to be decoded.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the field is to be decoded. Must not be null.
    - `wire_type`: The wire type of the field in the stream, which should match the expected wire type for the field being decoded.
    - `field`: A pointer to a pb_field_iter_t structure representing the field iterator for the field to be decoded. Must not be null and should be properly initialized to point to the field in question.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the decoding operation. On failure, an error message is set in the stream.
- **See also**: [`checkreturn::decode_basic_field`](#checkreturndecode_basic_field)  (Implementation)


---
### decode\_static\_field<!-- {{#callable_declaration:checkreturn::decode_static_field}} -->
Decodes a static field from a protobuf stream.
- **Description**: This function is used to decode a static field from a protobuf input stream, handling different field types such as required, optional, repeated, and oneof. It should be called when processing a protobuf message to extract field data according to its type. The function expects the stream to be properly initialized and positioned at the start of the field to decode. It handles various wire types and ensures that the field data is correctly interpreted and stored. The function returns a boolean indicating success or failure, and it is crucial to check this return value to ensure that the decoding process was successful.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the field data is read. Must not be null and should be properly initialized.
    - `wire_type`: A pb_wire_type_t value indicating the wire type of the field being decoded. Must be a valid wire type for the field.
    - `field`: A pointer to a pb_field_iter_t structure representing the field iterator for the field being decoded. Must not be null and should be properly initialized to point to the correct field in the message.
- **Output**: Returns a boolean value: true if the field was successfully decoded, false if an error occurred during decoding.
- **See also**: [`checkreturn::decode_static_field`](#checkreturndecode_static_field)  (Implementation)


---
### decode\_pointer\_field<!-- {{#callable_declaration:checkreturn::decode_pointer_field}} -->
Decodes a pointer field from a protobuf input stream.
- **Description**: This function is used to decode a pointer field from a protobuf input stream, handling various field types such as required, optional, oneof, and repeated fields. It must be called with a valid input stream and field iterator, and is only available when dynamic memory allocation is enabled. The function manages memory allocation for fields and handles duplicate fields by releasing old allocations. It returns false if memory allocation fails or if an invalid field type is encountered.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the field is to be decoded. Must not be null.
    - `wire_type`: The wire type of the field being decoded, which determines how the field is encoded in the stream.
    - `field`: A pointer to a pb_field_iter_t structure that specifies the field to be decoded. Must not be null and should be properly initialized before calling this function.
- **Output**: Returns a boolean value: true if the field was successfully decoded, or false if an error occurred (e.g., memory allocation failure or invalid field type).
- **See also**: [`checkreturn::decode_pointer_field`](#checkreturndecode_pointer_field)  (Implementation)


---
### decode\_callback\_field<!-- {{#callable_declaration:checkreturn::decode_callback_field}} -->
Decodes a field using a callback function if available.
- **Description**: This function is used to decode a field from a protobuf input stream, utilizing a callback function if one is specified in the field's descriptor. It handles both string and non-string wire types, creating a substream for string types to ensure proper decoding. If no callback is available, it skips the field. This function should be used when decoding fields that may have custom processing requirements defined by a callback.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the field is to be decoded. Must not be null.
    - `wire_type`: A `pb_wire_type_t` value indicating the wire type of the field being decoded. Must be a valid wire type.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field iterator, which includes the field descriptor and other metadata. Must not be null and must have a valid descriptor with a potential callback.
- **Output**: Returns `true` if the field is successfully decoded using the callback or skipped; returns `false` if an error occurs during decoding.
- **See also**: [`checkreturn::decode_callback_field`](#checkreturndecode_callback_field)  (Implementation)


---
### decode\_field<!-- {{#callable_declaration:checkreturn::decode_field}} -->
Decodes a protobuf field from the input stream.
- **Description**: Use this function to decode a single field from a protobuf input stream, ensuring that the field is correctly interpreted based on its type. This function should be called when processing each field in a protobuf message. It handles different field types, including static, pointer, and callback fields, and ensures proper memory management for oneof fields if dynamic memory allocation is enabled. The function must be used with a valid input stream and field iterator, and it will return false if an error occurs, such as an invalid field type or memory allocation failure.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the field is to be decoded. Must not be null.
    - `wire_type`: The wire type of the field being decoded, which determines how the field is interpreted.
    - `field`: A pointer to a pb_field_iter_t structure that specifies the field to be decoded. Must not be null and should be properly initialized to point to the correct field in the message.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the decoding operation.
- **See also**: [`checkreturn::decode_field`](#checkreturndecode_field)  (Implementation)


---
### default\_extension\_decoder<!-- {{#callable_declaration:checkreturn::default_extension_decoder}} -->
Decodes a protobuf extension field from the input stream.
- **Description**: This function attempts to decode a protobuf extension field from the provided input stream. It should be used when you need to handle extension fields in a protobuf message. The function checks if the extension matches the expected tag and wire type, and if so, marks the extension as found and decodes the field. It is important to ensure that the stream and extension are properly initialized before calling this function.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the extension field is to be decoded. Must not be null.
    - `extension`: A pointer to a `pb_extension_t` structure representing the extension to be decoded. Must not be null and should be properly initialized.
    - `tag`: A `uint32_t` value representing the expected tag of the extension field. It should match the tag of the extension being decoded.
    - `wire_type`: A `pb_wire_type_t` value representing the expected wire type of the extension field. It should match the wire type of the extension being decoded.
- **Output**: Returns `true` if the extension field is successfully decoded or if the tag does not match; returns `false` if an error occurs during decoding.
- **See also**: [`checkreturn::default_extension_decoder`](#checkreturndefault_extension_decoder)  (Implementation)


---
### decode\_extension<!-- {{#callable_declaration:checkreturn::decode_extension}} -->
Attempts to decode a protobuf extension field.
- **Description**: This function is used to attempt decoding of a protobuf extension field from a given input stream. It should be called when there is a need to process unknown fields as potential extensions. The function iterates over the linked list of extensions and tries to decode the field using each extension's decoder function. If a decoder function is not provided, a default decoder is used. The function returns false if decoding fails for any extension, otherwise it returns true. It is important to ensure that the stream and extension parameters are properly initialized before calling this function.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the extension field is to be decoded. Must not be null and should be properly initialized.
    - `tag`: A uint32_t representing the tag of the field to be decoded. It should be a valid tag value as per the protobuf specification.
    - `wire_type`: A pb_wire_type_t value indicating the wire type of the field to be decoded. It should match the expected wire type for the field.
    - `extension`: A pointer to a pb_extension_t structure representing the linked list of extensions to be checked for decoding. Must not be null and should be properly initialized with at least one extension.
- **Output**: Returns a boolean value: true if the extension field was successfully decoded by any of the extensions, false otherwise.
- **See also**: [`checkreturn::decode_extension`](#checkreturndecode_extension)  (Implementation)


---
### pb\_field\_set\_to\_default<!-- {{#callable_declaration:pb_field_set_to_default}} -->
Sets a protobuf field to its default value.
- **Description**: This function is used to reset a protobuf field to its default state, which is useful when reusing structures or ensuring fields are initialized before use. It handles different field types, including extensions, static fields, pointers, and callbacks, setting them to their respective default values. This function should be called when you need to ensure that a field is in its initial state, especially before decoding new data into it. It returns a boolean indicating success or failure, which should be checked to ensure the operation completed successfully.
- **Inputs**:
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be set to its default value. Must not be null. The function assumes the field is properly initialized and points to a valid protobuf field.
- **Output**: Returns a boolean value: true if the field was successfully set to its default value, false if an error occurred during the process.
- **See also**: [`pb_field_set_to_default`](#pb_field_set_to_default)  (Implementation)


---
### pb\_message\_set\_to\_defaults<!-- {{#callable_declaration:pb_message_set_to_defaults}} -->
Set all fields of a protobuf message to their default values.
- **Description**: This function initializes all fields of a protobuf message to their default values as specified in the message descriptor. It should be called before decoding a message to ensure that all fields are properly initialized. The function iterates over each field in the message, setting it to its default value if specified. If a field has a default value in the descriptor, it is read from a default value stream. The function returns false if any field cannot be set to its default value, indicating an error in the process.
- **Inputs**:
    - `iter`: A pointer to a pb_field_iter_t structure that iterates over the fields of the message. Must not be null and should be properly initialized to point to the message descriptor and data.
- **Output**: Returns true if all fields are successfully set to their default values, false otherwise.
- **See also**: [`pb_message_set_to_defaults`](#pb_message_set_to_defaults)  (Implementation)


---
### pb\_dec\_bool<!-- {{#callable_declaration:checkreturn::pb_dec_bool}} -->
Decodes a boolean value from a protobuf stream.
- **Description**: Use this function to decode a boolean value from a protobuf input stream and store it in the specified field. It is typically called during the decoding process of a protobuf message to handle fields of boolean type. Ensure that the input stream is properly initialized and points to a valid boolean field in the protobuf message. The function expects the field to be of the correct type and will return false if the decoding fails.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the boolean value is to be decoded. Must not be null and should be properly initialized.
    - `field`: A pointer to a pb_field_iter_t structure representing the field where the decoded boolean value will be stored. The field's pData must point to a valid boolean variable.
- **Output**: Returns true if the boolean value is successfully decoded and stored in the field; otherwise, returns false.
- **See also**: [`checkreturn::pb_dec_bool`](#checkreturnpb_dec_bool)  (Implementation)


---
### pb\_dec\_varint<!-- {{#callable_declaration:checkreturn::pb_dec_varint}} -->
Decodes a varint from the input stream into the specified field.
- **Description**: Use this function to decode a varint from a protobuf input stream and store it in the specified field. It handles both unsigned and signed varints, clamping values to fit the field's data size and checking for overflow. This function should be called when a varint field is encountered in the protobuf message. Ensure that the stream and field parameters are valid and properly initialized before calling this function.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the varint is to be decoded. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field where the decoded varint will be stored. Must not be null and should be properly initialized with the correct data type and size.
- **Output**: Returns true if the varint is successfully decoded and stored in the field; false if an error occurs, such as an overflow or invalid data size.
- **See also**: [`checkreturn::pb_dec_varint`](#checkreturnpb_dec_varint)  (Implementation)


---
### pb\_dec\_bytes<!-- {{#callable_declaration:checkreturn::pb_dec_bytes}} -->
Decodes a byte array from a protobuf stream into a field.
- **Description**: This function is used to decode a byte array from a protobuf input stream and store it in the specified field. It should be called when a byte array field is encountered in a protobuf message. The function handles both static and dynamically allocated fields, depending on whether malloc support is enabled. It checks for size constraints and ensures that the byte array does not exceed the maximum allowed size. If the field is a pointer type and malloc support is enabled, it allocates memory for the byte array. The function must be used in a context where the protobuf stream and field iterator are properly initialized and valid.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the byte array is to be decoded. The stream must be valid and properly initialized.
    - `field`: A pointer to a pb_field_iter_t structure representing the field where the decoded byte array will be stored. The field must be valid and properly initialized. If the field is a pointer type, malloc support must be enabled for dynamic allocation.
- **Output**: Returns true if the byte array is successfully decoded and stored in the field; otherwise, returns false if an error occurs, such as size overflow or end-of-stream.
- **See also**: [`checkreturn::pb_dec_bytes`](#checkreturnpb_dec_bytes)  (Implementation)


---
### pb\_dec\_string<!-- {{#callable_declaration:checkreturn::pb_dec_string}} -->
Decodes a string from a protobuf input stream.
- **Description**: Use this function to decode a string field from a protobuf input stream into a specified field. It handles both static and dynamically allocated memory for the string, ensuring that the string is null-terminated. The function must be called with a valid input stream and field iterator. It checks for various error conditions such as end-of-stream, size overflow, and invalid UTF-8 encoding if enabled. This function is typically used within a protobuf decoding process to handle string fields.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the string is to be decoded. Must not be null and should be properly initialized with data to read.
    - `field`: A pointer to a pb_field_iter_t structure representing the field where the decoded string will be stored. Must not be null and should point to a valid field descriptor with appropriate data size or pointer for dynamic allocation.
- **Output**: Returns true if the string is successfully decoded and stored in the field, false otherwise.
- **See also**: [`checkreturn::pb_dec_string`](#checkreturnpb_dec_string)  (Implementation)


---
### pb\_dec\_submessage<!-- {{#callable_declaration:checkreturn::pb_dec_submessage}} -->
Decodes a submessage from a protobuf input stream.
- **Description**: This function is used to decode a submessage from a protobuf input stream, ensuring that the submessage is correctly processed according to its field descriptor. It should be called when a submessage field is encountered during protobuf decoding. The function handles message-level callbacks if present and ensures that the submessage is fully consumed. It is important to ensure that the field descriptor is valid before calling this function.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which the submessage is to be decoded. The stream must be valid and properly initialized.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field descriptor for the submessage. The `submsg_desc` member must not be null, as it describes the submessage structure.
- **Output**: Returns `true` if the submessage is successfully decoded, otherwise returns `false` if an error occurs, such as an invalid field descriptor or an I/O error.
- **See also**: [`checkreturn::pb_dec_submessage`](#checkreturnpb_dec_submessage)  (Implementation)


---
### pb\_dec\_fixed\_length\_bytes<!-- {{#callable_declaration:checkreturn::pb_dec_fixed_length_bytes}} -->
Decodes a fixed-length byte array from a protobuf stream.
- **Description**: Use this function to decode a fixed-length byte array from a protobuf input stream into a specified field. It is essential that the size of the byte array in the stream matches the expected fixed length specified by the field's data size. If the byte array in the stream is empty, the function will initialize the field's data to all zeros. This function should be called when you expect a fixed-length byte array in the protobuf message, and it must be used with care to ensure that the stream and field parameters are correctly set up.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream from which the byte array is to be decoded. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field where the decoded byte array will be stored. The field's data_size must match the expected size of the byte array. Must not be null.
- **Output**: Returns true if the byte array is successfully decoded and matches the expected fixed length; otherwise, returns false.
- **See also**: [`checkreturn::pb_dec_fixed_length_bytes`](#checkreturnpb_dec_fixed_length_bytes)  (Implementation)


---
### pb\_skip\_varint<!-- {{#callable_declaration:checkreturn::pb_skip_varint}} -->
Skips over a varint in the input stream.
- **Description**: Use this function to advance the read position in a protobuf input stream past a varint field without decoding it. This is useful when you want to ignore certain fields in a protobuf message. The function must be called with a valid input stream that has been properly initialized. It will return false if the stream ends before the varint is completely skipped, indicating an error in reading.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream. The stream must be valid and properly initialized. The function will read from this stream to skip the varint.
- **Output**: Returns true if the varint was successfully skipped, or false if an error occurred (e.g., end of stream before completion).
- **See also**: [`checkreturn::pb_skip_varint`](#checkreturnpb_skip_varint)  (Implementation)


---
### pb\_skip\_string<!-- {{#callable_declaration:checkreturn::pb_skip_string}} -->
Skips a string field in a protobuf input stream.
- **Description**: Use this function to skip over a string field in a protobuf input stream when you do not need to process the string's content. This function is useful in scenarios where you want to ignore certain fields in a protobuf message. It must be called with a valid input stream that is positioned at the start of a string field. The function will read the length of the string and advance the stream's position by that length. If the length is too large to handle, or if reading the length fails, the function will return false, indicating an error.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure representing the input stream. The stream must be valid and properly initialized. The function will modify the stream's state to skip over the string field. If the stream is null or improperly initialized, the behavior is undefined.
- **Output**: Returns a boolean value: true if the string was successfully skipped, or false if an error occurred (e.g., if the length is too large or if reading fails).
- **See also**: [`checkreturn::pb_skip_string`](#checkreturnpb_skip_string)  (Implementation)


---
### allocate\_field<!-- {{#callable_declaration:checkreturn::allocate_field}} -->
Allocates or reallocates memory for a field in a protobuf message.
- **Description**: This function is used to allocate or reallocate memory for a field in a protobuf message, ensuring that the memory size is sufficient for the specified data and array sizes. It should be called when dynamic memory allocation is enabled and required for handling fields in protobuf messages. The function checks for invalid sizes and potential multiplication overflows, returning an error if these conditions are met. It is important to note that on failure, the old pointer remains unchanged, and the caller is responsible for freeing the memory even if an error occurs.
- **Inputs**:
    - `stream`: A pointer to a pb_istream_t structure, which represents the input stream. It must not be null and is used for error reporting.
    - `pData`: A pointer to a pointer where the allocated memory address will be stored. It must not be null, and the caller retains ownership of the memory.
    - `data_size`: The size of each data element to be allocated. It must be greater than zero, otherwise an error is returned.
    - `array_size`: The number of elements to allocate. It must be greater than zero, otherwise an error is returned.
- **Output**: Returns true if the allocation is successful; otherwise, returns false and sets an error message in the stream.
- **See also**: [`checkreturn::allocate_field`](#checkreturnallocate_field)  (Implementation)


---
### initialize\_pointer\_field<!-- {{#callable_declaration:initialize_pointer_field}} -->
Initialize a pointer field based on its type.
- **Description**: This function is used to initialize a pointer field within a protobuf message structure. It should be called when setting up fields that are either strings, byte arrays, or submessages. For string and byte array types, the pointer is set to NULL. For submessage types, the memory is zeroed out to ensure any callbacks are set to NULL, with default values to be set later by the decoding process. This function is typically used in environments where dynamic memory allocation is enabled.
- **Inputs**:
    - `pItem`: A pointer to the memory location of the field to be initialized. The caller retains ownership and must ensure it points to valid memory.
    - `field`: A pointer to a pb_field_iter_t structure that describes the field type and size. Must not be null and should be properly initialized to reflect the field's properties.
- **Output**: None
- **See also**: [`initialize_pointer_field`](#initialize_pointer_field)  (Implementation)


---
### pb\_release\_single\_field<!-- {{#callable_declaration:pb_release_single_field}} -->
Releases resources associated with a protobuf field.
- **Description**: Use this function to release any dynamically allocated resources associated with a protobuf field, such as memory for extensions, submessages, or repeated fields. It should be called when you are done with a protobuf message to prevent memory leaks. This function handles different field types, including extensions, submessages, and repeated fields, ensuring that all associated resources are properly freed. It is particularly important in environments where dynamic memory allocation is used.
- **Inputs**:
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field to be released. This parameter must not be null, and it should point to a valid field iterator that has been initialized and used in decoding a protobuf message.
- **Output**: None
- **See also**: [`pb_release_single_field`](#pb_release_single_field)  (Implementation)


