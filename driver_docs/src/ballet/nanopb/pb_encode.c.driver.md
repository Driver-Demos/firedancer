# Purpose
The provided C source code file, `pb_encode.c`, is part of a library designed to encode Protocol Buffers (protobuf) messages using minimal resources. This file implements the encoding functionality for protobuf messages, focusing on efficiency and low memory usage. It includes functions to encode various data types and structures defined in protobuf schemas, such as integers, booleans, strings, bytes, and submessages. The file is structured to handle different field types, including static, pointer, and callback fields, and supports both proto2 and proto3 syntax, ensuring compatibility with different protobuf versions.

Key technical components of this file include the `pb_ostream_t` structure, which represents an output stream for writing encoded data, and a series of static functions that perform the actual encoding of different field types. The file also defines macros and conditional compilation directives to optimize the code for different compilers and platforms, such as handling 64-bit integers and endian-specific operations. The [`pb_encode`](#checkreturnpb_encode) and [`pb_encode_ex`](#checkreturnpb_encode_ex) functions serve as the primary interfaces for encoding entire messages, while helper functions like [`pb_encode_varint`](#checkreturnpb_encode_varint) and [`pb_encode_fixed32`](#checkreturnpb_encode_fixed32) handle specific encoding tasks. This file is intended to be part of a larger library and is not an executable on its own; it is designed to be included and used by other parts of the protobuf encoding library.
# Imports and Dependencies

---
- `pb_firedancer.h`
- `pb_encode.h`
- `pb_common.h`


# Functions

---
### buf\_write<!-- {{#callable:checkreturn::buf_write}} -->
The `buf_write` function writes a specified number of bytes from a buffer to a stream and updates the stream's state.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where data will be written.
    - `buf`: A pointer to a buffer containing the data to be written to the stream.
    - `count`: The number of bytes to write from the buffer to the stream.
- **Control Flow**:
    - Cast the `state` member of the `stream` to a `pb_byte_t*` and store it in `dest`.
    - Update the `state` member of the `stream` to point to the location after the written data by adding `count` to `dest`.
    - Use `memcpy` to copy `count` bytes from `buf` to `dest`.
    - Return `true` to indicate successful writing.
- **Output**: The function returns a boolean value `true` to indicate that the write operation was successful.


---
### pb\_ostream\_from\_buffer<!-- {{#callable:pb_ostream_from_buffer}} -->
The function `pb_ostream_from_buffer` initializes a `pb_ostream_t` structure for writing to a buffer with a specified size.
- **Inputs**:
    - `buf`: A pointer to a buffer of type `pb_byte_t` where the stream will write data.
    - `bufsize`: The size of the buffer, indicating the maximum number of bytes that can be written to the stream.
- **Control Flow**:
    - A `pb_ostream_t` structure named `stream` is declared.
    - If `PB_BUFFER_ONLY` is defined, a static integer `marker` is used to set the `callback` pointer to a non-NULL value to indicate a buffer stream.
    - If `PB_BUFFER_ONLY` is not defined, the `callback` is set to the function `buf_write`.
    - The `state` of the stream is set to the provided buffer `buf`.
    - The `max_size` of the stream is set to the provided `bufsize`.
    - The `bytes_written` field of the stream is initialized to 0.
    - If `PB_NO_ERRMSG` is not defined, the `errmsg` field is initialized to NULL.
    - The initialized `pb_ostream_t` structure is returned.
- **Output**: A `pb_ostream_t` structure initialized for writing to the specified buffer with the given size constraints.


---
### pb\_write<!-- {{#callable:checkreturn::pb_write}} -->
The `pb_write` function writes a specified number of bytes from a buffer to a protobuf output stream, ensuring that the stream does not exceed its maximum size and handling errors appropriately.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where data is to be written.
    - `buf`: A pointer to a buffer containing the bytes to be written to the stream.
    - `count`: The number of bytes to write from the buffer to the stream.
- **Control Flow**:
    - Check if the count is greater than 0 and the stream's callback is not NULL.
    - Verify that adding the count to the current bytes written does not cause an overflow or exceed the stream's maximum size.
    - If the `PB_BUFFER_ONLY` macro is defined, use [`buf_write`](#checkreturnbuf_write) to write the data; otherwise, use the stream's callback function.
    - If writing fails, return an error using `PB_RETURN_ERROR`.
    - Increment the `bytes_written` field of the stream by the count.
    - Return true to indicate successful writing.
- **Output**: Returns a boolean value `true` if the bytes are successfully written to the stream, otherwise it returns an error through `PB_RETURN_ERROR`.
- **Functions called**:
    - [`checkreturn::buf_write`](#checkreturnbuf_write)


---
### safe\_read\_bool<!-- {{#callable:safe_read_bool}} -->
The `safe_read_bool` function safely reads a boolean value from a memory location without causing undefined behavior.
- **Inputs**:
    - `pSize`: A pointer to a memory location from which the boolean value is to be read.
- **Control Flow**:
    - Cast the input pointer `pSize` to a `const char*` pointer `p`.
    - Iterate over each byte in the memory location up to the size of a boolean type.
    - Check if any byte in the memory location is non-zero.
    - If a non-zero byte is found, return `true`.
    - If no non-zero byte is found after checking all bytes, return `false`.
- **Output**: A boolean value indicating whether any byte in the specified memory location is non-zero, interpreted as `true` if any byte is non-zero, otherwise `false`.


---
### encode\_array<!-- {{#callable:checkreturn::encode_array}} -->
The `encode_array` function encodes a static array into a protobuf stream, handling size calculations and packing if applicable.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field descriptor and data to be encoded.
- **Control Flow**:
    - Retrieve the count of elements in the array from `field->pSize`.
    - If the count is zero, return true immediately as there's nothing to encode.
    - Check if the array size exceeds the maximum allowed size for non-pointer types and return an error if it does.
    - If arrays are not unpacked and the field type is packable, encode the array in packed format by first encoding the tag and then the size of the packed data.
    - For fixed-size types (e.g., FIXED32, FIXED64), calculate the total size directly; for others, iterate over the array to calculate the size using a sizing stream.
    - Encode the size of the packed data as a varint and write the data to the stream, handling both fixed and variable types appropriately.
    - If the field type is not packable or arrays are unpacked, iterate over each element, handling pointer-type fields (e.g., strings, bytes) by dereferencing pointers and encoding each element individually.
    - Return true if the encoding process completes successfully.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the encoding process.
- **Functions called**:
    - [`checkreturn::pb_encode_tag`](#checkreturnpb_encode_tag)
    - [`checkreturn::pb_enc_varint`](#checkreturnpb_enc_varint)
    - [`checkreturn::pb_encode_varint`](#checkreturnpb_encode_varint)
    - [`checkreturn::pb_write`](#checkreturnpb_write)
    - [`checkreturn::pb_enc_fixed`](#checkreturnpb_enc_fixed)
    - [`pb_encode_tag_for_field`](#pb_encode_tag_for_field)
    - [`checkreturn::encode_basic_field`](#checkreturnencode_basic_field)


---
### pb\_check\_proto3\_default\_value<!-- {{#callable:checkreturn::pb_check_proto3_default_value}} -->
The function `pb_check_proto3_default_value` checks if a given protobuf field in a proto3 message is set to its default value, which is considered 'zero' or 'empty' for encoding purposes.
- **Inputs**:
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field to be checked.
- **Control Flow**:
    - Determine the field type using `field->type` and check if it is statically allocated (`PB_ATYPE_STATIC`).
    - For static fields, handle different field types: required, repeated, oneof, optional, and fields with default values, returning `false` if they are not at their default state.
    - For singular fields, check if they are simple types (integers/floats), bytes, strings, fixed-length bytes, or submessages, and verify if they are at their default state.
    - For pointer-allocated fields (`PB_ATYPE_POINTER`), check if the data pointer is `NULL`.
    - For callback-allocated fields (`PB_ATYPE_CALLBACK`), check if the field is an extension or if the callback is the default, and verify if they are at their default state.
    - Return `false` as a safe default for any unhandled or special cases.
- **Output**: A boolean value indicating whether the field is at its default value (true) or not (false).
- **Functions called**:
    - [`safe_read_bool`](#safe_read_bool)
    - [`pb_field_iter_begin`](pb_common.c.driver.md#pb_field_iter_begin)
    - [`pb_field_iter_next`](pb_common.c.driver.md#pb_field_iter_next)


---
### encode\_basic\_field<!-- {{#callable:checkreturn::encode_basic_field}} -->
The `encode_basic_field` function encodes a basic protobuf field into a stream based on its type.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field to be encoded, which contains metadata about the field type and data.
- **Control Flow**:
    - Check if the field's data pointer (`pData`) is NULL, and return true if it is, indicating a missing pointer field.
    - Attempt to encode the field's tag using [`pb_encode_tag_for_field`](#pb_encode_tag_for_field); return false if this fails.
    - Use a switch statement to determine the field's type using `PB_LTYPE(field->type)`.
    - For each case in the switch statement, call the appropriate encoding function based on the field type (e.g., [`pb_enc_bool`](#checkreturnpb_enc_bool), [`pb_enc_varint`](#checkreturnpb_enc_varint), etc.).
    - If the field type is not recognized, return an error using `PB_RETURN_ERROR`.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the encoding process.
- **Functions called**:
    - [`pb_encode_tag_for_field`](#pb_encode_tag_for_field)
    - [`checkreturn::pb_enc_bool`](#checkreturnpb_enc_bool)
    - [`checkreturn::pb_enc_varint`](#checkreturnpb_enc_varint)
    - [`checkreturn::pb_enc_fixed`](#checkreturnpb_enc_fixed)
    - [`checkreturn::pb_enc_bytes`](#checkreturnpb_enc_bytes)
    - [`checkreturn::pb_enc_string`](#checkreturnpb_enc_string)
    - [`checkreturn::pb_enc_submessage`](#checkreturnpb_enc_submessage)
    - [`checkreturn::pb_enc_fixed_length_bytes`](#checkreturnpb_enc_fixed_length_bytes)


---
### encode\_callback\_field<!-- {{#callable:checkreturn::encode_callback_field}} -->
The `encode_callback_field` function encodes a field using a user-defined callback function if it is available.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure, which represents the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure, which represents the field to be encoded, including its descriptor and data.
- **Control Flow**:
    - Check if the `field_callback` in the field's descriptor is not NULL.
    - If the `field_callback` is not NULL, call it with NULL, the stream, and the field as arguments.
    - If the callback returns false, return an error using `PB_RETURN_ERROR`.
    - Return true if the callback is NULL or if it executes successfully.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the encoding operation.


---
### encode\_field<!-- {{#callable:checkreturn::encode_field}} -->
The `encode_field` function encodes a protobuf field into a stream, handling different field types and presence conditions.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded field will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field to be encoded, containing metadata and data pointers.
- **Control Flow**:
    - Check if the field is a 'oneof' type and if its tag matches the expected tag; if not, return true to skip encoding.
    - For 'optional' fields, check if the field is present using its size pointer; if not present, return true to skip encoding.
    - If the field data pointer is NULL, check if the field is 'required'; if so, return an error, otherwise return true to skip encoding.
    - Determine the field's allocation type: if it's a callback, call [`encode_callback_field`](#checkreturnencode_callback_field); if it's repeated, call [`encode_array`](#checkreturnencode_array); otherwise, call [`encode_basic_field`](#checkreturnencode_basic_field).
- **Output**: Returns a boolean indicating success (true) or failure (false) of the encoding process.
- **Functions called**:
    - [`safe_read_bool`](#safe_read_bool)
    - [`checkreturn::pb_check_proto3_default_value`](#checkreturnpb_check_proto3_default_value)
    - [`checkreturn::encode_callback_field`](#checkreturnencode_callback_field)
    - [`checkreturn::encode_array`](#checkreturnencode_array)
    - [`checkreturn::encode_basic_field`](#checkreturnencode_basic_field)


---
### default\_extension\_encoder<!-- {{#callable:checkreturn::default_extension_encoder}} -->
The `default_extension_encoder` function encodes a protobuf extension field using a default handler.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure, which represents the output stream where the encoded data will be written.
    - `extension`: A pointer to a `pb_extension_t` structure, which represents the extension field to be encoded.
- **Control Flow**:
    - Initialize a `pb_field_iter_t` iterator to iterate over the fields of the extension.
    - Call [`pb_field_iter_begin_extension_const`](pb_common.c.driver.md#pb_field_iter_begin_extension_const) to start iterating over the extension fields.
    - If the iterator initialization fails, return an error using `PB_RETURN_ERROR`.
    - If the iterator is successfully initialized, call [`encode_field`](#checkreturnencode_field) to encode the field represented by the iterator.
- **Output**: Returns a boolean value indicating success (`true`) or failure (`false`) of the encoding process.
- **Functions called**:
    - [`pb_field_iter_begin_extension_const`](pb_common.c.driver.md#pb_field_iter_begin_extension_const)
    - [`checkreturn::encode_field`](#checkreturnencode_field)


---
### encode\_extension\_field<!-- {{#callable:checkreturn::encode_extension_field}} -->
The `encode_extension_field` function encodes all registered extensions for a given field into a protobuf stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field iterator for the current field being processed.
- **Control Flow**:
    - Retrieve the extension from the field's data pointer.
    - Enter a loop that continues as long as there is an extension to process.
    - Check if the extension has a custom encode function; if so, use it to encode the extension.
    - If no custom encode function is available, use the [`default_extension_encoder`](#checkreturndefault_extension_encoder) to encode the extension.
    - If encoding fails at any point, return false to indicate failure.
    - Move to the next extension in the linked list and repeat the process.
    - Return true if all extensions are successfully encoded.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of encoding all extensions.
- **Functions called**:
    - [`checkreturn::default_extension_encoder`](#checkreturndefault_extension_encoder)


---
### pb\_encode<!-- {{#callable:checkreturn::pb_encode}} -->
The `pb_encode` function encodes a protobuf message from a given structure into a stream using the specified message descriptor.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure that represents the output stream where the encoded message will be written.
    - `fields`: A pointer to a `pb_msgdesc_t` structure that describes the fields of the protobuf message to be encoded.
    - `src_struct`: A pointer to the source structure containing the data to be encoded into the protobuf message.
- **Control Flow**:
    - Initialize a field iterator `iter` using [`pb_field_iter_begin_const`](pb_common.c.driver.md#pb_field_iter_begin_const) with the provided fields and source structure.
    - Check if the message type is empty by evaluating the result of [`pb_field_iter_begin_const`](pb_common.c.driver.md#pb_field_iter_begin_const); if true, return `true`.
    - Iterate over each field in the message using a `do-while` loop with [`pb_field_iter_next`](pb_common.c.driver.md#pb_field_iter_next).
    - For each field, check if it is an extension field using `PB_LTYPE(iter.type) == PB_LTYPE_EXTENSION`.
    - If it is an extension field, call [`encode_extension_field`](#checkreturnencode_extension_field) to encode it; if encoding fails, return `false`.
    - If it is a regular field, call [`encode_field`](#checkreturnencode_field) to encode it; if encoding fails, return `false`.
    - Continue the loop until all fields have been processed.
    - Return `true` after successfully encoding all fields.
- **Output**: The function returns a boolean value `true` if the encoding is successful, or `false` if an error occurs during encoding.
- **Functions called**:
    - [`pb_field_iter_begin_const`](pb_common.c.driver.md#pb_field_iter_begin_const)
    - [`checkreturn::encode_extension_field`](#checkreturnencode_extension_field)
    - [`checkreturn::encode_field`](#checkreturnencode_field)
    - [`pb_field_iter_next`](pb_common.c.driver.md#pb_field_iter_next)


---
### pb\_encode\_ex<!-- {{#callable:checkreturn::pb_encode_ex}} -->
The `pb_encode_ex` function encodes a protobuf message into a stream with optional flags for delimited or null-terminated encoding.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded message will be written.
    - `fields`: A pointer to a `pb_msgdesc_t` structure that describes the fields of the protobuf message to be encoded.
    - `src_struct`: A pointer to the source structure containing the data to be encoded into the protobuf message.
    - `flags`: An unsigned integer representing encoding options, such as `PB_ENCODE_DELIMITED` or `PB_ENCODE_NULLTERMINATED`.
- **Control Flow**:
    - Check if the `flags` argument has the `PB_ENCODE_DELIMITED` bit set.
    - If `PB_ENCODE_DELIMITED` is set, call [`pb_encode_submessage`](#checkreturnpb_encode_submessage) to encode the message as a submessage and return its result.
    - Check if the `flags` argument has the `PB_ENCODE_NULLTERMINATED` bit set.
    - If `PB_ENCODE_NULLTERMINATED` is set, call [`pb_encode`](#checkreturnpb_encode) to encode the message, and if successful, write a null byte to the stream using [`pb_write`](#checkreturnpb_write).
    - If neither flag is set, call [`pb_encode`](#checkreturnpb_encode) to encode the message without any special termination.
- **Output**: Returns a boolean value indicating success (`true`) or failure (`false`) of the encoding process.
- **Functions called**:
    - [`checkreturn::pb_encode_submessage`](#checkreturnpb_encode_submessage)
    - [`checkreturn::pb_encode`](#checkreturnpb_encode)
    - [`checkreturn::pb_write`](#checkreturnpb_write)


---
### pb\_get\_encoded\_size<!-- {{#callable:pb_get_encoded_size}} -->
The `pb_get_encoded_size` function calculates the size of the encoded protobuf message for a given structure and message descriptor.
- **Inputs**:
    - `size`: A pointer to a `size_t` variable where the function will store the calculated size of the encoded message.
    - `fields`: A pointer to a `pb_msgdesc_t` structure that describes the fields of the protobuf message to be encoded.
    - `src_struct`: A pointer to the source structure containing the data to be encoded into the protobuf message.
- **Control Flow**:
    - Initialize a `pb_ostream_t` stream with `PB_OSTREAM_SIZING` to calculate the size without actual encoding.
    - Call [`pb_encode`](#checkreturnpb_encode) with the stream, fields, and source structure to perform the encoding size calculation.
    - If [`pb_encode`](#checkreturnpb_encode) returns false, indicating an error during encoding, return false from the function.
    - If encoding is successful, store the number of bytes written to the stream in the `size` variable.
    - Return true to indicate successful size calculation.
- **Output**: Returns a boolean value: true if the size calculation was successful, false if there was an error during encoding.
- **Functions called**:
    - [`checkreturn::pb_encode`](#checkreturnpb_encode)


---
### pb\_encode\_varint\_32<!-- {{#callable:checkreturn::pb_encode_varint_32}} -->
The `pb_encode_varint_32` function encodes a 32-bit varint from two 32-bit integers (low and high) into a byte buffer and writes it to a protobuf output stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded varint will be written.
    - `low`: A 32-bit unsigned integer representing the lower part of the value to be encoded.
    - `high`: A 32-bit unsigned integer representing the higher part of the value to be encoded.
- **Control Flow**:
    - Initialize a buffer to hold up to 10 bytes and a byte variable to store the least significant 7 bits of the 'low' input.
    - Shift the 'low' input right by 7 bits and enter a loop that continues while there are more bits to encode in 'low' or 'high'.
    - In each iteration, set the most significant bit of the byte to 1 (indicating more bytes follow), store the byte in the buffer, and update the byte with the next 7 bits of 'low'.
    - If 'high' is non-zero, encode its bits by setting the most significant bit of the byte to 1 and shifting 'high' right by 3 bits, continuing until all bits are processed.
    - Store the final byte in the buffer and write the buffer to the output stream using [`pb_write`](#checkreturnpb_write).
- **Output**: Returns a boolean indicating success (true) or failure (false) of writing the encoded varint to the stream.
- **Functions called**:
    - [`checkreturn::pb_write`](#checkreturnpb_write)


---
### pb\_encode\_varint<!-- {{#callable:checkreturn::pb_encode_varint}} -->
The `pb_encode_varint` function encodes a 64-bit unsigned integer into a variable-length format and writes it to a given output stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded varint will be written.
    - `value`: A 64-bit unsigned integer (`pb_uint64_t`) that is to be encoded into a varint format.
- **Control Flow**:
    - Check if the value is less than or equal to 0x7F (127 in decimal).
    - If true, cast the value to a single byte and write it to the stream using [`pb_write`](#checkreturnpb_write).
    - If false, check if the `PB_WITHOUT_64BIT` macro is defined.
    - If `PB_WITHOUT_64BIT` is defined, call [`pb_encode_varint_32`](#checkreturnpb_encode_varint_32) with the value and 0 as arguments.
    - If `PB_WITHOUT_64BIT` is not defined, call [`pb_encode_varint_32`](#checkreturnpb_encode_varint_32) with the lower 32 bits and the upper 32 bits of the value as arguments.
- **Output**: Returns a boolean indicating success (`true`) or failure (`false`) of the encoding operation.
- **Functions called**:
    - [`checkreturn::pb_write`](#checkreturnpb_write)
    - [`checkreturn::pb_encode_varint_32`](#checkreturnpb_encode_varint_32)


---
### pb\_encode\_svarint<!-- {{#callable:checkreturn::pb_encode_svarint}} -->
The `pb_encode_svarint` function encodes a signed integer into a stream using ZigZag encoding and then encodes it as a varint.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded varint will be written.
    - `value`: A signed 64-bit integer (`pb_int64_t`) that is to be encoded using ZigZag encoding.
- **Control Flow**:
    - The function first defines a `pb_uint64_t` variable `zigzagged` to store the ZigZag encoded value.
    - It also defines a `mask` variable to ensure proper integer handling, especially for negative values.
    - If the input `value` is negative, it applies ZigZag encoding by negating the bitwise AND of the value and the mask, then left-shifting by one.
    - If the input `value` is non-negative, it simply left-shifts the value by one to apply ZigZag encoding.
    - Finally, it calls [`pb_encode_varint`](#checkreturnpb_encode_varint) with the stream and the ZigZag encoded value, returning the result of this function call.
- **Output**: The function returns a boolean value indicating the success or failure of encoding the ZigZag encoded integer as a varint into the stream.
- **Functions called**:
    - [`checkreturn::pb_encode_varint`](#checkreturnpb_encode_varint)


---
### pb\_encode\_fixed32<!-- {{#callable:checkreturn::pb_encode_fixed32}} -->
The `pb_encode_fixed32` function encodes a 32-bit fixed-width integer into a protobuf stream, handling both little-endian and non-little-endian systems.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `value`: A pointer to the 32-bit integer value to be encoded and written to the stream.
- **Control Flow**:
    - Check if the system is little-endian and 8-bit, if so, directly write the 4 bytes of the value to the stream using [`pb_write`](#checkreturnpb_write).
    - If not little-endian, extract each byte of the 32-bit integer value manually by shifting and masking, then store them in a byte array.
    - Write the byte array to the stream using [`pb_write`](#checkreturnpb_write).
- **Output**: Returns a boolean indicating success (`true`) or failure (`false`) of the write operation.
- **Functions called**:
    - [`checkreturn::pb_write`](#checkreturnpb_write)


---
### pb\_encode\_fixed64<!-- {{#callable:checkreturn::pb_encode_fixed64}} -->
The `pb_encode_fixed64` function encodes a 64-bit fixed-width integer into a protobuf stream, handling both little-endian and non-little-endian systems.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `value`: A pointer to the 64-bit integer value to be encoded and written to the stream.
- **Control Flow**:
    - Check if the system is little-endian and 8-bit, and if so, directly write the 64-bit value to the stream using [`pb_write`](#checkreturnpb_write).
    - If the system is not little-endian, manually extract each byte from the 64-bit integer, starting from the least significant byte to the most significant byte, and store them in an array.
    - Write the byte array to the stream using [`pb_write`](#checkreturnpb_write).
- **Output**: Returns a boolean value indicating success (`true`) or failure (`false`) of the write operation.
- **Functions called**:
    - [`checkreturn::pb_write`](#checkreturnpb_write)


---
### pb\_encode\_tag<!-- {{#callable:checkreturn::pb_encode_tag}} -->
The `pb_encode_tag` function encodes a Protobuf field tag by combining the field number and wire type into a single varint and writes it to the output stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded tag will be written.
    - `wiretype`: A `pb_wire_type_t` value representing the wire type of the field to be encoded.
    - `field_number`: A `uint32_t` representing the field number of the Protobuf field to be encoded.
- **Control Flow**:
    - Calculate the tag by shifting the field number left by 3 bits and OR-ing it with the wire type.
    - Call [`pb_encode_varint`](#checkreturnpb_encode_varint) to encode the calculated tag as a varint and write it to the provided output stream.
    - Return the result of the [`pb_encode_varint`](#checkreturnpb_encode_varint) function call, indicating success or failure.
- **Output**: A boolean value indicating whether the tag was successfully encoded and written to the stream.
- **Functions called**:
    - [`checkreturn::pb_encode_varint`](#checkreturnpb_encode_varint)


---
### pb\_encode\_tag\_for\_field<!-- {{#callable:pb_encode_tag_for_field}} -->
The `pb_encode_tag_for_field` function encodes a protobuf field tag and wire type into a stream based on the field's type.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded tag will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field whose tag and wire type are to be encoded.
- **Control Flow**:
    - Determine the wire type based on the field's type using a switch statement.
    - For boolean, varint, uvarint, and svarint types, set the wire type to `PB_WT_VARINT`.
    - For fixed32 type, set the wire type to `PB_WT_32BIT`.
    - For fixed64 type, set the wire type to `PB_WT_64BIT`.
    - For bytes, string, submessage, submsg_w_cb, and fixed_length_bytes types, set the wire type to `PB_WT_STRING`.
    - If the field type is invalid, return an error using `PB_RETURN_ERROR`.
    - Call [`pb_encode_tag`](#checkreturnpb_encode_tag) with the determined wire type and the field's tag to encode the tag into the stream.
- **Output**: Returns a boolean indicating success (`true`) or failure (`false`) of the encoding operation.
- **Functions called**:
    - [`checkreturn::pb_encode_tag`](#checkreturnpb_encode_tag)


---
### pb\_encode\_string<!-- {{#callable:checkreturn::pb_encode_string}} -->
The `pb_encode_string` function encodes a string into a protobuf stream by first encoding its length as a varint and then writing the string data to the stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `buffer`: A pointer to a `pb_byte_t` array containing the string data to be encoded.
    - `size`: The size of the string data in bytes.
- **Control Flow**:
    - The function first attempts to encode the size of the string as a varint using [`pb_encode_varint`](#checkreturnpb_encode_varint).
    - If encoding the size fails, the function returns `false`.
    - If encoding the size succeeds, the function proceeds to write the string data to the stream using [`pb_write`](#checkreturnpb_write).
    - The function returns the result of the [`pb_write`](#checkreturnpb_write) operation, which indicates success or failure.
- **Output**: The function returns a boolean value indicating whether the string was successfully encoded and written to the stream.
- **Functions called**:
    - [`checkreturn::pb_encode_varint`](#checkreturnpb_encode_varint)
    - [`checkreturn::pb_write`](#checkreturnpb_write)


---
### pb\_encode\_submessage<!-- {{#callable:checkreturn::pb_encode_submessage}} -->
The `pb_encode_submessage` function encodes a submessage into a protobuf stream, ensuring the size is calculated and verified before writing.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded submessage will be written.
    - `fields`: A pointer to a `pb_msgdesc_t` structure that describes the fields of the submessage to be encoded.
    - `src_struct`: A pointer to the source structure containing the data to be encoded into the submessage.
- **Control Flow**:
    - Initialize a non-writing substream to calculate the size of the submessage.
    - Call [`pb_encode`](#checkreturnpb_encode) to encode the submessage into the substream to determine its size.
    - If encoding fails, propagate the error message and return false.
    - Store the calculated size from the substream.
    - Encode the size as a varint into the main stream.
    - If the stream's callback is NULL, write the size and return, as only sizing is needed.
    - Check if the stream has enough space to accommodate the submessage; if not, return an error.
    - Set up the substream with the main stream's callback, state, and size constraints.
    - Encode the submessage again using the substream to ensure the callback does not exceed the calculated size.
    - Update the main stream's state and bytes written with the substream's results.
    - If the substream's bytes written do not match the calculated size, return an error.
    - Return the status of the encoding operation.
- **Output**: Returns a boolean indicating the success or failure of encoding the submessage.
- **Functions called**:
    - [`checkreturn::pb_encode`](#checkreturnpb_encode)
    - [`checkreturn::pb_encode_varint`](#checkreturnpb_encode_varint)
    - [`checkreturn::pb_write`](#checkreturnpb_write)


---
### pb\_enc\_bool<!-- {{#callable:checkreturn::pb_enc_bool}} -->
The `pb_enc_bool` function encodes a boolean value from a protobuf field into a varint format and writes it to a given output stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the protobuf field containing the boolean data to be encoded.
- **Control Flow**:
    - The function reads the boolean value from the field's data using [`safe_read_bool`](#safe_read_bool) and converts it to a uint32_t value (1 for true, 0 for false).
    - The `PB_UNUSED` macro is used to suppress unused variable warnings for the `field` parameter.
    - The function calls [`pb_encode_varint`](#checkreturnpb_encode_varint) to encode the boolean value as a varint and write it to the output stream.
- **Output**: Returns a boolean indicating success (true) or failure (false) of the encoding operation.
- **Functions called**:
    - [`safe_read_bool`](#safe_read_bool)
    - [`checkreturn::pb_encode_varint`](#checkreturnpb_encode_varint)


---
### pb\_enc\_varint<!-- {{#callable:checkreturn::pb_enc_varint}} -->
The `pb_enc_varint` function encodes a field's data as a varint, handling both unsigned and signed integer types based on the field's type and data size.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded varint will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field to be encoded, containing information about the field's type, data size, and data pointer.
- **Control Flow**:
    - Check if the field type is unsigned varint (`PB_LTYPE_UVARINT`).
    - If unsigned, determine the value based on the data size and cast the data pointer to the appropriate unsigned integer type.
    - If the data size is invalid, return an error using `PB_RETURN_ERROR`.
    - Encode the unsigned integer value using [`pb_encode_varint`](#checkreturnpb_encode_varint).
    - If the field type is not unsigned, treat it as a signed integer.
    - Determine the signed integer value based on the data size and cast the data pointer to the appropriate signed integer type.
    - If the data size is invalid, return an error using `PB_RETURN_ERROR`.
    - If the field type is signed varint (`PB_LTYPE_SVARINT`), encode the value using [`pb_encode_svarint`](#checkreturnpb_encode_svarint).
    - If the field type is not signed varint and the value is negative (only if `PB_WITHOUT_64BIT` is defined), encode using [`pb_encode_varint_32`](#checkreturnpb_encode_varint_32).
    - Otherwise, encode the signed integer value as an unsigned varint using [`pb_encode_varint`](#checkreturnpb_encode_varint).
- **Output**: Returns a boolean indicating success (`true`) or failure (`false`) of the encoding operation.
- **Functions called**:
    - [`checkreturn::pb_encode_varint`](#checkreturnpb_encode_varint)
    - [`checkreturn::pb_encode_svarint`](#checkreturnpb_encode_svarint)
    - [`checkreturn::pb_encode_varint_32`](#checkreturnpb_encode_varint_32)


---
### pb\_enc\_fixed<!-- {{#callable:checkreturn::pb_enc_fixed}} -->
The `pb_enc_fixed` function encodes fixed-size numeric fields into a protobuf stream, handling both 32-bit and 64-bit data sizes.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field to be encoded, which contains information about the data type and size.
- **Control Flow**:
    - Check if `PB_CONVERT_DOUBLE_FLOAT` is defined and if the field is a 32-bit float being encoded as a 64-bit fixed type, then call [`pb_encode_float_as_double`](#pb_encode_float_as_double) to encode it as a double.
    - If the field's data size is 32 bits, call [`pb_encode_fixed32`](#checkreturnpb_encode_fixed32) to encode the data as a 32-bit fixed-size field.
    - If 64-bit support is enabled and the field's data size is 64 bits, call [`pb_encode_fixed64`](#checkreturnpb_encode_fixed64) to encode the data as a 64-bit fixed-size field.
    - If none of the conditions are met, return an error indicating an invalid data size.
- **Output**: Returns a boolean value indicating success (`true`) or failure (`false`) of the encoding operation.
- **Functions called**:
    - [`pb_encode_float_as_double`](#pb_encode_float_as_double)
    - [`checkreturn::pb_encode_fixed32`](#checkreturnpb_encode_fixed32)
    - [`checkreturn::pb_encode_fixed64`](#checkreturnpb_encode_fixed64)


---
### pb\_enc\_bytes<!-- {{#callable:checkreturn::pb_enc_bytes}} -->
The `pb_enc_bytes` function encodes a byte array field into a protobuf stream, handling null pointers and size constraints.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field descriptor and data to be encoded.
- **Control Flow**:
    - Retrieve the byte array from the field's data pointer.
    - Check if the byte array is NULL; if so, encode an empty byte string and return the result.
    - If the field type is static and the byte array size exceeds the allowed size, return an error.
    - Encode the byte array into the stream using [`pb_encode_string`](#checkreturnpb_encode_string) and return the result.
- **Output**: Returns a boolean indicating success (true) or failure (false) of the encoding operation.
- **Functions called**:
    - [`checkreturn::pb_encode_string`](#checkreturnpb_encode_string)


---
### pb\_enc\_string<!-- {{#callable:checkreturn::pb_enc_string}} -->
The `pb_enc_string` function encodes a string field into a protobuf stream, ensuring it is properly terminated and optionally validating UTF-8 encoding.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded string will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field metadata, including the string data and its size.
- **Control Flow**:
    - Initialize `size` to 0 and `max_size` to the field's data size.
    - Check if the field type is a pointer; if so, set `max_size` to the maximum possible size.
    - If the field type is not a pointer, ensure `max_size` allows space for a null terminator and is not zero.
    - If the string pointer `str` is NULL, treat it as an empty string.
    - Otherwise, iterate through the string to calculate its length up to `max_size`, checking for a null terminator.
    - If the string is not null-terminated within `max_size`, return an error.
    - Optionally validate the string as UTF-8 if `PB_VALIDATE_UTF8` is defined.
    - Encode the string using [`pb_encode_string`](#checkreturnpb_encode_string) with the calculated size.
- **Output**: Returns `true` if the string is successfully encoded into the stream, otherwise returns `false` if an error occurs.
- **Functions called**:
    - [`pb_validate_utf8`](pb_common.c.driver.md#pb_validate_utf8)
    - [`checkreturn::pb_encode_string`](#checkreturnpb_encode_string)


---
### pb\_enc\_submessage<!-- {{#callable:checkreturn::pb_enc_submessage}} -->
The `pb_enc_submessage` function encodes a submessage field in a Protocol Buffers stream, handling optional callback encoding if specified.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field descriptor for the submessage to be encoded.
- **Control Flow**:
    - Check if the `submsg_desc` in the field is NULL and return an error if so.
    - If the field type is `PB_LTYPE_SUBMSG_W_CB` and `pSize` is not NULL, retrieve the callback function stored before `pSize`.
    - If the callback's encode function is present, call it with the stream, field, and callback argument, returning false if it fails.
    - Call [`pb_encode_submessage`](#checkreturnpb_encode_submessage) with the stream, submessage descriptor, and field data to encode the submessage.
- **Output**: Returns a boolean indicating success (true) or failure (false) of the encoding process.
- **Functions called**:
    - [`checkreturn::pb_encode_submessage`](#checkreturnpb_encode_submessage)


---
### pb\_enc\_fixed\_length\_bytes<!-- {{#callable:checkreturn::pb_enc_fixed_length_bytes}} -->
The `pb_enc_fixed_length_bytes` function encodes a fixed-length byte array into a protobuf output stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written.
    - `field`: A pointer to a `pb_field_iter_t` structure containing the field data to be encoded, specifically the byte array and its size.
- **Control Flow**:
    - The function calls [`pb_encode_string`](#checkreturnpb_encode_string), passing the output stream, the byte array from `field->pData`, and the size of the byte array from `field->data_size`.
- **Output**: The function returns a boolean value indicating success (`true`) or failure (`false`) of the encoding operation.
- **Functions called**:
    - [`checkreturn::pb_encode_string`](#checkreturnpb_encode_string)


---
### pb\_encode\_float\_as\_double<!-- {{#callable:pb_encode_float_as_double}} -->
The function `pb_encode_float_as_double` encodes a 32-bit float as a 64-bit double and writes it to a protobuf output stream.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded double will be written.
    - `value`: A 32-bit floating-point number (float) that needs to be encoded as a double.
- **Control Flow**:
    - The function begins by using a union to interpret the float as a 32-bit integer for bit manipulation.
    - It extracts the sign, exponent, and mantissa from the float's binary representation.
    - If the exponent indicates a special value (like NaN), it sets the exponent to 1024 for double representation.
    - If the exponent indicates a denormalized number, it normalizes the mantissa and adjusts the exponent accordingly.
    - The mantissa is shifted to fit the double's mantissa size, and the exponent and sign are adjusted and combined into a 64-bit integer.
    - The combined 64-bit integer is then written to the output stream using [`pb_encode_fixed64`](#checkreturnpb_encode_fixed64).
- **Output**: The function returns a boolean indicating success (`true`) or failure (`false`) of the encoding operation.
- **Functions called**:
    - [`checkreturn::pb_encode_fixed64`](#checkreturnpb_encode_fixed64)


# Function Declarations (Public API)

---
### buf\_write<!-- {{#callable_declaration:checkreturn::buf_write}} -->
Writes a buffer to a protobuf output stream.
- **Description**: This function writes a specified number of bytes from a buffer to a protobuf output stream. It is typically used when encoding data into a protobuf format, ensuring that the data is correctly placed into the stream's current position. The function assumes that the stream's state is correctly initialized to point to a writable memory area. It is important to ensure that the stream has enough space to accommodate the data being written, as this function does not perform bounds checking.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream. The stream's state must point to a valid memory location where data can be written.
    - `buf`: A pointer to a buffer containing the data to be written. The buffer must not be null and should contain at least `count` bytes.
    - `count`: The number of bytes to write from the buffer to the stream. Must be a positive integer.
- **Output**: Returns `true` to indicate successful writing of the buffer to the stream.
- **See also**: [`checkreturn::buf_write`](#checkreturnbuf_write)  (Implementation)


---
### encode\_array<!-- {{#callable_declaration:checkreturn::encode_array}} -->
Encodes a static array into a protobuf stream.
- **Description**: This function is used to encode a static array field into a protobuf output stream. It handles both packed and unpacked encoding based on the field's type and configuration. The function should be called when encoding a repeated field in a protobuf message. It requires that the field's size is correctly set and that the stream is properly initialized. The function will return false if the array exceeds its maximum size or if any encoding operation fails.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded data will be written. Must not be null and should be properly initialized.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. Must not be null and should have its size and data correctly set. The function expects the field's type to be compatible with array encoding.
- **Output**: Returns a boolean value: true if the array was successfully encoded, or false if an error occurred during encoding.
- **See also**: [`checkreturn::encode_array`](#checkreturnencode_array)  (Implementation)


---
### pb\_check\_proto3\_default\_value<!-- {{#callable_declaration:checkreturn::pb_check_proto3_default_value}} -->
Checks if a protobuf field has its default value in proto3.
- **Description**: This function determines whether a given protobuf field, represented by a field iterator, is set to its default value according to proto3 semantics. It is useful when encoding messages to decide if a field should be omitted, as proto3 omits fields with default values. The function should be called with a valid field iterator, and it handles various field types including static, pointer, and callback types. It returns a boolean indicating whether the field is at its default state.
- **Inputs**:
    - `field`: A pointer to a pb_field_iter_t structure representing the field to check. The pointer must not be null, and the structure should be properly initialized to point to a valid field in a protobuf message.
- **Output**: Returns a boolean value: true if the field is at its default value according to proto3 rules, false otherwise.
- **See also**: [`checkreturn::pb_check_proto3_default_value`](#checkreturnpb_check_proto3_default_value)  (Implementation)


---
### encode\_basic\_field<!-- {{#callable_declaration:checkreturn::encode_basic_field}} -->
Encodes a basic protobuf field into the output stream.
- **Description**: This function is used to encode a basic field of a protobuf message into a given output stream. It handles various field types such as boolean, varint, fixed32, fixed64, bytes, string, submessage, and fixed-length bytes. The function must be called with a valid field iterator and an output stream. If the field's data pointer is null, the function treats it as a missing field and returns true without encoding. The function returns false if encoding fails due to an invalid field type or if the tag encoding fails.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded data will be written. The stream must be properly initialized and must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. The field must be properly initialized and must not be null. The function checks the field's data pointer and handles it accordingly.
- **Output**: Returns a boolean value: true if the field is successfully encoded or if the field's data pointer is null, and false if an error occurs during encoding.
- **See also**: [`checkreturn::encode_basic_field`](#checkreturnencode_basic_field)  (Implementation)


---
### encode\_callback\_field<!-- {{#callable_declaration:checkreturn::encode_callback_field}} -->
Encodes a field using a callback function if available.
- **Description**: This function is used to encode a field in a protocol buffer message by invoking a user-defined callback function if it is specified in the field's descriptor. It should be called when encoding fields that require custom handling through callbacks. The function ensures that if a callback is present, it is executed with the provided stream and field parameters. If the callback fails, an error is returned through the stream's error handling mechanism. This function is typically used internally during the encoding process of protocol buffer messages.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded data will be written. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. Must not be null and should have a valid descriptor with an optional field_callback.
- **Output**: Returns true if the field was successfully encoded, or false if an error occurred during the callback execution.
- **See also**: [`checkreturn::encode_callback_field`](#checkreturnencode_callback_field)  (Implementation)


---
### encode\_field<!-- {{#callable_declaration:checkreturn::encode_field}} -->
Encodes a protobuf field into the output stream.
- **Description**: This function is used to encode a single protobuf field into the provided output stream. It handles different field types, including optional, required, repeated, and oneof fields, and encodes them according to their type and presence. The function must be called with a valid output stream and field iterator. It checks for field presence and handles missing required fields by returning an error. The function is typically used as part of a larger encoding process for protobuf messages.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the field will be encoded. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. Must not be null and should be properly initialized to point to a valid field.
- **Output**: Returns a boolean value indicating success (true) or failure (false). Failure occurs if a required field is missing or if there is an error during encoding.
- **See also**: [`checkreturn::encode_field`](#checkreturnencode_field)  (Implementation)


---
### encode\_extension\_field<!-- {{#callable_declaration:checkreturn::encode_extension_field}} -->
Encodes all registered extensions for a given field into a protobuf stream.
- **Description**: This function is used to encode all extensions associated with a specific field into a protobuf output stream. It should be called when you need to serialize extension fields of a protobuf message. The function iterates over each extension linked to the field and attempts to encode it using either a custom encoder provided by the extension or a default encoder. It is important to ensure that the `stream` and `field` parameters are properly initialized and valid before calling this function. The function returns a boolean indicating success or failure of the encoding process.
- **Inputs**:
    - `stream`: A pointer to a `pb_ostream_t` structure representing the output stream where the encoded data will be written. The stream must be properly initialized and must not be null.
    - `field`: A pointer to a `pb_field_iter_t` structure representing the field whose extensions are to be encoded. This must be a valid field iterator pointing to a field with extensions, and must not be null.
- **Output**: Returns `true` if all extensions are successfully encoded, otherwise returns `false` if an error occurs during encoding.
- **See also**: [`checkreturn::encode_extension_field`](#checkreturnencode_extension_field)  (Implementation)


---
### default\_extension\_encoder<!-- {{#callable_declaration:checkreturn::default_extension_encoder}} -->
Encodes a protobuf extension field into the output stream.
- **Description**: This function is used to encode a protobuf extension field into a given output stream. It should be called when you need to serialize an extension field as part of a protobuf message. The function requires a valid extension descriptor and an initialized output stream. If the extension is invalid, the function will return an error. This function is typically used internally within a protobuf encoding process and assumes that the stream and extension are properly set up before calling.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded data will be written. The stream must be initialized and must not be null.
    - `extension`: A pointer to a pb_extension_t structure representing the extension field to be encoded. The extension must be valid and must not be null.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the encoding process. If the extension is invalid, the function returns false and sets an error message in the stream.
- **See also**: [`checkreturn::default_extension_encoder`](#checkreturndefault_extension_encoder)  (Implementation)


---
### pb\_encode\_varint\_32<!-- {{#callable_declaration:checkreturn::pb_encode_varint_32}} -->
Encodes a 32-bit varint into a protobuf stream.
- **Description**: This function is used to encode a 32-bit varint into a protobuf stream, which is useful when dealing with protocol buffers that require efficient serialization of integer values. It should be called when you need to encode a varint that is split into low and high parts, typically when the integer value exceeds the range of a single 32-bit integer. The function writes the encoded varint to the provided stream and returns a boolean indicating success or failure. Ensure that the stream is properly initialized and has enough space to accommodate the encoded data.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded varint will be written. Must not be null and should be properly initialized.
    - `low`: The lower 32 bits of the integer to be encoded. It is a 32-bit unsigned integer.
    - `high`: The higher bits of the integer to be encoded, used when the integer value exceeds 32 bits. It is a 32-bit unsigned integer.
- **Output**: Returns a boolean value: true if the varint was successfully encoded and written to the stream, false if there was an error (e.g., if the stream is full).
- **See also**: [`checkreturn::pb_encode_varint_32`](#checkreturnpb_encode_varint_32)  (Implementation)


---
### pb\_enc\_bool<!-- {{#callable_declaration:checkreturn::pb_enc_bool}} -->
Encodes a boolean field into a protobuf stream.
- **Description**: This function is used to encode a boolean field into a protobuf stream by converting the boolean value to a varint format. It should be called when encoding a boolean field within a protobuf message. The function expects the field data to be accessible and valid, and it will handle the conversion of the boolean value to a varint, writing it to the provided stream. The function must be used in contexts where the stream is properly initialized and capable of handling varint encoding.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded data will be written. Must not be null and should be properly initialized for writing.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. The field's pData should point to a boolean value. The function assumes the field data is valid and accessible.
- **Output**: Returns a boolean indicating success (true) or failure (false) of the encoding operation.
- **See also**: [`checkreturn::pb_enc_bool`](#checkreturnpb_enc_bool)  (Implementation)


---
### pb\_enc\_varint<!-- {{#callable_declaration:checkreturn::pb_enc_varint}} -->
Encodes a field as a varint into the output stream.
- **Description**: This function is used to encode a field from a protocol buffer message as a varint into the provided output stream. It handles both unsigned and signed integer types, performing the necessary conversions based on the field's type. The function should be called when encoding fields that are represented as varints in the protocol buffer schema. It requires a valid output stream and a field iterator pointing to the field to be encoded. The function will return an error if the field's data size is invalid for the expected type.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded varint will be written. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. Must not be null and should point to a valid field with appropriate data size and type.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the encoding operation.
- **See also**: [`checkreturn::pb_enc_varint`](#checkreturnpb_enc_varint)  (Implementation)


---
### pb\_enc\_fixed<!-- {{#callable_declaration:checkreturn::pb_enc_fixed}} -->
Encodes a fixed-size numeric field into a protobuf stream.
- **Description**: This function is used to encode fixed-size numeric fields, such as 32-bit or 64-bit integers, into a protobuf output stream. It should be called when you need to serialize fixed-size numeric data as part of a protobuf message. The function expects the field's data size to match the expected size for fixed32 or fixed64 types. If the data size is invalid, the function will return an error. Ensure that the stream and field parameters are properly initialized before calling this function.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded data will be written. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. The field's data_size must be either 4 (for fixed32) or 8 (for fixed64). Must not be null.
- **Output**: Returns true if the encoding is successful; otherwise, returns false if an error occurs, such as an invalid data size.
- **See also**: [`checkreturn::pb_enc_fixed`](#checkreturnpb_enc_fixed)  (Implementation)


---
### pb\_enc\_bytes<!-- {{#callable_declaration:checkreturn::pb_enc_bytes}} -->
Encodes a bytes field into a protobuf stream.
- **Description**: This function is used to encode a bytes field from a protobuf message into a given output stream. It should be called when you need to serialize a bytes field as part of a protobuf message. The function handles null pointers by treating them as empty byte fields and checks for size constraints when the field is statically allocated. It is important to ensure that the stream and field parameters are properly initialized before calling this function.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the bytes field will be encoded. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. Must not be null and should point to a valid bytes field.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the encoding operation.
- **See also**: [`checkreturn::pb_enc_bytes`](#checkreturnpb_enc_bytes)  (Implementation)


---
### pb\_enc\_string<!-- {{#callable_declaration:checkreturn::pb_enc_string}} -->
Encodes a string field into a protobuf output stream.
- **Description**: This function is used to encode a string field from a protobuf message into a given output stream. It handles both pointer and static string types, ensuring that the string is properly null-terminated if required. The function should be called when encoding a protobuf message that includes a string field. It checks for null pointers, treating them as empty strings, and validates UTF-8 encoding if enabled. The function returns an error if the string is not properly terminated or if it exceeds the maximum allowed size.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded string will be written. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. It contains the string data and its size. Must not be null.
- **Output**: Returns a boolean indicating success (true) or failure (false) of the encoding process.
- **See also**: [`checkreturn::pb_enc_string`](#checkreturnpb_enc_string)  (Implementation)


---
### pb\_enc\_submessage<!-- {{#callable_declaration:checkreturn::pb_enc_submessage}} -->
Encodes a submessage field into a protobuf stream.
- **Description**: This function is used to encode a submessage field into a protobuf stream. It should be called when you need to serialize a submessage as part of a larger protobuf message. The function requires a valid field descriptor for the submessage and handles optional encoding callbacks if specified. It is important to ensure that the field descriptor is not null before calling this function, as a null descriptor will result in an error. The function returns a boolean indicating success or failure, and it is crucial to check this return value to handle any encoding errors appropriately.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the submessage will be encoded. The stream must be properly initialized and have sufficient space for the encoded data.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. The field must have a valid submsg_desc, and if the field type is PB_LTYPE_SUBMSG_W_CB, it may have an associated callback function for encoding.
- **Output**: Returns a boolean value: true if the submessage was successfully encoded, or false if an error occurred during encoding.
- **See also**: [`checkreturn::pb_enc_submessage`](#checkreturnpb_enc_submessage)  (Implementation)


---
### pb\_enc\_fixed\_length\_bytes<!-- {{#callable_declaration:checkreturn::pb_enc_fixed_length_bytes}} -->
Encodes a fixed-length byte array into a protobuf stream.
- **Description**: This function is used to encode a fixed-length byte array from a protobuf field into a given output stream. It is typically called during the serialization process of a protobuf message when a field of fixed-length bytes needs to be encoded. The function requires a valid output stream and a field iterator pointing to the field data to be encoded. It is important to ensure that the field's data size is correctly set, as this function will encode exactly that number of bytes. The function returns a boolean indicating success or failure, which should be checked to ensure the encoding process completes without errors.
- **Inputs**:
    - `stream`: A pointer to a pb_ostream_t structure representing the output stream where the encoded data will be written. Must not be null.
    - `field`: A pointer to a pb_field_iter_t structure representing the field to be encoded. This structure must contain valid data and data size for the fixed-length byte array. Must not be null.
- **Output**: Returns a boolean value: true if the encoding was successful, false if an error occurred during encoding.
- **See also**: [`checkreturn::pb_enc_fixed_length_bytes`](#checkreturnpb_enc_fixed_length_bytes)  (Implementation)


