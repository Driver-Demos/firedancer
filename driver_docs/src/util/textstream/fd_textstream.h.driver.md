# Purpose
This C header file defines the interface for a text stream utility, which is designed to manage and manipulate streams of text data. The primary structure, `fd_textstream_t`, encapsulates a text stream, including memory allocation details and pointers to the first and last blocks of the stream. The utility provides a variety of functions to create, clear, and destroy text streams, as well as to append text and retrieve the total size of the stream. Additionally, it offers functionality to encode data into different formats such as UTF-8, Base58, Base64, and hexadecimal, which suggests its use in applications requiring data serialization or encoding.

The file also defines an `fd_iovec` structure, which is used to facilitate operations involving multiple buffers, such as retrieving the stream's data in a format suitable for I/O operations. The presence of functions like [`fd_textstream_sprintf`](#fd_textstream_sprintf) indicates support for formatted text output, enhancing the utility's flexibility in handling text data. This header file is intended to be included in other C source files, providing a public API for text stream management and encoding operations, making it a versatile component in larger software systems that require efficient text processing capabilities.
# Imports and Dependencies

---
- `../valloc/fd_valloc.h`


# Global Variables

---
### fd\_textstream\_new
- **Type**: `function pointer`
- **Description**: The `fd_textstream_new` is a function that initializes a new `fd_textstream_t` structure. It takes a pointer to an `fd_textstream_t` structure, a `fd_valloc_t` allocator, and an allocation size as parameters.
- **Use**: This function is used to create and initialize a new text stream object with specified memory allocation settings.


# Data Structures

---
### fd\_textstream
- **Type**: `struct`
- **Members**:
    - `valloc`: A memory allocator used for dynamic memory management within the text stream.
    - `alloc_sz`: The size of the memory allocation for the text stream.
    - `first_blk`: A pointer to the first block in the text stream.
    - `last_blk`: A pointer to the last block in the text stream.
- **Description**: The `fd_textstream` structure is designed to manage a dynamic text stream, utilizing a custom memory allocator (`fd_valloc_t`) for efficient memory management. It maintains pointers to the first and last blocks of the text stream, allowing for operations such as appending text, clearing the stream, and encoding data in various formats. The structure is integral to handling text data dynamically, supporting operations like UTF-8 encoding and base conversions.


---
### fd\_textstream\_t
- **Type**: `struct`
- **Members**:
    - `valloc`: An instance of fd_valloc_t used for memory allocation within the text stream.
    - `alloc_sz`: The size of the memory allocation for the text stream.
    - `first_blk`: A pointer to the first block in the text stream.
    - `last_blk`: A pointer to the last block in the text stream.
- **Description**: The `fd_textstream_t` structure is designed to manage a dynamic text stream, utilizing a custom allocator (`fd_valloc_t`) for memory management. It maintains pointers to the first and last blocks of the stream, allowing for efficient appending and manipulation of text data. The structure supports various encoding methods and provides functionality to clear, destroy, and retrieve the total size of the text stream.


---
### fd\_iovec
- **Type**: `struct`
- **Members**:
    - `iov_base`: Starting address of the memory block.
    - `iov_len`: Number of bytes to transfer from the memory block.
- **Description**: The `fd_iovec` structure is used to describe a block of memory, specifying both the starting address and the length of the block in bytes. It is typically used in operations that involve transferring data to or from a contiguous block of memory, allowing for efficient data handling in input/output operations.


# Function Declarations (Public API)

---
### fd\_textstream\_new<!-- {{#callable_declaration:fd_textstream_new}} -->
Initialize a text stream with a specified allocator and block size.
- **Description**: This function initializes a text stream object using a specified memory allocator and block size. It should be called to set up a text stream before any operations are performed on it. The function allocates the initial block of memory for the stream using the provided allocator. If the allocation fails, the function returns NULL, indicating that the stream could not be initialized. The caller must ensure that the `strm` parameter points to a valid `fd_textstream_t` structure and that the `valloc` parameter is a valid allocator. The `alloc_sz` parameter specifies the size of the memory block to allocate for the text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure that will be initialized. Must not be null and should point to a valid, uninitialized `fd_textstream_t` object.
    - `valloc`: A memory allocator of type `fd_valloc_t` used to allocate memory for the text stream. Must be a valid allocator.
    - `alloc_sz`: The size of the memory block to allocate for the text stream. Must be a positive integer.
- **Output**: Returns a pointer to the initialized `fd_textstream_t` structure on success, or NULL if memory allocation fails.
- **See also**: [`fd_textstream_new`](fd_textstream.c.driver.md#fd_textstream_new)  (Implementation)


---
### fd\_textstream\_clear<!-- {{#callable_declaration:fd_textstream_clear}} -->
Clears all data from the text stream.
- **Description**: Use this function to remove all data from a text stream, effectively resetting it to an empty state. This function should be called when you want to reuse an existing text stream without retaining any of its previous content. It is important to ensure that the text stream has been properly initialized before calling this function. After execution, the text stream will be in a state as if it was newly created, with no data blocks except the initial one, which is reset.
- **Inputs**:
    - `strm`: A pointer to an initialized fd_textstream_t structure. Must not be null. The function assumes the text stream is valid and properly initialized. Invalid or null input will lead to undefined behavior.
- **Output**: None
- **See also**: [`fd_textstream_clear`](fd_textstream.c.driver.md#fd_textstream_clear)  (Implementation)


---
### fd\_textstream\_destroy<!-- {{#callable_declaration:fd_textstream_destroy}} -->
Releases all resources associated with a text stream.
- **Description**: Use this function to free all memory and resources associated with a `fd_textstream_t` object when it is no longer needed. This function should be called to prevent memory leaks after the text stream has been used and is no longer required. It is important to ensure that the `strm` parameter is not null before calling this function, as passing a null pointer will result in undefined behavior. After calling this function, the `fd_textstream_t` object should not be used unless it is reinitialized.
- **Inputs**:
    - `strm`: A pointer to the `fd_textstream_t` object to be destroyed. Must not be null. The caller retains ownership of the pointer itself, but the resources managed by the text stream will be freed.
- **Output**: None
- **See also**: [`fd_textstream_destroy`](fd_textstream.c.driver.md#fd_textstream_destroy)  (Implementation)


---
### fd\_textstream\_append<!-- {{#callable_declaration:fd_textstream_append}} -->
Appends text to a text stream.
- **Description**: Use this function to add a specified amount of text to an existing text stream. It is essential to ensure that the text stream has been properly initialized before calling this function. The function attempts to append the text to the current block of the stream. If the current block does not have enough space, a new block is allocated, provided the text size does not exceed the allocation size of the stream. If the text size is larger than the allocation size, the function will return an error. This function modifies the state of the text stream by increasing the used space in the current block or by adding a new block if necessary.
- **Inputs**:
    - `strm`: A pointer to an initialized fd_textstream_t structure. Must not be null. The caller retains ownership.
    - `text`: A pointer to the text to be appended. Must not be null. The caller retains ownership.
    - `text_sz`: The size of the text to append, in bytes. Must be a positive value and should not exceed the allocation size of the stream.
- **Output**: Returns 0 on success. Returns -1 if the text size exceeds the allocation size or if a new block cannot be allocated.
- **See also**: [`fd_textstream_append`](fd_textstream.c.driver.md#fd_textstream_append)  (Implementation)


---
### fd\_textstream\_total\_size<!-- {{#callable_declaration:fd_textstream_total_size}} -->
Calculate the total size of data in a text stream.
- **Description**: Use this function to determine the total amount of data currently stored in a text stream. It is useful for understanding the memory usage or for operations that depend on the size of the data in the stream. The function must be called with a valid text stream that has been properly initialized. It does not modify the stream or its contents.
- **Inputs**:
    - `strm`: A pointer to a `fd_textstream_t` structure representing the text stream. It must not be null and should point to a valid, initialized text stream. If the stream is not properly initialized, the behavior is undefined.
- **Output**: Returns the total size in bytes of the data stored in the text stream.
- **See also**: [`fd_textstream_total_size`](fd_textstream.c.driver.md#fd_textstream_total_size)  (Implementation)


---
### fd\_textstream\_get\_output<!-- {{#callable_declaration:fd_textstream_get_output}} -->
Copies the contents of a text stream into a provided buffer.
- **Description**: Use this function to extract and copy all the data from a text stream into a specified output buffer. The function iterates over all blocks in the text stream and copies their contents sequentially into the buffer. It is essential that the output buffer is large enough to hold the entire content of the text stream, which can be determined using `fd_textstream_total_size`. The function does not modify the text stream or the buffer beyond writing the data.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream to be copied. Must not be null.
    - `outbuf`: A pointer to a character buffer where the text stream's contents will be copied. The buffer must be pre-allocated and large enough to hold the entire content of the text stream.
- **Output**: Returns 0 on successful completion. The output buffer is filled with the text stream's contents.
- **See also**: [`fd_textstream_get_output`](fd_textstream.c.driver.md#fd_textstream_get_output)  (Implementation)


---
### fd\_textstream\_get\_iov\_count<!-- {{#callable_declaration:fd_textstream_get_iov_count}} -->
Returns the number of I/O vector blocks in the text stream.
- **Description**: Use this function to determine how many I/O vector blocks are currently present in a given text stream. This can be useful for understanding the structure of the data within the stream or for preparing to perform operations that depend on the number of blocks. The function must be called with a valid text stream object, and it will return the count of blocks linked within the stream. Ensure that the text stream has been properly initialized before calling this function.
- **Inputs**:
    - `strm`: A pointer to a `fd_textstream_t` structure representing the text stream. Must not be null, and the text stream should be properly initialized before calling this function.
- **Output**: Returns the total number of I/O vector blocks in the text stream as an unsigned long integer.
- **See also**: [`fd_textstream_get_iov_count`](fd_textstream.c.driver.md#fd_textstream_get_iov_count)  (Implementation)


---
### fd\_textstream\_get\_iov<!-- {{#callable_declaration:fd_textstream_get_iov}} -->
Populate an array of iovec structures with the data from a text stream.
- **Description**: Use this function to fill an array of `fd_iovec` structures with pointers to the data blocks within a `fd_textstream_t` object. This is useful for operations that require scatter-gather I/O, where data is spread across multiple non-contiguous memory blocks. The function assumes that the `iov` array is large enough to hold all the iovec structures corresponding to the blocks in the text stream. It must be called with a valid `fd_textstream_t` object that has been properly initialized and potentially populated with data.
- **Inputs**:
    - `strm`: A pointer to a `fd_textstream_t` object. It must not be null and should be initialized before calling this function. The text stream should contain data to be described by the iovec structures.
    - `iov`: A pointer to an array of `fd_iovec` structures. The array must be large enough to hold all the iovec structures for the blocks in the text stream. The caller is responsible for allocating this array.
- **Output**: Returns 0 on success. The `iov` array is populated with pointers to the data blocks and their sizes from the text stream.
- **See also**: [`fd_textstream_get_iov`](fd_textstream.c.driver.md#fd_textstream_get_iov)  (Implementation)


---
### fd\_textstream\_encode\_utf8<!-- {{#callable_declaration:fd_textstream_encode_utf8}} -->
Encodes an array of Unicode code points into UTF-8 and appends it to a text stream.
- **Description**: Use this function to encode an array of Unicode code points into UTF-8 format and append the result to a specified text stream. This function is useful when you need to convert and store Unicode data in a UTF-8 encoded format within a text stream. Ensure that the text stream has been properly initialized before calling this function. The function will return an error if any code point is outside the valid Unicode range (0 to 0x10FFFF) or if the encoded data exceeds the stream's allocation size.
- **Inputs**:
    - `strm`: A pointer to an initialized fd_textstream_t structure where the UTF-8 encoded data will be appended. Must not be null.
    - `chars`: A pointer to an array of unsigned integers representing Unicode code points to be encoded. Must not be null.
    - `chars_sz`: The number of code points in the chars array. Must be non-negative.
- **Output**: Returns 0 on success. Returns -1 if a code point is invalid or if the encoded data cannot fit within the stream's allocation size.
- **See also**: [`fd_textstream_encode_utf8`](fd_textstream.c.driver.md#fd_textstream_encode_utf8)  (Implementation)


---
### fd\_textstream\_encode\_base58<!-- {{#callable_declaration:fd_textstream_encode_base58}} -->
Encodes binary data into Base58 and appends it to a text stream.
- **Description**: Use this function to encode binary data into a Base58 representation and append the result to a specified text stream. This function is useful when you need to store or transmit binary data in a text-friendly format. The function must be called with a valid text stream that has been properly initialized. The size of the data to be encoded must not exceed 400 bytes, as larger sizes will result in an error. Ensure that the text stream has sufficient space to accommodate the encoded data, or the function will attempt to allocate additional space. If the allocation fails or the data size exceeds the limit, the function will return an error.
- **Inputs**:
    - `strm`: A pointer to an initialized fd_textstream_t structure where the encoded Base58 data will be appended. Must not be null.
    - `data`: A pointer to the binary data to be encoded. The caller retains ownership of the data, and it must not be null.
    - `data_sz`: The size of the binary data in bytes. Must be 400 or less; otherwise, the function returns an error.
- **Output**: Returns 0 on success, or -1 if the data size exceeds 400 bytes or if memory allocation fails.
- **See also**: [`fd_textstream_encode_base58`](fd_textstream.c.driver.md#fd_textstream_encode_base58)  (Implementation)


---
### fd\_textstream\_encode\_base64<!-- {{#callable_declaration:fd_textstream_encode_base64}} -->
Encodes data into Base64 format and appends it to a text stream.
- **Description**: Use this function to encode binary data into Base64 format and append the encoded string to the specified text stream. This function is useful when you need to store or transmit binary data in a text-friendly format. Ensure that the text stream has been properly initialized and has sufficient space to accommodate the encoded data. If the encoded data size exceeds the stream's allocation size, the function will return an error. The function modifies the text stream by appending the Base64 encoded data.
- **Inputs**:
    - `strm`: A pointer to an initialized fd_textstream_t structure where the Base64 encoded data will be appended. Must not be null.
    - `data`: A pointer to the binary data to be encoded. The caller retains ownership of the data, and it must not be null.
    - `data_sz`: The size in bytes of the data to be encoded. Must be a non-negative value.
- **Output**: Returns 0 on success, or -1 if the encoded data size exceeds the stream's allocation size or if a new block cannot be allocated.
- **See also**: [`fd_textstream_encode_base64`](fd_textstream.c.driver.md#fd_textstream_encode_base64)  (Implementation)


---
### fd\_textstream\_encode\_hex<!-- {{#callable_declaration:fd_textstream_encode_hex}} -->
Encodes binary data as a hexadecimal string and appends it to a text stream.
- **Description**: This function converts binary data into a hexadecimal string representation and appends it to the specified text stream. It should be used when there is a need to represent binary data in a human-readable hexadecimal format within a text stream. The function requires that the text stream has been properly initialized and has sufficient space to accommodate the encoded data. If the current block in the stream does not have enough space, a new block is allocated. The function returns an error if the data size exceeds the stream's allocation size or if a new block cannot be allocated.
- **Inputs**:
    - `strm`: A pointer to an initialized fd_textstream_t structure where the encoded data will be appended. Must not be null.
    - `data`: A pointer to the binary data to be encoded. The caller retains ownership and it must not be null.
    - `data_sz`: The size in bytes of the binary data to be encoded. Must be a non-negative value.
- **Output**: Returns 0 on success, or -1 if the data size exceeds the stream's allocation size or if a new block cannot be allocated.
- **See also**: [`fd_textstream_encode_hex`](fd_textstream.c.driver.md#fd_textstream_encode_hex)  (Implementation)


---
### fd\_textstream\_sprintf<!-- {{#callable_declaration:fd_textstream_sprintf}} -->
Formats and appends a formatted string to a text stream.
- **Description**: Use this function to append a formatted string to the specified text stream. It behaves similarly to `sprintf`, allowing you to format a string using a format specifier and a variable number of arguments. The function attempts to write the formatted string into the current block of the text stream. If the current block does not have enough space, a new block is allocated. The function returns an error if it fails to allocate a new block or if the formatted string cannot fit within the allocated space. Ensure that the text stream is properly initialized before calling this function.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream. Must not be null and should be initialized before use.
    - `format`: A C string that contains the text to be written, optionally containing embedded format specifiers. Must not be null.
    - `...`: A variable number of arguments that correspond to the format specifiers in the format string.
- **Output**: Returns 0 on success, indicating the formatted string was successfully appended. Returns -1 on failure, which can occur if memory allocation fails or if the formatted string cannot fit in the available space.
- **See also**: [`fd_textstream_sprintf`](fd_textstream.c.driver.md#fd_textstream_sprintf)  (Implementation)


