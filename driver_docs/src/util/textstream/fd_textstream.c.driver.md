# Purpose
This C source code file implements a text stream management system, providing functionality for creating, managing, and manipulating text streams in a memory-efficient manner. The primary structure used is `fd_textstream_t`, which manages a linked list of blocks (`fd_textstream_blk_t`) that store chunks of text data. The code includes functions to create and destroy text streams, append text, clear the stream, and retrieve the total size of the text stored. It also provides functions to encode data into various formats such as UTF-8, Base58, Base64, and hexadecimal, and to format strings using a `sprintf`-like function.

The file is designed to be part of a larger system, as indicated by the inclusion of external headers like `fd_util.h` and `fd_textstream.h`. It does not define a main function, suggesting it is intended to be used as a library or module within a larger application. The code provides a public API for text stream operations, allowing other parts of the application to interact with text data efficiently. The use of memory allocation functions like `fd_valloc_malloc` and `fd_valloc_free` suggests a focus on custom memory management, which is crucial for handling potentially large amounts of text data without excessive memory overhead.
# Imports and Dependencies

---
- `stdio.h`
- `stdlib.h`
- `stdarg.h`
- `../fd_util.h`
- `fd_textstream.h`


# Global Variables

---
### b58digits\_ordered
- **Type**: ``const char[]``
- **Description**: The `b58digits_ordered` is a static constant character array that contains the characters used in Base58 encoding. Base58 is a binary-to-text encoding scheme used to represent large integers as alphanumeric strings, commonly used in cryptocurrencies like Bitcoin.
- **Use**: This variable is used to map numerical values to their corresponding Base58 characters during encoding operations.


---
### base64\_encoding\_table
- **Type**: `char[]`
- **Description**: The `base64_encoding_table` is a static array of characters that contains the Base64 encoding alphabet. It includes uppercase and lowercase letters, digits, and the '+' and '/' symbols, which are used in Base64 encoding to represent binary data in an ASCII string format.
- **Use**: This variable is used to map binary data to Base64 encoded characters during the Base64 encoding process.


---
### hex\_encoding\_table
- **Type**: ``const char[]``
- **Description**: The `hex_encoding_table` is a static constant character array that contains the hexadecimal digits from '0' to 'F'. It is used to map binary data to its hexadecimal representation.
- **Use**: This variable is used in the `fd_textstream_encode_hex` function to convert binary data into a hexadecimal string representation.


# Data Structures

---
### fd\_textstream\_blk
- **Type**: `struct`
- **Members**:
    - `next`: A pointer to the next block in the linked list.
    - `used`: An unsigned long integer indicating the amount of data used in the block.
- **Description**: The `fd_textstream_blk` structure is a node in a linked list used to manage blocks of text data in a text stream. Each block contains a pointer to the next block, allowing for dynamic expansion of the text stream, and a `used` field that tracks how much of the block's allocated space is currently in use. This structure is part of a larger system for managing text streams, enabling efficient memory allocation and data management.


---
### fd\_textstream\_blk\_t
- **Type**: `struct`
- **Members**:
    - `next`: A pointer to the next block in the linked list of text stream blocks.
    - `used`: An unsigned long integer indicating the number of bytes used in the current block.
- **Description**: The `fd_textstream_blk_t` structure is a node in a linked list used to manage blocks of text data in a text stream. Each block contains a pointer to the next block (`next`) and a counter (`used`) that tracks how much of the block's allocated space is currently in use. This structure is part of a larger system for managing dynamic text streams, allowing for efficient memory allocation and text manipulation.


# Functions

---
### fd\_textstream\_new<!-- {{#callable:fd_textstream_new}} -->
The `fd_textstream_new` function initializes a new text stream structure with a specified allocator and allocation size, and allocates the first block of memory for the stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure that will be initialized.
    - `valloc`: An allocator of type `fd_valloc_t` used for memory allocation.
    - `alloc_sz`: The size of the memory block to allocate for the text stream.
- **Control Flow**:
    - Assigns the provided allocator `valloc` and allocation size `alloc_sz` to the `strm` structure.
    - Attempts to allocate a memory block using `fd_valloc_malloc` with the specified alignment and size.
    - Checks if the memory allocation was successful; if not, returns `NULL`.
    - Initializes the allocated block's `next` pointer to `NULL` and `used` size to `0`.
    - Sets the `first_blk` and `last_blk` pointers of the `strm` to the newly allocated block.
    - Returns the initialized `strm` structure.
- **Output**: Returns a pointer to the initialized `fd_textstream_t` structure, or `NULL` if memory allocation fails.


---
### fd\_textstream\_destroy<!-- {{#callable:fd_textstream_destroy}} -->
The `fd_textstream_destroy` function deallocates all memory blocks associated with a given text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream to be destroyed.
- **Control Flow**:
    - Initialize a loop with `blk` pointing to the first block of the text stream (`strm->first_blk`).
    - Iterate over each block in the text stream until `blk` is NULL.
    - In each iteration, store the next block pointer (`blk->next`) in `next`.
    - Free the current block using `fd_valloc_free` with the allocator from the text stream (`strm->valloc`).
    - Move to the next block by setting `blk` to `next`.
- **Output**: The function does not return any value; it performs cleanup by freeing memory.


---
### fd\_textstream\_clear<!-- {{#callable:fd_textstream_clear}} -->
The `fd_textstream_clear` function clears all blocks in a text stream except the first one, resetting the stream to its initial state.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream to be cleared.
- **Control Flow**:
    - Iterate over all blocks in the text stream starting from the second block (i.e., `strm->first_blk->next`).
    - For each block, store the next block in a temporary variable, free the current block using `fd_valloc_free`, and move to the next block.
    - After all blocks except the first are freed, set the `next` pointer of the first block to `NULL` and reset its `used` field to 0.
    - Update the `last_blk` pointer of the stream to point to the first block.
- **Output**: The function does not return a value; it modifies the text stream in place.


---
### fd\_textstream\_new\_blk<!-- {{#callable:fd_textstream_new_blk}} -->
The `fd_textstream_new_blk` function allocates and initializes a new block for a text stream, linking it to the existing stream structure.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream to which the new block will be added.
- **Control Flow**:
    - Allocate memory for a new `fd_textstream_blk_t` block using `fd_valloc_malloc`, with alignment and size based on the stream's allocator and allocation size.
    - Check if the memory allocation was successful; if not, return `NULL`.
    - Initialize the new block's `next` pointer to `NULL` and `used` size to `0`.
    - Link the new block to the end of the current stream by setting the `next` pointer of the last block to the new block.
    - Update the stream's `last_blk` pointer to point to the new block.
    - Return the pointer to the newly created block.
- **Output**: A pointer to the newly allocated and initialized `fd_textstream_blk_t` block, or `NULL` if the allocation fails.


---
### fd\_textstream\_append<!-- {{#callable:fd_textstream_append}} -->
The `fd_textstream_append` function appends a given text to a text stream, allocating a new block if necessary.
- **Inputs**:
    - `strm`: A pointer to the `fd_textstream_t` structure representing the text stream to which the text will be appended.
    - `text`: A pointer to the character array containing the text to be appended to the stream.
    - `text_sz`: The size (in bytes) of the text to be appended.
- **Control Flow**:
    - Retrieve the last block of the text stream from `strm->last_blk`.
    - Check if the current block has enough space to accommodate the new text (`blk->used + text_sz <= strm->alloc_sz`).
    - If there is enough space, proceed to copy the text into the current block.
    - If the text size exceeds the allocation size of a block (`text_sz > strm->alloc_sz`), return -1 indicating failure.
    - If the current block does not have enough space, allocate a new block using [`fd_textstream_new_blk`](#fd_textstream_new_blk) and update the block pointer.
    - If the new block allocation fails, return -1 indicating failure.
    - Copy the text into the block's buffer starting from the current used position.
    - Update the `used` field of the block to reflect the newly added text size.
    - Return 0 to indicate successful appending of the text.
- **Output**: Returns 0 on successful appending of the text, or -1 if the text size exceeds the allocation size or if a new block cannot be allocated.
- **Functions called**:
    - [`fd_textstream_new_blk`](#fd_textstream_new_blk)


---
### fd\_textstream\_total\_size<!-- {{#callable:fd_textstream_total_size}} -->
The `fd_textstream_total_size` function calculates the total size of data used across all blocks in a text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream whose total size is to be calculated.
- **Control Flow**:
    - Initialize a variable `tot` to zero to accumulate the total size.
    - Iterate over each block in the text stream starting from `strm->first_blk`.
    - For each block, add the `used` size of the block to `tot`.
    - Continue the iteration until all blocks have been processed.
    - Return the accumulated total size `tot`.
- **Output**: The function returns an `ulong` representing the total size of data used in the text stream.


---
### fd\_textstream\_get\_output<!-- {{#callable:fd_textstream_get_output}} -->
The `fd_textstream_get_output` function copies the contents of a text stream into a provided output buffer.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream from which data is to be copied.
    - `outbuf`: A pointer to a character buffer where the output data from the text stream will be copied.
- **Control Flow**:
    - Initialize a variable `tot` to zero to keep track of the total number of bytes copied.
    - Iterate over each block in the text stream starting from `strm->first_blk`.
    - For each block, copy the used portion of the block (starting from the memory location immediately after the block header) into the `outbuf` at the current offset `tot`.
    - Update `tot` by adding the number of bytes copied from the current block.
    - Continue this process until all blocks have been processed.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### fd\_textstream\_get\_iov\_count<!-- {{#callable:fd_textstream_get_iov_count}} -->
The function `fd_textstream_get_iov_count` counts the number of blocks in a text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream whose blocks are to be counted.
- **Control Flow**:
    - Initialize a counter `tot` to zero.
    - Iterate over each block in the text stream starting from `strm->first_blk`.
    - For each block, increment the counter `tot`.
    - Continue the iteration until there are no more blocks (i.e., the block pointer becomes NULL).
- **Output**: The function returns the total number of blocks in the text stream as an unsigned long integer.


---
### fd\_textstream\_get\_iov<!-- {{#callable:fd_textstream_get_iov}} -->
The `fd_textstream_get_iov` function populates an array of `fd_iovec` structures with pointers and lengths of data blocks from a text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream from which data blocks are retrieved.
    - `iov`: A pointer to an array of `fd_iovec` structures where the function will store the base addresses and lengths of the data blocks.
- **Control Flow**:
    - Initialize a counter `tot` to zero to track the number of blocks processed.
    - Iterate over each block in the text stream starting from `strm->first_blk`.
    - For each block, set the `iov_base` of the current `iov` entry to point to the data portion of the block (i.e., `blk+1`).
    - Set the `iov_len` of the current `iov` entry to the `used` size of the block.
    - Increment the `tot` counter to move to the next `iov` entry.
    - Continue until all blocks in the stream have been processed.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### fd\_textstream\_encode\_utf8<!-- {{#callable:fd_textstream_encode_utf8}} -->
The `fd_textstream_encode_utf8` function encodes an array of Unicode code points into UTF-8 and appends the result to a text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream to which the UTF-8 encoded data will be appended.
    - `chars`: A pointer to an array of unsigned integers representing the Unicode code points to be encoded into UTF-8.
    - `chars_sz`: The number of Unicode code points in the `chars` array.
- **Control Flow**:
    - Initialize `out_sz` to 0 to track the size of the UTF-8 encoded output.
    - Iterate over each Unicode code point in the `chars` array to calculate the total size of the UTF-8 encoded output (`out_sz`).
    - Check if each code point is within valid UTF-8 range and calculate the number of bytes needed for its UTF-8 representation, returning -1 if any code point is invalid.
    - Check if the current block in the text stream has enough space for the UTF-8 encoded data; if not, allocate a new block.
    - Encode each Unicode code point into its UTF-8 representation and store it in the destination buffer within the text stream block.
    - Update the `used` field of the current block to reflect the newly added data size.
    - Return 0 to indicate successful encoding and appending.
- **Output**: Returns 0 on successful encoding and appending of UTF-8 data to the text stream, or -1 if an error occurs (e.g., invalid code point or memory allocation failure).
- **Functions called**:
    - [`fd_textstream_new_blk`](#fd_textstream_new_blk)


---
### fd\_textstream\_encode\_base58<!-- {{#callable:fd_textstream_encode_base58}} -->
The `fd_textstream_encode_base58` function encodes binary data into a Base58 string and appends it to a text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure where the encoded Base58 string will be appended.
    - `data`: A pointer to the binary data that needs to be encoded into Base58.
    - `data_sz`: The size of the binary data in bytes.
- **Control Flow**:
    - Check if `data_sz` exceeds 400 to prevent excessive computation and return -1 if true.
    - Initialize variables and count leading zero bytes in the input data.
    - Calculate the size of a temporary buffer for the Base58 conversion and initialize it to zero.
    - Iterate over the input data, performing Base58 encoding by dividing the data into 58 and storing the remainder in the buffer.
    - Skip leading zeroes in the buffer to find the start of the Base58 encoded data.
    - Calculate the size of the output and check if it fits in the current text stream block; allocate a new block if necessary.
    - Fill the output buffer with '1' for each leading zero in the input data, then map the buffer values to Base58 characters using `b58digits_ordered`.
    - Update the used size of the current block in the text stream.
- **Output**: Returns 0 on successful encoding and appending to the text stream, or -1 if an error occurs (e.g., data size too large or memory allocation failure).
- **Functions called**:
    - [`fd_textstream_new_blk`](#fd_textstream_new_blk)


---
### fd\_textstream\_encode\_base64<!-- {{#callable:fd_textstream_encode_base64}} -->
The `fd_textstream_encode_base64` function encodes binary data into a Base64 string and appends it to a text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream where the Base64 encoded data will be appended.
    - `data`: A pointer to the binary data that needs to be encoded into Base64.
    - `data_sz`: The size of the binary data in bytes.
- **Control Flow**:
    - Calculate the required output size for the Base64 encoded data.
    - Check if the current block in the text stream has enough space to accommodate the encoded data.
    - If not enough space and the output size exceeds the allocation size, return -1 indicating failure.
    - If not enough space but the output size is within the allocation size, allocate a new block in the text stream.
    - Iterate over the input data in chunks of 3 bytes, encoding each chunk into 4 Base64 characters.
    - Handle cases where the remaining data is less than 3 bytes by padding with '=' characters as per Base64 encoding rules.
    - Update the used size of the current block in the text stream with the number of characters written.
    - Return 0 indicating successful encoding and appending.
- **Output**: Returns 0 on successful encoding and appending to the text stream, or -1 if there is an error such as insufficient space for the encoded data.
- **Functions called**:
    - [`fd_textstream_new_blk`](#fd_textstream_new_blk)


---
### fd\_textstream\_encode\_hex<!-- {{#callable:fd_textstream_encode_hex}} -->
The `fd_textstream_encode_hex` function encodes binary data into a hexadecimal string and appends it to a text stream.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream where the encoded data will be appended.
    - `data`: A pointer to the binary data that needs to be encoded into hexadecimal format.
    - `data_sz`: The size of the binary data in bytes.
- **Control Flow**:
    - Calculate the required output size as twice the size of the input data.
    - Check if the current block in the text stream has enough space to accommodate the encoded data.
    - If not enough space and the output size exceeds the allocation size, return -1 indicating failure.
    - If not enough space but the output size is within the allocation size, allocate a new block in the text stream.
    - Iterate over each byte of the input data, converting it to two hexadecimal characters using a lookup table.
    - Append the encoded characters to the current block in the text stream.
    - Update the used size of the current block by the number of characters added.
- **Output**: Returns 0 on success, or -1 if there is insufficient space to encode the data.
- **Functions called**:
    - [`fd_textstream_new_blk`](#fd_textstream_new_blk)


---
### fd\_textstream\_sprintf<!-- {{#callable:fd_textstream_sprintf}} -->
The `fd_textstream_sprintf` function formats a string using a variable argument list and appends it to a text stream, allocating new blocks if necessary.
- **Inputs**:
    - `strm`: A pointer to an `fd_textstream_t` structure representing the text stream to which the formatted string will be appended.
    - `format`: A C-style format string that specifies how subsequent arguments are converted for output.
    - `...`: A variable number of arguments that are formatted according to the format string.
- **Control Flow**:
    - Retrieve the last block of the text stream and calculate the remaining space in it.
    - Use `vsnprintf` to attempt to format the string into the remaining space of the current block.
    - If the formatted string fits, update the used space in the block and return 0.
    - If the formatted string does not fit, allocate a new block using [`fd_textstream_new_blk`](#fd_textstream_new_blk).
    - Attempt to format the string into the new block's space.
    - If successful, update the used space in the new block and return 0.
    - If the string still does not fit, return -1 indicating failure.
- **Output**: Returns 0 on success if the formatted string is appended to the text stream, or -1 if there is an error such as memory allocation failure or insufficient space.
- **Functions called**:
    - [`fd_textstream_new_blk`](#fd_textstream_new_blk)


