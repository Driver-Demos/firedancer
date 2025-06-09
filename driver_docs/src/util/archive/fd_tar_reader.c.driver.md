# Purpose
This C source code file provides functionality for reading and processing TAR archive headers and data. It defines a set of functions and structures that facilitate the creation and management of a TAR reader, which is capable of interpreting TAR file headers and extracting file data. The primary components include the [`fd_tar_reader_new`](#fd_tar_reader_new) and [`fd_tar_reader_delete`](#fd_tar_reader_delete) functions for creating and destroying TAR reader instances, and the [`fd_tar_read`](#fd_tar_read) function, which processes the data from a TAR archive. The code also includes helper functions like [`fd_tar_process_hdr`](#fd_tar_process_hdr), [`fd_tar_read_hdr`](#fd_tar_read_hdr), and [`fd_tar_read_data`](#fd_tar_read_data) to handle specific tasks related to reading TAR headers and data blocks.

The code is structured to ensure proper alignment and memory management, with checks for null pointers and alignment issues. It uses a callback mechanism, defined by `fd_tar_read_vtable_t`, to allow custom handling of file headers and data as they are read. This design makes the code flexible and extensible, allowing it to be integrated into larger systems that require TAR file processing. The file does not define a public API or external interfaces directly but provides a foundational implementation that can be used as part of a library or application dealing with TAR archives.
# Imports and Dependencies

---
- `fd_tar.h`
- `../fd_util.h`
- `errno.h`


# Functions

---
### fd\_tar\_reader\_new<!-- {{#callable:fd_tar_reader_new}} -->
The `fd_tar_reader_new` function initializes a new TAR reader object in the provided memory space, setting up callback functions for file and read operations.
- **Inputs**:
    - `mem`: A pointer to the memory location where the TAR reader object will be initialized.
    - `cb_vt`: A pointer to a structure containing callback functions for file and read operations.
    - `cb_arg`: A pointer to user-defined data that will be passed to the callback functions.
- **Control Flow**:
    - Check if the `mem` pointer is NULL and log a warning if it is, returning NULL.
    - Check if the `cb_vt` pointer is NULL or if its `file` or `read` members are NULL, log a warning, and return NULL if any are true.
    - Check if the `mem` pointer is properly aligned according to `fd_tar_reader_align()`, log a warning, and return NULL if it is not aligned.
    - Cast the `mem` pointer to `fd_tar_reader_t *` and zero out the memory for the TAR reader object using `fd_memset`.
    - Copy the callback vtable structure pointed to by `cb_vt` into the TAR reader object.
    - Set the `cb_arg` in the TAR reader object to the provided `cb_arg`.
    - Return the initialized TAR reader object.
- **Output**: Returns a pointer to the initialized `fd_tar_reader_t` object, or NULL if any input validation fails.
- **Functions called**:
    - [`fd_tar_reader_align`](fd_tar.h.driver.md#fd_tar_reader_align)


---
### fd\_tar\_reader\_delete<!-- {{#callable:fd_tar_reader_delete}} -->
The `fd_tar_reader_delete` function resets a `fd_tar_reader_t` structure to zero and returns a pointer to it, or returns NULL if the input is NULL.
- **Inputs**:
    - `reader`: A pointer to an `fd_tar_reader_t` structure that is to be reset.
- **Control Flow**:
    - Check if the `reader` pointer is NULL using `FD_UNLIKELY`; if it is, return NULL immediately.
    - Use `fd_memset` to set the memory of the `reader` structure to zero, effectively resetting it.
    - Return the `reader` pointer.
- **Output**: A pointer to the reset `fd_tar_reader_t` structure, or NULL if the input was NULL.


---
### fd\_tar\_process\_hdr<!-- {{#callable:fd_tar_process_hdr}} -->
The `fd_tar_process_hdr` function processes a TAR file header, validates its magic number, extracts the file size, and invokes a callback function with the header information.
- **Inputs**:
    - `reader`: A pointer to an `fd_tar_reader_t` structure, which contains the buffer with the TAR header and callback information.
- **Control Flow**:
    - Cast the buffer in the reader to a `fd_tar_meta_t` structure to access the TAR header fields.
    - Check if the magic number in the header matches the expected TAR magic number; if not, check for EOF or log a protocol error and return an error code.
    - If the magic number is valid, extract the file size from the header using [`fd_tar_meta_get_size`](#fd_tar_meta_get_size).
    - If the file size extraction fails, log a warning and return a protocol error code.
    - Set the file size in the reader and reset the buffer counter.
    - Ensure the file name in the header is null-terminated.
    - Invoke the callback function `file` from the reader's callback vtable with the header and file size.
    - Return the result of the callback function, mapped to an error code if necessary.
- **Output**: Returns 0 on success, -1 if EOF is detected, or an error code (such as `EPROTO` or `EIO`) if a protocol error or callback error occurs.
- **Functions called**:
    - [`fd_tar_meta_get_size`](#fd_tar_meta_get_size)


---
### fd\_tar\_read\_hdr<!-- {{#callable:fd_tar_read_hdr}} -->
The `fd_tar_read_hdr` function reads and processes a TAR file header from a buffer, handling padding and incomplete headers.
- **Inputs**:
    - `reader`: A pointer to an `fd_tar_reader_t` structure that maintains the state of the TAR reading process.
    - `pcur`: A pointer to a pointer to an `uchar` that indicates the current position in the buffer being read.
    - `end`: A pointer to an `uchar` that marks the end of the buffer being read.
- **Control Flow**:
    - Initialize `cur` to the current position pointed to by `*pcur`.
    - If `reader->buf_ctr` is zero, calculate the padding size needed to align the position to 512 bytes and skip this padding in the buffer.
    - Calculate the number of bytes needed to complete the TAR header, ensuring it does not exceed the available bytes in the buffer.
    - Copy the determined number of bytes from the buffer to the reader's buffer, updating `cur` and `reader->buf_ctr` accordingly.
    - If the reader's buffer now contains a complete TAR header, call [`fd_tar_process_hdr`](#fd_tar_process_hdr) to process it.
    - Update `*pcur` to the new position `cur` in the buffer.
    - Return the result of [`fd_tar_process_hdr`](#fd_tar_process_hdr) if a complete header was processed, otherwise return 0.
- **Output**: Returns an integer indicating the result of processing the TAR header, where 0 indicates success and a non-zero value indicates an error.
- **Functions called**:
    - [`fd_tar_process_hdr`](#fd_tar_process_hdr)


---
### fd\_tar\_read\_data<!-- {{#callable:fd_tar_read_data}} -->
The `fd_tar_read_data` function reads a chunk of data from a TAR file and processes it using a callback function, updating the reader's state accordingly.
- **Inputs**:
    - `reader`: A pointer to an `fd_tar_reader_t` structure, which maintains the state of the TAR file reading process.
    - `pcur`: A pointer to a pointer to an `uchar`, representing the current position in the data buffer being read.
    - `end`: A pointer to an `uchar`, representing the end of the data buffer being read.
- **Control Flow**:
    - Initialize `cur` to the value pointed to by `pcur` and assert that `cur` is less than or equal to `end`.
    - Calculate `chunk_sz` as the minimum of `reader->file_sz` and the available size in the buffer (`end - cur`).
    - Invoke the `read` callback function from the reader's callback vtable, passing the current position, the chunk size, and the callback argument.
    - Advance the `cur` pointer by `chunk_sz` and decrease `reader->file_sz` by `chunk_sz`.
    - Update `*pcur` to the new value of `cur`.
    - Return the error code from the callback function.
- **Output**: Returns an integer error code from the callback function, indicating success or failure of the read operation.


---
### fd\_tar\_read<!-- {{#callable:fd_tar_read}} -->
The `fd_tar_read` function processes a buffer of TAR file data, reading headers and file data, and handles errors according to specified tracking behavior.
- **Inputs**:
    - `reader_`: A pointer to a `fd_tar_reader_t` structure that maintains the state of the TAR reading process.
    - `data`: A pointer to a buffer containing the TAR data to be read.
    - `data_sz`: The size of the data buffer in bytes.
    - `track_err`: An integer representing a specific error code to track during the reading process.
- **Control Flow**:
    - Initialize the reader's position and set pointers to the start and end of the data buffer.
    - Initialize a flag `seen_tracked_err` to track if the specified error has been encountered.
    - Enter a loop that continues until the entire data buffer is processed.
    - If there is remaining file data to read (`reader->file_sz` is non-zero), call [`fd_tar_read_data`](#fd_tar_read_data) to read file data.
    - Check for errors from [`fd_tar_read_data`](#fd_tar_read_data); if an error occurs that is not `track_err`, return the error immediately.
    - If `track_err` is encountered, set `seen_tracked_err` to true.
    - Update the reader's position based on the amount of data processed.
    - If no file data remains (`reader->file_sz` is zero), call [`fd_tar_read_hdr`](#fd_tar_read_hdr) to read the next TAR header.
    - Check for errors from [`fd_tar_read_hdr`](#fd_tar_read_hdr); if any error occurs, return it immediately.
    - After processing the entire buffer, if `track_err` was seen, return `track_err`; otherwise, return 0.
- **Output**: Returns 0 if the entire buffer is processed without errors, or `track_err` if that specific error was encountered; otherwise, returns the first non-tracked error encountered.
- **Functions called**:
    - [`fd_tar_read_data`](#fd_tar_read_data)
    - [`fd_tar_read_hdr`](#fd_tar_read_hdr)


---
### fd\_tar\_meta\_get\_size<!-- {{#callable:fd_tar_meta_get_size}} -->
The `fd_tar_meta_get_size` function retrieves the size of a file from a tar header, handling both binary and octal size encodings.
- **Inputs**:
    - `meta`: A pointer to a `fd_tar_meta_t` structure containing the tar header metadata, specifically the size field.
- **Control Flow**:
    - Retrieve the size field from the `meta` structure and store it in `buf`.
    - Check if the first byte of `buf` has the highest bit set, indicating a binary size encoding for OLDGNU tar files.
    - If binary encoding is detected, load the size using `FD_LOAD` and swap the byte order using `fd_ulong_bswap`, then return the result.
    - If not binary encoded, initialize `ret` to 0 and iterate over the first 12 bytes of `buf`.
    - For each byte, if it is a null character, break the loop; otherwise, shift `ret` left by 3 bits and add the numeric value of the current byte (interpreted as an octal digit).
    - Return the computed size in `ret`.
- **Output**: The function returns an `ulong` representing the size of the file as extracted from the tar header.


---
### fd\_tar\_set\_octal<!-- {{#callable:fd_tar_set_octal}} -->
The `fd_tar_set_octal` function converts an unsigned long integer to an octal string representation and stores it in a buffer.
- **Inputs**:
    - `buf`: A character array of at least 12 elements where the octal string representation of the value will be stored.
    - `val`: An unsigned long integer that is to be converted to an octal string.
- **Control Flow**:
    - The function sets the last character of the buffer to a null terminator '\0' to ensure the string is properly terminated.
    - A loop iterates from index 10 to 0 of the buffer, converting the least significant 3 bits of the value to an octal digit and storing it in the buffer.
    - The value is right-shifted by 3 bits in each iteration to process the next set of bits.
    - The loop continues until all 11 characters of the buffer are filled with octal digits.
- **Output**: The function returns an integer indicating whether the conversion was successful, specifically returning 1 if the entire value was successfully converted to octal and 0 otherwise.


