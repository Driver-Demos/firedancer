# Purpose
The provided C code is a part of a library that manages data checkpointing with optional compression using the LZ4 algorithm. It defines several functions to initialize, manage, and finalize checkpoint streams, either in memory-mapped I/O (MMIO) mode or streaming mode. The code includes functionality to check if a particular frame style is supported, handle errors with descriptive messages, and perform data compression and decompression using LZ4 if available. The code is structured to handle both small and large data buffers efficiently, optimizing for performance by using a gather buffer for small buffers and direct compression for larger ones.

The file defines a set of functions that form a cohesive API for managing checkpoints, including [`fd_checkpt_init_stream`](#fd_checkpt_init_stream), [`fd_checkpt_init_mmio`](#fd_checkpt_init_mmio), [`fd_checkpt_fini`](#fd_checkpt_fini), [`fd_checkpt_open_advanced`](#fd_checkpt_open_advanced), and [`fd_checkpt_close_advanced`](#fd_checkpt_close_advanced). These functions are responsible for setting up the checkpoint environment, handling data buffers, and ensuring that the data is correctly compressed and stored. The code also includes conditional compilation to support LZ4 compression if the library is available, making it adaptable to different environments. The use of macros and conditional checks ensures that the code is robust and can handle various error conditions gracefully. Overall, this file provides a specialized functionality focused on efficient data checkpointing with optional compression, suitable for applications that require data persistence and recovery.
# Imports and Dependencies

---
- `fd_checkpt.h`
- `lz4.h`


# Functions

---
### fd\_checkpt\_frame\_style\_is\_supported<!-- {{#callable:fd_checkpt_frame_style_is_supported}} -->
The function `fd_checkpt_frame_style_is_supported` checks if a given frame style is supported by the system.
- **Inputs**:
    - `frame_style`: An integer representing the frame style to be checked for support.
- **Control Flow**:
    - Initialize a variable `supported` to check if `frame_style` is equal to `FD_CHECKPT_FRAME_STYLE_RAW`.
    - If `FD_HAS_LZ4` is defined, update `supported` to also check if `frame_style` is equal to `FD_CHECKPT_FRAME_STYLE_LZ4`.
    - Return the value of `supported`, which indicates whether the frame style is supported.
- **Output**: An integer value indicating whether the specified frame style is supported (non-zero if supported, zero if not).


---
### fd\_checkpt\_strerror<!-- {{#callable:fd_checkpt_strerror}} -->
The `fd_checkpt_strerror` function returns a human-readable string describing the error code passed to it.
- **Inputs**:
    - `err`: An integer representing the error code for which a descriptive string is needed.
- **Control Flow**:
    - The function uses a switch statement to match the input error code against predefined error constants.
    - If the error code matches one of the predefined constants (e.g., `FD_CHECKPT_SUCCESS`, `FD_CHECKPT_ERR_INVAL`, etc.), the function returns a corresponding descriptive string (e.g., "success", "bad input args", etc.).
    - If the error code does not match any predefined constants, the function returns the string "unknown".
- **Output**: A constant character pointer to a string that describes the error code.


---
### fd\_checkpt\_private\_lz4<!-- {{#callable:fd_checkpt_private_lz4}} -->
The `fd_checkpt_private_lz4` function compresses a given buffer using the LZ4 compression algorithm, optimizing for both small and large buffer sizes, and returns the size of the compressed data including a header.
- **Inputs**:
    - `lz4`: A pointer to an LZ4_stream_t structure used for LZ4 compression.
    - `_ubuf`: A pointer to the uncompressed input buffer.
    - `ubuf_usz`: The size of the uncompressed input buffer in bytes.
    - `_cbuf`: A pointer to the buffer where the compressed data will be stored.
    - `cbuf_max`: The maximum size of the compressed buffer in bytes.
    - `_gbuf`: A pointer to a gather buffer used for optimizing compression of small buffers.
    - `gbuf_sz`: The size of the gather buffer in bytes.
    - `gbuf_thresh`: The threshold size to determine if the buffer is considered small.
    - `_gbuf_cursor`: A pointer to the current position in the gather buffer.
- **Control Flow**:
    - Check if the size of the uncompressed buffer (ubuf_usz) is within the valid range and if the compressed buffer (cbuf_max) is large enough to store a header and compressed data.
    - Determine if the buffer is small by comparing ubuf_usz with gbuf_thresh.
    - If the buffer is small, copy it into the gather buffer and update the gather buffer cursor.
    - Calculate the maximum possible compressed size (ubuf_csz_max) based on cbuf_max and a 24-bit limit.
    - Compress the buffer using LZ4_compress_fast_continue, storing the result in the compressed buffer with space for a header.
    - Check for compression errors or unexpected compressed sizes, logging warnings and returning 0 on failure.
    - Write the compressed size into the first three bytes of the compressed buffer as a 24-bit little-endian integer.
    - Return the total size of the compressed data including the header.
- **Output**: Returns the size of the compressed data including a 3-byte header, or 0 if compression fails.


---
### fd\_checkpt\_init\_stream<!-- {{#callable:fd_checkpt_init_stream}} -->
The `fd_checkpt_init_stream` function initializes a checkpoint structure for streaming mode with optional LZ4 compression.
- **Inputs**:
    - `mem`: A pointer to memory where the checkpoint structure will be initialized.
    - `fd`: A file descriptor for the stream; must be non-negative.
    - `wbuf`: A pointer to a write buffer used for streaming.
    - `wbuf_sz`: The size of the write buffer, which must be at least `FD_CHECKPT_WBUF_MIN`.
- **Control Flow**:
    - Check if the `mem` pointer is NULL and return NULL if true, logging a warning.
    - Check if `mem` is aligned according to `FD_CHECKPT_ALIGN` and return NULL if not, logging a warning.
    - Check if `fd` is negative and return NULL if true, logging a warning.
    - Check if the `wbuf` pointer is NULL and return NULL if true, logging a warning.
    - Check if `wbuf_sz` is less than `FD_CHECKPT_WBUF_MIN` and return NULL if true, logging a warning.
    - If LZ4 is available, create an LZ4 stream and return NULL if creation fails, logging a warning.
    - Initialize the `fd_checkpt_t` structure with the provided parameters and the created LZ4 stream if applicable.
    - Return the initialized `fd_checkpt_t` structure.
- **Output**: A pointer to the initialized `fd_checkpt_t` structure, or NULL if initialization fails due to invalid inputs or LZ4 stream creation failure.


---
### fd\_checkpt\_init\_mmio<!-- {{#callable:fd_checkpt_init_mmio}} -->
The `fd_checkpt_init_mmio` function initializes a memory-mapped I/O checkpoint structure with optional LZ4 compression support.
- **Inputs**:
    - `mem`: A pointer to the memory where the checkpoint structure will be initialized; must be aligned to `FD_CHECKPT_ALIGN`.
    - `mmio`: A pointer to the memory-mapped I/O region; can be NULL if `mmio_sz` is zero.
    - `mmio_sz`: The size of the memory-mapped I/O region; must be zero if `mmio` is NULL.
- **Control Flow**:
    - Check if `mem` is NULL and log a warning if so, returning NULL.
    - Check if `mem` is aligned to `FD_CHECKPT_ALIGN` and log a warning if not, returning NULL.
    - Check if `mmio` is NULL while `mmio_sz` is non-zero and log a warning if so, returning NULL.
    - If LZ4 is available, create an LZ4 stream and log a warning if creation fails, returning NULL.
    - Initialize the `fd_checkpt_t` structure at `mem` with default values, setting `fd` to -1 for mmio mode, `frame_style` to 0, and assigning the LZ4 stream if available.
    - Set the `mmio` and `mmio_sz` fields of the checkpoint structure to the provided `mmio` and `mmio_sz` values.
    - Return the initialized checkpoint structure.
- **Output**: A pointer to the initialized `fd_checkpt_t` structure, or NULL if initialization fails due to invalid inputs or LZ4 stream creation failure.


---
### fd\_checkpt\_fini<!-- {{#callable:fd_checkpt_fini}} -->
The `fd_checkpt_fini` function finalizes a checkpoint by ensuring it is not in a frame and optionally freeing LZ4 resources if LZ4 is enabled.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure representing the checkpoint to be finalized.
- **Control Flow**:
    - Check if the `checkpt` pointer is NULL; if so, log a warning and return NULL.
    - Check if the checkpoint is currently in a frame using [`fd_checkpt_in_frame`](fd_checkpt.h.driver.md#fd_checkpt_in_frame); if so, log a warning, set `frame_style` to -1 to indicate failure, and return NULL.
    - If LZ4 is enabled, attempt to free the LZ4 stream associated with the checkpoint; log a warning if freeing fails but continue execution.
    - Return the `checkpt` pointer cast to a `void *`.
- **Output**: Returns a `void *` pointer to the `checkpt` if successful, or NULL if an error occurs.
- **Functions called**:
    - [`fd_checkpt_in_frame`](fd_checkpt.h.driver.md#fd_checkpt_in_frame)


---
### fd\_checkpt\_open\_advanced<!-- {{#callable:fd_checkpt_open_advanced}} -->
The `fd_checkpt_open_advanced` function initializes a checkpoint for writing with a specified frame style and returns the current offset.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure representing the checkpoint to be opened.
    - `frame_style`: An integer specifying the frame style to be used for the checkpoint, which can be raw or LZ4 compressed if supported.
    - `_off`: A pointer to an unsigned long where the current offset of the checkpoint will be stored.
- **Control Flow**:
    - Check if `checkpt` is NULL; if so, log a warning and return an invalid argument error.
    - Check if the checkpoint can be opened using [`fd_checkpt_can_open`](fd_checkpt.h.driver.md#fd_checkpt_can_open); if not, log a warning, set `frame_style` to -1, and return an invalid argument error.
    - Check if `_off` is NULL; if so, log a warning, set `frame_style` to -1, and return an invalid argument error.
    - Determine the effective `frame_style` using `fd_int_if`, defaulting to `FD_CHECKPT_FRAME_STYLE_DEFAULT` if `frame_style` is zero.
    - Use a switch statement to handle different `frame_style` cases:
    - For `FD_CHECKPT_FRAME_STYLE_RAW`, do nothing.
    - For `FD_CHECKPT_FRAME_STYLE_LZ4`, reset the LZ4 stream and set `gbuf_cursor` to 0, if LZ4 is supported.
    - For unsupported frame styles, log a warning, set `frame_style` to -1, and return an unsupported error.
    - Set the `frame_style` of the checkpoint to the effective `frame_style`.
    - Store the current offset of the checkpoint in `_off`.
    - Return success.
- **Output**: Returns an integer status code indicating success or the type of error encountered, such as invalid argument or unsupported frame style.
- **Functions called**:
    - [`fd_checkpt_can_open`](fd_checkpt.h.driver.md#fd_checkpt_can_open)


---
### fd\_checkpt\_close\_advanced<!-- {{#callable:fd_checkpt_close_advanced}} -->
The `fd_checkpt_close_advanced` function finalizes a checkpoint operation by ensuring all data is written out and updates the checkpoint state accordingly.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure representing the checkpoint to be closed.
    - `_off`: A pointer to an `ulong` where the final offset after closing the checkpoint will be stored.
- **Control Flow**:
    - Check if `checkpt` is NULL and log a warning if so, returning `FD_CHECKPT_ERR_INVAL`.
    - Verify if the checkpoint is currently in a frame using [`fd_checkpt_in_frame`](fd_checkpt.h.driver.md#fd_checkpt_in_frame); if not, log a warning and return `FD_CHECKPT_ERR_INVAL`.
    - Check if `_off` is NULL, log a warning if true, and return `FD_CHECKPT_ERR_INVAL`.
    - Retrieve the current offset from the checkpoint structure.
    - Determine if the checkpoint is in memory-mapped I/O (mmio) mode using [`fd_checkpt_is_mmio`](fd_checkpt.h.driver.md#fd_checkpt_is_mmio).
    - If in mmio mode, do nothing further as no data flushing is required.
    - If in streaming mode, check if there are any pending bytes in the write buffer (`wbuf.used`).
    - If there are pending bytes, attempt to write them to the file descriptor using `fd_io_write`.
    - If the write operation fails, log a warning and return `FD_CHECKPT_ERR_IO`.
    - Update the offset with the number of bytes written and check for overflow, logging a warning and returning `FD_CHECKPT_ERR_IO` if overflow occurs.
    - Reset the write buffer usage to zero.
    - Update the checkpoint's offset and set its frame style to indicate it is not in a frame.
    - Store the final offset in the location pointed to by `_off`.
    - Return `FD_CHECKPT_SUCCESS` to indicate successful closure.
- **Output**: Returns an integer status code, `FD_CHECKPT_SUCCESS` on success, or an error code such as `FD_CHECKPT_ERR_INVAL` or `FD_CHECKPT_ERR_IO` on failure.
- **Functions called**:
    - [`fd_checkpt_in_frame`](fd_checkpt.h.driver.md#fd_checkpt_in_frame)
    - [`fd_checkpt_is_mmio`](fd_checkpt.h.driver.md#fd_checkpt_is_mmio)


---
### fd\_checkpt\_private\_buf<!-- {{#callable:fd_checkpt_private_buf}} -->
The `fd_checkpt_private_buf` function writes a buffer to a checkpoint structure, handling different frame styles and ensuring data integrity and size constraints.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure representing the checkpoint context.
    - `buf`: A constant pointer to the buffer containing the data to be written to the checkpoint.
    - `sz`: The size of the buffer `buf` in bytes.
    - `max`: The maximum allowable size for the buffer `buf`.
- **Control Flow**:
    - Check if `checkpt` is NULL and return an error if so.
    - Verify that the checkpoint is in a valid frame; if not, log a warning and return an error.
    - If `sz` is zero, return success immediately as there is nothing to do.
    - Ensure `sz` does not exceed `max`; if it does, log a warning and return an error.
    - Check if `buf` is NULL when `sz` is non-zero, log a warning, and return an error if true.
    - Determine the current offset in the checkpoint structure.
    - Switch based on the `frame_style` of the checkpoint.
    - For `FD_CHECKPT_FRAME_STYLE_RAW`, handle both MMIO and streaming modes, writing data directly or using buffered writes, respectively.
    - For `FD_CHECKPT_FRAME_STYLE_LZ4`, handle both MMIO and streaming modes, compressing data using LZ4 and writing it to the appropriate destination.
    - If an unsupported frame style is encountered, log a warning and return an error.
    - Update the checkpoint's offset and return success.
- **Output**: Returns an integer status code indicating success or the type of error encountered, such as invalid input, I/O error, or compression error.
- **Functions called**:
    - [`fd_checkpt_in_frame`](fd_checkpt.h.driver.md#fd_checkpt_in_frame)
    - [`fd_checkpt_is_mmio`](fd_checkpt.h.driver.md#fd_checkpt_is_mmio)
    - [`fd_checkpt_private_lz4`](#fd_checkpt_private_lz4)


---
### fd\_checkpt\_meta<!-- {{#callable:fd_checkpt_meta}} -->
The `fd_checkpt_meta` function writes metadata to a checkpoint buffer, ensuring the size does not exceed a predefined maximum.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure representing the checkpoint context.
    - `buf`: A constant pointer to the buffer containing the metadata to be written.
    - `sz`: An unsigned long integer representing the size of the metadata buffer.
- **Control Flow**:
    - The function calls [`fd_checkpt_private_buf`](#fd_checkpt_private_buf) with the provided `checkpt`, `buf`, `sz`, and `FD_CHECKPT_META_MAX` as arguments.
    - The [`fd_checkpt_private_buf`](#fd_checkpt_private_buf) function handles the actual writing of the buffer to the checkpoint, checking for various conditions such as whether the checkpoint is in a valid frame, the size is within limits, and the buffer is not null.
    - If any condition fails, appropriate error codes are returned, and warnings are logged.
- **Output**: Returns an integer status code indicating success or failure of the operation, with specific error codes for invalid input, unsupported operations, or I/O errors.
- **Functions called**:
    - [`fd_checkpt_private_buf`](#fd_checkpt_private_buf)


---
### fd\_checkpt\_data<!-- {{#callable:fd_checkpt_data}} -->
The `fd_checkpt_data` function writes a buffer of data to a checkpoint, handling both memory-mapped I/O and streaming modes, with a maximum size limit of `ULONG_MAX`.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure representing the checkpoint context.
    - `buf`: A constant pointer to the buffer containing the data to be written to the checkpoint.
    - `sz`: An unsigned long integer representing the size of the data buffer to be written.
- **Control Flow**:
    - The function calls [`fd_checkpt_private_buf`](#fd_checkpt_private_buf) with the provided `checkpt`, `buf`, and `sz`, and a maximum size of `ULONG_MAX`.
- **Output**: The function returns an integer status code, where `FD_CHECKPT_SUCCESS` indicates success, and other values indicate various errors.
- **Functions called**:
    - [`fd_checkpt_private_buf`](#fd_checkpt_private_buf)


