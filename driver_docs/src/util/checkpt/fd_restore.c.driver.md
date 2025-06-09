# Purpose
The provided C code is a specialized library for handling data restoration from checkpoints, with optional support for LZ4 compression. It defines a set of functions that facilitate the initialization, management, and finalization of data restoration processes, either from memory-mapped I/O (MMIO) or streaming sources. The code includes functions for initializing restoration streams ([`fd_restore_init_stream`](#fd_restore_init_stream)) and MMIO ([`fd_restore_init_mmio`](#fd_restore_init_mmio)), managing the decompression of data using LZ4 ([`fd_restore_private_lz4`](#fd_restore_private_lz4)), and handling the opening and closing of data frames ([`fd_restore_open_advanced`](#fd_restore_open_advanced) and [`fd_restore_close_advanced`](#fd_restore_close_advanced)). The library is designed to be robust, with extensive error checking and logging to handle various edge cases and ensure data integrity during the restoration process.

The core functionality revolves around the `fd_restore_t` structure, which maintains the state of the restoration process, including file descriptors, buffer management, and decompression streams. The code is modular, with conditional compilation directives to include LZ4-specific functionality only if the LZ4 library is available (`FD_HAS_LZ4`). This makes the library flexible and adaptable to different environments. The functions are designed to be used as part of a larger system, providing a public API for initializing, managing, and finalizing data restoration tasks, with a focus on efficiency and error handling. The library does not define a `main` function, indicating that it is intended to be integrated into other applications rather than being a standalone executable.
# Imports and Dependencies

---
- `fd_checkpt.h`
- `lz4.h`


# Functions

---
### fd\_restore\_private\_lz4<!-- {{#callable:fd_restore_private_lz4}} -->
The `fd_restore_private_lz4` function decompresses a compressed buffer using LZ4 and handles small buffer optimizations.
- **Inputs**:
    - `lz4`: A pointer to an LZ4_streamDecode_t structure used for LZ4 decompression.
    - `_ubuf`: A pointer to the destination buffer where decompressed data will be stored.
    - `ubuf_usz`: The size of the uncompressed buffer.
    - `_cbuf`: A pointer to the source buffer containing compressed data.
    - `cbuf_max`: The maximum size of the compressed buffer.
    - `_sbuf`: A pointer to a small buffer used for optimization.
    - `sbuf_sz`: The size of the small buffer.
    - `sbuf_thresh`: The threshold size to determine if the small buffer optimization should be applied.
    - `_sbuf_cursor`: A pointer to a cursor indicating the current position in the small buffer.
- **Control Flow**:
    - Check if `ubuf_usz` is within valid range and `cbuf_max` is large enough to store a header and a non-trivial compressed body.
    - Extract and validate the header from the compressed buffer to determine the size of the compressed data.
    - Check if the compressed buffer size is within valid limits and does not exceed `cbuf_max`.
    - Determine if the small buffer optimization should be applied based on `ubuf_usz` and `sbuf_thresh`.
    - If small buffer optimization is applicable, adjust the small buffer cursor and set `ubuf` to point to the small buffer.
    - Decompress the data using `LZ4_decompress_safe_continue` and handle any errors.
    - If small buffer optimization was used, copy the decompressed data back to the original buffer.
    - Return the size of the compressed buffer used.
- **Output**: Returns the size of the compressed buffer used for decompression, or 0 if an error occurs.


---
### fd\_restore\_init\_stream<!-- {{#callable:fd_restore_init_stream}} -->
The `fd_restore_init_stream` function initializes a restore object for reading from a file descriptor stream, setting up necessary buffers and decompression structures.
- **Inputs**:
    - `mem`: A pointer to memory where the restore object will be initialized.
    - `fd`: A file descriptor from which the stream will be read.
    - `rbuf`: A pointer to a buffer used for reading data from the stream.
    - `rbuf_sz`: The size of the read buffer, which must be at least `FD_RESTORE_RBUF_MIN`.
- **Control Flow**:
    - Check if `mem` is NULL or misaligned, returning NULL if so.
    - Check if `fd` is negative, returning NULL if so.
    - Check if `rbuf` is NULL or `rbuf_sz` is too small, returning NULL if so.
    - Attempt to get the size and current position of the file descriptor; if not seekable, set size to ULONG_MAX and offset to 0.
    - If LZ4 is available, create an LZ4 decompression stream; return NULL if creation fails.
    - Initialize the `fd_restore_t` structure with the provided and calculated values.
    - Return the initialized `fd_restore_t` structure.
- **Output**: A pointer to the initialized `fd_restore_t` structure, or NULL if initialization fails.


---
### fd\_restore\_init\_mmio<!-- {{#callable:fd_restore_init_mmio}} -->
The `fd_restore_init_mmio` function initializes a memory-mapped I/O (MMIO) restore operation by setting up a decompression stream and configuring the restore structure with the provided memory and MMIO parameters.
- **Inputs**:
    - `mem`: A pointer to the memory where the restore structure will be initialized; must be aligned according to `FD_RESTORE_ALIGN`.
    - `mmio`: A constant pointer to the memory-mapped I/O region to be used for the restore operation; can be NULL if `mmio_sz` is zero.
    - `mmio_sz`: The size of the MMIO region; must not exceed `LONG_MAX`.
- **Control Flow**:
    - Check if `mem` is NULL and log a warning if so, returning NULL.
    - Check if `mem` is properly aligned; if not, log a warning and return NULL.
    - Check if `mmio` is NULL while `mmio_sz` is non-zero; if so, log a warning and return NULL.
    - Check if `mmio_sz` exceeds `LONG_MAX`; if so, log a warning and return NULL.
    - If LZ4 is available, create an LZ4 decompression stream; log a warning and return NULL if creation fails.
    - Initialize the `fd_restore_t` structure with the provided `mem`, `mmio`, and `mmio_sz`, setting the mode to MMIO and initializing other fields.
- **Output**: Returns a pointer to the initialized `fd_restore_t` structure, or NULL if any input validation fails or if decompression stream creation fails.


---
### fd\_restore\_fini<!-- {{#callable:fd_restore_fini}} -->
The `fd_restore_fini` function finalizes a restore operation by checking the validity of the restore object, ensuring it is not in a frame, and freeing any associated LZ4 decompression resources if applicable.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure representing the restore operation to be finalized.
- **Control Flow**:
    - Check if the `restore` pointer is NULL; if so, log a warning and return NULL.
    - Check if the restore operation is currently in a frame using [`fd_restore_in_frame`](fd_checkpt.h.driver.md#fd_restore_in_frame); if so, log a warning, set `frame_style` to -1 to indicate failure, and return NULL.
    - If LZ4 support is enabled, attempt to free the LZ4 stream decoder using `LZ4_freeStreamDecode`; log a warning if this operation fails, but continue execution.
    - Return the `restore` pointer.
- **Output**: Returns the `restore` pointer if successful, or NULL if there was an error or the restore operation was in a frame.
- **Functions called**:
    - [`fd_restore_in_frame`](fd_checkpt.h.driver.md#fd_restore_in_frame)


---
### fd\_restore\_open\_advanced<!-- {{#callable:fd_restore_open_advanced}} -->
The `fd_restore_open_advanced` function initializes a restore operation with a specified frame style and updates the offset pointer if successful.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure representing the restore context.
    - `frame_style`: An integer specifying the desired frame style for the restore operation.
    - `_off`: A pointer to an unsigned long where the current offset will be stored if the operation is successful.
- **Control Flow**:
    - Check if the `restore` pointer is NULL and log a warning if so, returning an invalid error code.
    - Verify if the restore context can be opened using [`fd_restore_can_open`](fd_checkpt.h.driver.md#fd_restore_can_open); if not, log a warning, set the frame style to failed, and return an invalid error code.
    - Check if the `_off` pointer is NULL, log a warning if so, set the frame style to failed, and return an invalid error code.
    - Determine the frame style using `fd_int_if`, defaulting to `FD_CHECKPT_FRAME_STYLE_DEFAULT` if `frame_style` is zero.
    - Use a switch statement to handle different frame styles:
    - For `FD_CHECKPT_FRAME_STYLE_RAW`, do nothing and proceed.
    - For `FD_CHECKPT_FRAME_STYLE_LZ4`, attempt to set up LZ4 stream decoding; if it fails, log a warning, set the frame style to failed, and return a compression error code.
    - For unsupported frame styles, log a warning, set the frame style to failed, and return an unsupported error code.
    - Set the `restore`'s frame style to the determined frame style.
    - Update the `_off` pointer with the current offset from the `restore` structure.
    - Return success code `FD_CHECKPT_SUCCESS`.
- **Output**: Returns an integer status code indicating success (`FD_CHECKPT_SUCCESS`) or an error code if the operation fails.
- **Functions called**:
    - [`fd_restore_can_open`](fd_checkpt.h.driver.md#fd_restore_can_open)


---
### fd\_restore\_close\_advanced<!-- {{#callable:fd_restore_close_advanced}} -->
The `fd_restore_close_advanced` function finalizes the closing of a restore frame and updates the offset if the restore is valid and in a frame.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure representing the restore context.
    - `_off`: A pointer to an unsigned long where the current offset will be stored.
- **Control Flow**:
    - Check if the `restore` pointer is NULL; if so, log a warning and return an invalid error code.
    - Check if the restore is currently in a frame using [`fd_restore_in_frame`](fd_checkpt.h.driver.md#fd_restore_in_frame); if not, log a warning, set `frame_style` to -1, and return an invalid error code.
    - Check if the `_off` pointer is NULL; if so, log a warning, set `frame_style` to -1, and return an invalid error code.
    - Set the `frame_style` of the restore to 0, indicating the frame is closed.
    - Store the current offset from the restore structure into the location pointed to by `_off`.
    - Return a success code.
- **Output**: Returns an integer status code, `FD_CHECKPT_SUCCESS` on success or `FD_CHECKPT_ERR_INVAL` on failure.
- **Functions called**:
    - [`fd_restore_in_frame`](fd_checkpt.h.driver.md#fd_restore_in_frame)


---
### fd\_restore\_seek<!-- {{#callable:fd_restore_seek}} -->
The `fd_restore_seek` function adjusts the current offset of a restore operation to a specified position, handling both memory-mapped I/O and streaming modes, while ensuring the offset is valid and within bounds.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure representing the restore operation context.
    - `off`: An unsigned long integer specifying the new offset position to seek to within the restore context.
- **Control Flow**:
    - Check if the `restore` pointer is NULL and log a warning if so, returning an invalid error code.
    - Verify if the restore operation can be opened; if not, log a warning, set the frame style to failed, and return an invalid error code.
    - Check if the size of the restore context exceeds `LONG_MAX`; if so, log a warning, set the frame style to failed, and return an invalid error code.
    - Ensure the specified offset `off` is within the valid range of the restore size; if not, log a warning, set the frame style to failed, and return an invalid error code.
    - If the restore is in memory-mapped I/O mode, directly set the offset to `off`.
    - Otherwise, attempt to seek the file descriptor to the specified offset using `fd_io_seek`; if it fails, log a warning, set the frame style to failed, and return an I/O error code.
    - If the seek operation does not result in the expected offset, log a warning, set the frame style to failed, and return an I/O error code.
    - If successful, update the restore context's offset and reset the buffer's low and ready positions.
- **Output**: Returns `FD_CHECKPT_SUCCESS` on successful seek operation, or an error code indicating the type of failure encountered.
- **Functions called**:
    - [`fd_restore_can_open`](fd_checkpt.h.driver.md#fd_restore_can_open)
    - [`fd_restore_is_mmio`](fd_checkpt.h.driver.md#fd_restore_is_mmio)


---
### fd\_restore\_private\_buf<!-- {{#callable:fd_restore_private_buf}} -->
The `fd_restore_private_buf` function restores data from a checkpoint into a buffer, handling different frame styles and ensuring data integrity.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure that contains the state of the restore operation.
    - `buf`: A pointer to the buffer where the restored data will be written.
    - `sz`: The size of the data to be restored.
    - `max`: The maximum allowable size for the data to be restored.
- **Control Flow**:
    - Check if the `restore` pointer is NULL and return an error if so.
    - Verify that the restore operation is within a valid frame; if not, log a warning and return an error.
    - If `sz` is zero, return success immediately as there is nothing to restore.
    - Ensure `sz` does not exceed `max`; if it does, log a warning and return an error.
    - Check if `buf` is NULL when `sz` is non-zero, log a warning, and return an error if true.
    - Retrieve the current offset from the `restore` structure.
    - Switch based on the `frame_style` of the restore operation.
    - For `FD_CHECKPT_FRAME_STYLE_RAW`, handle both memory-mapped I/O (mmio) and streaming modes, copying data directly or using buffered reads respectively.
    - For `FD_CHECKPT_FRAME_STYLE_LZ4`, handle decompression in both mmio and streaming modes, using LZ4 decompression functions and buffering as needed.
    - If an unsupported frame style is encountered, log a warning and return an error.
    - Update the offset in the `restore` structure after successful data restoration.
    - Return success if the operation completes without errors.
- **Output**: Returns an integer status code indicating success or the type of error encountered during the restore operation.
- **Functions called**:
    - [`fd_restore_in_frame`](fd_checkpt.h.driver.md#fd_restore_in_frame)
    - [`fd_restore_is_mmio`](fd_checkpt.h.driver.md#fd_restore_is_mmio)
    - [`fd_restore_private_lz4`](#fd_restore_private_lz4)


---
### fd\_restore\_meta<!-- {{#callable:fd_restore_meta}} -->
The `fd_restore_meta` function restores metadata from a checkpoint into a buffer using a specified maximum size limit.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure representing the restore context.
    - `buf`: A pointer to the buffer where the metadata will be restored.
    - `sz`: The size of the buffer, indicating how much data to restore.
- **Control Flow**:
    - The function calls [`fd_restore_private_buf`](#fd_restore_private_buf) with the provided `restore`, `buf`, and `sz` arguments, along with `FD_CHECKPT_META_MAX` as the maximum size limit.
    - The [`fd_restore_private_buf`](#fd_restore_private_buf) function handles the actual restoration process, checking for valid inputs and ensuring the operation is performed within the specified size constraints.
- **Output**: The function returns an integer status code indicating success or failure of the restoration process.
- **Functions called**:
    - [`fd_restore_private_buf`](#fd_restore_private_buf)


---
### fd\_restore\_data<!-- {{#callable:fd_restore_data}} -->
The `fd_restore_data` function restores data from a checkpoint into a buffer using a specified restore context.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure that contains the context for the restore operation.
    - `buf`: A pointer to the buffer where the restored data will be stored.
    - `sz`: The size of the data to be restored, specified as an unsigned long integer.
- **Control Flow**:
    - The function calls [`fd_restore_private_buf`](#fd_restore_private_buf) with the provided `restore`, `buf`, and `sz` arguments, and a maximum size of `ULONG_MAX`.
    - The [`fd_restore_private_buf`](#fd_restore_private_buf) function handles the actual data restoration process, checking the validity of inputs and performing the restoration based on the frame style (e.g., raw or LZ4 compressed).
    - If the restoration is successful, the function returns a success code; otherwise, it returns an error code indicating the type of failure.
- **Output**: The function returns an integer status code indicating the success or failure of the data restoration operation.
- **Functions called**:
    - [`fd_restore_private_buf`](#fd_restore_private_buf)


