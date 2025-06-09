# Purpose
This C source code file provides functionality for handling Zstandard (ZSTD) compressed data streams. It is designed to work with the Zstandard compression library, as indicated by the inclusion of `<zstd.h>` and the preprocessor directive that checks for the presence of the `libzstd` library. The file defines several functions that facilitate the creation, management, and operation of ZSTD decompression streams. These functions include initializing a new decompression stream ([`fd_zstd_dstream_new`](#fd_zstd_dstream_new)), resetting a stream ([`fd_zstd_dstream_reset`](#fd_zstd_dstream_reset)), reading and decompressing data from a stream ([`fd_zstd_dstream_read`](#fd_zstd_dstream_read)), and deleting a stream ([`fd_zstd_dstream_delete`](#fd_zstd_dstream_delete)). Additionally, the file provides utility functions to determine the alignment and memory footprint required for a decompression stream.

The code is structured to ensure robust error handling and memory management, with checks for potential errors and memory corruption. It uses a custom data structure (`fd_zstd_dstream_t`) to manage the state of the decompression stream, including memory size and a magic number for validation. The [`fd_zstd_peek`](#fd_zstd_peek) function is used to inspect the frame header of a ZSTD compressed buffer, extracting information such as window size and frame content size. This file is intended to be part of a larger system, likely a library, that provides ZSTD decompression capabilities, and it does not define a standalone executable. The functions defined here serve as an interface for other parts of the system to interact with ZSTD compressed data.
# Imports and Dependencies

---
- `fd_zstd.h`
- `fd_zstd_private.h`
- `../../util/fd_util.h`
- `zstd.h`
- `errno.h`


# Functions

---
### fd\_zstd\_peek<!-- {{#callable:fd_zstd_peek}} -->
The `fd_zstd_peek` function inspects a Zstandard compressed data buffer to extract and return frame header information into a provided structure.
- **Inputs**:
    - `peek`: A pointer to an `fd_zstd_peek_t` structure where the frame header information will be stored.
    - `buf`: A constant pointer to the buffer containing the Zstandard compressed data to be inspected.
    - `bufsz`: An unsigned long integer representing the size of the buffer `buf`.
- **Control Flow**:
    - Declare a `ZSTD_frameHeader` array `hdr` with one element.
    - Call `ZSTD_getFrameHeader` to fill `hdr` with the frame header information from `buf` and store the result in `err`.
    - Check if `err` indicates an error using `ZSTD_isError`; if so, return `NULL`.
    - Check if `err` is greater than 0, indicating that more data is needed; if so, return `NULL`.
    - Call `fd_msan_unpoison` to mark the `hdr` memory as initialized for memory sanitizers.
    - Check if `hdr->windowSize` exceeds the maximum allowed window size; if so, return `NULL`.
    - Populate the `peek` structure with `hdr`'s `windowSize`, `frameContentSize`, and `frameType` information.
    - Return the `peek` pointer.
- **Output**: Returns a pointer to the `fd_zstd_peek_t` structure filled with frame header information, or `NULL` if an error occurs or more data is needed.


---
### fd\_zstd\_dstream\_align<!-- {{#callable:fd_zstd_dstream_align}} -->
The function `fd_zstd_dstream_align` returns the alignment requirement for a ZSTD decompression stream.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `FD_ZSTD_DSTREAM_ALIGN`.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for a ZSTD decompression stream.


---
### fd\_zstd\_dstream\_footprint<!-- {{#callable:fd_zstd_dstream_footprint}} -->
The function `fd_zstd_dstream_footprint` calculates the memory footprint required for a Zstandard decompression stream given a maximum window size.
- **Inputs**:
    - `max_window_sz`: The maximum window size for the Zstandard decompression stream, specified as an unsigned long integer.
- **Control Flow**:
    - The function calculates the offset of the 'mem' field within the 'fd_zstd_dstream_t' structure using the 'offsetof' macro.
    - It then calls 'ZSTD_estimateDStreamSize' with 'max_window_sz' to estimate the size of the decompression stream.
    - The function returns the sum of the offset and the estimated decompression stream size.
- **Output**: The function returns an unsigned long integer representing the total memory footprint required for the decompression stream.


---
### fd\_zstd\_dstream\_new<!-- {{#callable:fd_zstd_dstream_new}} -->
The `fd_zstd_dstream_new` function initializes a new Zstandard decompression stream using a provided memory buffer and a specified maximum window size.
- **Inputs**:
    - `mem`: A pointer to a memory buffer where the decompression stream will be initialized.
    - `max_window_sz`: The maximum window size for the decompression stream, which influences the memory size estimation.
- **Control Flow**:
    - The function casts the provided memory buffer to a `fd_zstd_dstream_t` pointer and estimates the memory size required for the decompression stream using `ZSTD_estimateDStreamSize` with the given `max_window_sz`.
    - It initializes a static decompression stream context using `ZSTD_initStaticDStream` with the memory buffer and the estimated size.
    - If the context initialization fails (unlikely), it logs a warning and returns `NULL`.
    - If the context pointer does not match the memory buffer pointer (unlikely), it logs a critical error.
    - It sets a magic number in the `dstream` structure to indicate successful initialization and returns the `dstream` pointer.
- **Output**: Returns a pointer to the initialized `fd_zstd_dstream_t` structure, or `NULL` if initialization fails.


---
### fd\_zstd\_dstream\_ctx<!-- {{#callable:fd_zstd_dstream_ctx}} -->
The `fd_zstd_dstream_ctx` function retrieves the ZSTD decompression context from a given `fd_zstd_dstream_t` structure, ensuring the structure's integrity by checking its magic number.
- **Inputs**:
    - `dstream`: A pointer to an `fd_zstd_dstream_t` structure, which contains the memory and state for a ZSTD decompression stream.
- **Control Flow**:
    - Check if the `magic` field of the `dstream` structure matches the expected `FD_ZSTD_DSTREAM_MAGIC` value to ensure the structure is valid and not corrupted.
    - If the `magic` value is incorrect, log a critical error indicating potential memory corruption.
    - Return the ZSTD decompression context by casting the `mem` field of the `dstream` structure to a `ZSTD_DCtx` pointer.
- **Output**: A pointer to a `ZSTD_DCtx` structure, which is the decompression context extracted from the `dstream`.


---
### fd\_zstd\_dstream\_delete<!-- {{#callable:fd_zstd_dstream_delete}} -->
The `fd_zstd_dstream_delete` function safely deletes a Zstandard decompression stream by resetting its magic number and memory size to zero, ensuring no memory corruption issues.
- **Inputs**:
    - `dstream`: A pointer to an `fd_zstd_dstream_t` structure representing the Zstandard decompression stream to be deleted.
- **Control Flow**:
    - Check if the `dstream` pointer is NULL; if so, return NULL immediately.
    - Verify that the `magic` field of `dstream` matches the expected `FD_ZSTD_DSTREAM_MAGIC` value to ensure the stream is valid; if not, log a critical error indicating potential memory corruption.
    - Use memory fence operations (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before and after resetting the `magic` and `mem_sz` fields to zero.
    - Return the `dstream` pointer cast to a `void *`.
- **Output**: Returns a `void *` pointer to the `dstream` after it has been reset, or NULL if the input `dstream` was NULL.


---
### fd\_zstd\_dstream\_reset<!-- {{#callable:fd_zstd_dstream_reset}} -->
The `fd_zstd_dstream_reset` function resets a Zstandard decompression stream to prepare it for a new decompression session.
- **Inputs**:
    - `dstream`: A pointer to an `fd_zstd_dstream_t` structure representing the decompression stream to be reset.
- **Control Flow**:
    - The function calls [`fd_zstd_dstream_ctx`](#fd_zstd_dstream_ctx) to retrieve the `ZSTD_DCtx` context from the provided `dstream`.
    - It then calls `ZSTD_DCtx_reset` on the retrieved context with the `ZSTD_reset_session_only` flag to reset the session state of the decompression context.
- **Output**: This function does not return a value; it performs an in-place reset of the decompression stream's session state.
- **Functions called**:
    - [`fd_zstd_dstream_ctx`](#fd_zstd_dstream_ctx)


---
### fd\_zstd\_dstream\_read<!-- {{#callable:fd_zstd_dstream_read}} -->
The `fd_zstd_dstream_read` function decompresses a stream of data using the Zstandard library, updating input and output pointers, and handling errors.
- **Inputs**:
    - `dstream`: A pointer to an `fd_zstd_dstream_t` structure representing the decompression stream context.
    - `in_p`: A pointer to a pointer to the start of the input buffer, which will be updated to reflect the new position after decompression.
    - `in_end`: A pointer to the end of the input buffer.
    - `out_p`: A pointer to a pointer to the start of the output buffer, which will be updated to reflect the new position after decompression.
    - `out_end`: A pointer to the end of the output buffer.
    - `opt_errcode`: An optional pointer to a `ulong` where an error code will be stored if an error occurs during decompression.
- **Control Flow**:
    - Initialize a local error code storage if `opt_errcode` is not provided.
    - Set `in_start` and `out_start` to the current positions of the input and output buffers, respectively.
    - Check if the input or output pointers are invalid (i.e., start is greater than end) and return `EINVAL` if so.
    - Initialize `ZSTD_inBuffer` and `ZSTD_outBuffer` structures with the input and output buffer details.
    - Retrieve the decompression context using [`fd_zstd_dstream_ctx`](#fd_zstd_dstream_ctx).
    - Call `ZSTD_decompressStream` to perform the decompression.
    - Check if the decompression resulted in an error using `ZSTD_isError`, log a warning, set the error code, and return `EPROTO` if an error occurred.
    - Check if no progress was made in decompression (input and output positions did not change) and return `EPIPE` if so.
    - Update the input and output pointers to reflect the new positions after decompression.
    - Return `-1` if the decompression frame is complete, otherwise return `0` to indicate more data is needed.
- **Output**: Returns `-1` if the decompression frame is complete, `0` if more data is needed, or an error code (`EINVAL`, `EPROTO`, or `EPIPE`) if an error occurs.
- **Functions called**:
    - [`fd_zstd_dstream_ctx`](#fd_zstd_dstream_ctx)


