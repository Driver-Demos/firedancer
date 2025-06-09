# Purpose
The provided C source code file implements a set of functions for file descriptor-based input/output operations, primarily targeting POSIX-compliant systems. It defines a series of functions that facilitate reading, writing, seeking, truncating, and memory-mapping files using file descriptors. The code is structured to handle various edge cases and errors, such as non-blocking I/O and end-of-file conditions, and it provides detailed error handling and reporting through functions like [`fd_io_strerror`](#fd_io_strerror) and [`fd_io_strsignal`](#fd_io_strsignal), which translate error codes and signals into human-readable strings. The file is designed to be included in other C programs, as indicated by the inclusion of a header file (`fd_io.h`) and the absence of a `main` function, suggesting it is part of a larger library or system.

The code is modular, with each function addressing a specific aspect of file I/O, such as [`fd_io_read`](#fd_io_read) for reading data, [`fd_io_write`](#fd_io_write) for writing data, and [`fd_io_mmio_init`](#fd_io_mmio_init) for memory-mapped I/O initialization. It also includes buffered I/O operations, which optimize performance for small read and write operations. The use of macros and conditional compilation allows the code to adapt to different environments, ensuring compatibility with various platforms. The file provides a robust and comprehensive interface for file descriptor operations, making it a valuable component for systems requiring efficient and reliable file I/O handling.
# Imports and Dependencies

---
- `fd_io.h`
- `errno.h`
- `signal.h`
- `unistd.h`
- `sys/stat.h`
- `sys/mman.h`


# Functions

---
### fd\_io\_read<!-- {{#callable:fd_io_read}} -->
The `fd_io_read` function reads data from a file descriptor into a buffer, ensuring a minimum number of bytes are read and handling various error conditions.
- **Inputs**:
    - `fd`: An integer representing the file descriptor from which to read.
    - `_dst`: A pointer to the destination buffer where the read data will be stored.
    - `dst_min`: The minimum number of bytes to read from the file descriptor.
    - `dst_max`: The maximum number of bytes to read from the file descriptor.
    - `_dst_sz`: A pointer to an unsigned long where the actual number of bytes read will be stored.
- **Control Flow**:
    - Check if `dst_max` is zero; if so, set `*_dst_sz` to zero and return 0.
    - Initialize `dst` as a pointer to the destination buffer and `dst_sz` to zero.
    - Enter a loop to read data until `dst_sz` is at least `dst_min`.
    - In each iteration, calculate the maximum number of bytes to read, considering `LONG_MAX` and the remaining buffer space.
    - Call `read` to attempt reading from the file descriptor into the buffer.
    - Check if the read was successful and within bounds; if not, handle EOF or errors.
    - If EOF is reached, set `*_dst_sz` to `dst_sz` and return -1.
    - If an error occurs, check for `EAGAIN` and retry if necessary, otherwise return the error code.
    - If the read is successful, update `dst_sz` with the number of bytes read.
    - Continue the loop until `dst_sz` is at least `dst_min`.
    - Set `*_dst_sz` to `dst_sz` and return 0.
- **Output**: Returns 0 on success, -1 on EOF, or an error code on failure; `*_dst_sz` is updated with the number of bytes read.


---
### fd\_io\_write<!-- {{#callable:fd_io_write}} -->
The `fd_io_write` function writes data from a source buffer to a file descriptor, ensuring a minimum amount of data is written and handling potential errors.
- **Inputs**:
    - `fd`: An integer representing the file descriptor to which data will be written.
    - `_src`: A pointer to the source buffer containing the data to be written.
    - `src_min`: An unsigned long specifying the minimum number of bytes that must be written.
    - `src_max`: An unsigned long specifying the maximum number of bytes that can be written.
    - `_src_sz`: A pointer to an unsigned long where the function will store the number of bytes actually written.
- **Control Flow**:
    - Check if `src_max` is zero; if so, set `*_src_sz` to zero and return 0.
    - Cast `_src` to a `uchar` pointer `src` for byte-wise operations.
    - Initialize `src_sz` to zero to track the number of bytes written.
    - Enter a loop that continues until `src_sz` is at least `src_min`.
    - Within the loop, attempt to write data using the `write` system call, limiting the write size to the smaller of `src_max-src_sz` and `LONG_MAX`.
    - Check if the write was successful by ensuring `ssz` is positive and `wsz` is within the remaining buffer size.
    - If the write was unsuccessful, handle errors: map `EWOULDBLOCK` to `EAGAIN`, retry if `src_sz` is less than `src_min` and error is `EAGAIN`, otherwise return an error code.
    - If the write was successful, increment `src_sz` by the number of bytes written (`wsz`).
    - After the loop, set `*_src_sz` to `src_sz` and return 0 to indicate success.
- **Output**: The function returns 0 on success, with `*_src_sz` updated to reflect the number of bytes written; on error, it returns a non-zero error code and sets `*_src_sz` to zero.


---
### fd\_io\_sz<!-- {{#callable:fd_io_sz}} -->
The `fd_io_sz` function retrieves the size of a file associated with a given file descriptor and stores it in a provided variable.
- **Inputs**:
    - `fd`: An integer representing the file descriptor of the file whose size is to be determined.
    - `_sz`: A pointer to an unsigned long where the size of the file will be stored if the operation is successful.
- **Control Flow**:
    - Declare a `struct stat` array to hold file status information.
    - Call `fstat` with the file descriptor `fd` to populate the `stat` structure with file information.
    - Retrieve the file size from `stat->st_size` and store it in `sz`.
    - Check if the `fstat` call was successful and if the file size is within valid bounds (0 to `LONG_MAX`).
    - If the check fails, set the error code to `errno` or `EPROTO` if `errno` is not set, set `*_sz` to 0, and return the error code.
    - If the check passes, cast the file size to `ulong` and store it in `*_sz`, then return 0 indicating success.
- **Output**: Returns 0 on success, with the file size stored in `*_sz`; on failure, returns an error code and sets `*_sz` to 0.


---
### fd\_io\_truncate<!-- {{#callable:fd_io_truncate}} -->
The `fd_io_truncate` function attempts to truncate a file to a specified size using a file descriptor.
- **Inputs**:
    - `fd`: An integer representing the file descriptor of the file to be truncated.
    - `sz`: An unsigned long integer representing the desired size to truncate the file to.
- **Control Flow**:
    - Check if the desired size `sz` is greater than `LONG_MAX` or if it cannot be safely cast to `off_t`; if so, return `EINVAL`.
    - Attempt to truncate the file using `ftruncate` with the file descriptor `fd` and size `sz` cast to `off_t`.
    - If `ftruncate` fails, retrieve the error number from `errno`; if `errno` is not set, use `EPROTO` as a fallback error code.
    - Return the error code if truncation fails, otherwise return 0 indicating success.
- **Output**: Returns 0 on success, or an error code on failure, such as `EINVAL` for invalid size or `EPROTO` for protocol errors.


---
### fd\_io\_seek<!-- {{#callable:fd_io_seek}} -->
The `fd_io_seek` function adjusts the file offset of a file descriptor based on a specified relative offset and seek type, and returns the new offset.
- **Inputs**:
    - `fd`: An integer representing the file descriptor whose offset is to be adjusted.
    - `rel_off`: A long integer specifying the relative offset to apply to the file descriptor's current position.
    - `type`: An integer indicating the type of seek operation, which can be 0 (SEEK_SET), 1 (SEEK_CUR), or 2 (SEEK_END).
    - `_idx`: A pointer to an unsigned long where the resulting file offset will be stored.
- **Control Flow**:
    - The function first checks if the `type` is within the valid range [0, 3] and if `rel_off` can be safely cast to `off_t`. If not, it sets `_idx` to 0 and returns `EINVAL`.
    - It then calls `lseek` with the file descriptor `fd`, the casted `rel_off`, and the corresponding `whence` value from the `whence` array based on `type`.
    - If `lseek` returns an invalid offset (less than 0 or greater than `LONG_MAX`), it retrieves the error from `errno`, sets `_idx` to 0, and returns the error code.
    - If successful, it sets `_idx` to the new offset and returns 0.
- **Output**: The function returns 0 on success, with the new file offset stored in `_idx`. On failure, it returns an error code and sets `_idx` to 0.


---
### fd\_io\_buffered\_read<!-- {{#callable:fd_io_buffered_read}} -->
The `fd_io_buffered_read` function reads data from a file descriptor into a destination buffer, utilizing an intermediate buffer to optimize for small reads.
- **Inputs**:
    - `fd`: The file descriptor from which data is to be read.
    - `_dst`: A pointer to the destination buffer where the read data will be stored.
    - `dst_sz`: The size of the destination buffer, indicating the maximum number of bytes to read.
    - `_rbuf`: A pointer to the read buffer used for buffering data between reads.
    - `rbuf_sz`: The size of the read buffer.
    - `_rbuf_lo`: A pointer to the current offset in the read buffer, indicating where the next read should start.
    - `_rbuf_ready`: A pointer to the number of bytes currently available in the read buffer.
- **Control Flow**:
    - Check if `dst_sz` is zero; if so, return immediately as there's nothing to read.
    - Cast input pointers to appropriate types for processing.
    - If there are bytes already buffered (`rbuf_ready` > 0), copy as many as possible to the destination buffer.
    - If the destination buffer is filled, update buffer pointers and return.
    - If more data is needed, check if the remaining data to read is larger than the buffer size (`rbuf_sz`).
    - If so, read directly into the destination buffer in multiples of `rbuf_sz` to optimize performance.
    - If the destination buffer is still not filled, read the remaining bytes into the read buffer and copy them to the destination buffer.
    - Update the read buffer pointers and return.
- **Output**: Returns 0 on success, or an error code if the read operation fails.
- **Functions called**:
    - [`fd_io_read`](#fd_io_read)


---
### fd\_io\_buffered\_skip<!-- {{#callable:fd_io_buffered_skip}} -->
The `fd_io_buffered_skip` function skips a specified number of bytes in a file descriptor, using buffered data if available, and falls back to seeking or reading if necessary.
- **Inputs**:
    - `fd`: The file descriptor from which bytes are to be skipped.
    - `skip_sz`: The number of bytes to skip.
    - `rbuf`: A buffer used for reading data from the file descriptor.
    - `rbuf_sz`: The size of the buffer `rbuf`.
    - `_rbuf_lo`: A pointer to the current position in the buffer `rbuf`.
    - `_rbuf_ready`: A pointer to the number of bytes currently available in the buffer `rbuf`.
- **Control Flow**:
    - Retrieve the number of bytes currently available in the buffer from `_rbuf_ready`.
    - Check if `skip_sz` is greater than the available buffered bytes (`rbuf_ready`).
    - If `skip_sz` is greater, reduce `skip_sz` by `rbuf_ready` and attempt to skip the remaining bytes using `lseek`.
    - If `lseek` fails with `ESPIPE`, indicating the stream is not seekable, perform actual reads to skip the bytes.
    - Update `_rbuf_lo` and `_rbuf_ready` to reflect the new buffer state after skipping.
    - If `skip_sz` is less than or equal to `rbuf_ready`, adjust `_rbuf_lo` and `_rbuf_ready` to skip the bytes within the buffer.
- **Output**: Returns 0 on success, or an error code if an error occurs during seeking or reading.
- **Functions called**:
    - [`fd_io_read`](#fd_io_read)


---
### fd\_io\_buffered\_write<!-- {{#callable:fd_io_buffered_write}} -->
The `fd_io_buffered_write` function writes data from a source buffer to a file descriptor using a temporary buffer to optimize for small writes.
- **Inputs**:
    - `fd`: The file descriptor to which data will be written.
    - `_src`: A pointer to the source buffer containing the data to be written.
    - `src_sz`: The size of the data in the source buffer to be written.
    - `_wbuf`: A pointer to the temporary buffer used for buffering writes.
    - `wbuf_sz`: The size of the temporary buffer.
    - `_wbuf_used`: A pointer to a variable that tracks the amount of data currently in the temporary buffer.
- **Control Flow**:
    - Check if there is no data to write (`src_sz` is zero) and return immediately if true.
    - Cast the source and buffer pointers to `uchar` pointers for byte-wise operations.
    - Retrieve the current amount of data in the buffer from `_wbuf_used`.
    - If there is already data in the buffer, attempt to copy as much data as possible from the source to the buffer.
    - If the buffer becomes full, flush it by writing to the file descriptor and reset the buffer usage counter.
    - If all data from the source has been written, update `_wbuf_used` and return success.
    - If there is still data to write and the buffer is empty, check if the remaining data is larger than the buffer size.
    - If the remaining data is larger than the buffer size, write it directly to the file descriptor in chunks of `wbuf_sz`.
    - If there is still data left after direct writes, buffer the remaining data in the temporary buffer and update `_wbuf_used`.
- **Output**: Returns 0 on success or an error code if a write operation fails.
- **Functions called**:
    - [`fd_io_write`](#fd_io_write)


---
### fd\_io\_mmio\_init<!-- {{#callable:fd_io_mmio_init}} -->
The `fd_io_mmio_init` function initializes memory-mapped I/O by mapping a file into the caller's address space based on the specified mode.
- **Inputs**:
    - `fd`: An integer file descriptor representing the file to be memory-mapped.
    - `mode`: An integer specifying the mode of access, either read-only or read-write, using predefined constants `FD_IO_MMIO_MODE_READ_ONLY` or `FD_IO_MMIO_MODE_READ_WRITE`.
    - `_mmio`: A pointer to a void pointer where the address of the mapped memory will be stored.
    - `_mmio_sz`: A pointer to an unsigned long where the size of the mapped memory will be stored.
- **Control Flow**:
    - Check if the mode is valid (either read-only or read-write); if not, set `_mmio` to NULL, `_mmio_sz` to 0, and return `EINVAL`.
    - Determine the file size using [`fd_io_sz`](#fd_io_sz); if an error occurs or the file size is zero, set `_mmio` to NULL, `_mmio_sz` to 0, and return the error code.
    - Use `mmap` to map the file into memory with the appropriate protection based on the mode; if `mmap` fails, set `_mmio` to NULL, `_mmio_sz` to 0, and return the error code.
    - If successful, set `_mmio` to the mapped memory address and `_mmio_sz` to the size of the mapped memory, then return 0.
- **Output**: Returns 0 on success, or an error code if the operation fails, with `_mmio` and `_mmio_sz` updated to reflect the mapping status.
- **Functions called**:
    - [`fd_io_sz`](#fd_io_sz)


---
### fd\_io\_mmio\_fini<!-- {{#callable:fd_io_mmio_fini}} -->
The `fd_io_mmio_fini` function unmaps a memory-mapped file from the process's address space if the provided memory address and size are valid.
- **Inputs**:
    - `mmio`: A pointer to the start of the memory-mapped file region to be unmapped.
    - `mmio_sz`: The size of the memory-mapped file region to be unmapped, in bytes.
- **Control Flow**:
    - Check if the `mmio` pointer is NULL or if `mmio_sz` is zero; if either is true, return immediately without doing anything.
    - If both `mmio` and `mmio_sz` are valid, call `munmap` to unmap the memory region specified by `mmio` and `mmio_sz`.
- **Output**: The function does not return any value.


---
### fd\_io\_strerror<!-- {{#callable:fd_io_strerror}} -->
The `fd_io_strerror` function returns a human-readable string description of a given POSIX error code.
- **Inputs**:
    - `err`: An integer representing a POSIX error code, which can be negative, zero, or a positive error code.
- **Control Flow**:
    - Check if the error code is negative; if so, return "end-of-file".
    - If the error code is EWOULDBLOCK, map it to EAGAIN.
    - If the error code is EOPNOTSUPP, map it to ENOTSUP.
    - Use a switch statement to match the error code to a predefined set of POSIX error codes and return the corresponding string description.
    - If the error code does not match any predefined cases, return "unknown".
- **Output**: A constant character pointer to a string describing the error code, or "unknown" if the code is not recognized.


---
### fd\_io\_strsignal<!-- {{#callable:fd_io_strsignal}} -->
The `fd_io_strsignal` function returns a string description of a signal number provided as input.
- **Inputs**:
    - `sig`: An integer representing the signal number for which a string description is needed.
- **Control Flow**:
    - The function uses a switch statement to match the input signal number (`sig`) with predefined signal constants.
    - For each matched signal constant, it returns a corresponding string that describes the signal.
    - If the signal number does not match any predefined constants, the function returns the string "unknown".
    - The function includes conditional compilation directives to handle platform-specific signals like `SIGSTKFLT`, `SIGEMT`, `SIGWINCH`, `SIGPOLL`, and `SIGPWR`.
- **Output**: A constant character pointer to a string that describes the signal corresponding to the input signal number, or "unknown" if the signal is not recognized.


