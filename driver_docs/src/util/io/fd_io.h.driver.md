# Purpose
The provided C header file defines a comprehensive API for high-performance, platform-agnostic stream I/O operations. It includes both blocking and non-blocking read and write functionalities, as well as buffered I/O operations to optimize performance by reducing the number of system calls required for small data transfers. The file defines several key structures and functions for managing input and output streams, including [`fd_io_read`](#fd_io_read), [`fd_io_write`](#fd_io_write), and their buffered counterparts, [`fd_io_buffered_read`](#fd_io_buffered_read) and [`fd_io_buffered_write`](#fd_io_buffered_write). These functions are designed to handle various I/O scenarios, such as reading or writing a specific number of bytes, handling end-of-file conditions, and managing I/O errors in a consistent manner.

Additionally, the file provides memory-mapped I/O capabilities through functions like [`fd_io_mmio_init`](#fd_io_mmio_init) and [`fd_io_mmio_fini`](#fd_io_mmio_fini), allowing files to be mapped into memory for efficient access. The header also includes utility functions for error and signal handling, such as [`fd_io_strerror`](#fd_io_strerror) and [`fd_io_strsignal`](#fd_io_strsignal), which convert error codes and signal codes into human-readable strings. The API is designed to be robust and efficient, with careful attention to error handling and performance optimization, making it suitable for high-performance applications that require efficient data streaming and manipulation.
# Imports and Dependencies

---
- `../bits/fd_bits.h`


# Global Variables

---
### fd\_io\_strerror
- **Type**: ``FD_FN_CONST char const *``
- **Description**: The `fd_io_strerror` function is a global function that returns a constant character pointer. It is used to convert an fd_io error code into a human-readable string. The function is thread-safe and the returned string has an infinite lifetime.
- **Use**: This function is used to provide a human-readable description of error codes related to fd_io operations.


---
### fd\_io\_strsignal
- **Type**: `function pointer`
- **Description**: `fd_io_strsignal` is a function that converts a signal code, such as those returned by `WTERMSIG`, into a human-readable string. This function is designed to be thread-safe and does not rely on system calls like `brk(3)` or `futex(2)`, unlike some other implementations such as glibc's `strsignal`. The returned string is always non-NULL and has an infinite lifetime.
- **Use**: This function is used to obtain a human-readable description of a signal code in a thread-safe manner.


# Data Structures

---
### fd\_io\_buffered\_istream\_private
- **Type**: `struct`
- **Members**:
    - `fd`: An integer representing the open file descriptor of the stream.
    - `rbuf`: A pointer to an unsigned character array serving as the read buffer.
    - `rbuf_sz`: An unsigned long indicating the size of the read buffer.
    - `rbuf_lo`: An unsigned long representing the number of bytes in the buffer that have already been consumed.
    - `rbuf_ready`: An unsigned long indicating the number of buffered bytes that have not yet been consumed.
- **Description**: The `fd_io_buffered_istream_private` structure is designed to manage buffered input streams in a platform-agnostic manner, facilitating high-performance I/O operations. It encapsulates the state of a buffered input stream, including the file descriptor, a read buffer, and metadata about the buffer's size and consumption state. This structure is used internally to optimize read operations by minimizing system calls and efficiently managing buffered data.


---
### fd\_io\_buffered\_istream\_t
- **Type**: `struct`
- **Members**:
    - `fd`: Open normal-ish file descriptor of stream.
    - `rbuf`: Read buffer, non-NULL, indexed [0,rbuf_sz), arb alignment.
    - `rbuf_sz`: Read buffer size, positive.
    - `rbuf_lo`: Buf bytes [0,rbuf_lo) have already been consumed.
    - `rbuf_ready`: Number of buffered bytes that haven't been consumed, 0<=rbuf_lo<=(rbuf_lo+rbuf_ready)<=rbuf_sz.
- **Description**: The `fd_io_buffered_istream_t` is a structure designed for buffered input stream operations, providing efficient reading from a file descriptor by utilizing a buffer. It maintains the state of the stream, including the file descriptor, the buffer for reading, and the current status of the buffer in terms of consumed and ready bytes. This structure is used to optimize I/O operations by reducing the number of system calls required for reading data, especially useful in high-performance scenarios where minimizing latency and maximizing throughput are critical.


---
### fd\_io\_buffered\_ostream\_private
- **Type**: `struct`
- **Members**:
    - `fd`: Open normal-ish file descriptor of stream.
    - `wbuf`: Write buffer, non-NULL, indexed [0,wbuf_sz), arb alignment.
    - `wbuf_sz`: Write buffer size, positive.
    - `wbuf_used`: Number of buffered bytes that haven't been written to fd, in [0,wbuf_sz].
- **Description**: The `fd_io_buffered_ostream_private` structure is used to manage buffered output streams in a platform-agnostic high-performance I/O system. It contains a file descriptor `fd` for the stream, a write buffer `wbuf` to temporarily hold data before writing it to the file descriptor, the size of this buffer `wbuf_sz`, and `wbuf_used` which tracks how much of the buffer is currently filled with data that has not yet been written to the file descriptor. This structure is crucial for optimizing write operations by reducing the number of system calls needed for small writes, thus improving performance.


---
### fd\_io\_buffered\_ostream\_t
- **Type**: `struct`
- **Members**:
    - `fd`: Open normal-ish file descriptor of stream.
    - `wbuf`: Write buffer, non-NULL, indexed [0,wbuf_sz), arb alignment.
    - `wbuf_sz`: Write buffer size, positive.
    - `wbuf_used`: Number of buffered bytes that haven't been written to fd, in [0,wbuf_sz].
- **Description**: The `fd_io_buffered_ostream_t` is a data structure designed for buffered output stream operations. It encapsulates a file descriptor and a write buffer, allowing efficient writing by minimizing the number of system calls through buffering. The structure maintains the state of the buffer, including its size and the number of bytes currently buffered but not yet written to the file descriptor. This setup is particularly useful for high-performance I/O operations where reducing the overhead of frequent system calls is critical.


# Functions

---
### fd\_io\_buffered\_istream\_init<!-- {{#callable:fd_io_buffered_istream_init}} -->
The `fd_io_buffered_istream_init` function initializes a buffered input stream for reading from a file descriptor using a specified buffer.
- **Inputs**:
    - `in`: A pointer to an `fd_io_buffered_istream_t` structure that will hold the state of the buffered input stream.
    - `fd`: An integer representing the file descriptor from which the stream will read.
    - `rbuf`: A pointer to a memory region that will be used as the read buffer for the stream.
    - `rbuf_sz`: An unsigned long representing the size of the read buffer.
- **Control Flow**:
    - Assigns the file descriptor `fd` to the `fd` field of the `in` structure.
    - Casts the `rbuf` pointer to `uchar *` and assigns it to the `rbuf` field of the `in` structure.
    - Sets the `rbuf_sz` field of the `in` structure to the value of `rbuf_sz`.
    - Initializes the `rbuf_lo` field to 0, indicating no bytes have been consumed yet.
    - Initializes the `rbuf_ready` field to 0, indicating no bytes are currently buffered.
    - Returns the pointer `in` after initialization.
- **Output**: Returns the initialized `fd_io_buffered_istream_t` pointer `in`.


---
### fd\_io\_buffered\_istream\_fd<!-- {{#callable:fd_io_buffered_istream_fd}} -->
The function `fd_io_buffered_istream_fd` retrieves the file descriptor from a buffered input stream structure.
- **Inputs**:
    - `in`: A pointer to a constant `fd_io_buffered_istream_t` structure, representing a buffered input stream.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It directly accesses the `fd` member of the `fd_io_buffered_istream_t` structure pointed to by `in` and returns its value.
- **Output**: The function returns an integer representing the file descriptor associated with the buffered input stream.


---
### fd\_io\_buffered\_istream\_rbuf<!-- {{#callable:fd_io_buffered_istream_rbuf}} -->
The function `fd_io_buffered_istream_rbuf` returns the read buffer pointer from a buffered input stream structure.
- **Inputs**:
    - `in`: A pointer to a constant `fd_io_buffered_istream_t` structure, representing the buffered input stream from which the read buffer pointer is to be retrieved.
- **Control Flow**:
    - The function is a simple accessor that directly returns the `rbuf` member of the `fd_io_buffered_istream_t` structure pointed to by `in`.
- **Output**: A void pointer to the read buffer (`rbuf`) used by the buffered input stream.


---
### fd\_io\_buffered\_istream\_rbuf\_sz<!-- {{#callable:fd_io_buffered_istream_rbuf_sz}} -->
The function `fd_io_buffered_istream_rbuf_sz` returns the size of the read buffer used in a buffered input stream.
- **Inputs**:
    - `in`: A pointer to a constant `fd_io_buffered_istream_t` structure, representing a buffered input stream.
- **Control Flow**:
    - The function is a simple inline function that directly accesses the `rbuf_sz` member of the `fd_io_buffered_istream_t` structure pointed to by `in`.
    - It returns the value of `rbuf_sz`, which represents the size of the read buffer associated with the input stream.
- **Output**: The function returns an `ulong` representing the size of the read buffer (`rbuf_sz`) of the buffered input stream.


---
### fd\_io\_buffered\_istream\_fini<!-- {{#callable:fd_io_buffered_istream_fini}} -->
The `fd_io_buffered_istream_fini` function finalizes a buffered input stream, indicating that it is no longer in use and relinquishing ownership of the underlying file descriptor and buffer.
- **Inputs**:
    - `in`: A pointer to an `fd_io_buffered_istream_t` structure representing the buffered input stream to be finalized.
- **Control Flow**:
    - The function takes a single argument, a pointer to a buffered input stream structure.
    - It performs no operations on the input stream, as indicated by the cast to void, which suggests that the function is a placeholder or a no-op in its current form.
- **Output**: The function does not return any value or produce any output.


---
### fd\_io\_buffered\_istream\_read<!-- {{#callable:fd_io_buffered_istream_read}} -->
The `fd_io_buffered_istream_read` function reads a specified number of bytes from a buffered input stream into a destination buffer, updating the stream's buffer state accordingly.
- **Inputs**:
    - `in`: A pointer to an initialized `fd_io_buffered_istream_t` structure representing the buffered input stream.
    - `dst`: A pointer to the destination buffer where the read bytes will be stored.
    - `dst_sz`: The number of bytes to read from the input stream into the destination buffer.
- **Control Flow**:
    - Extracts the current buffer state from the `in` structure, specifically `rbuf_lo` and `rbuf_ready`.
    - Calls [`fd_io_buffered_read`](fd_io.c.driver.md#fd_io_buffered_read) with the file descriptor, destination buffer, destination size, read buffer, read buffer size, and pointers to `rbuf_lo` and `rbuf_ready` to perform the read operation.
    - Updates the `rbuf_lo` and `rbuf_ready` fields in the `in` structure with the new buffer state after the read operation.
    - Returns the error code from [`fd_io_buffered_read`](fd_io.c.driver.md#fd_io_buffered_read), indicating success or failure of the read operation.
- **Output**: Returns an integer error code: 0 on success, a negative value if EOF is encountered before reading the specified number of bytes, or a positive errno-compatible error code on I/O failure.
- **Functions called**:
    - [`fd_io_buffered_read`](fd_io.c.driver.md#fd_io_buffered_read)


---
### fd\_io\_buffered\_istream\_skip<!-- {{#callable:fd_io_buffered_istream_skip}} -->
The `fd_io_buffered_istream_skip` function skips a specified number of bytes in a buffered input stream, updating the stream's internal buffer state accordingly.
- **Inputs**:
    - `in`: A pointer to an initialized `fd_io_buffered_istream_t` structure representing the buffered input stream.
    - `skip_sz`: The number of bytes to skip in the input stream.
- **Control Flow**:
    - Destructure the input stream `in` to local variables `rbuf_lo` and `rbuf_ready` to avoid pointer escapes that might inhibit optimizations.
    - Call [`fd_io_buffered_skip`](fd_io.c.driver.md#fd_io_buffered_skip) with the file descriptor, skip size, buffer, buffer size, and the local variables to perform the skip operation.
    - Update the `rbuf_lo` and `rbuf_ready` fields of `in` with the modified local variables.
    - Return the error code from [`fd_io_buffered_skip`](fd_io.c.driver.md#fd_io_buffered_skip).
- **Output**: Returns an integer error code: 0 on success, a negative value if EOF is encountered before skipping the specified bytes, or a positive errno-compatible error code on failure.
- **Functions called**:
    - [`fd_io_buffered_skip`](fd_io.c.driver.md#fd_io_buffered_skip)


---
### fd\_io\_buffered\_istream\_peek<!-- {{#callable:fd_io_buffered_istream_peek}} -->
The `fd_io_buffered_istream_peek` function returns a pointer to the first unconsumed byte in a buffered input stream.
- **Inputs**:
    - `in`: A pointer to an initialized `fd_io_buffered_istream_t` structure representing the buffered input stream.
- **Control Flow**:
    - The function accesses the read buffer (`rbuf`) of the input stream structure `in`.
    - It calculates the address of the first unconsumed byte by adding the offset `rbuf_lo` to the base address of the buffer `rbuf`.
    - The function returns this calculated address as a pointer to the first unconsumed byte.
- **Output**: A pointer to the first byte in the read buffer that has been read but not yet consumed, valid until the next read, fetch, or fini operation.


---
### fd\_io\_buffered\_istream\_peek\_sz<!-- {{#callable:fd_io_buffered_istream_peek_sz}} -->
The function `fd_io_buffered_istream_peek_sz` returns the number of bytes currently buffered and ready to be consumed from a buffered input stream.
- **Inputs**:
    - `in`: A pointer to an `fd_io_buffered_istream_t` structure representing the buffered input stream.
- **Control Flow**:
    - The function accesses the `rbuf_ready` field of the `fd_io_buffered_istream_t` structure pointed to by `in`.
    - It returns the value of `rbuf_ready`, which indicates the number of bytes that have been read into the buffer but not yet consumed.
- **Output**: The function returns an `ulong` representing the number of bytes currently buffered and ready to be consumed.


---
### fd\_io\_buffered\_istream\_seek<!-- {{#callable:fd_io_buffered_istream_seek}} -->
The `fd_io_buffered_istream_seek` function advances the read buffer pointers of a buffered input stream by a specified number of bytes.
- **Inputs**:
    - `in`: A pointer to an `fd_io_buffered_istream_t` structure representing the buffered input stream.
    - `sz`: The number of bytes to advance the read buffer pointers by.
- **Control Flow**:
    - The function increments the `rbuf_lo` member of the `fd_io_buffered_istream_t` structure by `sz`, indicating that `sz` bytes have been consumed from the buffer.
    - The function decrements the `rbuf_ready` member of the `fd_io_buffered_istream_t` structure by `sz`, reducing the count of buffered bytes that are ready to be consumed.
- **Output**: This function does not return a value; it modifies the state of the input stream buffer in place.


---
### fd\_io\_buffered\_istream\_fetch<!-- {{#callable:fd_io_buffered_istream_fetch}} -->
The `fd_io_buffered_istream_fetch` function attempts to fill a buffered input stream's read buffer with as many unconsumed bytes as possible from the underlying file descriptor.
- **Inputs**:
    - `in`: A pointer to an initialized `fd_io_buffered_istream_t` structure representing the buffered input stream.
- **Control Flow**:
    - Check if the buffer is already full by comparing `rbuf_ready` with `rbuf_sz`; if full, return 0.
    - If there are unconsumed bytes (`rbuf_ready` > 0) and the buffer is not at the start (`rbuf_lo` > 0), move the unconsumed bytes to the beginning of the buffer using `memmove`.
    - Call [`fd_io_read`](fd_io.c.driver.md#fd_io_read) to read more data from the file descriptor into the buffer, starting at the position after the unconsumed bytes, and update `rsz` with the number of bytes read.
    - Update `rbuf_lo` to 0 and `rbuf_ready` to the sum of the previous `rbuf_ready` and `rsz`.
    - Return the error code from [`fd_io_read`](fd_io.c.driver.md#fd_io_read), which indicates success, end-of-file, or an I/O error.
- **Output**: Returns an integer error code: 0 on success, a negative value if end-of-file is encountered, or a positive errno-compatible error code on failure.
- **Functions called**:
    - [`fd_io_read`](fd_io.c.driver.md#fd_io_read)


---
### fd\_io\_buffered\_ostream\_init<!-- {{#callable:fd_io_buffered_ostream_init}} -->
The `fd_io_buffered_ostream_init` function initializes a buffered output stream for writing to a file descriptor using a specified buffer.
- **Inputs**:
    - `out`: A pointer to an `fd_io_buffered_ostream_t` structure that will hold the state of the buffered output stream.
    - `fd`: An integer representing the file descriptor to which the buffered output stream will write.
    - `wbuf`: A pointer to a memory region that will be used as the write buffer for the buffered output stream.
    - `wbuf_sz`: An unsigned long integer specifying the size of the write buffer.
- **Control Flow**:
    - Assigns the file descriptor `fd` to the `fd` field of the `out` structure.
    - Casts the `wbuf` pointer to `uchar *` and assigns it to the `wbuf` field of the `out` structure.
    - Sets the `wbuf_sz` field of the `out` structure to the value of `wbuf_sz`.
    - Initializes the `wbuf_used` field of the `out` structure to 0, indicating that no bytes are currently buffered.
    - Returns the pointer `out` after initialization.
- **Output**: Returns a pointer to the initialized `fd_io_buffered_ostream_t` structure.


---
### fd\_io\_buffered\_ostream\_fd<!-- {{#callable:fd_io_buffered_ostream_fd}} -->
The function `fd_io_buffered_ostream_fd` retrieves the file descriptor from a buffered output stream structure.
- **Inputs**:
    - `out`: A pointer to a constant `fd_io_buffered_ostream_t` structure representing the buffered output stream.
- **Control Flow**:
    - The function accesses the `fd` field of the `fd_io_buffered_ostream_t` structure pointed to by `out`.
    - It returns the value of the `fd` field, which is the file descriptor associated with the buffered output stream.
- **Output**: The function returns an integer representing the file descriptor of the buffered output stream.


---
### fd\_io\_buffered\_ostream\_wbuf<!-- {{#callable:fd_io_buffered_ostream_wbuf}} -->
The function `fd_io_buffered_ostream_wbuf` returns the write buffer pointer of a buffered output stream.
- **Inputs**:
    - `out`: A pointer to a constant `fd_io_buffered_ostream_t` structure representing the buffered output stream.
- **Control Flow**:
    - The function accesses the `wbuf` member of the `fd_io_buffered_ostream_t` structure pointed to by `out`.
    - It returns the value of the `wbuf` member, which is a pointer to the write buffer.
- **Output**: A pointer to the write buffer (`void *`) of the buffered output stream.


---
### fd\_io\_buffered\_ostream\_wbuf\_sz<!-- {{#callable:fd_io_buffered_ostream_wbuf_sz}} -->
The function `fd_io_buffered_ostream_wbuf_sz` returns the size of the write buffer for a given buffered output stream.
- **Inputs**:
    - `out`: A pointer to a constant `fd_io_buffered_ostream_t` structure representing the buffered output stream.
- **Control Flow**:
    - The function accesses the `wbuf_sz` field of the `fd_io_buffered_ostream_t` structure pointed to by `out`.
    - It returns the value of the `wbuf_sz` field, which represents the size of the write buffer.
- **Output**: The function returns an `ulong` representing the size of the write buffer for the specified buffered output stream.


---
### fd\_io\_buffered\_ostream\_fini<!-- {{#callable:fd_io_buffered_ostream_fini}} -->
The `fd_io_buffered_ostream_fini` function finalizes a buffered output stream, releasing ownership of the underlying file descriptor and write buffer without performing any final flush of buffered data.
- **Inputs**:
    - `out`: A pointer to an `fd_io_buffered_ostream_t` structure representing the buffered output stream to be finalized.
- **Control Flow**:
    - The function takes a single argument, `out`, which is a pointer to a buffered output stream structure.
    - The function does not perform any operations on the `out` parameter other than casting it to void to suppress unused variable warnings.
    - The function does not perform any flushing of buffered data, leaving it to the caller to handle any necessary final flushes before calling this function.
- **Output**: The function does not return any value or output.


---
### fd\_io\_buffered\_ostream\_write<!-- {{#callable:fd_io_buffered_ostream_write}} -->
The `fd_io_buffered_ostream_write` function writes data from a source buffer to a buffered output stream, updating the buffer's usage and returning any error encountered during the write operation.
- **Inputs**:
    - `out`: A pointer to an `fd_io_buffered_ostream_t` structure representing the buffered output stream.
    - `src`: A pointer to the source data to be written to the output stream.
    - `src_sz`: The size in bytes of the data to be written from the source buffer.
- **Control Flow**:
    - Extract the current number of used bytes in the write buffer from the `out` structure.
    - Call [`fd_io_buffered_write`](fd_io.c.driver.md#fd_io_buffered_write) to write data from `src` to the output stream, using the buffer in `out` and updating the number of used bytes.
    - Update the `wbuf_used` field in `out` with the new number of used bytes after the write operation.
    - Return the error code from [`fd_io_buffered_write`](fd_io.c.driver.md#fd_io_buffered_write), indicating success or failure of the write operation.
- **Output**: Returns an integer error code, where 0 indicates success and non-zero indicates an I/O error.
- **Functions called**:
    - [`fd_io_buffered_write`](fd_io.c.driver.md#fd_io_buffered_write)


---
### fd\_io\_buffered\_ostream\_peek<!-- {{#callable:fd_io_buffered_ostream_peek}} -->
The `fd_io_buffered_ostream_peek` function returns a pointer to the location in the write buffer where new data can be prepared for streaming out.
- **Inputs**:
    - `out`: A pointer to an initialized `fd_io_buffered_ostream_t` structure representing the buffered output stream.
- **Control Flow**:
    - The function accesses the `wbuf` and `wbuf_used` fields of the `fd_io_buffered_ostream_t` structure pointed to by `out`.
    - It calculates the pointer to the next available space in the write buffer by adding `wbuf_used` to the base address of `wbuf`.
    - The function returns this calculated pointer.
- **Output**: A pointer to the next available space in the write buffer, where new data can be prepared for writing.


---
### fd\_io\_buffered\_ostream\_peek\_sz<!-- {{#callable:fd_io_buffered_ostream_peek_sz}} -->
The function `fd_io_buffered_ostream_peek_sz` returns the amount of unused space available in the write buffer of a buffered output stream.
- **Inputs**:
    - `out`: A pointer to an `fd_io_buffered_ostream_t` structure representing the buffered output stream.
- **Control Flow**:
    - The function calculates the unused space in the write buffer by subtracting the number of bytes currently used (`wbuf_used`) from the total buffer size (`wbuf_sz`).
    - It returns the result of this subtraction, which represents the available space in the buffer.
- **Output**: The function returns an `ulong` representing the number of bytes of unused space in the write buffer, which is in the range [0, wbuf_sz].


---
### fd\_io\_buffered\_ostream\_seek<!-- {{#callable:fd_io_buffered_ostream_seek}} -->
The `fd_io_buffered_ostream_seek` function updates the number of used bytes in the write buffer of a buffered output stream by a specified size.
- **Inputs**:
    - `out`: A pointer to an `fd_io_buffered_ostream_t` structure representing the buffered output stream.
    - `sz`: An unsigned long integer representing the number of bytes to add to the `wbuf_used` field of the output stream.
- **Control Flow**:
    - The function takes a pointer to a buffered output stream and a size as inputs.
    - It increments the `wbuf_used` field of the `fd_io_buffered_ostream_t` structure by the specified size `sz`.
- **Output**: The function does not return any value; it modifies the `wbuf_used` field of the `fd_io_buffered_ostream_t` structure in place.


---
### fd\_io\_buffered\_ostream\_flush<!-- {{#callable:fd_io_buffered_ostream_flush}} -->
The `fd_io_buffered_ostream_flush` function flushes the buffered data from a buffered output stream to the underlying file descriptor.
- **Inputs**:
    - `out`: A pointer to an `fd_io_buffered_ostream_t` structure representing the buffered output stream to be flushed.
- **Control Flow**:
    - Retrieve the number of bytes currently buffered (`wbuf_used`) from the `out` structure.
    - Check if `wbuf_used` is zero; if so, return 0 immediately to optimize for cases with many small writes.
    - Set `wbuf_used` in the `out` structure to zero, indicating the buffer is now empty.
    - Call [`fd_io_write`](fd_io.c.driver.md#fd_io_write) to write the buffered data to the file descriptor, passing the file descriptor, buffer, and the number of bytes to write.
    - Return the result of the [`fd_io_write`](fd_io.c.driver.md#fd_io_write) call, which indicates success or failure of the write operation.
- **Output**: Returns 0 on success, indicating all buffered bytes have been written to the file descriptor, or a non-zero error code if an I/O error occurs.
- **Functions called**:
    - [`fd_io_write`](fd_io.c.driver.md#fd_io_write)


# Function Declarations (Public API)

---
### fd\_io\_read<!-- {{#callable_declaration:fd_io_read}} -->
Reads data from a file descriptor into a buffer.
- **Description**: This function reads at least `dst_min` bytes and at most `dst_max` bytes from the specified file descriptor `fd` into the buffer pointed to by `dst`. It is designed to handle both blocking and non-blocking file descriptors. The function will block until at least `dst_min` bytes are read, EOF is encountered, or an error occurs. If `dst_min` is zero, the function attempts a non-blocking read. The function updates the number of bytes read in `_dst_sz` and returns 0 on success, a negative value if EOF is encountered before `dst_min` bytes are read, or a positive error code on failure. The buffer contents are undefined in case of an error.
- **Inputs**:
    - `fd`: An open file descriptor from which data is to be read. It can be blocking or non-blocking.
    - `dst`: A pointer to the buffer where the read data will be stored. Must not be null and should have at least `dst_max` bytes available.
    - `dst_min`: The minimum number of bytes to read. Must be less than or equal to `dst_max`.
    - `dst_max`: The maximum number of bytes to read. If zero, the function is a no-op.
    - `_dst_sz`: A pointer to a variable where the number of bytes actually read will be stored. Must not be null.
- **Output**: Returns 0 on success with `_dst_sz` updated to the number of bytes read. Returns a negative value if EOF is encountered before `dst_min` bytes are read, with `_dst_sz` indicating the number of bytes read. Returns a positive error code on failure, with `_dst_sz` set to zero and buffer contents undefined.
- **See also**: [`fd_io_read`](fd_io.c.driver.md#fd_io_read)  (Implementation)


---
### fd\_io\_write<!-- {{#callable_declaration:fd_io_write}} -->
Writes data from a buffer to a file descriptor.
- **Description**: This function writes a specified number of bytes from a source buffer to a file descriptor, ensuring that at least a minimum number of bytes are written. It is designed to handle both blocking and non-blocking file descriptors. The function will attempt to write between `src_min` and `src_max` bytes from the buffer pointed to by `src`. If `src_min` is greater than zero, the function will block until at least `src_min` bytes are written or an error occurs. If `src_min` is zero, the function will attempt a non-blocking write if the file descriptor is non-blocking. The function returns an error code if an I/O error occurs, and the file descriptor should be considered failed if the error is not `EAGAIN`. The number of bytes successfully written is stored in the location pointed to by `_src_sz`.
- **Inputs**:
    - `fd`: An open file descriptor to which data will be written. It must be a valid, open file descriptor.
    - `src`: A pointer to the buffer containing the data to be written. Must not be null, and the caller retains ownership.
    - `src_min`: The minimum number of bytes to write. Must be less than or equal to `src_max`.
    - `src_max`: The maximum number of bytes to write. If zero, the function is a no-op.
    - `_src_sz`: A pointer to a location where the function will store the number of bytes actually written. Must not be null.
- **Output**: Returns 0 on success, with `_src_sz` set to the number of bytes written. Returns a positive error code on failure, with `_src_sz` set to zero.
- **See also**: [`fd_io_write`](fd_io.c.driver.md#fd_io_write)  (Implementation)


---
### fd\_io\_sz<!-- {{#callable_declaration:fd_io_sz}} -->
Retrieve the size of a file from a file descriptor.
- **Description**: Use this function to obtain the current size of the file associated with a given file descriptor. It is useful when you need to know the file size for operations like reading or writing. The function should be called with a valid file descriptor, and it will return the size in bytes if successful. If the function fails, it returns an error code and sets the size to zero. This function is particularly useful in scenarios where the file size might change, such as when writing to a file.
- **Inputs**:
    - `fd`: An integer representing the file descriptor of the file whose size is to be determined. It must be a valid, open file descriptor.
    - `_sz`: A pointer to an unsigned long where the file size will be stored. Must not be null. On failure, the value pointed to by _sz will be set to zero.
- **Output**: Returns 0 on success, with *_sz containing the file size in bytes. On failure, returns a positive error code and *_sz is set to zero.
- **See also**: [`fd_io_sz`](fd_io.c.driver.md#fd_io_sz)  (Implementation)


---
### fd\_io\_truncate<!-- {{#callable_declaration:fd_io_truncate}} -->
Truncates a file to a specified size.
- **Description**: Use this function to change the size of a file associated with a given file descriptor to a specified number of bytes. It can either extend the file by zero-padding or reduce it by discarding excess bytes. This function should be called when you need to adjust the file size, ensuring that the size is within the permissible range for the system. Be cautious when truncating a file to a size smaller than the current file offset of any open file descriptor, as this can lead to undefined behavior.
- **Inputs**:
    - `fd`: An open file descriptor representing the file to be truncated. The file descriptor must be valid and open for writing.
    - `sz`: The desired size of the file in bytes. It must be a non-negative value that does not exceed the maximum allowable size for the system. If the size is invalid, the function returns an error.
- **Output**: Returns 0 on success. On failure, returns a positive error code compatible with strerror, indicating the reason for failure.
- **See also**: [`fd_io_truncate`](fd_io.c.driver.md#fd_io_truncate)  (Implementation)


---
### fd\_io\_seek<!-- {{#callable_declaration:fd_io_seek}} -->
Seeks to a specified byte index in a file descriptor.
- **Description**: This function adjusts the byte index of a given file descriptor based on a relative offset and a specified seek type. It is used to navigate within a file, allowing for reading or writing at different positions. The function must be called with a valid file descriptor and a seek type that is within the defined range. It handles errors by returning a standard error code and setting the output index to zero if the operation fails. This function is useful for applications that require precise control over file read/write positions.
- **Inputs**:
    - `fd`: An open file descriptor representing the file to seek within. It must be a valid, open descriptor that supports seeking.
    - `rel_off`: A long integer representing the relative offset from the position specified by the seek type. It must be within the range that can be cast to an off_t type.
    - `type`: An integer indicating the seek type, which must be one of FD_IO_SEEK_TYPE_SET, FD_IO_SEEK_TYPE_CUR, or FD_IO_SEEK_TYPE_END. Values outside this range will result in an error.
    - `_idx`: A pointer to an unsigned long where the new byte index will be stored upon successful completion. Must not be null, and the caller retains ownership.
- **Output**: Returns 0 on success, with *_idx set to the new byte index. On failure, returns a positive error code and sets *_idx to 0.
- **See also**: [`fd_io_seek`](fd_io.c.driver.md#fd_io_seek)  (Implementation)


---
### fd\_io\_buffered\_read<!-- {{#callable_declaration:fd_io_buffered_read}} -->
Reads data from a file descriptor into a buffer with optional buffering.
- **Description**: This function reads a specified number of bytes from a file descriptor into a destination buffer, utilizing an intermediate buffer to optimize for small read operations. It should be used when you want to perform buffered reads from a file descriptor, especially when dealing with many small reads. The function will block until the requested number of bytes is read or an end-of-file or error is encountered. It is important to ensure that the read buffer is properly initialized and that the buffer sizes are correctly set. The function updates the read buffer's state to reflect the consumed and available bytes.
- **Inputs**:
    - `fd`: An open file descriptor from which data will be read. It should be a valid, open file descriptor.
    - `_dst`: A pointer to the destination buffer where the read data will be stored. Must not be null if dst_sz is greater than zero.
    - `dst_sz`: The number of bytes to read into the destination buffer. Must be greater than zero for the function to perform any read operation.
    - `_rbuf`: A pointer to the read buffer used for buffering data. Must not be null and should point to a valid memory region of size rbuf_sz.
    - `rbuf_sz`: The size of the read buffer. Must be greater than zero.
    - `_rbuf_lo`: A pointer to the current offset in the read buffer where unconsumed data starts. Must not be null and should be initialized to a valid offset within the buffer.
    - `_rbuf_ready`: A pointer to the number of bytes currently available in the read buffer. Must not be null and should be initialized to reflect the current state of the buffer.
- **Output**: Returns 0 on success, indicating that the requested number of bytes was read. On failure, returns a non-zero error code, which can be positive (indicating an I/O error) or negative (indicating end-of-file). The destination buffer is updated with the read data, and the read buffer's state is updated to reflect the new offset and available bytes.
- **See also**: [`fd_io_buffered_read`](fd_io.c.driver.md#fd_io_buffered_read)  (Implementation)


---
### fd\_io\_buffered\_skip<!-- {{#callable_declaration:fd_io_buffered_skip}} -->
Skips a specified number of bytes in a buffered stream.
- **Description**: This function is used to skip over a specified number of bytes in a buffered stream associated with a file descriptor. It is useful when you need to advance the read position without processing the data. The function handles both seekable and non-seekable streams, optimizing for seekable streams by using lseek and for non-seekable streams by reading and discarding data. It should be used when you want to efficiently skip data in a stream, especially when dealing with large skips. The function updates the buffer state accordingly and returns an error code if an I/O error occurs.
- **Inputs**:
    - `fd`: An open file descriptor representing the stream. It must be valid and open for reading.
    - `skip_sz`: The number of bytes to skip. Must be a positive value.
    - `rbuf`: A pointer to the read buffer used for buffering the stream data. Must not be null.
    - `rbuf_sz`: The size of the read buffer. Must be greater than zero.
    - `_rbuf_lo`: A pointer to the current position in the buffer. The function updates this to reflect the new position after skipping.
    - `_rbuf_ready`: A pointer to the number of bytes currently buffered and ready to be consumed. The function updates this to reflect the remaining buffered data after skipping.
- **Output**: Returns 0 on success, a negative value if EOF is encountered before skipping all bytes, or a positive errno-compatible error code on failure. Updates *_rbuf_lo and *_rbuf_ready to reflect the new buffer state.
- **See also**: [`fd_io_buffered_skip`](fd_io.c.driver.md#fd_io_buffered_skip)  (Implementation)


---
### fd\_io\_buffered\_write<!-- {{#callable_declaration:fd_io_buffered_write}} -->
Writes data to a file descriptor using a buffered approach.
- **Description**: This function is used to write data from a source buffer to a file descriptor, utilizing a write buffer to optimize performance for small writes. It is particularly useful when dealing with many small writes, as it consolidates them into larger writes to the file descriptor, reducing the number of system calls. The function should be called when you have data to write and a buffer available for temporary storage. It requires the caller to manage the buffer state, ensuring that the buffer is flushed when necessary. The function will block until the write is complete or an error occurs.
- **Inputs**:
    - `fd`: An open file descriptor where data will be written. It must be valid and open for writing.
    - `_src`: A pointer to the source data to be written. It must not be null if src_sz is greater than zero.
    - `src_sz`: The size of the source data in bytes. If zero, the function does nothing and returns immediately.
    - `_wbuf`: A pointer to the write buffer used for buffering data before writing to the file descriptor. It must not be null and should have a size of at least wbuf_sz.
    - `wbuf_sz`: The size of the write buffer in bytes. It must be greater than zero.
    - `_wbuf_used`: A pointer to a variable that tracks the number of bytes currently used in the write buffer. It must not be null and should be initialized to a valid state before calling the function.
- **Output**: Returns 0 on success, or a non-zero error code if an I/O error occurs. The write buffer state is updated to reflect the number of bytes buffered but not yet written.
- **See also**: [`fd_io_buffered_write`](fd_io.c.driver.md#fd_io_buffered_write)  (Implementation)


---
### fd\_io\_mmio\_init<!-- {{#callable_declaration:fd_io_mmio_init}} -->
Initialize memory-mapped I/O for a file descriptor.
- **Description**: This function maps a file into the caller's address space for memory-mapped I/O, based on the specified mode. It should be used when you need to access a file's contents directly in memory, either in read-only or read-write mode. The function requires a valid file descriptor and a mode indicating the desired access level. On success, it provides a pointer to the mapped memory region and its size. If the file is empty or an error occurs, the function returns an error code and sets the memory region to NULL with a size of zero. The caller is responsible for managing the memory mapping's lifecycle, including unmapping it when no longer needed.
- **Inputs**:
    - `fd`: An open file descriptor representing the file to be memory-mapped. It must be valid and support memory mapping.
    - `mode`: Specifies the access mode for the memory mapping. Must be either FD_IO_MMIO_MODE_READ_ONLY or FD_IO_MMIO_MODE_READ_WRITE. Invalid modes result in an EINVAL error.
    - `_mmio`: A pointer to a location where the function will store the address of the mapped memory region. Must not be null.
    - `_mmio_sz`: A pointer to a location where the function will store the size of the mapped memory region. Must not be null.
- **Output**: Returns 0 on success, with _mmio pointing to the mapped memory and _mmio_sz containing its size. On failure, returns a non-zero error code, with _mmio set to NULL and _mmio_sz set to zero.
- **See also**: [`fd_io_mmio_init`](fd_io.c.driver.md#fd_io_mmio_init)  (Implementation)


---
### fd\_io\_mmio\_fini<!-- {{#callable_declaration:fd_io_mmio_fini}} -->
Finalize memory-mapped I/O on a file.
- **Description**: Use this function to end memory-mapped I/O operations on a file that was previously initialized for such operations. It should be called with the memory region and size that were obtained from the corresponding initialization function. This function ensures that the memory-mapped region is properly unmapped and that any changes made to the mapped region are finalized. It is guaranteed not to fail from the caller's perspective, making it safe to call even if the region is already unmapped or the size is zero.
- **Inputs**:
    - `mmio`: A pointer to the start of the memory-mapped region. It must be the same pointer obtained from the initialization function. If the region size is zero, this can be null.
    - `mmio_sz`: The size of the memory-mapped region in bytes. It must be the same size obtained from the initialization function. If the size is zero, the function will perform no operation.
- **Output**: None
- **See also**: [`fd_io_mmio_fini`](fd_io.c.driver.md#fd_io_mmio_fini)  (Implementation)


---
### fd\_io\_strerror<!-- {{#callable_declaration:fd_io_strerror}} -->
Converts an error code into a human-readable string.
- **Description**: Use this function to obtain a human-readable description of an error code returned by other I/O functions. It is particularly useful for logging or displaying error messages to users. The function handles standard POSIX error codes, including special cases where certain error codes may map to the same value, such as EWOULDBLOCK/EAGAIN and EOPNOTSUPP/ENOTSUP. It also recognizes negative values as indicating end-of-file. The function is thread-safe and returns a constant string with an infinite lifetime.
- **Inputs**:
    - `err`: An integer representing the error code to be converted. It can be a standard POSIX error code, a negative value indicating end-of-file, or zero indicating success. The function handles special cases where certain error codes may map to the same value.
- **Output**: A constant string describing the error code. The string is always non-NULL and has an infinite lifetime.
- **See also**: [`fd_io_strerror`](fd_io.c.driver.md#fd_io_strerror)  (Implementation)


---
### fd\_io\_strsignal<!-- {{#callable_declaration:fd_io_strsignal}} -->
Converts a signal code to a human-readable string.
- **Description**: Use this function to obtain a human-readable description of a signal code, such as those returned by functions like `waitpid` when a process is terminated by a signal. This function is useful for logging or displaying signal information in a user-friendly format. It handles a variety of common signal codes and returns a default message for unknown signals. The function is thread-safe and the returned string has an infinite lifetime.
- **Inputs**:
    - `sig`: An integer representing the signal code to be converted. It should be a valid signal number as defined in signal.h, such as `SIGINT` or `SIGTERM`. If the signal code is not recognized, the function returns "unknown".
- **Output**: A constant character pointer to a string describing the signal. The string is always non-NULL and provides a human-readable description of the signal code.
- **See also**: [`fd_io_strsignal`](fd_io.c.driver.md#fd_io_strsignal)  (Implementation)


