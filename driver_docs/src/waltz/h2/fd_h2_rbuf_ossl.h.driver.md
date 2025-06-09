# Purpose
This C header file, `fd_h2_rbuf_ossl.h`, provides utility functions for facilitating I/O operations between a ring buffer (`rbuf`) and OpenSSL's `SSL` objects. It includes two main inline functions: [`fd_h2_rbuf_ssl_read`](#fd_h2_rbuf_ssl_read) and [`fd_h2_rbuf_ssl_write`](#fd_h2_rbuf_ssl_write). The [`fd_h2_rbuf_ssl_read`](#fd_h2_rbuf_ssl_read) function reads data from an `SSL` connection and stores it into a ring buffer, handling potential errors by updating an error variable. Conversely, [`fd_h2_rbuf_ssl_write`](#fd_h2_rbuf_ssl_write) writes data from a ring buffer to an `SSL` connection, with a note indicating the need for handling fatal errors. The file is conditionally compiled only if OpenSSL support is available, as indicated by the `FD_HAS_OPENSSL` macro. This header is part of a larger system that likely deals with secure data transmission using OpenSSL, providing a bridge between buffered data and SSL communication.
# Imports and Dependencies

---
- `fd_h2_rbuf.h`
- `openssl/err.h`
- `openssl/ssl.h`


# Functions

---
### fd\_h2\_rbuf\_ssl\_read<!-- {{#callable:fd_h2_rbuf_ssl_read}} -->
The `fd_h2_rbuf_ssl_read` function reads data from an SSL connection into a ring buffer, handling potential SSL errors.
- **Inputs**:
    - `rbuf_out`: A pointer to the ring buffer (`fd_h2_rbuf_t`) where the read data will be stored.
    - `ssl`: A pointer to the SSL connection (`SSL *`) from which data is to be read.
    - `ssl_err`: A pointer to an integer where any SSL error code will be stored if the read operation fails.
- **Control Flow**:
    - Initialize two variables `sz0` and `sz1` to hold the sizes of free space in the ring buffer.
    - Call [`fd_h2_rbuf_peek_free`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_peek_free) to get a pointer to the free space in the ring buffer and update `sz0` and `sz1`.
    - Check if `sz0` is zero, indicating no space is available in the buffer; if so, return 0.
    - Clear any existing SSL errors using `ERR_clear_error()`.
    - Attempt to read data from the SSL connection into the buffer using `SSL_read_ex`.
    - If the read operation fails, retrieve the SSL error code using `SSL_get_error` and store it in `ssl_err`, then return 0.
    - If the read operation succeeds, allocate the read size in the ring buffer using [`fd_h2_rbuf_alloc`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_alloc).
    - Return the number of bytes successfully read.
- **Output**: The function returns the number of bytes successfully read from the SSL connection into the ring buffer, or 0 if the read operation fails or if there is no space available in the buffer.
- **Functions called**:
    - [`fd_h2_rbuf_peek_free`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_peek_free)
    - [`fd_h2_rbuf_alloc`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_alloc)


---
### fd\_h2\_rbuf\_ssl\_write<!-- {{#callable:fd_h2_rbuf_ssl_write}} -->
The `fd_h2_rbuf_ssl_write` function writes data from a ring buffer to an SSL connection using OpenSSL.
- **Inputs**:
    - `rbuf_in`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer containing data to be written.
    - `ssl`: A pointer to an `SSL` structure representing the SSL connection to which data will be written.
- **Control Flow**:
    - Retrieve the used portion of the ring buffer using [`fd_h2_rbuf_peek_used`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_peek_used), obtaining two sizes `sz0` and `sz1`.
    - Check if `sz0` is zero, indicating no data to write, and return 0 if true.
    - Attempt to write `sz0` bytes from the ring buffer to the SSL connection using `SSL_write_ex`.
    - If the write fails, return 0.
    - If there is a second segment (`sz1` is non-zero) and the first write was successful, attempt to write the second segment using `SSL_write_ex`.
    - Add the size of the second write to the total written size if successful.
    - Advance the ring buffer's read position by the total number of bytes written using [`fd_h2_rbuf_skip`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_skip).
    - Return the total number of bytes written.
- **Output**: The function returns the total number of bytes successfully written to the SSL connection as an unsigned long integer.
- **Functions called**:
    - [`fd_h2_rbuf_peek_used`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_peek_used)
    - [`fd_h2_rbuf_skip`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_skip)


