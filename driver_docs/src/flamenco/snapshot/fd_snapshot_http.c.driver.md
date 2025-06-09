# Purpose
This C source code file implements functionality for handling HTTP requests and responses specifically for downloading snapshots over a network. The code is structured around a state machine that manages the lifecycle of an HTTP connection, from initialization to request sending, response handling, and data downloading. The primary data structure used is `fd_snapshot_http_t`, which encapsulates the state and configuration for an HTTP snapshot operation, including details like the destination IP, port, and snapshot directory.

The file provides a set of functions that manage the HTTP request and response process, including setting up the request path, initializing the connection, sending the request, handling redirects, and downloading the response data. The code also includes error handling and logging to ensure robustness and traceability. The functions are designed to be used as part of a larger system, likely involving other components that manage memory and I/O operations. The file defines a public API through the [`fd_io_istream_snapshot_http_read`](#fd_io_istream_snapshot_http_read) function, which serves as an entry point for reading data from the HTTP stream, and it is part of a virtual table structure `fd_io_istream_vt_t`, indicating that it is intended to be used polymorphically within a larger framework.
# Imports and Dependencies

---
- `fd_snapshot_http.h`
- `../../waltz/http/picohttpparser.h`
- `fd_snapshot.h`
- `assert.h`
- `errno.h`
- `stdlib.h`
- `strings.h`
- `unistd.h`
- `netinet/in.h`
- `netinet/ip.h`
- `sys/socket.h`
- `sys/types.h`
- `sys/stat.h`
- `fcntl.h`


# Global Variables

---
### fd\_io\_istream\_snapshot\_http\_vt
- **Type**: `fd_io_istream_vt_t const`
- **Description**: The `fd_io_istream_snapshot_http_vt` is a constant instance of the `fd_io_istream_vt_t` structure, which is used to define a virtual table for input stream operations. This particular instance is configured to use the `fd_io_istream_snapshot_http_read` function for reading operations.
- **Use**: This variable is used to provide a specific implementation of the read operation for HTTP-based snapshot input streams.


# Functions

---
### fd\_snapshot\_http\_set\_path<!-- {{#callable:fd_snapshot_http_set_path}} -->
The `fd_snapshot_http_set_path` function sets the HTTP request path for a snapshot, ensuring it is properly formatted and stored in the `fd_snapshot_http_t` structure.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure where the HTTP path and related information will be stored.
    - `path`: A constant character pointer representing the HTTP path to be set.
    - `path_len`: An unsigned long integer representing the length of the path.
    - `base_slot`: An unsigned long integer representing the base slot for the snapshot.
- **Control Flow**:
    - Check if `path_len` is zero; if so, set `path` to "/" and `path_len` to 1.
    - Check if `path_len` exceeds `FD_SNAPSHOT_HTTP_REQ_PATH_MAX`; if so, log a critical error and exit.
    - Check if `this->save_snapshot` is true and `this->snapshot_filename_max` is less than `path_len`; if so, log a critical error and exit.
    - Calculate the offset `off` for right-aligning the path in `this->path`.
    - Copy "GET " and the `path` into `this->path` starting at the calculated offset.
    - Set `this->req_tail` and `this->path_off` to the calculated offset.
    - Set `this->base_slot` to the provided `base_slot`.
    - If `this->save_snapshot` is true, copy the `path` into `this->snapshot_path` at the offset `this->snapshot_filename_off` and null-terminate it.
- **Output**: The function does not return a value; it modifies the `fd_snapshot_http_t` structure pointed to by `this`.


---
### fd\_snapshot\_http\_new<!-- {{#callable:fd_snapshot_http_new}} -->
The `fd_snapshot_http_new` function initializes a new `fd_snapshot_http_t` structure for handling HTTP snapshot requests, setting up necessary parameters and preparing the HTTP request headers.
- **Inputs**:
    - `mem`: A pointer to a memory block where the `fd_snapshot_http_t` structure will be initialized.
    - `dst_str`: A string representing the destination host for the HTTP request.
    - `dst_ipv4`: An unsigned integer representing the destination IPv4 address.
    - `dst_port`: An unsigned short representing the destination port number.
    - `snapshot_dir`: A string representing the directory path where snapshots will be saved.
    - `name_out`: A pointer to an `fd_snapshot_name_t` structure where the snapshot name will be stored.
- **Control Flow**:
    - Check if the `mem` pointer is NULL and log a warning if it is, returning NULL.
    - Initialize the `fd_snapshot_http_t` structure with zeroed memory and set various fields such as `next_ipv4`, `next_port`, `socket_fd`, `state`, `req_timeout`, `hops`, and `name_out`.
    - If `name_out` is NULL, use a dummy name instead.
    - Determine the length of `snapshot_dir` and, if valid, copy it to `snapshot_path`, appending a '/' and setting related fields for snapshot saving.
    - Set the default HTTP request path using [`fd_snapshot_http_set_path`](#fd_snapshot_http_set_path).
    - Initialize the HTTP request headers with standard fields and append the destination string.
    - Calculate the request header length and store it in `req_head`.
    - Return the initialized `fd_snapshot_http_t` structure.
- **Output**: Returns a pointer to the initialized `fd_snapshot_http_t` structure, or NULL if the `mem` pointer is invalid.
- **Functions called**:
    - [`fd_snapshot_http_set_path`](#fd_snapshot_http_set_path)


---
### fd\_snapshot\_http\_cleanup\_fds<!-- {{#callable:fd_snapshot_http_cleanup_fds}} -->
The `fd_snapshot_http_cleanup_fds` function closes and resets the file descriptors for snapshot and socket in the `fd_snapshot_http_t` structure if they are open.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure, which contains the file descriptors to be cleaned up.
- **Control Flow**:
    - Check if `this->snapshot_fd` is not equal to -1, indicating it is open.
    - If open, close the file descriptor `this->snapshot_fd` and set it to -1 to mark it as closed.
    - Check if `this->socket_fd` is not equal to -1, indicating it is open.
    - If open, close the file descriptor `this->socket_fd` and set it to -1 to mark it as closed.
- **Output**: This function does not return any value; it performs cleanup operations on the file descriptors within the provided structure.


---
### fd\_snapshot\_http\_delete<!-- {{#callable:fd_snapshot_http_delete}} -->
The `fd_snapshot_http_delete` function cleans up file descriptors associated with an `fd_snapshot_http_t` object and returns the object pointer.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` object that needs to be cleaned up.
- **Control Flow**:
    - Check if the input pointer `this` is NULL; if so, return NULL immediately.
    - Call [`fd_snapshot_http_cleanup_fds`](#fd_snapshot_http_cleanup_fds) to close any open file descriptors associated with the `fd_snapshot_http_t` object.
    - Return the input pointer `this` cast to a `void *`.
- **Output**: Returns a `void *` pointer to the `fd_snapshot_http_t` object that was passed in, or NULL if the input was NULL.
- **Functions called**:
    - [`fd_snapshot_http_cleanup_fds`](#fd_snapshot_http_cleanup_fds)


---
### fd\_snapshot\_http\_init<!-- {{#callable:fd_snapshot_http_init}} -->
The `fd_snapshot_http_init` function initializes a TCP connection for an HTTP snapshot request, setting up the socket and connection parameters.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure, which contains the state and configuration for the HTTP snapshot operation.
- **Control Flow**:
    - Log the attempt to connect to the specified IP address and port.
    - Set the request deadline based on the current time and the request timeout.
    - Create a socket using `socket(AF_INET, SOCK_STREAM, 0)` and check for errors.
    - Set the socket receive buffer size using `setsockopt` and check for errors.
    - Initialize a `sockaddr_in` structure with the target IP address and port, converting the port to network byte order.
    - Attempt to connect the socket to the specified address using `connect` and check for errors.
    - Log the successful sending of the request and update the state to `FD_SNAPSHOT_HTTP_STATE_REQ`.
- **Output**: Returns 0 on success, or an error code if any socket operation fails, setting the state to `FD_SNAPSHOT_HTTP_STATE_FAIL` on failure.


---
### fd\_snapshot\_http\_req<!-- {{#callable:fd_snapshot_http_req}} -->
The `fd_snapshot_http_req` function sends an HTTP request over a non-blocking socket, handling timeouts and partial sends.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure, which contains the state and data for the HTTP request.
- **Control Flow**:
    - Retrieve the current time and compare it with the request deadline to check for a timeout.
    - If the current time exceeds the deadline, log a warning, set the state to failure, and return a timeout error code.
    - Calculate the available size of the request buffer to be sent and assert that it is within the buffer's capacity.
    - Attempt to send the available data from the request buffer using a non-blocking send call.
    - If the send call fails with an error other than `EWOULDBLOCK`, log a warning, set the state to failure, and return the error code.
    - If the send call is successful, update the request tail to reflect the number of bytes sent.
    - If the entire request has been sent (tail equals head), update the state to indicate that the response is expected.
    - Return 0 to indicate success or that the operation should be retried.
- **Output**: Returns 0 on success or if the operation should be retried, `ETIMEDOUT` if the request timed out, or an error code if a send operation failed.


---
### fd\_snapshot\_http\_follow\_redirect<!-- {{#callable:fd_snapshot_http_follow_redirect}} -->
The `fd_snapshot_http_follow_redirect` function processes HTTP redirect responses by validating the 'Location' header and updating the state of the HTTP snapshot object to follow the redirect.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure representing the current HTTP snapshot state.
    - `headers`: A pointer to an array of `phr_header` structures containing the HTTP headers from the response.
    - `header_cnt`: The number of headers in the `headers` array.
- **Control Flow**:
    - Assert that the number of remaining hops is greater than zero and decrement the hop count.
    - Iterate over the headers to find the 'Location' header and extract its value and length.
    - If the 'Location' header is not found, log a warning, set the state to failure, and return an error code.
    - Validate the length and format of the 'Location' value, ensuring it is an absolute path and contains only valid characters.
    - If validation fails, log a warning, set the state to failure, and return an error code.
    - Log a notice about following the redirect and attempt to parse the new location into a snapshot name.
    - If parsing fails or the snapshot name cannot be validated, log a warning, set the state to failure, and return an error code.
    - Re-initialize the HTTP request path with the new location and update the request deadline.
    - Set the state to request and reset response buffer indices.
- **Output**: Returns 0 on success, or an error code if the redirect cannot be followed due to missing or invalid headers.
- **Functions called**:
    - [`fd_snapshot_name_from_buf`](fd_snapshot_base.c.driver.md#fd_snapshot_name_from_buf)
    - [`fd_snapshot_name_slot_validate`](fd_snapshot_base.c.driver.md#fd_snapshot_name_slot_validate)
    - [`fd_snapshot_http_set_path`](#fd_snapshot_http_set_path)


---
### fd\_snapshot\_http\_resp<!-- {{#callable:fd_snapshot_http_resp}} -->
The `fd_snapshot_http_resp` function handles receiving and parsing HTTP response headers for a snapshot download, managing redirects, and preparing for the download of the snapshot content.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure, which holds the state and data for the HTTP snapshot operation.
- **Control Flow**:
    - Retrieve the current time and check if the operation has timed out; if so, log a warning, set the state to fail, and return a timeout error.
    - Attempt to read data from the socket into the response buffer; handle errors and incomplete reads appropriately.
    - Parse the HTTP response headers using `phr_parse_response`; handle parsing errors and incomplete headers.
    - Check if the response indicates a redirect; if so, handle the redirect or fail if too many redirects have occurred.
    - Validate the HTTP status code, expecting a 200 status; log a warning and fail if the status is unexpected.
    - Extract the 'Content-Length' header from the response; log a warning and fail if it is missing.
    - Determine if the snapshot should be saved to a file or kept in memory, and handle file operations accordingly, including checking existing file sizes and opening files for reading or writing.
- **Output**: Returns an integer status code indicating success (0) or an error code if a failure occurs during the process.
- **Functions called**:
    - [`fd_snapshot_http_follow_redirect`](#fd_snapshot_http_follow_redirect)
    - [`fd_snapshot_name_from_buf`](fd_snapshot_base.c.driver.md#fd_snapshot_name_from_buf)
    - [`fd_snapshot_name_slot_validate`](fd_snapshot_base.c.driver.md#fd_snapshot_name_slot_validate)


---
### fd\_snapshot\_http\_dl<!-- {{#callable:fd_snapshot_http_dl}} -->
The `fd_snapshot_http_dl` function handles downloading data from an HTTP response into a buffer and optionally writing it to a file, while managing the state of the download process.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure representing the current HTTP snapshot download context.
    - `dst`: A pointer to the destination buffer where the downloaded data will be stored.
    - `dst_max`: The maximum number of bytes that can be written to the destination buffer.
    - `dst_sz`: A pointer to an `ulong` where the function will store the number of bytes actually written to the destination buffer.
- **Control Flow**:
    - Check if the current state is `FD_SNAPSHOT_HTTP_STATE_DL`; if not, log a critical error.
    - If the response buffer is empty, attempt to receive more data from the socket.
    - If the download is complete, log a notice and return -1.
    - If receiving data fails due to an error other than `EWOULDBLOCK` or `EAGAIN`, log a warning, set the state to fail, clean up file descriptors, and return the error code.
    - If the connection is closed, log a warning, set the state to fail, clean up file descriptors, and return -1.
    - Update the total downloaded size and log progress if a certain download threshold is crossed.
    - If the content length is reached or exceeded, log a notice, close the socket, and check for any discrepancies in the content length.
    - Calculate the available size in the response buffer and copy the data to the destination buffer, updating the destination size.
    - If a snapshot file descriptor is open, write the data to the file and handle any errors.
    - Update the response buffer tail and total written size, and if the content length matches the total written size, log a notice, set the state to done, and clean up file descriptors.
- **Output**: Returns 0 on success, -1 if the download is already complete, or an error code if a failure occurs during the download process.
- **Functions called**:
    - [`fd_snapshot_http_cleanup_fds`](#fd_snapshot_http_cleanup_fds)


---
### fd\_snapshot\_http\_read<!-- {{#callable:fd_snapshot_http_read}} -->
The `fd_snapshot_http_read` function reads data from a pre-existing snapshot file into a destination buffer, ensuring the read operation is valid and complete.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure representing the current HTTP snapshot context.
    - `dst`: A pointer to the destination buffer where the read data will be stored.
    - `dst_max`: The maximum number of bytes that can be written to the destination buffer.
    - `dst_sz`: A pointer to an `ulong` where the actual number of bytes read will be stored.
- **Control Flow**:
    - Check if the current state is `FD_SNAPSHOT_HTTP_STATE_READ`; if not, log a critical error and exit.
    - Calculate the number of bytes to read (`write_sz`) as the minimum of the remaining content length and `dst_max`.
    - Attempt to read `write_sz` bytes from the snapshot file into `dst` using `fd_io_read`.
    - If the read operation fails, log a warning, set the state to `FD_SNAPSHOT_HTTP_STATE_FAIL`, clean up file descriptors, and return the error code.
    - Update `dst_sz` with the number of bytes read (`write_sz`).
    - Increment `write_total` by `write_sz`.
    - If all content has been written (`write_total` equals `content_len`), log a notice, set the state to `FD_SNAPSHOT_HTTP_STATE_DONE`, and clean up file descriptors.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or an error code if the read operation fails.
- **Functions called**:
    - [`fd_snapshot_http_cleanup_fds`](#fd_snapshot_http_cleanup_fds)


---
### fd\_io\_istream\_snapshot\_http\_read<!-- {{#callable:fd_io_istream_snapshot_http_read}} -->
The `fd_io_istream_snapshot_http_read` function manages the state transitions and data reading for an HTTP-based snapshot download process.
- **Inputs**:
    - `_this`: A pointer to a `fd_snapshot_http_t` structure representing the current HTTP snapshot download context.
    - `dst`: A pointer to a buffer where the read data will be stored.
    - `dst_max`: The maximum number of bytes that can be written to the `dst` buffer.
    - `dst_sz`: A pointer to a `ulong` where the actual number of bytes read will be stored.
- **Control Flow**:
    - The function casts the `_this` pointer to a `fd_snapshot_http_t` pointer named `this`.
    - It initializes an error variable `err` to 0.
    - A switch statement is used to handle different states of the `this->state` variable.
    - If the state is `FD_SNAPSHOT_HTTP_STATE_INIT`, it calls [`fd_snapshot_http_init`](#fd_snapshot_http_init) to initialize the HTTP connection.
    - If the state is `FD_SNAPSHOT_HTTP_STATE_REQ`, it calls [`fd_snapshot_http_req`](#fd_snapshot_http_req) to send the HTTP request.
    - If the state is `FD_SNAPSHOT_HTTP_STATE_RESP`, it calls [`fd_snapshot_http_resp`](#fd_snapshot_http_resp) to handle the HTTP response headers.
    - If the state is `FD_SNAPSHOT_HTTP_STATE_DL`, it calls [`fd_snapshot_http_dl`](#fd_snapshot_http_dl) to download the data and return the result immediately.
    - If the state is `FD_SNAPSHOT_HTTP_STATE_READ`, it calls [`fd_snapshot_http_read`](#fd_snapshot_http_read) to read data from a pre-existing snapshot file and return the result immediately.
    - If none of the states match, it sets `*dst_sz` to 0 and returns the error code `err`.
- **Output**: The function returns an integer error code, with `*dst_sz` updated to reflect the number of bytes read if applicable.
- **Functions called**:
    - [`fd_snapshot_http_init`](#fd_snapshot_http_init)
    - [`fd_snapshot_http_req`](#fd_snapshot_http_req)
    - [`fd_snapshot_http_resp`](#fd_snapshot_http_resp)
    - [`fd_snapshot_http_dl`](#fd_snapshot_http_dl)
    - [`fd_snapshot_http_read`](#fd_snapshot_http_read)


