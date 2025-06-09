# Purpose
The provided C header file, `fd_snapshot_http.h`, defines an API for downloading Solana blockchain snapshots via HTTP using non-blocking sockets. This file is part of a larger system, likely related to the Flamenco project, and it provides a specialized functionality focused on handling HTTP-based snapshot downloads. The file defines a state machine for managing the different stages of an HTTP transaction, from initialization to completion or failure, and includes constants for managing request and response size limits, as well as the number of redirects to follow by default.

The core component of this header is the `fd_snapshot_http_t` structure, which encapsulates the state and data necessary for managing an HTTP client session. This includes fields for socket management, request and response buffers, and tracking the progress of the download. The file also declares several functions for creating and managing instances of this structure, such as [`fd_snapshot_http_new`](#fd_snapshot_http_new), [`fd_snapshot_http_delete`](#fd_snapshot_http_delete), and functions for setting timeouts and request paths. Additionally, it provides an interface for reading data from the HTTP stream, integrating with a virtual table mechanism for input streams. This header is intended to be included in other C source files that require HTTP-based snapshot downloading capabilities, and it defines a public API for interacting with this functionality.
# Imports and Dependencies

---
- `fd_snapshot_base.h`
- `fd_snapshot_istream.h`


# Global Variables

---
### fd\_snapshot\_http\_new
- **Type**: `fd_snapshot_http_t *`
- **Description**: The `fd_snapshot_http_new` function is a constructor for creating a new instance of the `fd_snapshot_http_t` structure, which represents an HTTP client for streaming Solana snapshots. It initializes the client with specified parameters such as memory allocation, destination address, port, snapshot directory, and an output name structure.
- **Use**: This function is used to allocate and initialize a new HTTP client instance for downloading Solana snapshots over HTTP.


---
### fd\_snapshot\_http\_delete
- **Type**: `function pointer`
- **Description**: The `fd_snapshot_http_delete` is a function that takes a pointer to an `fd_snapshot_http_t` structure and returns a void pointer. This function is likely responsible for cleaning up or deallocating resources associated with an `fd_snapshot_http_t` instance.
- **Use**: This function is used to delete or clean up an `fd_snapshot_http_t` object, freeing any resources it may have allocated.


---
### fd\_io\_istream\_snapshot\_http\_vt
- **Type**: `fd_io_istream_vt_t const`
- **Description**: The `fd_io_istream_snapshot_http_vt` is a constant of type `fd_io_istream_vt_t`, which is likely a structure or type that defines a virtual table for input stream operations specific to HTTP snapshot streaming. This variable is used to provide a set of function pointers or methods that implement the behavior of an input stream for downloading Solana snapshots over HTTP.
- **Use**: This variable is used as a virtual table to define the operations for an HTTP-based input stream, facilitating the streaming download of Solana snapshots.


# Data Structures

---
### fd\_snapshot\_http\_t
- **Type**: `struct`
- **Members**:
    - `next_ipv4`: Stores the next IPv4 address in big-endian format.
    - `next_port`: Stores the next port number.
    - `hops`: Indicates the number of redirects still permitted.
    - `socket_fd`: File descriptor for the socket connection.
    - `state`: Current state of the HTTP client state machine.
    - `req_timeout`: Timeout for the HTTP request in nanoseconds.
    - `req_deadline`: Deadline for the HTTP request.
    - `req_buf`: Buffer for storing the HTTP request, including path and headers.
    - `req_tail`: Index of the first unsent character in the request buffer.
    - `req_head`: Index of the end of the request buffer.
    - `path_off`: Offset for the path in the request buffer.
    - `_pad`: Padding for alignment.
    - `resp_buf`: Buffer for storing the HTTP response headers.
    - `resp_tail`: Index of the last processed character in the response buffer.
    - `resp_head`: Index of the end of the response buffer.
    - `name_out`: Pointer to the name from the last redirect.
    - `name_dummy`: Dummy name used for redirection.
    - `base_slot`: Slot number for the incremental snapshot base.
    - `content_len`: Value from the "content-length:" header.
    - `dl_total`: Total amount of data downloaded so far.
    - `write_total`: Total amount of data written out so far.
    - `snapshot_path`: Path to the snapshot file.
    - `snapshot_filename_off`: Offset for the snapshot filename.
    - `snapshot_filename_max`: Maximum length of the snapshot filename.
    - `snapshot_fd`: File descriptor for the snapshot file.
    - `save_snapshot`: Flag indicating whether to save the snapshot.
- **Description**: The `fd_snapshot_http_t` structure is a comprehensive data structure designed to manage the state and operations of an HTTP client specifically for streaming downloads of Solana snapshots. It includes fields for managing network connections, HTTP request and response buffers, state management, and file handling for snapshots. The structure supports non-blocking socket operations and handles redirects, timeouts, and incremental snapshot management, making it a robust solution for handling HTTP-based snapshot downloads.


# Functions

---
### fd\_io\_istream\_snapshot\_http\_virtual<!-- {{#callable:fd_io_istream_snapshot_http_virtual}} -->
The function `fd_io_istream_snapshot_http_virtual` initializes and returns an `fd_io_istream_obj_t` object for HTTP snapshot streaming.
- **Inputs**:
    - `this`: A pointer to an `fd_snapshot_http_t` structure, representing the HTTP client state for snapshot streaming.
- **Control Flow**:
    - The function takes a single argument, `this`, which is a pointer to an `fd_snapshot_http_t` structure.
    - It constructs an `fd_io_istream_obj_t` object using the provided `this` pointer.
    - The `vt` member of the `fd_io_istream_obj_t` is set to point to the `fd_io_istream_snapshot_http_vt` structure, which likely contains function pointers for virtual method implementations.
    - The constructed `fd_io_istream_obj_t` object is returned.
- **Output**: An `fd_io_istream_obj_t` object initialized with the provided `fd_snapshot_http_t` pointer and a virtual table pointer for HTTP snapshot streaming.


# Function Declarations (Public API)

---
### fd\_snapshot\_http\_new<!-- {{#callable_declaration:fd_snapshot_http_new}} -->
Creates and initializes a new HTTP client for downloading Solana snapshots.
- **Description**: This function initializes a new HTTP client instance for downloading Solana snapshots via HTTP. It must be provided with a memory region to use for the client structure, and it configures the client with the specified destination IP address, port, and optional snapshot directory. The function prepares the client for non-blocking operations and sets default parameters such as request timeout and maximum redirects. It is essential to ensure that the provided memory is valid and that the destination string and IP address are correctly specified. The function returns a pointer to the initialized client structure or NULL if the memory is invalid.
- **Inputs**:
    - `mem`: A pointer to a memory region where the client structure will be initialized. Must not be null.
    - `dst_str`: A string representing the destination host. Must be a valid, null-terminated string.
    - `dst_ipv4`: An unsigned integer representing the destination IPv4 address in big-endian format.
    - `dst_port`: An unsigned short representing the destination port number.
    - `snapshot_dir`: A string representing the directory where snapshots will be saved. Can be null, in which case snapshots are not saved.
    - `name_out`: A pointer to an fd_snapshot_name_t structure where the name from the last redirect will be stored. Can be null, in which case an internal dummy name is used.
- **Output**: Returns a pointer to the initialized fd_snapshot_http_t structure, or NULL if the provided memory is invalid.
- **See also**: [`fd_snapshot_http_new`](fd_snapshot_http.c.driver.md#fd_snapshot_http_new)  (Implementation)


---
### fd\_snapshot\_http\_delete<!-- {{#callable_declaration:fd_snapshot_http_delete}} -->
Deletes an HTTP snapshot client instance.
- **Description**: Use this function to clean up and delete an instance of an HTTP snapshot client when it is no longer needed. This function should be called to release resources associated with the client. It is important to ensure that the pointer to the client instance is valid and not null before calling this function. If the provided pointer is null, the function will return null without performing any operations.
- **Inputs**:
    - `this`: A pointer to the fd_snapshot_http_t instance to be deleted. Must not be null. If null, the function returns null and performs no operations. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the deleted fd_snapshot_http_t instance, or null if the input was null.
- **See also**: [`fd_snapshot_http_delete`](fd_snapshot_http.c.driver.md#fd_snapshot_http_delete)  (Implementation)


---
### fd\_snapshot\_http\_set\_path<!-- {{#callable_declaration:fd_snapshot_http_set_path}} -->
Set the path for the next HTTP request.
- **Description**: This function configures the path for the next HTTP request made by the snapshot HTTP client. It should be called before initiating a new request to ensure the correct path is used. The path should start with a '/' and must not exceed the maximum allowed length. If the provided path length is zero, a default path of '/' is used. The function also sets the base slot for the snapshot, which is relevant for incremental snapshots. It is important to ensure that the path length does not exceed the maximum allowed by the client configuration, as this will result in a critical error.
- **Inputs**:
    - `this`: A pointer to an fd_snapshot_http_t structure representing the HTTP client. Must not be null.
    - `path`: A pointer to a character array representing the path for the HTTP request. The path should start with '/'. If path_len is zero, this can be null.
    - `path_len`: The length of the path. Must be greater than zero and less than or equal to FD_SNAPSHOT_HTTP_REQ_PATH_MAX. If zero, a default path of '/' is used.
    - `base_slot`: An unsigned long representing the slot number that the incremental snapshot should be based off of.
- **Output**: None
- **See also**: [`fd_snapshot_http_set_path`](fd_snapshot_http.c.driver.md#fd_snapshot_http_set_path)  (Implementation)


---
### fd\_io\_istream\_snapshot\_http\_read<!-- {{#callable_declaration:fd_io_istream_snapshot_http_read}} -->
Reads data from an HTTP snapshot stream into a buffer.
- **Description**: This function is used to read data from an HTTP snapshot stream into a provided buffer. It should be called when the snapshot HTTP client is in a state ready to read data, specifically when the state is FD_SNAPSHOT_HTTP_STATE_DL or FD_SNAPSHOT_HTTP_STATE_READ. The function manages the state transitions internally and handles the reading process based on the current state. It is important to ensure that the buffer provided is large enough to hold the data being read, as specified by the dst_max parameter. The function will update the dst_sz parameter with the actual number of bytes read. If the client is not ready to read, the function will set dst_sz to zero and return an error code.
- **Inputs**:
    - `_this`: A pointer to an fd_snapshot_http_t object representing the HTTP snapshot client. Must not be null.
    - `dst`: A pointer to the destination buffer where the data will be read into. Must not be null.
    - `dst_max`: The maximum number of bytes that can be written to the destination buffer. Must be a positive value.
    - `dst_sz`: A pointer to a ulong where the function will store the number of bytes actually read. Must not be null.
- **Output**: Returns an integer error code. A return value of 0 indicates success, while a non-zero value indicates an error occurred. The number of bytes read is stored in the location pointed to by dst_sz.
- **See also**: [`fd_io_istream_snapshot_http_read`](fd_snapshot_http.c.driver.md#fd_io_istream_snapshot_http_read)  (Implementation)


