# Purpose
This C source code file implements a client for making remote procedure calls (RPC) over HTTP, specifically designed to interact with a JSON-RPC server. The primary functionality of this code is to manage the lifecycle of RPC requests, including creating new requests, sending them to a server, and handling responses. The code defines several functions to initialize the RPC client, send requests for specific methods like `getLatestBlockhash` and `getTransactionCount`, and process the responses. It uses non-blocking sockets and the `poll` system call to manage multiple concurrent requests efficiently. The code also includes error handling mechanisms to manage network errors, malformed responses, and other potential issues during communication.

The file includes several external libraries, such as `picohttpparser` for parsing HTTP responses, `cJSON` for JSON parsing, and a base58 encoding library. These libraries are crucial for handling the HTTP and JSON aspects of the RPC communication. The code is structured to support multiple concurrent requests, with each request being tracked by a unique request ID. The functions [`fd_rpc_client_request_latest_block_hash`](#fd_rpc_client_request_latest_block_hash) and [`fd_rpc_client_request_transaction_count`](#fd_rpc_client_request_transaction_count) demonstrate how specific JSON-RPC methods are requested. The code is designed to be part of a larger system, likely a library, as it does not contain a `main` function and instead provides an API for other parts of a program to use.
# Imports and Dependencies

---
- `fd_rpc_client.h`
- `fd_rpc_client_private.h`
- `../../../waltz/http/picohttpparser.h`
- `../../../ballet/json/cJSON.h`
- `../../../ballet/base58/fd_base58.h`
- `errno.h`
- `stdio.h`
- `stdlib.h`
- `unistd.h`
- `strings.h`
- `sys/socket.h`
- `sys/types.h`
- `netinet/ip.h`


# Functions

---
### fd\_rpc\_client\_new<!-- {{#callable:fd_rpc_client_new}} -->
The `fd_rpc_client_new` function initializes a new RPC client structure with specified memory, address, and port, and sets up its request slots and file descriptors.
- **Inputs**:
    - `mem`: A pointer to the memory location where the RPC client structure will be initialized.
    - `rpc_addr`: An unsigned integer representing the RPC server's address.
    - `rpc_port`: An unsigned short representing the RPC server's port number.
- **Control Flow**:
    - Cast the provided memory pointer to an `fd_rpc_client_t` pointer and assign it to `rpc`.
    - Initialize `rpc->request_id` to 0.
    - Set `rpc->rpc_addr` to the provided `rpc_addr`.
    - Set `rpc->rpc_port` to the provided `rpc_port`.
    - Iterate over each request slot (up to `FD_RPC_CLIENT_REQUEST_CNT`):
    - Set the state of each request to `FD_RPC_CLIENT_STATE_NONE`.
    - Initialize each file descriptor to -1 and set its events to `POLLIN | POLLOUT`.
    - Return the initialized `rpc` pointer cast to a `void *`.
- **Output**: A pointer to the initialized RPC client structure cast to `void *`.


---
### fd\_rpc\_client\_wait\_ready<!-- {{#callable:fd_rpc_client_wait_ready}} -->
The `fd_rpc_client_wait_ready` function attempts to establish a non-blocking connection to a specified RPC server and waits until the connection is ready or a timeout occurs.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure containing the RPC server's address and port information.
    - `timeout_ns`: A long integer specifying the maximum time to wait for the connection to be ready, in nanoseconds.
- **Control Flow**:
    - Initialize a `sockaddr_in` structure with the RPC server's address and port.
    - Create a `pollfd` structure to monitor the socket for readiness to write (POLLOUT).
    - Record the current time as the start time for the timeout calculation.
    - Enter an infinite loop to attempt connecting to the server.
    - Create a non-blocking socket and check for errors; return an error code if socket creation fails.
    - Attempt to connect the socket to the server; if the connection fails immediately with an error other than EINPROGRESS, close the socket and return an error code.
    - Enter another loop to poll the socket for readiness or timeout.
    - Check if the current time exceeds the timeout; if so, close the socket and return an error code.
    - Use `poll` to check the socket's status; handle cases where poll returns 0 (timeout), -1 with EINTR (interrupted), or -1 (error).
    - If the socket is ready for writing (POLLOUT), close the socket and return success.
    - If the socket has an error or hang-up (POLLERR or POLLHUP), close the socket and break out of the loop to retry.
- **Output**: Returns `FD_RPC_CLIENT_SUCCESS` if the connection is ready, or `FD_RPC_CLIENT_ERR_NETWORK` if a network error occurs or the timeout is reached.


---
### fd\_rpc\_available\_slot<!-- {{#callable:fd_rpc_available_slot}} -->
The `fd_rpc_available_slot` function searches for the first available slot in the RPC client's request array that is not currently in use.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure, which contains the client's request array and other related data.
- **Control Flow**:
    - Iterate over the request slots from index 0 to `FD_RPC_CLIENT_REQUEST_CNT - 1`.
    - For each slot, check if the `state` of the request is `FD_RPC_CLIENT_STATE_NONE`, indicating it is available.
    - If an available slot is found, return its index immediately.
    - If no available slot is found after checking all slots, return `ULONG_MAX` to indicate no slots are available.
- **Output**: The function returns the index of the first available slot in the request array, or `ULONG_MAX` if no slots are available.


---
### fd\_rpc\_find\_request<!-- {{#callable:fd_rpc_find_request}} -->
The `fd_rpc_find_request` function searches for a request with a specific request ID in an RPC client's request list and returns its index.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client containing the requests.
    - `request_id`: A long integer representing the unique identifier of the request to find.
- **Control Flow**:
    - Iterates over the requests in the `rpc` client from index 0 to `FD_RPC_CLIENT_REQUEST_CNT - 1`.
    - For each request, checks if the request's state is not `FD_RPC_CLIENT_STATE_NONE` to ensure it is an active request.
    - Checks if the request's `response.request_id` matches the given `request_id`.
    - If a match is found, returns the index of the request.
    - If no matching request is found after checking all requests, returns `ULONG_MAX`.
- **Output**: Returns the index of the request with the specified `request_id` if found, otherwise returns `ULONG_MAX` if no such request exists.


---
### fd\_rpc\_client\_request<!-- {{#callable:fd_rpc_client_request}} -->
The `fd_rpc_client_request` function initiates an RPC request by preparing and sending an HTTP POST request to a specified server, managing the connection and request state.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client context.
    - `method`: An unsigned long integer representing the method to be used for the RPC request.
    - `request_id`: A long integer representing the unique identifier for the request.
    - `contents`: A character pointer to the contents of the request, typically in JSON format.
    - `contents_len`: An integer representing the length of the contents to be sent in the request.
- **Control Flow**:
    - Check for an available slot in the RPC client request array using [`fd_rpc_available_slot`](#fd_rpc_available_slot) and return an error if no slots are available.
    - Validate the `contents_len` to ensure it is non-negative and does not exceed `MAX_REQUEST_LEN`, returning an error if invalid.
    - Format the HTTP POST request into the `request_bytes` buffer of the selected request slot, checking for errors in formatting or buffer overflow.
    - Create a non-blocking socket and attempt to connect to the server using the provided RPC address and port, handling connection errors appropriately.
    - Assign the socket file descriptor to the appropriate slot in the RPC client's file descriptor array and update the request state to `FD_RPC_CLIENT_STATE_CONNECTED`.
    - Set the request's method, status, and request ID, and initialize the `request_bytes_sent` counter to zero.
    - Return the request ID as the function's output.
- **Output**: The function returns the request ID of the initiated RPC request, or an error code if the request could not be initiated.
- **Functions called**:
    - [`fd_rpc_available_slot`](#fd_rpc_available_slot)


---
### fd\_rpc\_client\_request\_latest\_block\_hash<!-- {{#callable:fd_rpc_client_request_latest_block_hash}} -->
The `fd_rpc_client_request_latest_block_hash` function sends a request to retrieve the latest block hash from an RPC server using a JSON-RPC 2.0 formatted message.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client context.
- **Control Flow**:
    - Initialize a character array `contents` to store the JSON-RPC request message.
    - Calculate the next `request_id` by incrementing the current `rpc->request_id`, wrapping around if it reaches `LONG_MAX`.
    - Format the JSON-RPC request message into the `contents` array using `snprintf`, specifying the method `getLatestBlockhash` and the calculated `request_id`.
    - Call [`fd_rpc_client_request`](#fd_rpc_client_request) with the prepared parameters to send the request and return its result.
- **Output**: Returns a `long` representing the request ID of the sent request, or an error code if the request could not be sent.
- **Functions called**:
    - [`fd_rpc_client_request`](#fd_rpc_client_request)


---
### fd\_rpc\_client\_request\_transaction\_count<!-- {{#callable:fd_rpc_client_request_transaction_count}} -->
The `fd_rpc_client_request_transaction_count` function sends a JSON-RPC request to get the transaction count from a remote server using the provided RPC client.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client used to send the request.
- **Control Flow**:
    - Initialize a character array `contents` to store the JSON-RPC request string.
    - Calculate the next `request_id` by incrementing the current `rpc->request_id`, resetting to 0 if it reaches `LONG_MAX`.
    - Format the JSON-RPC request string into `contents` using `snprintf`, specifying the method as `getTransactionCount` with a parameter for commitment set to `processed`.
    - Call [`fd_rpc_client_request`](#fd_rpc_client_request) with the prepared request details to send the request and return the result.
- **Output**: Returns a `long` representing the request ID of the sent transaction count request, or an error code if the request fails.
- **Functions called**:
    - [`fd_rpc_client_request`](#fd_rpc_client_request)


---
### fd\_rpc\_mark\_error<!-- {{#callable:fd_rpc_mark_error}} -->
The `fd_rpc_mark_error` function marks a specific RPC request as finished with an error status and closes its associated file descriptor if it is open.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client.
    - `idx`: An unsigned long integer representing the index of the request in the RPC client's request array.
    - `error`: A long integer representing the error code to be set for the request.
- **Control Flow**:
    - Check if the file descriptor at the specified index is open (i.e., greater than or equal to 0).
    - If the file descriptor is open, attempt to close it and log a warning if the close operation fails.
    - Set the file descriptor at the specified index to -1, indicating it is closed.
    - Set the state of the request at the specified index to `FD_RPC_CLIENT_STATE_FINISHED`.
    - Set the response status of the request at the specified index to the provided error code.
- **Output**: This function does not return any value; it modifies the state of the RPC client and its requests in place.


---
### fd\_rpc\_phr\_content\_length<!-- {{#callable:fd_rpc_phr_content_length}} -->
The `fd_rpc_phr_content_length` function extracts the 'Content-Length' value from an array of HTTP headers.
- **Inputs**:
    - `headers`: A pointer to an array of `phr_header` structures representing HTTP headers.
    - `num_headers`: The number of headers in the `headers` array.
- **Control Flow**:
    - Iterates over each header in the `headers` array.
    - Checks if the header name length is 14 and matches 'Content-Length' case-insensitively.
    - If a match is found, attempts to convert the header's value to an unsigned long integer using `strtoul`.
    - If the conversion fails (i.e., no digits were found), returns `ULONG_MAX`.
    - If successful, returns the parsed content length.
    - If no 'Content-Length' header is found, returns `ULONG_MAX`.
- **Output**: Returns the content length as an unsigned long integer if found and valid, otherwise returns `ULONG_MAX`.


---
### parse\_response<!-- {{#callable:parse_response}} -->
The `parse_response` function parses an HTTP response to extract and validate JSON data for specific RPC methods, returning appropriate status codes based on the parsing outcome.
- **Inputs**:
    - `response`: A pointer to the character array containing the HTTP response to be parsed.
    - `response_len`: The length of the response data in bytes.
    - `last_response_len`: The length of the last response data processed, used for incremental parsing.
    - `result`: A pointer to a `fd_rpc_client_response_t` structure where the parsed result will be stored.
- **Control Flow**:
    - Initialize variables for HTTP parsing, including minor version, status, message, and headers.
    - Call `phr_parse_response` to parse the HTTP response headers and determine the length of the HTTP message.
    - Check if the response is incomplete or malformed, returning `FD_RPC_CLIENT_PENDING` or `FD_RPC_CLIENT_ERR_MALFORMED` respectively.
    - Determine the content length from the headers and validate it against constraints, returning errors if invalid.
    - Ensure the HTTP status is 200 (OK), otherwise return `FD_RPC_CLIENT_ERR_MALFORMED`.
    - Parse the JSON body of the response using `cJSON_ParseWithLengthOpts`.
    - Based on the `result->method`, extract specific JSON fields and validate them, returning `FD_RPC_CLIENT_ERR_MALFORMED` if any validation fails.
    - For `FD_RPC_CLIENT_METHOD_TRANSACTION_COUNT`, extract the transaction count and store it in the result structure.
    - For `FD_RPC_CLIENT_METHOD_LATEST_BLOCK_HASH`, extract the block hash, decode it using Base58, and store it in the result structure.
    - Return `FD_RPC_CLIENT_SUCCESS` if parsing and validation are successful, otherwise return an error code.
- **Output**: Returns a long integer status code indicating the result of the parsing operation, such as `FD_RPC_CLIENT_SUCCESS`, `FD_RPC_CLIENT_PENDING`, or various error codes.
- **Functions called**:
    - [`fd_rpc_phr_content_length`](#fd_rpc_phr_content_length)


---
### fd\_rpc\_client\_service<!-- {{#callable:fd_rpc_client_service}} -->
The `fd_rpc_client_service` function processes RPC client requests by polling for events and handling sending and receiving of data over network sockets.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client context.
    - `wait`: An integer indicating whether the function should block indefinitely (if non-zero) or return immediately (if zero) when polling for events.
- **Control Flow**:
    - Set the `timeout` variable based on the `wait` parameter: -1 for indefinite wait, 0 for immediate return.
    - Call `poll` on the file descriptors in `rpc->fds` with the specified `timeout`.
    - If `poll` returns 0 or is interrupted by a signal (`EINTR`), return 0 indicating no events were processed.
    - If `poll` fails with an error, log the error and terminate the program.
    - Iterate over each request in `rpc->requests`.
    - For requests in the `FD_RPC_CLIENT_STATE_CONNECTED` state with `POLLOUT` event, attempt to send data using `send`.
    - If `send` returns `EAGAIN`, continue to the next request; if it fails, mark the request with a network error and continue.
    - Update the number of bytes sent and transition the request to `FD_RPC_CLIENT_STATE_SENT` if all bytes are sent.
    - For requests in the `FD_RPC_CLIENT_STATE_SENT` state with `POLLIN` event, attempt to receive data using `recv`.
    - If `recv` returns `EAGAIN`, continue to the next request; if it fails, mark the request with a network error and continue.
    - Update the number of bytes read and check if the response buffer is full, marking an error if it is.
    - Parse the response using [`parse_response`](#parse_response) and handle the result: continue if pending, close the connection and mark success if successful, or mark an error otherwise.
    - Return 1 indicating that at least one event was processed.
- **Output**: Returns 1 if at least one event was processed, or 0 if no events were processed or the poll was interrupted.
- **Functions called**:
    - [`fd_rpc_mark_error`](#fd_rpc_mark_error)
    - [`parse_response`](#parse_response)


---
### fd\_rpc\_client\_status<!-- {{#callable:fd_rpc_client_status}} -->
The `fd_rpc_client_status` function retrieves the status of a specific RPC request, optionally waiting for its completion.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client.
    - `request_id`: A long integer representing the unique identifier of the request whose status is being queried.
    - `wait`: An integer flag indicating whether to wait for the request to complete (non-zero) or not (zero).
- **Control Flow**:
    - The function first calls [`fd_rpc_find_request`](#fd_rpc_find_request) to locate the index of the request with the given `request_id` in the `rpc` client structure.
    - If the request is not found (index is `ULONG_MAX`), the function returns `NULL`.
    - If `wait` is zero, the function immediately returns the response associated with the request at the found index.
    - If `wait` is non-zero, the function enters a loop where it repeatedly checks if the request's state is `FD_RPC_CLIENT_STATE_FINISHED`.
    - If the request is finished, the function returns the response; otherwise, it calls [`fd_rpc_client_service`](#fd_rpc_client_service) to process the request and continues the loop.
- **Output**: A pointer to an `fd_rpc_client_response_t` structure containing the response of the specified request, or `NULL` if the request is not found.
- **Functions called**:
    - [`fd_rpc_find_request`](#fd_rpc_find_request)
    - [`fd_rpc_client_service`](#fd_rpc_client_service)


---
### fd\_rpc\_client\_close<!-- {{#callable:fd_rpc_client_close}} -->
The `fd_rpc_client_close` function closes a specific RPC client request by its request ID, ensuring the associated file descriptor is closed and the request state is reset.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client.
    - `request_id`: A long integer representing the unique identifier of the request to be closed.
- **Control Flow**:
    - Finds the index of the request with the given `request_id` using [`fd_rpc_find_request`](#fd_rpc_find_request) function.
    - If the request is not found (index is `ULONG_MAX`), the function returns immediately.
    - Checks if the file descriptor associated with the request is valid (greater than or equal to 0).
    - If the file descriptor is valid, attempts to close it using the `close` function and logs a warning if the close operation fails.
    - Sets the file descriptor to -1 to mark it as closed.
    - Resets the state of the request at the found index to `FD_RPC_CLIENT_STATE_NONE`.
- **Output**: The function does not return any value (void).
- **Functions called**:
    - [`fd_rpc_find_request`](#fd_rpc_find_request)


