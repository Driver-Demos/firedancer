# Purpose
This C source code file is designed to implement a fuzz testing framework for an HTTP server, specifically targeting its WebSocket and HTTP request handling capabilities. The code is structured to simulate various client-server interactions, including opening and closing connections, sending HTTP and WebSocket requests, and handling server responses. It utilizes a pseudo-random number generator (Xorshift) to introduce variability in the requests and responses, thereby testing the robustness and resilience of the server under different conditions. The file includes functions for building HTTP and WebSocket requests, managing client connections, and executing random API calls to simulate real-world usage scenarios.

The code is part of a larger system, as indicated by the inclusion of several external headers and the use of a specific HTTP server API (`fd_http_server`). It defines a set of parameters for the server, such as maximum connection counts and buffer sizes, and provides callback functions for handling various server events like connection openings, closings, and message receptions. The [`LLVMFuzzerTestOneInput`](#LLVMFuzzerTestOneInput) function serves as the entry point for the fuzzing process, orchestrating the setup and teardown of the server environment, and executing a series of randomized actions to test the server's behavior. This file is not intended to be a standalone executable but rather a component of a fuzz testing suite, likely integrated with a larger testing framework such as LLVM's libFuzzer.
# Imports and Dependencies

---
- `assert.h`
- `stdio.h`
- `stdlib.h`
- `unistd.h`
- `arpa/inet.h`
- `netinet/in.h`
- `pthread.h`
- `poll.h`
- `errno.h`
- `../../util/fd_util.h`
- `../../util/sanitize/fd_fuzz.h`
- `fd_http_server_private.h`
- `fd_http_server.h`


# Global Variables

---
### PARAMS
- **Type**: ``fd_http_server_params_t``
- **Description**: The `PARAMS` variable is a constant instance of the `fd_http_server_params_t` structure, which holds configuration parameters for an HTTP server. It specifies limits and sizes for various server capabilities, such as the maximum number of connections, maximum request length, and buffer sizes for handling WebSocket connections.
- **Use**: This variable is used to configure the HTTP server with predefined limits and buffer sizes for handling connections and requests.


---
### http\_server
- **Type**: `fd_http_server_t*`
- **Description**: The `http_server` variable is a pointer to an instance of the `fd_http_server_t` structure, which represents an HTTP server. It is initialized to `NULL` and is used to manage the server's state and operations, such as handling connections and requests.
- **Use**: This variable is used to store the reference to the HTTP server instance, allowing various functions to perform operations like listening for connections, sending responses, and managing WebSocket connections.


---
### port
- **Type**: `uint16_t`
- **Description**: The `port` variable is a global variable of type `uint16_t` that is initialized to 0. It is used to store the port number on which the HTTP server listens for incoming connections.
- **Use**: The `port` variable is set to the port number obtained from the server's socket address after binding, allowing the server to accept connections on that port.


---
### clients\_fd
- **Type**: `int array`
- **Description**: The `clients_fd` is a static integer array with a size of `FD_HTTP_SERVER_GUI_MAX_CONNS * 2`, initialized with all elements set to -1. This array is used to store file descriptors for client connections in the HTTP server.
- **Use**: It is used to manage and track the file descriptors of active client connections, allowing the server to handle multiple connections simultaneously.


---
### clients\_ws\_fd
- **Type**: `char array`
- **Description**: The `clients_ws_fd` is a static global character array that is used to track the state of WebSocket connections for clients connected to the HTTP server. It is initialized to zero and has a size of `FD_HTTP_SERVER_GUI_MAX_CONNS * 2`, which allows it to accommodate twice the maximum number of GUI connections defined by the server parameters.
- **Use**: This array is used to indicate whether a particular client connection is using a WebSocket, with each element corresponding to a client connection.


---
### clients\_fd\_cnt
- **Type**: ``uint``
- **Description**: The `clients_fd_cnt` variable is a static global variable of type `uint` that is initialized to 0. It is used to keep track of the number of client file descriptors currently in use by the HTTP server.
- **Use**: This variable is incremented when a new client connection is established and decremented when a connection is closed, ensuring the server does not exceed its maximum allowed connections.


---
### poll\_rng
- **Type**: `Xorshift`
- **Description**: The `poll_rng` variable is a static instance of the `Xorshift` struct, which is used to generate pseudo-random numbers. The `Xorshift` struct contains a single field, `state`, which holds the current state of the random number generator.
- **Use**: `poll_rng` is used throughout the code to generate random numbers for various operations, such as selecting random actions or generating random data for HTTP requests.


---
### stem\_iters
- **Type**: `ulong`
- **Description**: The `stem_iters` variable is a static global variable of type `ulong` initialized to 0. It is used to count the number of iterations performed by the `stem_thread` function.
- **Use**: This variable is incremented in each iteration of the `stem_thread` function to track the number of iterations executed.


---
### stop
- **Type**: `int`
- **Description**: The `stop` variable is a static integer initialized to 0, used as a flag to control the termination of a loop within the `stem_thread` function.
- **Use**: This variable is used to signal the `stem_thread` function to exit its loop and terminate the thread when set to a non-zero value.


# Data Structures

---
### Unstructured
- **Type**: `struct`
- **Members**:
    - `data`: A pointer to an array of unsigned characters, representing the raw data.
    - `size`: An unsigned long integer indicating the total size of the data array.
    - `used`: An unsigned long integer tracking the amount of data that has been used or processed.
- **Description**: The `Unstructured` struct is designed to manage a block of raw data, providing mechanisms to track the total size of the data and how much of it has been utilized. It is particularly useful in scenarios where data is being read or processed incrementally, allowing functions to access and manipulate the data while keeping track of the portion that has already been consumed. This struct is often used in conjunction with functions that require random access to data, such as generating random values or constructing network requests.


---
### Xorshift
- **Type**: `struct`
- **Members**:
    - `state`: A 32-bit unsigned integer representing the internal state of the Xorshift random number generator.
- **Description**: The `Xorshift` structure is a simple data structure used to implement a Xorshift random number generator, which is a type of pseudorandom number generator. It contains a single member, `state`, which holds the current state of the generator. The generator uses bitwise operations to produce a sequence of random numbers, and the state is updated with each call to generate a new number. This structure is initialized with a seed value, and the state is manipulated using bitwise shifts and XOR operations to produce the next random number in the sequence.


---
### Action
- **Type**: `enum`
- **Members**:
    - `HttpOpen`: Represents the action to open an HTTP connection.
    - `Close`: Represents the action to close a connection.
    - `Send`: Represents the action to send data over a connection.
    - `ActionEnd`: Marks the end of the Action enumeration, used for iteration or boundary checks.
- **Description**: The `Action` enumeration defines a set of constants representing different actions that can be performed in the context of an HTTP server. These actions include opening an HTTP connection, closing a connection, and sending data. The `ActionEnd` constant is used as a boundary marker for the enumeration, facilitating iteration or validation of action values. This enumeration is likely used to control the flow of operations in a network communication context, particularly within the HTTP server implementation.


---
### sockaddr\_pun
- **Type**: `union`
- **Members**:
    - `addr_in`: A member of type `struct sockaddr_in` representing an IPv4 socket address.
    - `sa`: A member of type `struct sockaddr` representing a generic socket address.
- **Description**: The `sockaddr_pun` is a union data structure that allows for the interpretation of a socket address as either an IPv4-specific address (`struct sockaddr_in`) or a generic socket address (`struct sockaddr`). This is useful for network programming where a single variable may need to be treated as different types of socket addresses depending on the context, providing flexibility in handling socket operations.


# Functions

---
### rand\_uchar<!-- {{#callable:rand_uchar}} -->
The `rand_uchar` function retrieves a random unsigned character from a given data structure or generates one if the data is insufficient.
- **Inputs**:
    - `u`: A pointer to a `struct Unstructured` which contains a data buffer, its size, and the amount of data already used.
- **Control Flow**:
    - Check if there is enough unused data in the structure to read an `uchar` by comparing the sum of `sizeof(uchar)` and `u->used` with `u->size`.
    - If there is enough data, retrieve the `uchar` from the data buffer at the current `used` position, increment `u->used` by `sizeof(uchar)`, and return the retrieved `uchar`.
    - If there is not enough data, generate a random `uchar` using the `rand()` function and return it.
- **Output**: An `uchar` value, either retrieved from the data buffer or generated randomly.


---
### rand\_uint<!-- {{#callable:rand_uint}} -->
The `rand_uint` function retrieves a `uint` value from a given `Unstructured` data structure or generates a random `uint` if insufficient data is available.
- **Inputs**:
    - `u`: A pointer to an `Unstructured` structure containing a data buffer, its total size, and the amount of data already used.
- **Control Flow**:
    - Check if there is enough unused data in the `Unstructured` structure to read a `uint` value.
    - If there is enough data, read a `uint` from the current position in the data buffer, update the `used` field, and return the value.
    - If there is not enough data, generate and return a random `uint` using the `rand()` function.
- **Output**: A `uint` value, either retrieved from the `Unstructured` data buffer or generated randomly.


---
### rand\_ulong<!-- {{#callable:rand_ulong}} -->
The `rand_ulong` function generates a random unsigned long integer using data from a given `Unstructured` structure or falls back to using the `rand()` function if insufficient data is available.
- **Inputs**:
    - `u`: A pointer to an `Unstructured` structure containing a data buffer, its size, and the amount of data already used.
- **Control Flow**:
    - Check if there is enough unused data in the `Unstructured` structure to extract an `ulong` value.
    - If sufficient data is available, extract an `ulong` from the data buffer at the current `used` position, update the `used` counter, and return the extracted value.
    - If insufficient data is available, generate a random `ulong` by combining two `rand()` calls, shifting the first result by 32 bits, and return the combined value.
- **Output**: An unsigned long integer, either extracted from the `Unstructured` data or generated using the `rand()` function.


---
### rand\_bytes<!-- {{#callable:rand_bytes}} -->
The `rand_bytes` function fills a buffer with random bytes, either from a predefined data source or by generating them using the `rand()` function.
- **Inputs**:
    - `u`: A pointer to a `struct Unstructured` which contains a data buffer, its size, and the amount of data already used.
    - `len`: The number of bytes to fill in the buffer `p`.
    - `p`: A pointer to a buffer where the random bytes will be stored.
- **Control Flow**:
    - Check if the requested length `len` plus the already used bytes in `u` is less than the total size of `u`'s data buffer.
    - If true, copy `len` bytes from `u->data` starting at `u->used` into the buffer `p`, and increment `u->used` by `len`.
    - If false, fill the buffer `p` with `len` random bytes generated by the `rand()` function.
- **Output**: The function does not return a value; it modifies the buffer `p` in place.


---
### reset\_clients\_fd<!-- {{#callable:reset_clients_fd}} -->
The `reset_clients_fd` function initializes the client file descriptor arrays and resets the client file descriptor count to zero.
- **Inputs**: None
- **Control Flow**:
    - Set `clients_fd_cnt` to 0, indicating no active client connections.
    - Iterate over the range from 0 to `FD_HTTP_SERVER_GUI_MAX_CONNS * 2`.
    - For each index in the iteration, set `clients_fd[i]` to -1, marking the file descriptor as unused.
    - Set `clients_ws_fd[i]` to 0, indicating no active WebSocket connection.
- **Output**: The function does not return any value; it modifies global variables `clients_fd`, `clients_ws_fd`, and `clients_fd_cnt`.


---
### LLVMFuzzerInitialize<!-- {{#callable:LLVMFuzzerInitialize}} -->
The `LLVMFuzzerInitialize` function initializes the environment for fuzz testing by setting up logging, signal handling, and resetting client file descriptors.
- **Inputs**:
    - `argc`: A pointer to the argument count, typically passed to the main function of a C program.
    - `argv`: A pointer to the argument vector, typically passed to the main function of a C program, which is an array of strings representing the command-line arguments.
- **Control Flow**:
    - The function sets the environment variable `FD_LOG_BACKTRACE` to `0` to disable backtrace logging.
    - It calls `fd_boot` with `argc` and `argv` to perform necessary bootstrapping operations.
    - The `atexit` function is used to register `fd_halt` to be called on program exit.
    - The logging level for core logs is set to `3`, which indicates crashing on warning logs.
    - The logging level for standard error logs is set to `4`, effectively disabling parsing error logging.
    - The [`reset_clients_fd`](#reset_clients_fd) function is called to reset the client file descriptors to their initial state.
- **Output**: The function returns `0`, indicating successful initialization.
- **Functions called**:
    - [`reset_clients_fd`](#reset_clients_fd)


---
### xorshift\_init<!-- {{#callable:xorshift_init}} -->
The `xorshift_init` function initializes a Xorshift random number generator with a given seed, ensuring the state is never zero.
- **Inputs**:
    - `x`: A pointer to a Xorshift structure that will be initialized.
    - `seed`: A 32-bit unsigned integer used to initialize the state of the Xorshift structure.
- **Control Flow**:
    - Check if the provided seed is non-zero.
    - If the seed is non-zero, set the state of the Xorshift structure to the seed.
    - If the seed is zero, set the state of the Xorshift structure to 1 to avoid a zero state.
- **Output**: The function does not return a value; it initializes the state of the Xorshift structure pointed to by `x`.


---
### xorshift\_next<!-- {{#callable:xorshift_next}} -->
The `xorshift_next` function generates the next random number in a sequence using the xorshift algorithm.
- **Inputs**:
    - `x`: A pointer to an Xorshift structure containing the current state of the random number generator.
- **Control Flow**:
    - Retrieve the current state from the Xorshift structure.
    - Perform a series of bitwise XOR and shift operations on the state to generate a new state.
    - Update the Xorshift structure with the new state.
    - Return the new state as the next random number.
- **Output**: The function returns a 32-bit unsigned integer representing the next random number in the sequence.


---
### random\_api\_call<!-- {{#callable:random_api_call}} -->
The `random_api_call` function performs one of four random actions on an HTTP server using a pseudo-random number generator.
- **Inputs**:
    - `u`: A pointer to an Xorshift structure used for generating pseudo-random numbers.
- **Control Flow**:
    - The function uses [`xorshift_next`](#xorshift_next) to generate a random number and takes the modulus with 4 to decide which case to execute.
    - In case 0, it attempts to send a WebSocket message to a randomly selected connection if it is active.
    - In case 1, it broadcasts a WebSocket message to all connections.
    - In case 2, it generates a random length of data, fills it with a specific byte, and sends it to the server using [`fd_http_server_memcpy`](fd_http_server.c.driver.md#fd_http_server_memcpy).
    - In case 3, it generates a random length of data, fills it with a specific byte, and sends it to the server using [`fd_http_server_printf`](fd_http_server.c.driver.md#fd_http_server_printf).
- **Output**: The function does not return any value; it performs actions on the HTTP server based on the random case selected.
- **Functions called**:
    - [`xorshift_next`](#xorshift_next)
    - [`fd_http_server_ws_send`](fd_http_server.c.driver.md#fd_http_server_ws_send)
    - [`fd_http_server_ws_broadcast`](fd_http_server.c.driver.md#fd_http_server_ws_broadcast)
    - [`fd_http_server_memcpy`](fd_http_server.c.driver.md#fd_http_server_memcpy)
    - [`fd_http_server_printf`](fd_http_server.c.driver.md#fd_http_server_printf)


---
### open\_callback<!-- {{#callable:open_callback}} -->
The `open_callback` function performs a series of random API calls based on a pseudo-random number generator when a connection is opened.
- **Inputs**:
    - `conn_id`: An unsigned long integer representing the connection ID, which is not used in the function.
    - `sockfd`: An integer representing the socket file descriptor, which is not used in the function.
    - `ctx`: A pointer to a context, which is not used in the function.
- **Control Flow**:
    - The function begins by explicitly ignoring the input parameters `conn_id`, `sockfd`, and `ctx` using the `(void)` cast to prevent unused variable warnings.
    - A loop is executed a number of times determined by the result of `xorshift_next(&poll_rng) % 3`, which generates a pseudo-random number between 0 and 2.
    - Within the loop, the [`random_api_call`](#random_api_call) function is called with `poll_rng` as its argument, executing a random API call based on the state of the pseudo-random number generator.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`xorshift_next`](#xorshift_next)
    - [`random_api_call`](#random_api_call)


---
### close\_callback<!-- {{#callable:close_callback}} -->
The `close_callback` function executes a series of random API calls when a connection is closed, using a pseudo-random number generator to determine the number of calls.
- **Inputs**:
    - `conn_id`: An unsigned long integer representing the connection ID, which is not used in the function.
    - `reason`: An integer representing the reason for the connection closure, which is not used in the function.
    - `ctx`: A pointer to a context object, which is not used in the function.
- **Control Flow**:
    - The function begins by explicitly ignoring the input parameters `conn_id`, `reason`, and `ctx` using the `(void)` cast to prevent unused variable warnings.
    - A loop is executed a number of times determined by the result of `xorshift_next(&poll_rng) % 3`, which generates a pseudo-random number between 0 and 2.
    - Within each iteration of the loop, the [`random_api_call`](#random_api_call) function is called with `poll_rng` as its argument.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`xorshift_next`](#xorshift_next)
    - [`random_api_call`](#random_api_call)


---
### request\_callback<!-- {{#callable:request_callback}} -->
The `request_callback` function generates a pseudo-random HTTP server response based on a given request and a random number generator.
- **Inputs**:
    - `request`: A pointer to a constant `fd_http_server_request_t` structure representing the incoming HTTP request.
- **Control Flow**:
    - Initialize a `fd_http_server_response_t` structure `resp` to zero.
    - Use a switch statement with a random number to set the HTTP status code of the response, with cases for 200, 204, 400, 404, 405, 500, and a default case for a random status.
    - Randomly set various HTTP response headers such as `content_type`, `cache_control`, `content_encoding`, `access_control_allow_origin`, `access_control_allow_methods`, `access_control_allow_headers`, and `access_control_max_age` based on random conditions.
    - Randomly set the `static_body` and `static_body_len` fields of the response.
    - If the request's headers indicate a WebSocket upgrade and a random condition is met, set the response status to 200 and enable WebSocket upgrade.
    - Perform a number of random API calls based on a random number.
    - Return the constructed `fd_http_server_response_t` response.
- **Output**: A `fd_http_server_response_t` structure containing the generated HTTP response.
- **Functions called**:
    - [`xorshift_next`](#xorshift_next)
    - [`random_api_call`](#random_api_call)


---
### ws\_open\_callback<!-- {{#callable:ws_open_callback}} -->
The `ws_open_callback` function is a WebSocket connection open event handler that triggers a series of random API calls based on a pseudo-random number generator.
- **Inputs**:
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID, which is not used in the function.
    - `ctx`: A pointer to a context object, which is not used in the function.
- **Control Flow**:
    - The function begins by explicitly ignoring the `ws_conn_id` and `ctx` parameters using casting to void.
    - A loop is executed a number of times determined by the result of `xorshift_next(&poll_rng) % 3`, which generates a pseudo-random number between 0 and 2.
    - Within the loop, the [`random_api_call`](#random_api_call) function is called, which performs one of several random actions based on another pseudo-random number.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`xorshift_next`](#xorshift_next)
    - [`random_api_call`](#random_api_call)


---
### ws\_close\_callback<!-- {{#callable:ws_close_callback}} -->
The `ws_close_callback` function is a WebSocket close event handler that performs a series of random API calls based on a pseudo-random number generator.
- **Inputs**:
    - `ws_conn_id`: The WebSocket connection identifier, which is not used in the function.
    - `reason`: The reason for the WebSocket closure, which is not used in the function.
    - `ctx`: A context pointer, which is not used in the function.
- **Control Flow**:
    - The function begins by explicitly ignoring its input parameters using the `(void)` cast to prevent unused variable warnings.
    - A loop is executed a number of times determined by the result of `xorshift_next(&poll_rng) % 3`, which generates a pseudo-random number between 0 and 2.
    - Within the loop, the [`random_api_call`](#random_api_call) function is called, which performs a random action based on the state of the `poll_rng` pseudo-random number generator.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`xorshift_next`](#xorshift_next)
    - [`random_api_call`](#random_api_call)


---
### ws\_message\_callback<!-- {{#callable:ws_message_callback}} -->
The `ws_message_callback` function is a WebSocket message handler that performs a series of random API calls based on a pseudo-random number generator.
- **Inputs**:
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID.
    - `data`: A pointer to an unsigned char array containing the message data received.
    - `data_len`: An unsigned long integer representing the length of the message data.
    - `ctx`: A void pointer to a context object, which is not used in this function.
- **Control Flow**:
    - The function begins by explicitly ignoring all input parameters using the `(void)` cast to suppress unused variable warnings.
    - A loop is executed a number of times determined by the result of `xorshift_next(&poll_rng) % 3`, which generates a pseudo-random number between 0 and 2.
    - Within the loop, the `random_api_call(&poll_rng)` function is called, which performs a random action based on the state of the `poll_rng` pseudo-random number generator.
- **Output**: The function does not return any value; it is a void function.
- **Functions called**:
    - [`xorshift_next`](#xorshift_next)
    - [`random_api_call`](#random_api_call)


---
### close\_reset\_clients\_fd<!-- {{#callable:close_reset_clients_fd}} -->
The `close_reset_clients_fd` function closes and resets all client file descriptors and poll file descriptors associated with an HTTP server.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server whose client and poll file descriptors are to be closed and reset.
- **Control Flow**:
    - Iterate over all client file descriptors up to `clients_fd_cnt` and close any that are open (not equal to -1), then reset them to -1 and set the corresponding WebSocket file descriptor to 0.
    - Reset `clients_fd_cnt` to 0, indicating no active client file descriptors.
    - Iterate over all poll file descriptors in the `http` server up to the sum of `PARAMS.max_connection_cnt` and `PARAMS.max_ws_connection_cnt`, closing any that are open (not equal to -1).
- **Output**: This function does not return any value; it performs its operations directly on the provided `http` server structure and global client file descriptor arrays.


---
### reserve\_client\_fd<!-- {{#callable:reserve_client_fd}} -->
The `reserve_client_fd` function reserves a file descriptor for a new client connection if the maximum number of connections has not been reached.
- **Inputs**: None
- **Control Flow**:
    - Check if the current number of client file descriptors (`clients_fd_cnt`) is greater than or equal to the maximum allowed (`FD_HTTP_SERVER_GUI_MAX_CONNS * 2`).
    - If the maximum is reached, return `NULL` indicating no more file descriptors can be reserved.
    - If not, return a pointer to the next available file descriptor in the `clients_fd` array and increment the `clients_fd_cnt`.
- **Output**: A pointer to an integer representing the reserved client file descriptor, or `NULL` if the maximum number of connections is reached.


---
### build\_http\_header<!-- {{#callable:build_http_header}} -->
The `build_http_header` function constructs an HTTP header string based on random selection of header types and values, and writes it to a buffer.
- **Inputs**:
    - `u`: A pointer to a `struct Unstructured` which provides random data for header selection.
    - `buf`: A character buffer where the constructed HTTP header will be written.
    - `max_len`: The maximum length of the buffer `buf` to ensure the header does not exceed this size.
    - `use_web_socket`: A pointer to an integer that will be set to 1 if a WebSocket header is constructed, otherwise it remains unchanged.
- **Control Flow**:
    - Check if `max_len` is less than or equal to 0, and return 0 if true, indicating no header is built.
    - Initialize `used` to 0 to track the number of characters written to `buf`.
    - Use a random number to select one of three cases for building a header: Content-Type, Accept-Encoding, or WebSocket.
    - For Content-Type, randomly select a content type and optionally append a charset, then write to `buf`.
    - For Accept-Encoding, construct a comma-separated list of encodings and write to `buf`.
    - For WebSocket, write a fixed WebSocket upgrade header to `buf` and set `*use_web_socket` to 1.
    - If the number of characters written (`used`) exceeds `max_len`, reset `buf` to an empty string and set `used` to 0.
    - Return the number of characters written to `buf`.
- **Output**: The function returns the number of characters written to the buffer `buf`, or 0 if the header could not be constructed within the given `max_len`.
- **Functions called**:
    - [`rand_uchar`](#rand_uchar)


---
### build\_http\_req<!-- {{#callable:build_http_req}} -->
The `build_http_req` function constructs an HTTP request string based on random selections and writes it into a provided buffer.
- **Inputs**:
    - `u`: A pointer to a `struct Unstructured` which provides random data for generating the HTTP request.
    - `buf`: A pointer to an unsigned character array where the constructed HTTP request will be stored.
    - `len`: A pointer to an integer representing the maximum size of the buffer, which will be updated to the actual size of the constructed request.
    - `use_websocket`: A pointer to an integer that will be set to 1 if the request includes a WebSocket upgrade header, otherwise it remains unchanged.
- **Control Flow**:
    - Initialize the buffer to zero and set up variables for maximum size and current size.
    - Randomly select an HTTP method from "GET", "POST", or "OPTIONS" and determine if it is a POST request.
    - Set the URI to "/home" and the HTTP version to "HTTP/1.1".
    - Initialize a headers buffer and set up a loop to add random headers until a random number of headers is reached.
    - If the method is POST, add a "Content-Length: 4" header to the headers buffer.
    - Use [`build_http_header`](#build_http_header) to add additional headers, potentially including a WebSocket upgrade header.
    - Construct the HTTP request line and headers into the buffer using `snprintf`, checking for buffer overflow.
    - If the method is POST, append a body to the request and update the size.
    - Update the `len` pointer to reflect the actual size of the constructed request.
- **Output**: The function outputs the constructed HTTP request in the `buf` and updates `len` to the size of the request. The `use_websocket` flag may be set if a WebSocket header is included.
- **Functions called**:
    - [`rand_uchar`](#rand_uchar)
    - [`rand_uint`](#rand_uint)
    - [`build_http_header`](#build_http_header)


---
### build\_ws\_req<!-- {{#callable:build_ws_req}} -->
The `build_ws_req` function constructs a WebSocket request frame with a random opcode and payload length, and fills the payload with random data.
- **Inputs**:
    - `u`: A pointer to a `Unstructured` struct, which provides random data for generating the WebSocket request.
    - `buf`: A pointer to an unsigned char buffer where the WebSocket request frame will be constructed.
    - `len`: A pointer to an integer that initially contains the maximum length of the buffer and will be updated to the actual length of the constructed WebSocket request.
- **Control Flow**:
    - Initialize `cur_pos` to point to the start of the buffer `buf`.
    - Select a random opcode from the predefined `OPCODES` array and store it in `opcode`.
    - Set the first byte of the buffer to the opcode, potentially setting the FIN bit based on a random condition.
    - Increment `cur_pos` to point to the next position in the buffer.
    - Determine a random payload length, adjusting it based on the opcode and the initial value of `len`.
    - Set the next byte in the buffer to the payload length, using special values 126 or 127 if the length exceeds 125, and set the MASK bit.
    - Increment `cur_pos` and, if necessary, write the extended payload length (16 or 64 bits) to the buffer.
    - Write a zero mask key to the buffer and increment `cur_pos`.
    - Fill the buffer with random data for the payload, using the determined payload length.
    - Update `len` to reflect the total length of the constructed WebSocket request frame.
- **Output**: The function outputs a WebSocket request frame in the buffer `buf`, and updates `len` to the length of the constructed frame.
- **Functions called**:
    - [`rand_uchar`](#rand_uchar)
    - [`rand_uint`](#rand_uint)


---
### stem\_thread<!-- {{#callable:stem_thread}} -->
The `stem_thread` function runs a loop that performs random API calls and polls an HTTP server until a stop condition is met.
- **Inputs**:
    - `arg`: A void pointer argument that is not used in the function.
- **Control Flow**:
    - Initialize `stem_iters` to 0.
    - Enter an infinite loop that continues until the `stop` variable is set to a non-zero value.
    - Within the loop, perform a random number (between 0 and 2) of API calls using [`random_api_call`](#random_api_call).
    - Poll the HTTP server using [`fd_http_server_poll`](fd_http_server.c.driver.md#fd_http_server_poll) with a timeout of 0.
    - Perform another random number (between 0 and 2) of API calls using [`random_api_call`](#random_api_call).
    - Increment the `stem_iters` counter.
    - Check if the `stop` variable is set; if so, break out of the loop.
    - Yield the processor to allow other threads to run using `sched_yield`.
- **Output**: Returns `NULL` when the loop exits.
- **Functions called**:
    - [`xorshift_next`](#xorshift_next)
    - [`random_api_call`](#random_api_call)
    - [`fd_http_server_poll`](fd_http_server.c.driver.md#fd_http_server_poll)


---
### do\_action<!-- {{#callable:do_action}} -->
The `do_action` function performs a random network action such as opening a connection, closing a connection, or sending data based on a random choice.
- **Inputs**:
    - `u`: A pointer to a `struct Unstructured` which contains random data used for decision making and generating random values.
- **Control Flow**:
    - The function begins by selecting a random action using `rand_uchar(u) % ActionEnd` to determine which case to execute.
    - If `HttpOpen` is selected, it attempts to open a new socket connection to a local server on port `port`, and if successful, it reserves a client file descriptor and connects to the server.
    - If `Close` is selected, it randomly selects an active client connection and closes it, marking the file descriptor as unused.
    - If `Send` is selected, it randomly selects an active client connection and sends either an HTTP or WebSocket request, potentially mutating the request data before sending.
- **Output**: The function does not return any value; it performs actions that affect global state, such as modifying client connections.
- **Functions called**:
    - [`rand_uchar`](#rand_uchar)
    - [`reserve_client_fd`](#reserve_client_fd)
    - [`build_http_req`](#build_http_req)
    - [`build_ws_req`](#build_ws_req)


---
### LLVMFuzzerTestOneInput<!-- {{#callable:LLVMFuzzerTestOneInput}} -->
The function `LLVMFuzzerTestOneInput` initializes and runs a fuzzing test on an HTTP server using the provided input data.
- **Inputs**:
    - `data`: A pointer to an array of unsigned characters representing the input data for the fuzzing test.
    - `size`: An unsigned long integer representing the size of the input data array.
- **Control Flow**:
    - Check if the input size is greater than or equal to the size of an integer; if not, return immediately.
    - Initialize a virtual memory allocator and an `Unstructured` struct to manage the input data.
    - Convert the IP address '0.0.0.0' to a network address and store it in `ip_as_int`.
    - Seed the random number generator using a random integer derived from the input data.
    - Allocate shared memory for the HTTP server using the virtual memory allocator.
    - Define HTTP server callbacks for various events such as open, close, request, and WebSocket events.
    - Create and start an HTTP server, binding it to the IP address and a random port.
    - Retrieve and store the port number the server is bound to.
    - Initialize a random number generator for polling operations.
    - Create a separate thread to run the `stem_thread` function, which handles server polling and random API calls.
    - Perform a series of random actions on the server, such as opening connections, sending requests, and closing connections, based on the input data.
    - Signal the thread to stop and wait for it to finish execution.
    - Clean up by closing client connections, shutting down the server, and freeing allocated memory.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`rand_uint`](#rand_uint)
    - [`fd_http_server_align`](fd_http_server.c.driver.md#fd_http_server_align)
    - [`fd_http_server_footprint`](fd_http_server.c.driver.md#fd_http_server_footprint)
    - [`fd_http_server_join`](fd_http_server.c.driver.md#fd_http_server_join)
    - [`fd_http_server_new`](fd_http_server.c.driver.md#fd_http_server_new)
    - [`fd_http_server_listen`](fd_http_server.c.driver.md#fd_http_server_listen)
    - [`xorshift_init`](#xorshift_init)
    - [`rand_uchar`](#rand_uchar)
    - [`do_action`](#do_action)
    - [`close_reset_clients_fd`](#close_reset_clients_fd)
    - [`fd_http_server_fd`](fd_http_server.c.driver.md#fd_http_server_fd)
    - [`fd_http_server_delete`](fd_http_server.c.driver.md#fd_http_server_delete)
    - [`fd_http_server_leave`](fd_http_server.c.driver.md#fd_http_server_leave)


# Function Declarations (Public API)

---
### build\_http\_req<!-- {{#callable_declaration:build_http_req}} -->
Constructs an HTTP request and writes it to a buffer.
- **Description**: This function generates an HTTP request using random data and writes it to the provided buffer. It is intended for use in scenarios where randomized HTTP requests are needed, such as in fuzz testing. The function requires a buffer with a specified maximum length and updates the length to reflect the actual size of the generated request. It also indicates whether the request is intended to use a WebSocket. The function must be called with a valid `Unstructured` data source and a buffer that is large enough to hold the generated request.
- **Inputs**:
    - `u`: A pointer to an `Unstructured` structure that provides random data for generating the HTTP request. The structure must be properly initialized and contain sufficient data for the function to operate.
    - `buf`: A pointer to a buffer where the generated HTTP request will be written. The buffer must be pre-allocated and large enough to hold the request.
    - `len`: A pointer to an integer that initially contains the maximum size of the buffer. Upon return, it is updated to reflect the actual size of the generated request.
    - `use_websocket`: A pointer to an integer that is set to indicate whether the generated request is intended to use a WebSocket. The value is set to 1 if a WebSocket is used, otherwise it remains 0.
- **Output**: None
- **See also**: [`build_http_req`](#build_http_req)  (Implementation)


---
### build\_ws\_req<!-- {{#callable_declaration:build_ws_req}} -->
Constructs a WebSocket request frame.
- **Description**: This function constructs a WebSocket request frame using random values derived from the provided `Unstructured` data source. It writes the frame into the provided buffer and updates the length to reflect the size of the constructed frame. This function is typically used in scenarios where WebSocket frames need to be generated dynamically, such as in testing or simulation environments. The buffer must be large enough to accommodate the frame, and the initial length should reflect the maximum buffer size available.
- **Inputs**:
    - `u`: A pointer to an `Unstructured` structure that provides random data for constructing the WebSocket frame. The structure must be properly initialized and must not be null.
    - `buf`: A pointer to a buffer where the WebSocket frame will be written. The buffer must be pre-allocated and large enough to hold the frame. The caller retains ownership of the buffer.
    - `len`: A pointer to an integer representing the maximum size of the buffer. On return, it is updated to reflect the actual size of the constructed WebSocket frame. The pointer must not be null.
- **Output**: None
- **See also**: [`build_ws_req`](#build_ws_req)  (Implementation)


---
### fd\_http\_server\_close<!-- {{#callable_declaration:fd_http_server_close}} -->
Closes a connection on the HTTP server.
- **Description**: Use this function to close an active connection on the HTTP server, specifying a reason for the closure. This function should be called when a connection needs to be terminated, either due to an error, completion of a request, or any other reason. It is important to ensure that the `http` server instance is valid and that the `conn_id` corresponds to an active connection. The function does not return a value and does not provide feedback on the success of the operation.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` instance representing the HTTP server. Must not be null and should be a valid server instance.
    - `conn_id`: An unsigned long integer representing the connection ID to be closed. It should correspond to an active connection on the server.
    - `reason`: An integer indicating the reason for closing the connection. The specific values and their meanings are determined by the application logic.
- **Output**: None
- **See also**: [`fd_http_server_close`](fd_http_server.c.driver.md#fd_http_server_close)  (Implementation)


---
### fd\_http\_server\_ws\_close<!-- {{#callable_declaration:fd_http_server_ws_close}} -->
Closes a WebSocket connection on the HTTP server.
- **Description**: Use this function to close an active WebSocket connection identified by its connection ID on the HTTP server. This function should be called when you need to terminate a WebSocket connection, either due to an error, a client request, or server-side logic. Ensure that the `http` parameter is a valid pointer to an initialized HTTP server instance and that the `ws_conn_id` corresponds to an active WebSocket connection. The `reason` parameter allows specifying a reason for the closure, which can be used for logging or debugging purposes.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server. Must not be null and should point to a valid, initialized server instance.
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID to be closed. It should be within the range of active WebSocket connections managed by the server.
    - `reason`: An integer specifying the reason for closing the connection. This can be used for logging or debugging purposes and does not affect the closure process.
- **Output**: None
- **See also**: [`fd_http_server_ws_close`](fd_http_server.c.driver.md#fd_http_server_ws_close)  (Implementation)


---
### fd\_http\_server\_ws\_send<!-- {{#callable_declaration:fd_http_server_ws_send}} -->
Sends a staged WebSocket frame to a specified connection.
- **Description**: This function is used to send a WebSocket frame that has been previously staged to a specific connection identified by `ws_conn_id`. It should be called when a WebSocket frame is ready to be sent from the staging buffer. The function checks for any errors in the staging process and ensures that the connection is still open before attempting to send. If the connection has been closed or if the staging process encountered an error, the function will return an error code. Additionally, if the connection's send buffer is full, the connection will be closed, and the function will return without sending the frame.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server. Must not be null, and the server should be properly initialized and running.
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID. It should be a valid ID corresponding to an active WebSocket connection managed by the server.
- **Output**: Returns 0 on success, indicating the frame was successfully queued for sending. Returns -1 if there was an error in the staging process or if the connection is closed. If the connection's send buffer is full, the connection is closed, and the function returns 0.
- **See also**: [`fd_http_server_ws_send`](fd_http_server.c.driver.md#fd_http_server_ws_send)  (Implementation)


---
### fd\_http\_server\_ws\_broadcast<!-- {{#callable_declaration:fd_http_server_ws_broadcast}} -->
Broadcasts a WebSocket frame to all connected clients.
- **Description**: Use this function to send a WebSocket frame to all currently connected WebSocket clients. It should be called when there is data staged in the server that needs to be broadcasted. The function checks for any errors in the staging process and handles them by resetting the error state. It also manages the sending queue for each connection, ensuring that clients that are too slow to process frames are closed to prevent resource exhaustion. This function should be called in the context of a running HTTP server with WebSocket support.
- **Inputs**:
    - `http`: A pointer to an initialized and running fd_http_server_t instance. Must not be null. The server should have active WebSocket connections to broadcast the frame to. If the server is in an error state, the function will reset the error and return -1.
- **Output**: Returns 0 on success, indicating that the frame was broadcasted to all connections. Returns -1 if there was an error in the staging process, which is then reset.
- **See also**: [`fd_http_server_ws_broadcast`](fd_http_server.c.driver.md#fd_http_server_ws_broadcast)  (Implementation)


---
### fd\_http\_server\_printf<!-- {{#callable_declaration:fd_http_server_printf}} -->
Formats and appends a string to the HTTP server's response buffer.
- **Description**: Use this function to format a string using a printf-style format and append it to the current HTTP response being constructed by the server. This function should be called only when constructing a response, and it is important to ensure that the server is not in an error state before calling it. The function handles variable arguments similar to printf, allowing for flexible string formatting. It is crucial to ensure that the server's response buffer has enough space to accommodate the formatted string, as the function will attempt to reserve the necessary space before appending.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null, and the server should not be in an error state.
    - `fmt`: A printf-style format string. Must not be null and should be a valid format string for the arguments provided.
    - `...`: Variable arguments corresponding to the format specifiers in fmt. These should match the expected types for the format specifiers used.
- **Output**: None
- **See also**: [`fd_http_server_printf`](fd_http_server.c.driver.md#fd_http_server_printf)  (Implementation)


---
### fd\_http\_server\_memcpy<!-- {{#callable_declaration:fd_http_server_memcpy}} -->
Copies data into the HTTP server's buffer.
- **Description**: Use this function to copy a specified amount of data into the buffer of an HTTP server instance. It is essential to ensure that the server instance is properly initialized and that the data length does not exceed the available buffer space. This function should be called when you need to append data to the server's outgoing buffer. If the server is in an error state, the function will return without performing any operation.
- **Inputs**:
    - `http`: A pointer to an initialized `fd_http_server_t` structure representing the HTTP server. Must not be null.
    - `data`: A pointer to the data to be copied. The caller retains ownership of the data, and it must not be null.
    - `data_len`: The length of the data to be copied, specified as an `ulong`. It should not exceed the available buffer space in the server.
- **Output**: None
- **See also**: [`fd_http_server_memcpy`](fd_http_server.c.driver.md#fd_http_server_memcpy)  (Implementation)


---
### fd\_http\_server\_stage\_trunc<!-- {{#callable_declaration:fd_http_server_stage_trunc}} -->
Truncates the HTTP server's staging buffer to a specified length.
- **Description**: Use this function to set the length of the HTTP server's staging buffer to a specific value. This is typically done to manage the amount of data being staged for processing or transmission. It is important to ensure that the `http` parameter is a valid pointer to an `fd_http_server_t` structure before calling this function. The function does not perform any validation on the `len` parameter, so it is the caller's responsibility to ensure that the specified length is appropriate for the current context.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server. Must not be null, and the caller retains ownership.
    - `len`: An unsigned long integer specifying the new length of the staging buffer. The function does not validate this value, so it should be set with care.
- **Output**: None
- **See also**: [`fd_http_server_stage_trunc`](fd_http_server.c.driver.md#fd_http_server_stage_trunc)  (Implementation)


---
### fd\_http\_server\_unstage<!-- {{#callable_declaration:fd_http_server_unstage}} -->
Resets the HTTP server's staging error and length.
- **Description**: Use this function to reset the staging error and length of an HTTP server instance. This is typically done to clear any previous state related to staging operations, ensuring that the server is ready for new operations. It should be called when you want to discard any current staging data and start fresh. The function does not perform any validation on the input parameter, so it is important to ensure that the `http` parameter is a valid pointer to an `fd_http_server_t` instance.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` instance. This parameter must not be null, as the function does not perform null checks. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_http_server_unstage`](fd_http_server.c.driver.md#fd_http_server_unstage)  (Implementation)


---
### fd\_http\_server\_stage\_body<!-- {{#callable_declaration:fd_http_server_stage_body}} -->
Stages the HTTP response body for transmission.
- **Description**: Use this function to prepare the HTTP response body for sending by updating the response object with the current stage offset and length. It should be called when you need to finalize the body content of an HTTP response. If there is an error in the staging process, indicated by a non-zero `stage_err` in the `http` object, the function will reset the error state and return an error code. This function assumes that the `http` object has been properly initialized and is in a valid state for staging.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` object representing the HTTP server context. Must not be null and should be properly initialized before calling this function.
    - `response`: A pointer to an `fd_http_server_response_t` object where the body offset and length will be set. Must not be null and should be a valid response object.
- **Output**: Returns 0 on success, indicating the body was staged correctly, or -1 if there was an error in the staging process.
- **See also**: [`fd_http_server_stage_body`](fd_http_server.c.driver.md#fd_http_server_stage_body)  (Implementation)


