# Purpose
This C source code file implements a simple HTTP server with WebSocket support. The server is designed to handle HTTP GET requests and WebSocket connections, providing basic functionality for serving HTML content and JSON responses. The code includes signal handling to gracefully terminate the server upon receiving an interrupt signal (SIGINT). The server is configured with specific parameters such as maximum connection counts and buffer sizes, and it uses a set of callback functions to manage HTTP requests, WebSocket events, and connection closures. The main function initializes the server, sets up the signal handler, and enters a loop to poll for incoming connections and requests, periodically broadcasting messages to all WebSocket clients.

The code is structured to provide a narrow functionality focused on HTTP and WebSocket communication. It defines a `test_http_server_t` structure to maintain server state and uses the `fd_http_server` library for server operations. The server responds to HTTP GET requests with either a simple HTML page or a JSON response, depending on the request details. WebSocket connections are managed through callbacks that log connection events and handle incoming messages. The code is intended to be compiled into an executable, as indicated by the presence of the [`main`](#main) function, and it does not define any public APIs or external interfaces beyond the server's HTTP and WebSocket endpoints.
# Imports and Dependencies

---
- `fd_http_server.h`
- `../../util/fd_util.h`
- `signal.h`
- `stdio.h`
- `errno.h`
- `stdlib.h`


# Global Variables

---
### stop
- **Type**: `int`
- **Description**: The `stop` variable is a static volatile integer that is used as a flag to control the termination of the main loop in the program. It is initially set to 0 and is modified by the signal handler to 1 when a SIGINT signal is received, indicating that the program should stop running.
- **Use**: The `stop` variable is used in the main loop to determine when to exit the loop and terminate the program.


# Data Structures

---
### test\_http\_server
- **Type**: `struct`
- **Members**:
    - `http`: A pointer to an fd_http_server_t structure, representing the HTTP server instance associated with this test server.
- **Description**: The `test_http_server` structure is a simple data structure that encapsulates a pointer to an `fd_http_server_t` instance, which is used to manage and operate an HTTP server within the context of a test environment. This structure is primarily used to maintain the state of the HTTP server, allowing for operations such as handling requests, managing WebSocket connections, and broadcasting messages. It serves as a context holder for the server operations defined in the accompanying code.


---
### test\_http\_server\_t
- **Type**: `struct`
- **Members**:
    - `http`: A pointer to an fd_http_server_t structure, representing the HTTP server instance associated with this test HTTP server.
- **Description**: The `test_http_server_t` structure is a simple wrapper around an `fd_http_server_t` pointer, used to manage and interact with an HTTP server instance in a test environment. It encapsulates the server instance, allowing for easy access and manipulation of the server's state and behavior during testing. This structure is primarily used to facilitate the handling of HTTP requests and WebSocket connections within the test server application.


# Functions

---
### signal\_handler<!-- {{#callable:signal_handler}} -->
The `signal_handler` function sets a global stop flag when a signal is received.
- **Inputs**:
    - `sig`: The signal number that triggered the handler, which is ignored in this function.
- **Control Flow**:
    - The function takes an integer `sig` as an argument, which represents the signal number.
    - The function explicitly ignores the `sig` parameter by casting it to void.
    - The global variable `stop` is set to 1, indicating that a stop condition has been triggered.
- **Output**: The function does not return any value.


---
### install\_signal\_handler<!-- {{#callable:install_signal_handler}} -->
The `install_signal_handler` function sets up a signal handler for the SIGINT signal to gracefully handle interrupt requests.
- **Inputs**: None
- **Control Flow**:
    - A `sigaction` structure `sa` is initialized with `signal_handler` as the handler function and no flags.
    - The `sigaction` function is called to associate the SIGINT signal with the `sa` structure.
    - If the `sigaction` call fails, an error message is logged using `FD_LOG_ERR`.
- **Output**: The function does not return any value.


---
### request<!-- {{#callable:request}} -->
The `request` function processes HTTP server requests, handling GET requests with optional WebSocket upgrades and other methods by logging and responding with JSON data.
- **Inputs**:
    - `request`: A pointer to a constant `fd_http_server_request_t` structure representing the incoming HTTP request, containing details such as method, path, headers, and context.
- **Control Flow**:
    - The function begins by casting the request's context to a `test_http_server_t` pointer named `state`.
    - It logs the request details including connection ID, method, path, content type, and context.
    - If the request method is GET, it checks if the request is a WebSocket upgrade.
    - If it is a WebSocket upgrade, it returns a response with status 200, WebSocket upgrade flag set, and content type as 'application/json'.
    - If it is not a WebSocket upgrade, it sends an HTML response with a 'Hello, world!' message and returns a response with status 200, no WebSocket upgrade, and content type as 'text/html'.
    - For non-GET requests, it logs the request body to stdout, sends a JSON-RPC response, and returns a response with status 200, no WebSocket upgrade, and content type as 'application/json'.
- **Output**: The function returns an `fd_http_server_response_t` structure representing the HTTP response, with fields for status, WebSocket upgrade flag, and content type.
- **Functions called**:
    - [`fd_http_server_method_str`](fd_http_server.c.driver.md#fd_http_server_method_str)
    - [`fd_http_server_printf`](fd_http_server.c.driver.md#fd_http_server_printf)
    - [`fd_http_server_stage_body`](fd_http_server.c.driver.md#fd_http_server_stage_body)


---
### http\_close<!-- {{#callable:http_close}} -->
The `http_close` function logs a notice message indicating the closure of an HTTP connection with its ID, reason, and context.
- **Inputs**:
    - `conn_id`: The unique identifier for the HTTP connection being closed.
    - `reason`: An integer representing the reason for the connection closure.
    - `ctx`: A pointer to a context object associated with the connection.
- **Control Flow**:
    - The function logs a notice message using the `FD_LOG_NOTICE` macro.
    - The log message includes the connection ID, a string representation of the closure reason obtained from `fd_http_server_connection_close_reason_str(reason)`, and the context pointer cast to an unsigned long.
- **Output**: The function does not return any value; it performs logging as a side effect.
- **Functions called**:
    - [`fd_http_server_connection_close_reason_str`](fd_http_server.c.driver.md#fd_http_server_connection_close_reason_str)


---
### ws\_open<!-- {{#callable:ws_open}} -->
The `ws_open` function logs a notice message indicating that a WebSocket connection has been opened, including the connection ID and context.
- **Inputs**:
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID.
    - `ctx`: A pointer to a context object associated with the WebSocket connection.
- **Control Flow**:
    - The function logs a notice message using the `FD_LOG_NOTICE` macro.
    - The log message includes the WebSocket connection ID and the context pointer, formatted as hexadecimal.
- **Output**: The function does not return any value; it is a void function.


---
### ws\_close<!-- {{#callable:ws_close}} -->
The `ws_close` function logs a notice message when a WebSocket connection is closed, including the connection ID, reason for closure, and context.
- **Inputs**:
    - `ws_conn_id`: The unique identifier for the WebSocket connection that is being closed.
    - `reason`: An integer representing the reason for the WebSocket connection closure.
    - `ctx`: A pointer to a context object associated with the WebSocket connection.
- **Control Flow**:
    - The function logs a notice message using the `FD_LOG_NOTICE` macro.
    - The log message includes the WebSocket connection ID, a string representation of the closure reason obtained from `fd_http_server_connection_close_reason_str(reason)`, and the context pointer cast to an unsigned long.
- **Output**: The function does not return any value; it performs logging as a side effect.
- **Functions called**:
    - [`fd_http_server_connection_close_reason_str`](fd_http_server.c.driver.md#fd_http_server_connection_close_reason_str)


---
### ws\_message<!-- {{#callable:ws_message}} -->
The `ws_message` function logs a WebSocket message and writes the message data to the standard output.
- **Inputs**:
    - `ws_conn_id`: The unique identifier for the WebSocket connection.
    - `data`: A pointer to the data received in the WebSocket message.
    - `data_len`: The length of the data received in the WebSocket message.
    - `ctx`: A context pointer that can be used to pass additional information.
- **Control Flow**:
    - Log the WebSocket connection ID and context using `FD_LOG_NOTICE`.
    - Write the string '>>>' to the standard output to indicate the start of the message.
    - Write the WebSocket message data to the standard output using `fwrite`.
    - Print the string '<<<' followed by a newline to the standard output to indicate the end of the message.
- **Output**: This function does not return any value; it performs logging and output operations.


---
### ws\_send\_all<!-- {{#callable:ws_send_all}} -->
The `ws_send_all` function sends a predefined JSON-RPC response to all connected WebSocket clients and verifies the broadcast operation's success.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server context.
- **Control Flow**:
    - The function calls [`fd_http_server_printf`](fd_http_server.c.driver.md#fd_http_server_printf) to send a JSON-RPC response with a result of 0 and an id of 1 to the HTTP server context.
    - It then calls [`fd_http_server_ws_broadcast`](fd_http_server.c.driver.md#fd_http_server_ws_broadcast) to broadcast this message to all connected WebSocket clients.
    - The function uses `FD_TEST` to assert that the broadcast operation was successful, ensuring no errors occurred.
- **Output**: The function does not return a value; it performs operations on the provided HTTP server context.
- **Functions called**:
    - [`fd_http_server_printf`](fd_http_server.c.driver.md#fd_http_server_printf)
    - [`fd_http_server_ws_broadcast`](fd_http_server.c.driver.md#fd_http_server_ws_broadcast)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs an HTTP server with WebSocket support, handling requests and connections until a termination signal is received.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the application with `fd_boot` using the command-line arguments.
    - Define server parameters and callback functions for handling HTTP requests and WebSocket events.
    - Create and join a new HTTP server instance with the specified parameters and callbacks.
    - Start listening for incoming connections on port 4321.
    - Install a signal handler to gracefully handle termination signals (e.g., SIGINT).
    - Enter a loop that continues until a termination signal is received, polling the server for events.
    - Periodically send WebSocket messages to all connected clients every second.
    - Upon receiving a termination signal, clean up by deleting and freeing the server resources.
    - Log a notice indicating successful termination and halt the application.
- **Output**: The function returns an integer status code, 0, indicating successful execution.
- **Functions called**:
    - [`fd_http_server_join`](fd_http_server.c.driver.md#fd_http_server_join)
    - [`fd_http_server_new`](fd_http_server.c.driver.md#fd_http_server_new)
    - [`fd_http_server_align`](fd_http_server.c.driver.md#fd_http_server_align)
    - [`fd_http_server_footprint`](fd_http_server.c.driver.md#fd_http_server_footprint)
    - [`fd_http_server_listen`](fd_http_server.c.driver.md#fd_http_server_listen)
    - [`install_signal_handler`](#install_signal_handler)
    - [`fd_http_server_poll`](fd_http_server.c.driver.md#fd_http_server_poll)
    - [`ws_send_all`](#ws_send_all)
    - [`fd_http_server_delete`](fd_http_server.c.driver.md#fd_http_server_delete)
    - [`fd_http_server_leave`](fd_http_server.c.driver.md#fd_http_server_leave)


