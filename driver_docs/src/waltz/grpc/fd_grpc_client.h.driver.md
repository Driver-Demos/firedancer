# Purpose
The provided C header file, `fd_grpc_client.h`, defines an API for managing gRPC client operations over HTTP/2 with TLS encryption. This file is part of a larger system and is intended to be included in other C source files to provide functionality for dispatching unary and server-streaming gRPC requests. The header file outlines the structure and operations of a gRPC client, including the definition of a private client structure (`fd_grpc_client_t`), metrics for monitoring client performance (`fd_grpc_client_metrics_t`), and a set of callback functions (`fd_grpc_client_callbacks_t`) that handle various stages of the gRPC communication process, such as connection establishment, message transmission, and reception.

The file also specifies several important constants and functions. For instance, it defines `FD_GRPC_CLIENT_MAX_STREAMS`, which limits the number of concurrent requests, and provides functions for creating and deleting gRPC client instances, setting client version information, and handling I/O operations with SSL or TCP sockets. The API includes mechanisms for starting gRPC requests, checking if requests are blocked, and accessing internal buffers for testing purposes. The header file is designed to be used in environments where OpenSSL is available, as indicated by conditional compilation directives. Overall, this file provides a comprehensive interface for integrating gRPC client capabilities into C applications, focusing on efficient communication and error handling.
# Imports and Dependencies

---
- `fd_grpc_codec.h`
- `../../ballet/nanopb/pb_firedancer.h`
- `openssl/types.h`


# Global Variables

---
### fd\_grpc\_client\_new
- **Type**: `fd_grpc_client_t *`
- **Description**: The `fd_grpc_client_new` function is a constructor for creating a new gRPC client instance. It initializes a client object that can dispatch unary and server-streaming gRPC requests over HTTP/2 with TLS. The function takes several parameters including memory allocation, callback functions, metrics tracking, application context, buffer size, and a random number generator seed.
- **Use**: This function is used to instantiate a new gRPC client, setting up necessary resources and configurations for handling gRPC communications.


---
### fd\_grpc\_client\_delete
- **Type**: `function pointer`
- **Description**: `fd_grpc_client_delete` is a function that takes a pointer to an `fd_grpc_client_t` structure and returns a void pointer. It is used to delete or clean up a gRPC client instance, likely freeing any resources associated with it.
- **Use**: This function is used to delete a gRPC client instance, freeing its resources.


---
### fd\_grpc\_client\_rbuf\_tx
- **Type**: `fd_h2_rbuf_t *`
- **Description**: The `fd_grpc_client_rbuf_tx` is a function that returns a pointer to an `fd_h2_rbuf_t` structure, which is likely a buffer used for transmitting data in the gRPC client over HTTP/2. This buffer is part of the internal workings of the gRPC client, specifically for handling outgoing data streams.
- **Use**: This function is used to access the transmission buffer of a gRPC client, allowing for the management and inspection of outgoing data streams.


---
### fd\_grpc\_client\_rbuf\_rx
- **Type**: `fd_h2_rbuf_t *`
- **Description**: The `fd_grpc_client_rbuf_rx` is a function that returns a pointer to an `fd_h2_rbuf_t` structure, which is likely a receive buffer used in the context of a gRPC client for handling incoming data over HTTP/2. This function takes a pointer to an `fd_grpc_client_t` structure as its parameter, indicating that it operates on a specific gRPC client instance.
- **Use**: This function is used to access the receive buffer associated with a gRPC client, facilitating the handling of incoming data streams.


---
### fd\_grpc\_client\_h2\_conn
- **Type**: `fd_h2_conn_t *`
- **Description**: The `fd_grpc_client_h2_conn` is a function that returns a pointer to an `fd_h2_conn_t` structure. This function is used to access the HTTP/2 connection associated with a gRPC client.
- **Use**: This function is used to retrieve the HTTP/2 connection object for a given gRPC client, allowing for operations or inspections on the connection.


---
### fd\_grpc\_client\_h2\_callbacks
- **Type**: `fd_h2_callbacks_t const`
- **Description**: The `fd_grpc_client_h2_callbacks` is a constant global variable of type `fd_h2_callbacks_t`. It is likely used to define a set of callback functions for handling HTTP/2 events in the context of a gRPC client. These callbacks are essential for managing the lifecycle and events of HTTP/2 connections, such as connection establishment, data transmission, and connection termination.
- **Use**: This variable is used to provide a predefined set of HTTP/2 callback functions for the gRPC client to handle various connection events.


# Data Structures

---
### fd\_grpc\_client\_t
- **Type**: `typedef struct fd_grpc_client_private fd_grpc_client_t;`
- **Members**:
    - `fd_grpc_client_private`: A private structure representing the internal state and data of the gRPC client.
- **Description**: The `fd_grpc_client_t` is a typedef for a private structure `fd_grpc_client_private`, which encapsulates the internal state and data necessary for managing gRPC client operations over HTTP/2+TLS. This data structure is part of an API designed to handle unary and server-streaming gRPC requests, providing functionalities such as connection management, request queuing, and data transmission. The structure is used in conjunction with metrics and callback structures to facilitate efficient communication and error handling in gRPC client-server interactions.


---
### fd\_grpc\_client\_metrics
- **Type**: `struct`
- **Members**:
    - `wakeup_cnt`: Counts the number of times the gRPC client was polled for I/O.
    - `stream_err_cnt`: Counts the number of survivable stream errors, such as out-of-memory conditions and decode failures.
    - `conn_err_cnt`: Counts the number of connection errors that resulted in connection termination, including protocol and I/O errors.
    - `stream_chunks_tx_cnt`: Increments whenever a DATA frame containing request bytes is sent.
    - `stream_chunks_tx_bytes`: Counts the number of stream bytes sent.
    - `stream_chunks_rx_cnt`: Increments whenever a DATA frame containing response bytes is received.
    - `stream_chunks_rx_bytes`: Counts the number of stream bytes received.
    - `requests_sent`: Increments whenever a gRPC request finished sending.
    - `streams_active`: Represents the number of streams not in 'closed' state.
    - `rx_wait_ticks_cum`: Cumulative time in ticks that incoming gRPC messages were in a 'waiting' state, indicating server-to-client congestion.
    - `tx_wait_ticks_cum`: Cumulative time in ticks that an outgoing message was in a 'waiting' state, indicating client-to-server congestion.
- **Description**: The `fd_grpc_client_metrics` structure is designed to hold various counters and metrics related to the operation of a gRPC client. It tracks the number of times the client is polled for I/O, counts different types of errors, and measures the amount of data sent and received. Additionally, it provides insights into the number of active streams and the waiting times for both incoming and outgoing messages, which can be used to assess network congestion and performance issues. This structure is crucial for monitoring and debugging the performance of gRPC client operations.


---
### fd\_grpc\_client\_metrics\_t
- **Type**: `struct`
- **Members**:
    - `wakeup_cnt`: Counts the number of times the gRPC client was polled for I/O.
    - `stream_err_cnt`: Counts the number of survivable stream errors, such as out-of-memory conditions and decode failures.
    - `conn_err_cnt`: Counts the number of connection errors that resulted in connection termination, including protocol and I/O errors.
    - `stream_chunks_tx_cnt`: Increments whenever a DATA frame containing request bytes is sent.
    - `stream_chunks_tx_bytes`: Counts the number of stream bytes sent.
    - `stream_chunks_rx_cnt`: Increments whenever a DATA frame containing response bytes is received.
    - `stream_chunks_rx_bytes`: Counts the number of stream bytes received.
    - `requests_sent`: Increments whenever a gRPC request finished sending.
    - `streams_active`: Represents the number of streams not in 'closed' state.
    - `rx_wait_ticks_cum`: Cumulative time in ticks that incoming gRPC messages were in a 'waiting' state, indicating server-to-client congestion.
    - `tx_wait_ticks_cum`: Cumulative time in ticks that an outgoing message was in a 'waiting' state, indicating client-to-server congestion.
- **Description**: The `fd_grpc_client_metrics_t` structure is designed to hold various counters that track the performance and error metrics of a gRPC client. It includes fields for counting the number of times the client was polled, the number of stream and connection errors, and the number of bytes sent and received. Additionally, it tracks the number of active streams and the cumulative waiting time for both incoming and outgoing messages, providing insights into potential congestion issues in the client-server communication.


---
### fd\_grpc\_client\_callbacks
- **Type**: `struct`
- **Members**:
    - `conn_established`: A callback function called when the initial HTTP/2 SETTINGS exchange concludes.
    - `conn_dead`: A callback function called when the HTTP/2 connection ends, indicating the connection is not recoverable.
    - `tx_complete`: A callback function marking the completion of a transmission operation.
    - `rx_start`: A callback function signaling that the server sent back a response header indicating success.
    - `rx_msg`: A callback function delivering a gRPC message, possibly called multiple times for server streaming.
    - `rx_end`: A callback function indicating that no more rx_msg callbacks will be delivered for a request.
    - `ping_ack`: A callback function delivering an acknowledgement of a PING previously sent.
- **Description**: The `fd_grpc_client_callbacks` structure is a virtual function table containing callback functions for various events in a gRPC client lifecycle over HTTP/2. These callbacks handle connection establishment and termination, transmission completion, reception of response headers and messages, and acknowledgements of PINGs. This structure allows the application to define custom behaviors for these events by providing function pointers that are invoked at appropriate times during the gRPC communication process.


---
### fd\_grpc\_client\_callbacks\_t
- **Type**: `struct`
- **Members**:
    - `conn_established`: Callback function called when the initial HTTP/2 SETTINGS exchange concludes.
    - `conn_dead`: Callback function called when the HTTP/2 connection ends, indicating the connection is not recoverable.
    - `tx_complete`: Callback function marking the completion of a transmission operation.
    - `rx_start`: Callback function signaling that the server sent back a response header indicating success.
    - `rx_msg`: Callback function delivering a gRPC message, possibly called multiple times for server streaming.
    - `rx_end`: Callback function indicating that no more rx_msg callbacks will be delivered for a request.
    - `ping_ack`: Callback function delivering an acknowledgement of a PING previously sent.
- **Description**: The `fd_grpc_client_callbacks_t` structure is a virtual function table containing callback functions for a gRPC client application. These callbacks handle various stages of the gRPC communication process, such as connection establishment, connection termination, transmission completion, and message reception. Each function pointer in the structure is designed to be implemented by the application to define specific behaviors when these events occur, allowing for customized handling of gRPC client operations.


# Function Declarations (Public API)

---
### fd\_grpc\_client\_align<!-- {{#callable_declaration:fd_grpc_client_align}} -->
Return the alignment requirement of the gRPC client structure.
- **Description**: Use this function to determine the memory alignment requirement for the `fd_grpc_client_t` structure. This is useful when allocating memory for a gRPC client to ensure that the memory is properly aligned according to the platform's requirements. This function does not require any prior initialization and can be called at any time.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the alignment requirement in bytes for the `fd_grpc_client_t` structure.
- **See also**: [`fd_grpc_client_align`](fd_grpc_client.c.driver.md#fd_grpc_client_align)  (Implementation)


---
### fd\_grpc\_client\_footprint<!-- {{#callable_declaration:fd_grpc_client_footprint}} -->
Calculate the memory footprint required for a gRPC client.
- **Description**: Use this function to determine the amount of memory needed to allocate for a gRPC client, based on the maximum buffer size specified. This is useful for ensuring that sufficient memory is allocated before initializing a gRPC client. The function calculates the total memory footprint by considering various internal buffers and structures required for the client to operate. It is important to call this function before creating a gRPC client to ensure that the memory allocation is adequate.
- **Inputs**:
    - `buf_max`: Specifies the maximum size of the buffer in bytes. It must be a positive integer, and the function will use this value to calculate the total memory footprint required. If an invalid value is provided, the behavior is undefined.
- **Output**: Returns the total memory footprint in bytes required for the gRPC client, based on the specified buffer size.
- **See also**: [`fd_grpc_client_footprint`](fd_grpc_client.c.driver.md#fd_grpc_client_footprint)  (Implementation)


---
### fd\_grpc\_client\_new<!-- {{#callable_declaration:fd_grpc_client_new}} -->
Creates a new gRPC client instance.
- **Description**: This function initializes a new gRPC client for dispatching unary and server-streaming requests over HTTP/2+TLS. It should be called when a new client instance is needed, and it requires a memory block to store the client data. The function also sets up necessary buffers and metrics tracking. The caller must ensure that the provided memory is sufficient and properly aligned. The function returns a pointer to the new client instance or NULL if the memory is insufficient or the buffer size is too small. It is important to call this function before attempting any gRPC operations with the client.
- **Inputs**:
    - `mem`: A pointer to a memory block where the client instance will be allocated. Must not be null and should be properly aligned and sized.
    - `callbacks`: A pointer to a structure containing callback functions for handling various gRPC client events. The caller retains ownership and must ensure it remains valid for the client's lifetime.
    - `metrics`: A pointer to a structure for tracking client metrics. The caller retains ownership and must ensure it remains valid for the client's lifetime.
    - `app_ctx`: A user-defined context pointer passed to callback functions. The caller retains ownership.
    - `buf_max`: The maximum size of internal buffers. Must be at least 4096. Smaller values will result in a NULL return.
    - `rng_seed`: A seed for random number generation used internally by the client.
- **Output**: Returns a pointer to the newly created gRPC client instance, or NULL if initialization fails due to invalid input or insufficient resources.
- **See also**: [`fd_grpc_client_new`](fd_grpc_client.c.driver.md#fd_grpc_client_new)  (Implementation)


---
### fd\_grpc\_client\_delete<!-- {{#callable_declaration:fd_grpc_client_delete}} -->
Deletes a gRPC client instance.
- **Description**: Use this function to delete a gRPC client instance when it is no longer needed. This function should be called to clean up resources associated with the client. It is important to ensure that the client is not in use or referenced elsewhere in the application before calling this function to avoid undefined behavior.
- **Inputs**:
    - `client`: A pointer to the gRPC client instance to be deleted. The pointer must not be null, and the client should not be in use by any other part of the application when this function is called.
- **Output**: Returns the pointer to the client that was passed in.
- **See also**: [`fd_grpc_client_delete`](fd_grpc_client.c.driver.md#fd_grpc_client_delete)  (Implementation)


---
### fd\_grpc\_client\_set\_version<!-- {{#callable_declaration:fd_grpc_client_set_version}} -->
Sets the gRPC client's version string.
- **Description**: Use this function to set the version string for a gRPC client, which is relayed via the user-agent header. The function copies the provided version string into the client object, so no reference to the original string is maintained. The version string does not need to be null-terminated. Ensure that the version length does not exceed FD_GRPC_CLIENT_VERSION_LEN_MAX; otherwise, a warning is logged, and the version string remains unchanged.
- **Inputs**:
    - `client`: A pointer to an fd_grpc_client_t structure representing the gRPC client. Must not be null.
    - `version`: A pointer to a character array containing the version string to set. The string does not need to be null-terminated.
    - `version_len`: The length of the version string. Must be less than or equal to FD_GRPC_CLIENT_VERSION_LEN_MAX. If it exceeds this limit, the function logs a warning and does not change the client's version string.
- **Output**: None
- **See also**: [`fd_grpc_client_set_version`](fd_grpc_client.c.driver.md#fd_grpc_client_set_version)  (Implementation)


---
### fd\_grpc\_client\_rxtx\_ossl<!-- {{#callable_declaration:fd_grpc_client_rxtx_ossl}} -->
Drive I/O operations against an SSL object for a gRPC client.
- **Description**: This function facilitates the exchange of data between a gRPC client and a server over a secure connection using OpenSSL. It should be called when there is a need to perform read and write operations on the SSL object associated with the client. The function handles the SSL handshake if it has not been completed yet and manages data transfer between the SSL layer and the HTTP/2 buffers. It is important to ensure that the client is properly initialized and that the SSL object is valid before calling this function. The function will return 1 on successful data transfer or if the operation is still in progress, and 0 if an unrecoverable SSL error occurs.
- **Inputs**:
    - `client`: A pointer to an initialized fd_grpc_client_t structure. The client must be properly set up before calling this function. The caller retains ownership.
    - `ssl`: A pointer to an SSL object representing the secure connection. This must be a valid and properly initialized SSL object. The caller retains ownership.
    - `charge_busy`: A pointer to an integer that will be set to 1 if any data was read or written during the call, indicating that the client was busy. The caller must provide a valid pointer.
- **Output**: Returns 1 on success or if the operation is still in progress, and 0 if there is an unrecoverable SSL error.
- **See also**: [`fd_grpc_client_rxtx_ossl`](fd_grpc_client.c.driver.md#fd_grpc_client_rxtx_ossl)  (Implementation)


---
### fd\_grpc\_client\_rxtx\_socket<!-- {{#callable_declaration:fd_grpc_client_rxtx_socket}} -->
Drives I/O operations on a TCP socket for a gRPC client.
- **Description**: This function is used to perform non-blocking I/O operations on a TCP socket associated with a gRPC client, utilizing the recvmsg and sendmsg system calls with MSG_NOSIGNAL and MSG_DONTWAIT flags. It should be called when there is a need to process incoming and outgoing data on the socket. The function updates the charge_busy flag if any data was successfully received or sent, indicating that the client was active. It returns 1 on success and 0 if there is a disconnection or an error during the send operation. This function is typically used in the context of a gRPC client that communicates over HTTP/2.
- **Inputs**:
    - `client`: A pointer to an fd_grpc_client_t structure representing the gRPC client. Must not be null.
    - `sock_fd`: An integer representing the file descriptor of the TCP socket. Must be a valid, open socket descriptor.
    - `charge_busy`: A pointer to an integer that will be set to 1 if data was received or sent, indicating activity. Must not be null.
- **Output**: Returns 1 on successful I/O operations, or 0 if a disconnection or send error occurs.
- **See also**: [`fd_grpc_client_rxtx_socket`](fd_grpc_client.c.driver.md#fd_grpc_client_rxtx_socket)  (Implementation)


---
### fd\_grpc\_client\_request\_start<!-- {{#callable_declaration:fd_grpc_client_request_start}} -->
Queue a gRPC request for sending with a Protobuf message.
- **Description**: This function is used to initiate a gRPC request over HTTP/2 with TLS encryption, sending a single Protobuf message. It should be called when the connection is established, and there is no other request currently being sent. The function requires a valid client object, host and path information, and a Protobuf message descriptor and data. An optional authorization token can be included. The function returns immediately if the client is blocked or if encoding the message fails. It is important to ensure that the serialized message size does not exceed the maximum allowed size and that the client has quota to open a new stream.
- **Inputs**:
    - `client`: A pointer to an fd_grpc_client_t object representing the gRPC client. Must not be null.
    - `host`: A constant character pointer to the host name. The caller retains ownership and it must not be null.
    - `host_len`: The length of the host string. Must be a valid length corresponding to the host string.
    - `port`: The port number to connect to. Must be a valid port number.
    - `path`: A constant character pointer to the HTTP request path, typically in the format '/path.to.package/Service.Function'. The caller retains ownership and it must not be null.
    - `path_len`: The length of the path string. Must be in the range [0, 128).
    - `request_ctx`: An arbitrary number used to identify the request, echoed in callbacks. Must be a valid ulong value.
    - `fields`: A pointer to a pb_msgdesc_t structure describing the Protobuf message fields. Must not be null.
    - `message`: A constant pointer to the Protobuf message data. The caller retains ownership and it must not be null.
    - `auth_token`: A constant character pointer to an optional authorization token. If auth_token_sz is greater than zero, it is included in the request header as 'authorization: Bearer <auth_token>'. Can be null if auth_token_sz is zero.
    - `auth_token_sz`: The size of the authorization token. If zero, the authorization header is omitted.
- **Output**: Returns 1 on success, indicating the request was queued for sending, or 0 if the client is blocked or an error occurs.
- **See also**: [`fd_grpc_client_request_start`](fd_grpc_client.c.driver.md#fd_grpc_client_request_start)  (Implementation)


---
### fd\_grpc\_client\_request\_is\_blocked<!-- {{#callable_declaration:fd_grpc_client_request_is_blocked}} -->
Determine if a gRPC client request is blocked.
- **Description**: Use this function to check if initiating a gRPC request with the client would fail due to various blocking conditions. It should be called before attempting to start a new request to ensure that the client is ready and able to process it. This function checks for conditions such as an incomplete SSL/HTTP/2 handshake, a dead connection, or if the client's transmission buffer is not empty. It is essential to ensure that the client is properly initialized and connected before calling this function.
- **Inputs**:
    - `client`: A pointer to an fd_grpc_client_t structure representing the gRPC client. Must not be null. If null, the function will return 1, indicating that the request is blocked.
- **Output**: Returns 1 if the request is blocked due to conditions like an incomplete handshake or a non-empty transmission buffer, otherwise returns 0.
- **See also**: [`fd_grpc_client_request_is_blocked`](fd_grpc_client.c.driver.md#fd_grpc_client_request_is_blocked)  (Implementation)


---
### fd\_grpc\_client\_rbuf\_tx<!-- {{#callable_declaration:fd_grpc_client_rbuf_tx}} -->
Retrieve the transmit buffer for the gRPC client.
- **Description**: Use this function to access the transmit buffer associated with a gRPC client. This is typically used for testing or debugging purposes to inspect or manipulate the buffer directly. It is important to ensure that the client is properly initialized before calling this function. The function does not modify the state of the client or the buffer.
- **Inputs**:
    - `client`: A pointer to an initialized fd_grpc_client_t structure. Must not be null. The caller retains ownership and responsibility for the client object.
- **Output**: Returns a pointer to the fd_h2_rbuf_t structure representing the transmit buffer of the specified gRPC client.
- **See also**: [`fd_grpc_client_rbuf_tx`](fd_grpc_client.c.driver.md#fd_grpc_client_rbuf_tx)  (Implementation)


---
### fd\_grpc\_client\_rbuf\_rx<!-- {{#callable_declaration:fd_grpc_client_rbuf_rx}} -->
Retrieve the receive buffer for a gRPC client.
- **Description**: Use this function to access the receive buffer associated with a gRPC client. This is typically used for testing or debugging purposes to inspect the data being received by the client. The function should be called with a valid gRPC client object, and it assumes that the client has been properly initialized and is in a state where it can receive data.
- **Inputs**:
    - `client`: A pointer to a valid fd_grpc_client_t object. The client must be properly initialized and not null. If the client is invalid or null, the behavior is undefined.
- **Output**: Returns a pointer to the fd_h2_rbuf_t structure representing the receive buffer of the specified gRPC client.
- **See also**: [`fd_grpc_client_rbuf_rx`](fd_grpc_client.c.driver.md#fd_grpc_client_rbuf_rx)  (Implementation)


---
### fd\_grpc\_client\_h2\_conn<!-- {{#callable_declaration:fd_grpc_client_h2_conn}} -->
Retrieve the HTTP/2 connection associated with a gRPC client.
- **Description**: Use this function to obtain the HTTP/2 connection object from a gRPC client instance. This is typically used for low-level operations or testing purposes where direct access to the connection is necessary. Ensure that the gRPC client is properly initialized before calling this function to avoid undefined behavior.
- **Inputs**:
    - `client`: A pointer to a valid fd_grpc_client_t instance. Must not be null. The caller retains ownership of the client object.
- **Output**: Returns a pointer to the fd_h2_conn_t associated with the provided gRPC client. The returned pointer is valid as long as the client is valid.
- **See also**: [`fd_grpc_client_h2_conn`](fd_grpc_client.c.driver.md#fd_grpc_client_h2_conn)  (Implementation)


