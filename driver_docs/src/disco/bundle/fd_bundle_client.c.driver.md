# Purpose
The `fd_bundle_client.c` file is a C source file that implements a client for managing gRPC connections to a bundle server. This client is responsible for establishing and maintaining a connection to the server, handling authentication, and subscribing to various data streams such as packets and bundles. The file includes functions for resetting the client state, creating and managing TCP and SSL connections, and handling gRPC requests and responses. It also includes mechanisms for handling connection errors, performing backoff strategies, and logging connection status.

The file is structured around a central theme of managing network communication with a bundle server using gRPC. It includes several static functions that encapsulate specific tasks such as connecting to the server, subscribing to data streams, and handling incoming data. The file also defines a set of callbacks for gRPC client events, such as connection establishment and message reception. The code is designed to be integrated into a larger system, as indicated by the inclusion of various headers and the use of external functions and data structures. The file does not define a public API but rather provides internal functionality for managing the client-side aspects of the bundle server communication.
# Imports and Dependencies

---
- `fd_bundle_auth.h`
- `fd_bundle_tile_private.h`
- `proto/block_engine.pb.h`
- `proto/bundle.pb.h`
- `proto/packet.pb.h`
- `../fd_txn_m_t.h`
- `../plugin/fd_plugin.h`
- `../../waltz/h2/fd_h2_conn.h`
- `../../ballet/base58/fd_base58.h`
- `../../ballet/nanopb/pb_decode.h`
- `../../util/net/fd_ip4.h`
- `fcntl.h`
- `errno.h`
- `unistd.h`
- `poll.h`
- `sys/socket.h`
- `netinet/in.h`


# Global Variables

---
### fdctl\_version\_string
- **Type**: ``char const[]``
- **Description**: The `fdctl_version_string` is a global constant character array that holds the version information of the fdctl (Firedancer control) component. It is defined externally, likely in a separate source file, and is used to provide versioning information for the software.
- **Use**: This variable is used to set the version information in the gRPC client, ensuring that the client communicates its version to the server.


---
### fd\_bundle\_client\_grpc\_callbacks
- **Type**: `fd_grpc_client_callbacks_t`
- **Description**: The `fd_bundle_client_grpc_callbacks` is a global variable of type `fd_grpc_client_callbacks_t` that holds a set of function pointers for handling various gRPC client events. These events include connection establishment, connection termination, transmission completion, reception start, message reception, reception end, and ping acknowledgment.
- **Use**: This variable is used to define the behavior of the gRPC client by specifying callback functions that are invoked during different stages of the gRPC communication process.


# Functions

---
### fd\_bundle\_client\_reset<!-- {{#callable:fd_bundle_client_reset}} -->
The `fd_bundle_client_reset` function resets the state of a bundle client context, closing any active connections and clearing subscription statuses.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure representing the client context to be reset.
- **Control Flow**:
    - Check if the client was previously connected by evaluating `bundle_subscription_live` and `packet_subscription_live` flags, and log a warning if true.
    - If the TCP socket (`tcp_sock`) is open, attempt to close it and log an error if the close operation fails, then reset the socket state.
    - Reset various context flags and states such as `defer_reset`, `builder_info_wait`, `packet_subscription_live`, `packet_subscription_wait`, `bundle_subscription_live`, and `bundle_subscription_wait` to zero.
    - If OpenSSL is enabled and an SSL context exists, free the SSL context and set it to NULL.
    - Set the `grpc_client` pointer to NULL, indicating no active gRPC client.
    - Invoke [`fd_bundle_tile_backoff`](#fd_bundle_tile_backoff) to handle backoff logic for reconnection attempts.
    - Call [`fd_bundle_auther_handle_request_fail`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_request_fail) to handle any failed authentication requests.
- **Output**: The function does not return a value; it modifies the state of the `fd_bundle_tile_t` context passed to it.
- **Functions called**:
    - [`fd_bundle_tile_backoff`](#fd_bundle_tile_backoff)
    - [`fd_bundle_auther_handle_request_fail`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_request_fail)


---
### fd\_bundle\_client\_do\_connect<!-- {{#callable:fd_bundle_client_do_connect}} -->
The `fd_bundle_client_do_connect` function attempts to establish a TCP connection to a server using a given IP address and context information, returning any error encountered during the connection attempt.
- **Inputs**:
    - `ctx`: A constant pointer to an `fd_bundle_tile_t` structure containing context information, including the server's TCP port and socket.
    - `ip4_addr`: An unsigned integer representing the IPv4 address of the server to connect to.
- **Control Flow**:
    - Initialize a `sockaddr_in` structure with the provided IPv4 address, the server's TCP port (byte-swapped), and the address family set to `AF_INET`.
    - Set the global `errno` variable to 0 to clear any previous error state.
    - Attempt to connect to the server using the `connect` function with the socket from the context and the initialized `sockaddr_in` structure.
    - Return the value of `errno`, which indicates the success or failure of the connection attempt.
- **Output**: Returns an integer representing the error code from the connection attempt, with 0 indicating success and any other value indicating an error.


---
### fd\_bundle\_client\_create\_conn<!-- {{#callable:fd_bundle_client_create_conn}} -->
The `fd_bundle_client_create_conn` function initializes and establishes a TCP connection to a server, optionally setting up SSL, and prepares a gRPC client for communication.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure that contains context and configuration for the connection, including server details and metrics.
- **Control Flow**:
    - The function begins by resetting the client state using [`fd_bundle_client_reset`](#fd_bundle_client_reset) to ensure a clean start.
    - It sets up address information hints for an IPv4 connection and attempts to resolve the server's address using `fd_getaddrinfo`.
    - If address resolution fails, it logs a warning, resets the client, increments the transport failure count, and exits.
    - On success, it extracts the IPv4 address and stores it in the context.
    - A TCP socket is created with `socket`, and if this fails, an error is logged and the function exits.
    - The socket's receive buffer size is set using `setsockopt`, and the socket is set to non-blocking mode using `fcntl`.
    - The connection scheme is determined based on whether SSL is enabled, defaulting to HTTP or HTTPS.
    - An informational log is made about the connection attempt.
    - The function attempts to connect to the server using [`fd_bundle_client_do_connect`](#fd_bundle_client_do_connect). If the connection fails with an error other than `EINPROGRESS`, it logs a warning, resets the client, increments the transport failure count, and exits.
    - If SSL is enabled, it sets up the SSL context and associates it with the socket using OpenSSL functions.
    - A new gRPC client is created with `fd_grpc_client_new`, and if this fails, a critical error is logged.
    - Finally, the gRPC client version is set using `fd_grpc_client_set_version`.
- **Output**: The function does not return a value; it modifies the `ctx` structure to reflect the new connection state and logs any errors encountered during the process.
- **Functions called**:
    - [`fd_bundle_client_reset`](#fd_bundle_client_reset)
    - [`fd_bundle_client_do_connect`](#fd_bundle_client_do_connect)


---
### fd\_bundle\_client\_drive\_io<!-- {{#callable:fd_bundle_client_drive_io}} -->
The `fd_bundle_client_drive_io` function manages the input/output operations for a gRPC client, using either SSL or a regular TCP socket based on the context configuration.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure that contains the context for the gRPC client, including connection details and state information.
    - `charge_busy`: A pointer to an integer that indicates whether the function should mark the client as busy after performing I/O operations.
- **Control Flow**:
    - Check if the context (`ctx`) is configured to use SSL (`ctx->is_ssl`).
    - If SSL is enabled, call `fd_grpc_client_rxtx_ossl` with the gRPC client, SSL context, and `charge_busy` to handle I/O operations over SSL.
    - If SSL is not enabled, call `fd_grpc_client_rxtx_socket` with the gRPC client, TCP socket, and `charge_busy` to handle I/O operations over a regular socket.
- **Output**: Returns the result of the I/O operation, which is the return value from either `fd_grpc_client_rxtx_ossl` or `fd_grpc_client_rxtx_socket`, depending on whether SSL is used.


---
### fd\_bundle\_client\_request\_builder\_info<!-- {{#callable:fd_bundle_client_request_builder_info}} -->
The `fd_bundle_client_request_builder_info` function initiates a gRPC request to retrieve block builder fee information if the client is not currently blocked.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure, which contains the context and state for the gRPC client and related operations.
- **Control Flow**:
    - Check if the gRPC client is blocked using `fd_grpc_client_request_is_blocked`; if blocked, return immediately.
    - Initialize a `block_engine_BlockBuilderFeeInfoRequest` structure with default values.
    - Define a static path string for the gRPC request endpoint.
    - Call `fd_grpc_client_request_start` to initiate the request with the specified parameters, including the gRPC client, server details, request type, and authorization token.
    - If the request initiation fails (`req_ok` is false), return immediately.
    - Set `ctx->builder_info_wait` to 1 to indicate that the request is in progress.
- **Output**: The function does not return a value; it modifies the state of the `ctx` structure to indicate that a request for builder fee information is in progress.


---
### fd\_bundle\_client\_subscribe\_packets<!-- {{#callable:fd_bundle_client_subscribe_packets}} -->
The `fd_bundle_client_subscribe_packets` function initiates a gRPC request to subscribe to packet updates from a server if the client is not currently blocked.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure representing the client context, which contains information about the gRPC client, server details, and authentication tokens.
- **Control Flow**:
    - Check if the gRPC client request is blocked using `fd_grpc_client_request_is_blocked`; if blocked, return immediately.
    - Initialize a `block_engine_SubscribePacketsRequest` structure with default values.
    - Define a static string `path` representing the gRPC endpoint for subscribing to packets.
    - Call `fd_grpc_client_request_start` to initiate the gRPC request with the server details, request type, message, and authentication tokens.
    - If the request initiation fails (`req_ok` is false), return immediately.
    - Set `ctx->packet_subscription_wait` to 1 to indicate that a packet subscription request is in progress.
- **Output**: The function does not return a value; it modifies the state of the `ctx` structure to reflect the initiation of a packet subscription request.


---
### fd\_bundle\_client\_subscribe\_bundles<!-- {{#callable:fd_bundle_client_subscribe_bundles}} -->
The `fd_bundle_client_subscribe_bundles` function initiates a gRPC request to subscribe to bundle updates from a server if the client is not currently blocked.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure that contains the context for the bundle client, including gRPC client information and authentication details.
- **Control Flow**:
    - Check if the gRPC client request is blocked using `fd_grpc_client_request_is_blocked`; if blocked, return immediately.
    - Initialize a `block_engine_SubscribeBundlesRequest` structure with default values.
    - Define a static path string for the gRPC request endpoint.
    - Call `fd_grpc_client_request_start` to initiate the gRPC request with the specified parameters, including server details and authentication tokens.
    - If the request initiation fails (`req_ok` is false), return immediately.
    - Set `ctx->bundle_subscription_wait` to 1 to indicate that a subscription request is in progress.
- **Output**: The function does not return a value; it modifies the state of the `ctx` structure to reflect the initiation of a bundle subscription request.


---
### fd\_bundle\_client\_send\_ping<!-- {{#callable:fd_bundle_client_send_ping}} -->
The `fd_bundle_client_send_ping` function sends a PING frame over an HTTP/2 connection if the connection is available and not busy, updating the context with the current timestamp and a randomized value.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure representing the context of the bundle client, which includes the gRPC client and other related state information.
- **Control Flow**:
    - Check if the gRPC client in the context is available; if not, return immediately.
    - Retrieve the HTTP/2 connection from the gRPC client; if unavailable, return immediately.
    - Check if the connection is busy by examining its flags; if busy, return immediately.
    - Retrieve the transmission buffer for the gRPC client.
    - Attempt to send a PING frame using the HTTP/2 connection and transmission buffer.
    - If the PING is successfully sent, update the context's last ping transmission timestamp and generate a new random value for ping randomization.
- **Output**: The function does not return a value; it updates the context's state if a PING is successfully sent.


---
### fd\_bundle\_client\_keepalive\_due<!-- {{#callable:fd_bundle_client_keepalive_due}} -->
The `fd_bundle_client_keepalive_due` function determines if a keepalive ping is due based on the current time and the last ping timestamp.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_bundle_tile_t` structure containing context information such as the last ping timestamp and ping threshold ticks.
    - `now_ticks`: A long integer representing the current time in ticks.
- **Control Flow**:
    - Calculate `delay_min` as half of `ctx->ping_threshold_ticks`.
    - Calculate `delay_rng` as the bitwise AND of `ctx->ping_threshold_ticks` and `ctx->ping_randomize`.
    - Compute `delay` as the sum of `delay_min` and `delay_rng`.
    - Determine `deadline` by adding `delay` to `ctx->last_ping_tx_ts`.
    - Return true if `now_ticks` is greater than or equal to `deadline`, indicating a keepalive ping is due.
- **Output**: Returns an integer (1 or 0) indicating whether a keepalive ping is due (1) or not (0).


---
### fd\_bundle\_client\_step<!-- {{#callable:fd_bundle_client_step}} -->
The `fd_bundle_client_step` function manages the connection and communication with a gRPC server, handling socket connections, authentication, and various subscription requests.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure that holds the context and state for the bundle client, including connection status, authentication state, and subscription flags.
    - `charge_busy`: A pointer to an integer that indicates whether the function has performed any busy work, which is set to 1 if the function engages in any significant processing or state changes.
- **Control Flow**:
    - Check if the TCP socket is connected; if not, attempt to connect or handle connection errors.
    - If the gRPC client is not available, attempt to reconnect or handle stalling conditions.
    - Drive I/O operations, including SSL handshakes and processing inflight requests; reset the client on errors.
    - Check if the client is ready to issue new requests and handle stalling conditions.
    - If authentication polling is needed, perform it and set `charge_busy` to 1.
    - Request block builder information if not already live or waiting.
    - Subscribe to packet and bundle streams if not already live or waiting.
    - Send a keepalive PING if due, and set `charge_busy` to 1 if any of these operations are performed.
- **Output**: The function does not return a value but modifies the state of the `ctx` structure and the `charge_busy` flag to reflect the operations performed.
- **Functions called**:
    - [`fd_bundle_client_do_connect`](#fd_bundle_client_do_connect)
    - [`fd_bundle_client_reset`](#fd_bundle_client_reset)
    - [`fd_bundle_tile_should_stall`](fd_bundle_tile_private.h.driver.md#fd_bundle_tile_should_stall)
    - [`fd_bundle_client_create_conn`](#fd_bundle_client_create_conn)
    - [`fd_bundle_client_drive_io`](#fd_bundle_client_drive_io)
    - [`fd_bundle_auther_poll`](fd_bundle_auth.c.driver.md#fd_bundle_auther_poll)
    - [`fd_bundle_client_request_builder_info`](#fd_bundle_client_request_builder_info)
    - [`fd_bundle_client_subscribe_packets`](#fd_bundle_client_subscribe_packets)
    - [`fd_bundle_client_subscribe_bundles`](#fd_bundle_client_subscribe_bundles)
    - [`fd_bundle_client_keepalive_due`](#fd_bundle_client_keepalive_due)
    - [`fd_bundle_client_send_ping`](#fd_bundle_client_send_ping)


---
### fd\_bundle\_tile\_backoff<!-- {{#callable:fd_bundle_tile_backoff}} -->
The `fd_bundle_tile_backoff` function calculates and sets a backoff period for a given context based on the current timestamp and a random wait time.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure representing the context for which the backoff is being calculated.
    - `ts_ticks`: A long integer representing the current timestamp in ticks.
- **Control Flow**:
    - Retrieve the current backoff iteration count from the context.
    - If the current timestamp is less than the backoff reset time, reset the iteration count to zero.
    - Increment the iteration count.
    - Calculate a fixed wait time in ticks using a tempo tick conversion function.
    - Generate a random wait time by masking a random number with a bitmask derived from the most significant bit of the wait time.
    - Set the backoff until time in the context to the current timestamp plus the random wait time.
    - Set the backoff reset time in the context to the current timestamp plus twice the random wait time.
    - Update the backoff iteration count in the context.
- **Output**: The function does not return a value; it modifies the `fd_bundle_tile_t` context structure in place.


---
### fd\_bundle\_client\_grpc\_conn\_established<!-- {{#callable:fd_bundle_client_grpc_conn_established}} -->
The function `fd_bundle_client_grpc_conn_established` logs a message indicating that a gRPC connection has been successfully established.
- **Inputs**:
    - `app_ctx`: A void pointer to application context, which is not used in this function.
- **Control Flow**:
    - The function takes a single argument `app_ctx`, which is not used, and is cast to void to avoid compiler warnings.
    - A log message is generated using `FD_LOG_INFO` to indicate that the gRPC connection has been established.
- **Output**: The function does not return any value or output.


---
### fd\_bundle\_client\_grpc\_conn\_dead<!-- {{#callable:fd_bundle_client_grpc_conn_dead}} -->
The function `fd_bundle_client_grpc_conn_dead` logs the closure of a gRPC connection and sets a flag to defer a reset of the connection context.
- **Inputs**:
    - `app_ctx`: A pointer to the application context, specifically a `fd_bundle_tile_t` structure, which holds the state and configuration for the gRPC connection.
    - `h2_err`: An unsigned integer representing the HTTP/2 error code that caused the connection to close.
    - `closed_by`: An integer indicating whether the connection was closed by the peer (non-zero value) or due to an error (zero value).
- **Control Flow**:
    - Cast the `app_ctx` to a `fd_bundle_tile_t` pointer to access the connection context.
    - Log an informational message indicating that the gRPC connection has been closed, specifying whether it was closed by the peer or due to an error, and including the HTTP/2 error code and its string representation.
    - Set the `defer_reset` flag in the context to 1, indicating that a reset of the connection should be deferred.
- **Output**: The function does not return any value; it performs logging and modifies the state of the connection context.


---
### fd\_bundle\_tile\_publish\_bundle\_txn<!-- {{#callable:fd_bundle_tile_publish_bundle_txn}} -->
The `fd_bundle_tile_publish_bundle_txn` function publishes a bundle transaction to the tango message bus after preparing and verifying the transaction data.
- **Inputs**:
    - `ctx`: A pointer to the `fd_bundle_tile_t` context structure, which contains various state and configuration information for the bundle tile.
    - `txn`: A constant pointer to the transaction data to be published.
    - `txn_sz`: The size of the transaction data, which must be less than or equal to `FD_TXN_MTU`.
    - `bundle_txn_cnt`: The count of transactions in the current bundle.
- **Control Flow**:
    - Check if builder information is available in the context; if not, increment the missing builder info fail count and return.
    - Convert the current chunk to a local address and initialize a transaction message structure with the provided transaction size and bundle transaction count.
    - Copy the builder's public key and the transaction data into the transaction message structure.
    - Calculate the realized footprint size of the transaction message.
    - Check if the stem is set in the context; if not, log a critical error.
    - Publish the transaction message to the stem with the calculated size and timestamp.
    - Update the chunk in the context to the next compacted chunk and increment the transaction received count in the metrics.
- **Output**: The function does not return a value; it performs operations on the provided context and updates its state and metrics.


---
### fd\_bundle\_tile\_publish\_txn<!-- {{#callable:fd_bundle_tile_publish_txn}} -->
The `fd_bundle_tile_publish_txn` function forwards a regular transaction to the tango message bus by preparing a transaction message and publishing it through a specified stem.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bundle_tile_t` structure that contains context information for the transaction processing.
    - `txn`: A constant pointer to the transaction data to be published.
    - `txn_sz`: An unsigned long integer representing the size of the transaction, which must be less than or equal to `FD_TXN_MTU`.
- **Control Flow**:
    - Convert the chunk address to a local address using `fd_chunk_to_laddr` and store it in `txnm`.
    - Initialize the `fd_txn_m_t` structure pointed to by `txnm` with default values, including setting `payload_sz` to `txn_sz` and `bundle_txn_cnt` to 1.
    - Copy the transaction data from `txn` to the payload of `txnm` using `fd_memcpy`.
    - Calculate the realized footprint size of the transaction using `fd_txn_m_realized_footprint`.
    - Check if `ctx->stem` is set; if not, log a critical error indicating a bug.
    - Compute the publication timestamp using `fd_frag_meta_ts_comp` and `fd_tickcount`.
    - Publish the transaction using `fd_stem_publish` with the calculated size and timestamp.
    - Update `ctx->verify_out.chunk` to the next compacted chunk using `fd_dcache_compact_next`.
    - Increment the transaction received count in `ctx->metrics`.
- **Output**: The function does not return a value; it performs operations to publish a transaction and updates the context state.


---
### fd\_bundle\_client\_visit\_pb\_bundle\_txn\_preflight<!-- {{#callable:fd_bundle_client_visit_pb_bundle_txn_preflight}} -->
The function `fd_bundle_client_visit_pb_bundle_txn_preflight` increments the transaction count for a bundle in the context of a protobuf stream processing.
- **Inputs**:
    - `istream`: A pointer to a `pb_istream_t` structure, representing the input stream for protobuf decoding.
    - `field`: A pointer to a `pb_field_t` structure, representing the field being processed in the protobuf message.
    - `arg`: A pointer to a pointer to a `void`, which is expected to be a pointer to a `fd_bundle_tile_t` structure, representing the context for the bundle processing.
- **Control Flow**:
    - The function begins by casting the `arg` parameter to a `fd_bundle_tile_t` pointer, which is used as the context for the operation.
    - It increments the `bundle_txn_cnt` field of the `fd_bundle_tile_t` context, which tracks the number of transactions in the current bundle.
    - The function returns `true`, indicating successful processing of the transaction preflight.
- **Output**: The function returns a boolean value `true`, indicating that the transaction preflight processing was successful.


---
### fd\_bundle\_client\_visit\_pb\_bundle\_txn<!-- {{#callable:fd_bundle_client_visit_pb_bundle_txn}} -->
The `fd_bundle_client_visit_pb_bundle_txn` function decodes a protobuf packet and publishes it as a bundle transaction if it is within the allowed size.
- **Inputs**:
    - `istream`: A pointer to a `pb_istream_t` structure representing the input stream from which the protobuf data is read.
    - `field`: A pointer to a `pb_field_t` structure representing the field being processed, though it is not used in this function.
    - `arg`: A pointer to a pointer to a `fd_bundle_tile_t` structure, which holds the context for the bundle client.
- **Control Flow**:
    - The function begins by casting the `arg` parameter to a `fd_bundle_tile_t` context pointer.
    - A `packet_Packet` structure is initialized to its default state.
    - The function attempts to decode the protobuf data from `istream` into the `packet` structure using `pb_decode`.
    - If decoding fails, it increments the `decode_fail_cnt` metric in the context and logs a warning, then returns `false`.
    - If the decoded packet's data size exceeds `FD_TXN_MTU`, a warning is logged, and the function returns `true` to ignore the oversized transaction.
    - If the packet is valid and within size limits, it calls [`fd_bundle_tile_publish_bundle_txn`](#fd_bundle_tile_publish_bundle_txn) to publish the transaction, passing the context, packet data, size, and transaction count.
    - Finally, the function returns `true` to indicate successful processing.
- **Output**: The function returns a boolean value: `true` if the transaction was successfully processed or ignored due to size, and `false` if there was a decoding failure.
- **Functions called**:
    - [`fd_bundle_tile_publish_bundle_txn`](#fd_bundle_tile_publish_bundle_txn)


---
### fd\_bundle\_client\_visit\_pb\_bundle\_uuid<!-- {{#callable:fd_bundle_client_visit_pb_bundle_uuid}} -->
The function `fd_bundle_client_visit_pb_bundle_uuid` processes a Protobuf stream to count and publish transactions within a bundle, updating the context with transaction counts and handling potential decode failures.
- **Inputs**:
    - `istream`: A pointer to a `pb_istream_t` structure representing the input stream from which the Protobuf data is read.
    - `field`: A pointer to a `pb_field_t` structure, which is not used in this function.
    - `arg`: A pointer to a pointer to a `void` type, which is expected to be a `fd_bundle_tile_t` context structure used to maintain state and metrics.
- **Control Flow**:
    - The function begins by resetting the bundle state, setting `bundle_txn_cnt` to 0 and incrementing `bundle_seq`.
    - A copy of the input stream is made to perform a first pass decode to count the number of transactions in the bundle using `fd_bundle_client_visit_pb_bundle_txn_preflight`.
    - If the first pass decode fails, the function logs a warning, increments the decode failure count, and returns false.
    - If the first pass is successful, the function proceeds to a second pass to actually publish the bundle packets using `fd_bundle_client_visit_pb_bundle_txn`.
    - If the second pass decode fails, the function logs a warning, increments the decode failure count, and returns false.
    - If both passes are successful, the function increments the bundle received count and returns true.
- **Output**: The function returns a boolean value indicating success (true) or failure (false) of the decoding and processing of the bundle.


---
### fd\_bundle\_client\_handle\_bundle\_batch<!-- {{#callable:fd_bundle_client_handle_bundle_batch}} -->
The `fd_bundle_client_handle_bundle_batch` function processes a batch of bundle data from a gRPC response stream, updating metrics and handling errors as necessary.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure that holds the context and state information for the bundle client.
    - `istream`: A pointer to a `pb_istream_t` structure representing the input stream from which the bundle data is read.
- **Control Flow**:
    - Check if builder information is available in the context; if not, increment the missing builder info failure count and return.
    - Initialize a `block_engine_SubscribeBundlesResponse` structure with default values and set up a callback for processing bundle UUIDs.
    - Attempt to decode the input stream into the `block_engine_SubscribeBundlesResponse` structure using the `pb_decode` function.
    - If decoding fails, increment the decode failure count, log a warning with the error message, and return.
- **Output**: The function does not return a value; it updates the context's metrics and logs warnings if errors occur during processing.


---
### fd\_bundle\_client\_visit\_pb\_packet<!-- {{#callable:fd_bundle_client_visit_pb_packet}} -->
The `fd_bundle_client_visit_pb_packet` function decodes a protobuf packet and processes it if it is within a specified size limit.
- **Inputs**:
    - `istream`: A pointer to a `pb_istream_t` structure representing the input stream from which the protobuf packet is to be decoded.
    - `field`: A pointer to a `pb_field_t` structure, which is not used in this function.
    - `arg`: A pointer to a pointer to a `void` type, which is expected to point to a `fd_bundle_tile_t` context structure.
- **Control Flow**:
    - The function begins by casting the `arg` parameter to a `fd_bundle_tile_t` pointer named `ctx`.
    - A `packet_Packet` structure is initialized to its default values.
    - The function attempts to decode a protobuf packet from the `istream` into the `packet` structure using `pb_decode`.
    - If decoding fails, it increments the `decode_fail_cnt` metric in the context and logs a warning, then returns `false`.
    - If the packet's data size exceeds `FD_TXN_MTU`, a warning is logged, and the function returns `true` without further processing.
    - If the packet is valid and within size limits, it calls [`fd_bundle_tile_publish_txn`](#fd_bundle_tile_publish_txn) to process the packet data and increments the `packet_received_cnt` metric.
    - Finally, the function returns `true` to indicate successful processing.
- **Output**: The function returns a boolean value: `true` if the packet was successfully processed or ignored due to size, and `false` if there was a decoding failure.
- **Functions called**:
    - [`fd_bundle_tile_publish_txn`](#fd_bundle_tile_publish_txn)


---
### fd\_bundle\_client\_handle\_packet\_batch<!-- {{#callable:fd_bundle_client_handle_packet_batch}} -->
The `fd_bundle_client_handle_packet_batch` function processes a batch of packets from a gRPC SubscribePacketsResponse by decoding them and updating the context metrics.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure that holds the context and state information for the bundle client.
    - `istream`: A pointer to a `pb_istream_t` structure representing the input stream from which the protobuf message is to be decoded.
- **Control Flow**:
    - Initialize a `block_engine_SubscribePacketsResponse` structure with default values.
    - Set the `packets` field of the `batch` in the response to a callback function `fd_bundle_client_visit_pb_packet` with `ctx` as its argument.
    - Attempt to decode the protobuf message from `istream` into the `res` structure using `pb_decode`.
    - If decoding fails, increment the `decode_fail_cnt` metric in `ctx` and log a warning message.
    - Return from the function if decoding fails.
- **Output**: The function does not return a value; it updates the context metrics and logs warnings if decoding fails.


---
### fd\_bundle\_client\_log\_progress<!-- {{#callable:fd_bundle_client_log_progress}} -->
The `fd_bundle_client_log_progress` function logs a notice indicating a successful connection to the bundle server if certain conditions are met.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure, which contains the context and state information for the bundle client.
- **Control Flow**:
    - The function checks if `ctx->packet_subscription_live`, `ctx->bundle_subscription_live`, and `ctx->builder_info_live` are all true (non-zero).
    - If all conditions are true, it logs a notice message indicating that the client is connected to the bundle server.
- **Output**: The function does not return any value; it performs logging as a side effect.


---
### fd\_bundle\_client\_handle\_builder\_fee\_info<!-- {{#callable:fd_bundle_client_handle_builder_fee_info}} -->
The function `fd_bundle_client_handle_builder_fee_info` processes a gRPC response containing block builder fee information, updating the context with the commission and public key if valid.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure representing the context in which the function operates, containing state and metrics for the bundle client.
    - `istream`: A pointer to a `pb_istream_t` structure representing the input stream from which the protobuf message is decoded.
- **Control Flow**:
    - Initialize a boolean `changed` to indicate if builder info availability has changed.
    - Decode the protobuf message from `istream` into a `block_engine_BlockBuilderFeeInfoResponse` structure `res`.
    - If decoding fails, increment the decode failure count in `ctx->metrics`, log a warning, and return.
    - Check if `res.commission` is greater than 100; if so, increment the decode failure count, log a warning, and return.
    - Set `ctx->builder_commission` to the decoded commission value.
    - Attempt to decode the base58 public key from `res.pubkey` into `ctx->builder_pubkey`; if this fails, log a warning and return.
    - Set `ctx->builder_info_avail` and `ctx->builder_info_live` to 1, indicating the builder info is now available and live.
    - If `changed` is true, call [`fd_bundle_client_log_progress`](#fd_bundle_client_log_progress) to log the progress.
- **Output**: The function does not return a value; it updates the `ctx` structure with the builder commission and public key if the response is valid.
- **Functions called**:
    - [`fd_bundle_client_log_progress`](#fd_bundle_client_log_progress)


---
### fd\_bundle\_client\_grpc\_tx\_complete<!-- {{#callable:fd_bundle_client_grpc_tx_complete}} -->
The `fd_bundle_client_grpc_tx_complete` function is a placeholder for handling the completion of a gRPC transaction, but currently does nothing.
- **Inputs**:
    - `app_ctx`: A pointer to application-specific context data, which is not used in this function.
    - `request_ctx`: An unsigned long integer representing the context of the request, which is not used in this function.
- **Control Flow**:
    - The function takes two parameters, `app_ctx` and `request_ctx`, but does not use them.
    - Both parameters are cast to void to suppress unused variable warnings.
    - The function body is empty, indicating no operations are performed.
- **Output**: The function does not return any value or produce any output.


---
### fd\_bundle\_client\_grpc\_rx\_start<!-- {{#callable:fd_bundle_client_grpc_rx_start}} -->
The `fd_bundle_client_grpc_rx_start` function updates the subscription status of a gRPC client based on the request context and logs progress if there is a change.
- **Inputs**:
    - `app_ctx`: A pointer to the application context, specifically a `fd_bundle_tile_t` structure, which holds the state and configuration of the gRPC client.
    - `request_ctx`: An unsigned long integer representing the request context, which indicates the type of subscription request being processed (e.g., subscribing to packets or bundles).
- **Control Flow**:
    - The function begins by casting the `app_ctx` to a `fd_bundle_tile_t` pointer named `ctx`.
    - A boolean variable `changed` is initialized to `0` to track if any subscription status changes occur.
    - A switch statement is used to handle different `request_ctx` values.
    - If `request_ctx` is `FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets`, the function sets `ctx->packet_subscription_live` to `1` and `ctx->packet_subscription_wait` to `0`, then sets `changed` to `1`.
    - If `request_ctx` is `FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles`, the function sets `ctx->bundle_subscription_live` to `1` and `ctx->bundle_subscription_wait` to `0`, then sets `changed` to `1`.
    - If `changed` is `1`, the function calls [`fd_bundle_client_log_progress`](#fd_bundle_client_log_progress) with `ctx` to log the progress of the subscription.
- **Output**: The function does not return a value; it modifies the state of the `fd_bundle_tile_t` structure pointed to by `app_ctx`.
- **Functions called**:
    - [`fd_bundle_client_log_progress`](#fd_bundle_client_log_progress)


---
### fd\_bundle\_client\_grpc\_rx\_msg<!-- {{#callable:fd_bundle_client_grpc_rx_msg}} -->
The `fd_bundle_client_grpc_rx_msg` function processes incoming gRPC messages based on the request context and updates the application context accordingly.
- **Inputs**:
    - `app_ctx`: A pointer to the application context, specifically a `fd_bundle_tile_t` structure, which holds the state and metrics for the gRPC client.
    - `protobuf`: A pointer to the buffer containing the protobuf-encoded message received from the gRPC server.
    - `protobuf_sz`: The size of the protobuf message buffer.
    - `request_ctx`: An unsigned long integer representing the context or type of the gRPC request, which determines how the message should be processed.
- **Control Flow**:
    - The function begins by casting `app_ctx` to a `fd_bundle_tile_t` pointer named `ctx` and initializes a protobuf input stream `istream` from the `protobuf` buffer.
    - A switch statement is used to handle different `request_ctx` values, each corresponding to a specific gRPC request type.
    - For `FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge` and `FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens`, it calls respective handler functions to process authentication responses and increments a decode failure counter and triggers a backoff if the response handling fails.
    - For `FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles`, it calls [`fd_bundle_client_handle_bundle_batch`](#fd_bundle_client_handle_bundle_batch) to process a batch of bundle subscriptions.
    - For `FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets`, it calls [`fd_bundle_client_handle_packet_batch`](#fd_bundle_client_handle_packet_batch) to process a batch of packet subscriptions.
    - For `FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo`, it calls [`fd_bundle_client_handle_builder_fee_info`](#fd_bundle_client_handle_builder_fee_info) to process block builder fee information.
    - If the `request_ctx` does not match any known type, it logs an error indicating an unexpected gRPC message was received.
- **Output**: The function does not return a value; it operates by updating the state and metrics within the `fd_bundle_tile_t` context based on the received gRPC message.
- **Functions called**:
    - [`fd_bundle_auther_handle_challenge_resp`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_challenge_resp)
    - [`fd_bundle_tile_backoff`](#fd_bundle_tile_backoff)
    - [`fd_bundle_auther_handle_tokens_resp`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_tokens_resp)
    - [`fd_bundle_client_handle_bundle_batch`](#fd_bundle_client_handle_bundle_batch)
    - [`fd_bundle_client_handle_packet_batch`](#fd_bundle_client_handle_packet_batch)
    - [`fd_bundle_client_handle_builder_fee_info`](#fd_bundle_client_handle_builder_fee_info)


---
### fd\_bundle\_client\_request\_failed<!-- {{#callable:fd_bundle_client_request_failed}} -->
The `fd_bundle_client_request_failed` function handles the failure of a client request by initiating a backoff and potentially handling authentication request failures.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure representing the context of the bundle client.
    - `request_ctx`: An unsigned long integer representing the context of the request that failed.
- **Control Flow**:
    - Call [`fd_bundle_tile_backoff`](#fd_bundle_tile_backoff) with the current context and tick count to initiate a backoff strategy.
    - Use a switch statement to check the `request_ctx` value.
    - If `request_ctx` matches `FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge` or `FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens`, call [`fd_bundle_auther_handle_request_fail`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_request_fail) to handle the failure in the authentication process.
- **Output**: This function does not return a value; it performs actions based on the request failure.
- **Functions called**:
    - [`fd_bundle_tile_backoff`](#fd_bundle_tile_backoff)
    - [`fd_bundle_auther_handle_request_fail`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_request_fail)


---
### fd\_hex\_unhex<!-- {{#callable:fd_hex_unhex}} -->
The `fd_hex_unhex` function converts a single hexadecimal character to its integer value or returns -1 if the character is not a valid hexadecimal digit.
- **Inputs**:
    - `c`: An integer representing a character, which is expected to be a hexadecimal digit ('0'-'9', 'a'-'f', or 'A'-'F').
- **Control Flow**:
    - Check if the character is between '0' and '9'; if true, return the integer value by subtracting '0'.
    - Check if the character is between 'a' and 'f'; if true, return the integer value by subtracting 'a' and adding 0xa.
    - Check if the character is between 'A' and 'F'; if true, return the integer value by subtracting 'A' and adding 0xa.
    - If none of the above conditions are met, return -1 indicating an invalid hexadecimal character.
- **Output**: An integer representing the numeric value of the hexadecimal character, or -1 if the character is not a valid hexadecimal digit.


---
### fd\_url\_unescape<!-- {{#callable:fd_url_unescape}} -->
The `fd_url_unescape` function decodes percent-encoded characters in a URL string, modifying the string in place.
- **Inputs**:
    - `msg`: A pointer to the character array (string) that contains the URL-encoded message to be decoded.
    - `len`: The length of the string to be processed, indicating how many characters from the start of the string should be considered for decoding.
- **Control Flow**:
    - Initialize `end` as a pointer to the end of the string based on `len`, `state` to 0, and `dst` to point to `msg`.
    - Iterate over each character in the string from `msg` to `end` using `src` as the iterator.
    - In state 0, if the current character is not '%', copy it to `dst` and increment `dst`; otherwise, change state to 1.
    - In state 1, if the current character is not '%', decode the first hex digit and store it in `dst`, then change state to 2; if it is '%', store '%' in `dst` and revert to state 0.
    - In state 2, decode the second hex digit, combine it with the first, store the result in `dst`, increment `dst`, and revert to state 0.
    - Return the number of characters in the decoded string by calculating the difference between `dst` and `msg`.
- **Output**: The function returns the length of the decoded string as an unsigned long integer.
- **Functions called**:
    - [`fd_hex_unhex`](#fd_hex_unhex)


---
### fd\_bundle\_client\_grpc\_rx\_end<!-- {{#callable:fd_bundle_client_grpc_rx_end}} -->
The `fd_bundle_client_grpc_rx_end` function processes the end of a gRPC response, handling errors and updating subscription states based on the request context.
- **Inputs**:
    - `app_ctx`: A pointer to the application context, specifically a `fd_bundle_tile_t` structure.
    - `request_ctx`: An unsigned long integer representing the context of the request, used to determine the type of request that was made.
    - `resp`: A pointer to a `fd_grpc_resp_hdrs_t` structure containing the response headers from the gRPC call.
- **Control Flow**:
    - Check if the HTTP status in the response is not 200; if so, log a warning and call [`fd_bundle_client_request_failed`](#fd_bundle_client_request_failed) to handle the failure, then return.
    - Unescape the gRPC message in the response and update its length; if the length is zero, set the message to 'unknown error' and its length to 13.
    - Use a switch statement on `request_ctx` to determine the type of request and update the corresponding subscription states and call [`fd_bundle_tile_backoff`](#fd_bundle_tile_backoff) to handle backoff logic.
    - Check if the gRPC status in the response is not OK; if so, log a warning, call [`fd_bundle_client_request_failed`](#fd_bundle_client_request_failed), and reset the auther if the status indicates an authentication issue, then return.
- **Output**: The function does not return a value; it performs operations on the application context and logs warnings or errors as needed.
- **Functions called**:
    - [`fd_bundle_client_request_failed`](#fd_bundle_client_request_failed)
    - [`fd_url_unescape`](#fd_url_unescape)
    - [`fd_bundle_tile_backoff`](#fd_bundle_tile_backoff)
    - [`fd_bundle_auther_reset`](fd_bundle_auth.c.driver.md#fd_bundle_auther_reset)


---
### fd\_bundle\_client\_grpc\_ping\_ack<!-- {{#callable:fd_bundle_client_grpc_ping_ack}} -->
The `fd_bundle_client_grpc_ping_ack` function updates the last received ping timestamp and increments the ping acknowledgment count for a gRPC client context.
- **Inputs**:
    - `app_ctx`: A pointer to the application context, specifically a `fd_bundle_tile_t` structure, which holds the state and metrics for the gRPC client.
- **Control Flow**:
    - Cast the `app_ctx` to a `fd_bundle_tile_t` pointer named `ctx`.
    - Update `ctx->last_ping_rx_ts` with the current tick count using `fd_tickcount()`.
    - Increment the `ctx->metrics.ping_ack_cnt` to reflect a received ping acknowledgment.
- **Output**: This function does not return any value; it updates the state of the `fd_bundle_tile_t` context passed to it.


---
### fd\_bundle\_client\_status<!-- {{#callable:fd_bundle_client_status}} -->
The `fd_bundle_client_status` function checks the status of a bundle client connection and returns whether it is disconnected, connecting, or connected.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_bundle_tile_t` structure representing the context of the bundle client.
- **Control Flow**:
    - Check if the TCP socket is connected and if the gRPC client is initialized; if not, return DISCONNECTED.
    - Retrieve the HTTP/2 connection from the gRPC client and check if it is valid; if not, return DISCONNECTED.
    - Check if the connection flags indicate a dead connection or a GOAWAY signal; if so, return DISCONNECTED.
    - Check if the connection is in an initial or waiting state; if so, return CONNECTING.
    - Check if the authentication state is not done; if so, return CONNECTING.
    - Check if builder info is available and subscriptions are live; if not, return CONNECTING.
    - Calculate the ping timeout and check if the last ping received timestamp exceeds this timeout; if so, return DISCONNECTED.
    - If all checks pass, return CONNECTED indicating the connection is alive and well.
- **Output**: An integer representing the connection status: DISCONNECTED, CONNECTING, or CONNECTED.


