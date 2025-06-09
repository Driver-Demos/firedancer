# Purpose
This C header file, `fd_bundle_tile_private.h`, is designed to define and manage the internal structures and functions necessary for a client that interacts with a bundle server using gRPC over HTTP/2. The file provides a comprehensive set of data structures and function prototypes that facilitate the client's operations, including authentication, subscription to data streams, and error handling. The primary structures defined include `fd_bundle_out_ctx_t`, `fd_bundle_metrics_t`, and `fd_bundle_tile_t`, each serving specific roles such as managing output contexts, tracking metrics, and maintaining the state of the client, respectively. The file also includes conditional support for OpenSSL, indicating that secure communication is a consideration, and it integrates with various components like key switching, key guarding, and network database resolution.

The file is not intended to be a standalone executable but rather a private header file that supports a larger system by providing internal APIs and data structures. It defines several function prototypes, such as [`fd_bundle_client_step`](#fd_bundle_client_step), [`fd_bundle_tile_backoff`](#fd_bundle_tile_backoff), and [`fd_bundle_client_status`](#fd_bundle_client_status), which are crucial for driving the client logic, handling errors, and monitoring the client's status. These functions enable the client to maintain a persistent connection with the server, manage subscriptions, and handle gRPC messages. The header file is part of a broader system, likely involving multiple components that work together to ensure reliable and secure communication with a bundle server, and it is designed to be included in other C source files that implement the actual logic and operations of the client.
# Imports and Dependencies

---
- `fd_bundle_auth.h`
- `../stem/fd_stem.h`
- `../keyguard/fd_keyswitch.h`
- `../keyguard/fd_keyguard_client.h`
- `../../waltz/grpc/fd_grpc_client.h`
- `../../waltz/resolv/fd_netdb.h`
- `../../util/alloc/fd_alloc.h`
- `openssl/ssl.h`


# Data Structures

---
### fd\_bundle\_out\_ctx
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing an index or identifier.
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `chunk0`: An unsigned long integer representing the initial chunk or offset.
    - `wmark`: An unsigned long integer representing a watermark or threshold value.
    - `chunk`: An unsigned long integer representing the current chunk or offset.
- **Description**: The `fd_bundle_out_ctx` structure is designed to manage and track the state of a memory workspace in a bundle processing context. It includes an index for identification, a pointer to a memory workspace, and several unsigned long integers to manage memory chunks and watermarks, which are likely used to control memory allocation and processing thresholds within the workspace.


---
### fd\_bundle\_out\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing an index or identifier.
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `chunk0`: An unsigned long integer representing the initial chunk or offset.
    - `wmark`: An unsigned long integer representing a watermark or threshold value.
    - `chunk`: An unsigned long integer representing the current chunk or offset.
- **Description**: The `fd_bundle_out_ctx_t` structure is designed to manage output context for a bundle, providing essential information such as memory workspace, indexing, and chunk management. It includes fields for tracking the current and initial chunks, as well as a watermark for managing data flow or processing thresholds. This structure is likely used in conjunction with other components to handle data output efficiently in a larger system.


---
### fd\_bundle\_metrics
- **Type**: `struct`
- **Members**:
    - `txn_received_cnt`: Counts the number of transactions received.
    - `bundle_received_cnt`: Counts the number of bundles received.
    - `packet_received_cnt`: Counts the number of packets received.
    - `shredstream_heartbeat_cnt`: Counts the number of shredstream heartbeats received.
    - `ping_ack_cnt`: Counts the number of ping acknowledgments received.
    - `decode_fail_cnt`: Counts the number of decode failures encountered.
    - `transport_fail_cnt`: Counts the number of transport failures encountered.
    - `missing_builder_info_fail_cnt`: Counts the number of failures due to missing builder information.
- **Description**: The `fd_bundle_metrics` structure is designed to track various metrics related to the operation of a bundle processing system. It includes counters for received transactions, bundles, packets, and shredstream heartbeats, as well as ping acknowledgments. Additionally, it tracks failure counts for decoding, transport, and missing builder information, providing a comprehensive overview of the system's performance and potential issues.


---
### fd\_bundle\_metrics\_t
- **Type**: `struct`
- **Members**:
    - `txn_received_cnt`: Counts the number of transactions received.
    - `bundle_received_cnt`: Counts the number of bundles received.
    - `packet_received_cnt`: Counts the number of packets received.
    - `shredstream_heartbeat_cnt`: Counts the number of shredstream heartbeats received.
    - `ping_ack_cnt`: Counts the number of ping acknowledgments received.
    - `decode_fail_cnt`: Counts the number of decode failures encountered.
    - `transport_fail_cnt`: Counts the number of transport failures encountered.
    - `missing_builder_info_fail_cnt`: Counts the number of failures due to missing builder information.
- **Description**: The `fd_bundle_metrics_t` structure is designed to hold various private metric counters related to the operation of a bundle system. These metrics include counts of received transactions, bundles, packets, and heartbeats, as well as counts of ping acknowledgments. Additionally, it tracks the number of failures encountered in decoding, transport, and missing builder information. This data structure is used to periodically publish metrics to `fd_metrics`, providing insights into the performance and issues within the system.


---
### fd\_bundle\_tile
- **Type**: `struct`
- **Members**:
    - `keyswitch`: Pointer to a key switch structure for managing key transitions.
    - `identity_switched`: Flag indicating if the identity has been switched.
    - `keyguard_client`: Array of keyguard client structures for key management.
    - `is_ssl`: Flag indicating if SSL is enabled.
    - `keylog_fd`: File descriptor for key logging.
    - `ssl_ctx`: Pointer to the SSL context structure (OpenSSL specific).
    - `ssl`: Pointer to the SSL structure (OpenSSL specific).
    - `ssl_alloc`: Pointer to the SSL allocator structure (OpenSSL specific).
    - `skip_cert_verify`: Flag indicating if certificate verification should be skipped (OpenSSL specific).
    - `server_fqdn`: Fully qualified domain name of the server.
    - `server_fqdn_len`: Length of the server's fully qualified domain name.
    - `server_sni`: Server Name Indication for SSL/TLS.
    - `server_sni_len`: Length of the server's SNI.
    - `server_tcp_port`: TCP port number of the server.
    - `netdb_fds`: Array of network database file descriptors for DNS resolution.
    - `server_ip4_addr`: IPv4 address of the server from the last DNS lookup.
    - `tcp_sock`: TCP socket file descriptor.
    - `so_rcvbuf`: Size of the TCP socket receive buffer.
    - `tcp_sock_connected`: Flag indicating if the TCP socket is connected.
    - `defer_reset`: Flag indicating if reset should be deferred.
    - `last_ping_tx_ts`: Timestamp of the last transmitted ping.
    - `last_ping_rx_ts`: Timestamp of the last received ping.
    - `ping_randomize`: Randomized value for ping operations.
    - `ping_threshold_ticks`: Threshold for keepalive timeout in ticks.
    - `grpc_client_mem`: Memory allocated for the gRPC client.
    - `grpc_buf_max`: Maximum buffer size for gRPC operations.
    - `grpc_client`: Pointer to the gRPC client structure.
    - `grpc_metrics`: Array of gRPC client metrics.
    - `map_seed`: Seed value for mapping operations.
    - `auther`: Bundle authenticator structure.
    - `builder_pubkey`: Public key of the bundle block builder.
    - `builder_commission`: Commission percentage for the block builder.
    - `builder_info_avail`: Flag indicating if block builder info is available.
    - `builder_info_live`: Flag indicating if block builder info is recent.
    - `builder_info_wait`: Flag indicating if a request for builder info is in-flight.
    - `packet_subscription_live`: Flag indicating if packet subscription is live.
    - `packet_subscription_wait`: Flag indicating if a packet subscription request is in-flight.
    - `bundle_subscription_live`: Flag indicating if bundle subscription is live.
    - `bundle_subscription_wait`: Flag indicating if a bundle subscription request is in-flight.
    - `bundle_seq`: Sequence number of the bundle.
    - `bundle_txn_cnt`: Transaction count within the bundle.
    - `rng`: Random number generator structure for error backoff.
    - `backoff_iter`: Iteration count for error backoff.
    - `backoff_until`: Timestamp until which backoff is active.
    - `backoff_reset`: Timestamp for resetting backoff.
    - `stem`: Pointer to the stem context structure.
    - `verify_out`: Output context for verification operations.
    - `plugin_out`: Output context for plugin operations.
    - `metrics`: Metrics structure for application performance.
    - `bundle_status_recent`: Most recent status of the bundle's 'check engine light'.
    - `bundle_status_plugin`: Last status update from the plugin.
- **Description**: The `fd_bundle_tile` structure is a comprehensive data structure used to manage and maintain the state of a bundle client in a networked environment. It includes various components such as key management, SSL/TLS configuration, server connection details, gRPC client management, and error handling mechanisms. The structure is designed to handle complex operations like DNS resolution, TCP socket management, and keepalive mechanisms using HTTP/2 PINGs. Additionally, it supports bundle authentication, block builder information, and subscription management for packets and bundles. The structure also incorporates error backoff strategies and maintains application metrics to monitor performance and status updates.


---
### fd\_bundle\_tile\_t
- **Type**: `struct`
- **Members**:
    - `keyswitch`: Pointer to a key switch object for managing key transitions.
    - `identity_switched`: Flag indicating if the identity has been switched.
    - `keyguard_client`: Array containing a keyguard client for managing key security.
    - `is_ssl`: Flag indicating if SSL is being used.
    - `keylog_fd`: File descriptor for key logging.
    - `ssl_ctx`: Pointer to the SSL context, used if OpenSSL is enabled.
    - `ssl`: Pointer to the SSL session, used if OpenSSL is enabled.
    - `ssl_alloc`: Pointer to the SSL allocator, used if OpenSSL is enabled.
    - `skip_cert_verify`: Flag indicating if certificate verification should be skipped.
    - `server_fqdn`: Fully qualified domain name of the server.
    - `server_fqdn_len`: Length of the server's fully qualified domain name.
    - `server_sni`: Server Name Indication for SSL/TLS.
    - `server_sni_len`: Length of the server's SNI.
    - `server_tcp_port`: TCP port number of the server.
    - `netdb_fds`: Array containing network database file descriptors.
    - `server_ip4_addr`: IPv4 address of the server from the last DNS lookup.
    - `tcp_sock`: TCP socket file descriptor.
    - `so_rcvbuf`: Size of the TCP receive buffer.
    - `tcp_sock_connected`: Flag indicating if the TCP socket is connected.
    - `defer_reset`: Flag indicating if a reset should be deferred.
    - `last_ping_tx_ts`: Timestamp of the last transmitted PING.
    - `last_ping_rx_ts`: Timestamp of the last received PING.
    - `ping_randomize`: Randomized value for PING operations.
    - `ping_threshold_ticks`: Threshold for PING keepalive timeout in ticks.
    - `grpc_client_mem`: Memory allocated for the gRPC client.
    - `grpc_buf_max`: Maximum buffer size for gRPC operations.
    - `grpc_client`: Pointer to the gRPC client object.
    - `grpc_metrics`: Array containing metrics for the gRPC client.
    - `map_seed`: Seed value for mapping operations.
    - `auther`: Bundle authenticator for verifying bundle authenticity.
    - `builder_pubkey`: Public key of the block builder.
    - `builder_commission`: Commission percentage of the block builder.
    - `builder_info_avail`: Flag indicating if block builder info is available.
    - `builder_info_live`: Flag indicating if block builder info is recent enough.
    - `builder_info_wait`: Flag indicating if a request for block builder info is in-flight.
    - `packet_subscription_live`: Flag indicating if a packet subscription is live.
    - `packet_subscription_wait`: Flag indicating if a packet subscription request is in-flight.
    - `bundle_subscription_live`: Flag indicating if a bundle subscription is live.
    - `bundle_subscription_wait`: Flag indicating if a bundle subscription request is in-flight.
    - `bundle_seq`: Sequence number of the current bundle.
    - `bundle_txn_cnt`: Transaction count within the current bundle.
    - `rng`: Random number generator for error backoff.
    - `backoff_iter`: Iteration count for error backoff.
    - `backoff_until`: Timestamp until which backoff is active.
    - `backoff_reset`: Timestamp for resetting backoff.
    - `stem`: Pointer to the stem context for publishing.
    - `verify_out`: Output context for verification operations.
    - `plugin_out`: Output context for plugin operations.
    - `metrics`: Metrics object for tracking various counters.
    - `bundle_status_recent`: Most recent status of the bundle's 'check engine light'.
    - `bundle_status_plugin`: Last status update from the plugin.
- **Description**: The `fd_bundle_tile_t` structure is a comprehensive context object used in the management of a bundle tile, which is part of a larger system involving key management, SSL/TLS connections, gRPC communications, and bundle processing. It contains various fields for handling key switching, SSL configurations, server connection details, gRPC client management, bundle authentication, and error handling. The structure is designed to facilitate the progression of the tile by maintaining state information, managing subscriptions, and tracking metrics, ensuring robust and efficient operation within the system.


# Functions

---
### fd\_bundle\_tile\_should\_stall<!-- {{#callable:fd_bundle_tile_should_stall}} -->
The function `fd_bundle_tile_should_stall` checks if the current tick count is less than the backoff threshold, indicating whether the process should stall due to an error.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_bundle_tile_t` structure, which contains the state and configuration for the tile, including the backoff threshold.
    - `tickcount`: A long integer representing the current tick count, used to determine if the process should stall.
- **Control Flow**:
    - The function compares the `tickcount` with the `backoff_until` value from the `ctx` structure.
    - If `tickcount` is less than `ctx->backoff_until`, the function returns 1, indicating that the process should stall.
    - If `tickcount` is greater than or equal to `ctx->backoff_until`, the function returns 0, indicating that the process should not stall.
- **Output**: The function returns an integer: 1 if the process should stall, and 0 if it should not.


# Function Declarations (Public API)

---
### fd\_bundle\_client\_step<!-- {{#callable_declaration:fd_bundle_client_step}} -->
Drives the client logic for connecting and interacting with a bundle server.
- **Description**: This function should be called periodically to manage the connection and communication with a bundle server. It handles the connection setup, authentication, and subscription to necessary data streams. The function ensures that the client attempts to reconnect if the connection is lost and manages the state transitions required for maintaining a live connection. It also updates the provided charge_busy flag to indicate whether the function performed any significant work during its execution. This function is essential for maintaining the operational state of the client and should be integrated into the main loop of the application.
- **Inputs**:
    - `ctx`: A pointer to an fd_bundle_tile_t structure that contains the state and configuration for the client. This parameter must not be null, and the structure should be properly initialized before calling this function.
    - `charge_busy`: A pointer to an integer that will be set to 1 if the function performs significant work, such as establishing a connection or processing data. This parameter must not be null.
- **Output**: None
- **See also**: [`fd_bundle_client_step`](fd_bundle_client.c.driver.md#fd_bundle_client_step)  (Implementation)


---
### fd\_bundle\_tile\_backoff<!-- {{#callable_declaration:fd_bundle_tile_backoff}} -->
Stalls forward progress for a randomized amount of time after an error occurs.
- **Description**: This function is used to introduce a delay in processing when an error is detected, to prevent rapid repeated errors from overwhelming the system. It should be called whenever an error condition is encountered. The function uses a randomized backoff strategy to determine the duration of the stall, which helps in spreading out retry attempts over time. This is particularly useful in networked or distributed systems where errors might be transient and retrying immediately could lead to repeated failures.
- **Inputs**:
    - `ctx`: A pointer to an fd_bundle_tile_t structure, which must be valid and properly initialized. The function updates the backoff-related fields within this structure.
    - `tickcount`: A long integer representing the current tick count. It is used to calculate the backoff duration and must be a valid tick count value.
- **Output**: None
- **See also**: [`fd_bundle_tile_backoff`](fd_bundle_client.c.driver.md#fd_bundle_tile_backoff)  (Implementation)


---
### fd\_bundle\_client\_grpc\_rx\_msg<!-- {{#callable_declaration:fd_bundle_client_grpc_rx_msg}} -->
Handles incoming gRPC messages for a bundle client.
- **Description**: This function processes incoming gRPC messages by interpreting the message type specified by `request_ctx` and handling the message accordingly. It is typically called by the gRPC client when a message is received. The function expects a valid application context, a protobuf message, and its size. It handles different types of requests, such as authentication challenges, token generation, and bundle subscriptions, by invoking appropriate handlers. If an unexpected message type is received, an error is logged. This function should be used in environments where gRPC communication is established, and the application context is properly initialized.
- **Inputs**:
    - `app_ctx`: A pointer to the application context (`fd_bundle_tile_t *`). Must not be null and should be properly initialized before calling this function.
    - `protobuf`: A pointer to the protobuf message data. Must not be null and should point to a valid protobuf message.
    - `protobuf_sz`: The size of the protobuf message in bytes. Must accurately reflect the size of the data pointed to by `protobuf`.
    - `request_ctx`: An identifier for the type of gRPC request. Must be one of the predefined request types (e.g., `FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge`). If an unexpected value is provided, an error is logged.
- **Output**: None
- **See also**: [`fd_bundle_client_grpc_rx_msg`](fd_bundle_client.c.driver.md#fd_bundle_client_grpc_rx_msg)  (Implementation)


---
### fd\_bundle\_client\_status<!-- {{#callable_declaration:fd_bundle_client_status}} -->
Check the connection status of the client.
- **Description**: Use this function to determine the current connection status of a client represented by the `fd_bundle_tile_t` context. It checks various conditions such as TCP socket connectivity, gRPC client status, authentication state, and subscription status to return a status code indicating whether the client is disconnected, connecting, or fully connected. This function is useful for monitoring the client's connection health and should be called whenever you need to verify the client's operational status.
- **Inputs**:
    - `ctx`: A pointer to a constant `fd_bundle_tile_t` structure representing the client context. This parameter must not be null, and the structure should be properly initialized before calling this function. Invalid or uninitialized contexts may lead to incorrect status reporting.
- **Output**: Returns an integer status code: `DISCONNECTED` if the client is not connected, `CONNECTING` if the client is in the process of connecting, or `CONNECTED` if the client is fully connected and operational.
- **See also**: [`fd_bundle_client_status`](fd_bundle_client.c.driver.md#fd_bundle_client_status)  (Implementation)


