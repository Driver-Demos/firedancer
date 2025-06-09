# Purpose
This C header file defines structures and functions for managing the state of TLS (Transport Layer Security) handshakes, specifically for both server and client contexts. The file provides a compact and efficient way to handle TLS handshake states, optimizing memory usage to prevent potential memory exhaustion attacks, particularly on the server side. The key components include `fd_tls_estate_base_t`, which serves as a shared base structure for both server (`fd_tls_estate_srv_t`) and client (`fd_tls_estate_cli_t`) handshake states, and `fd_tls_transcript_t`, which maintains a running hash of all handshake messages to ensure message integrity and authenticity.

The file is part of a larger library, as indicated by the inclusion of other headers, and is intended to be used in environments where TLS handshakes are performed, such as secure network communications. It defines public APIs for initializing and deleting handshake state objects for both server and client roles, with a focus on minimizing memory footprint and ensuring robust handling of handshake processes. The server-side implementation is particularly optimized to handle high volumes of incoming connections without significant memory overhead, while the client-side implementation, though more complex, is designed to handle the handshake process without being susceptible to packet floods. The use of unions and type punning allows for flexible handling of handshake states, making the code versatile for different TLS scenarios.
# Imports and Dependencies

---
- `../fd_waltz_base.h`
- `../../ballet/sha256/fd_sha256.h`


# Data Structures

---
### fd\_tls\_estate\_base
- **Type**: `struct`
- **Members**:
    - `state`: Represents the current state of the TLS handshake.
    - `server`: Indicates if the entity is a server (1) or a client (0).
    - `reason`: Stores the reason code for the current state, using predefined constants.
    - `client_random`: Holds a 32-byte random value used in the SSL key logging process.
- **Description**: The `fd_tls_estate_base` structure serves as a foundational component for both server and client TLS handshake state objects, encapsulating essential state information and configuration flags. It includes a state indicator, a flag to differentiate between server and client roles, a reason code for the current state, and a client random value necessary for SSL key logging. This structure is designed to be shared between server and client TLS estate objects, providing a common header for managing TLS handshake processes.


---
### fd\_tls\_estate\_base\_t
- **Type**: `struct`
- **Members**:
    - `state`: Represents the current state of the TLS handshake.
    - `server`: Indicates if the entity is a server (1) or a client (0).
    - `reason`: Stores the reason code for the current state, using predefined constants.
    - `client_random`: Holds a 32-byte random value used in the SSLKEYLOGFILE process.
- **Description**: The `fd_tls_estate_base_t` structure serves as a shared header for both server and client TLS estate objects, encapsulating common state information necessary for managing TLS handshakes. It includes fields to track the current state of the handshake, whether the entity is acting as a server or client, a reason code for the current state, and a client random value for SSL key logging purposes. This structure is foundational for the TLS handshake process, providing essential data that both server and client implementations rely on.


---
### fd\_tls\_transcript
- **Type**: `struct`
- **Members**:
    - `buf`: An array of 64 unsigned characters used to store a pending SHA block.
    - `sha`: An array of 8 unsigned integers representing the current internal SHA state.
    - `len`: An unsigned integer indicating the number of bytes compressed into the SHA state plus the number of bytes pending in the buffer.
- **Description**: The `fd_tls_transcript` structure is used to maintain a running hash over all handshake messages in a TLS session. It consists of a buffer for pending SHA blocks, the current SHA state, and a length field that tracks the total number of bytes processed. This structure is crucial for ensuring the integrity and authenticity of the handshake process by maintaining a hash of all messages exchanged during the handshake.


---
### fd\_tls\_transcript\_t
- **Type**: `struct`
- **Members**:
    - `buf`: Pending SHA block of 64 bytes.
    - `sha`: Current internal SHA state represented as an array of 8 unsigned integers.
    - `len`: Number of bytes compressed into SHA state plus bytes pending in buf.
- **Description**: The `fd_tls_transcript_t` structure is designed to maintain a running hash over all handshake messages in a TLS session. It consists of a buffer for pending SHA blocks, the current SHA state, and a length field that tracks the total number of bytes processed. This structure is crucial for ensuring the integrity and authenticity of the handshake process by maintaining a hash that reflects the sequence of messages exchanged between the client and server.


---
### fd\_tls\_estate\_srv\_t
- **Type**: `struct`
- **Members**:
    - `base`: Inherits the shared header of the TLS estate objects, indicating whether the instance is a server or client.
    - `server_cert_rpk`: Indicates if the server certificate is a raw public key (1) or X.509 (0).
    - `client_cert`: Indicates if client authentication is required (1) or not (0).
    - `client_cert_rpk`: Indicates if the client certificate is a raw public key (1) or X.509 (0).
    - `hello_retry`: Flag indicating if a HelloRetryRequest was sent.
    - `transcript`: Maintains the running hash of all handshake messages exchanged.
    - `client_hs_secret`: Stores the client's handshake secret used for deriving the 'client Finished' verify data.
    - `client_pubkey`: Holds the client's public key.
- **Description**: The `fd_tls_estate_srv_t` structure represents the state of a TLS server during a handshake, optimized for minimal memory usage to handle high volumes of incoming connections securely. It includes a base structure for shared TLS estate attributes, flags for certificate types and client authentication, a transcript for hashing handshake messages, and secrets for verifying client messages. This design allows for efficient memory management and robust handling of potential denial-of-service attacks by limiting memory usage per connection.


---
### fd\_tls\_estate\_cli\_t
- **Type**: `struct`
- **Members**:
    - `base`: Inherits common TLS handshake state from fd_tls_estate_base_t.
    - `server_pubkey`: Stores the server's public key as a 32-byte array.
    - `server_hs_secret`: Holds the server handshake secret as a 32-byte array.
    - `client_hs_secret`: Contains the client handshake secret as a 32-byte array.
    - `master_secret`: Stores the master secret as a 32-byte array.
    - `client_cert`: Indicates if client authentication is used (0=anonymous, 1=client auth).
    - `server_cert_rpk`: Indicates if the server certificate is a raw public key (1) or X.509 (0).
    - `client_cert_nox509`: Indicates if the client certificate is not X.509 (1).
    - `client_cert_rpk`: Indicates if the client certificate is a raw public key (1) or X.509 (0).
    - `server_pubkey_pin`: Indicates if the server certificate must match the server public key (1).
    - `transcript`: Maintains the SHA-256 hash of the handshake messages.
- **Description**: The fd_tls_estate_cli_t structure represents the state of a TLS client during a handshake, managing various cryptographic secrets and keys necessary for secure communication. It includes fields for storing the server's public key, handshake secrets for both client and server, and the master secret, all of which are crucial for establishing a secure TLS connection. The structure also contains flags to indicate the type of certificates used and whether client authentication is required. Additionally, it maintains a transcript of the handshake messages using SHA-256, ensuring the integrity and authenticity of the communication process.


---
### fd\_tls\_estate\_t
- **Type**: `union`
- **Members**:
    - `base`: A shared header structure for both server and client TLS handshake states.
    - `srv`: A structure containing compressed TLS server handshake state.
    - `cli`: A structure containing TLS client handshake state.
- **Description**: The `fd_tls_estate_t` is a union that encapsulates different states of a TLS handshake, either for a server or a client. It includes a base structure, `fd_tls_estate_base_t`, which is common to both server and client, and two specific structures, `fd_tls_estate_srv_t` and `fd_tls_estate_cli_t`, which handle the server and client handshake states respectively. This design allows for efficient memory usage and type punning between different handshake states, optimizing for scenarios like server-side memory constraints and client-side handshake complexity.


# Functions

---
### fd\_tls\_transcript\_store<!-- {{#callable:fd_tls_transcript_store}} -->
The `fd_tls_transcript_store` function stores the current state of a SHA-256 hash into a TLS transcript structure.
- **Inputs**:
    - `script`: A pointer to an `fd_tls_transcript_t` structure where the SHA-256 state will be stored.
    - `sha`: A pointer to a constant `fd_sha256_t` structure containing the current SHA-256 hash state to be stored.
- **Control Flow**:
    - Copy 64 bytes from the SHA-256 buffer (`sha->buf`) to the transcript buffer (`script->buf`).
    - Copy 32 bytes from the SHA-256 state (`sha->state`) to the transcript SHA state (`script->sha`).
    - Calculate the length of the data processed by the SHA-256 hash in bytes by dividing the bit count (`sha->bit_cnt`) by 8 and store it in `script->len`.
- **Output**: The function does not return a value; it modifies the `fd_tls_transcript_t` structure pointed to by `script` to store the current SHA-256 state.


---
### fd\_tls\_transcript\_load<!-- {{#callable:fd_tls_transcript_load}} -->
The `fd_tls_transcript_load` function initializes a SHA-256 hash state from a TLS transcript structure.
- **Inputs**:
    - `script`: A pointer to a constant `fd_tls_transcript_t` structure containing the current state of the TLS transcript, including a buffer of pending SHA data, the internal SHA state, and the length of data processed.
    - `sha`: A pointer to an `fd_sha256_t` structure where the SHA-256 hash state will be loaded, including the buffer, state, bit count, and buffer usage.
- **Control Flow**:
    - Copy 64 bytes from the `buf` field of `script` to the `buf` field of `sha` using `memcpy`.
    - Copy 32 bytes from the `sha` field of `script` to the `state` field of `sha` using `memcpy`.
    - Calculate the total number of bits processed by multiplying `script->len` by 8 and store it in `sha->bit_cnt`.
    - Calculate the number of bytes used in the buffer by taking `script->len` modulo 64 and store it in `sha->buf_used`.
- **Output**: The function does not return a value; it modifies the `sha` structure in place to reflect the state of the `script`.


---
### fd\_tls\_estate\_srv\_delete<!-- {{#callable:fd_tls_estate_srv_delete}} -->
The `fd_tls_estate_srv_delete` function is a no-op that returns the input `fd_tls_estate_srv_t` pointer cast to a `void *`.
- **Inputs**:
    - `estate`: A pointer to an `fd_tls_estate_srv_t` structure, representing the TLS server handshake state to be deleted.
- **Control Flow**:
    - The function takes a single argument, `estate`, which is a pointer to an `fd_tls_estate_srv_t` structure.
    - It returns the `estate` pointer cast to a `void *`, without performing any operations on it.
- **Output**: A `void *` that is the input `estate` pointer cast to a `void *`.


---
### fd\_tls\_estate\_cli\_delete<!-- {{#callable:fd_tls_estate_cli_delete}} -->
The `fd_tls_estate_cli_delete` function returns a pointer to the given TLS client estate object without performing any deletion operations.
- **Inputs**:
    - `estate`: A pointer to an `fd_tls_estate_cli_t` structure representing the TLS client estate to be 'deleted'.
- **Control Flow**:
    - The function takes a single argument, `estate`, which is a pointer to an `fd_tls_estate_cli_t` structure.
    - It casts the `estate` pointer to a `void *` type and returns it immediately without modifying the estate or performing any cleanup operations.
- **Output**: A `void *` pointer to the `fd_tls_estate_cli_t` structure passed as the argument.


