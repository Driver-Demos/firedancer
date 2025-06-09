# Purpose
The provided C header file, `fd_tls.h`, defines a specialized library for implementing a subset of the TLS v1.3 handshake protocol, specifically tailored for securing peer-to-peer QUIC connections within the Solana network protocol. This library is not a general-purpose TLS library but focuses on the necessary components to facilitate secure communication in this specific context. The file outlines the use of Ed25519 for peer authentication, X25519 for key exchange, and supports the TLS_AES_128_GCM_SHA256 cipher suite for data confidentiality and integrity. It includes references to several IETF RFCs that define the protocols and cryptographic methods used.

The file defines several callback types and structures that facilitate the TLS handshake process, including functions for handling encryption secrets, sending messages, and managing QUIC transport parameters. It also provides a public API for managing TLS handshakes, including server and client-side functions, and utility functions for handling cryptographic operations like HKDF expansion. The header defines various constants for handshake states, encryption levels, and error codes to aid in debugging and protocol management. Overall, this file serves as a critical component for implementing secure communication in a specific network protocol, providing a focused set of functionalities and interfaces for developers working within this domain.
# Imports and Dependencies

---
- `fd_tls_estate.h`


# Global Variables

---
### fd\_tls\_new
- **Type**: `function pointer`
- **Description**: `fd_tls_new` is a function pointer that returns a void pointer and takes a single void pointer as an argument. It is part of the public API for managing TLS (Transport Layer Security) contexts in the provided library.
- **Use**: This function is used to initialize a new TLS context, allocating necessary resources and setting up initial state.


---
### fd\_tls\_join
- **Type**: `fd_tls_t *`
- **Description**: The `fd_tls_join` is a function that returns a pointer to an `fd_tls_t` structure, which represents the local TLS configuration used for managing TLS handshakes and encryption in peer-to-peer QUIC connections. This structure contains various fields and function pointers necessary for handling TLS operations, such as random number generation, message sending, and key signing.
- **Use**: This function is used to join or initialize a TLS context from a given memory location, allowing the caller to interact with the TLS configuration and perform secure communications.


---
### fd\_tls\_leave
- **Type**: `void *`
- **Description**: The `fd_tls_leave` function is a global function that takes a pointer to an `fd_tls_t` structure as its argument and returns a `void *`. This function is likely used to perform cleanup or disassociation tasks related to the `fd_tls_t` structure, which represents the local TLS configuration shared across multiple TLS handshakes.
- **Use**: This function is used to leave or disassociate from a TLS context represented by an `fd_tls_t` structure.


---
### fd\_tls\_delete
- **Type**: `function pointer`
- **Description**: `fd_tls_delete` is a function pointer that takes a single `void *` argument and returns a `void *`. It is part of the public API for managing the lifecycle of a TLS context in the fd_tls library.
- **Use**: This function is used to delete or clean up a TLS context, freeing any resources associated with it.


---
### fd\_tls\_alert\_cstr
- **Type**: `function pointer to a constant character string`
- **Description**: The `fd_tls_alert_cstr` is a function that takes an unsigned integer `alert` as an argument and returns a constant character string. This function is likely used to convert a TLS alert code into a human-readable string representation.
- **Use**: This function is used to map TLS alert codes to their corresponding string descriptions for easier debugging and logging.


---
### fd\_tls\_reason\_cstr
- **Type**: `char const *`
- **Description**: The `fd_tls_reason_cstr` is a function that returns a constant character pointer. It is used to convert a numeric reason code into a human-readable string that describes the reason for a TLS alert or error. This function is part of the TLS implementation and helps in debugging by providing descriptive error messages.
- **Use**: This function is used to map TLS reason codes to their corresponding string descriptions for better understanding and debugging of TLS-related errors.


---
### fd\_tls\_hkdf\_expand\_label
- **Type**: `function`
- **Description**: The `fd_tls_hkdf_expand_label` function implements the HKDF-Expand-Label function as specified in TLS 1.3, using SHA-256 as the hash function. It takes a 32-byte secret, a label, and a context to derive a cryptographic key of specified size, writing the result to the output buffer.
- **Use**: This function is used to derive keys in the TLS 1.3 protocol by expanding a given secret with a label and context.


# Data Structures

---
### fd\_tls\_rand\_vt
- **Type**: `struct`
- **Members**:
    - `ctx`: An arbitrary pointer provided as a callback argument for the random function.
    - `rand_fn`: A function pointer to a secure pseudorandom value generator.
- **Description**: The `fd_tls_rand_vt` structure is designed to facilitate the generation of cryptographically secure pseudorandom values within the TLS protocol implementation. It contains a context pointer `ctx` that can be used to pass arbitrary data to the random function, and a function pointer `rand_fn` that points to the actual function responsible for generating the random values. This structure is crucial for ensuring the security of cryptographic operations by providing a reliable source of randomness.


---
### fd\_tls\_rand\_t
- **Type**: `typedef struct fd_tls_rand_vt fd_tls_rand_t;`
- **Members**:
    - `ctx`: An arbitrary pointer provided as a callback argument for the random function.
    - `rand_fn`: A function pointer to a secure pseudorandom value generator.
- **Description**: The `fd_tls_rand_t` structure is an abstraction for generating cryptographically secure pseudorandom values, used within the TLS protocol implementation. It consists of a context pointer and a function pointer, `rand_fn`, which is called to fill a buffer with random data. This structure is crucial for operations requiring randomness, such as key generation, ensuring that the random values are generated securely and efficiently without blocking.


---
### fd\_tls\_sign\_vt
- **Type**: `struct`
- **Members**:
    - `ctx`: An arbitrary pointer provided as a callback argument.
    - `sign_fn`: A function pointer to a signing function for TLS 1.3 certificate verify payloads.
- **Description**: The `fd_tls_sign_vt` structure is designed to facilitate the signing of TLS 1.3 certificate verify payloads using the Ed25519 signature algorithm. It contains a context pointer `ctx` that is passed to the signing function, and a function pointer `sign_fn` that performs the actual signing operation. This structure is part of a larger TLS implementation tailored for securing peer-to-peer QUIC connections, specifically within the Solana network protocol.


---
### fd\_tls\_sign\_t
- **Type**: `struct`
- **Members**:
    - `ctx`: An arbitrary pointer provided as a callback argument.
    - `sign_fn`: A function pointer to the signing function for TLS 1.3 certificate verify payloads.
- **Description**: The `fd_tls_sign_t` structure is a virtual table (vt) for handling the signing of TLS 1.3 certificate verify payloads using the Ed25519 algorithm. It contains a context pointer `ctx` and a function pointer `sign_fn` that is used to perform the actual signing operation. This structure is part of the TLS implementation for securing peer-to-peer QUIC connections, specifically for the Solana network protocol, and ensures that the server can prove possession of the private key during the handshake process.


---
### fd\_tls
- **Type**: `struct`
- **Members**:
    - `rand`: A structure for generating cryptographically secure random values.
    - `secrets_fn`: A callback function for handling new encryption secrets.
    - `sendmsg_fn`: A callback function for sending TLS messages to peers.
    - `quic_tp_self_fn`: A callback function for providing QUIC transport parameters to peers.
    - `quic_tp_peer_fn`: A callback function for receiving QUIC transport parameters from peers.
    - `kex_private_key`: A 32-byte X25519 private key used for key exchange.
    - `kex_public_key`: A 32-byte X25519 public key derived from the private key.
    - `sign`: A structure for signing TLS handshake transcripts with an Ed25519 key pair.
    - `cert_public_key`: A 32-byte Ed25519 public key identifying the server.
    - `cert_x509`: An optional X.509 certificate to present to peers.
    - `cert_x509_sz`: The size of the X.509 certificate.
    - `alpn`: A 32-byte buffer for the ALPN protocol identifier.
    - `alpn_sz`: The size of the ALPN protocol identifier.
    - `quic`: A flag indicating if QUIC-specific callbacks should be used.
    - `_flags_reserved`: Reserved flags for future use.
- **Description**: The `fd_tls` structure is a configuration and state holder for managing TLS 1.3 handshakes, specifically tailored for securing peer-to-peer QUIC connections in the Solana network protocol. It includes fields for cryptographic operations such as key exchange and signing, as well as callback functions for handling encryption secrets, message transmission, and QUIC transport parameters. The structure also manages server identity through Ed25519 keys and optional X.509 certificates, and supports ALPN protocol negotiation. The `fd_tls` structure is designed to be shared across multiple TLS handshakes, ensuring secure and efficient communication.


---
### fd\_tls\_t
- **Type**: `struct`
- **Members**:
    - `rand`: A structure for handling secure pseudorandom value generation.
    - `secrets_fn`: A callback function for handling new encryption secrets.
    - `sendmsg_fn`: A callback function for sending TLS messages to peers.
    - `quic_tp_self_fn`: A callback function for providing QUIC transport parameters to peers.
    - `quic_tp_peer_fn`: A callback function for handling peer's QUIC transport parameters.
    - `kex_private_key`: A 32-byte buffer for the X25519 private key used in key exchange.
    - `kex_public_key`: A 32-byte buffer for the X25519 public key derived from the private key.
    - `sign`: A structure for handling Ed25519 signing operations.
    - `cert_public_key`: A 32-byte buffer for the Ed25519 public key identifying the server.
    - `cert_x509`: A buffer for storing the X.509 certificate to present to peers.
    - `cert_x509_sz`: The size of the X.509 certificate stored in cert_x509.
    - `alpn`: A buffer for storing the ALPN protocol identifier.
    - `alpn_sz`: The size of the ALPN protocol identifier stored in alpn.
    - `quic`: A flag indicating if QUIC-specific callbacks are enabled.
    - `_flags_reserved`: Reserved flags for future use.
- **Description**: The `fd_tls_t` structure is a comprehensive configuration object for managing TLS 1.3 handshakes, specifically tailored for securing peer-to-peer QUIC connections in the Solana network protocol. It includes fields for handling secure random number generation, encryption secret management, message transmission, and QUIC transport parameters. The structure also manages key exchange using X25519, signing operations with Ed25519, and optional X.509 certificate handling. Additionally, it supports ALPN protocol negotiation and includes flags for enabling QUIC-specific functionality. This structure is designed to be shared across multiple TLS handshakes, ensuring consistent security configurations.


# Functions

---
### fd\_tls\_rand<!-- {{#callable:fd_tls_rand}} -->
The `fd_tls_rand` function generates cryptographically secure random data by invoking a user-defined random function.
- **Inputs**:
    - `rand`: A pointer to an `fd_tls_rand_t` structure containing the context and the random function to be used.
    - `buf`: A pointer to a buffer where the random data will be stored.
    - `bufsz`: The size of the buffer in bytes, indicating how much random data to generate.
- **Control Flow**:
    - The function calls the `rand_fn` function pointer from the `fd_tls_rand_t` structure, passing the context, buffer, and buffer size as arguments.
    - The `rand_fn` is expected to fill the buffer with cryptographically secure random data.
- **Output**: Returns a pointer to the buffer filled with random data on success, or NULL on failure.


---
### fd\_tls\_sign<!-- {{#callable:fd_tls_sign}} -->
The `fd_tls_sign` function invokes a callback to sign a TLS 1.3 CertificateVerify payload using Ed25519.
- **Inputs**:
    - `sign`: A pointer to an `fd_tls_sign_t` structure containing the context and the signing function to be used.
    - `sig`: A 64-byte buffer where the Ed25519 signature of the payload will be stored.
    - `payload`: A 130-byte buffer containing the TLS 1.3 CertificateVerify payload to be signed.
- **Control Flow**:
    - The function calls the `sign_fn` callback function from the `fd_tls_sign_t` structure.
    - It passes the context, the signature buffer, and the payload buffer to the `sign_fn` function.
- **Output**: The function does not return a value; it outputs the signature directly into the provided `sig` buffer.


---
### fd\_tls\_handshake<!-- {{#callable:fd_tls_handshake}} -->
The `fd_tls_handshake` function performs a TLS handshake by delegating to either a server or client handshake function based on the handshake state.
- **Inputs**:
    - `tls`: A pointer to a constant `fd_tls_t` structure containing the local TLS configuration.
    - `handshake`: A pointer to an `fd_tls_estate_t` structure representing the current handshake state.
    - `record`: A pointer to a constant buffer containing the TLS message to be processed.
    - `record_sz`: An unsigned long integer representing the size of the TLS message in bytes.
    - `encryption_level`: An unsigned integer indicating the encryption level to be used for the handshake.
- **Control Flow**:
    - Check if the handshake is in server mode by evaluating `handshake->base.server`.
    - If in server mode, call [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake) with the server-specific handshake state and return its result.
    - If not in server mode, call [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake) with the client-specific handshake state and return its result.
- **Output**: Returns a long integer which is the number of bytes read on success, or a negated TLS alert code on failure.
- **Functions called**:
    - [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake)
    - [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake)


# Function Declarations (Public API)

---
### fd\_tls\_align<!-- {{#callable_declaration:fd_tls_align}} -->
Returns the alignment requirement of the fd_tls_t type.
- **Description**: Use this function to determine the alignment requirement for the fd_tls_t type, which is necessary when allocating memory for structures or buffers that will store fd_tls_t instances. This function is useful in ensuring that memory allocations are correctly aligned to meet the requirements of the underlying hardware and data types, which can prevent undefined behavior and improve performance.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the alignment requirement of the fd_tls_t type.
- **See also**: [`fd_tls_align`](fd_tls.c.driver.md#fd_tls_align)  (Implementation)


---
### fd\_tls\_footprint<!-- {{#callable_declaration:fd_tls_footprint}} -->
Returns the memory footprint of the fd_tls_t structure.
- **Description**: Use this function to determine the size in bytes of the fd_tls_t structure, which is essential for memory allocation and management when working with TLS configurations. This function is useful when you need to allocate memory for an fd_tls_t instance or when you want to understand the memory requirements of the TLS configuration structure. It is a constant function and does not require any initialization or setup before being called.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the size in bytes of the fd_tls_t structure.
- **See also**: [`fd_tls_footprint`](fd_tls.c.driver.md#fd_tls_footprint)  (Implementation)


---
### fd\_tls\_new<!-- {{#callable_declaration:fd_tls_new}} -->
Allocate and initialize memory for a new TLS context.
- **Description**: This function prepares a memory region to be used as a new TLS context by zeroing it out. It should be called when a new TLS context is needed, and the memory region must be properly aligned and of sufficient size. The function will return a pointer to the initialized memory if successful, or NULL if the memory is NULL or not aligned correctly. Ensure that the memory region is aligned according to the requirements of the TLS context before calling this function.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be used for the TLS context. The memory must be aligned according to the alignment requirements of the TLS context, and it must not be NULL. If the memory is NULL or not aligned, the function will return NULL.
- **Output**: Returns a pointer to the initialized memory region if successful, or NULL if the input memory is NULL or not properly aligned.
- **See also**: [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new)  (Implementation)


---
### fd\_tls\_join<!-- {{#callable_declaration:fd_tls_join}} -->
Casts a memory pointer to a TLS configuration structure pointer.
- **Description**: Use this function to interpret a raw memory pointer as a pointer to a `fd_tls_t` structure, which contains the local TLS configuration. This function is typically used after allocating or obtaining a memory block intended to hold a TLS configuration. Ensure that the memory block is appropriately aligned and sized to hold a `fd_tls_t` structure before calling this function. This function does not perform any validation or initialization of the memory content.
- **Inputs**:
    - `mem`: A pointer to a memory block that is expected to be a valid `fd_tls_t` structure. The caller must ensure that the memory is correctly aligned and sized. Passing a null pointer or an incorrectly sized block may lead to undefined behavior.
- **Output**: Returns a pointer to `fd_tls_t`, allowing access to the TLS configuration stored in the provided memory block.
- **See also**: [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join)  (Implementation)


---
### fd\_tls\_leave<!-- {{#callable_declaration:fd_tls_leave}} -->
Returns a pointer to the given TLS server configuration.
- **Description**: Use this function to retrieve a pointer to the TLS server configuration structure when you are done using it. This function is typically called when you want to leave or detach from a TLS server context. It is important to ensure that the `server` parameter is a valid pointer to a `fd_tls_t` structure before calling this function.
- **Inputs**:
    - `server`: A pointer to a `fd_tls_t` structure representing the TLS server configuration. Must not be null and should be a valid TLS server context.
- **Output**: Returns a pointer to the `fd_tls_t` structure provided as input.
- **See also**: [`fd_tls_leave`](fd_tls.c.driver.md#fd_tls_leave)  (Implementation)


---
### fd\_tls\_delete<!-- {{#callable_declaration:fd_tls_delete}} -->
Deletes a TLS object and returns the memory pointer.
- **Description**: Use this function to delete a TLS object and retrieve the memory pointer that was used to store it. This is typically called when the TLS object is no longer needed, allowing the caller to manage or free the memory as appropriate. Ensure that the memory pointer provided is valid and was previously allocated for a TLS object.
- **Inputs**:
    - `mem`: A pointer to the memory allocated for a TLS object. The pointer must be valid and should have been previously allocated for this purpose. Invalid or null pointers may lead to undefined behavior.
- **Output**: Returns the same memory pointer that was provided as input, allowing the caller to manage or free the memory.
- **See also**: [`fd_tls_delete`](fd_tls.c.driver.md#fd_tls_delete)  (Implementation)


---
### fd\_tls\_alert\_cstr<!-- {{#callable_declaration:fd_tls_alert_cstr}} -->
Returns a string representation of a TLS alert code.
- **Description**: Use this function to obtain a human-readable string that describes a given TLS alert code. This is useful for logging or debugging purposes when handling TLS alerts. The function maps known alert codes to their corresponding descriptions. If an unknown alert code is provided, it returns "unknown alert" and logs a warning. This function is safe to call with any unsigned integer, but only defined alert codes will return meaningful descriptions.
- **Inputs**:
    - `alert`: An unsigned integer representing a TLS alert code. Valid values are predefined constants representing specific TLS alerts. If an unknown or undefined alert code is provided, the function returns "unknown alert".
- **Output**: A constant string describing the TLS alert corresponding to the provided code, or "unknown alert" if the code is not recognized.
- **See also**: [`fd_tls_alert_cstr`](fd_tls.c.driver.md#fd_tls_alert_cstr)  (Implementation)


---
### fd\_tls\_reason\_cstr<!-- {{#callable_declaration:fd_tls_reason_cstr}} -->
Returns a string description for a given TLS error reason code.
- **Description**: Use this function to obtain a human-readable description of a TLS error reason code, which can be useful for debugging and logging purposes. The function maps known reason codes to specific error messages. If an unknown reason code is provided, it returns a generic 'unknown reason' message. This function is particularly useful in contexts where understanding the specific cause of a TLS handshake failure or other TLS-related error is necessary.
- **Inputs**:
    - `reason`: An unsigned integer representing a TLS error reason code. Valid values are predefined constants representing specific TLS error conditions. If an invalid or unknown reason code is provided, the function returns a generic error message.
- **Output**: A constant character pointer to a string describing the error associated with the given reason code.
- **See also**: [`fd_tls_reason_cstr`](fd_tls.c.driver.md#fd_tls_reason_cstr)  (Implementation)


---
### fd\_tls\_server\_handshake<!-- {{#callable_declaration:fd_tls_server_handshake}} -->
Processes a TLS message from the client during a server-side handshake.
- **Description**: This function is used to handle incoming TLS messages from a client during the server-side handshake process. It should be called with a complete TLS record, as the function does not handle message defragmentation. The function processes the message synchronously, and it is important to ensure that the handshake state is correctly managed before calling this function. The function returns the number of bytes read on success, or a negated TLS alert code on failure, indicating an error in processing the message.
- **Inputs**:
    - `server`: A pointer to a constant fd_tls_t structure containing the server's TLS configuration. The caller retains ownership and it must not be null.
    - `handshake`: A pointer to an fd_tls_estate_srv_t structure representing the current handshake state. The caller retains ownership and it must not be null.
    - `msg`: A pointer to the buffer containing the TLS message to be processed. The buffer must contain a complete TLS record and must not be null.
    - `msg_sz`: The size of the message buffer in bytes. It must accurately reflect the size of the complete TLS record.
    - `encryption_level`: An unsigned integer indicating the encryption level to be used for processing the message. Valid values are defined by the FD_TLS_LEVEL_* constants.
- **Output**: Returns the number of bytes read on success, or a negated TLS alert code on failure.
- **See also**: [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake)  (Implementation)


---
### fd\_tls\_client\_handshake<!-- {{#callable_declaration:fd_tls_client_handshake}} -->
Performs a TLS 1.3 client-side handshake step.
- **Description**: This function processes a TLS message as part of a client-side handshake in a TLS 1.3 protocol, specifically for securing peer-to-peer QUIC connections. It should be called with a complete TLS record and is not suitable for messages sent after the handshake is completed, such as NewSessionTicket. The function handles different handshake states and processes the message accordingly. It is important to ensure that the handshake state is valid before calling this function, as an invalid state will result in a handshake failure alert.
- **Inputs**:
    - `client`: A pointer to a constant fd_tls_t structure containing the local TLS configuration. The caller retains ownership and it must not be null.
    - `handshake`: A pointer to an fd_tls_estate_cli_t structure representing the current state of the client-side handshake. The caller retains ownership and it must not be null.
    - `record`: A pointer to the buffer containing the TLS message to be processed. The caller retains ownership and it must not be null.
    - `record_sz`: The size of the TLS message in bytes. It must accurately reflect the size of the data pointed to by record.
    - `encryption_level`: An unsigned integer indicating the encryption level of the message. It must be a valid encryption level as defined by the TLS protocol.
- **Output**: Returns the number of bytes read on success, or a negated TLS alert code on failure.
- **See also**: [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake)  (Implementation)


---
### fd\_tls\_hkdf\_expand\_label<!-- {{#callable_declaration:fd_tls_hkdf_expand_label}} -->
Implements the TLS 1.3 HKDF-Expand function with SHA-256.
- **Description**: This function is used to perform the HKDF-Expand operation as specified in TLS 1.3, using SHA-256 as the hash function. It is typically called during the key derivation process in a TLS handshake to derive new keys from a given secret. The function writes the resulting hash to the provided output buffer. It requires a 32-byte secret, a label, and an optional context. The function must be called with valid parameters, adhering to the specified constraints on sizes and nullability.
- **Inputs**:
    - `out`: A pointer to a buffer where the resulting hash will be written. Must not be null.
    - `out_sz`: The size of the output buffer. Must be between 1 and 32, inclusive.
    - `secret`: A 32-byte array containing the secret value. Must not be null.
    - `label`: A pointer to a string containing the label. Can be null if label_sz is 0.
    - `label_sz`: The size of the label string. Must be between 0 and 64, inclusive.
    - `context`: A pointer to a byte array containing the context. Can be null if context_sz is 0.
    - `context_sz`: The size of the context byte array. Must be between 0 and 64, inclusive.
- **Output**: Returns a pointer to the output buffer containing the resulting hash.
- **See also**: [`fd_tls_hkdf_expand_label`](fd_tls.c.driver.md#fd_tls_hkdf_expand_label)  (Implementation)


