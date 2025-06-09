# Purpose
This C source code file is part of a library that provides functionality for integrating QUIC (Quick UDP Internet Connections) with TLS (Transport Layer Security) in a network communication context. The file defines a set of functions and data structures that facilitate the management of TLS sessions within a QUIC protocol implementation. The primary focus of the code is to handle the lifecycle of TLS sessions, including the initialization, processing, and cleanup of handshake data, as well as the management of encryption keys and transport parameters. The code includes functions for sending and receiving messages, managing encryption secrets, and handling random number generation, which are essential for secure communication.

The file is structured around several key components, including the `fd_quic_tls` and `fd_quic_tls_hs` structures, which represent the state of a TLS session and its associated handshake, respectively. The code provides a set of callback functions that are invoked during various stages of the TLS handshake process, such as when new encryption keys are available or when transport parameters need to be exchanged. Additionally, the file includes functions for creating and deleting TLS session instances, processing handshake messages, and managing handshake data buffers. The code is designed to be integrated into a larger QUIC implementation, providing the necessary hooks and interfaces for secure communication over UDP.
# Imports and Dependencies

---
- `fd_quic_tls.h`
- `../../../ballet/ed25519/fd_x25519.h`
- `../../../ballet/x509/fd_x509_mock.h`
- `errno.h`
- `stdlib.h`
- `string.h`
- `sys/uio.h`


# Global Variables

---
### fd\_quic\_tls\_rand
- **Type**: `function pointer`
- **Description**: `fd_quic_tls_rand` is a function pointer used as a random number generator (RNG) callback for the `fd_tls` library. It is implemented using the `getrandom()` syscall, which is noted to be inefficient. The function takes a context pointer, a buffer, and a buffer size as arguments, and fills the buffer with random data.
- **Use**: This function is used to provide random data to the `fd_tls` library, which is essential for cryptographic operations.


# Functions

---
### fd\_quic\_tls\_new<!-- {{#callable:fd_quic_tls_new}} -->
The `fd_quic_tls_new` function initializes a new QUIC TLS context with specified configuration and callbacks, ensuring all necessary components are valid and properly set up.
- **Inputs**:
    - `self`: A pointer to an `fd_quic_tls_t` structure that will be initialized.
    - `cfg`: A pointer to an `fd_quic_tls_cfg_t` structure containing configuration settings and callback functions for the QUIC TLS context.
- **Control Flow**:
    - Check if `self` is NULL and log a warning if so, returning NULL.
    - Check if `cfg` is NULL and log a warning if so, returning NULL.
    - Check if any of the required callbacks in `cfg` are missing, log a warning if so, and return NULL.
    - Assign the callback functions from `cfg` to the `self` structure.
    - Call [`fd_quic_tls_init`](#fd_quic_tls_init) to initialize the embedded TLS instance within `self` using the signer and certificate public key from `cfg`.
    - Return the initialized `self` structure.
- **Output**: Returns a pointer to the initialized `fd_quic_tls_t` structure, or NULL if initialization fails due to invalid inputs or missing callbacks.
- **Functions called**:
    - [`fd_quic_tls_init`](#fd_quic_tls_init)


---
### fd\_quic\_tls\_init<!-- {{#callable:fd_quic_tls_init}} -->
The `fd_quic_tls_init` function initializes a QUIC TLS context with specific cryptographic parameters and settings.
- **Inputs**:
    - `tls`: A pointer to an `fd_tls_t` structure that will be initialized.
    - `signer`: An `fd_tls_sign_t` type representing the signing function to be used.
    - `cert_public_key`: A constant array of 32 unsigned characters representing the certificate's public key.
- **Control Flow**:
    - The function begins by creating a new TLS context using `fd_tls_new` and assigns it to the `tls` pointer.
    - It initializes the `tls` structure with QUIC-specific settings, including setting the `quic` flag, random function, signing function, and various callback functions for secrets, message sending, and transport parameters.
    - The function generates an X25519 key pair, storing the private key in `tls->kex_private_key` and the public key in `tls->kex_public_key`.
    - It copies the provided `cert_public_key` into the `tls->cert_public_key` field.
    - An X.509 certificate is generated using `fd_x509_mock_cert`, and its size is set in `tls->cert_x509_sz`.
    - The ALPN protocol ID is set to "solana-tpu" with a length prefix, and its size is stored in `tls->alpn_sz`.
- **Output**: The function does not return a value; it initializes the `tls` structure in place.


---
### fd\_quic\_tls\_delete<!-- {{#callable:fd_quic_tls_delete}} -->
The `fd_quic_tls_delete` function checks if the provided `fd_quic_tls_t` pointer is non-null and returns it, otherwise logs a warning and returns null.
- **Inputs**:
    - `self`: A pointer to an `fd_quic_tls_t` structure that is intended to be deleted.
- **Control Flow**:
    - Check if the `self` pointer is null using `FD_UNLIKELY` macro.
    - If `self` is null, log a warning message 'NULL self' and return null.
    - If `self` is not null, return the `self` pointer.
- **Output**: Returns the `self` pointer if it is non-null, otherwise returns null.


---
### fd\_quic\_tls\_hs\_new<!-- {{#callable:fd_quic_tls_hs_new}} -->
The `fd_quic_tls_hs_new` function initializes a new QUIC TLS handshake structure, setting up necessary parameters and state for either a server or client handshake.
- **Inputs**:
    - `self`: A pointer to an `fd_quic_tls_hs_t` structure that will be initialized.
    - `quic_tls`: A pointer to an `fd_quic_tls_t` structure representing the QUIC TLS context.
    - `context`: A void pointer to user-defined context data associated with the handshake.
    - `is_server`: An integer flag indicating whether the handshake is for a server (non-zero) or a client (zero).
    - `self_transport_params`: A pointer to a constant `fd_quic_transport_params_t` structure containing the transport parameters for the local endpoint.
    - `now`: An unsigned long representing the current time, used to set the birthtime of the handshake.
- **Control Flow**:
    - The function begins by clearing the memory of the `self` structure using `fd_memset` to ensure all fields are initialized to zero.
    - It sets the `quic_tls`, `is_server`, and `context` fields of the `self` structure to the provided arguments.
    - The function initializes the handshake data free list, setting up indices for managing handshake data buffers.
    - It initializes pending data indices to indicate no data is pending and sets the head and tail of the used handshake data buffer to zero.
    - The handshake data offsets are reset to zero using `fd_memset`.
    - The local transport parameters are copied from `self_transport_params` to the `self` structure.
    - If `is_server` is true, it initializes server-specific TLS state; otherwise, it initializes client-specific TLS state and attempts a client handshake, setting an alert if the handshake fails.
    - The `birthtime` of the handshake is set to the current time (`now`).
    - Finally, the function returns the initialized `self` structure.
- **Output**: A pointer to the initialized `fd_quic_tls_hs_t` structure.


---
### fd\_quic\_tls\_hs\_delete<!-- {{#callable:fd_quic_tls_hs_delete}} -->
The `fd_quic_tls_hs_delete` function deletes a QUIC TLS handshake state by freeing resources associated with either a server or client handshake state.
- **Inputs**:
    - `self`: A pointer to an `fd_quic_tls_hs_t` structure representing the QUIC TLS handshake state to be deleted.
- **Control Flow**:
    - Check if the `self` pointer is NULL; if so, return immediately without doing anything.
    - Determine if the handshake state is for a server or a client by checking the `is_server` flag in the `self` structure.
    - If `is_server` is true, call `fd_tls_estate_srv_delete` to delete the server handshake state.
    - If `is_server` is false, call `fd_tls_estate_cli_delete` to delete the client handshake state.
- **Output**: The function does not return any value; it performs cleanup operations on the provided handshake state.


---
### fd\_quic\_tls\_process<!-- {{#callable:fd_quic_tls_process}} -->
The `fd_quic_tls_process` function processes QUIC TLS handshake messages and updates the handshake state accordingly.
- **Inputs**:
    - `self`: A pointer to an `fd_quic_tls_hs_t` structure representing the current TLS handshake state.
- **Control Flow**:
    - Check if the handshake state is `FD_TLS_HS_FAIL` and return `FD_QUIC_FAILED` if true.
    - Check if the handshake state is `FD_TLS_HS_CONNECTED` and return `FD_QUIC_SUCCESS` if true.
    - Enter a loop to process fully received handshake messages.
    - Calculate available data and check if there is enough data to read a message size; break if not.
    - Read the message size from the buffer and check if the full message is available; break if not.
    - Call `fd_tls_handshake` to process the message and handle errors or deadlock prevention by returning `FD_QUIC_FAILED`.
    - Update the offset in the buffer by the number of bytes processed.
    - After processing messages, check the handshake state and return `FD_QUIC_SUCCESS` if connected, `FD_QUIC_FAILED` if failed, or `FD_QUIC_SUCCESS` if not yet complete.
- **Output**: Returns an integer indicating the result of the handshake processing: `FD_QUIC_SUCCESS` if successful or not yet complete, and `FD_QUIC_FAILED` if there was a failure.


---
### fd\_quic\_tls\_sendmsg<!-- {{#callable:fd_quic_tls_sendmsg}} -->
The `fd_quic_tls_sendmsg` function manages the sending of handshake data in a QUIC TLS context by allocating buffer space, copying data, and updating metadata for transmission.
- **Inputs**:
    - `handshake`: A pointer to the handshake state object, which is cast to `fd_quic_tls_hs_t`.
    - `data`: A pointer to the data to be sent.
    - `data_sz`: The size of the data to be sent, in bytes.
    - `enc_level`: The encryption level at which the data should be sent.
    - `flush`: An unused parameter in this function, typically used to indicate whether to flush the data immediately.
- **Control Flow**:
    - Check if the data size exceeds the buffer size; if so, return 0 indicating failure.
    - Cast the handshake pointer to `fd_quic_tls_hs_t` to access the handshake state.
    - Check for a free index in the handshake data structure; if none is available, return 0 indicating failure.
    - Calculate the aligned size of the data and determine if there is enough contiguous space in the buffer to store it.
    - If the buffer wraps around, check if the space is available; otherwise, check the front of the buffer for space.
    - If space is available, allocate it and update the buffer pointers and free list.
    - Copy the data into the buffer and update the metadata in the handshake data structure.
    - Adjust the offset for the encryption level to prepare for more data.
    - Add the handshake data to the pending list for the specified encryption level.
    - Return 1 to indicate success.
- **Output**: Returns 1 on success, indicating that the data was successfully added to the handshake buffer, or 0 on failure, indicating that there was not enough space or no free structures available.


---
### fd\_quic\_tls\_secrets<!-- {{#callable:fd_quic_tls_secrets}} -->
The `fd_quic_tls_secrets` function is responsible for handling new encryption keys by copying them into a secret structure and invoking a callback with this information.
- **Inputs**:
    - `handshake`: A pointer to the handshake structure, which is cast to `fd_quic_tls_hs_t`.
    - `recv_secret`: A pointer to the received secret key data, expected to be 32 bytes long.
    - `send_secret`: A pointer to the send secret key data, expected to be 32 bytes long.
    - `enc_level`: An unsigned integer representing the encryption level.
- **Control Flow**:
    - Cast the `handshake` pointer to a `fd_quic_tls_hs_t` type.
    - Initialize a `fd_quic_tls_secret_t` structure with the provided `enc_level`.
    - Copy 32 bytes from `recv_secret` into the `read_secret` field of the `secret` structure.
    - Copy 32 bytes from `send_secret` into the `write_secret` field of the `secret` structure.
    - Invoke the `secret_cb` callback function from the `quic_tls` field of the `handshake` structure, passing the `handshake`, `context`, and `secret` as arguments.
- **Output**: The function does not return a value; it performs its operations through side effects, specifically by invoking a callback with the new secret information.


---
### fd\_quic\_tls\_get\_hs\_data<!-- {{#callable:fd_quic_tls_get_hs_data}} -->
The function `fd_quic_tls_get_hs_data` retrieves the pending handshake data for a specified encryption level from a QUIC TLS handshake structure.
- **Inputs**:
    - `self`: A pointer to an `fd_quic_tls_hs_t` structure representing the QUIC TLS handshake state.
    - `enc_level`: An unsigned integer representing the encryption level for which the handshake data is requested.
- **Control Flow**:
    - Check if the `self` pointer is NULL; if so, return NULL.
    - Retrieve the index of the pending handshake data for the specified encryption level from `self->hs_data_pend_idx`.
    - Check if the index is `FD_QUIC_TLS_HS_DATA_UNUSED`; if so, return NULL.
    - Return a pointer to the handshake data at the retrieved index in `self->hs_data`.
- **Output**: A pointer to an `fd_quic_tls_hs_data_t` structure containing the pending handshake data for the specified encryption level, or NULL if no data is pending or if `self` is NULL.


---
### fd\_quic\_tls\_get\_next\_hs\_data<!-- {{#callable:fd_quic_tls_get_next_hs_data}} -->
The function `fd_quic_tls_get_next_hs_data` retrieves the next handshake data structure from a linked list within a QUIC TLS handshake context.
- **Inputs**:
    - `self`: A pointer to an `fd_quic_tls_hs_t` structure representing the current QUIC TLS handshake context.
    - `hs`: A pointer to an `fd_quic_tls_hs_data_t` structure representing the current handshake data node from which the next node is to be retrieved.
- **Control Flow**:
    - Retrieve the index of the next handshake data node from the `next_idx` field of the current `hs` structure.
    - Check if the retrieved index is equal to the maximum value of an unsigned short (indicating no next node), and if so, return `NULL`.
    - Otherwise, return a pointer to the next handshake data node by adding the index to the base address of the `hs_data` array in the `self` structure.
- **Output**: A pointer to the next `fd_quic_tls_hs_data_t` structure in the linked list, or `NULL` if there is no next node.


---
### fd\_quic\_tls\_pop\_hs\_data<!-- {{#callable:fd_quic_tls_pop_hs_data}} -->
The `fd_quic_tls_pop_hs_data` function removes and processes pending handshake data for a specified encryption level in a QUIC TLS handshake context.
- **Inputs**:
    - `self`: A pointer to an `fd_quic_tls_hs_t` structure representing the QUIC TLS handshake context.
    - `enc_level`: An unsigned integer representing the encryption level for which handshake data is to be processed.
- **Control Flow**:
    - Retrieve the index of the pending handshake data for the specified encryption level from `self->hs_data_pend_idx`.
    - If the index is `FD_QUIC_TLS_HS_DATA_UNUSED`, return immediately as there is no data to process.
    - Retrieve the handshake data structure using the index.
    - Calculate the new tail position by adding `free_data_sz` to the current tail.
    - Check if the new tail exceeds the head, which would indicate a logic error, and log an error if so.
    - Adjust the head and tail pointers to maintain buffer invariants, wrapping around if necessary.
    - Update the head and tail pointers in the `self` structure.
    - Update the pending index for the encryption level to the next index in the list.
    - If the current index was the last in the list, update the end index to `FD_QUIC_TLS_HS_DATA_UNUSED`.
- **Output**: This function does not return a value; it modifies the state of the `fd_quic_tls_hs_t` structure to reflect the removal of processed handshake data.


---
### fd\_quic\_tls\_rand<!-- {{#callable:fd_quic_tls_rand}} -->
The `fd_quic_tls_rand` function generates cryptographically secure random data and stores it in a provided buffer.
- **Inputs**:
    - `ctx`: A context pointer, which is not used in this function.
    - `buf`: A pointer to the buffer where the random data will be stored.
    - `bufsz`: The size of the buffer, indicating how many bytes of random data to generate.
- **Control Flow**:
    - The function begins by explicitly ignoring the `ctx` parameter, as it is not used.
    - It calls the `fd_rng_secure` function to fill the `buf` with `bufsz` bytes of secure random data.
    - The `FD_TEST` macro is used to ensure that `fd_rng_secure` successfully generates the random data.
- **Output**: The function returns the pointer to the buffer `buf` containing the generated random data.


---
### fd\_quic\_tls\_tp\_self<!-- {{#callable:fd_quic_tls_tp_self}} -->
The `fd_quic_tls_tp_self` function encodes the QUIC transport parameters of the local endpoint into a buffer for transmission.
- **Inputs**:
    - `handshake`: A pointer to the handshake structure (`fd_quic_tls_hs_t`) containing the local QUIC transport parameters.
    - `quic_tp`: A pointer to the buffer where the encoded QUIC transport parameters will be stored.
    - `quic_tp_bufsz`: The size of the buffer `quic_tp` in bytes.
- **Control Flow**:
    - Cast the `handshake` pointer to a `fd_quic_tls_hs_t` type to access the local transport parameters.
    - Call `fd_quic_encode_transport_params` to encode the local transport parameters into the `quic_tp` buffer, passing the buffer size and a pointer to the local transport parameters.
    - Check if the encoding failed by comparing the result to `FD_QUIC_ENCODE_FAIL`.
    - If encoding failed, log a warning and return 0.
    - If encoding succeeded, return the size of the encoded data.
- **Output**: The function returns the size of the encoded transport parameters on success, or 0 if encoding fails.


---
### fd\_quic\_tls\_tp\_peer<!-- {{#callable:fd_quic_tls_tp_peer}} -->
The `fd_quic_tls_tp_peer` function is a callback that forwards the peer's QUIC transport parameters to a higher-level callback function in the QUIC TLS context.
- **Inputs**:
    - `handshake`: A pointer to the handshake context, which is cast to `fd_quic_tls_hs_t`.
    - `quic_tp`: A pointer to the peer's QUIC transport parameters.
    - `quic_tp_sz`: The size of the QUIC transport parameters.
- **Control Flow**:
    - Cast the `handshake` pointer to `fd_quic_tls_hs_t` to access the handshake state.
    - Retrieve the `fd_quic_tls_t` instance from the handshake state.
    - Invoke the `peer_params_cb` callback function from the `fd_quic_tls_t` instance, passing the context, transport parameters, and their size.
- **Output**: This function does not return a value; it performs a callback operation.


# Function Declarations (Public API)

---
### fd\_quic\_tls\_sendmsg<!-- {{#callable_declaration:fd_quic_tls_sendmsg}} -->
Sends a CRYPTO frame to the peer in a QUIC connection.
- **Description**: This function is used to send a CRYPTO frame to a peer during a QUIC connection handshake. It should be called when there is handshake data to be sent at a specific encryption level. The function requires a valid handshake context and data to be sent. It ensures that the data fits within the available buffer space and manages the internal state of the handshake data buffer. If the data size exceeds the buffer capacity or if there are no free structures available, the function will fail and return 0.
- **Inputs**:
    - `handshake`: A pointer to the handshake context, which must not be null. The caller retains ownership.
    - `record`: A pointer to the data to be sent, which must not be null. The caller retains ownership.
    - `record_sz`: The size of the data to be sent, in bytes. Must be less than or equal to the buffer size defined by FD_QUIC_TLS_HS_DATA_SZ.
    - `encryption_level`: The encryption level at which the data should be sent. It is expected to be a valid encryption level as per the QUIC protocol.
    - `flush`: An unused parameter in the current implementation, can be any integer value.
- **Output**: Returns 1 on success, indicating the data was successfully queued for sending. Returns 0 on failure, indicating insufficient buffer space or no free structures available.
- **See also**: [`fd_quic_tls_sendmsg`](#fd_quic_tls_sendmsg)  (Implementation)


---
### fd\_quic\_tls\_secrets<!-- {{#callable_declaration:fd_quic_tls_secrets}} -->
Notify when new encryption keys are available.
- **Description**: This function is used to inform the system that new encryption keys have been generated and are ready for use. It should be called whenever new handshake or application-level secrets are available. The function expects valid pointers to the handshake context and the new secrets, and it will trigger a callback to handle these secrets. It is crucial to ensure that the provided pointers are valid and point to the correct data, as the function does not perform any validation on the input data.
- **Inputs**:
    - `handshake`: A pointer to the handshake context. Must not be null and should be a valid context object.
    - `recv_secret`: A pointer to the buffer containing the new receive secret. Must not be null and should point to a 32-byte buffer.
    - `send_secret`: A pointer to the buffer containing the new send secret. Must not be null and should point to a 32-byte buffer.
    - `enc_level`: An unsigned integer representing the encryption level. It should be a valid encryption level as expected by the system.
- **Output**: None
- **See also**: [`fd_quic_tls_secrets`](#fd_quic_tls_secrets)  (Implementation)


---
### fd\_quic\_tls\_rand<!-- {{#callable_declaration:fd_quic_tls_rand}} -->
Generates cryptographically secure random data.
- **Description**: This function fills a buffer with cryptographically secure random data, which can be used in security-sensitive applications such as cryptographic key generation. It is intended to be used as a random number generator (RNG) callback in the context of TLS operations. The function requires a valid buffer and size to operate correctly. It does not depend on the context parameter, which is ignored.
- **Inputs**:
    - `ctx`: A context pointer that is ignored by this function. It can be NULL or any value, as it has no effect on the function's behavior.
    - `buf`: A pointer to a buffer where the random data will be stored. Must not be NULL, and the caller retains ownership of the buffer.
    - `bufsz`: The size of the buffer in bytes. Must be a positive number, indicating the amount of random data to generate.
- **Output**: Returns the pointer to the buffer filled with random data.
- **See also**: [`fd_quic_tls_rand`](#fd_quic_tls_rand)  (Implementation)


---
### fd\_quic\_tls\_tp\_self<!-- {{#callable_declaration:fd_quic_tls_tp_self}} -->
Retrieves and encodes QUIC transport parameters for the local endpoint.
- **Description**: This function is used to obtain the QUIC transport parameters for the local endpoint and encode them into a provided buffer. It should be called when the transport parameters need to be communicated to a peer during the QUIC handshake process. The function requires a valid handshake context and a sufficiently large buffer to store the encoded parameters. If encoding fails, the function returns zero, indicating that the buffer was not large enough or another error occurred.
- **Inputs**:
    - `handshake`: A pointer to the handshake context, which must not be null. The caller retains ownership of this pointer.
    - `quic_tp`: A pointer to a buffer where the encoded transport parameters will be stored. This buffer must be large enough to hold the encoded data.
    - `quic_tp_bufsz`: The size of the buffer pointed to by quic_tp. It must be large enough to store the encoded transport parameters; otherwise, the function will return zero.
- **Output**: The function returns the size of the encoded transport parameters on success, or zero if encoding fails.
- **See also**: [`fd_quic_tls_tp_self`](#fd_quic_tls_tp_self)  (Implementation)


---
### fd\_quic\_tls\_tp\_peer<!-- {{#callable_declaration:fd_quic_tls_tp_peer}} -->
Notifies the QUIC layer of the peer's transport parameters.
- **Description**: This function is used to inform the QUIC layer about the transport parameters received from a peer during a QUIC handshake. It should be called when the peer's transport parameters are available, typically as part of the TLS handshake process. The function expects a valid handshake context and transport parameters, and it will trigger a callback to handle these parameters. This function does not perform any validation on the transport parameters; it assumes they are correctly formatted and relevant to the current handshake context.
- **Inputs**:
    - `handshake`: A pointer to the handshake context, which must be a valid and initialized fd_quic_tls_hs_t structure. The caller retains ownership and must ensure it is not null.
    - `quic_tp`: A pointer to a buffer containing the peer's QUIC transport parameters. This buffer must be valid and non-null, and the data should be correctly formatted as expected by the QUIC protocol.
    - `quic_tp_sz`: The size of the transport parameters buffer in bytes. It must accurately reflect the size of the data in quic_tp.
- **Output**: None
- **See also**: [`fd_quic_tls_tp_peer`](#fd_quic_tls_tp_peer)  (Implementation)


---
### fd\_quic\_tls\_init<!-- {{#callable_declaration:fd_quic_tls_init}} -->
Initializes a QUIC TLS context for secure communication.
- **Description**: This function sets up a QUIC TLS context by initializing the provided `fd_tls_t` structure with necessary cryptographic parameters and callbacks for secure communication. It should be called as part of the QUIC TLS setup process, typically after allocating the `fd_tls_t` structure. The function configures the TLS context with a random number generator, signing function, and transport parameter functions, and it generates necessary cryptographic keys and certificates. It is essential to ensure that the `tls` parameter is a valid pointer to an allocated `fd_tls_t` structure before calling this function.
- **Inputs**:
    - `tls`: A pointer to an `fd_tls_t` structure that will be initialized. Must not be null and should point to a valid, allocated `fd_tls_t` structure.
    - `signer`: A signing function of type `fd_tls_sign_t` used for cryptographic signing operations. The caller is responsible for ensuring this function is valid.
    - `cert_public_key`: A constant array of 32 unsigned characters representing the public key for the certificate. Must not be null and must be exactly 32 bytes in size.
- **Output**: None
- **See also**: [`fd_quic_tls_init`](#fd_quic_tls_init)  (Implementation)


