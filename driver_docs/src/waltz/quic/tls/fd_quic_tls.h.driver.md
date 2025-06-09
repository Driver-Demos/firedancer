# Purpose
This C header file defines an API for managing the QUIC-TLS handshake process, which is a critical component of the QUIC protocol used for secure and efficient internet communication. The file provides a structured approach to setting up, managing, and tearing down TLS handshakes within the QUIC protocol. It includes definitions for configuration structures, callback function prototypes, and various data structures necessary for handling the handshake process. The API allows for the creation and deletion of QUIC-TLS objects and handshake objects, enabling the management of multiple concurrent handshakes and the processing of TLS handshake messages.

The file is organized around several key structures and functions. The `fd_quic_tls_cfg` structure is used to configure the QUIC-TLS environment, specifying callbacks for secret handling, handshake completion, and peer parameter management. The `fd_quic_tls` and `fd_quic_tls_hs` structures represent the main QUIC-TLS object and individual handshake sessions, respectively. Functions such as [`fd_quic_tls_new`](#fd_quic_tls_new), [`fd_quic_tls_delete`](#fd_quic_tls_delete), [`fd_quic_tls_hs_new`](#fd_quic_tls_hs_new), and [`fd_quic_tls_hs_delete`](#fd_quic_tls_hs_delete) provide mechanisms for creating and managing these objects. Additionally, the file defines constants and macros for managing handshake data, ensuring proper alignment and memory allocation. This header file is intended to be included in other C source files that require QUIC-TLS functionality, providing a public API for external use.
# Imports and Dependencies

---
- `../fd_quic_common.h`
- `../fd_quic_enum.h`
- `../../tls/fd_tls.h`
- `../templ/fd_quic_transport_params.h`


# Global Variables

---
### fd\_quic\_tls\_new
- **Type**: `function pointer`
- **Description**: The `fd_quic_tls_new` is a function that initializes a memory region to be used as an `fd_quic_tls_t` object, which is part of the QUIC-TLS API. It takes a pointer to a memory region and a configuration structure as parameters, and returns a pointer to the newly formatted `fd_quic_tls_t` object.
- **Use**: This function is used to create and initialize a QUIC-TLS object for managing TLS handshakes.


---
### fd\_quic\_tls\_delete
- **Type**: `function pointer`
- **Description**: `fd_quic_tls_delete` is a function pointer that takes a pointer to an `fd_quic_tls_t` structure as its argument and returns a void pointer. This function is responsible for unformatting a memory region used as an `fd_quic_tls_t` object, effectively deleting the QUIC-TLS object and freeing any associated resources.
- **Use**: This function is used to delete a QUIC-TLS object when it is no longer needed, ensuring proper cleanup of resources.


---
### fd\_quic\_tls\_hs\_new
- **Type**: `fd_quic_tls_hs_t *`
- **Description**: The `fd_quic_tls_hs_new` function is responsible for creating a new QUIC-TLS handshake object. It initializes a `fd_quic_tls_hs_t` structure, which is used to manage the state and data associated with a TLS handshake in a QUIC connection. This function takes several parameters, including a pointer to an existing handshake object, a QUIC-TLS object, a context pointer, a flag indicating if the handshake is for a server, transport parameters, and the current time.
- **Use**: This function is used to set up a new handshake object for managing the TLS handshake process in a QUIC connection.


---
### fd\_quic\_tls\_get\_hs\_data
- **Type**: `function pointer`
- **Description**: `fd_quic_tls_get_hs_data` is a function that retrieves the oldest queued handshake data from the queue of pending data to be sent to a peer. It returns a pointer to the `fd_quic_tls_hs_data_t` structure at the head of the queue or NULL if no data is available.
- **Use**: This function is used to access the next piece of handshake data that needs to be sent during a QUIC-TLS handshake process.


---
### fd\_quic\_tls\_get\_next\_hs\_data
- **Type**: `function pointer`
- **Description**: `fd_quic_tls_get_next_hs_data` is a function that retrieves the next unit of handshake data from a queue associated with a QUIC-TLS handshake. It takes a pointer to a `fd_quic_tls_hs_t` structure, representing the handshake state, and a pointer to a `fd_quic_tls_hs_data_t` structure, representing the current handshake data, as its parameters.
- **Use**: This function is used to iterate through the queued handshake data, returning the next available data unit or NULL if no more data is available.


# Data Structures

---
### fd\_quic\_tls\_secret
- **Type**: `struct`
- **Members**:
    - `enc_level`: Represents the encryption level used in the TLS handshake.
    - `read_secret`: An array of bytes used as the read secret for the TLS connection.
    - `write_secret`: An array of bytes used as the write secret for the TLS connection.
- **Description**: The `fd_quic_tls_secret` structure is used in the context of QUIC-TLS to manage encryption secrets for a TLS connection. It contains an encryption level identifier and two arrays of bytes, one for the read secret and one for the write secret, which are essential for securing data transmission in the TLS handshake process.


---
### fd\_quic\_tls\_cfg
- **Type**: `struct`
- **Members**:
    - `secret_cb`: A callback function for handling secrets during the TLS handshake.
    - `handshake_complete_cb`: A callback function that is called when the TLS handshake is complete.
    - `peer_params_cb`: A callback function for handling peer parameters.
    - `max_concur_handshakes`: The maximum number of concurrent handshakes that can be managed.
    - `signer`: A signing callback for TLS 1.3 CertificateVerify, which must outlive the TLS object.
    - `cert_public_key`: A pointer to the Ed25519 public key used for the certificate.
- **Description**: The `fd_quic_tls_cfg` structure is a configuration object for setting up QUIC-TLS operations. It includes callback functions for handling secrets, handshake completion, and peer parameters, as well as a limit on the number of concurrent handshakes. Additionally, it contains a signing callback for TLS 1.3 CertificateVerify and a pointer to an Ed25519 public key. This structure is essential for initializing and managing the TLS handshake process in a QUIC protocol implementation.


---
### fd\_quic\_tls\_hs\_data
- **Type**: `struct`
- **Members**:
    - `data`: A pointer to the handshake data.
    - `data_sz`: The size of the handshake data.
    - `free_data_sz`: The size of the free data, used internally.
    - `offset`: The offset within the data.
    - `enc_level`: The encryption level of the data.
    - `next_idx`: The index of the next element in a linked list, with ~0 indicating the end.
- **Description**: The `fd_quic_tls_hs_data` structure is used to manage individual units of handshake data within the QUIC-TLS handshake process. It contains a pointer to the data, its size, and metadata such as the encryption level and offset. The structure also includes internal fields for managing a linked list of handshake data, allowing for efficient organization and retrieval of data during the handshake process.


---
### fd\_quic\_tls
- **Type**: `struct`
- **Members**:
    - `secret_cb`: A callback function for handling secrets during the TLS handshake.
    - `handshake_complete_cb`: A callback function that is called when the TLS handshake is complete.
    - `peer_params_cb`: A callback function for handling peer parameters.
    - `tls`: An instance of fd_tls_t, which manages SSL-related operations.
- **Description**: The `fd_quic_tls` structure is designed to manage the TLS handshake process within a QUIC protocol implementation. It includes callback functions for handling secrets, handshake completion, and peer parameters, which are essential for the secure establishment of a connection. Additionally, it contains an `fd_tls_t` object to handle SSL-related operations, integrating the TLS layer with the QUIC transport layer to ensure secure communication.


---
### fd\_quic\_tls\_hs
- **Type**: `struct`
- **Members**:
    - `hs`: A TLS handshake handle for type punning with fd_tls_estate_{srv,cli}_t.
    - `quic_tls`: Pointer to the QUIC-TLS object managing the handshake.
    - `is_server`: Indicates if the handshake is for a server (1) or client (0).
    - `is_hs_complete`: Flag indicating if the handshake is complete.
    - `context`: User-defined context for callbacks.
    - `next`: Next index in the allocation pool/cache doubly linked list.
    - `prev`: Previous index in the cache doubly linked list.
    - `birthtime`: Timestamp of allocation for cache eviction checks.
    - `hs_data`: Array of handshake data structures to be sent to the peer.
    - `hs_data_free_idx`: Index of the head of the free list for handshake data.
    - `hs_data_pend_idx`: Indices of the head of pending handshake data for each encryption level.
    - `hs_data_pend_end_idx`: Indices of the end of pending handshake data for each encryption level.
    - `hs_data_buf`: Buffer for handshake data, allocated in chunks in a circular queue.
    - `hs_data_buf_head`: Head index of the used portion of the handshake data buffer.
    - `hs_data_buf_tail`: Tail index of the unused portion of the handshake data buffer.
    - `hs_data_offset`: Offsets for each encryption level in the handshake data buffer.
    - `rx_off`: Number of bytes processed by fd_tls in the receive buffer.
    - `rx_sz`: Number of contiguous bytes received from the peer.
    - `rx_enc_level`: Current encryption level of the receive buffer.
    - `rx_hs_buf`: Buffer for received handshake messages of one encryption level.
    - `alert`: TLS alert code.
    - `self_transport_params`: QUIC transport parameters for the local endpoint.
- **Description**: The `fd_quic_tls_hs` structure is designed to manage the state and data associated with a QUIC-TLS handshake. It includes fields for handling the handshake process, such as the TLS handshake handle, pointers to the managing QUIC-TLS object, and flags indicating the server status and handshake completion. The structure also manages user-defined context for callbacks, allocation and cache management through linked list indices, and timestamps for cache eviction. Handshake data is organized in an array and buffered in a circular queue, with indices tracking free and pending data for different encryption levels. Additionally, it includes a receive buffer for handshake messages, a TLS alert code, and transport parameters for the local endpoint.


# Function Declarations (Public API)

---
### fd\_quic\_tls\_new<!-- {{#callable_declaration:fd_quic_tls_new}} -->
Initialize a QUIC-TLS object with the specified configuration.
- **Description**: This function sets up a QUIC-TLS object using the provided configuration, which includes necessary callbacks for handling secrets, handshake completion, and peer parameters. It must be called with a valid memory region for the QUIC-TLS object and a fully populated configuration structure. The function will return NULL if any required parameter is missing or invalid, ensuring that the object is only created when all preconditions are met.
- **Inputs**:
    - `self`: A pointer to a memory region where the QUIC-TLS object will be initialized. Must not be null.
    - `cfg`: A pointer to a configuration structure containing callbacks and other settings for the QUIC-TLS object. Must not be null and must have all required callbacks set.
- **Output**: Returns a pointer to the initialized QUIC-TLS object, or NULL if initialization fails due to invalid input parameters.
- **See also**: [`fd_quic_tls_new`](fd_quic_tls.c.driver.md#fd_quic_tls_new)  (Implementation)


---
### fd\_quic\_tls\_delete<!-- {{#callable_declaration:fd_quic_tls_delete}} -->
Unformats and deletes a QUIC-TLS object.
- **Description**: Use this function to delete a QUIC-TLS object when it is no longer needed. It should be called to clean up resources associated with a QUIC-TLS object that was previously created using `fd_quic_tls_new`. This function expects a valid pointer to a `fd_quic_tls_t` object. If the provided pointer is `NULL`, the function will log a warning and return `NULL`. Otherwise, it returns the pointer to the deleted object.
- **Inputs**:
    - `self`: A pointer to the `fd_quic_tls_t` object to be deleted. Must not be `NULL`. If `NULL` is passed, a warning is logged and `NULL` is returned.
- **Output**: Returns the pointer to the deleted `fd_quic_tls_t` object, or `NULL` if the input was `NULL`.
- **See also**: [`fd_quic_tls_delete`](fd_quic_tls.c.driver.md#fd_quic_tls_delete)  (Implementation)


---
### fd\_quic\_tls\_hs\_new<!-- {{#callable_declaration:fd_quic_tls_hs_new}} -->
Initialize a new QUIC-TLS handshake object.
- **Description**: This function initializes a new QUIC-TLS handshake object, which is used to manage the TLS handshake process for a QUIC connection. It should be called when a new connection is established, either as a client or a server, to set up the necessary handshake data structures and parameters. The function requires a valid QUIC-TLS object and transport parameters, and it sets the initial state of the handshake object, including its role as a client or server. The caller must ensure that the provided pointers are valid and that the QUIC-TLS object has been properly configured before calling this function.
- **Inputs**:
    - `self`: A pointer to an fd_quic_tls_hs_t structure that will be initialized. Must not be null.
    - `quic_tls`: A pointer to an fd_quic_tls_t object that manages the TLS configuration and state. Must not be null.
    - `context`: A user-defined context pointer that will be associated with the handshake object. The caller retains ownership.
    - `is_server`: An integer indicating whether the handshake is for a server (non-zero) or a client (zero).
    - `self_transport_params`: A pointer to an fd_quic_transport_params_t structure containing the transport parameters for the connection. Must not be null.
    - `now`: An unsigned long representing the current time, used to set the birthtime of the handshake object.
- **Output**: Returns a pointer to the initialized fd_quic_tls_hs_t structure, or null if initialization fails.
- **See also**: [`fd_quic_tls_hs_new`](fd_quic_tls.c.driver.md#fd_quic_tls_hs_new)  (Implementation)


---
### fd\_quic\_tls\_hs\_delete<!-- {{#callable_declaration:fd_quic_tls_hs_delete}} -->
Deletes a QUIC-TLS handshake object.
- **Description**: Use this function to delete a QUIC-TLS handshake object when it is no longer needed. This function should be called to clean up resources associated with a handshake object, whether it represents a client or server. It is safe to pass a null pointer to this function, in which case it will perform no action. Ensure that the handshake object is not used after calling this function.
- **Inputs**:
    - `hs`: A pointer to the fd_quic_tls_hs_t object to be deleted. This pointer can be null, in which case the function does nothing. The caller retains ownership of the memory and is responsible for freeing it if necessary.
- **Output**: None
- **See also**: [`fd_quic_tls_hs_delete`](fd_quic_tls.c.driver.md#fd_quic_tls_hs_delete)  (Implementation)


---
### fd\_quic\_tls\_process<!-- {{#callable_declaration:fd_quic_tls_process}} -->
Processes available TLS handshake messages.
- **Description**: This function processes any available TLS handshake messages from previously received CRYPTO frames associated with the given handshake object. It should be called when there is a need to process incoming handshake data. The function returns success if any number of messages were processed, including when there is insufficient data to process a complete message. It returns failure if the TLS handshake has irrecoverably failed. This function must be called with a valid handshake object and is typically used in the context of managing a QUIC connection's TLS handshake.
- **Inputs**:
    - `self`: A pointer to a fd_quic_tls_hs_t structure representing the handshake state. Must not be null. The function will return an error if the handshake state indicates a failure.
- **Output**: Returns FD_QUIC_SUCCESS if messages were processed or if the handshake is not yet complete, and FD_QUIC_FAILED if the handshake has failed.
- **See also**: [`fd_quic_tls_process`](fd_quic_tls.c.driver.md#fd_quic_tls_process)  (Implementation)


---
### fd\_quic\_tls\_get\_hs\_data<!-- {{#callable_declaration:fd_quic_tls_get_hs_data}} -->
Retrieve the oldest queued handshake data for a specified encryption level.
- **Description**: Use this function to access the oldest piece of handshake data that is queued for sending to a peer at a specified encryption level. It is useful when you need to process or send pending handshake data. The function should be called with a valid handshake object and a valid encryption level. If there is no data available for the specified encryption level, the function returns NULL. The returned data is invalidated if `fd_quic_tls_pop_hs_data` or `fd_quic_tls_hs_delete` is called.
- **Inputs**:
    - `self`: A pointer to the `fd_quic_tls_hs_t` handshake object. It can be NULL, in which case the function returns NULL.
    - `enc_level`: An unsigned integer representing the encryption level for which the handshake data is requested. It must be a valid encryption level index.
- **Output**: Returns a pointer to the `fd_quic_tls_hs_data_t` structure containing the handshake data if available, or NULL if no data is available for the specified encryption level.
- **See also**: [`fd_quic_tls_get_hs_data`](fd_quic_tls.c.driver.md#fd_quic_tls_get_hs_data)  (Implementation)


---
### fd\_quic\_tls\_get\_next\_hs\_data<!-- {{#callable_declaration:fd_quic_tls_get_next_hs_data}} -->
Retrieve the next unit of handshake data from the queue.
- **Description**: Use this function to obtain the next available handshake data unit from a given handshake object. It is typically called after retrieving the current handshake data to continue processing subsequent data units. The function requires a valid handshake object and a reference to the current handshake data. If there are no more data units available, the function returns NULL, indicating the end of the queue.
- **Inputs**:
    - `self`: A pointer to the fd_quic_tls_hs_t structure representing the current handshake. Must not be null.
    - `hs`: A pointer to the current fd_quic_tls_hs_data_t structure from which to retrieve the next data unit. Must not be null.
- **Output**: Returns a pointer to the next fd_quic_tls_hs_data_t structure if available, or NULL if there are no more data units in the queue.
- **See also**: [`fd_quic_tls_get_next_hs_data`](fd_quic_tls.c.driver.md#fd_quic_tls_get_next_hs_data)  (Implementation)


---
### fd\_quic\_tls\_pop\_hs\_data<!-- {{#callable_declaration:fd_quic_tls_pop_hs_data}} -->
Remove handshake data from the head of the queue and free associated resources.
- **Description**: This function is used to manage the lifecycle of handshake data within a QUIC-TLS handshake object. It should be called when the data at the head of the queue has been processed and is no longer needed, allowing the resources to be freed and the queue to be updated. This function must be called with a valid handshake object and a valid encryption level. It is important to ensure that the function is not called in a state where more data is being freed than was allocated, as this will result in an error.
- **Inputs**:
    - `self`: A pointer to the fd_quic_tls_hs_t structure representing the handshake. Must not be null.
    - `enc_level`: An unsigned integer representing the encryption level of the handshake data to be removed. Must be a valid encryption level used in the handshake process.
- **Output**: None
- **See also**: [`fd_quic_tls_pop_hs_data`](fd_quic_tls.c.driver.md#fd_quic_tls_pop_hs_data)  (Implementation)


