# Purpose
This C source code file provides functionality for a client component of a keyguard system, which is likely part of a larger security or cryptographic framework. The file defines two primary functions: [`fd_keyguard_client_new`](#fd_keyguard_client_new) and [`fd_keyguard_client_sign`](#fd_keyguard_client_sign). The [`fd_keyguard_client_new`](#fd_keyguard_client_new) function initializes a new keyguard client using shared memory and metadata caches for request and response handling. It sets up the client structure with pointers to request and response metadata, data buffers, and initializes sequence numbers for tracking requests and responses. This setup is crucial for managing communication between the client and the keyguard service, ensuring that requests and responses are correctly sequenced and stored.

The [`fd_keyguard_client_sign`](#fd_keyguard_client_sign) function is responsible for handling signing requests. It copies the data to be signed into the client's request data buffer, publishes the request to a metadata cache, and waits for a response. The function uses a polling mechanism to wait for the response, ensuring that the request is processed and the signature is retrieved. The signature is then copied into the provided buffer. This function is critical for the client to interact with the keyguard service, allowing it to request cryptographic signatures on data. The code is designed to handle potential errors such as timeouts and overruns, ensuring robust communication. Overall, this file is part of a specialized library intended to be integrated into a larger system, providing a focused API for keyguard client operations.
# Imports and Dependencies

---
- `fd_keyguard_client.h`


# Functions

---
### fd\_keyguard\_client\_new<!-- {{#callable:fd_keyguard_client_new}} -->
The `fd_keyguard_client_new` function initializes a `fd_keyguard_client_t` structure using shared memory and metadata caches for request and response handling.
- **Inputs**:
    - `shmem`: A pointer to shared memory where the `fd_keyguard_client_t` structure will be initialized.
    - `request_mcache`: A pointer to the metadata cache for handling request data.
    - `request_data`: A pointer to the actual request data buffer.
    - `response_mcache`: A pointer to the metadata cache for handling response data.
    - `response_data`: A pointer to the actual response data buffer.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_keyguard_client_t` pointer named `client`.
    - Assign the `request_mcache` to `client->request`.
    - Determine the depth of the request metadata cache using `fd_mcache_depth` and assign it to `client->request_depth`.
    - Initialize `client->request_seq` to 0.
    - Assign the `request_data` pointer to `client->request_data`.
    - Assign the `response_mcache` to `client->response`.
    - Determine the depth of the response metadata cache using `fd_mcache_depth` and assign it to `client->response_depth`.
    - Initialize `client->response_seq` to 0.
    - Assign the `response_data` pointer to `client->response_data`.
    - Return the `shmem` pointer.
- **Output**: Returns the `shmem` pointer, which now points to an initialized `fd_keyguard_client_t` structure.


---
### fd\_keyguard\_client\_sign<!-- {{#callable:fd_keyguard_client_sign}} -->
The `fd_keyguard_client_sign` function handles the process of signing data using a keyguard client by publishing a sign request and waiting for a response.
- **Inputs**:
    - `client`: A pointer to an `fd_keyguard_client_t` structure, which contains the request and response metadata and data buffers.
    - `signature`: A pointer to a buffer where the resulting signature will be stored.
    - `sign_data`: A pointer to the data that needs to be signed.
    - `sign_data_len`: The length of the data to be signed.
    - `sign_type`: An integer representing the type of signature to be used.
- **Control Flow**:
    - Copy the sign data into the client's request data buffer using `fd_memcpy`.
    - Convert the sign type to an unsigned long and publish the sign request using `fd_mcache_publish`.
    - Increment the client's request sequence number using `fd_seq_inc`.
    - Initialize variables for metadata and sequence tracking, then wait for a response using `FD_MCACHE_WAIT`.
    - Check for timeout or overrun errors during polling and log errors if they occur.
    - Copy the response data into the signature buffer using `fd_memcpy`.
    - Query the sequence number from the response metadata and check for overruns, logging errors if necessary.
    - Increment the client's response sequence number using `fd_seq_inc`.
- **Output**: The function does not return a value, but it outputs the signature of the signed data into the provided `signature` buffer.


