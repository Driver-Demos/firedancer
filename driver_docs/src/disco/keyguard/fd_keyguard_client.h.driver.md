# Purpose
The provided C header file, `fd_keyguard_client.h`, defines a client interface for interacting with a remote signing server, specifically designed to operate within a secure, shared memory environment. This file is part of a larger system, likely involving multiple components, where it facilitates secure communication between a client and a keyguard server. The primary functionality revolves around sending signing requests to a remote server and receiving signatures, with a strong emphasis on security and data integrity. The header file outlines the structure `fd_keyguard_client_t`, which encapsulates metadata and data regions for both requests and responses, ensuring that these are aligned and managed correctly in shared memory.

The file defines several functions, including [`fd_keyguard_client_new`](#fd_keyguard_client_new), [`fd_keyguard_client_join`](#fd_keyguard_client_join), [`fd_keyguard_client_leave`](#fd_keyguard_client_leave), and [`fd_keyguard_client_delete`](#fd_keyguard_client_delete), which manage the lifecycle of the client object in shared memory. The critical function [`fd_keyguard_client_sign`](#fd_keyguard_client_sign) is responsible for sending signing requests and blocking until a response is received, highlighting the blocking nature of the client-server interaction. The design ensures that the signing process is treated as infallible, with no error handling for timeouts or server unavailability, which underscores the importance of the server's reliability in this system. The header file is intended to be included in other C source files, providing a public API for secure signing operations within a distributed system.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Global Variables

---
### fd\_keyguard\_client\_new
- **Type**: `function pointer`
- **Description**: The `fd_keyguard_client_new` is a function that initializes a new keyguard client instance. It takes shared memory and metadata caches for request and response as parameters, setting up the necessary structures for communication with a remote signing server.
- **Use**: This function is used to create and initialize a new instance of a keyguard client, facilitating secure communication with a remote signing server.


# Data Structures

---
### fd\_keyguard\_client
- **Type**: `struct`
- **Members**:
    - `request`: Pointer to the request metadata.
    - `request_seq`: Sequence number for the request.
    - `request_depth`: Depth of the request queue.
    - `request_data`: Pointer to the request data buffer.
    - `response`: Pointer to the response metadata.
    - `response_seq`: Sequence number for the response.
    - `response_depth`: Depth of the response queue.
    - `response_data`: Pointer to the response data buffer.
- **Description**: The `fd_keyguard_client` structure is designed to facilitate communication with a remote signing server by managing request and response data through shared memory caches. It contains pointers to metadata and data buffers for both requests and responses, along with sequence numbers and queue depths to track the state of these communications. The structure is aligned to a specific boundary for performance reasons and is used in a secure environment where memory access is tightly controlled to ensure data integrity and security.


---
### fd\_keyguard\_client\_t
- **Type**: `struct`
- **Members**:
    - `request`: Pointer to the request metadata cache.
    - `request_seq`: Sequence number for the request.
    - `request_depth`: Depth of the request queue.
    - `request_data`: Pointer to the request data buffer.
    - `response`: Pointer to the response metadata cache.
    - `response_seq`: Sequence number for the response.
    - `response_depth`: Depth of the response queue.
    - `response_data`: Pointer to the response data buffer.
- **Description**: The `fd_keyguard_client_t` structure is designed to facilitate communication with a remote signing server using a pair of input and output memory caches and data regions. It contains metadata and data pointers for both request and response operations, ensuring that requests and responses are properly sequenced and managed. The structure is aligned to 128 bytes for performance reasons, and it is intended to be used in a secure shared memory environment where access is restricted to specific tiles.


# Functions

---
### fd\_keyguard\_client\_join<!-- {{#callable:fd_keyguard_client_join}} -->
The `fd_keyguard_client_join` function casts a generic pointer to a `fd_keyguard_client_t` pointer.
- **Inputs**:
    - `shclient`: A generic pointer to a shared client object that is to be cast to a `fd_keyguard_client_t` pointer.
- **Control Flow**:
    - The function takes a single input parameter, `shclient`, which is a void pointer.
    - It performs a cast operation to convert the `shclient` pointer to a `fd_keyguard_client_t` pointer.
    - The function returns the result of the cast operation.
- **Output**: A pointer of type `fd_keyguard_client_t` that points to the same memory location as the input `shclient`.


---
### fd\_keyguard\_client\_leave<!-- {{#callable:fd_keyguard_client_leave}} -->
The `fd_keyguard_client_leave` function casts a `fd_keyguard_client_t` pointer to a `void` pointer and returns it.
- **Inputs**:
    - `client`: A pointer to an `fd_keyguard_client_t` structure, representing the client to be left.
- **Control Flow**:
    - The function takes a single argument, `client`, which is a pointer to a `fd_keyguard_client_t` structure.
    - It casts the `client` pointer to a `void` pointer.
    - The function returns the casted `void` pointer.
- **Output**: A `void` pointer that is the result of casting the input `fd_keyguard_client_t` pointer.


---
### fd\_keyguard\_client\_delete<!-- {{#callable:fd_keyguard_client_delete}} -->
The `fd_keyguard_client_delete` function returns the input pointer `shclient` without modification.
- **Inputs**:
    - `shclient`: A pointer to a shared client object that is intended to be deleted or cleaned up.
- **Control Flow**:
    - The function takes a single input parameter `shclient`.
    - It directly returns the `shclient` pointer without performing any operations on it.
- **Output**: The function returns the same pointer `shclient` that was passed to it as an argument.


# Function Declarations (Public API)

---
### fd\_keyguard\_client\_new<!-- {{#callable_declaration:fd_keyguard_client_new}} -->
Initialize a new keyguard client in shared memory.
- **Description**: This function sets up a new keyguard client using the provided shared memory and metadata caches for request and response handling. It is essential to ensure that the request and response memory caches and data regions are securely mapped in shared memory, accessible only to the calling and keyguard tiles, with appropriate read-only permissions as needed. This setup is crucial for maintaining security and ensuring that the keyguard client operates correctly. The function should be called when a new client needs to be initialized for communication with a remote signing server.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the keyguard client will be initialized. The caller retains ownership and must ensure it is properly aligned and sized.
    - `request_mcache`: A pointer to the metadata cache for requests. It must be placed in a shared memory map accessible only to the calling and keyguard tiles.
    - `request_data`: A pointer to the data region for requests. It must be placed in a shared memory map accessible only to the calling and keyguard tiles.
    - `response_mcache`: A pointer to the metadata cache for responses. It must be placed in a shared memory map accessible only to the calling and keyguard tiles.
    - `response_data`: A pointer to the data region for responses. It must be placed in a shared memory map accessible only to the calling and keyguard tiles.
- **Output**: Returns a pointer to the initialized keyguard client in the shared memory.
- **See also**: [`fd_keyguard_client_new`](fd_keyguard_client.c.driver.md#fd_keyguard_client_new)  (Implementation)


---
### fd\_keyguard\_client\_sign<!-- {{#callable_declaration:fd_keyguard_client_sign}} -->
Send a signing request to a remote server and wait for the signature response.
- **Description**: This function sends a signing request to a remote signing server and blocks until a response is received. It is designed for use in environments where the request and response data are securely shared between the calling tile and the keyguard tile, with strict access controls. The function does not handle errors internally and will hang indefinitely if the remote server is unresponsive. It is crucial that the data to be signed is correctly formatted and corresponds to the expected role, as any deviation will result in a critical error. The signature buffer must be pre-allocated and large enough to hold the 64-byte signature response.
- **Inputs**:
    - `client`: A pointer to an initialized fd_keyguard_client_t structure. The client must be properly set up with request and response mcaches and data regions as per the security guidelines.
    - `signature`: A pointer to a buffer where the 64-byte signature will be written. The buffer must be at least 64 bytes in size.
    - `sign_data`: A pointer to the data buffer that needs to be signed. The data must be correctly formatted for the role associated with the request mcache.
    - `sign_data_len`: The length of the data to be signed. It must accurately reflect the size of the data pointed to by sign_data.
    - `sign_type`: An integer representing the type of signing operation, which should be one of the predefined constants in FD_KEYGUARD_SIGN_TYPE_{...}.
- **Output**: None
- **See also**: [`fd_keyguard_client_sign`](fd_keyguard_client.c.driver.md#fd_keyguard_client_sign)  (Implementation)


