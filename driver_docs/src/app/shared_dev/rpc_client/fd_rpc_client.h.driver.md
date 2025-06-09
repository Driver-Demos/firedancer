# Purpose
This C header file defines a rudimentary RPC (Remote Procedure Call) client intended to interact with the Agave validator, specifically for retrieving blockchain-related information such as the latest block hash and the current transaction count. The file is not part of the Firedancer RPC implementation and is explicitly noted as a non-hardened, non-fuzzed utility meant for code interoperability rather than production use. The header defines several constants for error handling and state management, such as `FD_RPC_CLIENT_SUCCESS` and `FD_RPC_CLIENT_STATE_CONNECTED`, which help manage the client's lifecycle and error states.

The file introduces a structure, `fd_rpc_client_response_t`, to encapsulate the response from RPC requests, and it provides function prototypes for creating, managing, and interacting with the RPC client. Key functions include [`fd_rpc_client_new`](#fd_rpc_client_new) for initializing a new client, [`fd_rpc_client_request_latest_block_hash`](#fd_rpc_client_request_latest_block_hash) and [`fd_rpc_client_request_transaction_count`](#fd_rpc_client_request_transaction_count) for making specific RPC requests, and [`fd_rpc_client_service`](#fd_rpc_client_service) for handling the communication with the server. The header also includes mechanisms for checking the status of requests and closing them to free resources. This file is designed to be included in other C source files, providing a narrow set of functionalities focused on RPC client operations for specific blockchain data retrieval tasks.
# Imports and Dependencies

---
- `../../../util/fd_util.h`
- `poll.h`


# Global Variables

---
### fd\_rpc\_client\_new
- **Type**: `function pointer`
- **Description**: The `fd_rpc_client_new` function is a constructor for creating a new RPC client instance. It initializes the client with a specified memory location, RPC server address, and port number. This function is part of a simple RPC client implementation intended for interoperability with the Agave validator.
- **Use**: This function is used to allocate and initialize a new RPC client instance with the given memory, address, and port parameters.


---
### fd\_rpc\_client\_status
- **Type**: `function`
- **Description**: The `fd_rpc_client_status` function is used to retrieve the response of an RPC request identified by a specific request ID. It returns a pointer to an `fd_rpc_client_response_t` structure, which contains the status and result of the request. If the response is not yet available, the status will be `FD_RPC_CLIENT_PENDING`, and if the request ID does not exist or has already been closed, the function returns `NULL`. The function can operate in blocking mode if the `wait` parameter is set to true, ensuring it only returns when a response is available or an error occurs.
- **Use**: This function is used to check the status and retrieve the result of a specific RPC request made by the client.


# Data Structures

---
### fd\_rpc\_client\_response\_t
- **Type**: `struct`
- **Members**:
    - `request_id`: A long integer representing the unique identifier for the RPC request.
    - `method`: An unsigned long integer indicating the method used for the RPC request.
    - `status`: A long integer representing the status of the RPC request.
    - `result`: A union containing the result of the RPC request, which can be either the latest block hash or the transaction count.
- **Description**: The `fd_rpc_client_response_t` structure is used to encapsulate the response from an RPC client request. It includes a request ID to uniquely identify the request, a method to specify the type of request made, and a status to indicate the current state of the request. The result is stored in a union, allowing it to hold either the latest block hash or the transaction count, depending on the method used. This structure is part of a simple RPC client implementation for interacting with an Agave validator.


---
### fd\_rpc\_client\_t
- **Type**: `typedef struct fd_rpc_client_private fd_rpc_client_t;`
- **Description**: The `fd_rpc_client_t` is a typedef for a private structure `fd_rpc_client_private`, which is part of a rudimentary RPC client implementation. This client is designed to interact with the Agave validator, providing basic interoperability but lacking robustness and security features. The structure itself is not directly defined in the provided code, indicating that its details are encapsulated and not intended for direct manipulation. The client supports operations such as making requests for the latest block hash and transaction count, managing connections, and handling responses, but it is not suitable for production use due to its lack of fuzzing and hardening.


# Functions

---
### fd\_rpc\_client\_align<!-- {{#callable:fd_rpc_client_align}} -->
The `fd_rpc_client_align` function returns the alignment requirement for an RPC client.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests that the function's code will be inserted at each call site, potentially improving performance.
    - The function returns a constant value, `FD_RPC_CLIENT_ALIGN`, which is defined as `8UL`.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for an RPC client, specifically `8UL`.


---
### fd\_rpc\_client\_footprint<!-- {{#callable:fd_rpc_client_footprint}} -->
The `fd_rpc_client_footprint` function returns the memory footprint size required for the RPC client.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - It returns a constant value `FD_RPC_CLIENT_FOOTPRINT`, which is defined as `273424UL`.
- **Output**: The function outputs an unsigned long integer representing the memory footprint size of the RPC client, specifically `273424UL`.


---
### fd\_rpc\_client\_join<!-- {{#callable:fd_rpc_client_join}} -->
The `fd_rpc_client_join` function casts a generic pointer to a specific `fd_rpc_client_t` pointer type.
- **Inputs**:
    - `_rpc`: A generic pointer to be cast to a `fd_rpc_client_t` pointer.
- **Control Flow**:
    - The function takes a single input parameter, `_rpc`, which is a generic pointer.
    - It performs a type cast on `_rpc` to convert it into a pointer of type `fd_rpc_client_t`.
    - The function returns the casted pointer.
- **Output**: A pointer of type `fd_rpc_client_t` that is cast from the input generic pointer.


---
### fd\_rpc\_client\_leave<!-- {{#callable:fd_rpc_client_leave}} -->
The `fd_rpc_client_leave` function casts a pointer to an `fd_rpc_client_t` object back to a generic `void` pointer.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` object that is to be cast to a `void` pointer.
- **Control Flow**:
    - The function takes a single argument, `rpc`, which is a pointer to an `fd_rpc_client_t` object.
    - It returns the same pointer, `rpc`, cast to a `void` pointer.
- **Output**: A `void` pointer that is the result of casting the input `fd_rpc_client_t` pointer.


---
### fd\_rpc\_client\_delete<!-- {{#callable:fd_rpc_client_delete}} -->
The `fd_rpc_client_delete` function returns the input pointer as a void pointer, effectively performing no operation on the input.
- **Inputs**:
    - `_rpc`: A void pointer to an RPC client object that is intended to be deleted.
- **Control Flow**:
    - The function takes a single input parameter, `_rpc`, which is a void pointer.
    - It returns the same pointer, `_rpc`, cast back to a void pointer, without performing any additional operations.
- **Output**: The function returns the input pointer `_rpc` as a void pointer.


# Function Declarations (Public API)

---
### fd\_rpc\_client\_new<!-- {{#callable_declaration:fd_rpc_client_new}} -->
Creates a new RPC client instance.
- **Description**: This function initializes a new RPC client instance using the provided memory buffer, setting it up to communicate with a server at the specified address and port. It must be called before any other operations on the RPC client. The memory provided must be large enough to accommodate the client structure, and the function assumes the caller has allocated this memory appropriately. The function does not perform any network operations or validations on the address and port; it simply prepares the client for future use.
- **Inputs**:
    - `mem`: A pointer to a pre-allocated memory buffer where the RPC client instance will be initialized. The buffer must be aligned to FD_RPC_CLIENT_ALIGN and have a size of at least FD_RPC_CLIENT_FOOTPRINT bytes. The caller retains ownership of this memory.
    - `rpc_addr`: The address of the RPC server as an unsigned integer. This value is stored in the client instance for future use.
    - `rpc_port`: The port number of the RPC server as an unsigned short. This value is stored in the client instance for future use.
- **Output**: Returns a pointer to the initialized RPC client instance, which is the same as the input memory pointer.
- **See also**: [`fd_rpc_client_new`](fd_rpc_client.c.driver.md#fd_rpc_client_new)  (Implementation)


---
### fd\_rpc\_client\_wait\_ready<!-- {{#callable_declaration:fd_rpc_client_wait_ready}} -->
Waits for the RPC server to be ready to receive requests.
- **Description**: This function blocks until the RPC server is ready to accept requests or until the specified timeout period elapses. It should be called before making any RPC requests to ensure the server is prepared to handle them. If the timeout is set to -1, the function will wait indefinitely until the server is ready. This function is useful for synchronizing client operations with server availability. It returns a success code if the server becomes ready within the timeout period, or an error code if the timeout is reached or a network error occurs.
- **Inputs**:
    - `rpc`: A pointer to an initialized fd_rpc_client_t structure representing the RPC client. Must not be null.
    - `timeout_ns`: The maximum time to wait in nanoseconds for the server to be ready. If set to -1, the function will wait indefinitely.
- **Output**: Returns FD_RPC_CLIENT_SUCCESS if the server is ready, or FD_RPC_CLIENT_ERR_NETWORK if a network error occurs or the timeout is reached.
- **See also**: [`fd_rpc_client_wait_ready`](fd_rpc_client.c.driver.md#fd_rpc_client_wait_ready)  (Implementation)


---
### fd\_rpc\_client\_request\_latest\_block\_hash<!-- {{#callable_declaration:fd_rpc_client_request_latest_block_hash}} -->
Make an RPC request to get the latest block hash.
- **Description**: This function sends a request to retrieve the latest block hash from the RPC server. It should be called when you need to obtain the most recent block hash from the server. The function returns a request ID on success, which can be used to track the request's status. If the request cannot be processed, a negative error code is returned. Ensure that the RPC client is properly initialized and connected before calling this function. Be aware that if there are too many requests in flight, the function will return an error indicating this condition.
- **Inputs**:
    - `rpc`: A pointer to an initialized and connected fd_rpc_client_t structure. Must not be null. The caller retains ownership of this pointer.
- **Output**: Returns a non-negative request ID on success, or a negative error code on failure, such as FD_RPC_CLIENT_ERR_TOO_MANY if there are too many requests in flight.
- **See also**: [`fd_rpc_client_request_latest_block_hash`](fd_rpc_client.c.driver.md#fd_rpc_client_request_latest_block_hash)  (Implementation)


---
### fd\_rpc\_client\_request\_transaction\_count<!-- {{#callable_declaration:fd_rpc_client_request_transaction_count}} -->
Make an RPC request to retrieve the current transaction count.
- **Description**: This function sends a request to an RPC server to obtain the current transaction count. It should be used when you need to query the transaction count from the server. The function returns a request ID on success, which can be used to track the request status or retrieve the response later. It is important to ensure that the RPC client is properly initialized and connected before calling this function. If there are too many requests already in flight, the function will return an error indicating that no more requests can be processed at the moment.
- **Inputs**:
    - `rpc`: A pointer to an initialized and connected fd_rpc_client_t structure. Must not be null. The caller retains ownership and is responsible for ensuring the client is in a valid state before calling this function.
- **Output**: Returns a non-negative request ID on success, which can be used to track the request. On failure, returns a negative error code, such as FD_RPC_CLIENT_ERR_TOO_MANY if there are too many requests in flight.
- **See also**: [`fd_rpc_client_request_transaction_count`](fd_rpc_client.c.driver.md#fd_rpc_client_request_transaction_count)  (Implementation)


---
### fd\_rpc\_client\_service<!-- {{#callable_declaration:fd_rpc_client_service}} -->
Service all RPC connections to send and receive data.
- **Description**: Use this function to manage the sending and receiving of data for all active RPC connections. It processes requests by sending data to the server and receiving responses. The function can operate in non-blocking mode, returning immediately after attempting to send and receive data, or in blocking mode, where it waits until some progress is made if the `wait` parameter is set to true. It is useful for maintaining communication with the server and ensuring that requests are processed in a timely manner. The function returns an indication of whether any work was done to progress a connection.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client. Must not be null. The caller retains ownership.
    - `wait`: An integer flag indicating whether the function should block until progress is made. If non-zero, the function will block; otherwise, it will return immediately.
- **Output**: Returns 1 if any work was done to progress a connection, otherwise returns 0.
- **See also**: [`fd_rpc_client_service`](fd_rpc_client.c.driver.md#fd_rpc_client_service)  (Implementation)


---
### fd\_rpc\_client\_status<!-- {{#callable_declaration:fd_rpc_client_status}} -->
Retrieve the response of an RPC request by its ID.
- **Description**: Use this function to obtain the response of a previously made RPC request identified by its request ID. It can operate in both non-blocking and blocking modes, depending on the `wait` parameter. In non-blocking mode, the function returns immediately with the current status of the request. In blocking mode, it waits until the request is completed or an error occurs. This function should be called after making an RPC request to check its status or retrieve its result. If the request ID is invalid or the request has been closed, the function returns NULL.
- **Inputs**:
    - `rpc`: A pointer to an `fd_rpc_client_t` structure representing the RPC client. Must not be null.
    - `request_id`: A long integer representing the ID of the RPC request whose response is being queried. Must correspond to a valid, active request.
    - `wait`: An integer indicating whether to block until the response is available. Non-zero for blocking mode, zero for non-blocking mode.
- **Output**: Returns a pointer to an `fd_rpc_client_response_t` structure containing the response if successful, or NULL if the request ID is invalid or the request has been closed.
- **See also**: [`fd_rpc_client_status`](fd_rpc_client.c.driver.md#fd_rpc_client_status)  (Implementation)


---
### fd\_rpc\_client\_close<!-- {{#callable_declaration:fd_rpc_client_close}} -->
Close the RPC request with the specified ID.
- **Description**: Use this function to close an RPC request identified by the given request ID. It should be called once you are done inspecting the results of the request to free up resources. If the request is still pending, it will be abandoned. If the request has already been closed or does not exist, the function will return silently without any effect. This function is essential to prevent resource exhaustion, which can lead to failures in making new requests.
- **Inputs**:
    - `rpc`: A pointer to an fd_rpc_client_t structure representing the RPC client. Must not be null.
    - `request_id`: A long integer representing the ID of the request to be closed. If the request ID does not exist or has already been closed, the function will return without any action.
- **Output**: None
- **See also**: [`fd_rpc_client_close`](fd_rpc_client.c.driver.md#fd_rpc_client_close)  (Implementation)


