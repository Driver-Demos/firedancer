# Purpose
This C header file defines private data structures for an RPC (Remote Procedure Call) client, specifically for managing client requests and their states. The `fd_rpc_client_request` structure encapsulates the state of a request, including buffers for request and response data, and tracks the progress of data being sent and received. The `fd_rpc_client_private` structure is aligned for performance and contains an array of `pollfd` structures for monitoring multiple file descriptors, as well as an array of `fd_rpc_client_request` structures to handle multiple concurrent requests. This file is likely part of a larger RPC client implementation, providing the necessary internal mechanisms to manage and track the lifecycle of RPC requests.
# Imports and Dependencies

---
- `fd_rpc_client.h`
- `poll.h`


# Data Structures

---
### fd\_rpc\_client\_request
- **Type**: `struct`
- **Members**:
    - `state`: Represents the current state of the RPC client request.
    - `response_bytes`: A buffer shared across multiple states to store response data.
    - `connected`: A union member containing fields related to the connected state, including request byte count, bytes sent, and a buffer for request data.
    - `sent`: A union member containing a field for the number of response bytes read in the sent state.
    - `response`: An instance of fd_rpc_client_response_t representing the response associated with the request.
- **Description**: The `fd_rpc_client_request` structure is designed to manage the state and data of a client request in an RPC (Remote Procedure Call) system. It includes a state indicator, a shared buffer for response data, and a union to handle different states of the request lifecycle, such as 'connected' and 'sent'. Each state in the union has specific fields to track the progress of the request, such as the number of bytes sent or read. Additionally, it holds a response object to encapsulate the response details.


---
### fd\_rpc\_client\_private
- **Type**: `struct`
- **Members**:
    - `request_id`: A long integer representing the unique identifier for a request.
    - `rpc_addr`: An unsigned integer representing the address of the RPC server.
    - `rpc_port`: An unsigned short integer representing the port number of the RPC server.
    - `fds`: An array of pollfd structures used for polling file descriptors, with a size defined by FD_RPC_CLIENT_REQUEST_CNT.
    - `requests`: An array of fd_rpc_client_request structures, each representing a client request, with a size defined by FD_RPC_CLIENT_REQUEST_CNT.
- **Description**: The `fd_rpc_client_private` structure is designed to manage the state and communication details of an RPC client. It includes a unique request identifier, server address and port information, and arrays for handling multiple concurrent requests and their associated file descriptors. The structure is aligned according to `FD_RPC_CLIENT_ALIGN` to ensure proper memory alignment for efficient access.


