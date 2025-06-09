# Purpose
This C header file, `fd_grpc_codec.h`, provides utility functions and data structures to facilitate the use of gRPC over HTTP/2. It defines constants for gRPC status codes, which are used to represent the outcome of gRPC operations, and includes internal identifiers for gRPC headers. The file also declares several structures, such as `fd_grpc_hdr`, `fd_grpc_req_hdrs`, and `fd_grpc_resp_hdrs`, which are used to manage gRPC message headers and request/response metadata. Additionally, it provides function prototypes for generating and reading gRPC request and response headers, as well as a function to convert gRPC status codes to their string representations. This header is essential for applications that need to handle gRPC communication over HTTP/2, providing both the necessary protocol constants and helper functions to streamline the process.
# Imports and Dependencies

---
- `../h2/fd_h2_base.h`
- `../h2/fd_h2_hdr_match.h`


# Global Variables

---
### fd\_grpc\_status\_cstr
- **Type**: `function`
- **Description**: The `fd_grpc_status_cstr` function is a global function that takes a gRPC status code as an unsigned integer and returns a constant character pointer. This pointer is expected to point to a string representation of the gRPC status code.
- **Use**: This function is used to convert a gRPC status code into its corresponding string representation for easier interpretation and debugging.


# Data Structures

---
### fd\_grpc\_hdr
- **Type**: `struct`
- **Members**:
    - `compressed`: Indicates if the message is compressed, with a value of 0 or 1.
    - `msg_sz`: Specifies the size of the message in network byte order.
- **Description**: The `fd_grpc_hdr` structure is a packed data structure used to represent the header of a Length-Prefixed-Message in the gRPC protocol over HTTP/2. It contains a `compressed` field to indicate whether the message is compressed and a `msg_sz` field that specifies the size of the message in network byte order. This structure is crucial for handling gRPC messages, as it provides the necessary metadata to interpret the message content that follows the header.


---
### fd\_grpc\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `compressed`: Indicates if the message is compressed, with a value of 0 or 1.
    - `msg_sz`: Specifies the size of the message in network byte order.
- **Description**: The `fd_grpc_hdr_t` structure represents the header of a Length-Prefixed-Message in the gRPC protocol, containing information about whether the message is compressed and the size of the message in bytes. This structure is packed to ensure no padding is added between its fields, which is crucial for network communication where precise control over data layout is required.


---
### fd\_grpc\_req\_hdrs
- **Type**: `struct`
- **Members**:
    - `host`: Pointer to a string representing the host, excluding the port.
    - `host_len`: Length of the host string, with a maximum value of 255.
    - `port`: Unsigned short integer representing the port number.
    - `path`: Pointer to a string representing the path.
    - `path_len`: Length of the path string.
    - `https`: Bit field indicating if the connection is HTTPS (1) or HTTP (0).
    - `bearer_auth`: Pointer to a string representing the bearer authentication token.
    - `bearer_auth_len`: Length of the bearer authentication token string.
- **Description**: The `fd_grpc_req_hdrs` structure is used to represent the headers of a gRPC request over HTTP/2. It includes fields for the host and path of the request, along with their respective lengths, a port number, a flag indicating whether the request is using HTTPS, and fields for bearer authentication. This structure is essential for managing and generating the necessary headers for gRPC requests, ensuring that all required information is encapsulated and easily accessible.


---
### fd\_grpc\_req\_hdrs\_t
- **Type**: `struct`
- **Members**:
    - `host`: Pointer to a string representing the host, excluding the port.
    - `host_len`: Length of the host string, with a maximum of 255.
    - `port`: Port number associated with the host.
    - `path`: Pointer to a string representing the path of the request.
    - `path_len`: Length of the path string.
    - `https`: Flag indicating if the request is over HTTPS (1) or HTTP (0).
    - `bearer_auth`: Pointer to a string containing the bearer authentication token.
    - `bearer_auth_len`: Length of the bearer authentication token string.
- **Description**: The `fd_grpc_req_hdrs_t` structure is used to represent the headers of a gRPC request over HTTP/2. It includes fields for the host and path of the request, as well as their respective lengths. The structure also contains a port number, a flag indicating whether the request is over HTTPS, and fields for bearer authentication, including the token and its length. This structure is essential for generating and managing gRPC request headers in a network communication context.


---
### fd\_grpc\_resp\_hdrs
- **Type**: `struct`
- **Members**:
    - `h2_status`: Represents the HTTP/2 status code, where 0 implies an invalid status.
    - `is_grpc_proto`: A flag indicating if the protocol is gRPC, using 1 bit.
    - `grpc_status`: Represents the gRPC status code, where 0 implies an invalid status.
    - `grpc_msg`: A character array to store the gRPC message, with a maximum length of 1008 characters.
    - `grpc_msg_len`: Stores the length of the gRPC message.
- **Description**: The `fd_grpc_resp_hdrs` structure is designed to encapsulate the headers and trailers of a gRPC response over HTTP/2. It includes fields for storing the HTTP/2 status code and a flag to indicate if the protocol is gRPC. Additionally, it holds the gRPC status code, a message buffer, and the length of the message, facilitating the handling of gRPC response metadata and message content.


---
### fd\_grpc\_resp\_hdrs\_t
- **Type**: `struct`
- **Members**:
    - `h2_status`: Represents the HTTP/2 status code, where 0 implies invalid.
    - `is_grpc_proto`: A flag indicating if the protocol is gRPC (1 if true, 0 if false).
    - `grpc_status`: Represents the gRPC status code, where 0 implies invalid.
    - `grpc_msg`: A character array to store the gRPC message, with a maximum length of 1008 characters.
    - `grpc_msg_len`: The length of the gRPC message stored in grpc_msg.
- **Description**: The `fd_grpc_resp_hdrs_t` structure is designed to encapsulate the headers and trailers of a gRPC response over HTTP/2. It includes fields for storing the HTTP/2 status code, a flag indicating if the protocol is gRPC, the gRPC status code, and a message buffer with its length. This structure is essential for handling and interpreting the response headers and trailers in a gRPC communication context.


# Function Declarations (Public API)

---
### fd\_grpc\_h2\_gen\_request\_hdrs<!-- {{#callable_declaration:fd_grpc_h2_gen_request_hdrs}} -->
Generates a HEADERS frame with gRPC request headers.
- **Description**: This function is used to create a HEADERS frame containing gRPC request headers, which is essential for initiating a gRPC call over HTTP/2. It should be called when preparing to send a gRPC request, ensuring that the necessary headers are correctly formatted and included. The function requires a valid request headers structure, a buffer for transmission, and version information. It returns a success code if the headers are successfully generated, or an error code if there is insufficient space in the buffer.
- **Inputs**:
    - `req`: A pointer to a `fd_grpc_req_hdrs_t` structure containing the request headers information such as host, path, and optional bearer authentication. The structure must be properly initialized and must not be null.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` buffer where the generated headers will be written. The buffer must have sufficient space to accommodate the headers, and the caller retains ownership.
    - `version`: A pointer to a character array containing the version string to be included in the user-agent header. This must not be null.
    - `version_len`: The length of the version string. It must accurately reflect the length of the string pointed to by `version`.
- **Output**: Returns 1 on success, indicating that the headers were successfully generated and written to the buffer. Returns 0 on failure, typically due to insufficient space in the buffer.
- **See also**: [`fd_grpc_h2_gen_request_hdrs`](fd_grpc_codec.c.driver.md#fd_grpc_h2_gen_request_hdrs)  (Implementation)


---
### fd\_grpc\_h2\_read\_response\_hdrs<!-- {{#callable_declaration:fd_grpc_h2_read_response_hdrs}} -->
Parses HTTP/2 response headers for gRPC.
- **Description**: This function is used to parse HTTP/2 response headers and extract relevant gRPC information into a provided response headers structure. It should be called when you have received a HEADERS frame and need to interpret the gRPC-specific headers. The function requires a matcher to identify headers of interest and a payload containing the raw header data. It returns a success code if parsing is successful or an error code if there is a protocol parsing failure. The function logs a warning message in case of a failure.
- **Inputs**:
    - `resp`: A pointer to an fd_grpc_resp_hdrs_t structure where the parsed header information will be stored. The caller must ensure this pointer is valid and the structure is properly initialized before calling the function.
    - `matcher`: A pointer to a constant fd_h2_hdr_matcher_t structure used to identify headers of interest. This pointer must not be null and should be properly initialized to match the headers you want to extract.
    - `payload`: A pointer to an array of unsigned characters containing the raw HTTP/2 header data. This data is expected to be in a format suitable for parsing by the function. The pointer must not be null.
    - `payload_sz`: An unsigned long representing the size of the payload in bytes. It should accurately reflect the size of the data pointed to by the payload parameter.
- **Output**: Returns FD_H2_SUCCESS on successful parsing, or FD_H2_ERR_PROTOCOL if there is a protocol parsing error.
- **See also**: [`fd_grpc_h2_read_response_hdrs`](fd_grpc_codec.c.driver.md#fd_grpc_h2_read_response_hdrs)  (Implementation)


---
### fd\_grpc\_status\_cstr<!-- {{#callable_declaration:fd_grpc_status_cstr}} -->
Convert a gRPC status code to its corresponding string representation.
- **Description**: Use this function to obtain a human-readable string that describes a gRPC status code. It is useful for logging, debugging, or displaying status messages to users. The function maps known gRPC status codes to their respective string descriptions and returns "unknown" for any unrecognized status codes. This function does not modify any input parameters and is safe to call with any unsigned integer value.
- **Inputs**:
    - `status`: An unsigned integer representing a gRPC status code. Valid values are defined as macros (e.g., FD_GRPC_STATUS_OK, FD_GRPC_STATUS_CANCELLED). If the status code is not recognized, the function returns "unknown".
- **Output**: A constant string representing the description of the gRPC status code. Returns "unknown" if the status code is not recognized.
- **See also**: [`fd_grpc_status_cstr`](fd_grpc_codec.c.driver.md#fd_grpc_status_cstr)  (Implementation)


