# Purpose
This C header file, `fd_bundle_auth.h`, defines the structures and function prototypes necessary for implementing an authentication flow for a bundle server. It outlines a challenge-response mechanism where a client requests a challenge from the server, signs it with its identity key, and then requests an authentication token. The file includes necessary dependencies for gRPC and key management, and defines a `fd_bundle_auther` structure to maintain the state of the authentication process, including fields for the challenge, access token, and state management. It provides function prototypes for initializing the authentication process, polling for request work, resetting the authentication state, and handling responses for both challenges and tokens. This header is essential for managing the authentication lifecycle in a client-server architecture, ensuring secure communication through token-based authentication.
# Imports and Dependencies

---
- `../../waltz/grpc/fd_grpc_client.h`
- `../../disco/keyguard/fd_keyguard_client.h`


# Data Structures

---
### fd\_bundle\_auther
- **Type**: `struct`
- **Members**:
    - `state`: An integer representing the current state of the authentication process.
    - `needs_poll`: A 1-bit unsigned integer flag indicating if polling is required.
    - `pubkey`: A 32-byte array storing the public key used for authentication.
    - `challenge`: A 9-character array holding the challenge string for authentication.
    - `access_token`: A 1024-character array storing the access token received from the server.
    - `access_token_sz`: An unsigned short indicating the size of the access token.
- **Description**: The `fd_bundle_auther` structure is used in the authentication process for a bundle server, managing the state and data required for challenge-response transactions and token handling. It includes fields for tracking the authentication state, a flag for polling necessity, a public key for identity verification, a challenge string for signing, and an access token with its size for server communication.


---
### fd\_bundle\_auther\_t
- **Type**: `struct`
- **Members**:
    - `state`: An integer representing the current state of the authentication process.
    - `needs_poll`: A flag indicating whether polling is required for the authentication process.
    - `pubkey`: A 32-byte array storing the public key used for client identity.
    - `challenge`: A 9-byte array storing the challenge string received from the server.
    - `access_token`: A 1024-byte array storing the access token received from the server.
    - `access_token_sz`: A ushort representing the size of the access token.
- **Description**: The `fd_bundle_auther_t` structure is used to manage the authentication process for a bundle server, including handling the state of the authentication flow, storing necessary cryptographic keys and tokens, and managing the communication with the server to acquire and refresh authentication tokens.


# Function Declarations (Public API)

---
### fd\_bundle\_auther\_poll<!-- {{#callable_declaration:fd_bundle_auther_poll}} -->
Performs authentication request work based on the current state of the auther.
- **Description**: This function should be called to progress the authentication process for a bundle server. It operates based on the current state of the `auther` object, either requesting a challenge or requesting tokens. It should be invoked as soon as possible if `auther->needs_poll` is set, indicating that immediate action is required. Otherwise, it should be called periodically, approximately every 100 milliseconds, to ensure timely processing of authentication requests. The function does not return a value and does not directly modify the input parameters.
- **Inputs**:
    - `auther`: A pointer to an `fd_bundle_auther_t` structure representing the current authentication state. Must not be null.
    - `client`: A pointer to an `fd_grpc_client_t` structure used for gRPC communication. Must not be null.
    - `keyguard`: A pointer to an `fd_keyguard_client_t` structure used for key management. Must not be null.
    - `host`: A constant character pointer to the host address string. Must not be null and should point to a valid memory location.
    - `host_len`: An unsigned long representing the length of the host address string. Should accurately reflect the length of the string pointed to by `host`.
    - `port`: An unsigned short representing the port number to connect to. Should be a valid port number.
- **Output**: None
- **See also**: [`fd_bundle_auther_poll`](fd_bundle_auth.c.driver.md#fd_bundle_auther_poll)  (Implementation)


---
### fd\_bundle\_auther\_reset<!-- {{#callable_declaration:fd_bundle_auther_reset}} -->
Restart the authentication process for a bundle server.
- **Description**: Use this function to reset the authentication process for a bundle server, typically after an authentication failure. This function sets the internal state of the `fd_bundle_auther_t` structure to request a new challenge and marks it as needing a poll. It should be called when a previous authentication attempt has failed, allowing the client to start the authentication process anew.
- **Inputs**:
    - `auther`: A pointer to an `fd_bundle_auther_t` structure representing the current authentication session. This parameter must not be null, and the caller retains ownership of the structure. The function will modify the state and `needs_poll` fields of this structure.
- **Output**: None
- **See also**: [`fd_bundle_auther_reset`](fd_bundle_auth.c.driver.md#fd_bundle_auther_reset)  (Implementation)


---
### fd\_bundle\_auther\_handle\_request\_fail<!-- {{#callable_declaration:fd_bundle_auther_handle_request_fail}} -->
Handles a failed authentication request by updating the auther's state.
- **Description**: Use this function to handle situations where an authentication request fails during the challenge-response transaction process. It updates the state of the `fd_bundle_auther_t` object to retry the challenge request and sets the `needs_poll` flag to indicate that further processing is required. This function should be called when a request for either an authentication challenge or tokens fails, ensuring that the authentication process can be retried appropriately.
- **Inputs**:
    - `auther`: A pointer to an `fd_bundle_auther_t` structure representing the current state of the authentication process. The pointer must not be null, and the structure should be properly initialized before calling this function. The function modifies the state and `needs_poll` fields of this structure.
- **Output**: None
- **See also**: [`fd_bundle_auther_handle_request_fail`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_request_fail)  (Implementation)


---
### fd\_bundle\_auther\_handle\_challenge\_resp<!-- {{#callable_declaration:fd_bundle_auther_handle_challenge_resp}} -->
Handles the response to an authentication challenge.
- **Description**: This function processes the server's response to a challenge request during the authentication flow. It should be called when a challenge response is received from the server. The function decodes the response and updates the internal state of the `fd_bundle_auther_t` structure. If the response is valid and contains a challenge of the expected size, the function updates the challenge in the `auther` and sets the state to request tokens. If the response is invalid, it resets the state to request a new challenge. This function must be called with a valid `auther` that has been initialized, and the `data` must contain a properly formatted response.
- **Inputs**:
    - `auther`: A pointer to an `fd_bundle_auther_t` structure that represents the current authentication session. Must not be null and should be properly initialized before calling this function.
    - `data`: A pointer to a buffer containing the response data from the server. The data should be in the expected protobuf format for an authentication challenge response.
    - `data_sz`: The size of the data buffer in bytes. It should accurately reflect the size of the data provided.
- **Output**: Returns 1 if the response is successfully processed and the challenge is valid; returns 0 if the response is invalid or an error occurs during processing.
- **See also**: [`fd_bundle_auther_handle_challenge_resp`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_challenge_resp)  (Implementation)


---
### fd\_bundle\_auther\_handle\_tokens\_resp<!-- {{#callable_declaration:fd_bundle_auther_handle_tokens_resp}} -->
Handles the response for generating authentication tokens.
- **Description**: This function processes the server's response containing authentication tokens for a bundle server. It should be called when a response to an authentication token request is received. The function decodes the response and updates the `auther` structure with the access token if successful. If the response is invalid or the access token is missing or oversized, it sets the `auther` state to request a new challenge. This function is crucial for maintaining the authentication flow and should be used as part of the token acquisition process.
- **Inputs**:
    - `auther`: A pointer to an `fd_bundle_auther_t` structure that will be updated with the access token if the response is valid. Must not be null.
    - `data`: A pointer to the response data buffer containing the server's response. Must not be null.
    - `data_sz`: The size of the data buffer in bytes. Should accurately reflect the size of the response data.
- **Output**: Returns 1 if the response is successfully processed and the access token is valid; otherwise, returns 0 and updates the `auther` state to request a new challenge.
- **See also**: [`fd_bundle_auther_handle_tokens_resp`](fd_bundle_auth.c.driver.md#fd_bundle_auther_handle_tokens_resp)  (Implementation)


