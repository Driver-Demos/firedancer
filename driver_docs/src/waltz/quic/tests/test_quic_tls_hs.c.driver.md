# Purpose
The provided C source code file is a test program designed to perform a handshake using the `fd_quic_tls` API, which is a lightweight wrapper over the `fd_tls` API. This code is primarily focused on testing the QUIC (Quick UDP Internet Connections) protocol's TLS (Transport Layer Security) handshake process. It includes the necessary setup for both client and server sides of a QUIC connection, simulating the exchange of handshake messages and secrets. The code defines a structure `my_quic_tls_t` to maintain the state of the handshake, including whether it is complete and the security level. It also implements callback functions to handle the completion of the handshake, the reception of secrets, and the validation of transport parameters.

The main function initializes the necessary components, including random number generation and certificate key generation, and configures the QUIC TLS settings. It then creates and manages the handshake process for both client and server, simulating the exchange of encrypted data and ensuring that both sides reach a connected state. The code is structured to log detailed information about the handshake process, including the secrets exchanged and the transport parameters used. This file is not intended to be a reusable library or a public API but rather a standalone test executable to verify the correct implementation and behavior of the QUIC TLS handshake process.
# Imports and Dependencies

---
- `../../tls/test_tls_helper.h`
- `../tls/fd_quic_tls.h`
- `../templ/fd_quic_transport_params.h`


# Global Variables

---
### test\_tp
- **Type**: `uchar const[]`
- **Description**: The `test_tp` variable is a static constant array of unsigned characters (uchar) that holds a sequence of hexadecimal values. These values represent encoded transport parameters used in the QUIC (Quick UDP Internet Connections) protocol for testing purposes.
- **Use**: This variable is used to store predefined transport parameters that are compared against received parameters during the QUIC handshake process to ensure they match expected values.


# Data Structures

---
### my\_quic\_tls\_t
- **Type**: `struct`
- **Members**:
    - `is_server`: Indicates whether the instance is acting as a server (1) or client (0).
    - `is_hs_complete`: Indicates whether the handshake process is complete (1) or not (0).
    - `state`: Represents the current state of the TLS connection.
    - `sec_level`: Indicates the security level of the TLS connection.
- **Description**: The `my_quic_tls_t` structure is used to manage the state and configuration of a QUIC TLS connection, specifically indicating whether the instance is a server or client, whether the handshake is complete, and maintaining the state and security level of the connection. This structure is integral to the handshake process and the management of secure communication in a QUIC protocol context.


---
### my\_quic\_tls
- **Type**: `struct`
- **Members**:
    - `is_server`: Indicates whether the instance is acting as a server (1) or client (0).
    - `is_hs_complete`: Indicates whether the handshake process is complete (1) or not (0).
    - `state`: Represents the current state of the TLS connection.
    - `sec_level`: Specifies the security level of the TLS connection.
- **Description**: The `my_quic_tls` structure is designed to manage the state and configuration of a QUIC TLS connection. It includes flags to determine if the instance is operating as a server or client, and whether the handshake process has been completed. Additionally, it maintains the current state and security level of the connection, which are crucial for managing the lifecycle and security parameters of the TLS session.


# Functions

---
### my\_hs\_complete<!-- {{#callable:my_hs_complete}} -->
The `my_hs_complete` function marks the handshake as complete by setting a flag in the provided context.
- **Inputs**:
    - `hs`: A pointer to an `fd_quic_tls_hs_t` structure, which is not used in this function.
    - `context`: A pointer to a `my_quic_tls_t` structure, which contains the handshake state information.
- **Control Flow**:
    - The function begins by casting the `context` pointer to a `my_quic_tls_t` pointer named `ctx`.
    - A debug log message is generated to indicate that the handshake is complete.
    - The `is_hs_complete` field of the `ctx` structure is set to 1, marking the handshake as complete.
- **Output**: This function does not return any value; it modifies the state of the `my_quic_tls_t` structure pointed to by `context`.


---
### my\_secrets<!-- {{#callable:my_secrets}} -->
The `my_secrets` function logs information about the encryption secrets used during a QUIC TLS handshake.
- **Inputs**:
    - `hs`: A pointer to an `fd_quic_tls_hs_t` structure representing the QUIC TLS handshake state.
    - `context`: A void pointer to a context, which is not used in this function.
    - `secret`: A constant pointer to an `fd_quic_tls_secret_t` structure containing the encryption secrets.
- **Control Flow**:
    - The function begins by casting the `context` parameter to void to indicate it is unused.
    - It asserts that the `secret` pointer is not NULL using `FD_TEST`.
    - It logs whether the handshake is for a server or client and the encryption level using `FD_LOG_INFO`.
    - It logs the read and write secrets in hexadecimal format using `FD_LOG_HEXDUMP_INFO`.
- **Output**: The function does not return any value; it performs logging operations.


---
### my\_transport\_params<!-- {{#callable:my_transport_params}} -->
The `my_transport_params` function verifies that the provided QUIC transport parameters match a predefined set of test parameters.
- **Inputs**:
    - `context`: A void pointer to a context, which is not used in this function.
    - `quic_tp`: A pointer to an array of unsigned characters representing the QUIC transport parameters to be verified.
    - `quic_tp_sz`: An unsigned long representing the size of the `quic_tp` array.
- **Control Flow**:
    - The function begins by casting the `context` parameter to void to indicate it is unused.
    - It then checks if the size of the provided transport parameters (`quic_tp_sz`) matches the size of the predefined `test_tp` minus one, using the `FD_TEST` macro for assertion.
    - Next, it compares the provided transport parameters (`quic_tp`) with the predefined `test_tp` using `memcmp` to ensure they are identical, again using `FD_TEST` for assertion.
- **Output**: The function does not return any value; it performs assertions to verify the correctness of the input parameters.


---
### fd\_quic\_tls\_provide\_data<!-- {{#callable:fd_quic_tls_provide_data}} -->
The `fd_quic_tls_provide_data` function provides incoming TLS handshake data to a QUIC TLS handshake context and processes it.
- **Inputs**:
    - `tls_hs`: A pointer to an `fd_quic_tls_hs_t` structure representing the QUIC TLS handshake context.
    - `enc_level`: An unsigned integer representing the encryption level of the incoming data.
    - `msg`: A pointer to a constant unsigned character array containing the message data to be provided.
    - `msg_sz`: An unsigned long integer representing the size of the message data.
- **Control Flow**:
    - The function begins by asserting that the size of the message (`msg_sz`) does not exceed `FD_QUIC_TLS_RX_DATA_SZ`.
    - It sets the `rx_enc_level` field of the `tls_hs` structure to the provided `enc_level`.
    - It sets the `rx_sz` field of the `tls_hs` structure to the provided `msg_sz`.
    - It initializes the `rx_off` field of the `tls_hs` structure to 0.
    - It copies the message data from `msg` to the `rx_hs_buf` buffer within the `tls_hs` structure using `fd_memcpy`.
    - Finally, it calls `fd_quic_tls_process` to process the provided data within the handshake context.
- **Output**: The function does not return a value; it modifies the state of the `fd_quic_tls_hs_t` structure pointed to by `tls_hs`.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and performs a QUIC-TLS handshake simulation between a client and server using the fd_quic_tls API.
- **Inputs**:
    - `argc`: The number of command-line arguments.
    - `argv`: An array of command-line argument strings.
- **Control Flow**:
    - Initialize the environment with `fd_boot` and set up a random number generator `rng`.
    - Generate a certificate key using `fd_tls_test_sign_ctx` and configure QUIC-TLS parameters in `cfg`.
    - Decode and dump transport parameters from `test_tp` to `tmp_tp` and output them to `stdout`.
    - Create a new QUIC-TLS context `quic_tls` with the configuration `cfg`.
    - Initialize client and server QUIC-TLS handshake contexts `hs_client` and `hs_server` with `fd_quic_tls_hs_new`.
    - Enter a loop to simulate the handshake process, iterating up to 16 times.
    - Within the loop, check for handshake data to transfer between client and server, using `fd_quic_tls_get_hs_data` and [`fd_quic_tls_provide_data`](#fd_quic_tls_provide_data).
    - Log debug information about the handshake data being transferred.
    - Check if both client and server handshakes are complete and log the status.
    - If both handshakes are complete and no more data is available, break the loop.
    - Verify that both client and server are in the connected state using `FD_TEST`.
    - Delete the handshake contexts and the QUIC-TLS context, and clean up the random number generator.
    - Log a notice indicating the test passed and halt the program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_tls_provide_data`](#fd_quic_tls_provide_data)


