# Purpose
This C source code file is designed to test the interoperability between an OpenSSL client and an `fd_tls` server, as well as an `fd_tls` client and an OpenSSL server. The file includes functions that facilitate the handshake process between these entities using the TLS protocol, specifically focusing on the QUIC transport layer. The code is structured to handle encryption level mapping, secret management, and message recording for both OpenSSL and `fd_tls` implementations. It includes functions to simulate the handshake process, manage cryptographic keys, and handle QUIC transport parameters, ensuring that both client and server can establish a secure connection.

The file is not intended to be a standalone executable but rather a test suite for verifying the correct implementation of TLS handshakes between OpenSSL and `fd_tls`. It includes various callback functions for OpenSSL, such as those for handling alerts, logging information, and managing ALPN (Application-Layer Protocol Negotiation). The code also sets up cryptographic keys and certificates using mock data to simulate real-world scenarios. The main function initializes the OpenSSL context, configures the necessary parameters, and runs tests for both server and client scenarios, ensuring that the handshake process is completed successfully. This file is crucial for developers working on integrating or testing TLS implementations in environments where both OpenSSL and `fd_tls` are used.
# Imports and Dependencies

---
- `fd_tls.h`
- `fd_tls_proto.h`
- `../../ballet/ed25519/fd_ed25519.h`
- `../../ballet/ed25519/fd_x25519.h`
- `../../ballet/x509/fd_x509_mock.h`
- `../quic/fd_quic_common.h`
- `../quic/templ/fd_quic_transport_params.h`
- `openssl/ssl.h`
- `openssl/evp.h`
- `openssl/err.h`
- `openssl/tls1.h`
- `test_tls_helper.h`


# Global Variables

---
### \_is\_ossl\_to\_fd
- **Type**: `uchar`
- **Description**: The variable `_is_ossl_to_fd` is a static unsigned character (uchar) initialized to 0. It is used as a flag to indicate the direction of communication between OpenSSL and fd_tls.
- **Use**: This variable is used to determine the direction of message logging and sending, specifically whether the communication is from OpenSSL to fd_tls or vice versa.


---
### \_ossl\_level\_to\_fdtls
- **Type**: `array of unsigned integers`
- **Description**: The `_ossl_level_to_fdtls` is a static array that maps OpenSSL encryption levels to corresponding fd_tls encryption levels. It is used to translate between the encryption level constants defined by OpenSSL and those used in the fd_tls library.
- **Use**: This variable is used to convert OpenSSL encryption levels to fd_tls encryption levels during the TLS handshake process.


---
### \_fdtls\_level\_to\_ossl
- **Type**: `OSSL_ENCRYPTION_LEVEL const[]`
- **Description**: The `_fdtls_level_to_ossl` is a static constant array that maps internal TLS encryption levels used in the fd_tls library to the corresponding OpenSSL encryption levels. It is defined with four elements, each corresponding to a specific encryption level used during the TLS handshake process.
- **Use**: This array is used to translate fd_tls encryption levels to OpenSSL encryption levels during the TLS handshake process.


---
### secret
- **Type**: `uchar[32UL][2][4][2]`
- **Description**: The `secret` variable is a static multi-dimensional array of unsigned characters (uchar) with dimensions 32x2x4x2, initialized to zero. It is used to store cryptographic secrets during the TLS handshake process.
- **Use**: This variable is used to store read and write secrets for different encryption levels during the TLS handshake.


---
### \_ossl\_out
- **Type**: `test_record_buf_t`
- **Description**: The variable `_ossl_out` is a static instance of the `test_record_buf_t` structure, initialized to zero. This structure is likely used to buffer or manage records in a test environment, particularly for handling OpenSSL output in a TLS handshake scenario.
- **Use**: It is used to store and manage outgoing records from OpenSSL during the testing of TLS handshakes.


---
### \_fdtls\_out
- **Type**: `test_record_buf_t`
- **Description**: The variable `_fdtls_out` is a static instance of the `test_record_buf_t` structure, initialized to zero. This structure is likely used to buffer or store records related to the fd_tls (Fast Data Transport Layer Security) protocol operations.
- **Use**: It is used to store and manage outgoing records in the fd_tls protocol during testing.


---
### tp\_buf
- **Type**: `uchar const[]`
- **Description**: `tp_buf` is a static constant array of unsigned characters (uchar) initialized with four hexadecimal values: 0x01, 0x02, 0x47, and 0xd0. This array is used to store hardcoded QUIC transport parameters.
- **Use**: `tp_buf` is used in the function `_fdtls_quic_tp_self` to copy its contents into a buffer for QUIC transport parameters during a TLS handshake.


# Functions

---
### \_ossl\_secrets<!-- {{#callable:_ossl_secrets}} -->
The `_ossl_secrets` function stores read and write secrets for a given encryption level in a predefined secret array.
- **Inputs**:
    - `ssl`: A pointer to an SSL structure, which is not used in this function.
    - `enc_level`: The encryption level, of type `OSSL_ENCRYPTION_LEVEL`, which determines where in the secret array the secrets will be stored.
    - `read_secret`: A pointer to the read secret, an array of unsigned characters, which is expected to be 32 bytes long.
    - `write_secret`: A pointer to the write secret, an array of unsigned characters, which is expected to be 32 bytes long.
    - `secret_len`: The length of the secrets, which is expected to be 32 bytes.
- **Control Flow**:
    - The function begins by casting the `ssl` parameter to void to indicate it is unused.
    - It asserts that `secret_len` is 32 using `FD_TEST`.
    - The function maps the `enc_level` to an internal level using the `_ossl_level_to_fdtls` array.
    - It copies the `write_secret` into the `secret` array at the position determined by the mapped level and index 0.
    - It copies the `read_secret` into the `secret` array at the position determined by the mapped level and index 1.
    - The function returns 1 to indicate success.
- **Output**: The function returns an integer value of 1, indicating successful execution.


---
### \_fdtls\_secrets<!-- {{#callable:_fdtls_secrets}} -->
The function `_fdtls_secrets` stores received and sent encryption secrets for a given encryption level in a static array.
- **Inputs**:
    - `handshake`: A constant pointer to handshake data, which is not used in the function.
    - `recv_secret`: A constant pointer to the received encryption secret, expected to be 32 bytes long.
    - `send_secret`: A constant pointer to the sent encryption secret, expected to be 32 bytes long.
    - `encryption_level`: An unsigned integer representing the encryption level at which the secrets are stored.
- **Control Flow**:
    - The function begins by casting the `handshake` parameter to void to indicate it is unused.
    - It then copies 32 bytes from `recv_secret` into the `secret` array at the position corresponding to the given `encryption_level` and index 0.
    - Next, it copies 32 bytes from `send_secret` into the `secret` array at the position corresponding to the given `encryption_level` and index 1.
- **Output**: The function does not return any value; it modifies a static array to store the secrets.


---
### \_ossl\_sendmsg<!-- {{#callable:_ossl_sendmsg}} -->
The `_ossl_sendmsg` function logs and sends a record at a specified encryption level using OpenSSL.
- **Inputs**:
    - `ssl`: A pointer to an SSL structure, representing the SSL/TLS connection.
    - `enc_level`: The encryption level at which the record is to be sent, specified as an `OSSL_ENCRYPTION_LEVEL`.
    - `record`: A pointer to the record data to be sent, represented as an array of unsigned characters.
    - `record_sz`: The size of the record data to be sent, represented as an unsigned long integer.
- **Control Flow**:
    - The function begins by casting the `ssl` parameter to void to indicate it is unused.
    - It calls [`test_record_log`](test_tls_helper.h.driver.md#test_record_log) to log the record data and its size, using the global variable `_is_ossl_to_fd` to determine the direction of the log.
    - It then calls [`test_record_send`](test_tls_helper.h.driver.md#test_record_send) to send the record data to the output buffer `_ossl_out`, using the mapped encryption level from `_ossl_level_to_fdtls` and the provided record and its size.
    - Finally, the function returns 1 to indicate success.
- **Output**: The function returns an integer value of 1, indicating successful execution.
- **Functions called**:
    - [`test_record_log`](test_tls_helper.h.driver.md#test_record_log)
    - [`test_record_send`](test_tls_helper.h.driver.md#test_record_send)


---
### \_fdtls\_sendmsg<!-- {{#callable:_fdtls_sendmsg}} -->
The function `_fdtls_sendmsg` logs and sends a TLS record using a specified encryption level.
- **Inputs**:
    - `handshake`: A pointer to the handshake data, which is not used in this function.
    - `record`: A pointer to the TLS record data to be sent.
    - `record_sz`: The size of the TLS record data in bytes.
    - `encryption_level`: The encryption level at which the record should be sent.
    - `flush`: An integer indicating whether to flush the data, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the `handshake` and `flush` parameters to void to indicate they are unused.
    - It calls [`test_record_log`](test_tls_helper.h.driver.md#test_record_log) to log the record data, using the global variable `_is_ossl_to_fd` to determine the logging direction.
    - It then calls [`test_record_send`](test_tls_helper.h.driver.md#test_record_send) to send the record data using the `_fdtls_out` buffer, the specified `encryption_level`, and the `record` and `record_sz` parameters.
    - Finally, the function returns 1, indicating success.
- **Output**: The function returns an integer value of 1, indicating successful execution.
- **Functions called**:
    - [`test_record_log`](test_tls_helper.h.driver.md#test_record_log)
    - [`test_record_send`](test_tls_helper.h.driver.md#test_record_send)


---
### \_fd\_client\_respond<!-- {{#callable:_fd_client_respond}} -->
The `_fd_client_respond` function processes incoming TLS records for a client and performs the TLS handshake, logging errors and halting execution if the handshake fails.
- **Inputs**:
    - `client`: A pointer to an `fd_tls_t` structure representing the TLS client instance.
    - `hs`: A pointer to an `fd_tls_estate_cli_t` structure representing the client's handshake state.
- **Control Flow**:
    - Initialize a `test_record_t` pointer `rec` to receive records.
    - Enter a loop that continues as long as `test_record_recv` returns a non-null record from `_ossl_out`.
    - For each received record, call [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake) with the client, handshake state, and record details.
    - Check the result of [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake); if it is negative, log an error message with details about the alert and reason, then halt execution using `fd_halt`.
- **Output**: The function does not return a value; it performs operations and may halt execution if an error occurs.
- **Functions called**:
    - [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake)
    - [`fd_tls_alert_cstr`](fd_tls.c.driver.md#fd_tls_alert_cstr)
    - [`fd_tls_reason_cstr`](fd_tls.c.driver.md#fd_tls_reason_cstr)


---
### \_fd\_server\_respond<!-- {{#callable:_fd_server_respond}} -->
The `_fd_server_respond` function processes incoming TLS handshake records for a server and handles any errors that occur during the handshake process.
- **Inputs**:
    - `server`: A pointer to an `fd_tls_t` structure representing the server instance.
    - `hs`: A pointer to an `fd_tls_estate_srv_t` structure representing the server's handshake state.
- **Control Flow**:
    - Initialize a `test_record_t` pointer `rec` to receive records.
    - Enter a loop that continues as long as `test_record_recv` returns a non-null record from `_ossl_out`.
    - For each record, call [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake) with the server, handshake state, and record details.
    - Check the result of [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake); if it is negative, log an error message with details about the alert and reason, then halt execution.
- **Output**: The function does not return a value; it performs operations and may halt execution if an error occurs during the handshake.
- **Functions called**:
    - [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake)
    - [`fd_tls_alert_cstr`](fd_tls.c.driver.md#fd_tls_alert_cstr)
    - [`fd_tls_reason_cstr`](fd_tls.c.driver.md#fd_tls_reason_cstr)


---
### \_ossl\_respond<!-- {{#callable:_ossl_respond}} -->
The `_ossl_respond` function processes incoming test records and performs multiple OpenSSL handshake operations on a given SSL object.
- **Inputs**:
    - `ssl`: A pointer to an SSL object representing the OpenSSL connection context.
- **Control Flow**:
    - Initialize a `test_record_t` pointer `rec` to receive records.
    - Enter a loop that continues as long as `test_record_recv` returns a non-null record from `_fdtls_out`.
    - Log a debug message indicating the message being provided to OpenSSL.
    - Call `SSL_provide_quic_data` with the SSL object, the mapped encryption level, and the record's buffer and current size, asserting that it returns 1.
    - Perform an SSL handshake using `SSL_do_handshake` and assert that the result is non-zero.
    - Retrieve the error code from the handshake result using `SSL_get_error` and assert that it is either 0, `SSL_ERROR_WANT_READ`, or `SSL_ERROR_WANT_WRITE`.
    - Assert that there are no OpenSSL errors using `ERR_get_error`.
    - Perform three additional SSL handshake operations using `SSL_do_handshake`.
- **Output**: The function does not return a value; it operates on the SSL object and processes records.


---
### \_ossl\_flush\_flight<!-- {{#callable:_ossl_flush_flight}} -->
The function `_ossl_flush_flight` is a placeholder function that does nothing with its input and always returns 1.
- **Inputs**:
    - `ssl`: A pointer to an SSL structure, which is not used in the function.
- **Control Flow**:
    - The function takes an SSL pointer as an argument but does not use it, as indicated by the cast to void.
    - The function immediately returns the integer value 1.
- **Output**: The function returns an integer value of 1, indicating success or a no-operation result.


---
### \_fdtls\_quic\_tp\_self<!-- {{#callable:_fdtls_quic_tp_self}} -->
The function `_fdtls_quic_tp_self` copies a predefined QUIC transport parameter buffer to a provided buffer if the provided buffer is large enough.
- **Inputs**:
    - `handshake`: A void pointer to a handshake object, which is not used in this function.
    - `quic_tp`: A pointer to an unsigned char array where the QUIC transport parameters will be copied.
    - `quic_tp_bufsz`: An unsigned long representing the size of the `quic_tp` buffer.
- **Control Flow**:
    - The function begins by casting the `handshake` parameter to void to indicate it is unused.
    - It checks if `quic_tp_bufsz` is greater than or equal to the size of `tp_buf` using `FD_TEST`.
    - If the test passes, it copies the contents of `tp_buf` to `quic_tp` using `fd_memcpy`.
    - The function returns the size of `tp_buf`, which is 4UL.
- **Output**: The function returns an unsigned long value of 4, which is the size of the `tp_buf` array.


---
### \_fdtls\_quic\_tp\_peer<!-- {{#callable:_fdtls_quic_tp_peer}} -->
The function `_fdtls_quic_tp_peer` verifies that the provided QUIC transport parameters match a predefined buffer.
- **Inputs**:
    - `handshake`: A void pointer to a handshake context, which is not used in this function.
    - `quic_tp`: A pointer to an array of unsigned characters representing the QUIC transport parameters to be verified.
    - `quic_tp_sz`: An unsigned long representing the size of the `quic_tp` array.
- **Control Flow**:
    - The function begins by casting the `handshake` parameter to void to indicate it is unused.
    - It asserts that the size of the `quic_tp` array (`quic_tp_sz`) is exactly 4 bytes using `FD_TEST`.
    - It then compares the `quic_tp` array with a predefined buffer `tp_buf` using `memcmp` and asserts that they are identical.
- **Output**: The function does not return any value; it performs assertions to verify the input parameters.


---
### \_ossl\_send\_alert<!-- {{#callable:_ossl_send_alert}} -->
The `_ossl_send_alert` function logs an alert message to the standard error and returns a success indicator.
- **Inputs**:
    - `ssl`: A pointer to an SSL structure, representing the SSL connection context.
    - `level`: The encryption level at which the alert is being sent, represented by the `OSSL_ENCRYPTION_LEVEL` enumeration.
    - `alert`: An unsigned character representing the alert code to be sent.
- **Control Flow**:
    - The function begins by casting the `ssl` and `level` parameters to void to indicate they are unused.
    - It calls `ERR_print_errors_fp` to print any OpenSSL error messages to the standard error stream.
    - It logs an error message using `FD_LOG_ERR`, which includes the alert code and its corresponding short and long description strings obtained from `SSL_alert_desc_string` and `SSL_alert_desc_string_long`.
    - Finally, the function returns 1 to indicate success.
- **Output**: The function returns an integer value of 1, indicating successful execution.


---
### \_ossl\_info<!-- {{#callable:_ossl_info}} -->
The `_ossl_info` function logs OpenSSL information and state changes during SSL operations.
- **Inputs**:
    - `ssl`: A pointer to an SSL structure representing the SSL connection.
    - `type`: An integer representing the type of callback event.
    - `val`: An integer representing a value associated with the callback event.
- **Control Flow**:
    - The function begins by casting the input parameters to void to suppress unused variable warnings.
    - A debug log is generated with the type and value of the OpenSSL callback event.
    - The function checks if the type indicates an SSL state loop using a bitwise AND operation with `SSL_CB_LOOP`.
    - If the condition is true, an informational log is generated with the current OpenSSL state string obtained from `SSL_state_string_long`.
- **Output**: The function does not return any value; it performs logging operations.


---
### \_ossl\_keylog<!-- {{#callable:_ossl_keylog}} -->
The `_ossl_keylog` function logs a debug message containing a line of text related to OpenSSL operations.
- **Inputs**:
    - `ssl`: A pointer to an `SSL` structure, representing the OpenSSL session context, which is not used in this function.
    - `line`: A constant character pointer to a string that contains the line of text to be logged.
- **Control Flow**:
    - The function takes two parameters: `ssl` and `line`, but only `line` is used.
    - The `ssl` parameter is explicitly cast to void to indicate it is unused.
    - The function logs a debug message using `FD_LOG_DEBUG`, formatting the message to include the string `line`.
- **Output**: The function does not return any value; it performs logging as a side effect.


---
### \_ossl\_verify\_callback<!-- {{#callable:_ossl_verify_callback}} -->
The `_ossl_verify_callback` function is a placeholder callback for OpenSSL's certificate verification process that always returns success.
- **Inputs**:
    - `preverify_ok`: An integer indicating whether the pre-verification of the certificate was successful.
    - `ctx`: A pointer to an `X509_STORE_CTX` structure, which contains the context for the certificate verification process.
- **Control Flow**:
    - The function takes two parameters, `preverify_ok` and `ctx`, but does not use them in its logic.
    - It explicitly casts both parameters to void to suppress unused parameter warnings.
    - The function returns 1, indicating that the verification should always be considered successful.
- **Output**: The function returns an integer value of 1, indicating that the certificate verification is always successful.


---
### \_ossl\_alpn\_select<!-- {{#callable:_ossl_alpn_select}} -->
The `_ossl_alpn_select` function attempts to select the next protocol for ALPN (Application-Layer Protocol Negotiation) using OpenSSL's `SSL_select_next_proto` function.
- **Inputs**:
    - `ssl`: A pointer to an SSL structure, representing the SSL/TLS connection.
    - `out`: A pointer to a pointer where the selected protocol will be stored.
    - `outlen`: A pointer to a variable where the length of the selected protocol will be stored.
    - `in`: A pointer to the input buffer containing the list of protocols sent by the client.
    - `inlen`: The length of the input buffer.
    - `arg`: A pointer to additional arguments, not used in this function.
- **Control Flow**:
    - The function begins by casting the `ssl` and `arg` parameters to void to indicate they are unused.
    - It calls `SSL_select_next_proto` to select the next protocol from the client's list, comparing it against the hardcoded protocol `"\xasolana-tpu"`.
    - If `SSL_select_next_proto` returns `OPENSSL_NPN_NEGOTIATED`, indicating a successful negotiation, the function returns `SSL_TLSEXT_ERR_OK`.
    - If the negotiation fails, it logs an error message indicating that ALPN negotiation failed.
- **Output**: The function returns `SSL_TLSEXT_ERR_OK` on successful protocol negotiation, otherwise it logs an error and does not return a specific value.


---
### test\_server<!-- {{#callable:test_server}} -->
The `test_server` function sets up and tests a TLS handshake between an OpenSSL client and an fd_tls server.
- **Inputs**:
    - `ctx`: A pointer to an SSL_CTX structure, which is the context for the OpenSSL connection.
- **Control Flow**:
    - Logs the start of the test and sets a flag indicating the direction of the test.
    - Resets the test record buffers for OpenSSL and fd_tls.
    - Initializes a SHA-512 context for cryptographic operations.
    - Creates and joins a random number generator (RNG) instance.
    - Creates and joins an fd_tls server instance, setting up its configuration including random number generation, secrets handling, message sending, QUIC transport parameters, and signing context.
    - Initializes a server handshake state structure and verifies its creation.
    - Generates an ECDH key pair for the server and sets up the server's public key using Ed25519.
    - Mocks a server certificate using the public key and sets its size.
    - Initializes an OpenSSL SSL object and verifies its creation.
    - Generates a client key pair, sets up the client's private key in the SSL object, and mocks a client certificate using the public key.
    - Sets the SSL object to connect state and configures QUIC transport parameters.
    - Performs the TLS handshake, handling different handshake messages and states, including ClientHello, ServerHello, and Finished messages.
    - Checks if the handshake was successful and logs any errors if not.
    - Cleans up by deleting the server handshake state, the fd_tls server instance, the SSL object, the RNG instance, and the SHA-512 context.
- **Output**: The function does not return a value; it performs a series of operations to test the TLS handshake and logs the results.
- **Functions called**:
    - [`test_record_reset`](test_tls_helper.h.driver.md#test_record_reset)
    - [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join)
    - [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new)
    - [`fd_tls_test_sign_ctx`](test_tls_helper.h.driver.md#fd_tls_test_sign_ctx)
    - [`fd_tls_rand_t::fd_tls_test_rand`](test_tls_helper.h.driver.md#fd_tls_rand_tfd_tls_test_rand)
    - [`fd_tls_sign_t::fd_tls_test_sign`](test_tls_helper.h.driver.md#fd_tls_sign_tfd_tls_test_sign)
    - [`_fd_server_respond`](#_fd_server_respond)
    - [`_ossl_respond`](#_ossl_respond)
    - [`fd_tls_estate_srv_delete`](fd_tls_estate.h.driver.md#fd_tls_estate_srv_delete)
    - [`fd_tls_delete`](fd_tls.c.driver.md#fd_tls_delete)
    - [`fd_tls_leave`](fd_tls.c.driver.md#fd_tls_leave)


---
### test\_client<!-- {{#callable:test_client}} -->
The `test_client` function tests the handshake process between an fd_tls client and an OpenSSL server using TLS and QUIC protocols.
- **Inputs**:
    - `ctx`: A pointer to an SSL_CTX structure, which holds the context for the SSL/TLS connection.
- **Control Flow**:
    - Log the start of the test for fd_tls client to OpenSSL server.
    - Reset the test record buffers for OpenSSL and fd_tls outputs.
    - Initialize SHA-512 and random number generator contexts.
    - Create a new SSL object and set it to accept state for server operations.
    - Generate a server private key and derive the corresponding public key using Ed25519.
    - Create an EVP_PKEY structure for the server's private key and set it for the SSL object.
    - Generate a mock X.509 certificate for the server and set it for the SSL object.
    - Set QUIC transport parameters for the server using a predefined buffer.
    - Create and configure an fd_tls client instance with random, secrets, and message sending functions, and set QUIC and ALPN parameters.
    - Initialize a client handshake state and copy the server's public key into it.
    - Generate and set ECDH and Ed25519 keys for the client.
    - Generate a mock X.509 certificate for the client and set its size.
    - Perform the TLS handshake sequence: ClientHello, server responses, client responses, and NewSessionTicket.
    - Verify the connection state to ensure the handshake was successful.
    - Clean up by deleting the client handshake state, fd_tls client instance, SSL object, random number generator, and SHA-512 context.
- **Output**: The function does not return a value; it performs a series of operations to test the TLS handshake process and logs any errors encountered.
- **Functions called**:
    - [`test_record_reset`](test_tls_helper.h.driver.md#test_record_reset)
    - [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join)
    - [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new)
    - [`fd_tls_test_sign_ctx`](test_tls_helper.h.driver.md#fd_tls_test_sign_ctx)
    - [`fd_tls_rand_t::fd_tls_test_rand`](test_tls_helper.h.driver.md#fd_tls_rand_tfd_tls_test_rand)
    - [`fd_tls_sign_t::fd_tls_test_sign`](test_tls_helper.h.driver.md#fd_tls_sign_tfd_tls_test_sign)
    - [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake)
    - [`_ossl_respond`](#_ossl_respond)
    - [`_fd_client_respond`](#_fd_client_respond)
    - [`fd_tls_estate_cli_delete`](fd_tls_estate.h.driver.md#fd_tls_estate_cli_delete)
    - [`fd_tls_delete`](fd_tls.c.driver.md#fd_tls_delete)
    - [`fd_tls_leave`](fd_tls.c.driver.md#fd_tls_leave)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes OpenSSL, configures a TLS context, and tests both server and client TLS handshakes using the configured context.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Initialize OpenSSL by obtaining a method using `TLS_method` and creating a new SSL context with `SSL_CTX_new`.
    - Set the SSL context to not verify peer certificates using `SSL_CTX_set_verify`.
    - Set the minimum and maximum protocol versions to TLS 1.3 using `SSL_CTX_set_min_proto_version` and `SSL_CTX_set_max_proto_version`.
    - Set the ciphersuites to 'TLS_AES_128_GCM_SHA256' using `SSL_CTX_set_ciphersuites`.
    - Define a QUIC method structure and set it in the SSL context using `SSL_CTX_set_quic_method`.
    - Set various callbacks for the SSL context, including info, keylog, and ALPN selection callbacks.
    - Set ALPN protocols and selection callback using `SSL_CTX_set_alpn_protos` and `SSL_CTX_set_alpn_select_cb`.
    - Test the server with different group lists by calling [`test_server`](#test_server) twice with different configurations.
    - Test the client with and without certificate verification by calling [`test_client`](#test_client) twice with different verification settings.
    - Free the SSL context using `SSL_CTX_free`.
    - Log a notice indicating the tests passed and call `fd_halt` to terminate the program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_server`](#test_server)
    - [`test_client`](#test_client)


