# Purpose
This C source code file is designed to test the functionality of a TLS (Transport Layer Security) protocol implementation, specifically focusing on the TLS 1.3 version. The file includes a series of test functions that validate the encoding and decoding of TLS handshake messages, such as ClientHello and ServerHello, as well as the integration of client-server communication using TLS. The code imports binary fixtures of captured TLS messages to simulate real-world scenarios and ensure the correctness of the TLS protocol operations. It also includes tests for handling incorrect cipher suites, which are crucial for ensuring the robustness and security of the TLS implementation.

The file is structured to provide a comprehensive suite of tests for the TLS protocol, including serialization and deserialization of handshake messages, client-server integration tests, and error handling scenarios. It utilizes static assertions to verify data structure sizes and employs mock certificates for testing purposes. The code is intended to be executed as a standalone program, as indicated by the presence of a [`main`](#main) function, which orchestrates the execution of various test cases. This file is a critical component for developers working on TLS implementations, as it helps ensure that the protocol behaves correctly and securely under different conditions.
# Imports and Dependencies

---
- `fd_tls_proto.h`
- `../../ballet/x509/fd_x509_mock.h`
- `fd_tls.h`
- `test_tls_helper.h`
- `../../ballet/ed25519/fd_ed25519.h`
- `../../ballet/ed25519/fd_x25519.h`


# Global Variables

---
### test\_server\_out
- **Type**: `test_record_buf_t`
- **Description**: The `test_server_out` variable is a static instance of the `test_record_buf_t` data structure, initialized to zero. It is used to store outgoing test records from the server during TLS protocol testing.
- **Use**: This variable is used to log and send server-side test records during TLS handshake simulations.


---
### test\_client\_out
- **Type**: `test_record_buf_t`
- **Description**: The `test_client_out` variable is a static instance of the `test_record_buf_t` data structure, initialized to zero. This structure is likely used to buffer or store data related to TLS records for the client side in a testing environment.
- **Use**: It is used to store and manage outgoing TLS records from the client during test scenarios.


---
### test\_server\_hs
- **Type**: `static void const *`
- **Description**: The `test_server_hs` variable is a static constant pointer to a void type, initialized to NULL. It is used to hold a reference to a server handshake state during TLS testing.
- **Use**: This variable is used to determine if a message is from the server during the TLS handshake process in the `test_tls_sendmsg` function.


# Functions

---
### test\_client\_hello\_decode<!-- {{#callable:test_client_hello_decode}} -->
The `test_client_hello_decode` function tests the decoding of a TLS ClientHello message and verifies it against an expected structure.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `fd_tls_client_hello_t` structure `client_hello` to zero.
    - Call [`fd_tls_decode_client_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_client_hello) to decode the `test_client_hello` binary data into `client_hello` and store the size of the decoded data in `sz`.
    - Log the result of the decoding process using `FD_LOG_DEBUG`.
    - Assert that the size of the decoded data `sz` matches the expected size `test_client_hello_sz` using `FD_TEST`.
    - Define an expected `fd_tls_client_hello_t` structure `client_hello_expected` with predefined values for various fields such as `random`, `cipher_suites`, `supported_versions`, etc.
    - Clear out QUIC transport parameters, ALPN, and session ID fields in `client_hello` as they will be compared separately.
    - Compare the decoded `client_hello` structure with the expected `client_hello_expected` structure using `memcmp` and assert equality using `FD_TEST`.
- **Output**: The function does not return any value; it performs assertions to verify the correctness of the decoding process.
- **Functions called**:
    - [`fd_tls_decode_client_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_client_hello)


---
### test\_server\_hello\_encode<!-- {{#callable:test_server_hello_encode}} -->
The function `test_server_hello_encode` encodes a predefined TLS server hello message and verifies the encoding process.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `fd_tls_server_hello_t` structure with predefined random bytes, cipher suite, and key share values.
    - Declare a buffer `server_hello_buf` to hold the encoded server hello message.
    - Call [`fd_tls_encode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_encode_server_hello) to encode the `server_hello` structure into `server_hello_buf`, storing the size of the encoded message in `sz`.
    - Use `FD_TEST` to assert that the encoding size `sz` is non-negative, indicating successful encoding.
    - Log the encoded server hello message in hexadecimal format using `FD_LOG_HEXDUMP_DEBUG`.
- **Output**: The function does not return a value; it performs encoding and logging operations as part of a test.
- **Functions called**:
    - [`fd_tls_encode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_encode_server_hello)


---
### test\_server\_hello\_decode<!-- {{#callable:test_server_hello_decode}} -->
The function `test_server_hello_decode` tests the decoding of a TLS ServerHello message by verifying that the decoding process completes successfully.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `fd_tls_server_hello_t` structure named `server_hello` with zero values.
    - Call [`fd_tls_decode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_server_hello) to decode the ServerHello message from the binary data `test_server_hello` starting at the 5th byte and spanning `test_server_hello_sz-4` bytes, storing the result in `server_hello`.
    - Check if the size `sz` returned by [`fd_tls_decode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_server_hello) is non-negative using `FD_TEST`, indicating successful decoding.
- **Output**: The function does not return any value; it performs a test and asserts the success of the decoding operation.
- **Functions called**:
    - [`fd_tls_decode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_server_hello)


---
### test\_server\_finished\_decode<!-- {{#callable:test_server_finished_decode}} -->
The `test_server_finished_decode` function tests the decoding of a TLS server 'Finished' message using a predefined binary fixture.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `fd_tls_finished_t` structure named `finished` with zero values.
    - Call `fd_tls_decode_finished` to decode the server 'Finished' message from the `test_server_finished` binary data, starting from the 5th byte and using the size reduced by 4 bytes.
    - Store the result of the decoding operation in the variable `sz`.
    - Use `FD_TEST` to assert that the size `sz` is non-negative, indicating successful decoding.
- **Output**: The function does not return any value; it performs an assertion to verify successful decoding.


---
### test\_tls\_proto<!-- {{#callable:test_tls_proto}} -->
The `test_tls_proto` function executes a series of tests to validate the encoding and decoding of TLS protocol messages, specifically ClientHello, ServerHello, and ServerFinished messages.
- **Inputs**: None
- **Control Flow**:
    - The function calls [`test_client_hello_decode`](#test_client_hello_decode) to test the decoding of a ClientHello message.
    - It then calls [`test_server_hello_encode`](#test_server_hello_encode) to test the encoding of a ServerHello message.
    - Next, it calls [`test_server_hello_decode`](#test_server_hello_decode) to test the decoding of a ServerHello message.
    - Finally, it calls [`test_server_finished_decode`](#test_server_finished_decode) to test the decoding of a ServerFinished message.
- **Output**: The function does not return any value; it performs tests and likely logs results or assertions internally.
- **Functions called**:
    - [`test_client_hello_decode`](#test_client_hello_decode)
    - [`test_server_hello_encode`](#test_server_hello_encode)
    - [`test_server_hello_decode`](#test_server_hello_decode)
    - [`test_server_finished_decode`](#test_server_finished_decode)


---
### test\_tls\_sendmsg<!-- {{#callable:test_tls_sendmsg}} -->
The `test_tls_sendmsg` function logs and sends a TLS record, determining the direction based on the handshake context.
- **Inputs**:
    - `hs`: A pointer to the handshake context, used to determine if the message is from the server.
    - `record`: A pointer to the TLS record data to be sent.
    - `record_sz`: The size of the TLS record data.
    - `encryption_level`: The encryption level at which the record should be sent.
    - `flush`: An integer indicating whether to flush the output, though it is not used in this function.
- **Control Flow**:
    - The function first checks if the handshake context `hs` is equal to `test_server_hs` to determine if the message is from the server.
    - It logs the record using [`test_record_log`](test_tls_helper.h.driver.md#test_record_log), passing the record data, size, and the direction (from server or not).
    - It sends the record using [`test_record_send`](test_tls_helper.h.driver.md#test_record_send), choosing the appropriate output buffer (`test_server_out` or `test_client_out`) based on the direction, along with the encryption level, record data, and size.
    - The function returns 1, indicating successful execution.
- **Output**: The function returns an integer value of 1, indicating successful execution.
- **Functions called**:
    - [`test_record_log`](test_tls_helper.h.driver.md#test_record_log)
    - [`test_record_send`](test_tls_helper.h.driver.md#test_record_send)


---
### test\_tls\_client\_respond<!-- {{#callable:test_tls_client_respond}} -->
The function `test_tls_client_respond` processes incoming TLS records from a server and performs a client-side handshake, logging errors if the handshake fails.
- **Inputs**:
    - `client`: A pointer to an `fd_tls_t` structure representing the TLS client.
    - `hs`: A pointer to an `fd_tls_estate_cli_t` structure representing the client's handshake state.
- **Control Flow**:
    - Initialize a pointer `rec` to hold received records.
    - Enter a loop that continues as long as `test_record_recv` returns a non-null record from `test_server_out`.
    - For each received record, call [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake) with the client, handshake state, and record details.
    - If the handshake result `res` is negative, indicating an error, call `fd_halt` to stop execution and log an error message with details about the failure.
- **Output**: The function does not return a value; it performs operations and logs errors if they occur.
- **Functions called**:
    - [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake)
    - [`fd_tls_alert_cstr`](fd_tls.c.driver.md#fd_tls_alert_cstr)
    - [`fd_tls_reason_cstr`](fd_tls.c.driver.md#fd_tls_reason_cstr)


---
### test\_tls\_server\_respond<!-- {{#callable:test_tls_server_respond}} -->
The `test_tls_server_respond` function processes incoming TLS records from a client and performs a server-side handshake, logging errors if the handshake fails.
- **Inputs**:
    - `server`: A pointer to an `fd_tls_t` structure representing the server's TLS context.
    - `hs`: A pointer to an `fd_tls_estate_srv_t` structure representing the server's handshake state.
- **Control Flow**:
    - Initialize a pointer `rec` to hold received records.
    - Enter a loop that continues as long as `test_record_recv` returns a non-null record from `test_client_out`.
    - For each received record, call [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake) with the server, handshake state, and record details.
    - Check if the result of [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake) is negative, indicating a failure.
    - If a failure occurs, log an error message with details about the alert and reason for the failure.
- **Output**: The function does not return a value; it performs operations and logs errors as side effects.
- **Functions called**:
    - [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake)
    - [`fd_tls_alert_cstr`](fd_tls.c.driver.md#fd_tls_alert_cstr)
    - [`fd_tls_reason_cstr`](fd_tls.c.driver.md#fd_tls_reason_cstr)


---
### test\_tls\_secrets<!-- {{#callable:test_tls_secrets}} -->
The `test_tls_secrets` function is a placeholder function intended to handle TLS secret management but currently does nothing.
- **Inputs**:
    - `handshake`: A pointer to the handshake data, marked as unused.
    - `recv_secret`: A pointer to the received secret data, marked as unused.
    - `send_secret`: A pointer to the sent secret data, marked as unused.
    - `encryption_level`: An unsigned integer representing the encryption level, marked as unused.
- **Control Flow**:
    - The function is defined as static, meaning it is limited to the file scope.
    - All input parameters are marked with `FD_FN_UNUSED`, indicating they are not used within the function body.
    - The function body is empty, indicating no operations are performed.
- **Output**: The function does not produce any output or perform any operations.


---
### prepare\_tls\_pair<!-- {{#callable:prepare_tls_pair}} -->
The `prepare_tls_pair` function initializes and configures a pair of TLS client and server objects with random keys and mock certificates for testing purposes.
- **Inputs**:
    - `rng`: A pointer to a random number generator object used for generating random values.
    - `client`: A pointer to an `fd_tls_t` structure that will be initialized as a TLS client.
    - `server`: A pointer to an `fd_tls_t` structure that will be initialized as a TLS server.
- **Control Flow**:
    - Initialize static signing contexts for both client and server using [`fd_tls_test_sign_ctx`](test_tls_helper.h.driver.md#fd_tls_test_sign_ctx) with the provided random number generator.
    - Configure the `client` and `server` structures with random number generation, signing functions, and predefined secret and message sending functions.
    - Generate 32-byte private keys for both client and server using `fd_rng_uchar` and store them in their respective structures.
    - Copy the public keys from the signing contexts to the client and server structures using `fd_memcpy`.
    - Create mock X.509 certificates for both client and server using `fd_x509_mock_cert` and set their sizes to `FD_X509_MOCK_CERT_SZ`.
    - Compute the public keys for key exchange using `fd_x25519_public` for both client and server.
- **Output**: The function does not return a value; it modifies the `client` and `server` structures in place.
- **Functions called**:
    - [`fd_tls_test_sign_ctx`](test_tls_helper.h.driver.md#fd_tls_test_sign_ctx)
    - [`fd_tls_rand_t::fd_tls_test_rand`](test_tls_helper.h.driver.md#fd_tls_rand_tfd_tls_test_rand)
    - [`fd_tls_sign_t::fd_tls_test_sign`](test_tls_helper.h.driver.md#fd_tls_sign_tfd_tls_test_sign)


---
### test\_tls\_pair<!-- {{#callable:test_tls_pair}} -->
The `test_tls_pair` function sets up and tests a TLS handshake between a client and server, ensuring they successfully connect.
- **Inputs**:
    - `rng`: A pointer to a random number generator object used for generating cryptographic keys and randomness.
- **Control Flow**:
    - Initialize client and server TLS objects using [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new) and [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join).
    - Prepare the TLS pair by setting up cryptographic keys and contexts using [`prepare_tls_pair`](#prepare_tls_pair).
    - Create server and client handshake objects using `fd_tls_estate_srv_new` and `fd_tls_estate_cli_new`.
    - Copy the server's public key to the client's handshake object.
    - Perform the TLS handshake by sending and responding to handshake messages between the client and server.
    - Verify that both client and server have reached the connected state.
    - Clean up by deleting handshake objects and TLS objects.
- **Output**: The function does not return a value; it performs tests and asserts to ensure the TLS handshake is successful.
- **Functions called**:
    - [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join)
    - [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new)
    - [`prepare_tls_pair`](#prepare_tls_pair)
    - [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake)
    - [`test_tls_server_respond`](#test_tls_server_respond)
    - [`test_tls_client_respond`](#test_tls_client_respond)
    - [`fd_tls_estate_srv_delete`](fd_tls_estate.h.driver.md#fd_tls_estate_srv_delete)
    - [`fd_tls_estate_cli_delete`](fd_tls_estate.h.driver.md#fd_tls_estate_cli_delete)
    - [`fd_tls_delete`](fd_tls.c.driver.md#fd_tls_delete)
    - [`fd_tls_leave`](fd_tls.c.driver.md#fd_tls_leave)


---
### test\_tls\_client\_wrong\_ciphersuite<!-- {{#callable:test_tls_client_wrong_ciphersuite}} -->
The function `test_tls_client_wrong_ciphersuite` tests the TLS handshake process by simulating a client sending a ClientHello message with unsupported cipher suites, expecting the server to respond with a handshake failure alert.
- **Inputs**:
    - `rng`: A pointer to a random number generator object (`fd_rng_t`) used for generating cryptographic keys and other random values.
- **Control Flow**:
    - Initialize client and server TLS objects using [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join) and [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new).
    - Prepare the client and server TLS pair using [`prepare_tls_pair`](#prepare_tls_pair), which sets up cryptographic keys and certificates.
    - Create server and client handshake state objects (`fd_tls_estate_srv_t` and `fd_tls_estate_cli_t`) and initialize them with `fd_tls_estate_srv_new` and `fd_tls_estate_cli_new`.
    - Copy the server's public key to the client's handshake state object.
    - Define a static `client_hello` message containing unsupported cipher suites.
    - Invoke [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake) with the server object, server handshake state, and the `client_hello` message, expecting it to return a handshake failure alert.
    - Verify that the alert returned is `-FD_TLS_ALERT_HANDSHAKE_FAILURE` and the reason is `FD_TLS_REASON_CH_NEG_CIPHER`.
    - Clean up by deleting the handshake state objects and TLS objects.
- **Output**: The function does not return a value; it performs assertions to verify the expected behavior of the TLS handshake process when unsupported cipher suites are used.
- **Functions called**:
    - [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join)
    - [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new)
    - [`prepare_tls_pair`](#prepare_tls_pair)
    - [`fd_tls_server_handshake`](fd_tls.c.driver.md#fd_tls_server_handshake)
    - [`fd_tls_estate_srv_delete`](fd_tls_estate.h.driver.md#fd_tls_estate_srv_delete)
    - [`fd_tls_estate_cli_delete`](fd_tls_estate.h.driver.md#fd_tls_estate_cli_delete)
    - [`fd_tls_delete`](fd_tls.c.driver.md#fd_tls_delete)
    - [`fd_tls_leave`](fd_tls.c.driver.md#fd_tls_leave)


---
### test\_tls\_server\_wrong\_ciphersuite<!-- {{#callable:test_tls_server_wrong_ciphersuite}} -->
The function `test_tls_server_wrong_ciphersuite` tests the behavior of a TLS server when it receives a ServerHello message with a cipher suite not offered by the client, expecting an illegal parameter alert.
- **Inputs**:
    - `rng`: A pointer to a random number generator object used for cryptographic operations.
- **Control Flow**:
    - Initialize client and server TLS objects using [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join) and [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new).
    - Prepare the TLS client-server pair using [`prepare_tls_pair`](#prepare_tls_pair), which sets up cryptographic keys and certificates.
    - Create server and client handshake objects using `fd_tls_estate_srv_new` and `fd_tls_estate_cli_new`.
    - Copy the server's public key to the client's handshake object.
    - Initiate a ClientHello message from the client using [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake).
    - Send a ServerHello message from the server with a cipher suite not offered by the client.
    - Invoke [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake) on the server with the crafted ServerHello message and check for an illegal parameter alert.
    - Verify that the client's handshake reason is set to `FD_TLS_REASON_SH_PARSE`.
    - Clean up by deleting the handshake objects and TLS objects.
- **Output**: The function does not return a value but asserts that the server responds with an illegal parameter alert when a mismatched cipher suite is used.
- **Functions called**:
    - [`fd_tls_join`](fd_tls.c.driver.md#fd_tls_join)
    - [`fd_tls_new`](fd_tls.c.driver.md#fd_tls_new)
    - [`prepare_tls_pair`](#prepare_tls_pair)
    - [`fd_tls_client_handshake`](fd_tls.c.driver.md#fd_tls_client_handshake)
    - [`fd_tls_estate_srv_delete`](fd_tls_estate.h.driver.md#fd_tls_estate_srv_delete)
    - [`fd_tls_estate_cli_delete`](fd_tls_estate.h.driver.md#fd_tls_estate_cli_delete)
    - [`fd_tls_delete`](fd_tls.c.driver.md#fd_tls_delete)
    - [`fd_tls_leave`](fd_tls.c.driver.md#fd_tls_leave)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of TLS protocol tests, and then cleans up before exiting.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with the command-line arguments.
    - Create a random number generator instance using `fd_rng_new` and `fd_rng_join`.
    - Execute the [`test_tls_proto`](#test_tls_proto) function to test TLS protocol functionalities.
    - Execute the [`test_tls_pair`](#test_tls_pair) function to test a TLS client-server handshake using the random number generator.
    - Execute the [`test_tls_client_wrong_ciphersuite`](#test_tls_client_wrong_ciphersuite) function to test client behavior with an unsupported cipher suite.
    - Execute the [`test_tls_server_wrong_ciphersuite`](#test_tls_server_wrong_ciphersuite) function to test server behavior with an unsupported cipher suite.
    - Delete the random number generator instance using `fd_rng_leave` and `fd_rng_delete`.
    - Log a notice message indicating the tests passed.
    - Call `fd_halt` to perform any necessary cleanup before exiting.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_tls_proto`](#test_tls_proto)
    - [`test_tls_pair`](#test_tls_pair)
    - [`test_tls_client_wrong_ciphersuite`](#test_tls_client_wrong_ciphersuite)
    - [`test_tls_server_wrong_ciphersuite`](#test_tls_server_wrong_ciphersuite)


