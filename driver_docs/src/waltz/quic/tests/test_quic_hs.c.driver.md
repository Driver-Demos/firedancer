# Purpose
This C source code file is a test program designed to validate the functionality of a QUIC (Quick UDP Internet Connections) implementation. The code sets up a simulated environment where both a QUIC server and client are created and initialized. It tests the handshake process, stream data transmission, and the handling of TLS (Transport Layer Security) handshake caches. The program includes callback functions for handling new connections, receiving stream data, and completing handshakes, which are essential for simulating the QUIC protocol's behavior. The code also includes mechanisms to validate the integrity and order of TLS handshake cache entries, ensuring that the QUIC implementation adheres to expected standards.

The file is structured to perform a series of operations that mimic real-world QUIC interactions, such as establishing connections, sending data over streams, and closing connections. It uses a virtual pair to simulate network communication between the client and server. The program also tests edge cases, such as cache eviction based on time-to-live (TTL) settings, to ensure robustness. The use of logging and assertions throughout the code helps in tracking the execution flow and verifying the correctness of operations. This file is not intended to be a reusable library but rather a standalone executable for testing and validating specific aspects of the QUIC protocol implementation.
# Imports and Dependencies

---
- `../fd_quic.h`
- `../fd_quic_private.h`
- `fd_quic_test_helpers.h`
- `stdio.h`
- `stdlib.h`


# Global Variables

---
### server\_complete
- **Type**: `int`
- **Description**: The `server_complete` variable is a global integer initialized to 0, used to indicate whether the server-side handshake process in a QUIC connection has been completed successfully.
- **Use**: This variable is set to 1 in the `my_connection_new` callback function when the server handshake is complete, allowing the program to check the status of the server handshake.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a global integer initialized to 0, used to track the completion status of the client's handshake process in a QUIC connection.
- **Use**: This variable is set to 1 when the client's handshake is complete, indicating successful establishment of the connection.


---
### server\_conn
- **Type**: `fd_quic_conn_t *`
- **Description**: The `server_conn` is a global pointer variable of type `fd_quic_conn_t *`, which is initially set to `NULL`. It is intended to hold a reference to a QUIC connection object once a server connection is established.
- **Use**: This variable is used to store the server's QUIC connection object after the server handshake is complete, allowing further operations on the connection.


---
### now
- **Type**: `ulong`
- **Description**: The `now` variable is a global variable of type `ulong` initialized to 123. It acts as a simple counter or clock within the program.
- **Use**: This variable is used to simulate a clock or time progression in the QUIC test environment, particularly for testing TLS cache eviction based on time-to-live (TTL) conditions.


# Functions

---
### my\_stream\_rx\_cb<!-- {{#callable:my_stream_rx_cb}} -->
The `my_stream_rx_cb` function processes received QUIC stream data, ensuring it meets specific conditions before returning success.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection object, which is not used in this function.
    - `stream_id`: The identifier of the stream from which data is received.
    - `offset`: The offset in the stream where the data starts.
    - `data`: A pointer to the received data buffer.
    - `data_sz`: The size of the received data buffer.
    - `fin`: An integer flag indicating if this is the final data chunk (0 for not final).
- **Control Flow**:
    - Log the stream ID, data size, and offset for debugging purposes.
    - Check if the offset is aligned to 512 bytes using `fd_ulong_is_aligned`.
    - Log a hex dump of the received data for debugging purposes.
    - Verify that the size of the data is exactly 512 bytes.
    - Ensure that the `fin` flag is not set, indicating this is not the final data chunk.
    - Check that the first 11 bytes of the data match the string "Hello world".
    - Return `FD_QUIC_SUCCESS` to indicate successful processing.
- **Output**: The function returns `FD_QUIC_SUCCESS` if all conditions are met, indicating successful processing of the received data.


---
### my\_connection\_new<!-- {{#callable:my_connection_new}} -->
The `my_connection_new` function logs the completion of a server handshake and updates global variables to indicate the server connection is complete and store the connection object.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection.
    - `vp_context`: A void pointer to a context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `vp_context` to void to indicate it is unused.
    - A log message is generated to indicate that the server handshake is complete.
    - The global variable `server_complete` is set to 1, indicating the server connection is complete.
    - The global variable `server_conn` is set to the `conn` parameter, storing the connection object.
- **Output**: This function does not return any value.


---
### my\_handshake\_complete<!-- {{#callable:my_handshake_complete}} -->
The `my_handshake_complete` function logs a notice indicating that a client handshake is complete and sets a global flag to indicate this completion.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection; it is not used in the function.
    - `vp_context`: A void pointer to context data; it is not used in the function.
- **Control Flow**:
    - The function begins by casting the `conn` and `vp_context` parameters to void to indicate they are unused.
    - A log notice is generated with the message 'client handshake complete'.
    - The global variable `client_complete` is set to 1 to indicate that the client handshake has been completed.
- **Output**: The function does not return any value.


---
### validate\_quic\_hs\_tls\_cache<!-- {{#callable:validate_quic_hs_tls_cache}} -->
The `validate_quic_hs_tls_cache` function checks the integrity and order of the QUIC handshake TLS cache by iterating through the cache and verifying that the birth times are non-decreasing and that the cache count matches the used pool count.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC instance whose handshake TLS cache is to be validated.
- **Control Flow**:
    - Retrieve the state of the QUIC instance using `fd_quic_get_state` and store it in `state`.
    - Access the handshake cache and pool from the state and store them in `hs_cache` and `pool`, respectively.
    - Initialize a cache iterator using `fd_quic_tls_hs_cache_iter_fwd_init` to iterate over the handshake cache.
    - Enter a loop that continues until `fd_quic_tls_hs_cache_iter_done` returns true, indicating the end of the cache.
    - Within the loop, retrieve the current handshake element using `fd_quic_tls_hs_cache_iter_ele`.
    - Check that the current element's birth time is greater than or equal to the previous element's birth time using `FD_TEST`.
    - Update `prev_birth` to the current element's birth time and increment `cache_cnt`.
    - After the loop, verify that `cache_cnt` matches the number of used elements in the pool using `fd_quic_tls_hs_pool_used`.
- **Output**: The function does not return a value; it performs validation checks and uses `FD_TEST` to assert conditions, which may terminate the program if the conditions are not met.


---
### test\_clock<!-- {{#callable:test_clock}} -->
The `test_clock` function returns the current value of a global variable `now`, which represents a mock clock time.
- **Inputs**:
    - `ctx`: A void pointer to context data, which is not used in this function.
- **Control Flow**:
    - The function takes a single argument `ctx`, which is cast to void to indicate it is unused.
    - The function returns the value of the global variable `now`.
- **Output**: The function returns an unsigned long integer representing the current mock time from the global variable `now`.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests a QUIC (Quick UDP Internet Connections) server and client, simulating data transmission and validating handshake and stream operations.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and QUIC test framework with `fd_boot` and [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot).
    - Create a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to an actual size using `fd_cstr_to_shmem_page_sz` and log an error if unsupported.
    - Create a new anonymous workspace with the specified page size, count, and NUMA index using `fd_wksp_new_anonymous`.
    - Define QUIC limits and calculate the QUIC footprint using `fd_quic_footprint`.
    - Create server and client QUIC instances with [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous), setting callbacks for connection and stream events.
    - Initialize a virtual pair for the server and client QUICs using [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init).
    - Initialize the QUIC instances with `fd_quic_init` and validate them using `fd_quic_svc_validate`.
    - Create a client connection using `fd_quic_connect` and perform general processing in a loop to run services and validate handshakes.
    - Create streams for the client connection using `fd_quic_conn_new_stream`.
    - Send data over the streams in a loop, alternating between two streams and logging the result of `fd_quic_stream_send`.
    - Close the connections using `fd_quic_conn_close` and validate the QUIC services.
    - Run additional service loops to wait for acknowledgments and validate the TLS handshake cache.
    - Test the TLS cache behavior with different time-to-live (TTL) settings, checking for evictions and allocation failures.
    - Clean up resources by finalizing the virtual pair, deleting QUIC instances, and freeing the workspace and random number generator.
    - Log a final notice of success and halt the QUIC test and program execution.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)
    - [`validate_quic_hs_tls_cache`](#validate_quic_hs_tls_cache)
    - [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)
    - [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt)


