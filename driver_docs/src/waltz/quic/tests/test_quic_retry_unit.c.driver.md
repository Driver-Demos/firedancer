# Purpose
This C source code file is designed to test and benchmark the handling of QUIC protocol retry packets, specifically focusing on the integrity and authentication of retry tokens as specified in RFC 9001. The file includes functions to verify the integrity of retry packets, create retry tokens, and validate these tokens on both the client and server sides. It also includes benchmarks to measure the performance of these operations, providing metrics such as packets per second and time per packet. The code is structured to ensure that retry tokens are authenticated and that they expire as expected, preventing unauthorized or expired tokens from being accepted.

The file is a comprehensive test suite for QUIC retry packet handling, utilizing cryptographic functions to sign and verify integrity tags. It includes several static functions for benchmarking different aspects of retry handling, such as [`bench_retry_create`](#bench_retry_create), [`bench_retry_server_verify`](#bench_retry_server_verify), and [`bench_retry_client_verify`](#bench_retry_client_verify). These functions simulate high-throughput scenarios to assess the efficiency of the retry mechanisms. The file also contains tests for token malleability and expiration, ensuring robustness against potential security threats. The inclusion of detailed logging and hexdump outputs aids in debugging and verifying the correctness of the operations. Overall, this file serves as a critical component in ensuring the security and performance of QUIC protocol implementations.
# Imports and Dependencies

---
- `../crypto/fd_quic_crypto_suites.h`
- `../fd_quic_common.h`
- `../fd_quic_private.h`
- `../fd_quic_retry_private.h`
- `../templ/fd_quic_encoders_decl.h`
- `../templ/fd_quic_frames_templ.h`
- `../templ/fd_quic_templ.h`
- `../templ/fd_quic_undefs.h`
- `../../../ballet/aes/fd_aes_gcm.h`


# Functions

---
### test\_retry\_integrity\_tag<!-- {{#callable:test_retry_integrity_tag}} -->
The function `test_retry_integrity_tag` verifies the implementation of retry integrity tag signing and verification using a sample retry packet from RFC 9001.
- **Inputs**: None
- **Control Flow**:
    - Initialize an AES-GCM context `aes_gcm`.
    - Define a static array `retry_a41` representing a sample retry packet and a static `fd_quic_conn_id_t` structure `conn_id_a41` for connection ID.
    - Create a pseudo packet `retry_pseudo_pkt` using `fd_quic_retry_pseudo` and verify its length and content against `pseudo_a41`.
    - Log a warning if the pseudo packet does not match the expected content.
    - Generate a retry integrity tag using `fd_quic_retry_integrity_tag_sign` and verify it against the expected tag in `retry_a41`.
    - Perform a client-side verification of the retry packet using `fd_quic_retry_client_verify` and check for success.
- **Output**: The function does not return any value; it performs tests and logs warnings if any mismatches occur.


---
### bench\_retry\_create<!-- {{#callable:bench_retry_create}} -->
The `bench_retry_create` function benchmarks the performance of the `fd_quic_retry_create` function by measuring the time taken to create retry tokens over a large number of iterations.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the benchmarking process with a notice message.
    - Initializes a random number generator (RNG) using `fd_rng_new` and `fd_rng_join`.
    - Defines and initializes various variables including retry token buffer, packet, connection IDs, AES key, AES IV, and TTL.
    - Calls `fd_quic_retry_create` once to create a retry token and logs the token data using a hex dump.
    - Starts a timer using `fd_log_wallclock` to measure the time taken for a million iterations of retry token creation.
    - Performs a loop for a million iterations, calling `fd_quic_retry_create` in each iteration to create a retry token and uses `FD_COMPILER_UNPREDICTABLE` to prevent compiler optimizations on the retry token.
    - Stops the timer and calculates the million packets per second (Mpps) and nanoseconds per packet (ns) based on the elapsed time.
    - Logs the calculated Mpps and ns values as notice messages.
    - Cleans up the RNG by leaving and deleting it using `fd_rng_leave` and `fd_rng_delete`.
- **Output**: The function does not return any value; it logs performance metrics to the console.


---
### bench\_retry\_server\_verify<!-- {{#callable:bench_retry_server_verify}} -->
The `bench_retry_server_verify` function benchmarks the performance of the `fd_quic_retry_server_verify` function by measuring its execution time over a large number of iterations.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the benchmarking process with a notice message.
    - Initializes a static token array with predefined values.
    - Creates a random number generator (RNG) instance for use in the function.
    - Defines a constant packet structure `pkt` and initializes an `fd_quic_initial_t` structure with a destination connection ID length and the static token.
    - Initializes variables for original destination connection ID (`odcid`) and retry source connection ID (`rscid`).
    - Sets up AES key and IV arrays, and defines the current time (`now`) and time-to-live (`ttl`) for the token.
    - Starts a timer to measure the wall-clock time before entering a loop for benchmarking.
    - Executes a loop for 1,000,000 iterations, where in each iteration it calls `fd_quic_retry_server_verify` with the packet, initial structure, connection IDs, AES key, IV, current time, and TTL, and checks if the result is successful.
    - Stops the timer and calculates the elapsed time.
    - Computes the million packets per second (Mpps) and nanoseconds per packet based on the elapsed time and logs these metrics.
    - Deletes the RNG instance to clean up resources.
- **Output**: The function does not return any value; it logs performance metrics to the console.


---
### bench\_retry\_client\_verify<!-- {{#callable:bench_retry_client_verify}} -->
The `bench_retry_client_verify` function benchmarks the performance of the `fd_quic_retry_client_verify` function by repeatedly verifying a retry packet and measuring the throughput and latency.
- **Inputs**: None
- **Control Flow**:
    - Log a notice indicating the start of the benchmark for Retry Client Verify.
    - Define a static array `retry` containing a sample retry packet data.
    - Initialize `orig_dst_conn_id` with a size of 8 and declare `src_conn_id`, `token`, and `token_sz`.
    - Record the start time using `fd_log_wallclock()`.
    - Set the number of iterations to 1,000,000.
    - Loop over the number of iterations, calling `fd_quic_retry_client_verify` with the retry packet and checking that the result is `FD_QUIC_SUCCESS`.
    - Record the end time and calculate the elapsed time.
    - Compute the million packets per second (Mpps) and nanoseconds per packet (ns) based on the elapsed time and number of iterations.
    - Log the calculated Mpps and ns per packet.
- **Output**: The function does not return any value; it logs the performance metrics of the retry client verification process.


---
### test\_retry\_token\_malleability<!-- {{#callable:test_retry_token_malleability}} -->
The function `test_retry_token_malleability` tests the robustness of retry token verification by flipping each bit of a retry token and ensuring that the verification fails, while also verifying that a server can correctly verify a valid token.
- **Inputs**: None
- **Control Flow**:
    - Initialize a static array `retry` with predefined values representing a retry token.
    - Define a constant `orig_dst_conn_id` with a size of 8 and a variable `src_conn_id`.
    - Iterate over each byte of the `retry` array.
    - For each byte, iterate over each bit position (0 to 7).
    - Flip the current bit of the current byte in the `retry` array using XOR operation.
    - Call `fd_quic_retry_client_verify` to verify the modified retry token, expecting it to fail (return `FD_QUIC_FAILED`).
    - Restore the original bit by flipping it back using XOR operation.
    - Define a static array `token` with predefined values representing a valid token.
    - Initialize an `fd_quic_initial_t` structure `initial` with the `token` and its size.
    - Define a constant `pkt` and initialize AES key and IV arrays.
    - Set `now` to 50 and `ttl` to 3e9.
    - Iterate over each byte of the `token` array.
    - For each byte, iterate over each bit position (0 to 7).
    - Flip the current bit of the current byte in the `retry` array using XOR operation.
    - Call `fd_quic_retry_server_verify` to verify the modified token, expecting it to succeed (return `FD_QUIC_SUCCESS`).
    - Restore the original bit by flipping it back using XOR operation.
- **Output**: The function does not return any value; it performs tests and uses assertions to verify expected outcomes.


---
### test\_retry\_token\_time<!-- {{#callable:test_retry_token_time}} -->
The `test_retry_token_time` function tests the expiration behavior of retry tokens by verifying them at different timestamps against expected outcomes.
- **Inputs**: None
- **Control Flow**:
    - Define a static array `token` with predefined values representing a retry token.
    - Initialize a `fd_quic_initial_t` structure `initial` with a destination connection ID length of 8 and assign the `token` and its length to it.
    - Define a constant `fd_quic_pkt_t` structure `pkt` initialized to zero.
    - Define arrays `aes_key` and `aes_iv` with specific values and a `ttl` (time-to-live) value of 3 billion.
    - Declare variables `odcid` and `rscid` for connection ID and retry source connection ID respectively.
    - Use a macro `TRY` to test the `fd_quic_retry_server_verify` function with different timestamps and check if the result matches the expected outcome (`FD_QUIC_FAILED` or `FD_QUIC_SUCCESS`).
    - The macro `TRY` is used multiple times with different timestamp values to verify the token's validity at those times.
- **Output**: The function does not return any value; it uses assertions to verify the expected outcomes of the retry token verification at different timestamps.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests and benchmarks related to QUIC retry mechanisms, logs a success message, and then halts the program.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - The function begins by calling `fd_boot` to initialize the environment with the command-line arguments.
    - It sequentially calls several functions: [`test_retry_integrity_tag`](#test_retry_integrity_tag), [`bench_retry_create`](#bench_retry_create), [`bench_retry_server_verify`](#bench_retry_server_verify), [`bench_retry_client_verify`](#bench_retry_client_verify), [`test_retry_token_malleability`](#test_retry_token_malleability), and [`test_retry_token_time`](#test_retry_token_time), each performing specific tests or benchmarks related to QUIC retry mechanisms.
    - After executing all tests and benchmarks, it logs a notice message indicating success using `FD_LOG_NOTICE`.
    - Finally, it calls `fd_halt` to clean up and terminate the program, and returns 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_retry_integrity_tag`](#test_retry_integrity_tag)
    - [`bench_retry_create`](#bench_retry_create)
    - [`bench_retry_server_verify`](#bench_retry_server_verify)
    - [`bench_retry_client_verify`](#bench_retry_client_verify)
    - [`test_retry_token_malleability`](#test_retry_token_malleability)
    - [`test_retry_token_time`](#test_retry_token_time)


