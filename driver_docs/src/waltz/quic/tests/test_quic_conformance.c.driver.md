# Purpose
The provided C source code file is a comprehensive test suite designed to verify the conformance of an implementation of the QUIC protocol, specifically the `fd_quic` component, against the QUIC specification outlined in RFC 9000. This file contains a series of test functions that simulate various scenarios and edge cases to ensure that the `fd_quic` implementation adheres to the protocol's requirements, such as data flow control, stream concurrency, and error handling. Each test function is focused on a specific aspect of the QUIC protocol, such as enforcing stream data limits, handling PING frames, and managing connection states, among others.

The file is structured to include multiple test cases, each encapsulated in a function that sets up a testing environment using a sandbox and a random number generator. The tests are executed within a main function that initializes the necessary resources, runs all the test cases, and then cleans up the resources. The code makes extensive use of assertions to verify that the expected outcomes are achieved, and it logs detailed information for debugging purposes. This test suite is crucial for ensuring the robustness and reliability of the `fd_quic` implementation by systematically validating its behavior against the QUIC protocol's specifications.
# Imports and Dependencies

---
- `fd_quic_sandbox.h`
- `../fd_quic_proto.h`
- `../fd_quic_proto.c`
- `../fd_quic_private.h`
- `../templ/fd_quic_parse_util.h`
- `../../tls/fd_tls_proto.h`
- `../../../disco/metrics/generated/fd_metrics_enums.h`


# Functions

---
### test\_quic\_stream\_data\_limit\_enforcement<!-- {{#callable:test_quic_stream_data_limit_enforcement}} -->
The function `test_quic_stream_data_limit_enforcement` tests the enforcement of stream data limits in a QUIC connection, ensuring that a flow control error is triggered when the data limit is exceeded.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, which represents the testing environment for QUIC connections.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox with the server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Set the initial maximum stream data limit to 1 byte in the sandbox configuration.
    - Establish a new QUIC connection using `fd_quic_sandbox_new_conn_established`.
    - Set the supported stream ID for receiving to a client-initiated unidirectional stream.
    - Encode a stream frame with a length of 2 bytes, which exceeds the set limit, using `fd_quic_encode_stream_frame`.
    - Send the encoded frame using [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame).
    - Check that the connection state is aborted and the reason is a flow control error using `FD_TEST`.
    - Retrieve the last log record from the shared memory log using `fd_quic_log_rx_tail`.
    - Verify that the log record indicates a QUIC connection close event and contains the correct error code and source file information.
- **Output**: The function does not return a value; it uses assertions (`FD_TEST`) to verify that the connection is aborted due to a flow control error and logs the error details.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame)


---
### test\_quic\_stream\_limit\_enforcement<!-- {{#callable:test_quic_stream_limit_enforcement}} -->
The function `test_quic_stream_limit_enforcement` tests the enforcement of stream limits in a QUIC connection, ensuring that exceeding the stream limit results in a connection error.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, representing the testing environment for QUIC operations.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox with the server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Establish a new QUIC connection using `fd_quic_sandbox_new_conn_established`.
    - Set the connection's supported stream ID to a client-initiated unidirectional stream type.
    - Encode a stream frame with a client-initiated unidirectional stream ID, zero offset, zero length, and a FIN flag using `fd_quic_encode_stream_frame`.
    - Send the encoded frame using [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame).
    - Verify that the connection state is set to abort and the reason is a stream limit error using `FD_TEST`.
    - Retrieve the last log record from the shared memory log using `fd_quic_log_rx_tail`.
    - Check that the log record indicates a QUIC connection close event and the error code matches a stream limit error using `FD_TEST`.
    - Log a debug message indicating the source file and line number of the stream limit error.
- **Output**: The function does not return a value; it performs assertions to verify correct behavior and logs debug information.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame)


---
### test\_quic\_stream\_concurrency<!-- {{#callable:test_quic_stream_concurrency}} -->
The function `test_quic_stream_concurrency` tests the ability of a QUIC server to handle a large number of concurrent unidirectional client streams without closing them.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, representing the testing environment for QUIC operations.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox with the server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Establish a new QUIC connection using `fd_quic_sandbox_new_conn_established`.
    - Set the `rx_sup_stream_id` of the connection to a specific value to support unidirectional client streams.
    - Iterate 512 times to simulate the initiation of new streams.
    - In each iteration, encode a stream frame with a client stream ID and send it using [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame).
    - Verify that the connection remains in the active state after each frame is sent.
- **Output**: The function does not return a value; it performs tests and assertions to ensure the QUIC server can handle concurrent streams without errors.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame)


---
### test\_quic\_ping\_frame<!-- {{#callable:test_quic_ping_frame}} -->
The `test_quic_ping_frame` function tests the behavior of a QUIC connection when a PING frame is sent, ensuring that the connection state and acknowledgment generation behave as expected.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, representing the testing environment for QUIC operations.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox with the server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Establish a new QUIC connection using `fd_quic_sandbox_new_conn_established`.
    - Set the `is_elicited` flag of the connection's acknowledgment generator to 0.
    - Assert that the service type of the connection is `FD_QUIC_SVC_WAIT`.
    - Prepare a buffer containing a single byte (0x01) to represent a PING frame.
    - Send the PING frame using [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame).
    - Assert that the connection state is `FD_QUIC_CONN_STATE_ACTIVE`.
    - Assert that the `is_elicited` flag of the acknowledgment generator is set to 1, indicating that an acknowledgment is expected.
    - Assert that the service type of the connection is `FD_QUIC_SVC_ACK_TX`, indicating that an acknowledgment transmission is pending.
- **Output**: The function does not return a value; it uses assertions to verify the expected state and behavior of the QUIC connection after sending a PING frame.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame)


---
### test\_quic\_server\_alpn\_fail<!-- {{#callable:test_quic_server_alpn_fail}} -->
The function `test_quic_server_alpn_fail` tests the QUIC server's handling of an ALPN failure during the TLS handshake process.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, which represents the testing environment for QUIC operations.
    - `rng`: A pointer to an `fd_rng_t` structure, used for generating random numbers, likely for connection ID generation.
- **Control Flow**:
    - Initialize the QUIC sandbox in server mode using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Define a static array `crypto_frame` representing a CRYPTO frame extracted from an Initial Packet.
    - Retrieve the QUIC state and generate random connection IDs for both the server and peer using `fd_rng_ulong`.
    - Create a new QUIC connection object using `fd_quic_conn_create` with the generated connection IDs and predefined IP and port addresses.
    - Initialize a TLS handshake object for the connection using `fd_quic_tls_hs_new`.
    - Send a TLS handshake message using [`fd_quic_sandbox_send_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_frame) with the `crypto_frame`.
    - Verify that the connection state is aborted and the reason is an ALPN failure using `FD_TEST`.
    - Service the QUIC object to process any pending operations using `fd_quic_service`.
    - Retrieve the next packet from the sandbox using [`fd_quic_sandbox_next_packet`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_next_packet) and verify its contents.
    - Decode the initial packet header and verify the decrypted packet number and contents.
    - Check that the connection close frame has the expected error code and frame type.
- **Output**: The function does not return a value; it performs assertions to verify the correct handling of an ALPN failure in a QUIC server context.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_frame)
    - [`fd_quic_sandbox_next_packet`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_next_packet)


---
### test\_quic\_pktnum\_skip<!-- {{#callable:test_quic_pktnum_skip}} -->
The function `test_quic_pktnum_skip` tests the behavior of the QUIC protocol's packet number skipping and ACK transmission under conditions where packet numbers are aggressively skipped.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, which represents the testing environment for QUIC protocol operations.
    - `rng`: A pointer to an `fd_rng_t` structure, which is used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox with the server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Establish a new QUIC connection using `fd_quic_sandbox_new_conn_established`.
    - Verify that the ACK generator's head and tail are both at 0, indicating an empty ACK queue.
    - Fill the ACK transmission buffer by sending ping packets with incrementing packet numbers, ensuring the ACK queue is filled to its capacity (`FD_QUIC_ACK_QUEUE_CNT`).
    - Verify that no packet decryption failures have occurred and that the ACK queue is filled correctly with new ACKs, without any merged, canceled, or no-op ACKs.
    - Send an additional ping packet to overflow the ACK queue, and verify that the `FD_QUIC_ACK_TX_ENOSPC` metric is incremented, indicating a space error in the ACK queue.
- **Output**: The function does not return a value; it performs assertions to verify the correct behavior of the QUIC protocol's packet number handling and ACK transmission.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_ping_pkt`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_ping_pkt)


---
### test\_quic\_conn\_initial\_limits<!-- {{#callable:test_quic_conn_initial_limits}} -->
The function `test_quic_conn_initial_limits` initializes a QUIC connection with specific initial data and stream limits, tests the acceptance of stream frames, and verifies the connection's receive limits.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, which represents the testing environment for QUIC connections.
    - `rng`: A pointer to an `fd_rng_t` structure, which is a random number generator, though it is not used in this function.
- **Control Flow**:
    - Initialize the QUIC sandbox with the server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Retrieve and set the initial transport parameters for maximum data and unidirectional streams.
    - Create a new QUIC connection with specified connection IDs, IP address, and port, ensuring it is in the handshake state.
    - Encode a stream frame and send it using [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame), verifying the connection remains in the handshake state.
    - Check that the connection's receive limits for stream ID and maximum data are as expected.
- **Output**: The function does not return a value; it performs tests and assertions to verify the behavior of the QUIC connection under initial limit conditions.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame)


---
### test\_quic\_rx\_max\_data\_frame<!-- {{#callable:test_quic_rx_max_data_frame}} -->
The function `test_quic_rx_max_data_frame` tests the behavior of a QUIC connection when receiving MAX_DATA frames, ensuring that the connection's state and data limits are correctly updated and acknowledged.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, which provides the testing environment for QUIC operations.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox with the server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init) and set the initial maximum stream data to 1.
    - Establish a new QUIC connection using `fd_quic_sandbox_new_conn_established`.
    - Set the `max_data` field of a `fd_quic_max_data_frame_t` structure to 0x30 and encode it into a buffer using `fd_quic_encode_max_data_frame`.
    - Send the encoded frame using [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame) and verify that the connection state is active, the acknowledgment is elicited, and the maximum data is set to 0x30.
    - Reset the `is_elicited` flag to 0, change the `max_data` to 0x10, encode and send the frame again, and verify that the connection state remains active, the acknowledgment is elicited, and the maximum data remains 0x30.
- **Output**: The function does not return a value; it performs tests and uses assertions to verify the expected behavior of the QUIC connection when handling MAX_DATA frames.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame)


---
### test\_quic\_rx\_max\_streams\_frame<!-- {{#callable:test_quic_rx_max_streams_frame}} -->
The function `test_quic_rx_max_streams_frame` tests the handling of QUIC MAX_STREAMS frames in a sandbox environment, ensuring that the connection state and stream limits are correctly managed.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, representing the testing environment for QUIC operations.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox with a client role and set the initial maximum stream data limit.
    - Establish a new QUIC connection within the sandbox using the provided random number generator.
    - Set up a MAX_STREAMS frame for unidirectional streams with a limit of 0x30 and encode it into a buffer.
    - Verify the encoding was successful and send the frame as a lone frame in the sandbox, checking the connection state and stream ID limits.
    - Reset the `is_elicited` flag and set up a new MAX_STREAMS frame with a decreased limit of 0x10, encode, and send it, verifying the connection state and stream ID limits remain unchanged.
    - Set up a MAX_STREAMS frame for bidirectional streams with a limit of 0x60, encode it, and send it, verifying the connection state and stream ID limits.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correct behavior of the QUIC implementation regarding MAX_STREAMS frames.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame)


---
### test\_quic\_small\_pkt\_ping<!-- {{#callable:test_quic_small_pkt_ping}} -->
The function `test_quic_small_pkt_ping` tests the handling of a small QUIC ping packet in a sandbox environment, ensuring that the packet is correctly processed and acknowledged.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, representing the sandbox environment for testing QUIC connections.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the sandbox with the client role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Establish a new QUIC connection in the sandbox with `fd_quic_sandbox_new_conn_established`, setting its state to active.
    - Set the connection's flags to include a PING request and service the connection with `fd_quic_conn_service`.
    - Retrieve the sent packet using [`fd_quic_sandbox_next_packet`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_next_packet) and log its contents for debugging.
    - Insert the connection into the connection map using `fd_quic_conn_map_insert` to prepare for packet processing.
    - Record the current number of new ACK transmissions from the metrics.
    - Process the packet with `fd_quic_process_packet` and verify that the number of new ACK transmissions has increased by one, indicating successful packet processing.
- **Output**: The function does not return a value but performs assertions to verify the correct processing of a small QUIC ping packet, logging debug information and updating metrics.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_next_packet`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_next_packet)


---
### test\_quic\_parse\_path\_challenge<!-- {{#callable:test_quic_parse_path_challenge}} -->
The function `test_quic_parse_path_challenge` tests the decoding of QUIC path challenge and response frames with various data lengths to ensure correct parsing behavior.
- **Inputs**: None
- **Control Flow**:
    - Initialize `path_challenge` and `path_response` frame structures.
    - Enter a `do-while` loop that executes once.
    - Set up a data array with a specific initial byte value (0x1a) for path challenge tests.
    - Perform a series of tests using `FD_TEST` to check the return value of `fd_quic_decode_path_challenge_frame` with different data lengths (1, 8, 9, and 10 bytes).
    - Change the initial byte of the data array to 0x1b for path response tests.
    - Perform similar tests using `FD_TEST` to check the return value of `fd_quic_decode_path_response_frame` with the same data lengths.
- **Output**: The function does not return any value; it uses assertions to validate the behavior of the decoding functions.


---
### in\_stream\_list<!-- {{#callable:in_stream_list}} -->
The `in_stream_list` function checks if a given stream is present in a linked list of streams, returning 1 if found and 0 otherwise.
- **Inputs**:
    - `stream`: A pointer to the `fd_quic_stream_t` structure representing the stream to search for in the list.
    - `sentinel`: A pointer to the `fd_quic_stream_t` structure that acts as the sentinel node marking the boundaries of the list.
- **Control Flow**:
    - Initialize `curr` to the node following the `sentinel` node.
    - Enter a loop that continues as long as `curr` is not equal to `sentinel` and `curr` is not NULL.
    - Check if `curr` is equal to `stream`; if true, return 1 indicating the stream is in the list.
    - Move `curr` to the next node in the list.
    - If the loop completes without finding the stream, return 0.
- **Output**: Returns 1 if the `stream` is found in the list, otherwise returns 0.


---
### test\_quic\_send\_streams<!-- {{#callable:test_quic_send_streams}} -->
The `test_quic_send_streams` function tests the behavior of QUIC send streams under various conditions, ensuring streams are correctly moved between lists based on their data state.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, representing the testing environment for QUIC operations.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox as a server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Establish a new QUIC connection with `fd_quic_sandbox_new_conn_established` and set `tx_sup_stream_id` to 20.
    - Create an empty stream, add it to `send_streams`, and verify its presence using [`in_stream_list`](#in_stream_list).
    - Generate stream frames with `fd_quic_gen_stream_frames` and verify the stream is moved from `send_streams` to `used_streams`.
    - For two iterations (fin=0 and fin=1), create a big stream, send data, and verify it remains in `send_streams` after frame generation.
    - Reset the `send_streams` list for the next test by setting the sentinel flag.
- **Output**: The function does not return a value; it performs assertions to verify the correct behavior of QUIC send streams.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`in_stream_list`](#in_stream_list)


---
### pretend\_stream<!-- {{#callable:pretend_stream}} -->
The `pretend_stream` function sets specific flags and buffer states for a QUIC stream to simulate an unsent state.
- **Inputs**:
    - `stream`: A pointer to an `fd_quic_stream_t` structure representing the QUIC stream to be modified.
- **Control Flow**:
    - The function sets the `FD_QUIC_STREAM_FLAGS_UNSENT` flag in the `stream_flags` of the provided stream.
    - It sets the `head` of the `tx_buf` to 1, indicating the start of the buffer.
    - It resets the `tx_sent` counter to 0, indicating no data has been sent.
- **Output**: The function does not return any value; it modifies the state of the provided `fd_quic_stream_t` structure in place.


---
### test\_quic\_inflight\_pkt\_limit<!-- {{#callable:test_quic_inflight_pkt_limit}} -->
The function `test_quic_inflight_pkt_limit` tests the enforcement of packet inflight limits in a QUIC connection by simulating packet transmission and checking the metrics for failures when limits are exceeded.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, which provides the testing environment for QUIC operations.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize a QUIC connection using `fd_quic_sandbox_new_conn_established` and verify its active state and packet metadata usage.
    - Set up a single stream for transmission and iterate over a loop to simulate sending 12 packets.
    - For each packet, update the packet number, manually add the stream to the send list, and call `fd_quic_conn_service` to process the packet.
    - Check the metrics to ensure that the 12th packet transmission fails, indicating the enforcement of the inflight packet limit.
    - Define a set of QUIC limits and verify that the minimum inflight frame count per connection is respected by calling `fd_quic_footprint`.
- **Output**: The function does not return a value; it uses assertions to verify the correct behavior of inflight packet limit enforcement.
- **Functions called**:
    - [`pretend_stream`](#pretend_stream)
    - [`in_stream_list`](#in_stream_list)


---
### test\_quic\_conn\_free<!-- {{#callable:test_quic_conn_free}} -->
The `test_quic_conn_free` function tests the proper allocation, deallocation, and validation of QUIC connections within a sandbox environment.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure representing the sandbox environment for testing.
    - `rng`: A pointer to an `fd_rng_t` structure used for random number generation during the test.
- **Control Flow**:
    - Initialize the sandbox for a QUIC server role using [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init).
    - Retrieve the QUIC instance and its state from the sandbox.
    - Determine the maximum number of connections (`conn_max`) from the QUIC limits.
    - Verify that all connection IDs (`our_conn_id`) are initialized to zero, acting as sentinels in the connection map.
    - Validate the QUIC service state using `fd_quic_svc_validate`.
    - Establish a number of new connections up to `conn_max` and validate the service state again.
    - For each connection, ensure it is correctly mapped in the connection ID map, then free the connection and validate its state and mapping.
    - Reallocate connections using a Last-In-First-Out (LIFO) policy, ensuring old connection IDs are replaced and new connections are correctly mapped.
    - Validate that freed connections are counted as 'keys not available' in the metrics by simulating packet handling and checking metrics for key availability.
- **Output**: The function does not return a value but performs a series of tests to ensure connections are correctly managed and validated within the QUIC sandbox environment.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)


---
### test\_quic\_pktmeta\_pktnum\_skip<!-- {{#callable:test_quic_pktmeta_pktnum_skip}} -->
The function `test_quic_pktmeta_pktnum_skip` tests the behavior of packet number incrementation and allocation failure handling in a QUIC connection when packet metadata resources are exhausted.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, representing the testing environment for the QUIC connection.
    - `rng`: A pointer to an `fd_rng_t` structure, used for random number generation within the test.
- **Control Flow**:
    - Initialize the QUIC sandbox with a server role and establish a new QUIC connection.
    - Trigger a series of pings to increment the packet number and verify the incrementation.
    - Allocate all available packet metadata resources, linking them in a list.
    - Verify that the allocation failure count is initially zero.
    - Trigger additional pings with no packet metadata available, ensuring packet numbers do not increase and allocation failures are recorded.
    - Send pings from a peer to verify that acknowledgments can still be sent, incrementing the packet number.
    - Release some packet metadata resources back to the pool.
    - Trigger more pings to verify that packet numbers increment correctly again.
    - Verify that the allocation failure count remains consistent with expectations.
- **Output**: The function does not return a value; it uses assertions to verify correct behavior and logs any failures.
- **Functions called**:
    - [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)
    - [`fd_quic_sandbox_send_ping_pkt`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_ping_pkt)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, sets up a testing sandbox for QUIC protocol conformance, runs a series of tests, and then cleans up resources.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Create a random number generator `rng` using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index using `fd_tile_cpu_id` and `fd_tile_idx`, adjusting if necessary based on shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to an actual size using `fd_cstr_to_shmem_page_sz` and log an error if unsupported.
    - Define QUIC limits in a `fd_quic_limits_t` structure with specific parameters for connections, streams, and buffer sizes.
    - Log the creation of an anonymous workspace and create it using `fd_wksp_new_anonymous`.
    - Allocate memory for a QUIC sandbox using `fd_wksp_alloc_laddr` and initialize it with [`fd_quic_sandbox_new`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_new).
    - Run a series of QUIC protocol conformance tests using various test functions, passing the sandbox and RNG as arguments.
    - Free the allocated sandbox memory and delete the anonymous workspace.
    - Delete the random number generator and log the successful completion of tests.
    - Call `fd_halt` to terminate the program.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_sandbox_align`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_align)
    - [`fd_quic_sandbox_footprint`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_footprint)
    - [`fd_quic_sandbox_new`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_new)
    - [`test_quic_stream_data_limit_enforcement`](#test_quic_stream_data_limit_enforcement)
    - [`test_quic_stream_limit_enforcement`](#test_quic_stream_limit_enforcement)
    - [`test_quic_stream_concurrency`](#test_quic_stream_concurrency)
    - [`test_quic_ping_frame`](#test_quic_ping_frame)
    - [`test_quic_server_alpn_fail`](#test_quic_server_alpn_fail)
    - [`test_quic_pktnum_skip`](#test_quic_pktnum_skip)
    - [`test_quic_conn_initial_limits`](#test_quic_conn_initial_limits)
    - [`test_quic_rx_max_data_frame`](#test_quic_rx_max_data_frame)
    - [`test_quic_rx_max_streams_frame`](#test_quic_rx_max_streams_frame)
    - [`test_quic_small_pkt_ping`](#test_quic_small_pkt_ping)
    - [`test_quic_send_streams`](#test_quic_send_streams)
    - [`test_quic_inflight_pkt_limit`](#test_quic_inflight_pkt_limit)
    - [`test_quic_parse_path_challenge`](#test_quic_parse_path_challenge)
    - [`test_quic_conn_free`](#test_quic_conn_free)
    - [`test_quic_pktmeta_pktnum_skip`](#test_quic_pktmeta_pktnum_skip)
    - [`fd_quic_sandbox_delete`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_delete)


