# Purpose
The provided C source code file is part of a QUIC (Quick UDP Internet Connections) protocol implementation. It is designed to handle various aspects of the QUIC protocol, including connection management, packet processing, and encryption. The file includes a comprehensive set of functions and structures to manage QUIC connections, process incoming and outgoing packets, handle encryption and decryption, and manage the state of connections. It also includes functionality for handling different types of QUIC frames, such as ACK, STREAM, and CONNECTION_CLOSE frames, and provides mechanisms for retransmission and flow control.

The code is structured to support both client and server roles in a QUIC connection, with specific handling for initial handshakes, retries, and connection closures. It uses a variety of data structures, such as connection maps and packet metadata trackers, to efficiently manage the state and resources associated with each connection. The file also includes integration with TLS for secure communication, leveraging callbacks for handling TLS events like secret generation and handshake completion. Overall, this file is a critical component of a QUIC protocol stack, providing the necessary functionality to establish, maintain, and terminate QUIC connections in a secure and efficient manner.
# Imports and Dependencies

---
- `fd_quic.h`
- `fd_quic_ack_tx.h`
- `fd_quic_common.h`
- `fd_quic_conn_id.h`
- `fd_quic_enum.h`
- `fd_quic_private.h`
- `fd_quic_conn.h`
- `fd_quic_conn_map.h`
- `fd_quic_proto.h`
- `fd_quic_proto.c`
- `fd_quic_retry.h`
- `templ/fd_quic_frame_handler_decl.h`
- `templ/fd_quic_frames_templ.h`
- `templ/fd_quic_undefs.h`
- `fd_quic_pretty_print.c`
- `crypto/fd_quic_crypto_suites.h`
- `templ/fd_quic_transport_params.h`
- `templ/fd_quic_parse_util.h`
- `tls/fd_quic_tls.h`
- `fcntl.h`
- `unistd.h`
- `../../ballet/hex/fd_hex.h`
- `../../tango/tempo/fd_tempo.h`
- `../../util/log/fd_dtrace.h`
- `../../disco/metrics/generated/fd_metrics_enums.h`
- `../../util/tmpl/fd_map_dynamic.c`
- `templ/fd_quic_frame.c`


# Global Variables

---
### fd\_quic\_handle\_padding\_frame
- **Type**: `ulong`
- **Description**: The `fd_quic_handle_padding_frame` function is a static function that processes padding frames in the QUIC protocol. Padding frames are used to increase the size of a packet without adding any additional information, often for security or alignment purposes.
- **Use**: This function is used to handle and skip over padding frames in a QUIC packet, ensuring that the rest of the packet is processed correctly.


# Functions

---
### fd\_quic\_align<!-- {{#callable:fd_quic_align}} -->
The `fd_quic_align` function returns the alignment value for QUIC structures.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `FD_QUIC_ALIGN`.
    - There are no conditional statements or loops in the function.
- **Output**: The output is a `ulong` value representing the alignment requirement for QUIC structures.


---
### fd\_quic\_footprint\_ext<!-- {{#callable:fd_quic_footprint_ext}} -->
The `fd_quic_footprint_ext` function calculates the memory footprint required for a QUIC connection based on specified limits and populates a layout structure with byte offsets for various components.
- **Inputs**:
    - `limits`: A pointer to a `fd_quic_limits_t` structure that defines the limits for the QUIC connection, including connection count, connection ID count, log depth, handshake count, inflight frame count, transmission buffer size, and stream pool count.
    - `layout`: A pointer to a `fd_quic_layout_t` structure that will be populated with the calculated offsets and sizes of various components required for the QUIC connection.
- **Control Flow**:
    - The function begins by zeroing out the `layout` structure using `memset`.
    - It checks if the `limits` pointer is NULL; if so, it returns 0.
    - It retrieves various limit values from the `limits` structure, such as connection count and handshake count.
    - It performs several checks to ensure that the limits are valid, returning 0 if any checks fail.
    - The function calculates the memory offsets for different components, including the QUIC state, connections, connection IDs, handshake pool, stream pool, packet metadata pool, and log buffer.
    - For each component, it checks the validity of the calculated footprint and logs a warning if any footprint calculation fails.
    - Finally, it returns the total calculated footprint size.
- **Output**: The function returns an unsigned long value representing the total memory footprint required for the QUIC connection, or 0 if any validation checks fail.
- **Functions called**:
    - [`fd_quic_conn_align`](fd_quic_conn.c.driver.md#fd_quic_conn_align)
    - [`fd_quic_conn_footprint`](fd_quic_conn.c.driver.md#fd_quic_conn_footprint)
    - [`fd_quic_stream_pool_align`](fd_quic_stream_pool.h.driver.md#fd_quic_stream_pool_align)
    - [`fd_quic_stream_pool_footprint`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_footprint)
    - [`fd_quic_log_buf_align`](log/fd_quic_log.c.driver.md#fd_quic_log_buf_align)
    - [`fd_quic_log_buf_footprint`](log/fd_quic_log.c.driver.md#fd_quic_log_buf_footprint)


---
### fd\_quic\_footprint<!-- {{#callable:fd_quic_footprint}} -->
The `fd_quic_footprint` function calculates the memory footprint required for a QUIC connection based on specified limits.
- **Inputs**:
    - `limits`: A pointer to a `fd_quic_limits_t` structure that defines the limits for the QUIC connection, including counts for connections, connection IDs, handshakes, and buffer sizes.
- **Control Flow**:
    - The function initializes a `fd_quic_layout_t` structure to store layout information.
    - It calls the [`fd_quic_footprint_ext`](#fd_quic_footprint_ext) function, passing the `limits` and a pointer to the `layout` structure.
    - The [`fd_quic_footprint_ext`](#fd_quic_footprint_ext) function performs various checks on the limits and calculates the total memory footprint required for the QUIC connection.
    - If any of the checks fail, it returns 0, indicating an invalid configuration.
- **Output**: Returns the total memory footprint required for the QUIC connection as an unsigned long integer.
- **Functions called**:
    - [`fd_quic_footprint_ext`](#fd_quic_footprint_ext)


---
### fd\_quic\_clock\_wallclock<!-- {{#callable:fd_quic_clock_wallclock}} -->
The `fd_quic_clock_wallclock` function retrieves the current wall clock time.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_log_wallclock()` to obtain the current wall clock time.
    - The result from `fd_log_wallclock()` is cast to an unsigned long type.
    - The function returns the casted value.
- **Output**: The function returns the current wall clock time as an unsigned long.


---
### fd\_quic\_clock\_tickcount<!-- {{#callable:fd_quic_clock_tickcount}} -->
Returns the current tick count as an unsigned long integer.
- **Inputs**: None
- **Control Flow**:
    - The function does not perform any checks or operations on the input context as it is unused.
    - It directly calls the `fd_tickcount()` function to retrieve the current tick count.
    - The result from `fd_tickcount()` is cast to an unsigned long and returned.
- **Output**: An unsigned long integer representing the current tick count.


---
### fd\_quic\_new<!-- {{#callable:fd_quic_new}} -->
The `fd_quic_new` function initializes a new QUIC connection structure in a specified memory region.
- **Inputs**:
    - `mem`: A pointer to a memory region where the QUIC connection structure will be allocated.
    - `limits`: A pointer to a `fd_quic_limits_t` structure that defines the limits for the QUIC connection, such as connection count and handshake count.
- **Control Flow**:
    - The function first checks if the `mem` pointer is NULL and logs a warning if it is, returning NULL.
    - It checks if the memory address is aligned according to the required alignment for QUIC structures.
    - It verifies that the `limits` pointer is not NULL and that the values within the `limits` structure are valid.
    - The function calculates the memory footprint required for the QUIC connection based on the provided limits.
    - If the footprint is valid, it initializes the QUIC structure by clearing its memory and setting default configuration values.
    - It sets up the logging buffer for the QUIC connection.
    - Finally, it sets a magic number for validation and returns a pointer to the initialized QUIC connection structure.
- **Output**: Returns a pointer to the initialized `fd_quic_t` structure if successful, or NULL if any of the checks fail.
- **Functions called**:
    - [`fd_quic_align`](#fd_quic_align)
    - [`fd_quic_footprint_ext`](#fd_quic_footprint_ext)
    - [`fd_quic_log_buf_new`](log/fd_quic_log.c.driver.md#fd_quic_log_buf_new)


---
### fd\_quic\_get\_aio\_net\_rx<!-- {{#callable:fd_quic_get_aio_net_rx}} -->
This function initializes an asynchronous I/O (AIO) receive operation for a QUIC connection.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC connection for which the AIO receive operation is being set up.
- **Control Flow**:
    - Calls `fd_aio_new` to initialize the AIO receive structure `aio_rx` associated with the provided `quic` connection.
    - The `aio_rx` structure is set up with the callback function `fd_quic_aio_cb_receive` to handle incoming data.
- **Output**: Returns a pointer to the initialized `fd_aio_t` structure for the AIO receive operation.


---
### fd\_quic\_set\_aio\_net\_tx<!-- {{#callable:fd_quic_set_aio_net_tx}} -->
Sets the asynchronous I/O (AIO) transmit configuration for a QUIC connection.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC connection to be configured.
    - `aio_tx`: A pointer to a constant `fd_aio_t` structure that contains the AIO transmit configuration; if NULL, the transmit configuration will be reset.
- **Control Flow**:
    - The function first checks if the `aio_tx` pointer is not NULL.
    - If `aio_tx` is not NULL, it copies the contents of `aio_tx` into the `quic->aio_tx` member.
    - If `aio_tx` is NULL, it zeroes out the `quic->aio_tx` member using `memset`.
- **Output**: The function does not return a value; it modifies the `quic` structure directly to set or reset the AIO transmit configuration.


---
### fd\_quic\_ticks\_to\_us<!-- {{#callable:fd_quic_ticks_to_us}} -->
Converts QUIC ticks to microseconds based on the configured tick rate.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure that contains configuration and state information for the QUIC connection.
    - `ticks`: An unsigned long integer representing the number of ticks to be converted to microseconds.
- **Control Flow**:
    - The function retrieves the tick-to-microsecond conversion ratio from the `quic` configuration.
    - It then divides the input `ticks` by this ratio to convert the value to microseconds.
    - The result is cast to an unsigned long and returned.
- **Output**: Returns the equivalent time in microseconds as an unsigned long integer.


---
### fd\_quic\_us\_to\_ticks<!-- {{#callable:fd_quic_us_to_ticks}} -->
Converts microseconds to ticks based on the QUIC configuration.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure that contains configuration settings, including the conversion ratio from microseconds to ticks.
    - `us`: An unsigned long integer representing the time in microseconds that needs to be converted to ticks.
- **Control Flow**:
    - The function retrieves the conversion ratio from the `quic` structure, specifically from the `tick_per_us` field.
    - It then multiplies the input microseconds (`us`) by this ratio to calculate the equivalent number of ticks.
    - Finally, the result is cast to an unsigned long and returned.
- **Output**: Returns the calculated number of ticks as an unsigned long integer.


---
### fd\_quic\_set\_clock<!-- {{#callable:fd_quic_set_clock}} -->
Sets the clock configuration for a QUIC connection.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC connection.
    - `now_fn`: A function pointer of type `fd_quic_now_t` that returns the current time.
    - `now_ctx`: A context pointer that will be passed to the `now_fn` function.
    - `tick_per_us`: A double value representing the number of ticks per microsecond.
- **Control Flow**:
    - Retrieve the current configuration and callback structures from the `quic` object.
    - Calculate the ratio of the new `tick_per_us` to the existing `tick_per_us` in the configuration.
    - Update the `idle_timeout`, `ack_delay`, and `retry_ttl` in the configuration based on the calculated ratio.
    - Set the new `tick_per_us` in the configuration.
    - Assign the provided `now_fn` and `now_ctx` to the callback structure.
- **Output**: The function does not return a value; it modifies the configuration of the QUIC connection directly.


---
### fd\_quic\_set\_clock\_tickcount<!-- {{#callable:fd_quic_set_clock_tickcount}} -->
Sets the clock source for QUIC to use the tick count as the timing mechanism.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC connection context.
- **Control Flow**:
    - Calculates the number of ticks per microsecond by converting the ticks per nanosecond to microseconds.
    - Calls the [`fd_quic_set_clock`](#fd_quic_set_clock) function to set the clock source to use the tick count and the calculated ticks per microsecond.
- **Output**: The function does not return a value; it modifies the QUIC connection's clock settings.
- **Functions called**:
    - [`fd_quic_set_clock`](#fd_quic_set_clock)


---
### fd\_quic\_stream\_init<!-- {{#callable:fd_quic_stream_init}} -->
Initializes a `fd_quic_stream_t` structure to prepare it for use.
- **Inputs**:
    - `stream`: A pointer to a `fd_quic_stream_t` structure that will be initialized.
- **Control Flow**:
    - Sets the `context` field of the `stream` to NULL.
    - Initializes the `tx_buf` head and tail to 0, indicating an empty transmission buffer.
    - Sets `tx_sent` to 0, indicating no data has been sent yet.
    - Initializes `stream_flags` to 0, indicating no flags are set.
    - Sets the `state` of the stream to 0, indicating it is in an initial state.
    - Initializes `tx_max_stream_data` and `tx_tot_data` to 0, indicating no data limits or totals.
    - Initializes `rx_tot_data` to 0, indicating no received data.
    - Sets `upd_pkt_number` to 0, indicating no updates to the packet number.
- **Output**: The function does not return a value; it modifies the `stream` structure in place to prepare it for use.


---
### fd\_quic\_join<!-- {{#callable:fd_quic_join}} -->
The `fd_quic_join` function validates and returns a pointer to a `fd_quic_t` structure if the provided pointer is valid.
- **Inputs**:
    - `shquic`: A pointer to a `fd_quic_t` structure that is expected to be properly aligned and initialized.
- **Control Flow**:
    - The function first checks if the `shquic` pointer is NULL, logging a warning and returning NULL if it is.
    - Next, it checks if the `shquic` pointer is aligned according to `FD_QUIC_ALIGN`, logging a warning and returning NULL if it is not.
    - Then, it checks if the `magic` field of the `fd_quic_t` structure pointed to by `shquic` matches `FD_QUIC_MAGIC`, logging a warning and returning NULL if it does not.
    - If all checks pass, the function returns the pointer to the `fd_quic_t` structure.
- **Output**: Returns a pointer to the `fd_quic_t` structure if all validations are successful; otherwise, returns NULL.


---
### fd\_quic\_leave<!-- {{#callable:fd_quic_leave}} -->
The `fd_quic_leave` function returns a pointer to the `fd_quic_t` structure passed to it.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC connection.
- **Control Flow**:
    - The function directly returns the input pointer cast to a void pointer.
    - There are no conditional statements or loops in the function.
- **Output**: The function outputs a void pointer that points to the same `fd_quic_t` structure that was passed as an argument.


---
### fd\_quic\_init<!-- {{#callable:fd_quic_init}} -->
Initializes a `fd_quic_t` structure, setting up its configuration, state, and necessary resources for QUIC communication.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure that contains the configuration and state for the QUIC connection.
- **Control Flow**:
    - Checks if the `config.role`, `idle_timeout`, `ack_delay`, `retry_ttl`, and `tick_per_us` are set, logging warnings and returning NULL if any are invalid.
    - Validates the `identity_public_key` to ensure it is set.
    - Checks the `config.role` to ensure it is either `FD_QUIC_ROLE_SERVER` or `FD_QUIC_ROLE_CLIENT`, logging a warning and returning NULL if invalid.
    - Sets the `ack_threshold` to a default value if it is not set.
    - Calculates the memory layout for the QUIC structure and checks for memory corruption.
    - Resets the state of the QUIC connection.
    - Initializes the packet meta pool and connection ID map.
    - Sets up the service queue and initializes the TLS configuration.
    - Generates secure random numbers for retry tokens and initializes transport parameters.
    - Returns the initialized `quic` structure.
- **Output**: Returns a pointer to the initialized `fd_quic_t` structure, or NULL if initialization fails.
- **Functions called**:
    - [`fd_quic_footprint_ext`](#fd_quic_footprint_ext)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_pkt_meta_ds_init_pool`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_ds_init_pool)
    - [`fd_quic_conn_new`](fd_quic_conn.c.driver.md#fd_quic_conn_new)
    - [`fd_quic_tls_new`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_new)
    - [`fd_quic_stream_pool_new`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_new)


---
### fd\_quic\_enc\_level\_to\_pn\_space<!-- {{#callable:fd_quic_enc_level_to_pn_space}} -->
Maps the QUIC encryption level to the corresponding packet number space.
- **Inputs**:
    - `enc_level`: An unsigned integer representing the encryption level, which should be in the range [0, 4).
- **Control Flow**:
    - The function first checks if the `enc_level` is greater than or equal to 4, logging an error if it is.
    - It then uses a static mapping array `el2pn_map` to return the corresponding packet number space for the given encryption level.
- **Output**: Returns an unsigned integer representing the packet number space associated with the specified encryption level.


---
### fd\_quic\_reconstruct\_pkt\_num<!-- {{#callable:fd_quic_reconstruct_pkt_num}} -->
Reconstructs a packet number based on a compressed representation, size, and expected packet number.
- **Inputs**:
    - `pktnum_comp`: The compressed representation of the packet number.
    - `pktnum_sz`: The size of the packet number in bits.
    - `exp_pkt_number`: The expected packet number to use as a reference for reconstruction.
- **Control Flow**:
    - Calculates the number of bits for the packet number and the size of the window based on the provided size.
    - Determines the candidate packet number by combining the expected packet number with the compressed packet number.
    - Checks if the candidate packet number is within the acceptable range defined by the expected packet number and the window size.
    - If the candidate is valid, it returns the next packet number; otherwise, it adjusts the candidate based on the window and returns it.
- **Output**: Returns the reconstructed packet number based on the input parameters, ensuring it adheres to the expected range.


---
### fd\_quic\_svc\_unqueue<!-- {{#callable:fd_quic_svc_unqueue}} -->
The `fd_quic_svc_unqueue` function removes a connection from its service queue in a QUIC state.
- **Inputs**:
    - `state`: A pointer to the `fd_quic_state_t` structure representing the current state of the QUIC service.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection to be unqueued.
- **Control Flow**:
    - The function retrieves the service queue associated with the connection's service type from the state.
    - It obtains the previous and next indices of the connection in the queue.
    - It retrieves the previous and next connection elements based on these indices.
    - If the next index is not `UINT_MAX`, it updates the previous pointer of the next element to point to the previous index.
    - If the previous index is not `UINT_MAX`, it updates the next pointer of the previous element to point to the next index.
- **Output**: The function does not return a value; it modifies the state of the service queue by unlinking the specified connection.
- **Functions called**:
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)


---
### fd\_quic\_svc\_schedule<!-- {{#callable:fd_quic_svc_schedule}} -->
The `fd_quic_svc_schedule` function schedules a QUIC connection for service based on its current state and the specified service type.
- **Inputs**:
    - `state`: A pointer to the `fd_quic_state_t` structure representing the current state of the QUIC protocol.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection to be scheduled.
    - `svc_type`: An unsigned integer representing the type of service to be scheduled for the connection.
- **Control Flow**:
    - The function first checks if the provided `svc_type` is valid by comparing it against `FD_QUIC_SVC_CNT`.
    - It then checks if the connection's state is valid; if not, it logs an error.
    - The function determines if the connection is already queued for service and calculates the current and target delays.
    - If the connection is already queued and the current delay is less than or equal to the target delay, the function returns without making changes.
    - If the connection is queued, it is unqueued from the current service queue.
    - The connection is then added to the new service queue with updated service type and time.
- **Output**: The function does not return a value; it modifies the state of the connection and its scheduling in the service queue.
- **Functions called**:
    - [`fd_quic_svc_unqueue`](#fd_quic_svc_unqueue)
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)


---
### fd\_quic\_svc\_queue\_validate<!-- {{#callable:fd_quic_svc_queue_validate}} -->
The `fd_quic_svc_queue_validate` function validates the integrity of a service queue in a QUIC connection state.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC connection state.
    - `svc_type`: An unsigned integer representing the type of service queue to validate.
- **Control Flow**:
    - The function begins by asserting that `svc_type` is less than the total number of service types defined.
    - It retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - A loop iterates through the nodes in the specified service queue, validating each connection's state and properties.
    - During each iteration, it checks that the node index is valid, the connection state is not invalid, the service type matches, and the service time is within acceptable limits.
    - It also ensures that the previous node index matches the expected value.
    - Finally, it checks that the last node processed matches the head of the queue.
- **Output**: The function does not return a value; it performs assertions to validate the integrity of the service queue.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)


---
### fd\_quic\_conn\_free\_validate<!-- {{#callable:fd_quic_conn_free_validate}} -->
The `fd_quic_conn_free_validate` function validates the integrity of the free connection list in a QUIC connection state.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC connection.
- **Control Flow**:
    - The function retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - It initializes a counter `cnt` to track the number of connections processed.
    - It starts a loop that iterates through the free connection list using a `node` variable.
    - For each node, it checks that the node index is valid and within the connection count limit.
    - It retrieves the connection at the current index and verifies that its state is `FD_QUIC_CONN_STATE_INVALID`.
    - It checks that the previous service node index (`svc_prev`) and service type (`svc_type`) are both `UINT_MAX`.
    - The connection is marked as visited by setting its `visited` field to 1.
    - The loop continues to the next node in the free list until it reaches the end (indicated by `UINT_MAX`).
    - Finally, it ensures that the count of processed connections does not exceed the total connection count.
- **Output**: The function does not return a value but performs validation checks and may trigger assertions if any checks fail.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)


---
### fd\_quic\_svc\_validate<!-- {{#callable:fd_quic_svc_validate}} -->
Validates the state of QUIC connections and their associated service queues.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC instance to validate.
- **Control Flow**:
    - Retrieves the current state of the QUIC instance using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - Iterates over each connection index from 0 to the maximum connection count defined in `quic->limits.conn_cnt`.
    - For each connection, checks if its index matches its `conn_idx` and resets its `visited` flag.
    - If the connection state is `FD_QUIC_CONN_STATE_INVALID`, it verifies that its service type and previous service index are both set to `UINT_MAX`.
    - Calls [`fd_quic_svc_queue_validate`](#fd_quic_svc_queue_validate) for each service type to ensure the integrity of the service queues.
    - After validating the service queues, it checks again for any invalid connections and ensures they have not been visited.
    - Finally, it calls [`fd_quic_conn_free_validate`](#fd_quic_conn_free_validate) to validate the free connection list.
- **Output**: The function does not return a value but performs validation checks and asserts conditions on the state of connections and their service queues.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)
    - [`fd_quic_svc_queue_validate`](#fd_quic_svc_queue_validate)
    - [`fd_quic_conn_free_validate`](#fd_quic_conn_free_validate)


---
### fd\_quic\_log\_conn\_hdr<!-- {{#callable:fd_quic_log_conn_hdr}} -->
The `fd_quic_log_conn_hdr` function creates a log header for a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to a `fd_quic_conn_t` structure representing the QUIC connection for which the log header is being created.
- **Control Flow**:
    - The function initializes a `fd_quic_log_hdr_t` structure named `hdr`.
    - It sets the `conn_id` field of `hdr` to the `our_conn_id` of the provided `conn` structure.
    - The `flags` field of `hdr` is initialized to 0.
    - Finally, the function returns the `hdr` structure.
- **Output**: The function returns a `fd_quic_log_hdr_t` structure containing the connection ID and flags for logging purposes.


---
### fd\_quic\_log\_full\_hdr<!-- {{#callable:fd_quic_log_full_hdr}} -->
The `fd_quic_log_full_hdr` function constructs a full QUIC log header from a connection and packet.
- **Inputs**:
    - `conn`: A pointer to a `fd_quic_conn_t` structure representing the QUIC connection.
    - `pkt`: A pointer to a `fd_quic_pkt_t` structure representing the QUIC packet.
- **Control Flow**:
    - The function initializes a `fd_quic_log_hdr_t` structure named `hdr`.
    - It populates the `hdr` fields with values from the `conn` and `pkt` structures.
    - The `conn_id` is set from `conn->our_conn_id`, `pkt_num` from `pkt->pkt_number`, `ip4_saddr` from `pkt->ip4->saddr`, `udp_sport` from `pkt->udp->net_sport`, and `enc_level` from `pkt->enc_level`.
    - The `flags` field is initialized to 0.
    - Finally, the function returns the populated `hdr` structure.
- **Output**: The function returns a `fd_quic_log_hdr_t` structure containing the constructed log header.


---
### fd\_quic\_conn\_error1<!-- {{#callable:fd_quic_conn_error1}} -->
The `fd_quic_conn_error1` function sets the state of a QUIC connection to aborted and schedules it for immediate servicing.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `reason`: An unsigned integer representing the reason for the connection error, typically an RFC 9000 QUIC error code.
- **Control Flow**:
    - The function first checks if the `conn` pointer is NULL or if the connection state is `FD_QUIC_CONN_STATE_DEAD`, in which case it returns immediately without making any changes.
    - If the connection is valid, it calls [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state) to change the state of the connection to `FD_QUIC_CONN_STATE_ABORT`.
    - The `reason` for the error is then assigned to the `reason` field of the connection structure.
    - Finally, it calls [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1) to schedule the connection for servicing as soon as possible.
- **Output**: The function does not return a value; it modifies the state of the connection and schedules it for servicing.
- **Functions called**:
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)


---
### fd\_quic\_conn\_error<!-- {{#callable:fd_quic_conn_error}} -->
The `fd_quic_conn_error` function sets the connection state to aborted and logs the error details.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection that encountered an error.
    - `reason`: An unsigned integer representing the QUIC error code as defined in RFC 9000.
    - `error_line`: An unsigned integer indicating the line number in the source code where the error occurred.
- **Control Flow**:
    - The function first calls [`fd_quic_conn_error1`](#fd_quic_conn_error1) to set the connection state to aborted and record the error reason.
    - It retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - A log signature is generated for the QUIC close event.
    - A log frame is prepared with the connection header, error code, source file, and line number.
    - The log frame is submitted to the logging system.
- **Output**: The function does not return a value but modifies the state of the connection and logs the error details.
- **Functions called**:
    - [`fd_quic_conn_error1`](#fd_quic_conn_error1)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_log_sig`](log/fd_quic_log_tx.h.driver.md#fd_quic_log_sig)
    - [`fd_quic_log_tx_prepare`](log/fd_quic_log_tx.h.driver.md#fd_quic_log_tx_prepare)
    - [`fd_quic_log_conn_hdr`](#fd_quic_log_conn_hdr)
    - [`fd_quic_log_tx_submit`](log/fd_quic_log_tx.h.driver.md#fd_quic_log_tx_submit)


---
### fd\_quic\_frame\_error<!-- {{#callable:fd_quic_frame_error}} -->
The `fd_quic_frame_error` function handles error reporting for QUIC frames by logging the error and updating the connection state.
- **Inputs**:
    - `ctx`: A pointer to a `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame, including the connection and packet information.
    - `reason`: An unsigned integer representing the error reason code as defined in the QUIC protocol.
    - `error_line`: An unsigned integer indicating the line number in the source code where the error occurred, used for debugging purposes.
- **Control Flow**:
    - Retrieve the QUIC connection and packet from the context provided in `ctx`.
    - Call [`fd_quic_conn_error1`](#fd_quic_conn_error1) to set the connection state to aborted and log the error reason.
    - Check if the connection has a TLS handshake state and retrieve the TLS reason if it exists.
    - Prepare a log entry for the error frame using [`fd_quic_log_tx_prepare`](log/fd_quic_log_tx.h.driver.md#fd_quic_log_tx_prepare) and populate it with relevant information including the error reason and source location.
    - Submit the prepared log entry using [`fd_quic_log_tx_submit`](log/fd_quic_log_tx.h.driver.md#fd_quic_log_tx_submit).
- **Output**: The function does not return a value but updates the connection state and logs the error information.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_error1`](#fd_quic_conn_error1)
    - [`fd_quic_log_sig`](log/fd_quic_log_tx.h.driver.md#fd_quic_log_sig)
    - [`fd_quic_log_tx_prepare`](log/fd_quic_log_tx.h.driver.md#fd_quic_log_tx_prepare)
    - [`fd_quic_log_full_hdr`](#fd_quic_log_full_hdr)
    - [`fd_quic_log_tx_submit`](log/fd_quic_log_tx.h.driver.md#fd_quic_log_tx_submit)


---
### fd\_quic\_tx\_enc\_level<!-- {{#callable:fd_quic_tx_enc_level}} -->
The `fd_quic_tx_enc_level` function determines the appropriate encryption level for sending QUIC packets based on the connection state and available data.
- **Inputs**:
    - `conn`: A pointer to a `fd_quic_conn_t` structure representing the QUIC connection for which the encryption level is being determined.
    - `acks`: An integer flag indicating whether the function should consider acknowledgments when determining the encryption level.
- **Control Flow**:
    - The function initializes `enc_level` to an invalid state (~0u).
    - It checks the connection state using a switch statement to determine the appropriate action based on the current state.
    - If the connection is dead, it returns ~0u immediately.
    - For states like aborting or closing, it checks if the handshake is complete and returns the appropriate encryption level.
    - In the active state, it checks for stream data to send and may return the application data encryption level if applicable.
    - If there are acknowledgments to process, it retrieves the oldest acknowledgment's encryption level and returns it if valid.
    - The function also checks for handshake data to send and updates the encryption level accordingly.
    - If no conditions are met for sending data, it returns ~0u.
- **Output**: The function returns the encryption level to be used for the next packet transmission, or ~0u if there is nothing to send.
- **Functions called**:
    - [`fd_quic_enc_level_to_pn_space`](#fd_quic_enc_level_to_pn_space)
    - [`fd_quic_tls_get_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_get_hs_data)
    - [`fd_quic_tls_get_next_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_get_next_hs_data)


---
### fd\_quic\_handle\_v1\_frame<!-- {{#callable:fd_quic_handle_v1_frame}} -->
Handles the processing of QUIC version 1 frames.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection.
    - `pkt`: A pointer to the `fd_quic_pkt_t` structure representing the packet.
    - `pkt_type`: An unsigned integer representing the type of the packet.
    - `buf`: A pointer to a buffer containing the frame data.
    - `buf_sz`: An unsigned long representing the size of the buffer.
- **Control Flow**:
    - Checks if the connection state is 'DEAD' and returns failure if true.
    - Checks if the buffer size is less than 1 and returns failure if true.
    - Extracts the frame ID from the first byte of the buffer.
    - Logs the frame handling event using `FD_DTRACE_PROBE_4`.
    - Creates a frame context and checks if the frame type is allowed.
    - If the frame type is not allowed, logs an error and calls [`fd_quic_frame_error`](#fd_quic_frame_error).
    - Increments the frame reception count in the metrics.
    - Sets the acknowledgment flag in the packet based on the frame type.
    - Uses a switch statement to call the appropriate frame interpretation function based on the frame ID.
    - Handles unexpected frame types by logging an error and calling [`fd_quic_frame_error`](#fd_quic_frame_error).
- **Output**: Returns the number of bytes consumed from the buffer, or a failure code if an error occurs.
- **Functions called**:
    - [`fd_quic_frame_type_allowed`](templ/fd_quic_frame.h.driver.md#fd_quic_frame_type_allowed)
    - [`fd_quic_frame_error`](#fd_quic_frame_error)


---
### fd\_quic\_fini<!-- {{#callable:fd_quic_fini}} -->
Finalizes and cleans up resources associated with a `fd_quic_t` instance.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC connection to be finalized.
- **Control Flow**:
    - Checks if the `quic` pointer is NULL and logs a warning if it is.
    - Derives the memory layout of the QUIC instance using [`fd_quic_footprint_ext`](#fd_quic_footprint_ext).
    - Iterates over the connections associated with the QUIC instance and frees each connection if it is in use.
    - Deinitializes the TLS handshake pool and deletes the TLS context.
    - Deletes the connection ID map associated with the QUIC instance.
    - Clears the state structure associated with the QUIC instance.
- **Output**: Returns the pointer to the `fd_quic_t` instance that was finalized.
- **Functions called**:
    - [`fd_quic_footprint_ext`](#fd_quic_footprint_ext)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_free`](#fd_quic_conn_free)
    - [`fd_quic_tls_delete`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_delete)


---
### fd\_quic\_delete<!-- {{#callable:fd_quic_delete}} -->
The `fd_quic_delete` function safely deallocates a `fd_quic_t` structure, ensuring proper cleanup of associated resources.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure that represents the QUIC connection to be deleted.
- **Control Flow**:
    - The function first checks if the `quic` pointer is NULL, logging a warning and returning NULL if it is.
    - It then verifies that the `quic` pointer is properly aligned according to the QUIC alignment requirements, logging a warning and returning NULL if it is not.
    - Next, it checks the `magic` field of the `quic` structure to ensure it matches the expected magic value, logging a warning and returning NULL if it does not.
    - The function retrieves the shared log buffer address from the `quic` structure and attempts to delete it using [`fd_quic_log_buf_delete`](log/fd_quic_log.c.driver.md#fd_quic_log_buf_delete), logging a warning and returning NULL if the deletion fails.
    - Finally, it sets the `magic` field of the `quic` structure to 0, ensuring that the structure is marked as invalid, and returns the original `quic` pointer.
- **Output**: Returns the original `quic` pointer after successful deletion, or NULL if any checks fail or if the log buffer deletion fails.
- **Functions called**:
    - [`fd_quic_align`](#fd_quic_align)
    - [`fd_quic_log_buf_delete`](log/fd_quic_log.c.driver.md#fd_quic_log_buf_delete)


---
### fd\_quic\_conn\_new\_stream<!-- {{#callable:fd_quic_conn_new_stream}} -->
Creates a new QUIC stream associated with a given connection.
- **Inputs**:
    - `conn`: A pointer to a `fd_quic_conn_t` structure representing the QUIC connection to which the new stream will be added.
- **Control Flow**:
    - Checks if the connection's stream map is initialized; if not, returns NULL indicating the QUIC configuration is receive-only.
    - Retrieves the QUIC state and checks if the stream pool is available; if not, returns NULL.
    - Checks if the connection is active and if the next stream ID exceeds the peer's imposed limit; if so, returns NULL.
    - Attempts to allocate a new stream from the stream pool; if allocation fails, returns NULL.
    - Inserts the new stream into the stream map; if insertion fails, returns the stream to the pool and returns NULL.
    - Initializes the stream's properties, including its ID and maximum data size.
    - Inserts the stream into the list of used streams and updates the connection's next stream ID.
    - Updates the QUIC metrics for opened and active streams.
- **Output**: Returns a pointer to the newly created `fd_quic_stream_t` structure if successful, or NULL if any of the checks or allocations fail.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_stream_pool_alloc`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_alloc)
    - [`fd_quic_stream_pool_free`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_free)
    - [`fd_quic_stream_init`](#fd_quic_stream_init)


---
### fd\_quic\_stream\_send<!-- {{#callable:fd_quic_stream_send}} -->
The `fd_quic_stream_send` function sends data over a QUIC stream, managing flow control and stream state.
- **Inputs**:
    - `stream`: A pointer to the `fd_quic_stream_t` structure representing the stream over which data is to be sent.
    - `data`: A pointer to the data to be sent, represented as a constant void pointer.
    - `data_sz`: An unsigned long integer representing the size of the data to be sent.
    - `fin`: An integer flag indicating whether this is the final piece of data to be sent on the stream.
- **Control Flow**:
    - The function first checks if the stream is already in a finished state, returning an error if so.
    - It retrieves the associated connection and checks if the stream ID is valid for the current connection state.
    - If the connection is not active, it checks if the connection is in a handshake state and returns an error if so.
    - The function calculates the allowed data size for both the stream and the connection, returning an error if the data size exceeds these limits.
    - Data is then stored in the stream's transmission buffer, and the head of the buffer is advanced.
    - Flow control limits for both the stream and connection are updated based on the amount of data sent.
    - If the stream is not already marked for sending, it is added to the send list.
    - If the 'fin' flag is set, the stream's FIN state is updated.
    - Finally, the function schedules the connection for sending the data.
- **Output**: Returns FD_QUIC_SUCCESS on successful data transmission, or an error code indicating the type of failure.
- **Functions called**:
    - [`fd_quic_buffer_store`](fd_quic_stream.c.driver.md#fd_quic_buffer_store)
    - [`fd_quic_stream_fin`](#fd_quic_stream_fin)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)


---
### fd\_quic\_stream\_fin<!-- {{#callable:fd_quic_stream_fin}} -->
The `fd_quic_stream_fin` function marks a QUIC stream as finished for transmission.
- **Inputs**:
    - `stream`: A pointer to the `fd_quic_stream_t` structure representing the QUIC stream to be finalized.
- **Control Flow**:
    - The function first checks if the stream is already marked as finished by evaluating the `FD_QUIC_STREAM_STATE_TX_FIN` flag in the stream's state.
    - If the stream is not finished, it retrieves the associated connection from the stream's `conn` member.
    - The function then attempts to insert the stream into the send list if it is not already in action by calling `FD_QUIC_STREAM_ACTION`.
    - The stream's flags are updated to indicate that it has finished transmitting (`FD_QUIC_STREAM_FLAGS_TX_FIN`), and its state is updated accordingly.
    - Finally, the `upd_pkt_number` is set to `FD_QUIC_PKT_NUM_PENDING` to indicate that the stream's finalization should be included in the next packet to be sent.
- **Output**: The function does not return a value, but it modifies the state of the stream to indicate that it has finished sending data.


---
### fd\_quic\_conn\_set\_rx\_max\_data<!-- {{#callable:fd_quic_conn_set_rx_max_data}} -->
Sets the maximum amount of data that can be received by a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `rx_max_data`: An unsigned long integer representing the new maximum amount of data that can be received.
- **Control Flow**:
    - The function first checks if the new `rx_max_data` is greater than the current maximum and less than the maximum allowed value (2^62 - 1).
    - If the conditions are met, it updates the `rx_max_data` field in the connection's stream receive structure.
    - It also sets a flag indicating that the maximum data has changed, marks the packet number as pending, and schedules the connection for immediate servicing.
- **Output**: The function does not return a value; it modifies the state of the connection directly.
- **Functions called**:
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)


---
### fd\_quic\_abandon\_enc\_level<!-- {{#callable:fd_quic_abandon_enc_level}} -->
The `fd_quic_abandon_enc_level` function frees all resources associated with encryption levels less than or equal to the specified level.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `enc_level`: An unsigned integer representing the encryption level to abandon.
- **Control Flow**:
    - The function first checks if the specified `enc_level` is available in the connection's `keys_avail` bitfield; if not, it returns 0.
    - If the `enc_level` is available, it logs a debug message indicating the abandonment of the specified encryption level.
    - The function then calls [`fd_quic_ack_gen_abandon_enc_level`](fd_quic_ack_tx.c.driver.md#fd_quic_ack_gen_abandon_enc_level) to handle acknowledgment generation for the specified encryption level.
    - It iterates from 0 to `enc_level`, clearing the corresponding bits in `keys_avail` and treating all packets as acknowledged.
    - For each encryption level, it iterates through the sent packet metadata, releasing the associated resources and reclaiming the packet metadata.
    - Finally, it updates the total number of freed packet metadata and returns this count.
- **Output**: Returns the number of packet metadata entries that were freed as a result of abandoning the specified encryption level.
- **Functions called**:
    - [`fd_quic_ack_gen_abandon_enc_level`](fd_quic_ack_tx.c.driver.md#fd_quic_ack_gen_abandon_enc_level)
    - [`fd_quic_pkt_meta_ds_fwd_iter_done`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_done)
    - [`fd_quic_pkt_meta_ds_fwd_iter_next`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_next)
    - [`fd_quic_pkt_meta_ds_fwd_iter_ele`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_ele)
    - [`fd_quic_reclaim_pkt_meta`](#fd_quic_reclaim_pkt_meta)
    - [`fd_quic_pkt_meta_ds_ele_cnt`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_ele_cnt)
    - [`fd_quic_pkt_meta_ds_clear`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_ds_clear)


---
### fd\_quic\_gen\_initial\_secret\_and\_keys<!-- {{#callable:fd_quic_gen_initial_secret_and_keys}} -->
Generates initial secrets and keys for a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `dst_conn_id`: A pointer to the `fd_quic_conn_id_t` structure containing the destination connection ID.
    - `is_server`: An integer indicating whether the connection is a server (non-zero) or client (zero).
- **Control Flow**:
    - Calls [`fd_quic_gen_initial_secrets`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_initial_secrets) to generate the initial secrets based on the destination connection ID and whether the connection is a server.
    - Calls [`fd_quic_gen_keys`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_keys) twice to generate the encryption keys for the initial encryption level using the generated secrets.
- **Output**: The function does not return a value; it modifies the `conn` structure to include the generated secrets and keys.
- **Functions called**:
    - [`fd_quic_gen_initial_secrets`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_initial_secrets)
    - [`fd_quic_gen_keys`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_keys)


---
### fd\_quic\_send\_retry<!-- {{#callable:fd_quic_send_retry}} -->
The `fd_quic_send_retry` function creates and sends a QUIC retry packet.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC connection.
    - `pkt`: A pointer to the `fd_quic_pkt_t` structure representing the original packet that is being retried.
    - `odcid`: A pointer to the original destination connection ID (`fd_quic_conn_id_t`) used for the retry.
    - `scid`: A pointer to the source connection ID (`fd_quic_conn_id_t`) for the retry.
    - `new_conn_id`: A new connection ID to be used in the retry packet.
- **Control Flow**:
    - The function retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - It calculates the expiration time for the retry packet based on the current time and the configured retry TTL.
    - A retry packet is created using [`fd_quic_retry_create`](fd_quic_retry.c.driver.md#fd_quic_retry_create), which populates the `retry_pkt` buffer.
    - The retry transmission count is incremented in the metrics.
    - The function attempts to send the retry packet using [`fd_quic_tx_buffered_raw`](#fd_quic_tx_buffered_raw), which handles the actual transmission.
    - If the transmission fails, the function returns a failure code; otherwise, it returns success.
- **Output**: The function returns 0 on success or `FD_QUIC_PARSE_FAIL` if the transmission fails.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_retry_create`](fd_quic_retry.c.driver.md#fd_quic_retry_create)
    - [`fd_quic_tx_buffered_raw`](#fd_quic_tx_buffered_raw)


---
### fd\_quic\_tls\_hs\_cache\_evict<!-- {{#callable:fd_quic_tls_hs_cache_evict}} -->
The `fd_quic_tls_hs_cache_evict` function evicts the oldest TLS handshake state from the cache if it has exceeded its time-to-live (TTL).
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `new_conn`: A pointer to the `fd_quic_conn_t` structure representing a new connection, which may be set to dead if eviction fails.
    - `state`: A pointer to the `fd_quic_state_t` structure representing the current state of the QUIC instance.
- **Control Flow**:
    - The function retrieves the oldest handshake state from the handshake cache using `fd_quic_tls_hs_cache_ele_peek_head`.
    - It checks if the current time is less than the sum of the handshake's birth time and the configured TTL.
    - If the handshake is too young to evict, it marks the new connection as dead, schedules it for service, and increments the error count for allocation failures.
    - If the handshake can be evicted, it frees the associated connection context and increments the eviction count.
- **Output**: The function returns 1 if a handshake state was successfully evicted, or 0 if the eviction was not performed due to the handshake being too young.
- **Functions called**:
    - [`fd_quic_svc_schedule`](#fd_quic_svc_schedule)
    - [`fd_quic_conn_free`](#fd_quic_conn_free)


---
### fd\_quic\_handle\_v1\_initial<!-- {{#callable:fd_quic_handle_v1_initial}} -->
The `fd_quic_handle_v1_initial` function processes an Initial packet in the QUIC protocol, handling connection establishment and TLS handshake initiation.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `p_conn`: A pointer to a pointer of `fd_quic_conn_t`, which will be updated to point to the connection object.
    - `pkt`: A pointer to the `fd_quic_pkt_t` structure representing the received packet.
    - `dcid`: A pointer to the destination connection ID (`fd_quic_conn_id_t`) for the packet.
    - `peer_scid`: A pointer to the source connection ID (`fd_quic_conn_id_t`) of the peer.
    - `cur_ptr`: A pointer to the current position in the packet data buffer.
    - `cur_sz`: The size of the remaining data in the packet buffer.
- **Control Flow**:
    - Check if the connection is valid and has the necessary keys available; if not, increment the no-key count and return failure.
    - Decode the Initial packet from the provided data buffer and check for parsing errors.
    - Verify that the packet length is valid and that no tokens are present in the Initial packet when not allowed.
    - If no connection object exists for the destination connection ID, allocate a new connection object and set up transport parameters.
    - Handle retry logic if configured, including sending a retry packet if necessary.
    - Decrypt the incoming packet header and payload using the appropriate keys.
    - Process the frames contained in the packet, handling any errors that occur during frame processing.
    - Update the connection's last activity timestamp and expected packet number, then schedule the connection for servicing.
- **Output**: Returns the total number of bytes consumed from the packet, or a failure code if an error occurs during processing.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_send_retry`](#fd_quic_send_retry)
    - [`fd_quic_retry_server_verify`](fd_quic_retry.c.driver.md#fd_quic_retry_server_verify)
    - [`fd_quic_conn_create`](#fd_quic_conn_create)
    - [`fd_quic_tls_hs_cache_evict`](#fd_quic_tls_hs_cache_evict)
    - [`fd_quic_tls_hs_new`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_hs_new)
    - [`fd_quic_gen_initial_secret_and_keys`](#fd_quic_gen_initial_secret_and_keys)
    - [`fd_quic_crypto_decrypt_hdr`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt_hdr)
    - [`fd_quic_svc_schedule`](#fd_quic_svc_schedule)
    - [`fd_quic_h0_pkt_num_len`](templ/fd_quic_parse_util.h.driver.md#fd_quic_h0_pkt_num_len)
    - [`fd_quic_pktnum_decode`](templ/fd_quic_parse_util.h.driver.md#fd_quic_pktnum_decode)
    - [`fd_quic_reconstruct_pkt_num`](#fd_quic_reconstruct_pkt_num)
    - [`fd_quic_crypto_decrypt`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt)
    - [`fd_quic_handle_v1_frame`](#fd_quic_handle_v1_frame)
    - [`fd_quic_conn_error`](#fd_quic_conn_error)


---
### fd\_quic\_handle\_v1\_handshake<!-- {{#callable:fd_quic_handle_v1_handshake}} -->
The `fd_quic_handle_v1_handshake` function processes a QUIC handshake packet.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection associated with the handshake.
    - `pkt`: A pointer to the `fd_quic_pkt_t` structure representing the packet being processed.
    - `cur_ptr`: A pointer to the current position in the packet data buffer.
    - `cur_sz`: The size of the remaining data in the packet buffer.
- **Control Flow**:
    - The function first checks if the `conn` pointer is NULL, incrementing the no connection count metric and returning a failure code if it is.
    - It then checks if the connection state is invalid or if the handshake keys are not available, incrementing the no key count metric and returning a failure code if either condition is true.
    - The function proceeds to decode the handshake data from the packet using `fd_quic_decode_handshake`, returning a failure code if decoding fails.
    - It checks if the length of the handshake data is within the bounds of the packet size, returning a failure code if it exceeds the size.
    - The function retrieves the TLS handshake context from the connection and checks if it exists, returning a failure code if it does not.
    - It decrypts the packet header and payload using the appropriate keys, returning a failure code if decryption fails.
    - The function updates the connection state by abandoning the initial encryption level and setting the peer encryption level to handshake.
    - It processes the frames contained in the handshake packet, returning a failure code if any frame handling fails.
    - Finally, it updates the last activity timestamp and expected packet number before returning the total size of the processed packet.
- **Output**: The function returns the total number of bytes consumed from the handshake packet, or a failure code if an error occurs.
- **Functions called**:
    - [`fd_quic_crypto_decrypt_hdr`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt_hdr)
    - [`fd_quic_h0_pkt_num_len`](templ/fd_quic_parse_util.h.driver.md#fd_quic_h0_pkt_num_len)
    - [`fd_quic_pktnum_decode`](templ/fd_quic_parse_util.h.driver.md#fd_quic_pktnum_decode)
    - [`fd_quic_reconstruct_pkt_num`](#fd_quic_reconstruct_pkt_num)
    - [`fd_quic_crypto_decrypt`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt)
    - [`fd_quic_abandon_enc_level`](#fd_quic_abandon_enc_level)
    - [`fd_quic_handle_v1_frame`](#fd_quic_handle_v1_frame)
    - [`fd_quic_conn_error`](#fd_quic_conn_error)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)


---
### fd\_quic\_handle\_v1\_retry<!-- {{#callable:fd_quic_handle_v1_retry}} -->
Handles the QUIC v1 retry packet processing for clients.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection, or NULL if no connection exists.
    - `pkt`: A constant pointer to the `fd_quic_pkt_t` structure representing the received packet.
    - `cur_ptr`: A constant pointer to the current position in the packet data.
    - `cur_sz`: The size of the remaining data in the packet.
- **Control Flow**:
    - The function first checks if the QUIC instance is configured as a server; if so, it triggers a connection error for the client if a connection exists.
    - If no connection exists, it increments the packet count for packets without a connection and returns a failure.
    - It retrieves the original destination connection ID and prepares to verify the retry token.
    - The function calls [`fd_quic_retry_client_verify`](fd_quic_retry.c.driver.md#fd_quic_retry_client_verify) to validate the retry token; if verification fails, it increments the retry failure count and returns a failure.
    - If verification succeeds, it updates the peer connection ID, resets the handshake state, regenerates keys using the new connection ID, and prepares to send an INITIAL packet.
    - Finally, it schedules the connection for immediate service and returns the size of the current packet.
- **Output**: Returns the size of the current packet if processing is successful, or a failure code if an error occurs.
- **Functions called**:
    - [`fd_quic_conn_error`](#fd_quic_conn_error)
    - [`fd_quic_retry_client_verify`](fd_quic_retry.c.driver.md#fd_quic_retry_client_verify)
    - [`fd_quic_gen_initial_secret_and_keys`](#fd_quic_gen_initial_secret_and_keys)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)


---
### fd\_quic\_handle\_v1\_zero\_rtt<!-- {{#callable:fd_quic_handle_v1_zero_rtt}} -->
The `fd_quic_handle_v1_zero_rtt` function handles zero-RTT packets by failing the packet and signaling an internal error.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection associated with the packet.
    - `pkt`: A pointer to the `fd_quic_pkt_t` structure representing the packet being processed.
    - `cur_ptr`: A pointer to the current position in the packet data.
    - `cur_sz`: The size of the remaining data in the packet.
- **Control Flow**:
    - The function begins by ignoring the `pkt`, `cur_ptr`, and `cur_sz` parameters as they are not used.
    - It checks if the `conn` pointer is not null.
    - If `conn` is valid, it calls [`fd_quic_conn_error`](#fd_quic_conn_error) to signal an internal error for the connection.
    - Finally, it returns `FD_QUIC_PARSE_FAIL` to indicate that the packet processing has failed.
- **Output**: The function returns `FD_QUIC_PARSE_FAIL`, indicating that the processing of the zero-RTT packet has failed.
- **Functions called**:
    - [`fd_quic_conn_error`](#fd_quic_conn_error)


---
### fd\_quic\_lazy\_ack\_pkt<!-- {{#callable:fd_quic_lazy_ack_pkt}} -->
The `fd_quic_lazy_ack_pkt` function processes a QUIC acknowledgment packet and determines if an immediate acknowledgment should be sent.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC state.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `pkt`: A pointer to a constant `fd_quic_pkt_t` structure representing the received QUIC packet.
- **Control Flow**:
    - Checks if the `ACK_FLAG_CANCEL` is set in the packet's acknowledgment flags; if so, it returns `FD_QUIC_ACK_TX_CANCEL`.
    - Retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - Calls [`fd_quic_ack_pkt`](fd_quic_ack_tx.c.driver.md#fd_quic_ack_pkt) to acknowledge the packet number and update the acknowledgment generation state.
    - Updates the `is_elicited` flag in the acknowledgment generator based on the acknowledgment flags.
    - Determines if an immediate acknowledgment should be sent based on the unacknowledged size and acknowledgment flags.
    - Schedules the appropriate service type for sending the acknowledgment using [`fd_quic_svc_schedule`](#fd_quic_svc_schedule).
- **Output**: Returns the result of the acknowledgment processing, which indicates the outcome of the acknowledgment operation.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_ack_pkt`](fd_quic_ack_tx.c.driver.md#fd_quic_ack_pkt)
    - [`fd_quic_svc_schedule`](#fd_quic_svc_schedule)


---
### fd\_quic\_key\_update\_derive1<!-- {{#callable:fd_quic_key_update_derive1}} -->
The `fd_quic_key_update_derive1` function derives new keys for a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to a `fd_quic_conn_t` structure representing the QUIC connection whose keys are to be updated.
- **Control Flow**:
    - The function calls [`fd_quic_key_update_derive`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_key_update_derive), passing the secrets and new keys from the `conn` structure.
    - The [`fd_quic_key_update_derive`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_key_update_derive) function is responsible for the actual derivation of the new keys based on the current secrets.
- **Output**: The function does not return a value; it updates the keys in the provided connection structure.
- **Functions called**:
    - [`fd_quic_key_update_derive`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_key_update_derive)


---
### fd\_quic\_key\_update\_complete<!-- {{#callable:fd_quic_key_update_complete}} -->
The `fd_quic_key_update_complete` function updates the encryption keys and initialization vectors for a QUIC connection after a key update.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection whose keys are to be updated.
- **Control Flow**:
    - The function begins by defining the encryption level for application data as `fd_quic_enc_level_appdata_id`.
    - It updates the packet keys and initialization vectors for both the current and new keys using `memcpy`.
    - The function then updates the secrets for the encryption level with the new secrets.
    - It toggles the `key_phase` to prepare for the next key phase update.
    - Finally, it calls [`fd_quic_key_update_derive1`](#fd_quic_key_update_derive1) to derive the new keys and logs the completion of the key update.
- **Output**: The function does not return a value; it modifies the state of the `conn` structure directly.
- **Functions called**:
    - [`fd_quic_key_update_derive1`](#fd_quic_key_update_derive1)


---
### fd\_quic\_handle\_v1\_one\_rtt<!-- {{#callable:fd_quic_handle_v1_one_rtt}} -->
The `fd_quic_handle_v1_one_rtt` function processes a QUIC one-RTT packet, handling decryption, frame processing, and updating connection state.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection associated with the packet.
    - `pkt`: A pointer to the `fd_quic_pkt_t` structure where the processed packet information will be stored.
    - `cur_ptr`: A pointer to the current position in the packet data buffer.
    - `tot_sz`: The total size of the packet data.
- **Control Flow**:
    - Check if the connection pointer `conn` is NULL; if so, increment the no connection count and return failure.
    - Check if the connection state is invalid or if the application data keys are not available; if so, increment the no key count and return failure.
    - Verify that the total size of the packet is sufficient to contain the expected header and data; if not, increment the decrypt fail count and return failure.
    - Decrypt the packet header and payload using the appropriate keys based on the current key phase.
    - Reconstruct the packet number from the decrypted data and check if it is in the current key phase.
    - If the key phase has changed, update the connection's keys accordingly.
    - Process the frames contained in the packet, handling any errors that occur during frame processing.
    - Update the connection's last activity timestamp and expected packet number before returning the total size of the processed packet.
- **Output**: Returns the total size of the processed packet if successful, or `FD_QUIC_PARSE_FAIL` if an error occurs during processing.
- **Functions called**:
    - [`fd_quic_crypto_decrypt_hdr`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt_hdr)
    - [`fd_quic_h0_pkt_num_len`](templ/fd_quic_parse_util.h.driver.md#fd_quic_h0_pkt_num_len)
    - [`fd_quic_one_rtt_key_phase`](templ/fd_quic_parse_util.h.driver.md#fd_quic_one_rtt_key_phase)
    - [`fd_quic_pktnum_decode`](templ/fd_quic_parse_util.h.driver.md#fd_quic_pktnum_decode)
    - [`fd_quic_reconstruct_pkt_num`](#fd_quic_reconstruct_pkt_num)
    - [`fd_quic_crypto_decrypt`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt)
    - [`fd_quic_key_update_complete`](#fd_quic_key_update_complete)
    - [`fd_quic_handle_v1_frame`](#fd_quic_handle_v1_frame)
    - [`fd_quic_conn_error`](#fd_quic_conn_error)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)


---
### fd\_quic\_process\_quic\_packet\_v1<!-- {{#callable:fd_quic_process_quic_packet_v1}} -->
Processes a QUIC packet of version 1, handling both long and short header formats.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC connection.
    - `pkt`: A pointer to the `fd_quic_pkt_t` structure where the parsed packet data will be stored.
    - `cur_ptr`: A pointer to the current position in the packet data buffer.
    - `cur_sz`: The size of the packet data buffer.
- **Control Flow**:
    - Checks if the packet size is less than the minimum required size or greater than the maximum allowed size, incrementing metrics and returning a failure code if so.
    - Determines if the packet has a long or short header based on the first byte.
    - If the header is long, it decodes the long header and processes the packet based on its type (Initial, Handshake, Retry, or Zero-RTT).
    - If the header is short, it processes the packet as a One-RTT packet.
    - Handles any errors during processing by returning a failure code.
    - If all frames are parsed successfully, it acknowledges the packet and updates round-trip time metrics.
- **Output**: Returns the number of bytes consumed from the packet data buffer, or a failure code if an error occurred.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_h0_hdr_form`](templ/fd_quic_parse_util.h.driver.md#fd_quic_h0_hdr_form)
    - [`fd_quic_conn_id_t::fd_quic_conn_id_new`](fd_quic_conn_id.h.driver.md#fd_quic_conn_id_tfd_quic_conn_id_new)
    - [`fd_quic_conn_query`](fd_quic_private.h.driver.md#fd_quic_conn_query)
    - [`fd_quic_h0_long_packet_type`](templ/fd_quic_parse_util.h.driver.md#fd_quic_h0_long_packet_type)
    - [`fd_quic_handle_v1_initial`](#fd_quic_handle_v1_initial)
    - [`fd_quic_handle_v1_handshake`](#fd_quic_handle_v1_handshake)
    - [`fd_quic_handle_v1_retry`](#fd_quic_handle_v1_retry)
    - [`fd_quic_handle_v1_zero_rtt`](#fd_quic_handle_v1_zero_rtt)
    - [`fd_quic_handle_v1_one_rtt`](#fd_quic_handle_v1_one_rtt)
    - [`fd_quic_lazy_ack_pkt`](#fd_quic_lazy_ack_pkt)
    - [`fd_quic_sample_rtt`](fd_quic_private.h.driver.md#fd_quic_sample_rtt)


---
### is\_version\_invalid<!-- {{#callable:is_version_invalid}} -->
The `is_version_invalid` function checks if a given QUIC version is valid and updates metrics accordingly.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC connection.
    - `version`: An unsigned integer representing the version number to be validated.
- **Control Flow**:
    - If the `version` is 0, it increments the version negotiation count in `quic->metrics` and logs a debug message, returning 1.
    - If the `version` matches the pattern `0x0a0a0a0au`, it increments the version negotiation count and logs a debug message, returning 1.
    - If the `version` is not equal to 1, it increments the version negotiation count, logs a debug message, and returns 1.
    - If none of the above conditions are met, the function returns 0, indicating the version is valid.
- **Output**: Returns 1 if the version is invalid (0, forced negotiation, or unknown), otherwise returns 0.


---
### fd\_quic\_process\_packet<!-- {{#callable:fd_quic_process_packet}} -->
Processes a QUIC packet by decoding its headers and handling its contents.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC state.
    - `data`: A pointer to the raw packet data to be processed.
    - `data_sz`: The size of the packet data in bytes.
- **Control Flow**:
    - The function retrieves the current state of the QUIC connection and updates the current time.
    - It checks if the packet size exceeds the maximum allowed size, logging an error if it does.
    - The function attempts to decode the IPv4 header from the packet data, returning early if it fails.
    - It verifies that the packet is a UDP packet and checks for truncation based on the header's total length.
    - The function then decodes the UDP header and checks for valid lengths, returning early on failure.
    - It checks if the remaining payload size is sufficient for a valid QUIC packet.
    - If the packet is a long header, it processes it accordingly, handling multiple packets if necessary.
    - For short headers, it processes the packet directly.
    - Finally, it schedules the connection for servicing based on the processed packet.
- **Output**: The function does not return a value; it modifies the state of the QUIC connection and schedules it for further processing.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_now`](fd_quic_private.h.driver.md#fd_quic_now)
    - [`is_version_invalid`](#is_version_invalid)
    - [`fd_quic_process_quic_packet_v1`](#fd_quic_process_quic_packet_v1)


---
### fd\_quic\_aio\_cb\_receive<!-- {{#callable:fd_quic_aio_cb_receive}} -->
The `fd_quic_aio_cb_receive` function processes a batch of received QUIC packets.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_t` structure representing the QUIC context.
    - `batch`: An array of `fd_aio_pkt_info_t` structures containing information about the received packets.
    - `batch_cnt`: The number of packets in the batch.
    - `opt_batch_idx`: An optional pointer to store the index of the last processed packet.
    - `flush`: An integer flag indicating whether to flush the processing.
- **Control Flow**:
    - The function begins by ignoring the `flush` parameter.
    - It retrieves the current QUIC context from the `context` pointer.
    - The current tick count is recorded for performance metrics.
    - A debug block captures the current state time for performance analysis.
    - A loop iterates over each packet in the `batch`, processing each packet using [`fd_quic_process_packet`](#fd_quic_process_packet).
    - The total number of bytes received is accumulated into the metrics.
    - If `opt_batch_idx` is provided, it is set to the total number of packets processed.
    - The total number of packets received is updated in the metrics.
    - A debug block logs the time taken for processing if it exceeds a threshold.
    - Finally, the function samples the duration of the receive operation for metrics.
- **Output**: The function returns `FD_AIO_SUCCESS` to indicate successful processing of the received packets.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_process_packet`](#fd_quic_process_packet)
    - [`fd_quic_now`](fd_quic_private.h.driver.md#fd_quic_now)


---
### fd\_quic\_tls\_cb\_alert<!-- {{#callable:fd_quic_tls_cb_alert}} -->
The `fd_quic_tls_cb_alert` function handles TLS alert callbacks for QUIC connections.
- **Inputs**:
    - `hs`: A pointer to the TLS handshake state structure, which is currently unused in this function.
    - `context`: A pointer to the context, which is expected to be a `fd_quic_conn_t` structure representing the QUIC connection.
    - `alert`: An integer representing the TLS alert code that indicates the type of alert.
- **Control Flow**:
    - The function begins by casting the `context` pointer to a `fd_quic_conn_t` type to access the connection details.
    - It logs the server/client status of the connection and the alert code using debug logging.
    - The function currently does not implement any logic to store the alert for future use, as indicated by the TODO comment.
- **Output**: The function does not return any value; it primarily performs logging and has a placeholder for future alert handling.


---
### fd\_quic\_tls\_cb\_secret<!-- {{#callable:fd_quic_tls_cb_secret}} -->
The `fd_quic_tls_cb_secret` function processes the TLS secrets for a QUIC connection during the handshake phase.
- **Inputs**:
    - `hs`: A pointer to the `fd_quic_tls_hs_t` structure representing the TLS handshake state.
    - `context`: A pointer to the context, which is cast to a `fd_quic_conn_t` structure representing the QUIC connection.
    - `secret`: A pointer to a constant `fd_quic_tls_secret_t` structure containing the read and write secrets and the encryption level.
- **Control Flow**:
    - The function begins by casting the `context` pointer to a `fd_quic_conn_t` structure to access the connection details.
    - It verifies that the encryption level specified in the `secret` is valid by checking it against the defined number of encryption levels.
    - The read and write secrets are copied into the connection's secret storage for the specified encryption level.
    - The availability of keys for the specified encryption level is updated.
    - Local and peer keys are generated using the copied secrets.
    - If the encryption level is for application data, a key update is derived.
    - If a key logging function is set, the function logs the generated secrets for debugging or analysis.
- **Output**: The function does not return a value; it modifies the state of the QUIC connection by storing the secrets and generating keys.
- **Functions called**:
    - [`fd_quic_gen_keys`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_keys)
    - [`fd_quic_key_update_derive`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_key_update_derive)


---
### fd\_quic\_tls\_cb\_peer\_params<!-- {{#callable:fd_quic_tls_cb_peer_params}} -->
The `fd_quic_tls_cb_peer_params` function processes and applies transport parameters received from a peer in a QUIC connection.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_conn_t` structure representing the current QUIC connection.
    - `peer_tp_enc`: A pointer to the encoded transport parameters received from the peer.
    - `peer_tp_enc_sz`: The size of the encoded transport parameters.
- **Control Flow**:
    - The function begins by decoding the transport parameters from the encoded data using [`fd_quic_decode_transport_params`](templ/fd_quic_transport_params.c.driver.md#fd_quic_decode_transport_params).
    - If decoding fails, it logs an error and calls [`fd_quic_conn_error`](#fd_quic_conn_error) to signal a transport parameter error.
    - It updates the connection's flow control parameters based on the decoded values.
    - If the connection is not a server, it verifies the retry source connection ID against the received parameters.
    - It sets the maximum datagram size based on the received parameters, ensuring it meets minimum requirements.
    - It updates the maximum number of unidirectional streams based on whether the connection is a server or client.
    - It adjusts the idle timeout based on the minimum of the local and peer's maximum idle timeout values.
    - It sets the acknowledgment delay exponent and calculates the peer's maximum acknowledgment delay.
- **Output**: The function does not return a value but modifies the state of the connection based on the received transport parameters.
- **Functions called**:
    - [`fd_quic_decode_transport_params`](templ/fd_quic_transport_params.c.driver.md#fd_quic_decode_transport_params)
    - [`fd_quic_conn_error`](#fd_quic_conn_error)
    - [`fd_quic_us_to_ticks`](#fd_quic_us_to_ticks)


---
### fd\_quic\_tls\_cb\_handshake\_complete<!-- {{#callable:fd_quic_tls_cb_handshake_complete}} -->
The `fd_quic_tls_cb_handshake_complete` function handles the completion of a QUIC TLS handshake.
- **Inputs**:
    - `hs`: A pointer to the TLS handshake state structure, which contains information about the current handshake.
    - `context`: A pointer to the connection context, which is cast to a `fd_quic_conn_t` structure.
- **Control Flow**:
    - The function first checks the state of the connection referenced by `context`.
    - If the connection state is `FD_QUIC_CONN_STATE_ABORT`, `FD_QUIC_CONN_STATE_CLOSE_PENDING`, or `FD_QUIC_CONN_STATE_DEAD`, the function returns immediately, ignoring the handshake completion.
    - If the connection is in the `FD_QUIC_CONN_STATE_HANDSHAKE` state, it checks if the transport parameters have been set; if not, it logs a warning and triggers an internal error.
    - If the transport parameters are set, it marks the handshake as complete, updates the connection state to `FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE`, and returns.
- **Output**: The function does not return a value but modifies the state of the connection to indicate that the handshake is complete, or logs an error if the handshake is in an unexpected state.
- **Functions called**:
    - [`fd_quic_conn_error`](#fd_quic_conn_error)
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)


---
### fd\_quic\_handle\_crypto\_frame<!-- {{#callable:fd_quic_handle_crypto_frame}} -->
The `fd_quic_handle_crypto_frame` function processes a QUIC crypto frame, handling the reception of cryptographic data during the handshake phase.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context and packet information.
    - `crypto`: A pointer to the `fd_quic_crypto_frame_t` structure that contains the offset and length of the crypto data.
    - `p`: A pointer to the data buffer containing the crypto frame data.
    - `p_sz`: The size of the data buffer.
- **Control Flow**:
    - The function first retrieves the connection and TLS handshake state from the context.
    - It calculates the expected offset and size of the received crypto data.
    - If the received size exceeds the available data size, it triggers a frame error and returns a failure code.
    - If the TLS handshake is already completed, it ignores the frame and returns the size of the received data.
    - If the encryption level of the received data is lower than the current level, it returns the size without processing.
    - If the encryption level is higher, it updates the expected encryption level and resets the received data size.
    - If the received offset is greater than the current size of received data, it sets a cancel acknowledgment flag and returns the size.
    - If the received data exceeds the maximum buffer size, it triggers a frame error and returns a failure code.
    - The function copies the received data into the TLS handshake buffer and processes the TLS handshake.
    - If the TLS processing fails, it triggers a connection error based on the TLS alert and returns a failure code.
    - Finally, it returns the size of the received data.
- **Output**: Returns the size of the received crypto data if successful, or a failure code if an error occurs.
- **Functions called**:
    - [`fd_quic_frame_error`](#fd_quic_frame_error)
    - [`fd_quic_tls_process`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_process)


---
### fd\_quic\_svc\_poll<!-- {{#callable:fd_quic_svc_poll}} -->
The `fd_quic_svc_poll` function processes the state of a QUIC connection, handling idle timeouts and scheduling for service.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection to be polled.
    - `now`: An unsigned long integer representing the current time in ticks.
- **Control Flow**:
    - The function retrieves the current state of the QUIC instance using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - It checks if the connection state is invalid; if so, it logs an error and returns.
    - The service type and time for the connection are reset to default values.
    - If the current time exceeds the last activity time plus half of the idle timeout, it checks for idle timeout conditions.
    - If the connection has been idle for longer than the full idle timeout, it marks the connection as dead and increments the timeout count.
    - If the connection is not dead, it calls [`fd_quic_conn_service`](#fd_quic_conn_service) to handle the connection's service logic.
    - Finally, based on the connection's state, it either frees the connection, schedules it for future service, or does nothing.
- **Output**: The function returns an integer indicating the result of the polling operation, typically 1 to indicate successful processing.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_ticks_to_us`](#fd_quic_ticks_to_us)
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)
    - [`fd_quic_cb_conn_final`](fd_quic_private.h.driver.md#fd_quic_cb_conn_final)
    - [`fd_quic_conn_free`](#fd_quic_conn_free)
    - [`fd_quic_conn_service`](#fd_quic_conn_service)
    - [`fd_quic_svc_schedule`](#fd_quic_svc_schedule)


---
### fd\_quic\_svc\_poll\_head<!-- {{#callable:fd_quic_svc_poll_head}} -->
The `fd_quic_svc_poll_head` function processes the head of a service queue for QUIC connections, checking if the connection is ready for servicing based on the current time.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC state.
    - `svc_type`: An unsigned integer representing the type of service queue to poll.
    - `now`: An unsigned long representing the current time in ticks.
- **Control Flow**:
    - The function retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - It checks if the head of the specified service queue is empty (i.e., if `queue->head` is `UINT_MAX`). If it is, the function returns 0, indicating no connections to process.
    - It retrieves the connection at the head of the queue and checks if its scheduled service time (`conn->svc_time`) is greater than the current time (`now`). If it is, the function returns 0, indicating that the connection is not ready to be serviced yet.
    - If the connection is ready, it removes the head of the queue by updating the previous connection's next pointer and setting the queue's head to the previous connection's index.
    - Finally, it calls [`fd_quic_svc_poll`](#fd_quic_svc_poll) to process the connection.
- **Output**: The function returns an integer indicating the result of the polling operation, specifically the number of connections processed (0 or 1).
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)
    - [`fd_quic_svc_poll`](#fd_quic_svc_poll)


---
### fd\_quic\_svc\_poll\_tail<!-- {{#callable:fd_quic_svc_poll_tail}} -->
The `fd_quic_svc_poll_tail` function processes the tail of a service queue for QUIC connections, removing the tail connection if it is ready to be serviced.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `svc_type`: An unsigned integer representing the type of service queue to poll.
    - `now`: An unsigned long representing the current time in ticks.
- **Control Flow**:
    - The function retrieves the current state of the QUIC instance using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - It checks if the tail of the specified service queue is valid (not UINT_MAX).
    - If the tail is valid, it retrieves the connection at the tail index.
    - It checks if the connection's service time is less than or equal to the current time.
    - If the connection is ready, it removes the tail connection from the queue.
    - It updates the queue's tail to the next connection in the queue.
    - Finally, it calls [`fd_quic_svc_poll`](#fd_quic_svc_poll) to process the connection.
- **Output**: The function returns an integer indicating the result of the polling operation, specifically whether a connection was processed or not.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)
    - [`fd_quic_svc_poll`](#fd_quic_svc_poll)


---
### fd\_quic\_service<!-- {{#callable:fd_quic_service}} -->
The `fd_quic_service` function processes QUIC connection events and manages the service queue.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC connection state.
- **Control Flow**:
    - The function retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - It updates the current time in the state structure.
    - It records the current tick count for performance measurement.
    - The function polls the service queue for different service types: instant, ACK transmission, and waiting.
    - It accumulates the count of processed events from the polling functions.
    - Finally, it samples the service duration metric and returns the total count of processed events.
- **Output**: Returns an integer representing the total number of events processed during the service call.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_now`](fd_quic_private.h.driver.md#fd_quic_now)
    - [`fd_quic_svc_poll_tail`](#fd_quic_svc_poll_tail)
    - [`fd_quic_svc_poll_head`](#fd_quic_svc_poll_head)


---
### fd\_quic\_conn\_tx\_buf\_remaining<!-- {{#callable:fd_quic_conn_tx_buf_remaining}} -->
The `fd_quic_conn_tx_buf_remaining` function calculates the remaining space in the transmission buffer of a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to a `fd_quic_conn_t` structure representing the QUIC connection whose transmission buffer is being queried.
- **Control Flow**:
    - The function computes the size of the transmission buffer by accessing the `tx_buf_conn` member of the `conn` structure.
    - It calculates the remaining space by subtracting the current pointer position (`tx_ptr`) from the total size of the buffer (`tx_buf_conn`).
- **Output**: Returns the number of bytes remaining in the transmission buffer as an unsigned long integer.


---
### fd\_quic\_tx\_buffered\_raw<!-- {{#callable:fd_quic_tx_buffered_raw}} -->
The `fd_quic_tx_buffered_raw` function prepares and sends a QUIC packet containing buffered data over a network connection.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC connection configuration.
    - `tx_ptr_ptr`: A pointer to a pointer to the current position in the transmission buffer, which will be updated to point to the start of the buffer after sending.
    - `tx_buf`: A pointer to the buffer containing the data to be transmitted.
    - `ipv4_id`: A pointer to a `ushort` that holds the IPv4 identification field, which will be incremented after sending.
    - `dst_ipv4_addr`: The destination IPv4 address to which the packet will be sent.
    - `dst_udp_port`: The destination UDP port for the packet.
    - `src_ipv4_addr`: The source IPv4 address from which the packet is sent.
    - `src_udp_port`: The source UDP port from which the packet is sent.
- **Control Flow**:
    - The function calculates the size of the payload by determining the difference between the current transmission pointer and the start of the transmission buffer.
    - If the payload size is less than or equal to zero, the function returns 0, indicating that there is nothing to send.
    - The function initializes a `fd_quic_pkt_t` structure to hold the packet data, setting various fields such as IP version, total length, source and destination addresses, and ports.
    - It encodes the IPv4 header and checks for buffer overrun errors.
    - The function computes the checksum for the IPv4 header and encodes the UDP header, again checking for buffer overrun errors.
    - If there is insufficient space in the buffer for the payload, it resets the transmission pointer and returns a failure code.
    - The payload is copied into the buffer, and an asynchronous send operation is initiated.
    - If the send operation is successful, the function updates metrics and resets the transmission pointer.
- **Output**: The function returns `FD_QUIC_SUCCESS` on successful transmission, `FD_QUIC_FAILED` if the send operation fails, or 0 if there is nothing to send.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_encode_ip4`](fd_quic_proto.h.driver.md#fd_quic_encode_ip4)
    - [`fd_quic_encode_udp`](fd_quic_proto.h.driver.md#fd_quic_encode_udp)


---
### fd\_quic\_tx\_buffered<!-- {{#callable:fd_quic_tx_buffered}} -->
The `fd_quic_tx_buffered` function transmits buffered QUIC data from a connection's transmission buffer.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection from which data will be transmitted.
- **Control Flow**:
    - The function retrieves the peer endpoint information from the connection structure.
    - It then calls the [`fd_quic_tx_buffered_raw`](#fd_quic_tx_buffered_raw) function to handle the actual transmission of the buffered data.
    - The [`fd_quic_tx_buffered_raw`](#fd_quic_tx_buffered_raw) function is responsible for preparing the packet headers and sending the data over the network.
- **Output**: The function returns a status code indicating the success or failure of the transmission operation.
- **Functions called**:
    - [`fd_quic_tx_buffered_raw`](#fd_quic_tx_buffered_raw)


---
### fd\_quic\_conn\_can\_acquire\_pkt\_meta<!-- {{#callable:fd_quic_conn_can_acquire_pkt_meta}} -->
The `fd_quic_conn_can_acquire_pkt_meta` function checks if a QUIC connection can acquire packet metadata.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `tracker`: A pointer to the `fd_quic_pkt_meta_tracker_t` structure that tracks packet metadata.
- **Control Flow**:
    - The function retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - It checks the available space in the packet metadata pool using `fd_quic_pkt_meta_pool_free`.
    - If the pool is empty or the connection has reached its maximum inflight frame count, it updates the metrics accordingly and returns 0.
    - If there is available space, it increments the success count in the metrics and returns 1.
- **Output**: The function returns 1 if the connection can acquire packet metadata, or 0 if it cannot.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)


---
### fd\_quic\_gen\_frame\_store\_pkt\_meta<!-- {{#callable:fd_quic_gen_frame_store_pkt_meta}} -->
Stores packet metadata in a tracker for QUIC connections.
- **Inputs**:
    - `pkt_meta_tmpl`: A pointer to a template of the packet metadata structure (`fd_quic_pkt_meta_t`) that will be copied to the new metadata.
    - `type`: An unsigned character representing the type of the packet metadata being stored.
    - `value`: A value of type `fd_quic_pkt_meta_value_t` that holds the value associated with the packet metadata.
    - `tracker`: A pointer to a `fd_quic_pkt_meta_tracker_t` structure that manages the storage of packet metadata.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection associated with the packet metadata.
- **Control Flow**:
    - The function first checks if the connection can acquire packet metadata by calling [`fd_quic_conn_can_acquire_pkt_meta`](#fd_quic_conn_can_acquire_pkt_meta).
    - If the connection cannot acquire packet metadata, the function returns 0.
    - If successful, it increments the `used_pkt_meta` count in the connection structure.
    - It then acquires a new packet metadata element from the pool and copies the contents of `pkt_meta_tmpl` into it.
    - The type and value are set for the new packet metadata.
    - Finally, the new packet metadata is inserted into the tracker and the function returns 1.
- **Output**: Returns 1 if the packet metadata was successfully stored, or 0 if it failed due to insufficient resources.
- **Functions called**:
    - [`fd_quic_conn_can_acquire_pkt_meta`](#fd_quic_conn_can_acquire_pkt_meta)
    - [`fd_quic_pkt_meta_insert`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_insert)


---
### fd\_quic\_gen\_close\_frame<!-- {{#callable:fd_quic_gen_close_frame}} -->
Generates a QUIC connection close frame.
- **Inputs**:
    - `conn`: Pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `payload_ptr`: Pointer to the start of the payload buffer where the frame will be encoded.
    - `payload_end`: Pointer to the end of the payload buffer, indicating the maximum space available for encoding.
    - `pkt_meta_tmpl`: Pointer to a template for packet metadata that will be used for the generated frame.
    - `tracker`: Pointer to a `fd_quic_pkt_meta_tracker_t` structure used to track packet metadata.
- **Control Flow**:
    - Checks if a close frame has already been sent by examining the `FD_QUIC_CONN_FLAGS_CLOSE_SENT` flag in the connection's flags.
    - If a close frame has not been sent, it sets the `FD_QUIC_CONN_FLAGS_CLOSE_SENT` flag to indicate that a close frame is being generated.
    - Determines the type of close frame to generate based on the connection's reason and state.
    - Encodes the appropriate close frame (either `fd_quic_conn_close_0_frame_t` or `fd_quic_conn_close_1_frame_t`) into the provided payload buffer.
    - If encoding fails, logs a warning and returns 0.
    - Attempts to store packet metadata for the generated close frame using [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta).
    - Returns the size of the generated frame or 0 if any step fails.
- **Output**: Returns the size of the generated close frame in bytes, or 0 if the frame could not be generated.
- **Functions called**:
    - [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta)


---
### fd\_quic\_gen\_handshake\_frames<!-- {{#callable:fd_quic_gen_handshake_frames}} -->
Generates QUIC handshake frames for transmission.
- **Inputs**:
    - `conn`: Pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `payload_ptr`: Pointer to the current position in the payload buffer where data will be written.
    - `payload_end`: Pointer to the end of the payload buffer, used to check for buffer overflows.
    - `pkt_meta_tmpl`: Pointer to a template for packet metadata, which includes information about the encryption level.
    - `tracker`: Pointer to a `fd_quic_pkt_meta_tracker_t` structure used to track packet metadata.
- **Control Flow**:
    - Retrieve the encryption level from the packet metadata template.
    - Get the handshake data associated with the current encryption level.
    - If no handshake data is available, return the current position of the payload pointer.
    - Check if there is space in the packet metadata tracker to acquire new metadata.
    - Calculate offsets for sent and acknowledged handshake bytes.
    - Iterate through the handshake data, encoding it into frames until all data is processed or the payload buffer is full.
    - For each piece of handshake data, check if it has already been sent and skip it if so.
    - If a gap in the handshake data is detected, log a warning and break the loop.
    - Update the packet metadata with the range of bytes sent.
- **Output**: Returns a pointer to the updated position in the payload buffer after writing the handshake frames.
- **Functions called**:
    - [`fd_quic_tls_get_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_get_hs_data)
    - [`fd_quic_conn_can_acquire_pkt_meta`](#fd_quic_conn_can_acquire_pkt_meta)
    - [`fd_quic_tls_get_next_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_get_next_hs_data)
    - [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta)


---
### fd\_quic\_gen\_handshake\_done\_frame<!-- {{#callable:fd_quic_gen_handshake_done_frame}} -->
Generates a QUIC handshake done frame for transmission.
- **Inputs**:
    - `conn`: Pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `payload_ptr`: Pointer to the start of the payload buffer where the frame will be written.
    - `payload_end`: Pointer to the end of the payload buffer, used to check for buffer overflows.
    - `pkt_meta_tmpl`: Pointer to a template for packet metadata that will be used for the frame.
    - `tracker`: Pointer to a `fd_quic_pkt_meta_tracker_t` structure for tracking packet metadata.
- **Control Flow**:
    - The function first checks if the handshake done frame has already been sent; if so, it returns 0.
    - It sets the `handshake_done_send` flag to 0 to indicate that the handshake done frame is being sent.
    - It checks if the handshake done frame has already been acknowledged; if so, it returns 0.
    - It checks if there is space in the payload buffer; if not, it returns 0.
    - It writes the handshake done frame identifier (0x1E) to the payload buffer.
    - It attempts to store the packet metadata for the handshake done frame; if this fails, it returns 0.
    - Finally, it returns 1 to indicate that the frame was successfully generated.
- **Output**: Returns 1 if the handshake done frame was successfully generated and stored; otherwise, returns 0.
- **Functions called**:
    - [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta)


---
### fd\_quic\_gen\_max\_data\_frame<!-- {{#callable:fd_quic_gen_max_data_frame}} -->
Generates a QUIC Max Data frame for transmission.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection structure (`fd_quic_conn_t`) that holds the connection state and parameters.
    - `payload_ptr`: A pointer to the start of the buffer where the Max Data frame will be encoded.
    - `payload_end`: A pointer to the end of the buffer to ensure that the frame does not exceed the allocated space.
    - `pkt_meta_tmpl`: A pointer to a template for packet metadata (`fd_quic_pkt_meta_t`) that will be used to store information about the generated frame.
    - `tracker`: A pointer to a packet metadata tracker (`fd_quic_pkt_meta_tracker_t`) that manages the allocation and deallocation of packet metadata.
- **Control Flow**:
    - Checks if the connection has the `FD_QUIC_CONN_FLAGS_MAX_DATA` flag set; if not, returns 0.
    - Checks if the maximum data to be sent has already been acknowledged; if so, returns 0.
    - Creates a `fd_quic_max_data_frame_t` structure and populates it with the current maximum data value.
    - Attempts to encode the Max Data frame into the provided buffer using `fd_quic_encode_max_data_frame` and checks for encoding failure.
    - If encoding is successful, it attempts to store the packet metadata using [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta) and checks for success.
    - Updates the connection's packet number and returns the size of the encoded frame.
- **Output**: Returns the size of the generated Max Data frame in bytes, or 0 if the frame could not be generated.
- **Functions called**:
    - [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta)


---
### fd\_quic\_gen\_max\_streams\_frame<!-- {{#callable:fd_quic_gen_max_streams_frame}} -->
Generates a MAX_STREAMS frame for a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `payload_ptr`: A pointer to the buffer where the generated frame will be written.
    - `payload_end`: A pointer to the end of the buffer to prevent overflow.
    - `pkt_meta_tmpl`: A pointer to a template for packet metadata used for tracking.
    - `tracker`: A pointer to a `fd_quic_pkt_meta_tracker_t` structure for managing packet metadata.
- **Control Flow**:
    - The function retrieves the maximum number of unidirectional streams supported by the connection.
    - It checks if the `FD_QUIC_MAX_STREAMS_ALWAYS_UNLESS_ACKED` flag is set; if not, it verifies if the maximum streams flag is enabled and if the maximum streams have been acknowledged.
    - If the conditions are met, it constructs a `fd_quic_max_streams_frame_t` structure with the appropriate type and maximum streams value.
    - The function then encodes this frame into the provided payload buffer and checks for encoding success.
    - If encoding is successful, it stores the packet metadata and updates the connection's flags and packet number.
- **Output**: Returns the size of the generated frame in bytes, or 0 if the frame could not be generated.
- **Functions called**:
    - [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta)


---
### fd\_quic\_gen\_ping\_frame<!-- {{#callable:fd_quic_gen_ping_frame}} -->
Generates a QUIC ping frame for the specified connection.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `payload_ptr`: A pointer to the start of the payload buffer where the frame will be encoded.
    - `payload_end`: A pointer to the end of the payload buffer, indicating the maximum size available for the frame.
    - `pkt_meta_tmpl`: A pointer to a `fd_quic_pkt_meta_t` structure that serves as a template for the packet metadata.
    - `tracker`: A pointer to a `fd_quic_pkt_meta_tracker_t` structure used to track packet metadata.
- **Control Flow**:
    - Checks if the connection is allowed to send a ping frame by verifying the connection flags.
    - If a ping frame has already been sent, the function returns 0 to indicate no new frame is generated.
    - Encodes a ping frame into the provided payload buffer using `fd_quic_encode_ping_frame`.
    - If encoding fails, it returns 0.
    - Updates the connection flags to indicate that a ping has been sent and clears the ping request flag.
    - Records the packet number for the generated frame in the connection's metadata tracker.
- **Output**: Returns the size of the generated ping frame in bytes, or 0 if no frame was generated.
- **Functions called**:
    - [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta)


---
### fd\_quic\_gen\_stream\_frames<!-- {{#callable:fd_quic_gen_stream_frames}} -->
Generates QUIC stream frames for transmission over a connection.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `payload_ptr`: A pointer to the current position in the payload buffer where the stream frames will be written.
    - `payload_end`: A pointer to the end of the payload buffer, used to ensure that frames do not exceed the buffer size.
    - `pkt_meta_tmpl`: A pointer to a `fd_quic_pkt_meta_t` structure that serves as a template for packet metadata.
    - `tracker`: A pointer to a `fd_quic_pkt_meta_tracker_t` structure that tracks packet metadata for the connection.
- **Control Flow**:
    - The function initializes a loop to iterate through the streams associated with the connection.
    - For each stream, it checks if there is data available to send and if the stream is eligible for sending.
    - It calculates the amount of data available and checks if there is enough space in the payload buffer to write the stream frame.
    - If conditions are met, it encodes the stream ID, offset, and data length into the payload buffer.
    - The function updates the stream's metadata, including the number of bytes sent and the packet number.
    - If all data from a stream has been sent, it removes the stream from the send list and adds it to the used streams.
- **Output**: Returns a pointer to the updated position in the payload buffer after writing the stream frames.
- **Functions called**:
    - [`fd_quic_conn_can_acquire_pkt_meta`](#fd_quic_conn_can_acquire_pkt_meta)
    - [`fd_quic_varint_encode`](templ/fd_quic_parse_util.h.driver.md#fd_quic_varint_encode)
    - [`fd_quic_buffer_load`](fd_quic_stream.c.driver.md#fd_quic_buffer_load)
    - [`fd_quic_gen_frame_store_pkt_meta`](#fd_quic_gen_frame_store_pkt_meta)


---
### fd\_quic\_gen\_frames<!-- {{#callable:fd_quic_gen_frames}} -->
Generates QUIC frames for transmission based on the connection state and available data.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `payload_ptr`: A pointer to the current position in the payload buffer where frames will be generated.
    - `payload_end`: A pointer to the end of the payload buffer, indicating the maximum space available for frame generation.
    - `pkt_meta_tmpl`: A pointer to a `fd_quic_pkt_meta_t` structure that serves as a template for packet metadata.
    - `now`: A timestamp representing the current time, used for frame expiration and timing.
- **Control Flow**:
    - The function first checks the state of the connection to determine if it is closing.
    - It generates acknowledgment frames using [`fd_quic_gen_ack_frames`](fd_quic_ack_tx.c.driver.md#fd_quic_gen_ack_frames) and updates the payload pointer.
    - If the connection is closing, it generates a close frame using [`fd_quic_gen_close_frame`](#fd_quic_gen_close_frame).
    - If the connection is not closing, it generates handshake frames using [`fd_quic_gen_handshake_frames`](#fd_quic_gen_handshake_frames).
    - If the encryption level is application data, it generates additional frames such as handshake done, max data, max streams, and ping frames.
    - Finally, it returns the updated payload pointer.
- **Output**: Returns a pointer to the updated position in the payload buffer after generating the frames.
- **Functions called**:
    - [`fd_quic_gen_ack_frames`](fd_quic_ack_tx.c.driver.md#fd_quic_gen_ack_frames)
    - [`fd_quic_gen_close_frame`](#fd_quic_gen_close_frame)
    - [`fd_quic_gen_handshake_frames`](#fd_quic_gen_handshake_frames)
    - [`fd_quic_gen_handshake_done_frame`](#fd_quic_gen_handshake_done_frame)
    - [`fd_quic_gen_max_data_frame`](#fd_quic_gen_max_data_frame)
    - [`fd_quic_gen_max_streams_frame`](#fd_quic_gen_max_streams_frame)
    - [`fd_quic_gen_ping_frame`](#fd_quic_gen_ping_frame)
    - [`fd_quic_gen_stream_frames`](#fd_quic_gen_stream_frames)


---
### fd\_quic\_conn\_tx<!-- {{#callable:fd_quic_conn_tx}} -->
The `fd_quic_conn_tx` function is responsible for transmitting QUIC connection data by encoding and sending packets based on the current connection state.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection to be transmitted.
- **Control Flow**:
    - The function first checks if the connection state is `FD_QUIC_CONN_STATE_DEAD`, and if so, it returns immediately.
    - It retrieves the current state of the QUIC instance and prepares a scratch buffer for encoding frames.
    - If there is data to be transmitted (indicated by `tx_ptr` not being equal to `tx_buf_conn`), it calls [`fd_quic_tx_buffered`](#fd_quic_tx_buffered) to handle buffered data.
    - The function determines the appropriate encryption level for transmission, ensuring that ACK-only packets are minimized.
    - If the connection is a client and the encryption level is for handshake, it abandons the initial encryption level.
    - It initializes packet metadata and enters a loop to encode and send packets until there are no more packets to send or an error occurs.
    - Within the loop, it encodes the packet header and payload, checking for available space and handling any necessary padding.
    - If the encoding is successful, it encrypts the packet and updates the connection's packet number.
    - Finally, it schedules the connection for service to handle any further actions required.
- **Output**: The function does not return a value but modifies the state of the connection and the QUIC instance, potentially sending packets over the network.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_tx_buffered`](#fd_quic_tx_buffered)
    - [`fd_quic_svc_schedule`](#fd_quic_svc_schedule)
    - [`fd_quic_tx_enc_level`](#fd_quic_tx_enc_level)
    - [`fd_quic_abandon_enc_level`](#fd_quic_abandon_enc_level)
    - [`fd_quic_enc_level_to_pn_space`](#fd_quic_enc_level_to_pn_space)
    - [`fd_quic_initial_h0`](templ/fd_quic_parse_util.h.driver.md#fd_quic_initial_h0)
    - [`fd_quic_handshake_h0`](templ/fd_quic_parse_util.h.driver.md#fd_quic_handshake_h0)
    - [`fd_quic_one_rtt_h0`](templ/fd_quic_parse_util.h.driver.md#fd_quic_one_rtt_h0)
    - [`fd_quic_gen_frames`](#fd_quic_gen_frames)
    - [`fd_quic_conn_tx_buf_remaining`](#fd_quic_conn_tx_buf_remaining)
    - [`fd_quic_crypto_encrypt`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_encrypt)


---
### fd\_quic\_conn\_service<!-- {{#callable:fd_quic_conn_service}} -->
The `fd_quic_conn_service` function manages the state and transmission of QUIC connection data, handling tasks such as sending PING frames, processing connection state changes, and transmitting buffered data.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance managing the connection.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the specific QUIC connection being serviced.
    - `now`: An unsigned long integer representing the current time in ticks, used for timing and scheduling tasks.
- **Control Flow**:
    - The function first checks if a new RTT measurement probe should be sent based on the current time and the last acknowledgment time.
    - If the connection is in the HANDSHAKE or HANDSHAKE_COMPLETE state, it processes the TLS handshake and may send a handshake-done frame.
    - In the CLOSE_PENDING or PEER_CLOSE states, it transmits the failure reason and schedules the connection for closure.
    - In the ACTIVE state, it checks for data to transmit and calls the [`fd_quic_conn_tx`](#fd_quic_conn_tx) function to handle the transmission.
    - If the connection is DEAD or INVALID, the function exits without performing any actions.
- **Output**: The function does not return a value but modifies the state of the connection and may schedule further actions based on the connection's state and the data to be transmitted.
- **Functions called**:
    - [`fd_quic_pkt_meta_retry`](#fd_quic_pkt_meta_retry)
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)
    - [`fd_quic_abandon_enc_level`](#fd_quic_abandon_enc_level)
    - [`fd_quic_cb_conn_new`](fd_quic_private.h.driver.md#fd_quic_cb_conn_new)
    - [`fd_quic_tls_get_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_get_hs_data)
    - [`fd_quic_tls_pop_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_pop_hs_data)
    - [`fd_quic_conn_tx`](#fd_quic_conn_tx)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)


---
### fd\_quic\_conn\_free<!-- {{#callable:fd_quic_conn_free}} -->
Frees a QUIC connection and its associated resources.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection to be freed.
- **Control Flow**:
    - Checks if the `conn` pointer is NULL and logs a warning if so.
    - Checks if the connection state is invalid, logging a critical error if a double free is detected.
    - Sets the connection state to invalid using [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state).
    - Removes all streams associated with the connection, freeing each stream.
    - Checks if any stream map entries remain and attempts to clean them up.
    - If the connection has a TLS handshake state, it frees the TLS handshake resources.
    - Removes the connection from the service queue if it is scheduled.
    - Adds the connection back to the free list.
    - Clears the connection's secrets and keys.
- **Output**: The function does not return a value, but it modifies the state of the QUIC connection and its associated resources.
- **Functions called**:
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_tx_stream_free`](#fd_quic_tx_stream_free)
    - [`fd_quic_tls_hs_delete`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_hs_delete)
    - [`fd_quic_svc_unqueue`](#fd_quic_svc_unqueue)


---
### fd\_quic\_connect<!-- {{#callable:fd_quic_connect}} -->
Establishes a QUIC connection with specified parameters.
- **Inputs**:
    - `quic`: Pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `dst_ip_addr`: Destination IP address for the QUIC connection.
    - `dst_udp_port`: Destination UDP port for the QUIC connection.
    - `src_ip_addr`: Source IP address for the QUIC connection.
    - `src_udp_port`: Source UDP port for the QUIC connection.
- **Control Flow**:
    - Retrieve the current state of the QUIC instance using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - Check if there is space in the TLS handshake pool; if not, attempt to evict the oldest entry.
    - Generate a unique connection ID for the local connection and a random connection ID for the peer.
    - Create a new QUIC connection using [`fd_quic_conn_create`](#fd_quic_conn_create) with the generated IDs and provided addresses.
    - Prepare transport parameters for the QUIC-TLS handshake, ensuring certain fields are set to zero as required by the protocol.
    - Create a new TLS handshake object and check for errors; if an error occurs, free the connection and return NULL.
    - Store the TLS handshake in the state cache and increment the handshake creation count.
    - Generate initial secrets and keys for the connection.
    - Schedule the connection for immediate servicing.
    - Return the newly created connection object.
- **Output**: Returns a pointer to the newly created `fd_quic_conn_t` structure representing the established connection, or NULL if the connection could not be established.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_now`](fd_quic_private.h.driver.md#fd_quic_now)
    - [`fd_quic_tls_hs_cache_evict`](#fd_quic_tls_hs_cache_evict)
    - [`fd_quic_conn_id_rand`](fd_quic_conn_id.h.driver.md#fd_quic_conn_id_rand)
    - [`fd_quic_conn_create`](#fd_quic_conn_create)
    - [`fd_quic_tls_hs_new`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_hs_new)
    - [`fd_quic_conn_free`](#fd_quic_conn_free)
    - [`fd_quic_gen_initial_secret_and_keys`](#fd_quic_gen_initial_secret_and_keys)
    - [`fd_quic_svc_schedule`](#fd_quic_svc_schedule)


---
### fd\_quic\_conn\_create<!-- {{#callable:fd_quic_conn_create}} -->
Creates a new QUIC connection with specified parameters.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `our_conn_id`: A unique connection ID for the local endpoint.
    - `peer_conn_id`: A pointer to the `fd_quic_conn_id_t` structure representing the peer's connection ID.
    - `peer_ip_addr`: The IP address of the peer endpoint.
    - `peer_udp_port`: The UDP port of the peer endpoint.
    - `self_ip_addr`: The local IP address of the endpoint.
    - `self_udp_port`: The local UDP port of the endpoint.
    - `server`: An integer indicating whether this endpoint is a server (non-zero) or a client (zero).
- **Control Flow**:
    - Checks if the provided connection ID is valid; if not, returns NULL.
    - Fetches the current state of the QUIC instance and checks for available connection slots.
    - If no free connection slots are available, logs an error and returns NULL.
    - Validates the integrity of the connection free list and checks if the selected connection is in a valid state.
    - Prunes any previous connection map entry for the same connection ID.
    - Inserts the new connection into the connection map.
    - Initializes various members of the connection structure, including IP addresses, UDP ports, and connection state.
    - Sets up transport parameters and initializes stream IDs based on whether the endpoint is a server or client.
    - Schedules the connection for servicing and returns the newly created connection.
- **Output**: Returns a pointer to the newly created `fd_quic_conn_t` structure representing the connection, or NULL if the creation failed.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)
    - [`fd_quic_conn_query1`](fd_quic_private.h.driver.md#fd_quic_conn_query1)
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)
    - [`fd_quic_svc_schedule`](#fd_quic_svc_schedule)


---
### fd\_quic\_get\_next\_wakeup<!-- {{#callable:fd_quic_get_next_wakeup}} -->
The `fd_quic_get_next_wakeup` function determines the next wakeup time for QUIC connections based on their service queues.
- **Inputs**:
    - `quic`: A pointer to a `fd_quic_t` structure representing the QUIC state.
- **Control Flow**:
    - The function retrieves the current state of the QUIC connection using [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state).
    - It checks if there are any connections in the `FD_QUIC_SVC_INSTANT` service queue; if so, it returns 0, indicating immediate wakeup.
    - It initializes two variables, `ack_wakeup` and `wait_wakeup`, to `LONG_MAX` to track the next wakeup times for ACK and wait services.
    - If there are connections in the `FD_QUIC_SVC_ACK_TX` queue, it retrieves the connection at the head of the queue and updates `ack_wakeup` with its service time.
    - Similarly, if there are connections in the `FD_QUIC_SVC_WAIT` queue, it retrieves the connection at the head and updates `wait_wakeup`.
    - Finally, it returns the minimum of `ack_wakeup` and `wait_wakeup`, ensuring it does not return a negative value.
- **Output**: The function returns an unsigned long representing the next wakeup time in microseconds, or 0 if an immediate wakeup is required.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_conn_at_idx`](fd_quic_private.h.driver.md#fd_quic_conn_at_idx)


---
### fd\_quic\_handle\_ping\_frame<!-- {{#callable:fd_quic_handle_ping_frame}} -->
Handles a QUIC ping frame by skipping over padding bytes and returning the number of bytes processed.
- **Inputs**:
    - `ctx`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame, including the connection information.
    - `data`: A pointer to the `fd_quic_ping_frame_t` structure representing the ping frame data, which is unused in this function.
    - `p0`: A pointer to the start of the payload data for the ping frame, which is also unused in this function.
    - `p_sz`: The size of the payload data pointed to by `p0`, which is also unused in this function.
- **Control Flow**:
    - The function begins by probing the DTrace for the ping frame handling, logging the connection ID.
    - It initializes pointers to the start and end of the payload data.
    - A while loop iterates through the payload data, skipping over any bytes that are zero (padding).
    - The loop continues until it reaches the end of the payload data.
    - Finally, the function returns the number of bytes processed, which is the difference between the start and end pointers.
- **Output**: Returns the number of bytes processed from the payload, which indicates how many bytes were skipped over in the ping frame.


---
### fd\_quic\_pkt\_meta\_retry<!-- {{#callable:fd_quic_pkt_meta_retry}} -->
The `fd_quic_pkt_meta_retry` function manages the retransmission of QUIC packet metadata by freeing expired packet metadata or forcing the release of a specified minimum number of packet metadata entries.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC state.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `force`: An integer flag indicating whether to force the freeing of packet metadata.
    - `arg_enc_level`: An unsigned integer representing the encryption level to consider for packet metadata.
- **Control Flow**:
    - The function retrieves the current time from the QUIC state.
    - It determines the minimum number of packet metadata entries to free based on the `force` parameter.
    - A loop is initiated to find and process the earliest expiring packet metadata.
    - If the `arg_enc_level` is not specified, it iterates through all encryption levels to find the earliest expiring packet metadata.
    - If the `arg_enc_level` is specified, it directly checks the corresponding packet metadata.
    - The loop continues until the required number of packet metadata entries are freed or no more expired entries are found.
    - For each packet metadata entry processed, it updates the connection state and schedules necessary actions.
- **Output**: The function does not return a value but modifies the state of the QUIC connection and may schedule further actions based on the processed packet metadata.
- **Functions called**:
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_pkt_meta_min`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_min)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)
    - [`fd_quic_abandon_enc_level`](#fd_quic_abandon_enc_level)
    - [`fd_quic_tx_stream_free`](#fd_quic_tx_stream_free)
    - [`fd_quic_pkt_meta_remove_range`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_remove_range)


---
### fd\_quic\_reclaim\_pkt\_meta<!-- {{#callable:fd_quic_reclaim_pkt_meta}} -->
The `fd_quic_reclaim_pkt_meta` function processes and reclaims packet metadata for a QUIC connection based on the type of packet received.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `pkt_meta`: A pointer to the `fd_quic_pkt_meta_t` structure containing metadata about the packet.
    - `enc_level`: An unsigned integer representing the encryption level of the packet.
- **Control Flow**:
    - The function retrieves the type of packet from `pkt_meta` and the range of packet values.
    - A switch statement is used to handle different packet types, including PING, HS_DATA, HS_DONE, MAX_DATA, MAX_STREAMS_UNIDIR, and STREAM.
    - For each case, specific actions are taken to update connection flags, acknowledge bytes, or manage stream data.
    - In the case of HS_DATA, it checks if the received data is acknowledged and updates the acknowledged bytes accordingly.
    - For MAX_DATA and MAX_STREAMS_UNIDIR, it checks if the acknowledged values exceed the current limits and updates flags as necessary.
    - In the STREAM case, it processes the stream data, updating the stream's acknowledged bytes and potentially freeing up resources.
- **Output**: The function does not return a value but modifies the state of the connection and the packet metadata based on the processing of the received packet.
- **Functions called**:
    - [`fd_quic_tls_get_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_get_hs_data)
    - [`fd_quic_tls_pop_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_pop_hs_data)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_tls_hs_delete`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_hs_delete)
    - [`fd_quic_conn_error`](#fd_quic_conn_error)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)
    - [`fd_quic_tx_stream_free`](#fd_quic_tx_stream_free)


---
### fd\_quic\_process\_lost<!-- {{#callable:fd_quic_process_lost}} -->
Processes lost QUIC packets by marking them for expiry and triggering retries.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `enc_level`: An unsigned integer representing the encryption level of the packets to be processed.
    - `cnt`: An unsigned long integer indicating the number of packets to be marked as lost.
- **Control Flow**:
    - Initializes a tracker to access the packet metadata associated with the connection.
    - Iterates through the sent packet metadata for the specified encryption level.
    - For each packet, if the count of processed packets is less than `cnt`, it marks the packet's expiry to zero.
    - Once the count reaches `cnt`, it breaks the loop.
    - Finally, it triggers the retry mechanism for the connection.
- **Output**: The function does not return a value but modifies the state of the packets in the connection's metadata and triggers retries.
- **Functions called**:
    - [`fd_quic_pkt_meta_ds_fwd_iter_init`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_init)
    - [`fd_quic_pkt_meta_ds_fwd_iter_done`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_done)
    - [`fd_quic_pkt_meta_ds_fwd_iter_next`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_next)
    - [`fd_quic_pkt_meta_ds_fwd_iter_ele`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_ele)
    - [`fd_quic_pkt_meta_retry`](#fd_quic_pkt_meta_retry)


---
### fd\_quic\_process\_ack\_range<!-- {{#callable:fd_quic_process_ack_range}} -->
Processes an acknowledgment range for QUIC packets, updating RTT measurements and reclaiming packet metadata.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection being processed.
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure containing the context of the QUIC frame being processed.
    - `enc_level`: An unsigned integer representing the encryption level of the packets being acknowledged.
    - `largest_ack`: An unsigned long integer representing the largest acknowledged packet number.
    - `ack_range`: An unsigned long integer representing the range of packet numbers being acknowledged.
    - `is_largest`: An integer flag indicating whether the largest acknowledged packet is also the largest packet sent.
    - `now`: An unsigned long integer representing the current time in ticks.
    - `ack_delay`: An unsigned long integer representing the acknowledgment delay in peer units.
- **Control Flow**:
    - The function starts by defining the inclusive range of acknowledged packets using `largest_ack` and `ack_range`.
    - It probes the DTrace for debugging purposes with the connection ID and acknowledgment range.
    - It retrieves the packet metadata tracker and the sent packet metadata for the specified encryption level.
    - A forward iterator is initialized to traverse the sent packet metadata starting from the oldest sent packet.
    - For each packet in the range, it checks if the packet number is within the acknowledged range.
    - If the packet is the largest acknowledged and meets certain conditions, it updates the RTT measurements.
    - The packet metadata is reclaimed for each acknowledged packet.
    - Finally, the function updates the used packet metadata count by removing the acknowledged range.
- **Output**: The function does not return a value but modifies the state of the connection and updates the RTT measurements based on the acknowledged packets.
- **Functions called**:
    - [`fd_quic_pkt_meta_ds_idx_ge`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_idx_ge)
    - [`fd_quic_pkt_meta_ds_fwd_iter_done`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_done)
    - [`fd_quic_pkt_meta_ds_fwd_iter_next`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_next)
    - [`fd_quic_pkt_meta_ds_fwd_iter_ele`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_ele)
    - [`fd_quic_reclaim_pkt_meta`](#fd_quic_reclaim_pkt_meta)
    - [`fd_quic_pkt_meta_remove_range`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_remove_range)


---
### fd\_quic\_handle\_ack\_frame<!-- {{#callable:fd_quic_handle_ack_frame}} -->
Handles the processing of QUIC acknowledgment frames.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context and packet information.
    - `data`: A pointer to the `fd_quic_ack_frame_t` structure that contains the acknowledgment frame data.
    - `p`: A pointer to the byte array containing the encoded acknowledgment frame data.
    - `p_sz`: The size of the byte array `p`.
- **Control Flow**:
    - Checks if the first acknowledgment range is greater than the largest acknowledged packet, indicating a protocol violation.
    - Updates the connection's last acknowledgment time.
    - Processes the acknowledgment range for the largest acknowledged packet.
    - Iterates through additional acknowledgment ranges, decoding each and processing them accordingly.
    - Tracks lost packets based on the acknowledgment ranges processed.
    - Handles ECN counts if present in the acknowledgment frame.
- **Output**: Returns the number of bytes consumed from the input buffer, or a failure code if an error occurs.
- **Functions called**:
    - [`fd_quic_frame_error`](#fd_quic_frame_error)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_process_ack_range`](#fd_quic_process_ack_range)
    - [`fd_quic_pkt_meta_min`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_min)
    - [`fd_quic_pkt_meta_ds_fwd_iter_init`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_init)
    - [`fd_quic_pkt_meta_ds_fwd_iter_done`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_done)
    - [`fd_quic_pkt_meta_ds_fwd_iter_next`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_next)
    - [`fd_quic_pkt_meta_ds_fwd_iter_ele`](fd_quic_pkt_meta.h.driver.md#fd_quic_pkt_meta_ds_fwd_iter_ele)
    - [`fd_quic_process_lost`](#fd_quic_process_lost)


---
### fd\_quic\_handle\_reset\_stream\_frame<!-- {{#callable:fd_quic_handle_reset_stream_frame}} -->
Handles the QUIC reset stream frame.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_reset_stream_frame_t` structure that contains the reset stream frame data.
    - `p`: A pointer to the payload data, which is unused in this implementation.
    - `p_sz`: The size of the payload data, which is also unused in this implementation.
- **Control Flow**:
    - The function starts by probing for DTrace, logging the connection ID, stream ID, application protocol error code, and final size.
    - The function currently has a TODO comment indicating that the actual implementation is pending.
    - Finally, the function returns 0, indicating no bytes were consumed from the payload.
- **Output**: Returns 0, indicating that no bytes were consumed from the payload.


---
### fd\_quic\_handle\_stop\_sending\_frame<!-- {{#callable:fd_quic_handle_stop_sending_frame}} -->
Handles the QUIC Stop Sending frame.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_stop_sending_frame_t` structure that contains the details of the Stop Sending frame.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - The function begins by probing the DTrace for debugging purposes, logging the connection ID, stream ID, and application protocol error code.
    - No further processing is done within this function, as it simply returns 0, indicating no bytes were consumed from the buffer.
- **Output**: Returns 0, indicating that no bytes were consumed from the input buffer.


---
### fd\_quic\_handle\_new\_token\_frame<!-- {{#callable:fd_quic_handle_new_token_frame}} -->
The `fd_quic_handle_new_token_frame` function processes a NEW_TOKEN frame in a QUIC connection.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context of the QUIC frame being processed.
    - `data`: A pointer to the `fd_quic_new_token_frame_t` structure that contains the data of the NEW_TOKEN frame.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - The function starts by indicating that the receipt of a NEW_TOKEN frame is treated as a connection error of type PROTOCOL_VIOLATION, as per the QUIC specification.
    - The `data` parameter is not used in the function, which suggests that the function's primary purpose is to log the event rather than process the frame's contents.
    - A DTrace probe is triggered to log the handling of the NEW_TOKEN frame, specifically capturing the connection ID associated with the context.
- **Output**: The function returns 0, indicating that no bytes were consumed from the input buffer.


---
### fd\_quic\_tx\_stream\_free<!-- {{#callable:fd_quic_tx_stream_free}} -->
The `fd_quic_tx_stream_free` function frees a QUIC stream, notifying the relevant callback and cleaning up associated resources.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection associated with the stream.
    - `stream`: A pointer to the `fd_quic_stream_t` structure representing the QUIC stream to be freed.
    - `code`: An integer representing the reason code for freeing the stream, which may be used in notifications.
- **Control Flow**:
    - The function first checks if the stream's state is not `FD_QUIC_STREAM_STATE_UNUSED` using `FD_LIKELY` for optimization.
    - If the stream is in use, it calls [`fd_quic_cb_stream_notify`](fd_quic_private.h.driver.md#fd_quic_cb_stream_notify) to notify about the stream's freeing with the provided code.
    - The stream's state is then set to `FD_QUIC_STREAM_STATE_UNUSED`.
    - The stream ID is retrieved from the stream structure.
    - The function queries the stream map for the stream entry using `fd_quic_stream_map_query`.
    - If the stream entry is found and valid, it marks the stream as dead and removes it from the stream map.
    - The stream is then removed from its linked list using `FD_QUIC_STREAM_LIST_REMOVE`.
    - The stream's flags are set to indicate it is dead, and its ID is invalidated.
    - Finally, the stream is returned to the stream pool using [`fd_quic_stream_pool_free`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_free).
- **Output**: The function does not return a value, but it modifies the state of the stream and cleans up resources associated with it.
- **Functions called**:
    - [`fd_quic_cb_stream_notify`](fd_quic_private.h.driver.md#fd_quic_cb_stream_notify)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_stream_pool_free`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_free)


---
### fd\_quic\_handle\_stream\_frame<!-- {{#callable:fd_quic_handle_stream_frame}} -->
Handles the processing of a QUIC stream frame, validating its parameters and updating the connection state accordingly.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame being processed, including the connection and packet information.
    - `p`: A pointer to the data buffer containing the stream frame payload.
    - `p_sz`: The size of the data buffer pointed to by `p`.
    - `stream_id`: The identifier for the stream to which the frame belongs.
    - `offset`: The offset within the stream where the data should be written.
    - `data_sz`: The size of the data being sent in the stream frame.
    - `fin`: An integer flag indicating whether this is the final frame for the stream (1 if it is, 0 otherwise).
- **Control Flow**:
    - The function begins by extracting the QUIC context and connection information from the `context` parameter.
    - It checks the type of the `stream_id` to ensure it matches the expected type for the connection (client or server).
    - If the stream type is invalid, it logs a debug message and triggers a stream limit error, returning a failure code.
    - Next, it verifies that the size of the data (`data_sz`) does not exceed the size of the provided buffer (`p_sz`).
    - If the data size is invalid, it logs a debug message and triggers a frame encoding error, returning a failure code.
    - The function then updates the unacknowledged size of the connection by adding the size of the incoming data.
    - It checks if the `stream_id` is within the allowed range; if not, it logs a debug message and triggers a stream limit error, returning a failure code.
    - The function also checks if the data being sent exceeds the flow control limits; if it does, it logs a debug message and triggers a flow control error, returning a failure code.
    - If all checks pass, it calls the [`fd_quic_cb_stream_rx`](fd_quic_private.h.driver.md#fd_quic_cb_stream_rx) function to process the received stream data.
    - Finally, it updates the acknowledgment flag in the packet and returns the number of bytes consumed.
- **Output**: Returns the number of bytes consumed from the stream frame if successful, or a failure code if any validation checks fail.
- **Functions called**:
    - [`fd_quic_frame_error`](#fd_quic_frame_error)
    - [`fd_quic_cb_stream_rx`](fd_quic_private.h.driver.md#fd_quic_cb_stream_rx)


---
### fd\_quic\_handle\_stream\_8\_frame<!-- {{#callable:fd_quic_handle_stream_8_frame}} -->
Handles a QUIC stream frame of type 8 by delegating to a more general stream frame handler.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame processing, including the connection and packet information.
    - `data`: A pointer to the `fd_quic_stream_8_frame_t` structure that contains the specific data for the stream frame being handled, including the stream ID and type.
    - `p`: A pointer to the byte array containing the payload of the stream frame.
    - `p_sz`: The size of the payload in bytes.
- **Control Flow**:
    - Calls the [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame) function, passing the context, payload pointer, payload size, stream ID from the `data`, an offset of 0, the payload size, and a FIN flag derived from the `data` type.
    - The [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame) function processes the stream frame and returns the number of bytes consumed.
- **Output**: Returns the number of bytes consumed from the payload during the handling of the stream frame.
- **Functions called**:
    - [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame)


---
### fd\_quic\_handle\_stream\_a\_frame<!-- {{#callable:fd_quic_handle_stream_a_frame}} -->
Handles a QUIC stream frame by delegating to a lower-level stream frame handler.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame being processed, including the connection and packet information.
    - `data`: A pointer to the `fd_quic_stream_a_frame_t` structure that contains the specific data for the stream frame, including the stream ID and length.
    - `p`: A pointer to the byte array containing the payload of the stream frame.
    - `p_sz`: The size of the payload in bytes.
- **Control Flow**:
    - The function first calls [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame), passing the context, payload pointer, payload size, stream ID, offset (set to 0), length of the data, and a flag indicating if this is the final frame.
    - The return value from [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame) is returned as the output of this function.
- **Output**: Returns the number of bytes consumed from the payload, as determined by the [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame) function.
- **Functions called**:
    - [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame)


---
### fd\_quic\_handle\_stream\_c\_frame<!-- {{#callable:fd_quic_handle_stream_c_frame}} -->
The `fd_quic_handle_stream_c_frame` function processes a QUIC stream frame with a specific structure, handling the stream ID, offset, and data length.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame being processed.
    - `data`: A pointer to the `fd_quic_stream_c_frame_t` structure that contains the stream ID, offset, and other relevant data for the stream frame.
    - `p`: A pointer to the byte array containing the frame data.
    - `p_sz`: The size of the byte array pointed to by `p`, indicating how many bytes are available for processing.
- **Control Flow**:
    - The function first calls [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame) to handle the stream frame processing, passing the context, data, and relevant parameters.
    - It extracts the stream ID, offset, and data size from the `data` structure.
    - The function checks if the stream ID type matches the expected type based on whether the connection is a server or client.
    - It verifies that the data size does not exceed the available size indicated by `p_sz`.
    - If all checks pass, it processes the stream data and updates the connection state accordingly.
- **Output**: The function returns the number of bytes consumed from the input buffer, indicating how much of the stream frame was processed.
- **Functions called**:
    - [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame)


---
### fd\_quic\_handle\_stream\_e\_frame<!-- {{#callable:fd_quic_handle_stream_e_frame}} -->
Handles the QUIC stream 'E' frame by delegating to a lower-level stream frame handler.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame processing, including the connection and packet information.
    - `data`: A pointer to the `fd_quic_stream_e_frame_t` structure that contains the specific data for the 'E' stream frame, including stream ID, offset, and length.
    - `p`: A pointer to the byte array containing the raw frame data.
    - `p_sz`: The size of the raw frame data in bytes.
- **Control Flow**:
    - The function calls [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame) with the appropriate parameters extracted from the `data` structure.
    - It passes the stream ID, offset, length, and type information to the lower-level handler for processing.
- **Output**: Returns the number of bytes consumed from the input data buffer, as determined by the lower-level stream frame handler.
- **Functions called**:
    - [`fd_quic_handle_stream_frame`](#fd_quic_handle_stream_frame)


---
### fd\_quic\_handle\_max\_data\_frame<!-- {{#callable:fd_quic_handle_max_data_frame}} -->
Handles the QUIC Max Data frame by updating the maximum data limit for a connection.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_max_data_frame_t` structure that contains the new maximum data limit.
    - `p`: A pointer to the data buffer, which is unused in this function.
    - `p_sz`: The size of the data buffer, which is also unused in this function.
- **Control Flow**:
    - Retrieve the current connection from the context.
    - Store the old maximum data limit from the connection.
    - Store the new maximum data limit from the incoming frame.
    - Log the handling of the Max Data frame for tracing purposes.
    - Update the connection's maximum data limit to the greater of the old and new values.
    - Return 0 to indicate that no additional bytes were consumed from the buffer.
- **Output**: Returns 0, indicating that no additional bytes were consumed from the buffer.


---
### fd\_quic\_handle\_max\_stream\_data\_frame<!-- {{#callable:fd_quic_handle_max_stream_data_frame}} -->
Handles the MAX_STREAM_DATA frame in QUIC protocol.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_max_stream_data_frame_t` structure that contains the stream ID and the maximum stream data.
    - `p`: A pointer to the data buffer, which is unused in this function.
    - `p_sz`: The size of the data buffer, which is also unused in this function.
- **Control Flow**:
    - The function starts by extracting the connection from the context.
    - It retrieves the current maximum stream data limit for the connection.
    - The new maximum stream data is compared with the old limit.
    - If the new limit is greater than the old limit, it updates the connection's maximum stream data.
    - The function ends by returning 0, indicating no additional bytes were consumed from the buffer.
- **Output**: Returns 0, indicating that no additional bytes were consumed from the buffer.


---
### fd\_quic\_handle\_max\_streams\_frame<!-- {{#callable:fd_quic_handle_max_streams_frame}} -->
Handles the `MAX_STREAMS` frame in a QUIC connection, updating the maximum number of unidirectional streams allowed.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_max_streams_frame_t` structure that contains the data of the `MAX_STREAMS` frame.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - The function retrieves the connection object from the context.
    - It logs the handling of the `MAX_STREAMS` frame using DTrace.
    - It checks if the frame type is for unidirectional streams (0x13).
    - If the type is correct, it calculates the new maximum stream ID based on the provided `max_streams` value and updates the connection's `tx_sup_stream_id` accordingly.
- **Output**: Returns 0, indicating that no additional bytes were consumed from the buffer.


---
### fd\_quic\_handle\_data\_blocked\_frame<!-- {{#callable:fd_quic_handle_data_blocked_frame}} -->
Handles the DATA_BLOCKED frame in a QUIC connection.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_data_blocked_frame_t` structure that contains the details of the DATA_BLOCKED frame.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - The function begins by probing the DTrace for monitoring purposes, logging the connection ID and the maximum data specified in the DATA_BLOCKED frame.
    - It then contains a comment indicating that no runtime allocations will be attempted in response to the DATA_BLOCKED frame, implying that the function does not handle memory allocation.
    - Finally, the function returns 0, indicating that no bytes were consumed from the payload.
- **Output**: Returns 0, indicating that no bytes were consumed from the payload.


---
### fd\_quic\_handle\_stream\_data\_blocked\_frame<!-- {{#callable:fd_quic_handle_stream_data_blocked_frame}} -->
Handles the QUIC STREAM_DATA_BLOCKED frame.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_stream_data_blocked_frame_t` structure containing the details of the STREAM_DATA_BLOCKED frame.
    - `p`: A pointer to the data buffer, which is unused in this function.
    - `p_sz`: The size of the data buffer, which is also unused in this function.
- **Control Flow**:
    - The function starts by probing the DTrace for the STREAM_DATA_BLOCKED event, logging the connection ID, stream ID, and maximum stream data.
    - It does not perform any runtime allocations or memory management since it is designed to handle the STREAM_DATA_BLOCKED frame without needing additional resources.
    - The function concludes by returning 0, indicating that no additional bytes were consumed from the buffer.
- **Output**: Returns 0, indicating that no bytes were consumed from the input buffer.


---
### fd\_quic\_handle\_streams\_blocked\_frame<!-- {{#callable:fd_quic_handle_streams_blocked_frame}} -->
Handles the `STREAMS_BLOCKED` frame in QUIC protocol, which indicates that a client is unable to open new streams due to a limit on the maximum number of streams.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context and packet information.
    - `data`: A pointer to the `fd_quic_streams_blocked_frame_t` structure that contains the details of the blocked streams, specifically the maximum number of streams the client can open.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - The function begins by probing the DTrace for monitoring purposes, logging the connection ID and the maximum number of streams.
    - It checks the purpose of the `STREAMS_BLOCKED` frame, which is to inform the server that the client cannot open new streams due to a limit.
    - Currently, the function does not implement any handling logic for this frame, as the client does not utilize it as of December 2024.
    - The function returns 0, indicating no additional bytes were consumed from the buffer.
- **Output**: Returns 0, indicating that no bytes were consumed from the input buffer.


---
### fd\_quic\_handle\_new\_conn\_id\_frame<!-- {{#callable:fd_quic_handle_new_conn_id_frame}} -->
Handles the QUIC New Connection ID frame, which is currently not supported.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame being processed.
    - `data`: A pointer to the `fd_quic_new_conn_id_frame_t` structure that contains the data for the new connection ID frame.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - The function starts by logging a probe for the new connection ID frame handling.
    - It then marks the `data` pointer as unused.
    - Finally, it returns 0, indicating no bytes were consumed from the input buffer.
- **Output**: Returns 0, indicating that no bytes were consumed from the input buffer.


---
### fd\_quic\_handle\_retire\_conn\_id\_frame<!-- {{#callable:fd_quic_handle_retire_conn_id_frame}} -->
The `fd_quic_handle_retire_conn_id_frame` function processes a QUIC frame that requests the retirement of a connection ID.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame being processed.
    - `data`: A pointer to the `fd_quic_retire_conn_id_frame_t` structure that contains the data for the retire connection ID frame.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - The function starts by logging a DTrace probe with the connection ID associated with the context.
    - It then ignores the `data` and payload parameters, as the function does not currently implement any logic for handling the retirement of connection IDs.
    - Finally, it logs a debug message indicating that a retirement request was received and returns 0.
- **Output**: The function returns 0, indicating that no bytes were consumed from the input buffer.


---
### fd\_quic\_handle\_path\_challenge\_frame<!-- {{#callable:fd_quic_handle_path_challenge_frame}} -->
Handles a `PATH_CHALLENGE` frame in the QUIC protocol.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_path_challenge_frame_t` structure that contains the data of the path challenge.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - The function begins by logging the receipt of the `PATH_CHALLENGE` frame using `FD_DTRACE_PROBE_1`.
    - It then does not process the `data` parameter, as indicated by the comment and the `(void)data;` line.
    - Finally, the function returns 0, indicating no bytes were consumed from the payload.
- **Output**: Returns 0, indicating that no bytes were consumed from the payload.


---
### fd\_quic\_handle\_path\_response\_frame<!-- {{#callable:fd_quic_handle_path_response_frame}} -->
Handles the `PATH_RESPONSE` frame in QUIC protocol, which should not be received as the implementation does not generate `PATH_CHALLENGE` frames.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context for the QUIC frame being processed, including connection information.
    - `data`: A pointer to the `fd_quic_path_response_frame_t` structure that contains the data of the `PATH_RESPONSE` frame.
    - `p`: A pointer to the raw data buffer, which is unused in this function.
    - `p_sz`: The size of the raw data buffer, which is also unused in this function.
- **Control Flow**:
    - The function starts by logging a probe for the `PATH_RESPONSE` frame handling, using the connection ID from the context.
    - It then ignores the `data` parameter and does not process it further.
    - Finally, the function returns 0, indicating no further action is taken.
- **Output**: The function returns 0, indicating that it does not process the `PATH_RESPONSE` frame as it should not be received.


---
### fd\_quic\_handle\_conn\_close\_frame<!-- {{#callable:fd_quic_handle_conn_close_frame}} -->
Handles the connection close frame in a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection that is being closed.
- **Control Flow**:
    - Logs a debug message indicating that the peer has requested a connection close.
    - Checks the current state of the connection (`conn->state`).
    - If the state is `FD_QUIC_CONN_STATE_PEER_CLOSE`, `FD_QUIC_CONN_STATE_ABORT`, or `FD_QUIC_CONN_STATE_CLOSE_PENDING`, the function returns immediately without further action.
    - If the connection is in any other state, it sets the connection state to `FD_QUIC_CONN_STATE_PEER_CLOSE`.
    - Updates the packet number to indicate that a packet is pending to be sent.
    - Schedules the connection for immediate servicing.
- **Output**: The function does not return a value; it modifies the state of the connection and schedules it for processing.
- **Functions called**:
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)


---
### fd\_quic\_handle\_conn\_close\_0\_frame<!-- {{#callable:fd_quic_handle_conn_close_0_frame}} -->
Handles the QUIC connection close frame of type 0.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_conn_close_0_frame_t` structure that contains the details of the connection close frame.
    - `p`: A pointer to the byte buffer containing the frame data.
    - `p_sz`: The size of the byte buffer.
- **Control Flow**:
    - Checks if the length of the reason phrase exceeds the size of the provided buffer.
    - If the length is invalid, it triggers a frame error and returns a failure code.
    - Logs the error code, frame type, and reason phrase for debugging purposes.
    - Calls [`fd_quic_handle_conn_close_frame`](#fd_quic_handle_conn_close_frame) to handle the connection closure.
- **Output**: Returns the length of the reason phrase if successful, or a failure code if an error occurs.
- **Functions called**:
    - [`fd_quic_frame_error`](#fd_quic_frame_error)
    - [`fd_quic_handle_conn_close_frame`](#fd_quic_handle_conn_close_frame)


---
### fd\_quic\_handle\_conn\_close\_1\_frame<!-- {{#callable:fd_quic_handle_conn_close_1_frame}} -->
Handles the QUIC connection close frame of type 1, validating the reason phrase length and logging the error code and reason.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the context of the QUIC frame being processed.
    - `data`: A pointer to the `fd_quic_conn_close_1_frame_t` structure that contains the error code and reason phrase length for the connection close frame.
    - `p`: A pointer to the byte buffer containing the reason phrase data.
    - `p_sz`: The size of the byte buffer pointed to by `p`.
- **Control Flow**:
    - The function first checks if the length of the reason phrase exceeds the size of the provided buffer.
    - If the length is greater, it calls [`fd_quic_frame_error`](#fd_quic_frame_error) to log a frame encoding error and returns `FD_QUIC_PARSE_FAIL`.
    - If the length is valid, it logs the error code and the reason phrase for debugging purposes.
    - Finally, it calls [`fd_quic_handle_conn_close_frame`](#fd_quic_handle_conn_close_frame) to handle the connection close logic.
- **Output**: Returns the length of the reason phrase if valid, or `FD_QUIC_PARSE_FAIL` if an error occurs.
- **Functions called**:
    - [`fd_quic_frame_error`](#fd_quic_frame_error)
    - [`fd_quic_handle_conn_close_frame`](#fd_quic_handle_conn_close_frame)


---
### fd\_quic\_handle\_handshake\_done\_frame<!-- {{#callable:fd_quic_handle_handshake_done_frame}} -->
Handles the reception of a `HANDSHAKE_DONE` frame in a QUIC connection.
- **Inputs**:
    - `context`: A pointer to the `fd_quic_frame_ctx_t` structure that contains the connection context.
    - `data`: A pointer to the `fd_quic_handshake_done_frame_t` structure containing the handshake done frame data.
    - `p`: A pointer to the payload data, which is unused in this function.
    - `p_sz`: The size of the payload data, which is also unused in this function.
- **Control Flow**:
    - Checks if the connection is a server; if so, it triggers a protocol violation error.
    - If the connection is still in the handshake state, it marks the packet as canceled and returns.
    - If the connection is not in the handshake complete state, it returns without further action.
    - Acknowledges the first `HANDSHAKE_DONE` frame immediately.
    - Discards handshake keys as per RFC 9001 when the TLS handshake is confirmed.
    - Cleans up any remaining handshake data at the application level.
    - Sets the connection state to active.
    - Calls the user callback to indicate that the handshake is complete.
    - Deallocates the TLS handshake state if it exists.
- **Output**: Returns 0 if successful, or a failure code if an error occurs.
- **Functions called**:
    - [`fd_quic_frame_error`](#fd_quic_frame_error)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)
    - [`fd_quic_abandon_enc_level`](#fd_quic_abandon_enc_level)
    - [`fd_quic_tls_get_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_get_hs_data)
    - [`fd_quic_tls_pop_hs_data`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_pop_hs_data)
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)
    - [`fd_quic_cb_conn_hs_complete`](fd_quic_private.h.driver.md#fd_quic_cb_conn_hs_complete)
    - [`fd_quic_get_state`](fd_quic_private.h.driver.md#fd_quic_get_state)
    - [`fd_quic_tls_hs_delete`](tls/fd_quic_tls.c.driver.md#fd_quic_tls_hs_delete)


---
### fd\_quic\_conn\_close<!-- {{#callable:fd_quic_conn_close}} -->
The `fd_quic_conn_close` function initiates the closure of a QUIC connection, setting its state to close pending and scheduling it for immediate servicing.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection to be closed.
    - `app_reason`: An unsigned integer representing the application-specific reason for closing the connection.
- **Control Flow**:
    - The function first checks if the `conn` pointer is NULL; if it is, the function returns immediately.
    - Next, it checks the current state of the connection using a switch statement.
    - If the connection is in the states `FD_QUIC_CONN_STATE_INVALID`, `FD_QUIC_CONN_STATE_DEAD`, or `FD_QUIC_CONN_STATE_ABORT`, the function returns without making any changes.
    - For all other states, it sets the connection's state to `FD_QUIC_CONN_STATE_CLOSE_PENDING` and assigns the `app_reason` to the connection's `app_reason` field.
    - Finally, it calls [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1) to schedule the connection for servicing as soon as possible.
- **Output**: The function does not return a value; it modifies the state of the connection and schedules it for servicing.
- **Functions called**:
    - [`fd_quic_set_conn_state`](fd_quic_conn.h.driver.md#fd_quic_set_conn_state)
    - [`fd_quic_svc_schedule1`](fd_quic_private.h.driver.md#fd_quic_svc_schedule1)


