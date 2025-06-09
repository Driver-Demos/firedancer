# Purpose
This C source code file is part of a larger system that appears to manage network communication and data processing within a distributed or modular application architecture. The file defines a set of functions and structures that are primarily concerned with initializing, configuring, and managing a "bundle tile" within a topology. This bundle tile seems to be a component responsible for handling network connections, processing data packets, and interacting with other components through a plugin system. The code includes functionality for setting up secure connections using OpenSSL, managing memory allocations, and handling URL parsing and network configurations. It also integrates with a metrics system to track various operational statistics, such as transaction counts and error occurrences.

The file imports several headers, indicating its reliance on external libraries and modules for functionality such as metrics collection, topology management, key loading, and plugin handling. It defines a series of static and inline functions that perform specific tasks, such as calculating memory footprints, writing metrics, and publishing updates to a block engine. The code also includes logic for handling secure connections, including custom memory allocation functions for OpenSSL and a callback for logging SSL keys. Additionally, the file defines a `fd_topo_run_tile_t` structure, which encapsulates the configuration and operational parameters for running the bundle tile within the system's topology. This structure includes function pointers for initialization, security policy population, and the main execution loop, indicating that this file is a critical component in the setup and execution of the bundle tile within the broader application framework.
# Imports and Dependencies

---
- `fd_bundle_tile_private.h`
- `../metrics/fd_metrics.h`
- `../topo/fd_topo.h`
- `../keyguard/fd_keyload.h`
- `../plugin/fd_plugin.h`
- `../../waltz/http/fd_url.h`
- `errno.h`
- `stdio.h`
- `fcntl.h`
- `sys/mman.h`
- `sys/uio.h`
- `netinet/in.h`
- `netinet/tcp.h`
- `../../waltz/resolv/fd_netdb.h`
- `generated/fd_bundle_tile_seccomp.h`
- `../stem/fd_stem.c`


# Global Variables

---
### fd\_quic\_ssl\_mem\_function\_ctx
- **Type**: `fd_alloc_t *`
- **Description**: The `fd_quic_ssl_mem_function_ctx` is a static thread-local pointer to an `fd_alloc_t` structure, which is used to manage memory allocation for OpenSSL operations in a thread-safe manner. It is initialized to `NULL` and is intended to be set to a valid `fd_alloc_t` instance during the initialization of OpenSSL-related components.
- **Use**: This variable is used to store the context for custom memory allocation functions used by OpenSSL, ensuring that memory operations are handled by the `fd_alloc_t` allocator.


---
### fd\_tile\_bundle
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_bundle` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define the configuration and behavior of a tile in a topology. This structure includes function pointers for initialization, security policy population, and execution, as well as configuration parameters like resource limits and networking permissions.
- **Use**: This variable is used to configure and manage the execution of a specific tile, named 'bundle', within a larger system topology.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns the alignment requirement of the `fd_bundle_tile_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, meaning it does not modify any global state and its return value is determined solely by its parameters, which in this case are none.
    - It directly returns the result of the `alignof` operator applied to `fd_bundle_tile_t`, which is a type defined elsewhere in the code.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_bundle_tile_t` type.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a specific tile configuration in a system.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile configuration for which the memory footprint is being calculated.
- **Control Flow**:
    - The function begins by initializing a variable `l` with `FD_LAYOUT_INIT`.
    - It then appends the alignment and size of `fd_bundle_tile_t` to `l` using `FD_LAYOUT_APPEND`.
    - Next, it appends the alignment and footprint of a gRPC client, calculated using `fd_grpc_client_align()` and `fd_grpc_client_footprint(tile->bundle.buf_sz)`, to `l`.
    - It appends the alignment and footprint of an allocator using `fd_alloc_align()` and `fd_alloc_footprint()` to `l`.
    - Finally, it finalizes the layout with a 32-byte alignment using `FD_LAYOUT_FINI` and returns the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the specified tile configuration.


---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function returns a constant value representing the leftover space for OpenSSL allocations.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is not used in the function body.
    - The function returns a constant value `1UL<<26`, which is equivalent to 64 MiB.
- **Output**: The function returns an unsigned long integer representing 64 MiB of space.


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates various metrics and status indicators for a given `fd_bundle_tile_t` context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure containing metrics and status information to be updated.
- **Control Flow**:
    - The function begins by updating several metrics counters using the `FD_MCNT_SET` macro, which include transaction, bundle, packet, shredstream heartbeat, keepalive, and error counts from the `ctx->metrics` structure.
    - It retrieves the workspace containing the context using `fd_wksp_containing` and checks the workspace usage with `fd_wksp_usage`. If this check fails, it logs an error and exits (though this is marked as unreachable).
    - The function then updates heap size and free bytes metrics using the `FD_MGAUGE_SET` macro with the retrieved workspace usage data.
    - It checks the bundle client status using [`fd_bundle_client_status`](fd_bundle_client.c.driver.md#fd_bundle_client_status) and updates the connected status metric accordingly.
    - Finally, it updates the `ctx->bundle_status_recent` with the current bundle status.
- **Output**: The function does not return a value; it updates metrics and status indicators in the provided context.
- **Functions called**:
    - [`fd_bundle_client_status`](fd_bundle_client.c.driver.md#fd_bundle_client_status)


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function checks if a keyswitch state is pending and updates the context's identity and keyswitch state accordingly.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure, which contains the context for the bundle tile, including keyswitch state and identity information.
- **Control Flow**:
    - Check if the keyswitch state of the context is `FD_KEYSWITCH_STATE_SWITCH_PENDING` using `fd_keyswitch_state_query`.
    - If the keyswitch state is pending, set `ctx->identity_switched` to 1 to indicate an identity switch.
    - Copy 32 bytes from `ctx->keyswitch->bytes` to `ctx->auther.pubkey` to update the public key in the context.
    - Set the keyswitch state to `FD_KEYSWITCH_STATE_COMPLETED` using `fd_keyswitch_state`.
- **Output**: The function does not return a value; it modifies the state of the `ctx` structure in place.


---
### fd\_bundle\_tile\_publish\_block\_engine\_update<!-- {{#callable:fd_bundle_tile_publish_block_engine_update}} -->
The function `fd_bundle_tile_publish_block_engine_update` prepares and publishes a block engine update message using the provided context and stem.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure, which contains context information for the bundle tile, including plugin output memory and server details.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which is used for publishing the block engine update message.
- **Control Flow**:
    - Convert the chunk in `ctx->plugin_out` to a local address and zero out the memory for the update message.
    - Set the `name` field of the update message to "jito".
    - Format the URL using the server details from `ctx` and store it in the `url` field of the update message, truncating if necessary.
    - Format the IPv4 address from `ctx` and store it in the `ip_cstr` field of the update message.
    - Set the `status` field of the update message to the recent bundle status from `ctx`.
    - Compute the publication timestamp using `fd_tickcount` and `fd_frag_meta_ts_comp`.
    - Publish the update message using `fd_stem_publish` with the computed timestamp and other parameters from `ctx`.
    - Update `ctx->plugin_out.chunk` to the next compacted chunk using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it modifies the `ctx` structure to publish a block engine update message.


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function updates the context's stem and publishes a block engine update if necessary, while also managing the busy charge state.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure representing the current context.
    - `stem`: A pointer to an `fd_stem_context_t` structure representing the stem context.
    - `opt_poll_in`: An optional integer pointer, which is not used in this function.
    - `charge_busy`: A pointer to an integer that indicates whether the system is busy, which may be modified by the function.
- **Control Flow**:
    - The function begins by ignoring the `opt_poll_in` parameter, as it is not used.
    - It checks if the `ctx->stem` is not set, and if so, assigns it the value of `stem`.
    - The function calls [`fd_bundle_client_step`](fd_bundle_client.c.driver.md#fd_bundle_client_step) with `ctx` and `charge_busy` to perform a client step operation.
    - If `ctx->plugin_out.mem` is non-null, it checks if `ctx->bundle_status_recent` is different from `ctx->bundle_status_plugin`.
    - If the statuses differ, it calls [`fd_bundle_tile_publish_block_engine_update`](#fd_bundle_tile_publish_block_engine_update) to publish an update and sets `ctx->bundle_status_plugin` to `ctx->bundle_status_recent`.
    - It sets `*charge_busy` to 1 to indicate that the system is busy.
- **Output**: The function does not return a value; it modifies the `ctx` and `charge_busy` parameters in place.
- **Functions called**:
    - [`fd_bundle_client_step`](fd_bundle_client.c.driver.md#fd_bundle_client_step)
    - [`fd_bundle_tile_publish_block_engine_update`](#fd_bundle_tile_publish_block_engine_update)


---
### parse\_url<!-- {{#callable:parse_url}} -->
The `parse_url` function parses a URL string to extract and validate its components, including the scheme, port, and host, and determines if the connection should use SSL.
- **Inputs**:
    - `url_`: A pointer to an `fd_url_t` structure where the parsed URL components will be stored.
    - `url_str`: A constant character pointer to the URL string to be parsed.
    - `url_str_len`: An unsigned long integer representing the length of the URL string.
    - `tcp_port`: A pointer to an unsigned short where the parsed TCP port number will be stored.
    - `is_ssl`: A pointer to a boolean that will be set to indicate whether the URL uses SSL (HTTPS).
- **Control Flow**:
    - Initialize an error array and attempt to parse the URL string using `fd_url_parse_cstr`; if parsing fails, log an error based on the error code and exit.
    - Check the URL scheme; if it is 'https://', set `is_ssl` to true, if 'http://', set `is_ssl` to false; otherwise, log an error and exit.
    - Set the default TCP port to 443; if a port is specified in the URL, validate its length and convert it to an unsigned long; if invalid, log an error and exit.
    - Check the length of the host component; if it exceeds 255 characters, log a critical error (though this is marked as unreachable).
    - Copy the host component of the URL into a character array for further processing.
- **Output**: The function does not return a value but modifies the `url_`, `tcp_port`, and `is_ssl` pointers to store the parsed URL components and connection settings.


---
### fd\_bundle\_tile\_parse\_endpoint<!-- {{#callable:fd_bundle_tile_parse_endpoint}} -->
The `fd_bundle_tile_parse_endpoint` function parses a URL from a tile structure, extracts and sets the server's fully qualified domain name (FQDN), server name indication (SNI), TCP port, and SSL status in the context structure.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure where the parsed endpoint information will be stored.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure containing the URL and SNI information to be parsed.
- **Control Flow**:
    - Initialize a `fd_url_t` structure and a boolean `is_ssl` to store URL parsing results.
    - Call [`parse_url`](#parse_url) to parse the URL from `tile->bundle.url`, setting the TCP port and SSL status in `ctx`.
    - Check if the URL's host length exceeds 255 characters and log a critical error if it does (though this is marked as unreachable).
    - Append the URL's host to `ctx->server_fqdn` and set `ctx->server_fqdn_len` to the host length.
    - If `tile->bundle.sni_len` is non-zero, append the SNI to `ctx->server_sni` and set `ctx->server_sni_len` to the SNI length; otherwise, use the URL's host for SNI.
    - Set `ctx->is_ssl` based on the `is_ssl` flag.
    - If OpenSSL is not available and SSL is required, log an error message.
- **Output**: The function does not return a value; it modifies the `ctx` structure to store the parsed endpoint information.
- **Functions called**:
    - [`parse_url`](#parse_url)


---
### crypto\_malloc<!-- {{#callable:crypto_malloc}} -->
The `crypto_malloc` function allocates memory with a specified alignment and size, storing the size at the beginning of the allocated block for later use.
- **Inputs**:
    - `num`: The number of bytes to allocate.
    - `file`: The name of the file where the allocation is requested, used for debugging purposes.
    - `line`: The line number in the file where the allocation is requested, used for debugging purposes.
- **Control Flow**:
    - The function begins by casting the `file` and `line` parameters to void to indicate they are unused.
    - It calls `fd_alloc_malloc` with a context, alignment of 16 bytes, and a size of `num + 8` bytes to allocate memory.
    - If the allocation fails, it increments an error metric counter and returns `NULL`.
    - If successful, it stores the requested size (`num`) at the beginning of the allocated memory block.
    - It returns a pointer to the memory block, offset by 8 bytes to skip the stored size.
- **Output**: A pointer to the allocated memory block, offset by 8 bytes, or `NULL` if the allocation fails.


---
### crypto\_free<!-- {{#callable:crypto_free}} -->
The `crypto_free` function deallocates memory previously allocated for OpenSSL operations, adjusting for a size header.
- **Inputs**:
    - `addr`: A pointer to the memory block to be freed.
    - `file`: A string representing the file name where the free operation is called, used for debugging purposes.
    - `line`: An integer representing the line number in the file where the free operation is called, used for debugging purposes.
- **Control Flow**:
    - The function begins by casting the `file` and `line` parameters to void to indicate they are unused.
    - It checks if the `addr` is NULL using `FD_UNLIKELY`, and if so, it returns immediately without performing any operation.
    - If `addr` is not NULL, it calls `fd_alloc_free` to deallocate the memory, adjusting the address by subtracting 8 bytes to account for the size header stored at the beginning of the allocated block.
- **Output**: The function does not return any value.


---
### crypto\_realloc<!-- {{#callable:crypto_realloc}} -->
The `crypto_realloc` function reallocates a memory block with a new size, preserving the existing data up to the minimum of the old and new sizes, and handles special cases for null pointers and zero size.
- **Inputs**:
    - `addr`: A pointer to the memory block to be reallocated.
    - `num`: The new size for the memory block in bytes.
    - `file`: The name of the file where the reallocation is requested, used for debugging purposes.
    - `line`: The line number in the file where the reallocation is requested, used for debugging purposes.
- **Control Flow**:
    - If `addr` is NULL, the function calls [`crypto_malloc`](#crypto_malloc) to allocate a new block of memory of size `num` and returns the result.
    - If `num` is zero, the function calls [`crypto_free`](#crypto_free) to free the memory block pointed to by `addr` and returns NULL.
    - Allocates a new memory block of size `num + 8` bytes using `fd_alloc_malloc`, storing the result in `new`.
    - If the allocation fails (i.e., `new` is NULL), the function returns NULL.
    - Retrieves the size of the old memory block from the 8 bytes preceding `addr`.
    - Copies the minimum of `old_num` and `num` bytes from the old memory block to the new memory block, starting 8 bytes into the new block.
    - Frees the old memory block using `fd_alloc_free`.
    - Stores the new size `num` in the first 8 bytes of the new memory block.
    - Returns a pointer to the new memory block, offset by 8 bytes.
- **Output**: A pointer to the newly allocated memory block, or NULL if the allocation fails or if `num` is zero and `addr` is freed.
- **Functions called**:
    - [`crypto_malloc`](#crypto_malloc)
    - [`crypto_free`](#crypto_free)


---
### fd\_ossl\_keylog\_callback<!-- {{#callable:fd_ossl_keylog_callback}} -->
The `fd_ossl_keylog_callback` function logs SSL key information to a file descriptor for debugging purposes.
- **Inputs**:
    - `ssl`: A pointer to an SSL structure representing the SSL connection.
    - `line`: A string containing the key log line to be written.
- **Control Flow**:
    - Retrieve the SSL context associated with the given SSL connection using `SSL_get_SSL_CTX`.
    - Get the custom data associated with the SSL context, which is expected to be a `fd_bundle_tile_t` structure, using `SSL_CTX_get_ex_data`.
    - Calculate the length of the key log line using `strlen`.
    - Prepare an array of `iovec` structures to hold the key log line and a newline character.
    - Use `writev` to write the key log line and newline to the file descriptor specified in the `fd_bundle_tile_t` structure.
    - If the `writev` call fails to write the expected number of bytes, log a warning message with the error details.
- **Output**: The function does not return a value; it performs logging as a side effect.


---
### fd\_bundle\_tile\_init\_openssl<!-- {{#callable:fd_bundle_tile_init_openssl}} -->
The `fd_bundle_tile_init_openssl` function initializes OpenSSL for a given context by setting up custom memory allocation functions, configuring SSL context settings, and enabling key logging if applicable.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bundle_tile_t` structure that holds the context for the bundle tile, including SSL-related configurations.
    - `alloc_mem`: A pointer to a memory block used for custom memory allocation within the OpenSSL initialization process.
- **Control Flow**:
    - Join a new memory allocator using `fd_alloc_new` and `fd_alloc_join` with the provided `alloc_mem` and assign it to `ctx->ssl_alloc` and `fd_quic_ssl_mem_function_ctx`.
    - Check if the memory allocator was successfully created; if not, log an error and terminate.
    - Set custom memory allocation functions for OpenSSL using `CRYPTO_set_mem_functions` and log an error if it fails.
    - Initialize OpenSSL with specific options using `OPENSSL_init_ssl`.
    - Create a new SSL context using `SSL_CTX_new` with `TLS_client_method` and log an error if it fails.
    - Set the context's extra data using `SSL_CTX_set_ex_data` and log an error if it fails.
    - Configure the SSL context mode with `SSL_CTX_set_mode` to enable partial writes and automatic retries, logging an error if it fails.
    - Set the minimum protocol version to TLS 1.3 using `SSL_CTX_set_min_proto_version` and log an error if it fails.
    - Set the ALPN protocols to HTTP/2 using `SSL_CTX_set_alpn_protos` and log an error if it fails.
    - If the `keylog_fd` in the context is valid, set a keylog callback using `SSL_CTX_set_keylog_callback`.
    - Assign the created SSL context to `ctx->ssl_ctx`.
- **Output**: The function does not return a value; it modifies the `ctx` structure to include the initialized SSL context and memory allocator.


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a privileged context for a bundle tile, setting up memory allocations, cryptographic keys, and network configurations.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration.
- **Control Flow**:
    - Allocate scratch memory for the tile using `fd_topo_obj_laddr` and initialize it with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for `fd_bundle_tile_t`, gRPC client, and allocator using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch allocation with `FD_SCRATCH_ALLOC_FINI` and check for alignment and overflow errors.
    - Initialize the `fd_bundle_tile_t` context structure, setting default values and loading the public key.
    - If OpenSSL is available, open the key log file if specified and initialize OpenSSL with [`fd_bundle_tile_init_openssl`](#fd_bundle_tile_init_openssl).
    - Initialize network resolver file descriptors with `fd_netdb_open_fds`.
    - Generate a secure random seed for the header hashmap and timing RNG using `fd_rng_secure`.
    - Initialize the random number generator with `fd_rng_join`.
- **Output**: The function does not return a value; it initializes the context and resources for a bundle tile.
- **Functions called**:
    - [`scratch_align`](#scratch_align)
    - [`scratch_footprint`](#scratch_footprint)
    - [`fd_bundle_tile_init_openssl`](#fd_bundle_tile_init_openssl)


---
### bundle\_out\_link<!-- {{#callable:bundle_out_link}} -->
The `bundle_out_link` function initializes and returns a `fd_bundle_out_ctx_t` structure for a specified output link in a topology.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology configuration.
    - `link`: A pointer to a constant `fd_topo_link_t` structure representing the link configuration.
    - `out_link_idx`: An unsigned long integer representing the index of the output link.
- **Control Flow**:
    - Initialize an `fd_bundle_out_ctx_t` structure named `out` with zero values.
    - Set `out.idx` to the provided `out_link_idx`.
    - Retrieve the workspace memory address from the topology using the link's `dcache_obj_id` and set it to `out.mem`.
    - Calculate the compact chunk start using `fd_dcache_compact_chunk0` and assign it to `out.chunk0`.
    - Calculate the watermark using `fd_dcache_compact_wmark` and assign it to `out.wmark`.
    - Set `out.chunk` to the value of `out.chunk0`.
    - Return the initialized `fd_bundle_out_ctx_t` structure.
- **Output**: The function returns an `fd_bundle_out_ctx_t` structure initialized with the specified output link's context.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes an unprivileged bundle tile by setting up keyguard clients, keyswitches, and various output links, while configuring buffer sizes and timers.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to the `fd_topo_tile_t` structure representing the specific tile to be initialized.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `ctx`.
    - Check if the tile's `kind_id` is not zero, and log an error if it is, as there should only be one bundle tile.
    - Find the input link index for 'sign_bundle' and log an error if it is missing.
    - Find the output link index for 'bundle_sign' and log an error if it is missing.
    - Create and join a keyguard client using the input and output links' caches, logging an error if it fails.
    - Initialize the `keyswitch` by joining it with the local address of the keyswitch object.
    - Find the output link index for 'bundle_verif' and log an error if it is missing, then set `ctx->verify_out` using [`bundle_out_link`](#bundle_out_link).
    - Find the output link index for 'bundle_plugi', set `ctx->plugin_out` using [`bundle_out_link`](#bundle_out_link) if found, otherwise set it to a default value indicating no link.
    - Validate and set the socket receive buffer size from `tile->bundle.buf_sz`, logging an error if it is out of valid range.
    - Set the idle ping timer using `tile->bundle.keepalive_interval_nanos` and a random value from `ctx->rng`.
    - Force the tile to output a plugin message on startup by setting `ctx->bundle_status_plugin` and `ctx->bundle_status_recent`.
    - Parse the endpoint URL using [`fd_bundle_tile_parse_endpoint`](#fd_bundle_tile_parse_endpoint).
- **Output**: The function does not return a value; it initializes the state of the `fd_bundle_tile_t` context for the specified tile.
- **Functions called**:
    - [`bundle_out_link`](#bundle_out_link)
    - [`fd_bundle_tile_parse_endpoint`](#fd_bundle_tile_parse_endpoint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function configures a seccomp filter policy for a specific tile in a topology by populating a given array of socket filters with necessary file descriptors.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile within the topology.
    - `out_cnt`: An unsigned long integer representing the count of output socket filters to be populated.
    - `out`: A pointer to an array of `struct sock_filter` where the seccomp filter policy will be populated.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Call [`populate_sock_filter_policy_fd_bundle_tile`](generated/fd_bundle_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_bundle_tile) to populate the `out` array with socket filters using various file descriptors from the context and log file.
    - Return the constant `sock_filter_policy_fd_bundle_tile_instr_cnt` which presumably indicates the number of instructions in the populated seccomp filter.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the populated seccomp filter.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_bundle_tile`](generated/fd_bundle_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_bundle_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for a specific tile in a topology, ensuring that the array has at least five slots available.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the specific tile within the topology.
    - `out_fds_cnt`: An unsigned long integer representing the number of slots available in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Retrieve the context for the tile using `fd_topo_obj_laddr` with the topology and tile's object ID.
    - Check if `out_fds_cnt` is less than 5; if so, log an error and terminate the function.
    - Initialize `out_cnt` to 0 and set the first element of `out_fds` to 2, representing `stderr`.
    - Check if the log file descriptor is valid using `fd_log_private_logfile_fd`; if valid, add it to `out_fds`.
    - Check if the `etc_hosts` file descriptor in `ctx->netdb_fds` is valid; if valid, add it to `out_fds`.
    - Add the `etc_resolv_conf` file descriptor from `ctx->netdb_fds` to `out_fds`.
    - Check if `ctx->keylog_fd` is valid; if valid, add it to `out_fds`.
    - Return the count of file descriptors added to `out_fds`.
- **Output**: Returns an unsigned long integer representing the number of file descriptors added to the `out_fds` array.


