# Purpose
The provided C source code file is part of a larger system that appears to manage a peer-to-peer network, specifically focusing on a "repair" functionality. This code is responsible for maintaining and managing active peer connections, handling peer addresses, and managing protocol requests related to data repair. The file includes functions for creating, joining, and deleting repair structures ([`fd_repair_new`](#fd_repair_new), [`fd_repair_join`](#fd_repair_join), [`fd_repair_delete`](#fd_repair_delete)), as well as setting configurations and updating peer addresses ([`fd_repair_set_config`](#fd_repair_set_config), [`fd_repair_update_addr`](#fd_repair_update_addr)). It also includes mechanisms for managing inflight requests and handling peer cache files, which are used to store and retrieve peer information.

The code integrates several components, such as SHA-256, Ed25519, and Base58 encoding, indicating its use in cryptographic operations and data encoding/decoding. It also utilizes socket programming for network communication, as evidenced by the inclusion of headers like `<arpa/inet.h>` and `<sys/socket.h>`. The file defines a set of functions that manage the lifecycle of repair operations, including starting, continuing, and handling timed events ([`fd_repair_start`](#fd_repair_start), [`fd_repair_continue`](#fd_repair_continue)). Additionally, it provides utility functions for converting addresses to human-readable strings and managing protocol-specific requests. Overall, this file is a crucial part of a networked application, likely involved in maintaining data integrity and consistency across distributed nodes by facilitating repair operations.
# Imports and Dependencies

---
- `fd_repair.h`
- `../../ballet/sha256/fd_sha256.h`
- `../../ballet/ed25519/fd_ed25519.h`
- `../../ballet/base58/fd_base58.h`
- `../../disco/keyguard/fd_keyguard.h`
- `../../util/rng/fd_rng.h`
- `string.h`
- `stdio.h`
- `stdlib.h`
- `errno.h`
- `arpa/inet.h`
- `unistd.h`
- `sys/socket.h`


# Functions

---
### fd\_repair\_new<!-- {{#callable:fd_repair_new}} -->
The `fd_repair_new` function initializes a new repair structure in shared memory with various tables and settings, using a given seed for randomization.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the repair structure will be allocated.
    - `seed`: An unsigned long integer used to seed random number generation and other initializations.
- **Control Flow**:
    - Initialize scratch memory allocation with the provided shared memory pointer.
    - Allocate and zero-initialize a `fd_repair_t` structure in the scratch memory.
    - Allocate and initialize an active table, inflight table, and pinged table with respective alignments and footprints, joining them to the `fd_repair_t` structure.
    - Set various fields in the `fd_repair_t` structure to initial values, including stake weights, nonces, and random number generator.
    - Finalize the scratch memory allocation and check if the allocated space exceeds the available shared memory footprint.
    - Log an error if there is insufficient space, otherwise return the initialized `fd_repair_t` structure.
- **Output**: A pointer to the newly initialized `fd_repair_t` structure, or logs an error if there is insufficient space.
- **Functions called**:
    - [`fd_repair_footprint`](fd_repair.h.driver.md#fd_repair_footprint)


---
### fd\_repair\_join<!-- {{#callable:fd_repair_join}} -->
The `fd_repair_join` function casts a given shared memory pointer to a `fd_repair_t` pointer and returns it.
- **Inputs**:
    - `shmap`: A pointer to shared memory that is expected to be of type `fd_repair_t`.
- **Control Flow**:
    - The function takes a single argument, `shmap`, which is a pointer to shared memory.
    - It casts this pointer to a `fd_repair_t` pointer type.
    - The function then returns the casted pointer.
- **Output**: A pointer of type `fd_repair_t *`, which is the casted version of the input `shmap`.


---
### fd\_repair\_leave<!-- {{#callable:fd_repair_leave}} -->
The `fd_repair_leave` function returns the pointer to a `fd_repair_t` structure that was passed to it.
- **Inputs**:
    - `join`: A pointer to a `fd_repair_t` structure that represents a repair context.
- **Control Flow**:
    - The function takes a single argument, `join`, which is a pointer to a `fd_repair_t` structure.
    - It simply returns the same pointer that was passed to it.
- **Output**: The function returns the same pointer to `fd_repair_t` that was passed as an argument.


---
### fd\_repair\_delete<!-- {{#callable:fd_repair_delete}} -->
The `fd_repair_delete` function cleans up and deletes the active, inflight, and pinged tables associated with a repair object.
- **Inputs**:
    - `shmap`: A pointer to a shared memory region that contains the `fd_repair_t` structure to be deleted.
- **Control Flow**:
    - Cast the `shmap` pointer to a `fd_repair_t` pointer named `glob`.
    - Call `fd_active_table_leave` on `glob->actives` and pass the result to `fd_active_table_delete` to clean up the active table.
    - Call `fd_inflight_table_leave` on `glob->dupdetect` and pass the result to `fd_inflight_table_delete` to clean up the inflight table.
    - Call `fd_pinged_table_leave` on `glob->pinged` and pass the result to `fd_pinged_table_delete` to clean up the pinged table.
    - Return the `glob` pointer.
- **Output**: A pointer to the `fd_repair_t` structure that was passed in, after its associated tables have been deleted.


---
### fd\_repair\_addr\_str<!-- {{#callable:fd_repair_addr_str}} -->
The `fd_repair_addr_str` function converts a network address and port from a `fd_repair_peer_addr_t` structure into a human-readable string format and stores it in a provided buffer.
- **Inputs**:
    - `dst`: A pointer to a character buffer where the resulting string will be stored.
    - `dstlen`: The size of the destination buffer `dst`.
    - `src`: A pointer to a `fd_repair_peer_addr_t` structure containing the network address and port to be converted.
- **Control Flow**:
    - Declare a temporary buffer `tmp` to hold the string representation of the IP address.
    - Use `inet_ntop` to convert the IP address from network byte order to a string and store it in `tmp`.
    - Use `snprintf` to format the IP address and port into the `dst` buffer as a string in the format 'IP:port'.
    - Return the `dst` buffer containing the formatted address string.
- **Output**: The function returns a pointer to the `dst` buffer containing the formatted address string.


---
### fd\_repair\_set\_config<!-- {{#callable:fd_repair_set_config}} -->
The `fd_repair_set_config` function configures a `fd_repair_t` structure with the settings provided in a `fd_repair_config_t` structure.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure that will be configured.
    - `config`: A pointer to a `fd_repair_config_t` structure containing the configuration settings to be applied.
- **Control Flow**:
    - Encode the public key from the `config` structure into a Base58 string and log the configuration of the address and key.
    - Assign the public and private keys from the `config` structure to the `glob` structure.
    - Copy the intake and service addresses from the `config` structure to the `glob` structure using [`fd_repair_peer_addr_copy`](fd_repair.h.driver.md#fd_repair_peer_addr_copy).
    - Set the `good_peer_cache_file_fd` in the `glob` structure to the value from the `config` structure.
    - Return 0 to indicate successful configuration.
- **Output**: The function returns an integer value of 0, indicating successful configuration.
- **Functions called**:
    - [`fd_repair_addr_str`](#fd_repair_addr_str)
    - [`fd_repair_peer_addr_copy`](fd_repair.h.driver.md#fd_repair_peer_addr_copy)


---
### fd\_repair\_update\_addr<!-- {{#callable:fd_repair_update_addr}} -->
The `fd_repair_update_addr` function updates the intake and service addresses of a given `fd_repair_t` structure with new addresses provided as input.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure whose addresses are to be updated.
    - `intake_addr`: A pointer to an `fd_repair_peer_addr_t` structure representing the new intake address.
    - `service_addr`: A pointer to an `fd_repair_peer_addr_t` structure representing the new service address.
- **Control Flow**:
    - A temporary character array `tmp` of size 100 is declared for logging purposes.
    - The function logs a notice message indicating the update of the intake address using [`fd_repair_addr_str`](#fd_repair_addr_str) to convert the address to a string.
    - The [`fd_repair_peer_addr_copy`](fd_repair.h.driver.md#fd_repair_peer_addr_copy) function is called to copy the `intake_addr` into the `intake_addr` field of the `glob` structure.
    - The [`fd_repair_peer_addr_copy`](fd_repair.h.driver.md#fd_repair_peer_addr_copy) function is called again to copy the `service_addr` into the `service_addr` field of the `glob` structure.
    - The function returns 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_repair_addr_str`](#fd_repair_addr_str)
    - [`fd_repair_peer_addr_copy`](fd_repair.h.driver.md#fd_repair_peer_addr_copy)


---
### fd\_repair\_add\_active\_peer<!-- {{#callable:fd_repair_add_active_peer}} -->
The `fd_repair_add_active_peer` function adds a peer to the active peers list if it is not already present.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the global repair state.
    - `addr`: A constant pointer to an `fd_repair_peer_addr_t` structure representing the address of the peer to be added.
    - `id`: A constant pointer to an `fd_pubkey_t` structure representing the public key identifier of the peer to be added.
- **Control Flow**:
    - Query the active peers table using the provided `id` to check if the peer is already present.
    - If the peer is not found (`val` is `NULL`), insert the peer into the active peers table using the `id`.
    - Copy the provided `addr` to the newly inserted active element's address field.
    - Initialize the new active element's `avg_reqs`, `avg_reps`, `avg_lat`, and `stake` fields to zero.
    - Add the peer to the global peers list and increment the peer count.
    - Return 0 to indicate the peer was successfully added.
    - If the peer is already present, return 1 to indicate no addition was made.
- **Output**: Returns 0 if the peer was successfully added, or 1 if the peer was already present and no addition was made.
- **Functions called**:
    - [`fd_repair_peer_addr_copy`](fd_repair.h.driver.md#fd_repair_peer_addr_copy)


---
### fd\_repair\_settime<!-- {{#callable:fd_repair_settime}} -->
The `fd_repair_settime` function sets the current protocol time in nanoseconds for a given `fd_repair_t` structure.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure where the current protocol time will be set.
    - `ts`: A long integer representing the current protocol time in nanoseconds to be set in the `fd_repair_t` structure.
- **Control Flow**:
    - The function takes two parameters: a pointer to an `fd_repair_t` structure (`glob`) and a long integer (`ts`).
    - It assigns the value of `ts` to the `now` field of the `fd_repair_t` structure pointed to by `glob`.
- **Output**: This function does not return any value; it modifies the `now` field of the `fd_repair_t` structure in place.


---
### fd\_repair\_gettime<!-- {{#callable:fd_repair_gettime}} -->
The `fd_repair_gettime` function retrieves the current protocol time in nanoseconds from a given `fd_repair_t` structure.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure from which the current protocol time is to be retrieved.
- **Control Flow**:
    - The function accesses the `now` field of the `fd_repair_t` structure pointed to by `glob`.
    - It returns the value of the `now` field.
- **Output**: The function returns a `long` integer representing the current protocol time in nanoseconds.


---
### fd\_repair\_decay\_stats<!-- {{#callable:fd_repair_decay_stats}} -->
The `fd_repair_decay_stats` function iterates over active elements in a repair structure and reduces their average request, response, and latency statistics by 12.5%.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure, which contains the active elements whose statistics are to be decayed.
- **Control Flow**:
    - Initialize an iterator for the active elements in the `glob->actives` table.
    - Loop through each active element using the iterator until all elements are processed.
    - For each active element, retrieve the element using the iterator.
    - Apply a decay operation to the `avg_reqs`, `avg_reps`, and `avg_lat` fields of the element, reducing each by 12.5%.
- **Output**: The function does not return a value; it modifies the statistics of active elements in place.


---
### read\_line<!-- {{#callable:read_line}} -->
The `read_line` function reads characters from a file descriptor into a buffer until a newline character is encountered, the buffer limit is reached, or EOF is detected, and returns the number of characters read.
- **Inputs**:
    - `fd`: An integer representing the file descriptor from which to read.
    - `buf`: A character array (buffer) where the read line will be stored.
- **Control Flow**:
    - Initialize a counter `i` to 0 to track the number of characters read.
    - Enter a loop that continues until `i` reaches 255.
    - Read a single character from the file descriptor `fd` into a temporary variable `c`.
    - If the read operation returns a negative value, check if the error is `EINTR` and continue if so; otherwise, return -1 to indicate an error.
    - If the read operation returns 0, indicating EOF, break out of the loop.
    - Store the read character `c` into the buffer `buf` at the current index `i` and increment `i`.
    - If the character `c` is a newline character, break out of the loop.
    - After exiting the loop, null-terminate the buffer `buf` at index `i`.
    - Return the number of characters read, which is the value of `i`.
- **Output**: Returns a long integer representing the number of characters read into the buffer, excluding the null terminator, or -1 if an error occurs during reading.


---
### fd\_read\_in\_good\_peer\_cache\_file<!-- {{#callable:fd_read_in_good_peer_cache_file}} -->
The function `fd_read_in_good_peer_cache_file` reads and processes a list of peers from a specified file descriptor, adding valid peers to the repair structure's active peers list.
- **Inputs**:
    - `repair`: A pointer to an `fd_repair_t` structure, which contains the file descriptor for the good peer cache file and other repair-related data.
- **Control Flow**:
    - Check if the file descriptor for the good peer cache file is valid; if not, log a notice and return 0.
    - Seek to the beginning of the file; if seeking fails, log a warning and return 1.
    - Initialize variables for counting loaded peers and reading lines from the file.
    - Read lines from the file using [`read_line`](#read_line) until EOF is reached.
    - For each line, strip the newline character, skip empty or comment lines, and parse the line into base58 public key, IP address, and port components.
    - If parsing fails, log a warning and skip the line.
    - Decode the base58 public key; if decoding fails, log a warning and skip the line.
    - Convert the IP address to a network address; if conversion fails, log a warning and skip the line.
    - Convert the port to a long integer; if conversion fails or is out of range, log a warning and skip the line.
    - If all conversions are successful, increment the count of loaded peers.
    - Log the number of loaded peers and return 0.
- **Output**: Returns 0 on success or if no file is specified, and 1 if an error occurs during file seeking.
- **Functions called**:
    - [`read_line`](#read_line)


---
### fd\_repair\_start<!-- {{#callable:fd_repair_start}} -->
The `fd_repair_start` function initializes certain timestamp fields in the `fd_repair_t` structure and loads peers from a good peer cache file.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure that holds the state and configuration for the repair process.
- **Control Flow**:
    - Set `glob->last_sends`, `glob->last_decay`, and `glob->last_print` to the current time stored in `glob->now`.
    - Call [`fd_read_in_good_peer_cache_file`](#fd_read_in_good_peer_cache_file) with `glob` as an argument to load peers from the good peer cache file.
- **Output**: Returns the result of [`fd_read_in_good_peer_cache_file`](#fd_read_in_good_peer_cache_file), which is an integer indicating success (0) or failure (non-zero).
- **Functions called**:
    - [`fd_read_in_good_peer_cache_file`](#fd_read_in_good_peer_cache_file)


---
### fd\_repair\_continue<!-- {{#callable:fd_repair_continue}} -->
The `fd_repair_continue` function manages periodic tasks such as printing statistics, decaying statistics, and writing to a peer cache file based on elapsed time intervals.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure that holds the state and configuration for the repair process.
- **Control Flow**:
    - Check if the time since the last statistics print exceeds 30 seconds; if so, print all statistics, update the last print time, decay statistics, and update the last decay time.
    - If the above condition is not met, check if the time since the last statistics decay exceeds 15 seconds; if so, decay statistics and update the last decay time.
    - If neither of the above conditions are met, check if the time since the last good peer cache file write exceeds 60 seconds; if so, write to the good peer cache file and update the last write time.
- **Output**: The function returns 0, indicating successful execution of the periodic tasks.
- **Functions called**:
    - [`fd_repair_print_all_stats`](#fd_repair_print_all_stats)
    - [`fd_repair_decay_stats`](#fd_repair_decay_stats)
    - [`fd_write_good_peer_cache_file`](#fd_write_good_peer_cache_file)


---
### fd\_repair\_construct\_request\_protocol<!-- {{#callable:fd_repair_construct_request_protocol}} -->
The `fd_repair_construct_request_protocol` function constructs a repair request protocol message based on the specified type and updates the global metrics accordingly.
- **Inputs**:
    - `glob`: A pointer to the `fd_repair_t` structure, which holds global state and metrics for the repair process.
    - `protocol`: A pointer to the `fd_repair_protocol_t` structure, which will be populated with the constructed protocol message.
    - `type`: An enumeration value of type `fd_needed_elem_type` that specifies the type of repair request to construct.
    - `slot`: An unsigned long integer representing the slot number for which the repair request is being constructed.
    - `shred_index`: An unsigned integer representing the shred index within the slot for the repair request.
    - `recipient`: A pointer to a `fd_pubkey_t` structure representing the recipient's public key.
    - `nonce`: An unsigned integer used as a nonce for the request.
    - `now`: A long integer representing the current time in nanoseconds, used to set the timestamp in the protocol message.
- **Control Flow**:
    - The function begins by switching on the `type` parameter to determine the type of repair request to construct.
    - For `fd_needed_window_index`, it increments the corresponding metric, initializes the protocol for a window index request, and populates the protocol's header and fields with the provided inputs.
    - For `fd_needed_highest_window_index`, it increments the corresponding metric, initializes the protocol for a highest window index request, and populates the protocol's header and fields with the provided inputs.
    - For `fd_needed_orphan`, it increments the corresponding metric, initializes the protocol for an orphan request, and populates the protocol's header and fields with the provided inputs.
    - In each case, the function returns 1 after successfully constructing the protocol message.
    - If the `type` does not match any case, the function returns 0.
- **Output**: The function returns an integer: 1 if the protocol message was successfully constructed, or 0 if the type was not recognized.


---
### fd\_repair\_create\_inflight\_request<!-- {{#callable:fd_repair_create_inflight_request}} -->
The `fd_repair_create_inflight_request` function manages inflight requests for a specific type, slot, and shred index, ensuring requests are not sent too frequently.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure, which contains the global state for the repair process.
    - `type`: An integer representing the type of request, which is cast to an `enum fd_needed_elem_type`.
    - `slot`: An unsigned long integer representing the slot number for the request.
    - `shred_index`: An unsigned integer representing the shred index for the request.
    - `now`: A long integer representing the current time in nanoseconds.
- **Control Flow**:
    - Create a key `dupkey` using the provided `type`, `slot`, and `shred_index` to query the inflight table for existing requests.
    - Query the inflight table using `dupkey` to find an existing element `dupelem`.
    - If `dupelem` is not found, attempt to insert a new element into the inflight table with `dupkey`.
    - If insertion fails, log an error and return 0, indicating failure to create an inflight request.
    - If `dupelem` exists or is successfully inserted, check if the last send time plus 40 milliseconds is less than `now`.
    - If the condition is met, update `dupelem`'s last send time to `now`, set the request count to `FD_REPAIR_NUM_NEEDED_PEERS`, and return 1, indicating a new request can be sent.
    - If the condition is not met, return 0, indicating a request should not be sent yet.
- **Output**: Returns 1 if a new inflight request can be created and sent, or 0 if it cannot be sent due to recent activity.


---
### fd\_repair\_inflight\_remove<!-- {{#callable:fd_repair_inflight_remove}} -->
The `fd_repair_inflight_remove` function removes a specific shred from the inflight table if it exists.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure, which contains the inflight table among other data.
    - `slot`: An unsigned long integer representing the slot number associated with the shred to be removed.
    - `shred_index`: An unsigned integer representing the index of the shred to be removed.
- **Control Flow**:
    - Create a key `dupkey` with the type `fd_needed_window_index`, and the provided `slot` and `shred_index`.
    - Query the inflight table using `dupkey` to check if the shred exists.
    - If the shred exists (`dupelem` is not NULL), remove it from the inflight table using `fd_inflight_table_remove`.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### fd\_write\_good\_peer\_cache\_file<!-- {{#callable:fd_write_good_peer_cache_file}} -->
The `fd_write_good_peer_cache_file` function writes active sticky peers to a specified file in a specific format if certain conditions are met.
- **Inputs**:
    - `repair`: A pointer to an `fd_repair_t` structure containing information about the repair process, including the file descriptor for the good peer cache file and the list of active sticky peers.
- **Control Flow**:
    - Check if the file descriptor `good_peer_cache_file_fd` in the `repair` structure is valid (not -1); if not, return 0.
    - Check if there are any active sticky peers (`actives_sticky_cnt` is not 0); if not, return 0.
    - Truncate the file associated with `good_peer_cache_file_fd` to zero length; if this fails, log a warning and return 1.
    - Seek to the beginning of the file; if this fails, log a warning and return 1.
    - Iterate over each active sticky peer in the `actives_sticky` array.
    - For each peer, query the active table to get the peer's details; if the peer is not found, continue to the next peer.
    - Convert the peer's public key to a base58 string.
    - Convert the peer's IP address from network byte order to a dotted-decimal string.
    - Convert the peer's port from network byte order to host byte order.
    - Write the peer's base58 public key, IP address, and port to the file in the format 'base58EncodedPubkey/ipAddr/port'.
    - Return 0 after successfully writing all peers to the file.
- **Output**: Returns 0 on success or if no action is needed, and 1 if an error occurs during file operations.


---
### fd\_repair\_need\_window\_index<!-- {{#callable:fd_repair_need_window_index}} -->
The function `fd_repair_need_window_index` initiates an inflight request for a specific window index in a repair process.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure, which holds the state and configuration for the repair process.
    - `slot`: An unsigned long integer representing the slot number for which the window index is needed.
    - `shred_index`: An unsigned integer representing the shred index within the specified slot.
- **Control Flow**:
    - The function calls [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request) with the provided `glob`, `slot`, `shred_index`, and the current time from `glob->now`.
    - The [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request) function checks if there is an existing inflight request for the given slot and shred index.
    - If no inflight request exists or the last request was sent more than 40 milliseconds ago, it updates the inflight request and returns 1.
    - If an inflight request exists and was sent less than 40 milliseconds ago, it returns 0.
- **Output**: The function returns an integer indicating whether a new inflight request was successfully created (1) or not (0).
- **Functions called**:
    - [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request)


---
### fd\_repair\_need\_highest\_window\_index<!-- {{#callable:fd_repair_need_highest_window_index}} -->
The function `fd_repair_need_highest_window_index` initiates an inflight request for the highest window index needed for a given slot and shred index.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the global repair state.
    - `slot`: An unsigned long integer representing the slot for which the highest window index is needed.
    - `shred_index`: An unsigned integer representing the shred index within the slot.
- **Control Flow**:
    - The function calls [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request) with the parameters `glob`, `fd_needed_highest_window_index`, `slot`, `shred_index`, and `glob->now`.
    - The function returns the result of the [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request) call.
- **Output**: The function returns an integer indicating whether the inflight request was successfully created (1) or not (0).
- **Functions called**:
    - [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request)


---
### fd\_repair\_need\_orphan<!-- {{#callable:fd_repair_need_orphan}} -->
The `fd_repair_need_orphan` function initiates an inflight request for an orphan slot in the repair process.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the global repair state.
    - `slot`: An unsigned long integer representing the slot number for which an orphan request is needed.
- **Control Flow**:
    - The function calls [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request) with the parameters: `glob`, `fd_needed_orphan`, `slot`, `UINT_MAX`, and `glob->now`.
    - The [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request) function checks if there is an existing inflight request for the given slot and type.
    - If no inflight request exists, it inserts a new request into the inflight table and updates the last send time.
    - If an inflight request exists and the last send time is older than 40ms, it updates the last send time and sets the request count.
- **Output**: Returns an integer indicating whether the inflight request was successfully created (1) or not (0).
- **Functions called**:
    - [`fd_repair_create_inflight_request`](#fd_repair_create_inflight_request)


---
### print\_stats<!-- {{#callable:print_stats}} -->
The `print_stats` function logs statistical information about a repair peer's request and response activity, including request count, response rate, latency, and stake.
- **Inputs**:
    - `val`: A pointer to an `fd_active_elem_t` structure representing a repair peer, containing statistical data such as average requests, responses, latency, and stake.
- **Control Flow**:
    - Check if the input `val` is NULL and return immediately if it is.
    - Retrieve the public key from the `val` structure to identify the peer.
    - If the average requests (`avg_reqs`) is zero, log that no requests have been sent and display the peer's stake.
    - If the average responses (`avg_reps`) is zero, log the average requests sent, indicate no responses received, and display the peer's stake.
    - Otherwise, calculate the response rate and latency, then log the average requests, response rate, latency, and stake.
- **Output**: The function does not return a value; it logs information using the `FD_LOG_INFO` macro.


---
### fd\_repair\_print\_all\_stats<!-- {{#callable:fd_repair_print_all_stats}} -->
The `fd_repair_print_all_stats` function iterates over all active elements in a global repair structure and prints their statistics, followed by the total peer count.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure, which contains the active elements and other repair-related data.
- **Control Flow**:
    - Initialize an iterator for the active elements in the `glob->actives` table.
    - Iterate over each active element using the iterator until all elements are processed.
    - For each active element, retrieve the element and call [`print_stats`](#print_stats) to print its statistics.
    - After iterating through all elements, log the total count of active peers using `FD_LOG_INFO`.
- **Output**: The function does not return a value; it outputs statistics to the log.
- **Functions called**:
    - [`print_stats`](#print_stats)


---
### fd\_repair\_add\_sticky<!-- {{#callable:fd_repair_add_sticky}} -->
The `fd_repair_add_sticky` function adds a public key to the list of active sticky peers in the repair structure.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure, which holds the state and configuration for the repair process.
    - `id`: A constant pointer to an `fd_pubkey_t` structure representing the public key to be added to the active sticky peers list.
- **Control Flow**:
    - The function accesses the `actives_sticky` array within the `glob` structure.
    - It assigns the value of the public key pointed to by `id` to the current position in the `actives_sticky` array, indexed by `actives_sticky_cnt`.
    - The `actives_sticky_cnt` is then incremented to reflect the addition of a new sticky peer.
- **Output**: The function does not return a value; it modifies the `glob` structure in place by adding a new sticky peer.


---
### fd\_repair\_set\_stake\_weights<!-- {{#callable:fd_repair_set_stake_weights}} -->
The `fd_repair_set_stake_weights` function sets the stake weights for a repair object, ensuring the input is valid and copying the weights into the repair structure.
- **Inputs**:
    - `repair`: A pointer to an `fd_repair_t` structure where the stake weights will be set.
    - `stake_weights`: A pointer to an array of `fd_stake_weight_t` structures representing the stake weights to be set.
    - `stake_weights_cnt`: An unsigned long integer representing the number of stake weights in the `stake_weights` array.
- **Control Flow**:
    - Check if `stake_weights` is NULL and log an error if true.
    - Check if `stake_weights_cnt` exceeds `FD_STAKE_WEIGHTS_MAX` and log an error if true.
    - Clear the existing stake weights in the `repair` structure by setting them to zero.
    - Copy the provided `stake_weights` into the `repair` structure up to `stake_weights_cnt` elements.
    - Set the `stake_weights_cnt` field of the `repair` structure to the provided `stake_weights_cnt`.
- **Output**: The function does not return a value; it modifies the `repair` structure in place.


---
### fd\_repair\_get\_metrics<!-- {{#callable:fd_repair_get_metrics}} -->
The `fd_repair_get_metrics` function retrieves the metrics from a given repair structure.
- **Inputs**:
    - `repair`: A pointer to an `fd_repair_t` structure from which the metrics are to be retrieved.
- **Control Flow**:
    - The function takes a pointer to an `fd_repair_t` structure as input.
    - It accesses the `metrics` field of the `fd_repair_t` structure.
    - It returns a pointer to the `metrics` field.
- **Output**: A pointer to the `fd_repair_metrics_t` structure contained within the provided `fd_repair_t` structure.


# Function Declarations (Public API)

---
### fd\_repair\_print\_all\_stats<!-- {{#callable_declaration:fd_repair_print_all_stats}} -->
Logs statistics for all active peers.
- **Description**: Use this function to log detailed statistics for each active peer in the repair system. It iterates over all active peers and logs their request and response statistics, including average requests, response rate, latency, and stake. This function is typically used for monitoring and debugging purposes to understand the performance and behavior of the active peers. It should be called when you need a comprehensive overview of the current state of all active peers.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the global repair state. Must not be null. The function will access the active peers from this structure to log their statistics.
- **Output**: None
- **See also**: [`fd_repair_print_all_stats`](#fd_repair_print_all_stats)  (Implementation)


---
### fd\_write\_good\_peer\_cache\_file<!-- {{#callable_declaration:fd_write_good_peer_cache_file}} -->
Writes active sticky peers to a cache file.
- **Description**: This function writes the active sticky peers to a specified cache file in a specific format. It should be called when there is a need to persist the current state of active peers. The function requires that the file descriptor for the cache file is valid and that there are active sticky peers to write. If the file descriptor is invalid or there are no active sticky peers, the function returns immediately without performing any operations. The function handles file truncation and seeks to the beginning before writing, ensuring the file is overwritten with the latest data.
- **Inputs**:
    - `repair`: A pointer to an fd_repair_t structure. This must not be null and should be properly initialized with a valid file descriptor for the good peer cache file. The function expects the structure to contain active sticky peers to write.
- **Output**: Returns 0 on success or if no operation is needed, and 1 if an error occurs during file operations.
- **See also**: [`fd_write_good_peer_cache_file`](#fd_write_good_peer_cache_file)  (Implementation)


