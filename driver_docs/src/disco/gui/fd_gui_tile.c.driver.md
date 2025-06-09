# Purpose
This C source code file is part of a larger software system and is responsible for managing a graphical user interface (GUI) server that handles HTTP and WebSocket requests. The file includes various components and functionalities, such as setting up HTTP server parameters, handling incoming HTTP requests, managing WebSocket connections, and processing different types of messages related to plugins and data packets. The code is structured to support both privileged and unprivileged initialization, indicating that it is designed to operate in environments with varying levels of access control. It also includes functionality for compressing static assets using Zstandard, which suggests an optimization for serving web content efficiently.

The file imports several external components and libraries, such as JSON handling with cJSON, HTTP server management, and Zstandard compression, indicating that it is part of a modular system. It defines a public API for initializing and running the GUI server, which is likely intended to be integrated into a larger application. The code is organized around a central context structure (`fd_gui_ctx_t`) that maintains state information for the GUI server, including connection parameters, identity keys, and message buffers. This structure is used throughout the file to manage the server's operations and interactions with other components of the system. Overall, the file provides a comprehensive implementation of a GUI server within a distributed system, focusing on efficient handling of web requests and real-time data processing.
# Imports and Dependencies

---
- `generated/http_import_dist.h`
- `sys/socket.h`
- `generated/fd_gui_tile_arm64_seccomp.h`
- `generated/fd_gui_tile_seccomp.h`
- `../../disco/tiles.h`
- `../../disco/keyguard/fd_keyload.h`
- `../../disco/keyguard/fd_keyswitch.h`
- `../../disco/gui/fd_gui.h`
- `../../disco/plugin/fd_plugin.h`
- `../../waltz/http/fd_http_server.h`
- `../../ballet/json/cJSON.h`
- `sys/types.h`
- `unistd.h`
- `string.h`
- `poll.h`
- `stdio.h`
- `zstd.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fdctl\_major\_version
- **Type**: `ulong`
- **Description**: `fdctl_major_version` is a global constant variable of type `ulong` that represents the major version number of the Firedancer control software. It is declared as an external variable, indicating that its definition is located in another source file.
- **Use**: This variable is used to track and reference the major version of the software throughout the codebase.


---
### fdctl\_minor\_version
- **Type**: `ulong`
- **Description**: `fdctl_minor_version` is a global constant variable of type `ulong` that represents the minor version number of the Firedancer control software. It is declared as an external variable, indicating that its definition is located in another source file.
- **Use**: This variable is used to track and reference the minor version of the software, likely for version control and compatibility checks.


---
### fdctl\_patch\_version
- **Type**: `ulong`
- **Description**: The `fdctl_patch_version` is a global constant variable of type `ulong` that represents the patch version of the software. It is part of a versioning system that includes major, minor, and patch versions to track software updates and changes.
- **Use**: This variable is used to identify the specific patch version of the software, likely for compatibility checks or display purposes.


---
### fdctl\_commit\_ref
- **Type**: `uint`
- **Description**: The `fdctl_commit_ref` is a global constant variable of type `uint` that likely holds a reference or identifier related to a specific commit in a version control system, such as a commit hash or a unique identifier for a particular state of the codebase.
- **Use**: This variable is used to reference a specific commit in the codebase, potentially for version tracking or ensuring consistency across different parts of the software.


# Data Structures

---
### fd\_gui\_in\_ctx
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `mtu`: An unsigned long integer representing the maximum transmission unit size.
    - `chunk0`: An unsigned long integer indicating the starting chunk index.
    - `wmark`: An unsigned long integer representing the watermark or upper limit for chunks.
- **Description**: The `fd_gui_in_ctx` structure is designed to manage input context for a GUI component, specifically handling memory workspaces and chunk management. It includes a pointer to a memory workspace (`mem`), and several unsigned long integers (`mtu`, `chunk0`, and `wmark`) that define the maximum transmission unit, the starting chunk index, and the watermark for chunk processing, respectively. This structure is likely used to facilitate data handling and processing within a GUI context, ensuring efficient management of memory and data flow.


---
### fd\_gui\_in\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to an fd_wksp_t structure, representing a workspace for memory management.
    - `mtu`: An unsigned long integer representing the maximum transmission unit size.
    - `chunk0`: An unsigned long integer indicating the starting chunk index for data processing.
    - `wmark`: An unsigned long integer representing the watermark or upper limit for data processing.
- **Description**: The `fd_gui_in_ctx_t` structure is designed to manage input context for a GUI component, specifically handling memory workspace, data chunking, and transmission limits. It includes a pointer to a memory workspace (`mem`), and several unsigned long integers (`mtu`, `chunk0`, `wmark`) that define the data processing parameters such as maximum transmission unit, starting chunk index, and watermark for data processing.


---
### fd\_gui\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `topo`: Pointer to a topology structure, likely representing the network or system topology.
    - `gui`: Pointer to a GUI structure, representing the graphical user interface context.
    - `buf`: Buffer for storing message data, aligned to 8 bytes, with a size calculated for maximum message size.
    - `gui_server`: Pointer to an HTTP server structure, managing the GUI server.
    - `next_poll_deadline`: Timestamp for the next polling deadline.
    - `version_string`: String storing the version information, limited to 16 characters.
    - `keyswitch`: Pointer to a keyswitch structure, managing key switching operations.
    - `identity_key`: Pointer to a constant unsigned character array, representing the identity key.
    - `in_kind`: Array of 64 unsigned long integers, representing the kind of input.
    - `in_bank_idx`: Array of 64 unsigned long integers, representing the bank index for inputs.
    - `in`: Array of 64 input context structures, managing input data and metadata.
- **Description**: The `fd_gui_ctx_t` structure is a comprehensive context for managing a GUI server within a networked application. It includes pointers to various components such as the topology, GUI, and HTTP server, as well as buffers and arrays for handling message data and input contexts. The structure is designed to facilitate communication and data processing in a distributed system, with fields for managing deadlines, versioning, and key switching. The large buffer is specifically aligned and sized to accommodate the maximum expected message size, ensuring efficient data handling.


# Functions

---
### derive\_http\_params<!-- {{#callable:derive_http_params}} -->
The `derive_http_params` function initializes and returns an `fd_http_server_params_t` structure with HTTP server parameters derived from a given `fd_topo_tile_t` structure.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which contains configuration data for the HTTP server.
- **Control Flow**:
    - The function takes a pointer to a `fd_topo_tile_t` structure as input.
    - It initializes an `fd_http_server_params_t` structure with values derived from the `tile` structure and predefined constants.
    - The `max_connection_cnt` and `max_ws_connection_cnt` are set using values from the `tile->gui` structure.
    - The `max_request_len`, `max_ws_recv_frame_len`, and `max_ws_send_frame_cnt` are set using predefined constants.
    - The `outgoing_buffer_sz` is calculated by multiplying `tile->gui.send_buffer_size_mb` by 1 megabyte (1UL<<20UL).
    - The function returns the initialized `fd_http_server_params_t` structure.
- **Output**: An `fd_http_server_params_t` structure containing the derived HTTP server parameters.


---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use only within the file it is defined and suggests the compiler to inline it for performance.
    - The function does not take any parameters.
    - It directly returns the constant value 128UL, which is an unsigned long integer.
- **Output**: The function outputs a constant unsigned long integer value of 128, representing an alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for various components of a GUI server setup based on the configuration of a given tile.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure containing configuration parameters for the GUI server.
- **Control Flow**:
    - Call [`derive_http_params`](#derive_http_params) with `tile` to get HTTP server parameters.
    - Calculate the HTTP server footprint using `fd_http_server_footprint` with the derived parameters.
    - Check if the HTTP server footprint is valid; if not, log an error and terminate.
    - Initialize a layout variable `l` with `FD_LAYOUT_INIT`.
    - Append the size and alignment of `fd_gui_ctx_t` to `l`.
    - Append the alignment and footprint of the HTTP server to `l`.
    - Append the alignment and footprint of the GUI to `l`.
    - Append the alignment and footprint of the allocator to `l`.
    - Finalize the layout with `FD_LAYOUT_FINI` using [`scratch_align`](#scratch_align) and return the result.
- **Output**: Returns an `ulong` representing the total memory footprint required for the GUI server setup.
- **Functions called**:
    - [`derive_http_params`](#derive_http_params)
    - [`scratch_align`](#scratch_align)


---
### dist\_file\_sz<!-- {{#callable:dist_file_sz}} -->
The `dist_file_sz` function calculates the total size of all static files by summing their individual sizes.
- **Inputs**: None
- **Control Flow**:
    - Initialize a variable `tot_sz` to 0 to hold the total size of the files.
    - Iterate over each file in the `STATIC_FILES` array until a file with a null `name` is encountered, indicating the end of the array.
    - For each file, add the value pointed to by `f->data_len` to `tot_sz`.
    - Return the accumulated total size `tot_sz`.
- **Output**: The function returns an `ulong` representing the total size of all static files.


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function checks the state of a keyswitch and updates the GUI identity if a switch is pending, then marks the switch as completed.
- **Inputs**:
    - `ctx`: A pointer to an `fd_gui_ctx_t` structure, which contains context information for the GUI, including the keyswitch and GUI identity.
- **Control Flow**:
    - Check if the keyswitch state is `FD_KEYSWITCH_STATE_SWITCH_PENDING` using `fd_keyswitch_state_query`.
    - If the state is pending, update the GUI identity using `fd_gui_set_identity` with the keyswitch's bytes.
    - Set the keyswitch state to `FD_KEYSWITCH_STATE_COMPLETED` using `fd_keyswitch_state`.
- **Output**: This function does not return a value; it performs operations on the provided context.


---
### before\_credit<!-- {{#callable:before_credit}} -->
The `before_credit` function updates the polling state of a GUI context by checking deadlines and polling both the HTTP server and GUI, then sets a busy charge flag based on these operations.
- **Inputs**:
    - `ctx`: A pointer to an `fd_gui_ctx_t` structure representing the GUI context, which includes server and polling information.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which is not used in this function.
    - `charge_busy`: A pointer to an integer where the function will store the result of the busy charge calculation.
- **Control Flow**:
    - Initialize `charge_busy_server` to 0.
    - Get the current time using `fd_tickcount()`.
    - Check if the current time is greater than or equal to `ctx->next_poll_deadline`.
    - If the deadline has passed, poll the HTTP server using `fd_http_server_poll` and update `charge_busy_server` with the result.
    - Update `ctx->next_poll_deadline` to a new deadline based on the current time and a fixed interval.
    - Poll the GUI using `fd_gui_poll` and store the result in `charge_poll`.
    - Combine `charge_busy_server` and `charge_poll` using a bitwise OR operation and store the result in `*charge_busy`.
- **Output**: The function outputs an integer value through the `charge_busy` pointer, indicating whether the server or GUI polling resulted in a busy state.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes a data fragment from a specified input index, adjusting its size based on the message type and ensuring it is within valid bounds before copying it to a buffer.
- **Inputs**:
    - `ctx`: A pointer to the `fd_gui_ctx_t` context structure, which contains information about the GUI and input data.
    - `in_idx`: An unsigned long integer representing the index of the input source from which the fragment is being processed.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, marked as unused in this function.
    - `sig`: An unsigned long integer representing the signal or message type of the fragment.
    - `chunk`: An unsigned long integer representing the chunk identifier of the fragment.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `gui`: An unsigned long integer marked as unused in this function.
- **Control Flow**:
    - Convert the chunk identifier to a local address using `fd_chunk_to_laddr` and store it in `src`.
    - Check if the input kind at `in_idx` is `IN_KIND_PLUGIN`.
    - If the input kind is `IN_KIND_PLUGIN`, adjust the size `sz` based on the message type `sig` (e.g., `FD_PLUGIN_MSG_GOSSIP_UPDATE`, `FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE`, `FD_PLUGIN_MSG_LEADER_SCHEDULE`).
    - Verify that the chunk and size are within valid bounds; if not, log an error and exit.
    - Copy the data from `src` to `ctx->buf` using `fd_memcpy`.
    - If the input kind is not `IN_KIND_PLUGIN`, verify the chunk and size against different bounds and log an error if they are invalid.
    - Copy the data from `src` to `ctx->buf` using `fd_memcpy`.
- **Output**: The function does not return a value; it performs operations on the input data and logs errors if any conditions are violated.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes different types of input fragments based on their kind and signature, updating the GUI context accordingly.
- **Inputs**:
    - `ctx`: A pointer to the `fd_gui_ctx_t` structure, which holds the GUI context and related data.
    - `in_idx`: An unsigned long integer representing the index of the input kind in the context.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, though it is unused in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment, used to determine the packet type.
    - `sz`: An unsigned long integer representing the size of the fragment data.
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment, though it is unused in this function.
    - `tspub`: An unsigned long integer representing the publication timestamp of the fragment.
    - `stem`: A pointer to the `fd_stem_context_t` structure, though it is unused in this function.
- **Control Flow**:
    - The function first checks if the input kind at `in_idx` is `IN_KIND_PLUGIN`; if so, it calls `fd_gui_plugin_message` with the GUI context, signature, and buffer.
    - If the input kind is `IN_KIND_POH_PACK`, it verifies the packet type is `POH_PKT_TYPE_BECAME_LEADER` and processes it as a 'became leader' event, calling `fd_gui_became_leader`.
    - For `IN_KIND_PACK_BANK`, it checks the packet type; if `POH_PKT_TYPE_MICROBLOCK`, it processes the microblock execution begin event, otherwise, if `POH_PKT_TYPE_DONE_PACKING`, it processes the unbecame leader event.
    - If the input kind is `IN_KIND_BANK_POH`, it processes the microblock execution end event by calling `fd_gui_microblock_execution_end`.
    - If none of the expected input kinds match, it logs an error for an unexpected input kind.
- **Output**: The function does not return a value; it performs operations based on the input kind and signature to update the GUI context.


---
### gui\_http\_request<!-- {{#callable:gui_http_request}} -->
The `gui_http_request` function processes HTTP requests for a GUI server, handling specific paths and methods to return appropriate HTTP responses.
- **Inputs**:
    - `request`: A pointer to a constant `fd_http_server_request_t` structure representing the incoming HTTP request.
- **Control Flow**:
    - Check if the request method is not GET; if so, return a 405 Method Not Allowed response.
    - Check if the request path is '/websocket'; if so, return a 200 OK response with WebSocket upgrade.
    - Check if the request path is '/favicon.svg'; if so, return a 200 OK response with the SVG content and appropriate headers.
    - Determine if the request path corresponds to a Vite page by checking against several predefined paths.
    - Iterate over static files to find a match with the request path or if the path is a Vite page and the file is '/index.html'.
    - For a matching static file, determine the content type based on the file extension and set cache control headers based on the path.
    - Check if the request accepts Zstandard encoding and if the file has Zstandard compressed data, then set the content encoding and use the compressed data.
    - Return a 200 OK response with the static file content and appropriate headers if a match is found.
    - If no conditions are met, return a 404 Not Found response.
- **Output**: Returns an `fd_http_server_response_t` structure representing the HTTP response, including status code, headers, and body content if applicable.


---
### gui\_ws\_open<!-- {{#callable:gui_ws_open}} -->
The `gui_ws_open` function initializes a WebSocket connection for a GUI context using a given connection ID.
- **Inputs**:
    - `conn_id`: An unsigned long integer representing the connection ID for the WebSocket connection.
    - `_ctx`: A pointer to a context object, specifically cast to `fd_gui_ctx_t`, which contains the GUI state and resources.
- **Control Flow**:
    - Cast the `_ctx` parameter to a `fd_gui_ctx_t` pointer named `ctx`.
    - Call the `fd_gui_ws_open` function with `ctx->gui` and `conn_id` to open the WebSocket connection.
- **Output**: This function does not return a value; it performs an action to open a WebSocket connection.


---
### gui\_ws\_message<!-- {{#callable:gui_ws_message}} -->
The `gui_ws_message` function processes a WebSocket message for a GUI context and closes the connection if necessary.
- **Inputs**:
    - `ws_conn_id`: The unique identifier for the WebSocket connection.
    - `data`: A pointer to the data received in the WebSocket message.
    - `data_len`: The length of the data received.
    - `_ctx`: A pointer to the context, specifically a `fd_gui_ctx_t` structure, associated with the GUI.
- **Control Flow**:
    - Cast the `_ctx` pointer to a `fd_gui_ctx_t` pointer named `ctx`.
    - Call `fd_gui_ws_message` with the GUI context, connection ID, data, and data length to process the message.
    - Check if the return value `close` from `fd_gui_ws_message` is less than 0, indicating an error or a need to close the connection.
    - If `close` is less than 0, call `fd_http_server_ws_close` to close the WebSocket connection with the specified `close` code.
- **Output**: The function does not return a value; it performs operations based on the WebSocket message and may close the connection if needed.


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a GUI server context and sets up an HTTP server with specific parameters and callbacks, while also loading an identity key from a specified path.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile configuration, including GUI settings.
- **Control Flow**:
    - Retrieve a scratch memory address using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_gui_ctx_t` context structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Derive HTTP server parameters from the tile configuration using [`derive_http_params`](#derive_http_params).
    - Allocate memory for an HTTP server using `FD_SCRATCH_ALLOC_APPEND` with alignment and footprint based on the derived parameters.
    - Define HTTP server callbacks for handling requests, WebSocket openings, and WebSocket messages.
    - Create and join a new HTTP server with the allocated memory, parameters, and callbacks, storing the result in the context's `gui_server`.
    - Start listening on the HTTP server using the address and port specified in the tile's GUI configuration.
    - Check if the `identity_key_path` in the tile's GUI configuration is empty and log an error if it is.
    - Load the identity key from the specified path using `fd_keyload_load`, storing it in the context's `identity_key`.
- **Output**: The function does not return a value; it initializes the GUI server context and sets up the HTTP server.
- **Functions called**:
    - [`derive_http_params`](#derive_http_params)


---
### pre\_compress\_files<!-- {{#callable:pre_compress_files}} -->
The `pre_compress_files` function compresses static assets using Zstandard and allocates workspace memory for the compressed data.
- **Inputs**:
    - `wksp`: A pointer to an `fd_wksp_t` structure representing the workspace where memory allocations for compression will be made.
- **Control Flow**:
    - Estimate the size of the ZSTD compression context and allocate memory for it in the workspace.
    - Initialize a static ZSTD compression context using the allocated memory.
    - Allocate permanent space in the workspace for the compressed files.
    - Iterate over static files, checking their extensions to determine if they should be compressed (only .html, .css, .js, and .svg files are compressed).
    - For each file to be compressed, allocate a buffer in the workspace, compress the file data using the ZSTD context, and handle any compression errors by logging a warning and breaking the loop.
    - Store the compressed data and its size back into the file structure.
    - Calculate the total uncompressed and compressed sizes of all files.
    - Free the allocated ZSTD compression context memory.
    - Log the compression results, showing the total uncompressed and compressed sizes.
- **Output**: The function does not return a value; it modifies the static file structures in place to store compressed data and logs the compression results.
- **Functions called**:
    - [`dist_file_sz`](#dist_file_sz)


---
### cjson\_alloc<!-- {{#callable:cjson_alloc}} -->
The `cjson_alloc` function allocates memory of a specified size using a custom allocator if available, or falls back to the standard `malloc` if not.
- **Inputs**:
    - `sz`: The size in bytes of the memory to be allocated.
- **Control Flow**:
    - Check if the custom allocator context `cjson_alloc_ctx` is available using `FD_LIKELY`.
    - If `cjson_alloc_ctx` is available, call `fd_alloc_malloc` with `cjson_alloc_ctx`, an alignment of 8 bytes, and the requested size `sz` to allocate memory.
    - If `cjson_alloc_ctx` is not available, use the standard `malloc` function to allocate memory of size `sz`.
- **Output**: A pointer to the allocated memory block, or `NULL` if the allocation fails.


---
### cjson\_free<!-- {{#callable:cjson_free}} -->
The `cjson_free` function deallocates memory for a given pointer using a custom allocator context if available, or the standard `free` function otherwise.
- **Inputs**:
    - `ptr`: A pointer to the memory block that needs to be deallocated.
- **Control Flow**:
    - Check if the custom allocator context `cjson_alloc_ctx` is available using `FD_LIKELY`.
    - If `cjson_alloc_ctx` is available, call `fd_alloc_free` with `cjson_alloc_ctx` and `ptr` to deallocate the memory.
    - If `cjson_alloc_ctx` is not available, call the standard `free` function with `ptr` to deallocate the memory.
- **Output**: The function does not return any value; it performs memory deallocation for the provided pointer.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the GUI context and related resources for a tile in a topology, setting up memory allocations, GUI server, and input links.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration within the topology.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - If ZSTD compression is enabled, call [`pre_compress_files`](#pre_compress_files) to compress static assets.
    - Initialize scratch memory allocation using `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for `fd_gui_ctx_t`, HTTP server, GUI, and allocator using `FD_SCRATCH_ALLOC_APPEND`.
    - Check and format the version string using `fd_cstr_printf_check`.
    - Initialize the GUI context by joining a new GUI instance with `fd_gui_join` and `fd_gui_new`.
    - Join the keyswitch object using `fd_keyswitch_join`.
    - Initialize the cJSON hooks for memory allocation using `cJSON_InitHooks`.
    - Set the next poll deadline using `fd_tickcount`.
    - Iterate over each input link of the tile, setting up the input kind and memory context based on the link name.
    - Finalize the scratch memory allocation with `FD_SCRATCH_ALLOC_FINI` and check for overflow.
    - Log a warning message indicating the GUI server's listening address and port.
- **Output**: The function does not return a value; it initializes the GUI context and related resources for the specified tile.
- **Functions called**:
    - [`pre_compress_files`](#pre_compress_files)
    - [`derive_http_params`](#derive_http_params)
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function initializes a scratch memory area and populates a seccomp filter policy for a GUI tile, returning the instruction count of the policy.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output seccomp filter instructions.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter instructions will be stored.
- **Control Flow**:
    - Retrieve a scratch memory location using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Initialize the scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_gui_ctx_t` structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Call [`populate_sock_filter_policy_fd_gui_tile`](generated/fd_gui_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_gui_tile) to populate the seccomp filter policy using the provided output count, filter array, and file descriptors.
    - Return the instruction count of the seccomp filter policy from `sock_filter_policy_fd_gui_tile_instr_cnt`.
- **Output**: The function returns an unsigned long integer representing the instruction count of the seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_gui_tile`](generated/fd_gui_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_gui_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for a specific tile in a topology, ensuring that the array has at least three entries.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the specific tile within the topology.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Allocate scratch memory using `fd_topo_obj_laddr` and initialize it with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate a `fd_gui_ctx_t` context structure in the scratch memory using `FD_SCRATCH_ALLOC_APPEND`.
    - Check if `out_fds_cnt` is less than 3; if so, log an error and terminate using `FD_LOG_ERR`.
    - Initialize `out_cnt` to 0 and set `out_fds[out_cnt++]` to 2, which corresponds to the standard error file descriptor.
    - Check if the log file descriptor is valid (not -1) using `FD_LIKELY`; if valid, add it to `out_fds` and increment `out_cnt`.
    - Add the GUI server's file descriptor to `out_fds` using `fd_http_server_fd` and increment `out_cnt`.
    - Return the count of file descriptors added to `out_fds`.
- **Output**: Returns the number of file descriptors added to the `out_fds` array as an unsigned long integer.


---
### rlimit\_file\_cnt<!-- {{#callable:rlimit_file_cnt}} -->
The `rlimit_file_cnt` function calculates the total number of file descriptors required for a GUI tile, including base descriptors and those needed for HTTP and WebSocket connections.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which contains configuration details for the GUI tile, including maximum HTTP and WebSocket connections.
- **Control Flow**:
    - Initialize a base count of file descriptors to 5, accounting for pipefd, socket, stderr, logfile, and a spare for new accept() connections.
    - Add the maximum number of HTTP connections from the `tile` structure to the base count.
    - Add the maximum number of WebSocket connections from the `tile` structure to the base count.
    - Return the total count of file descriptors.
- **Output**: The function returns an `ulong` representing the total number of file descriptors required for the GUI tile.


