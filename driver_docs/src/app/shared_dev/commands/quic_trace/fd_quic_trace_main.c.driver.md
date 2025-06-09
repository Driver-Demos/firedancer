# Purpose
The provided C source code file, `fd_quic_trace_main.c`, is part of a larger system designed to trace QUIC (Quick UDP Internet Connections) traffic on a live system. This file specifically implements the functionality required to connect to and monitor QUIC traffic by interfacing with shared memory segments of a running `fd_quic_tile` on the same host. The code operates in a read-only mode to minimize its impact on the production system, ensuring that it does not interfere with the ongoing operations of the QUIC connections it monitors.

The file defines several global variables and functions that facilitate the tracing process. It includes functions for parsing command-line arguments, dumping QUIC configuration and connection details, and managing the connection state. The code also handles the setup and joining of shared memory objects, ensuring that the tracing tool can access the necessary data structures without modifying them. The [`quic_trace_cmd_fn`](#quic_trace_cmd_fn) function is the main entry point for executing the trace command, which involves setting up the environment, joining the necessary shared memory segments, and initiating the tracing process based on the specified event type (either stream or error). The file is part of a diagnostic toolset, as indicated by the `fd_action_quic_trace` structure, which registers the trace command with a description and marks it as a diagnostic action.
# Imports and Dependencies

---
- `fd_quic_trace.h`
- `../../../shared/fd_config.h`
- `../../../../disco/metrics/fd_metrics.h`
- `../../../../disco/quic/fd_quic_tile.h`
- `../../../../waltz/quic/log/fd_quic_log_user.h`
- `../../../../ballet/hex/fd_hex.h`


# Global Variables

---
### fd\_quic\_trace\_ctx
- **Type**: `fd_quic_ctx_t`
- **Description**: The `fd_quic_trace_ctx` is a global variable of type `fd_quic_ctx_t`, which is used to store the context for tracing QUIC traffic. This context is essential for managing the state and operations related to QUIC tracing in a live system.
- **Use**: This variable is used to hold the local copy of the QUIC context, which is derived from a remote QUIC context in shared memory, allowing the system to perform read-only operations for tracing purposes.


---
### fd\_quic\_trace\_ctx\_remote
- **Type**: `fd_quic_ctx_t const *`
- **Description**: The `fd_quic_trace_ctx_remote` is a global pointer variable that holds a constant reference to a `fd_quic_ctx_t` structure. This structure is used to represent the context of a QUIC (Quick UDP Internet Connections) tile in a remote shared memory segment.
- **Use**: This variable is used to access the remote QUIC context in a read-only manner to facilitate tracing of QUIC traffic without affecting the production system.


---
### fd\_quic\_trace\_ctx\_raddr
- **Type**: `ulong`
- **Description**: The `fd_quic_trace_ctx_raddr` is a global variable of type `ulong` that stores the remote address of the QUIC context in the tile address space. It is used to facilitate the rebasing of pointers when accessing shared memory segments of a remote `fd_quic_tile` object.
- **Use**: This variable is used to store the calculated remote address of the QUIC context, which is essential for correctly rebasing pointers to access shared memory in a read-only manner.


---
### fd\_quic\_trace\_target\_fseq
- **Type**: `ulong **`
- **Description**: `fd_quic_trace_target_fseq` is a global variable that is a pointer to an array of pointers to unsigned long integers. It is used to store the original fseq objects, which are monitored to ensure the trace RX tile does not skip ahead of the QUIC tile.
- **Use**: This variable is used to track the sequence numbers of incoming links to ensure synchronization between the trace RX tile and the QUIC tile.


---
### fd\_quic\_trace\_link\_metrics
- **Type**: `ulong volatile *`
- **Description**: The `fd_quic_trace_link_metrics` is a global variable that is a pointer to a volatile unsigned long integer. It is used to link and manage metrics related to the QUIC trace functionality in the system. The use of 'volatile' suggests that the value pointed to by this variable may be changed by something outside the control of the code section in which it appears, such as hardware or a different thread.
- **Use**: This variable is used to link the metrics for the QUIC trace, allowing the system to monitor and update metrics related to QUIC traffic tracing.


---
### fd\_quic\_trace\_log\_base
- **Type**: `void const *`
- **Description**: The `fd_quic_trace_log_base` is a global pointer to a constant void type, which indicates it is used to reference a memory location that should not be modified through this pointer. It is likely used to point to the base of a log buffer or memory segment related to QUIC tracing.
- **Use**: This variable is used to store the base address of the log buffer for QUIC tracing operations.


---
### \_fd\_quic\_trace\_peer\_map
- **Type**: `peer_conn_id_map_t`
- **Description**: The `_fd_quic_trace_peer_map` is a global array of `peer_conn_id_map_t` structures, with a size determined by the bit-shift operation `1UL<<PEER_MAP_LG_SLOT_CNT`. This array is used to store mappings of peer connection IDs for QUIC connections.
- **Use**: This variable is used to initialize and manage the peer connection ID map for tracing QUIC connections, allowing the system to track and reference connections by their peer IDs.


---
### fd\_quic\_trace\_peer\_map
- **Type**: `peer_conn_id_map_t*`
- **Description**: The `fd_quic_trace_peer_map` is a global pointer to a `peer_conn_id_map_t` data structure. This structure is used to map peer connection IDs to connection indices, facilitating the tracking and management of QUIC connections in the system.
- **Use**: This variable is used to store and manage mappings of peer connection IDs to their respective connection indices for QUIC traffic tracing.


---
### fd\_action\_quic\_trace
- **Type**: `action_t`
- **Description**: The `fd_action_quic_trace` is a global variable of type `action_t` that represents an action for tracing QUIC traffic. It is configured with a name, arguments, a function to execute, a description, and a diagnostic flag. This action is part of a system designed to monitor QUIC traffic by tapping into shared memory segments of a running QUIC tile.
- **Use**: This variable is used to define and execute the 'quic-trace' action, which is responsible for tracing QUIC traffic in a diagnostic capacity.


# Functions

---
### quic\_trace\_cmd\_args<!-- {{#callable:quic_trace_cmd_args}} -->
The `quic_trace_cmd_args` function processes command-line arguments to configure QUIC tracing options, setting event types and dump flags in the provided `args_t` structure.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `args_t` structure where the parsed command-line options will be stored.
- **Control Flow**:
    - Call `fd_env_strip_cmdline_cstr` to extract the `--event` argument from the command line, defaulting to "stream" if not provided.
    - Compare the extracted event string to "stream" and "error" to set the `args->quic_trace.event` to `EVENT_STREAM` or `EVENT_ERROR` respectively.
    - Log an error and terminate if the event type is unsupported.
    - Call `fd_env_strip_cmdline_contains` to check for the presence of `--dump`, `--dump-config`, and `--dump-conns` flags, setting the corresponding fields in `args->quic_trace`.
- **Output**: The function does not return a value; it modifies the `args` structure to reflect the parsed command-line options.


---
### dump\_val\_enum\_role<!-- {{#callable:dump_val_enum_role}} -->
The `dump_val_enum_role` function returns a string representation of a QUIC role based on the integer input.
- **Inputs**:
    - `role`: An integer representing the QUIC role, which can be either `FD_QUIC_ROLE_CLIENT`, `FD_QUIC_ROLE_SERVER`, or an unknown role.
- **Control Flow**:
    - The function uses a switch statement to determine the string representation of the role.
    - If the role is `FD_QUIC_ROLE_CLIENT`, it returns "ROLE_CLIENT".
    - If the role is `FD_QUIC_ROLE_SERVER`, it returns "ROLE_SERVER".
    - For any other value, it returns "ROLE_UNKNOWN".
- **Output**: A constant character pointer to a string that represents the role, such as "ROLE_CLIENT", "ROLE_SERVER", or "ROLE_UNKNOWN".


---
### dump\_val\_bool<!-- {{#callable:dump_val_bool}} -->
The `dump_val_bool` function converts an integer value to its corresponding boolean string representation.
- **Inputs**:
    - `value`: An integer representing a boolean value, typically expected to be 0 or 1.
- **Control Flow**:
    - The function uses a switch statement to evaluate the input integer 'value'.
    - If 'value' is 0, the function returns the string "false".
    - If 'value' is 1, the function returns the string "true".
    - For any other integer value, the function returns the string "invalid" to handle unexpected inputs.
- **Output**: A constant character pointer to a string representing the boolean value of the input integer, or "invalid" if the input is not 0 or 1.


---
### dump\_quic\_config<!-- {{#callable:dump_quic_config}} -->
The `dump_quic_config` function logs the configuration details of a QUIC connection based on its role and other parameters.
- **Inputs**:
    - `config`: A pointer to an `fd_quic_config_t` structure containing the QUIC configuration to be logged.
- **Control Flow**:
    - The function begins by checking the `role` field of the `config` structure and logs whether it is a client, server, or unknown role using `FD_LOG_NOTICE`.
    - It defines several macros for formatting and logging different types of configuration values, such as enums, booleans, units, values, pointers, and 32-byte hexadecimal values.
    - The `dump_val` macro is used to apply the appropriate logging macro to each configuration parameter in the `FD_QUIC_CONFIG_LIST`.
- **Output**: The function does not return a value; it outputs log messages detailing the configuration parameters.


---
### peer\_cid\_str<!-- {{#callable:peer_cid_str}} -->
The `peer_cid_str` function converts the first peer connection ID of a QUIC connection to a hexadecimal string representation.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing a QUIC connection, from which the peer connection ID is extracted.
- **Control Flow**:
    - Retrieve the size of the first peer connection ID from the `conn` structure.
    - Retrieve the connection ID itself from the `conn` structure.
    - Limit the size to `FD_QUIC_MAX_CONN_ID_SZ` using `fd_ulong_min`.
    - Encode the connection ID into a hexadecimal string using `fd_hex_encode`.
    - Return the buffer containing the hexadecimal string.
- **Output**: A pointer to a static character buffer containing the hexadecimal string representation of the first peer connection ID.


---
### dump\_connection<!-- {{#callable:dump_connection}} -->
The `dump_connection` function logs detailed information about a QUIC connection's state and attributes using a predefined format.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection whose details are to be logged.
- **Control Flow**:
    - The function begins by defining a macro `CONN_MEMB_LIST` that lists various attributes of the `fd_quic_conn_t` structure, each with a format specifier and a way to access the attribute from the `conn` object.
    - Two additional macros, `CONN_MEMB_FMT` and `CONN_MEMB_ARGS`, are defined to format the output string and arguments for logging, respectively.
    - The `FD_LOG_NOTICE` function is called with a formatted string that includes all the connection attributes defined in `CONN_MEMB_LIST`, using the `CONN_MEMB_FMT` and `CONN_MEMB_ARGS` macros to construct the log message.
- **Output**: The function does not return any value; it outputs the connection details to the log using the `FD_LOG_NOTICE` macro.


---
### quic\_trace\_cmd\_fn<!-- {{#callable:quic_trace_cmd_fn}} -->
The `quic_trace_cmd_fn` function initializes and manages the tracing of QUIC traffic by setting up the necessary context, joining shared memory objects, and processing connection states and events.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments and options for the QUIC trace operation.
    - `config`: A pointer to a `config_t` structure containing the configuration and topology information for the QUIC trace operation.
- **Control Flow**:
    - Initialize the topology from the configuration and join workspaces in read-only mode.
    - Search for the 'quic' tile in the topology and handle errors if not found or if multiple net tiles are present.
    - Rebase pointers for the QUIC context to handle non-relocatable object addressing.
    - Find the 'quic_net' link in the topology and handle errors if not found.
    - Initialize the trace context with options from the arguments.
    - Set up network input bounds and log the state of the QUIC tile.
    - Join the shared memory objects and verify their integrity.
    - Dump the QUIC configuration if requested.
    - Initialize and join the peer connection ID map.
    - Iterate over connections, dumping and inserting them into the peer map as needed.
    - Log the total number of connections and their states.
    - Allocate and initialize the target fseq array to monitor sequence numbers.
    - Join the QUIC log and handle errors if joining fails.
    - Redirect metadata writes to dummy buffers to prevent writes to read-only topology.
    - Register and link metrics for the QUIC trace.
    - Join the net-to-QUIC link consumer and start the trace based on the event type specified in the arguments.
    - Leave the QUIC log after processing.
- **Output**: The function does not return a value; it performs operations to set up and execute a QUIC trace based on the provided configuration and arguments.
- **Functions called**:
    - [`dump_quic_config`](#dump_quic_config)
    - [`dump_connection`](#dump_connection)
    - [`fd_quic_trace_rx_tile`](fd_quic_trace_rx_tile.c.driver.md#fd_quic_trace_rx_tile)
    - [`fd_quic_trace_log_tile`](fd_quic_trace_log_tile.c.driver.md#fd_quic_trace_log_tile)


