# Purpose
The provided C source code file is part of a larger system, specifically designed to implement a repair protocol for a Firedancer node, which is likely a component of a distributed system or blockchain infrastructure. The file defines a structure and functions necessary for setting up and managing an RPC (Remote Procedure Call) server tile within this system. The primary functionality revolves around handling incoming notifications and stake information, processing these inputs, and managing the state of the node's repair operations. The code integrates with various components such as block storage, key management, and network communication, indicating its role in maintaining the integrity and synchronization of the node within the network.

Key technical components include the `fd_rpcserv_tile_ctx_t` structure, which holds the context for the RPC server, including network parameters, identity keys, and memory management for incoming data. The file also defines several static functions that manage the lifecycle of the RPC server, from initialization ([`privileged_init`](#privileged_init) and [`unprivileged_init`](#unprivileged_init)) to handling incoming data fragments ([`during_frag`](#during_frag) and [`after_frag`](#after_frag)). The code is structured to be part of a modular system, with clear interfaces for integration with other components, such as the use of `fd_topo_run_tile_t` to define the tile's operational parameters. This file is not a standalone executable but rather a component intended to be integrated into a larger application, providing specific functionality related to RPC services and node repair protocols.
# Imports and Dependencies

---
- `../../disco/topo/fd_topo.h`
- `sys/socket.h`
- `generated/fd_rpcserv_tile_seccomp.h`
- `../rpcserver/fd_rpc_service.h`
- `../../disco/tiles.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../flamenco/fd_flamenco.h`
- `../../util/fd_util.h`
- `../../disco/fd_disco.h`
- `../../disco/shred/fd_stake_ci.h`
- `../../util/pod/fd_pod_format.h`
- `../../funk/fd_funk_filemap.h`
- `../../disco/keyguard/fd_keyload.h`
- `errno.h`
- `fcntl.h`
- `unistd.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### RPCSERV\_HTTP\_PARAMS
- **Type**: `fd_http_server_params_t`
- **Description**: `RPCSERV_HTTP_PARAMS` is a constant global variable of type `fd_http_server_params_t` that defines the configuration parameters for an HTTP server. It specifies limits and sizes for various aspects of the server, such as the maximum number of connections, maximum request length, and buffer sizes.
- **Use**: This variable is used to configure the HTTP server parameters for the RPC service, ensuring it operates within defined limits and resource allocations.


---
### fd\_tile\_rpcserv
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_rpcserv` is a global variable of type `fd_topo_run_tile_t` that represents a configuration for running a tile in the Firedancer node topology. It is specifically configured for the 'rpcsrv' tile, which is responsible for handling RPC server operations within the node. The structure includes function pointers and parameters necessary for initializing, running, and managing the tile's lifecycle and resources.
- **Use**: This variable is used to define and manage the behavior and resources of the 'rpcsrv' tile in the Firedancer node topology.


# Data Structures

---
### fd\_rpcserv\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `args`: Holds the arguments for the RPC server configuration.
    - `funk_file`: Stores the file path for the funk file, with a maximum length defined by PATH_MAX.
    - `activated`: Indicates whether the context has been activated.
    - `ctx`: Pointer to the RPC context used for managing RPC operations.
    - `identity_key`: Array containing the public key for identity verification.
    - `replay_notif_in_mem`: Pointer to the workspace memory for replay notifications.
    - `replay_notif_in_chunk0`: Starting chunk index for replay notifications.
    - `replay_notif_in_wmark`: Watermark for replay notification chunks.
    - `replay_notif_in_state`: State of the replay notification message.
    - `stake_ci_in_mem`: Pointer to the workspace memory for stake CI input.
    - `stake_ci_in_chunk0`: Starting chunk index for stake CI input.
    - `stake_ci_in_wmark`: Watermark for stake CI input chunks.
    - `blockstore_fd`: File descriptor for the blockstore file.
- **Description**: The `fd_rpcserv_tile_ctx` structure is designed to manage the context for an RPC server tile within a Firedancer node. It encapsulates various components necessary for the operation of the RPC server, including configuration arguments, file paths, activation status, and pointers to memory workspaces for handling replay notifications and stake CI inputs. Additionally, it maintains a public key for identity verification and a file descriptor for accessing the blockstore. This structure is integral to the functioning of the repair protocol, facilitating communication and data management within the node.


---
### fd\_rpcserv\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `args`: Holds the arguments for the RPC server configuration.
    - `funk_file`: Stores the file path for the funk file.
    - `activated`: Indicates whether the context is activated.
    - `ctx`: Pointer to the RPC context.
    - `identity_key`: Contains the public key for identity verification.
    - `replay_notif_in_mem`: Pointer to the workspace memory for replay notifications.
    - `replay_notif_in_chunk0`: Initial chunk index for replay notifications.
    - `replay_notif_in_wmark`: Watermark for replay notification chunks.
    - `replay_notif_in_state`: State of the replay notification message.
    - `stake_ci_in_mem`: Pointer to the workspace memory for stake CI input.
    - `stake_ci_in_chunk0`: Initial chunk index for stake CI input.
    - `stake_ci_in_wmark`: Watermark for stake CI input chunks.
    - `blockstore_fd`: File descriptor for the blockstore.
- **Description**: The `fd_rpcserv_tile_ctx_t` structure is a context for managing the state and configuration of an RPC server tile in the Firedancer node repair protocol. It includes configuration arguments, file paths, activation status, and pointers to various memory workspaces and states necessary for handling replay notifications and stake CI inputs. The structure also manages the identity key for security purposes and maintains a file descriptor for accessing the blockstore.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests inlining for performance.
    - The function is marked with `FD_FN_CONST`, indicating it has no side effects and its return value depends only on its parameters, which in this case are none.
    - The function simply returns the constant value `128UL`.
- **Output**: The function returns an unsigned long integer with the value 128, representing a memory alignment requirement.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a scratch space in a Firedancer node's repair tile.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT`.
    - Append the alignment and size of `fd_rpcserv_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of the stake CI to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of the scratchpad with a maximum size defined by `FD_RPC_SCRATCH_MAX` to `l` using `FD_LAYOUT_APPEND`.
    - Finalize the layout with `FD_LAYOUT_FINI` using `scratch_align()` and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the scratch space.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function calculates and returns the memory footprint size for a tile using a gigantic page size.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is marked as unused in this function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is not used in the function body.
    - It returns a constant value calculated as `1UL * FD_SHMEM_GIGANTIC_PAGE_SZ`.
- **Output**: The function returns an `ulong` representing the memory footprint size, specifically the size of a gigantic shared memory page.


---
### before\_credit<!-- {{#callable:before_credit}} -->
The `before_credit` function checks if the context is activated and sets the `charge_busy` flag based on the result of a WebSocket poll.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpcserv_tile_ctx_t` structure representing the context of the RPC server tile.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which is not used in this function.
    - `charge_busy`: A pointer to an integer where the function will store the result of the WebSocket poll or set to 0 if the context is not activated.
- **Control Flow**:
    - The function begins by explicitly ignoring the `stem` parameter, indicating it is not used.
    - It checks if the `activated` field of the `ctx` structure is false using `FD_UNLIKELY`.
    - If `ctx->activated` is false, it sets `*charge_busy` to 0, indicating no charge is busy.
    - If `ctx->activated` is true, it calls `fd_rpc_ws_poll` with `ctx->ctx` and assigns the result to `*charge_busy`.
- **Output**: The function outputs an integer value through the `charge_busy` pointer, which indicates whether the WebSocket is busy or not based on the context's activation state.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes fragments based on their index, either handling replay notifications or stake consensus information, and logs errors if the chunk is out of expected range.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpcserv_tile_ctx_t` structure containing context information for the RPC server tile.
    - `in_idx`: An unsigned long integer indicating the index of the input, which determines the type of fragment being processed.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, marked as unused in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment, marked as unused in this function.
    - `chunk`: An unsigned long integer representing the chunk identifier of the fragment.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `ctl`: An unsigned long integer representing control information for the fragment, marked as unused in this function.
- **Control Flow**:
    - Check if `in_idx` is equal to `REPLAY_NOTIF_IDX` (0).
    - If true, verify if `chunk` is within the range defined by `ctx->replay_notif_in_chunk0` and `ctx->replay_notif_in_wmark`.
    - If `chunk` is out of range, log an error message indicating corruption.
    - If `chunk` is within range, call `fd_rpc_replay_during_frag` with the appropriate parameters to handle the replay notification fragment.
    - If `in_idx` is not `REPLAY_NOTIF_IDX`, check if it is equal to `STAKE_CI_IN_IDX` (1).
    - If true, verify if `chunk` is within the range defined by `ctx->stake_ci_in_chunk0` and `ctx->stake_ci_in_wmark`.
    - If `chunk` is out of range, log an error message indicating corruption.
    - If `chunk` is within range, call `fd_rpc_stake_during_frag` with the appropriate parameters to handle the stake consensus information fragment.
    - If `in_idx` is neither `REPLAY_NOTIF_IDX` nor `STAKE_CI_IN_IDX`, log an error message indicating an unknown index.
- **Output**: The function does not return a value; it performs operations based on the input index and logs errors if necessary.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes fragments based on their input index, activating the context and starting services if necessary, and handling replay notifications or stake confirmations.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpcserv_tile_ctx_t` structure representing the context for the RPC server tile.
    - `in_idx`: An unsigned long integer representing the input index, which determines the type of fragment being processed.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, which is unused in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment, which is unused in this function.
    - `sz`: An unsigned long integer representing the size of the fragment, which is unused in this function.
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment, which is unused in this function.
    - `tspub`: An unsigned long integer representing the publication timestamp of the fragment, which is unused in this function.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which is unused in this function.
- **Control Flow**:
    - The function begins by checking if the `in_idx` is equal to `REPLAY_NOTIF_IDX` (likely scenario).
    - If the context (`ctx`) is not activated, it attempts to open a funk file and start the RPC service, setting `ctx->activated` to 1 upon success.
    - If the funk file cannot be opened, an error is logged.
    - After activation, it calls `fd_rpc_replay_after_frag` to handle replay notifications.
    - If `in_idx` is equal to `STAKE_CI_IN_IDX`, it calls `fd_rpc_stake_after_frag` to handle stake confirmations.
    - If `in_idx` is neither `REPLAY_NOTIF_IDX` nor `STAKE_CI_IN_IDX`, an error is logged indicating an unknown input index.
- **Output**: The function does not return a value; it performs actions based on the input index and modifies the context state as needed.


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes and configures the resources and context needed for a privileged RPC server tile in a Firedancer node.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the Firedancer node.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration within the topology.
- **Control Flow**:
    - Allocate scratch memory for the tile context, stake CI memory, and SPAD memory using `FD_SCRATCH_ALLOC_INIT` and `FD_SCRATCH_ALLOC_APPEND` macros.
    - Check if the `identity_key_path` is set; if not, log an error and exit.
    - Load the identity key from the specified path and store it in the context.
    - Initialize the `fd_rpcserver_args_t` structure with default values and parameters from the tile configuration.
    - Set up the TPU address and port using the tile's RPC server configuration.
    - Join the stake CI and SPAD memory regions using `fd_stake_ci_join` and `fd_spad_join`.
    - Copy the funk file path from the tile configuration to the context.
    - Query the blockstore object ID from the topology properties and join the blockstore using `fd_blockstore_join`.
    - Open the blockstore file specified in the tile configuration and log a warning if it fails.
    - Set various index maximums and history file path in the RPC server arguments from the tile configuration.
    - Push the SPAD memory to the stack and create the RPC context using `fd_rpc_create_ctx`.
- **Output**: The function does not return a value; it initializes the context and resources for the RPC server tile.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the unprivileged context for a repair tile in a Firedancer node, setting up memory and validating input links.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the Firedancer node.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to be initialized.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Check if the tile has exactly two input links named 'replay_notif' and 'stake_out'; log an error if not.
    - Check if the tile has no output links; log an error if there are any.
    - Initialize scratch memory using `FD_SCRATCH_ALLOC_INIT` and allocate memory for `fd_rpcserv_tile_ctx_t`, `fd_stake_ci`, and `fd_spad` structures.
    - Finalize the scratch memory allocation and check for overflow; log an error if overflow occurs.
    - Set the `activated` field of the context to 0, indicating it is not yet activated.
    - Retrieve and store memory workspace and cache details for the 'replay_notif' and 'stake_ci' input links in the context.
- **Output**: The function does not return a value; it initializes the context and memory for the tile.
- **Functions called**:
    - [`scratch_align`](#scratch_align)
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function initializes a scratch memory context and populates a seccomp filter policy for a given tile in a topology.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile within the topology.
    - `out_cnt`: An unsigned long integer representing the count of output seccomp filter instructions.
    - `out`: A pointer to an array of `struct sock_filter` where the seccomp filter policy will be populated.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Initialize the scratch memory allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_rpcserv_tile_ctx_t` context using `FD_SCRATCH_ALLOC_APPEND`.
    - Call [`populate_sock_filter_policy_fd_rpcserv_tile`](generated/fd_rpcserv_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_rpcserv_tile) to populate the seccomp filter policy using the provided `out_cnt`, `out`, and file descriptors obtained from the context.
    - Return the instruction count from `sock_filter_policy_fd_rpcserv_tile_instr_cnt`.
- **Output**: Returns an unsigned long integer representing the number of seccomp filter instructions populated.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_rpcserv_tile`](generated/fd_rpcserv_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_rpcserv_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for a specific tile in a topology.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile within the topology.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Initialize a scratch memory area using `fd_topo_obj_laddr` and `FD_SCRATCH_ALLOC_INIT` to allocate a `fd_rpcserv_tile_ctx_t` context structure.
    - Check if `out_fds_cnt` is less than 3, and if so, log an error using `FD_LOG_ERR`.
    - Initialize `out_cnt` to 0 and set the first element of `out_fds` to 2, representing the standard error file descriptor.
    - Check if the log file descriptor is valid using `fd_log_private_logfile_fd`, and if so, add it to `out_fds`.
    - Add the WebSocket file descriptor from `ctx->ctx` to `out_fds`.
    - Add the blockstore file descriptor from `ctx->blockstore_fd` to `out_fds`.
    - Return the count of file descriptors added to `out_fds`.
- **Output**: Returns the number of file descriptors added to the `out_fds` array as an unsigned long integer.


