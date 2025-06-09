# Purpose
This C header file, `fd_rpc_service.h`, defines the interface for an RPC (Remote Procedure Call) server within a larger software system. The file provides declarations for structures and functions that facilitate the creation and management of an RPC server context, as well as handling various RPC-related operations. The primary structure, `fd_rpcserver_args_t`, encapsulates configuration parameters necessary for initializing the RPC server, such as network settings, blockstore configurations, and other operational parameters. This structure is crucial for setting up the server environment and ensuring that all necessary resources and configurations are in place.

The file also declares several functions that manage the lifecycle and operations of the RPC server. These include [`fd_rpc_create_ctx`](#fd_rpc_create_ctx), which initializes the server context, and [`fd_rpc_start_service`](#fd_rpc_start_service), which starts the RPC service using the provided context. Additionally, the file includes functions for polling WebSocket connections and handling replay and stake operations during and after message fragments. The inclusion of various headers suggests that this file is part of a larger system involving networking, HTTP server management, and blockchain-related functionalities. Overall, this header file serves as a critical component for defining the public API of the RPC server, allowing other parts of the system to interact with and utilize its services.
# Imports and Dependencies

---
- `fd_block_to_json.h`
- `../replay/fd_replay_notif.h`
- `../../disco/topo/fd_topo.h`
- `../../disco/shred/fd_stake_ci.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../waltz/http/fd_http_server.h`
- `netinet/in.h`


# Data Structures

---
### fd\_rpc\_ctx\_t
- **Type**: `typedef struct fd_rpc_ctx fd_rpc_ctx_t;`
- **Description**: The `fd_rpc_ctx_t` is a forward declaration of a structure used in the context of RPC (Remote Procedure Call) services. It is likely used to encapsulate the state and data necessary for managing RPC operations, although the specific fields and their purposes are not defined in the provided code. The structure is utilized in various functions related to RPC service creation, management, and interaction, indicating its role as a central component in the RPC service framework.


---
### fd\_rpcserver\_args
- **Type**: `struct`
- **Members**:
    - `offline`: Indicates whether the server is offline.
    - `funk`: An array of fd_funk_t structures, presumably for handling specific functionalities.
    - `blockstore_ljoin`: A fd_blockstore_t structure for local blockstore joining.
    - `blockstore`: A pointer to a fd_blockstore_t structure for blockstore management.
    - `blockstore_fd`: File descriptor for the blockstore.
    - `stake_ci`: Pointer to a fd_stake_ci_t structure for stake consensus information.
    - `port`: Port number for the server to listen on.
    - `params`: HTTP server parameters encapsulated in fd_http_server_params_t.
    - `tpu_addr`: Socket address for TPU (Transaction Processing Unit) communication.
    - `block_index_max`: Maximum index for blocks.
    - `txn_index_max`: Maximum index for transactions.
    - `acct_index_max`: Maximum index for accounts.
    - `history_file`: Path to the history file, with a maximum length defined by PATH_MAX.
    - `spad`: Pointer to a fd_spad_t structure used as a bump allocator.
- **Description**: The `fd_rpcserver_args` structure is designed to encapsulate all necessary parameters and configurations required to initialize and run an RPC server. It includes fields for server state, blockstore management, network communication, and resource allocation. The structure supports both offline and online modes, manages blockstore connections, and configures HTTP server parameters. It also includes fields for managing maximum indices for blocks, transactions, and accounts, as well as a history file path for logging purposes. Additionally, it utilizes a bump allocator for efficient memory management.


---
### fd\_rpcserver\_args\_t
- **Type**: `struct`
- **Members**:
    - `offline`: An integer flag indicating whether the server is offline.
    - `funk`: An array of fd_funk_t, likely used for some functional operations.
    - `blockstore_ljoin`: An instance of fd_blockstore_t for local block storage joining.
    - `blockstore`: A pointer to fd_blockstore_t for accessing block storage.
    - `blockstore_fd`: An integer file descriptor for the blockstore.
    - `stake_ci`: A pointer to fd_stake_ci_t for stake consensus information.
    - `port`: A ushort representing the port number for the server.
    - `params`: An instance of fd_http_server_params_t for HTTP server parameters.
    - `tpu_addr`: A sockaddr_in structure for the TPU address.
    - `block_index_max`: An unsigned integer for the maximum block index.
    - `txn_index_max`: An unsigned integer for the maximum transaction index.
    - `acct_index_max`: An unsigned integer for the maximum account index.
    - `history_file`: A character array for the path to the history file.
    - `spad`: A pointer to fd_spad_t for a bump allocator.
- **Description**: The `fd_rpcserver_args_t` structure is designed to encapsulate all necessary parameters and configurations required to initialize and manage an RPC server within the system. It includes various fields for server configuration such as network settings, block storage, and stake consensus information. The structure also supports offline mode, HTTP server parameters, and maintains indices for blocks, transactions, and accounts. Additionally, it includes a bump allocator for memory management and a history file path for logging or state persistence.


# Function Declarations (Public API)

---
### fd\_rpc\_create\_ctx<!-- {{#callable_declaration:fd_rpc_create_ctx}} -->
Create and initialize an RPC context.
- **Description**: This function initializes an RPC context using the provided server arguments. It sets up necessary resources such as memory allocation, socket creation, and web server initialization. This function should be called before starting the RPC service to ensure that all required components are properly configured. The function handles both online and offline modes, adjusting its behavior accordingly. It is important to ensure that the `args` parameter is correctly populated with valid data before calling this function.
- **Inputs**:
    - `args`: A pointer to an `fd_rpcserver_args_t` structure containing configuration parameters for the RPC context. This includes network settings, storage configurations, and other operational parameters. The structure must be fully initialized and valid before calling this function.
    - `ctx_p`: A pointer to a pointer of type `fd_rpc_ctx_t`. This will be set to point to the newly created and initialized RPC context. The caller must ensure that `ctx_p` is not null.
- **Output**: None
- **See also**: [`fd_rpc_create_ctx`](fd_rpc_service.c.driver.md#fd_rpc_create_ctx)  (Implementation)


---
### fd\_rpc\_start\_service<!-- {{#callable_declaration:fd_rpc_start_service}} -->
Starts the RPC service with the specified arguments and context.
- **Description**: This function initializes and starts an RPC service using the provided server arguments and context. It must be called after the context has been created with `fd_rpc_create_ctx`. The function sets up the global context within the provided RPC context using the specified server arguments, preparing the service for operation. Ensure that the `args` and `ctx` parameters are properly initialized and valid before calling this function.
- **Inputs**:
    - `args`: A pointer to an `fd_rpcserver_args_t` structure containing the configuration and resources needed to start the RPC service. This includes function pointers, blockstore information, and other necessary parameters. The caller retains ownership and must ensure it remains valid for the duration of the service.
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure that represents the RPC context. This context must have been previously created and initialized using `fd_rpc_create_ctx`. The function modifies this context to set up the global context for the RPC service.
- **Output**: None
- **See also**: [`fd_rpc_start_service`](fd_rpc_service.c.driver.md#fd_rpc_start_service)  (Implementation)


---
### fd\_rpc\_ws\_poll<!-- {{#callable_declaration:fd_rpc_ws_poll}} -->
Polls the WebSocket connection for events.
- **Description**: Use this function to poll the WebSocket connection associated with the given RPC context for any incoming events or messages. This function is typically called within an event loop to continuously check for new data or events on the WebSocket. It is important to ensure that the context has been properly initialized and associated with a running WebSocket server before calling this function. The function returns an integer status code that indicates the result of the polling operation.
- **Inputs**:
    - `ctx`: A pointer to an fd_rpc_ctx_t structure representing the RPC context. This must be a valid, non-null pointer that has been initialized and associated with a WebSocket server. The caller retains ownership of the context.
- **Output**: Returns an integer status code indicating the result of the polling operation. The specific meaning of the return value should be checked against the documentation for fd_webserver_poll, which this function wraps.
- **See also**: [`fd_rpc_ws_poll`](fd_rpc_service.c.driver.md#fd_rpc_ws_poll)  (Implementation)


---
### fd\_rpc\_ws\_fd<!-- {{#callable_declaration:fd_rpc_ws_fd}} -->
Retrieve the file descriptor for the WebSocket associated with the RPC context.
- **Description**: Use this function to obtain the file descriptor for the WebSocket connection associated with a given RPC context. This is typically used when you need to perform operations directly on the WebSocket, such as monitoring it for events or integrating it with an event loop. Ensure that the RPC context has been properly initialized and is valid before calling this function. The function does not modify the context or any other state.
- **Inputs**:
    - `ctx`: A pointer to an fd_rpc_ctx_t structure representing the RPC context. Must not be null and should be properly initialized before use. The caller retains ownership of the context.
- **Output**: Returns the file descriptor associated with the WebSocket in the given RPC context. The return value is an integer representing the file descriptor.
- **See also**: [`fd_rpc_ws_fd`](fd_rpc_service.c.driver.md#fd_rpc_ws_fd)  (Implementation)


---
### fd\_rpc\_replay\_during\_frag<!-- {{#callable_declaration:fd_rpc_replay_during_frag}} -->
Copies a replay notification message into the provided state structure.
- **Description**: This function is used to update the state of a replay notification message during a fragment operation. It should be called when a new message needs to be processed and stored in the provided state structure. The function requires the size of the message to match the expected size of a `fd_replay_notif_msg_t` structure, ensuring that the message is correctly formatted before copying. This function does not modify the context or produce any side effects beyond updating the state.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure. This parameter is not used in the function and can be ignored.
    - `state`: A pointer to an `fd_replay_notif_msg_t` structure where the message will be copied. The caller must ensure this pointer is valid and points to sufficient memory to hold the message.
    - `msg`: A pointer to the message data to be copied. This must not be null and should point to a valid memory location containing a message of the correct size.
    - `sz`: An integer representing the size of the message. It must be equal to the size of an `fd_replay_notif_msg_t` structure. If the size does not match, the function will not perform the copy operation.
- **Output**: None
- **See also**: [`fd_rpc_replay_during_frag`](fd_rpc_service.c.driver.md#fd_rpc_replay_during_frag)  (Implementation)


---
### fd\_rpc\_replay\_after\_frag<!-- {{#callable_declaration:fd_rpc_replay_after_frag}} -->
Processes a replay notification message after a fragment is handled.
- **Description**: This function should be called after a fragment has been processed to handle replay notification messages. It updates performance samples and saves history based on the message type. The function also manages WebSocket subscriptions, sending updates to clients subscribed to slot or account notifications. It is important to ensure that the context and message provided are valid and properly initialized before calling this function.
- **Inputs**:
    - `ctx`: A pointer to an fd_rpc_ctx_t structure representing the RPC context. Must not be null and should be properly initialized before use.
    - `msg`: A pointer to an fd_replay_notif_msg_t structure containing the replay notification message. Must not be null and should be valid for the duration of the function call.
- **Output**: None
- **See also**: [`fd_rpc_replay_after_frag`](fd_rpc_service.c.driver.md#fd_rpc_replay_after_frag)  (Implementation)


---
### fd\_rpc\_stake\_during\_frag<!-- {{#callable_declaration:fd_rpc_stake_during_frag}} -->
Initialize stake message processing state.
- **Description**: This function is used to initialize the stake message processing state within a given context. It should be called when a new stake message needs to be processed during a fragment. The function prepares the state for further processing based on the provided message. It is expected to be used in environments where stake message handling is required, and it must be called with valid parameters to ensure correct operation.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure representing the RPC context. This parameter is not used in the function and can be ignored.
    - `state`: A pointer to an `fd_stake_ci_t` structure where the stake message processing state will be initialized. Must not be null.
    - `msg`: A pointer to a constant memory location containing the message to be processed. Must not be null.
    - `sz`: An integer representing the size of the message. This parameter is not used in the function and can be ignored.
- **Output**: None
- **See also**: [`fd_rpc_stake_during_frag`](fd_rpc_service.c.driver.md#fd_rpc_stake_during_frag)  (Implementation)


---
### fd\_rpc\_stake\_after\_frag<!-- {{#callable_declaration:fd_rpc_stake_after_frag}} -->
Finalize the stake message state after processing a fragment.
- **Description**: This function is used to finalize the state of a stake message after a fragment has been processed. It should be called once the processing of a fragment is complete to ensure that any resources associated with the stake message state are properly released or finalized. This function does not perform any operations on the `ctx` parameter, and its primary focus is on the `state` parameter. It is important to ensure that the `state` parameter is valid and properly initialized before calling this function.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure. This parameter is not used by the function, and can be ignored.
    - `state`: A pointer to an `fd_stake_ci_t` structure representing the stake message state to be finalized. Must be a valid, non-null pointer. The function will finalize the state, so it should not be used after this call unless re-initialized.
- **Output**: None
- **See also**: [`fd_rpc_stake_after_frag`](fd_rpc_service.c.driver.md#fd_rpc_stake_after_frag)  (Implementation)


