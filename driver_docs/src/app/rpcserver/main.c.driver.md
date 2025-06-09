# Purpose
This C source code file is designed to initialize and run an RPC (Remote Procedure Call) server, which can operate in both online and offline modes. The code is structured to handle command-line arguments for configuration, including file paths for data storage and network settings. It sets up the necessary environment for the server to function, such as opening files, attaching to shared memory workspaces, and configuring network parameters. The file includes functionality for managing connections and handling signals to gracefully stop the server. It also integrates with external components like "sham links" for replay notifications and stake management, which are likely part of a larger system for handling distributed data or blockchain-related operations.

The code defines two main initialization functions, [`init_args`](#init_args) and [`init_args_offline`](#init_args_offline), which configure the server based on whether it is running in online or offline mode. It uses several external libraries and headers, indicating that it is part of a larger software ecosystem. The main function sets up signal handlers, initializes the RPC context, and starts the RPC service. It also includes a loop to poll for incoming messages and process them accordingly, using the "sham link" mechanisms to handle specific types of notifications. The file is not a standalone executable but rather a component that is likely part of a larger application, providing specific functionality related to RPC services and data synchronization.
# Imports and Dependencies

---
- `fcntl.h`
- `stdio.h`
- `stdlib.h`
- `signal.h`
- `errno.h`
- `unistd.h`
- `netdb.h`
- `sys/socket.h`
- `netinet/in.h`
- `arpa/inet.h`
- `../../discof/rpcserver/fd_rpc_service.h`
- `../../funk/fd_funk_filemap.h`
- `sham_link.h`


# Global Variables

---
### stopflag
- **Type**: `int`
- **Description**: The `stopflag` is a static integer variable initialized to 0, used as a flag to control the termination of a loop in the program.
- **Use**: It is set to 1 by the `signal1` function when a termination signal is received, causing the main loop to exit.


# Functions

---
### init\_args<!-- {{#callable:init_args}} -->
The `init_args` function initializes the `fd_rpcserver_args_t` structure by parsing command-line arguments and setting up various resources required for the RPC server.
- **Inputs**:
    - `argc`: A pointer to the integer representing the number of command-line arguments.
    - `argv`: A pointer to the array of command-line argument strings.
    - `args`: A pointer to the `fd_rpcserver_args_t` structure that will be initialized.
- **Control Flow**:
    - The function begins by zeroing out the `args` structure using `memset`.
    - It retrieves the `--funk-file` command-line argument and attempts to open the specified funk file; if unsuccessful, it logs an error and exits.
    - It retrieves the `--blockstore-file` command-line argument and attempts to open the specified blockstore file; if unsuccessful, it logs an error and exits.
    - It attaches to a workspace specified by the `--wksp-name-blockstore` argument, or defaults to `fd1_bstore.wksp`, and verifies the presence of a blockstore; if unsuccessful, it logs an error and exits.
    - It initializes a public key for the identity and joins a stake consensus interface using this key.
    - It sets the server port from the `--port` argument or defaults to 8899.
    - It configures various server parameters such as maximum connection counts, request lengths, and buffer sizes using command-line arguments or default values.
    - It sets up the TPU (Transaction Processing Unit) address using the `--local-tpu-host` and `--local-tpu-port` arguments, resolving the host if necessary, and validates the port number.
    - Finally, it logs the configuration details and completes the initialization.
- **Output**: The function does not return a value; it initializes the `args` structure with the parsed and configured settings.


---
### init\_args\_offline<!-- {{#callable:init_args_offline}} -->
The `init_args_offline` function initializes the `fd_rpcserver_args_t` structure for offline mode by setting up the necessary configurations and resources such as the funk database and blockstore workspace.
- **Inputs**:
    - `argc`: A pointer to an integer representing the number of command-line arguments.
    - `argv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `fd_rpcserver_args_t` structure where the function will store the initialized arguments and configurations.
- **Control Flow**:
    - The function starts by zeroing out the `args` structure and setting the `offline` flag to 1.
    - It retrieves the `--funk-file` command-line argument and checks if it is provided; if not, it logs an error and exits.
    - It attempts to recover a funk database checkpoint if the `--restore-funk` argument is provided; otherwise, it opens the funk file in read-only mode.
    - If the funk database cannot be joined, it logs an error and exits.
    - The function checks for the `--wksp-name-blockstore` argument to attach to an existing workspace; if not provided, it attempts to restore a blockstore from a checkpoint using `--restore-blockstore`.
    - If neither workspace name nor restore option is provided, it logs an error and exits.
    - It queries the workspace for a blockstore and joins it; if unsuccessful, it logs an error and exits.
    - The function sets various parameters in the `args` structure using command-line arguments, with default values if not specified.
- **Output**: The function does not return a value; it initializes the `args` structure with the necessary configurations for offline mode.


---
### signal1<!-- {{#callable:signal1}} -->
The `signal1` function sets a global stop flag when a signal is received.
- **Inputs**:
    - `sig`: An integer representing the signal number that triggered the handler.
- **Control Flow**:
    - The function takes an integer `sig` as an argument, which represents the signal number.
    - The function explicitly ignores the `sig` argument by casting it to void, indicating that it does not use this parameter.
    - The function sets the global variable `stopflag` to 1, which is likely used to signal other parts of the program to stop or terminate.
- **Output**: The function does not return any value.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs an RPC server, handling both online and offline modes, and manages signal handling and sham link notifications.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and parse command-line arguments using `fd_boot`.
    - Check if the program is running in offline mode by parsing the `--offline` command-line argument.
    - If not offline, initialize arguments using [`init_args`](#init_args) and create sham links for replay and stake notifications.
    - If offline, initialize arguments using [`init_args_offline`](#init_args_offline).
    - Allocate shared memory for the application and join it to the application's context.
    - Set up signal handlers for SIGTERM and SIGINT to gracefully handle termination signals.
    - Create and start the RPC context and service using `fd_rpc_create_ctx` and `fd_rpc_start_service`.
    - If in offline mode, continuously poll the RPC WebSocket context until a stop signal is received.
    - If not offline, start the sham links and continuously poll for replay and stake notifications, as well as the RPC WebSocket context, until a stop signal is received.
    - Upon receiving a stop signal, halt the application and return 0.
- **Output**: The function returns an integer status code, typically 0, indicating successful execution.
- **Functions called**:
    - [`init_args`](#init_args)
    - [`init_args_offline`](#init_args_offline)


---
### replay\_sham\_link\_during\_frag<!-- {{#callable:replay_sham_link_during_frag}} -->
The function `replay_sham_link_during_frag` calls another function to handle replay notifications during a fragment.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure representing the RPC context.
    - `state`: A pointer to an `fd_replay_notif_msg_t` structure representing the state of the replay notification message.
    - `msg`: A constant pointer to a message that is being processed.
    - `sz`: An integer representing the size of the message.
- **Control Flow**:
    - The function directly calls `fd_rpc_replay_during_frag` with the provided arguments `ctx`, `state`, `msg`, and `sz`.
- **Output**: This function does not return any value; it is a void function.


---
### replay\_sham\_link\_after\_frag<!-- {{#callable:replay_sham_link_after_frag}} -->
The function `replay_sham_link_after_frag` calls another function `fd_rpc_replay_after_frag` with the same arguments to handle post-fragmentation replay notifications.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure, representing the context for the RPC (Remote Procedure Call) operations.
    - `msg`: A pointer to an `fd_replay_notif_msg_t` structure, representing the message or state related to replay notifications.
- **Control Flow**:
    - The function directly calls `fd_rpc_replay_after_frag` with the provided `ctx` and `msg` arguments.
- **Output**: This function does not return any value; it is a `void` function.


---
### stake\_sham\_link\_during\_frag<!-- {{#callable:stake_sham_link_during_frag}} -->
The `stake_sham_link_during_frag` function is a wrapper that calls `fd_rpc_stake_during_frag` to process a message fragment related to staking within a given RPC context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure representing the RPC context.
    - `state`: A pointer to an `fd_stake_ci_t` structure representing the current state of the stake.
    - `msg`: A constant void pointer to the message data to be processed.
    - `sz`: An integer representing the size of the message data.
- **Control Flow**:
    - The function directly calls `fd_rpc_stake_during_frag` with the provided arguments `ctx`, `state`, `msg`, and `sz`.
- **Output**: This function does not return any value; it is a void function.


---
### stake\_sham\_link\_after\_frag<!-- {{#callable:stake_sham_link_after_frag}} -->
The `stake_sham_link_after_frag` function calls `fd_rpc_stake_after_frag` with the provided context and state to handle post-fragmentation operations for staking.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure representing the RPC context.
    - `state`: A pointer to an `fd_stake_ci_t` structure representing the staking state.
- **Control Flow**:
    - The function directly calls `fd_rpc_stake_after_frag` with the provided `ctx` and `state` arguments.
- **Output**: This function does not return any value; it is a void function.


