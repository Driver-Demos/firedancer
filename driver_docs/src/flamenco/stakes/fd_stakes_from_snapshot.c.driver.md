# Purpose
This C source code file is an executable program designed to process Solana blockchain snapshot files to derive and display epoch stake information. The program provides functionality to extract and print details about available epochs, active stakes per node identity, and leader schedules from a given snapshot file. It supports two types of snapshot files: `.tar.zst` compressed files and raw bincode snapshot manifests, although the implementation for handling `.tar.zst` files is marked as a TODO. The program is structured to handle command-line arguments, allowing users to specify the mode of operation (epochs, nodes, or leaders) and the file path to the snapshot. It also includes options for configuring memory usage and specifying the epoch number of interest.

The code is organized into several static functions that encapsulate specific tasks, such as parsing command-line arguments, reading and deserializing the snapshot file, and performing actions based on the selected mode. Key technical components include the use of custom data structures and functions from the `fd_flamenco` and related libraries to manage memory, decode snapshot data, and compute stake weights and leader schedules. The program uses a workspace and scratch memory allocator to efficiently manage memory during execution. The main function orchestrates the overall flow, from initialization and argument parsing to executing the desired action and cleaning up resources. The code is intended to be executed as a standalone program and does not define public APIs or external interfaces for use by other software components.
# Imports and Dependencies

---
- `../fd_flamenco.h`
- `../../ballet/base58/fd_base58.h`
- `../types/fd_types.h`
- `../leaders/fd_leaders.h`
- `../runtime/sysvar/fd_sysvar_epoch_schedule.h`
- `fd_stakes.h`
- `errno.h`
- `stdio.h`
- `stdlib.h`
- `sys/stat.h`


# Functions

---
### usage<!-- {{#callable:usage}} -->
The `usage` function prints the usage instructions for the `fd_stakes_from_snapshot` command to the standard error stream.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fprintf` to print a detailed usage message to `stderr`, which includes the command syntax, modes, file requirements, and options.
    - The function then returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### \_find\_epoch<!-- {{#callable:_find_epoch}} -->
The function `_find_epoch` retrieves the epoch stakes for a specified epoch from a given Solana manifest, logging an error and aborting if the epoch is not found or is invalid.
- **Inputs**:
    - `manifest`: A pointer to a `fd_solana_manifest_t` structure containing the bank's epoch stakes information.
    - `epoch`: An unsigned long integer representing the epoch number to search for.
- **Control Flow**:
    - Check if the `epoch` is equal to `ULONG_MAX`, indicating a missing epoch, and if so, print an error message, call `usage()`, and exit the program.
    - Initialize a pointer `stakes` to `NULL` and retrieve the array of epoch stakes from the manifest.
    - Iterate over the array of epoch stakes, comparing each key with the specified `epoch`.
    - If a match is found, set `stakes` to point to the corresponding value and break out of the loop.
    - After the loop, check if `stakes` is still `NULL`, indicating the epoch was not found, and log an error message.
    - Return the pointer `stakes` which points to the epoch stakes for the specified epoch.
- **Output**: A pointer to a `fd_epoch_stakes_t` structure containing the stakes for the specified epoch, or logs an error and aborts if the epoch is not found.
- **Functions called**:
    - [`usage`](#usage)


---
### \_get\_stake\_weights<!-- {{#callable:_get_stake_weights}} -->
The function `_get_stake_weights` retrieves and allocates memory for the stake weights of vote accounts for a given epoch from a Solana manifest.
- **Inputs**:
    - `manifest`: A pointer to a `fd_solana_manifest_t` structure containing the Solana manifest data.
    - `epoch`: An unsigned long integer representing the epoch number for which stake weights are to be retrieved.
    - `out_cnt`: A pointer to an unsigned long integer where the function will store the count of stake weights retrieved.
- **Control Flow**:
    - Call [`_find_epoch`](#_find_epoch) to retrieve the epoch stakes for the specified epoch from the manifest.
    - Access the vote accounts from the retrieved epoch stakes.
    - Calculate the number of vote accounts using `fd_vote_accounts_pair_t_map_size`.
    - Log the number of vote accounts found.
    - Allocate memory for the stake weights using `fd_scratch_alloc` based on the number of vote accounts.
    - Check if memory allocation failed and log an error if it did.
    - Call [`fd_stake_weights_by_node`](fd_stakes.c.driver.md#fd_stake_weights_by_node) to populate the allocated memory with stake weights and retrieve the count of weights.
    - Check if [`fd_stake_weights_by_node`](fd_stakes.c.driver.md#fd_stake_weights_by_node) failed and log an error if it did.
    - Store the count of stake weights in `out_cnt`.
    - Return the pointer to the allocated stake weights.
- **Output**: A pointer to an array of `fd_stake_weight_t` structures containing the stake weights for the specified epoch's vote accounts.
- **Functions called**:
    - [`_find_epoch`](#_find_epoch)
    - [`fd_stake_weights_by_node`](fd_stakes.c.driver.md#fd_stake_weights_by_node)


---
### action\_epochs<!-- {{#callable:action_epochs}} -->
The `action_epochs` function iterates over the epoch stakes in a Solana manifest and prints each epoch key.
- **Inputs**:
    - `manifest`: A pointer to a constant `fd_solana_manifest_t` structure containing the bank's epoch stakes information.
- **Control Flow**:
    - Retrieve the `epoch_stakes` array from the `manifest` structure.
    - Iterate over each element in the `epoch_stakes` array using a for loop.
    - Print the `key` of each `fd_epoch_epoch_stakes_pair_t` element in the array.
    - Return 0 to indicate successful completion.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### action\_nodes<!-- {{#callable:action_nodes}} -->
The `action_nodes` function retrieves and prints the active stake per node identity for a given epoch from a Solana manifest.
- **Inputs**:
    - `manifest`: A pointer to a `fd_solana_manifest_t` structure containing the Solana manifest data.
    - `epoch`: An unsigned long integer representing the epoch number for which the stake information is to be retrieved.
- **Control Flow**:
    - Call [`_get_stake_weights`](#_get_stake_weights) with the manifest and epoch to retrieve the stake weights and count.
    - Iterate over each stake weight entry using a loop from 0 to `weight_cnt`.
    - For each entry, encode the node's public key to Base58 format using `fd_base58_encode_32`.
    - Print the Base58 encoded public key and the corresponding stake value in CSV format.
- **Output**: Returns an integer value 0, indicating successful execution.
- **Functions called**:
    - [`_get_stake_weights`](#_get_stake_weights)


---
### action\_leaders<!-- {{#callable:action_leaders}} -->
The `action_leaders` function generates and prints the leader schedule for a given epoch based on stake weights from a Solana manifest.
- **Inputs**:
    - `manifest`: A pointer to a `fd_solana_manifest_t` structure containing the Solana manifest data, which includes epoch schedule and stake information.
    - `epoch`: An unsigned long integer representing the epoch number for which the leader schedule is to be generated.
- **Control Flow**:
    - Retrieve stake weights for the given epoch using [`_get_stake_weights`](#_get_stake_weights), which also returns the count of weights.
    - Extract the epoch schedule from the manifest and calculate the starting slot (`slot0`), total slot count (`slot_cnt`), and schedule count (`sched_cnt`) for the epoch.
    - Allocate memory for the leader schedule using `fd_scratch_alloc` and initialize it with `fd_epoch_leaders_new`.
    - Join the leader schedule memory to a `fd_epoch_leaders_t` structure using `fd_epoch_leaders_join`.
    - Iterate over each schedule count (`sched_cnt`) to retrieve the leader for each slot using `fd_epoch_leaders_get`.
    - Encode the leader's public key to Base58 format using `fd_base58_encode_32`.
    - Print the slot number and the Base58-encoded leader public key for each slot in the epoch.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`_get_stake_weights`](#_get_stake_weights)


---
### \_is\_zstd<!-- {{#callable:_is_zstd}} -->
The function `_is_zstd` checks if a given file handle points to the beginning of a Zstandard (zstd) compressed stream by reading and verifying the magic number.
- **Inputs**:
    - `file`: A pointer to a FILE object representing the file to be checked for a zstd stream.
- **Control Flow**:
    - Read the first 4 bytes from the file into a variable `magic`.
    - Check if the end of the file is reached using `feof`; if true, clear the error and reset the file position, then return 0.
    - Check for any file read errors using `ferror`; if an error is detected, log the error and exit.
    - Reset the file position by seeking back 4 bytes.
    - Return 1 if the read magic number matches the zstd magic number `0xFD2FB528UL`, otherwise return 0.
- **Output**: Returns 1 if the file starts with the zstd magic number, indicating a zstd stream; otherwise, returns 0.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, processes command-line arguments, reads a snapshot file, deserializes its manifest, and performs actions based on the specified mode (epochs, nodes, or leaders).
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` and `fd_flamenco_boot` functions.
    - Check for the `--help` argument and display usage information if present.
    - Parse command-line options for page size, page count, scratch memory size, and epoch number using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to an actual size using `fd_cstr_to_shmem_page_sz` and handle unsupported sizes with an error.
    - Verify that exactly three arguments are provided, otherwise display an error and usage information.
    - Determine the action to perform based on the mode argument (epochs, nodes, or leaders) and handle invalid modes with an error.
    - Create a workspace and allocate scratch memory using `fd_wksp_new_anonymous` and `fd_wksp_alloc_laddr`.
    - Open the specified file and check if it is a zstd stream or a raw bincode file, handling errors appropriately.
    - Read the file into a buffer and log the size of the manifest read.
    - Deserialize the manifest using `fd_bincode_decode_scratch` and handle decoding errors.
    - Perform the specified action (epochs, nodes, or leaders) by calling the corresponding function and passing the manifest and epoch.
    - Clean up resources by freeing allocated memory, closing the file, and halting the environment.
- **Output**: The function returns an integer result from the action performed, which is either 0 for success or an error code.
- **Functions called**:
    - [`usage`](#usage)
    - [`_is_zstd`](#_is_zstd)
    - [`action_leaders`](#action_leaders)
    - [`action_nodes`](#action_nodes)
    - [`action_epochs`](#action_epochs)


