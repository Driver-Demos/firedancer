# Purpose
The provided C header file, `fd_restart.h`, is part of an implementation for Solana's SIMD-0046, known as the "wen-restart" protocol, which automates optimistic cluster restarts. This file defines the structures, constants, and function prototypes necessary for managing the state and operations of the wen-restart protocol. The primary structure, `fd_restart_t`, encapsulates all the state information required for the protocol, including stages of the restart process, stake weights, and fork slot information. The file also defines several constants that represent protocol parameters and implementation-specific limits, such as maximum peers and message sizes.

The header file provides a comprehensive API for interacting with the wen-restart state, including functions for initializing, joining, and managing the state. Functions like [`fd_restart_init`](#fd_restart_init), [`fd_restart_recv_gossip_msg`](#fd_restart_recv_gossip_msg), and [`fd_restart_verify_heaviest_fork`](#fd_restart_verify_heaviest_fork) facilitate the protocol's operations by handling initialization, message reception, and verification processes. Additionally, the file includes utility functions for memory alignment and footprint calculations, as well as bitmap conversion functions for encoding and decoding fork slot messages. This header is intended to be included in other C source files that implement the wen-restart protocol, providing a structured interface for managing the restart process in a Solana cluster.
# Imports and Dependencies

---
- `../../choreo/tower/fd_tower.h`
- `../../flamenco/types/fd_types.h`


# Global Variables

---
### fd\_restart\_new
- **Type**: `function pointer`
- **Description**: `fd_restart_new` is a function that formats an unused memory region for use as the state of the wen-restart protocol. It takes a non-NULL pointer to a memory region with the required footprint and alignment as its parameter.
- **Use**: This function is used to initialize a memory region to be used as the state for the wen-restart protocol.


---
### fd\_restart\_join
- **Type**: `fd_restart_t *`
- **Description**: The `fd_restart_join` function is a global function that returns a pointer to an `fd_restart_t` structure. This function is used to join the caller to the wen-restart state, which is a part of the Solana's optimistic cluster restart automation protocol.
- **Use**: This function is used to obtain a local pointer to the wen-restart state from a given memory region, allowing the caller to interact with the restart state.


# Data Structures

---
### fd\_wen\_restart\_stage\_t
- **Type**: `enum`
- **Members**:
    - `FD_RESTART_STAGE_WAIT_FOR_INIT`: Represents the initial stage where the system waits for initialization.
    - `FD_RESTART_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM`: Represents the stage where the system finds the heaviest fork slot number.
    - `FD_RESTART_STAGE_FIND_HEAVIEST_FORK_BANK_HASH`: Represents the stage where the system finds the heaviest fork bank hash.
    - `FD_RESTART_STAGE_GENERATE_SNAPSHOT`: Represents the stage where the system generates a snapshot.
    - `FD_RESTART_STAGE_DONE`: Represents the final stage indicating the restart process is complete.
- **Description**: The `fd_wen_restart_stage_t` is an enumeration that defines the various stages of the wen-restart process in the Solana protocol. Each enumerator represents a specific phase in the restart sequence, from initialization to completion, facilitating the management and tracking of the restart process within the system.


---
### fd\_restart
- **Type**: `struct`
- **Members**:
    - `stage`: Represents the current stage of the wen-restart process.
    - `funk_root`: The root slot number for the current restart process.
    - `root_epoch`: The epoch number at the root of the restart process.
    - `root_bank_hash`: The hash of the bank at the root of the restart process.
    - `epoch_schedule`: Pointer to the schedule of epochs used in the restart process.
    - `total_stake`: Array holding the total stake for each epoch.
    - `num_vote_accts`: Array holding the number of vote accounts for each epoch.
    - `stake_weights`: 2D array holding the stake weights for each epoch and peer.
    - `total_stake_received`: Array holding the total stake received for each epoch.
    - `total_stake_received_and_voted`: Array holding the total stake received and voted for each epoch.
    - `last_voted_fork_slots_received`: 2D array holding the last voted fork slots received for each epoch and peer.
    - `slot_to_stake`: Array mapping slots to stakes, indexed by an offset from funk_root.
    - `my_pubkey`: Public key of the current node.
    - `heaviest_fork_slot`: Slot number of the heaviest fork found.
    - `heaviest_fork_bank_hash`: Hash of the bank for the heaviest fork found.
    - `heaviest_fork_ready`: Flag indicating if the heaviest fork is ready.
    - `coordinator_pubkey`: Public key of the wen-restart coordinator.
    - `coordinator_heaviest_fork_slot`: Slot number of the heaviest fork as determined by the coordinator.
    - `coordinator_heaviest_fork_bank_hash`: Hash of the bank for the heaviest fork as determined by the coordinator.
    - `coordinator_heaviest_fork_ready`: Flag indicating if the coordinator's heaviest fork is ready.
- **Description**: The `fd_restart` structure is a comprehensive data structure used in the implementation of Solana's SIMD-0046, which automates optimistic cluster restarts, also known as wen-restart. It maintains various states and parameters necessary for the restart process, including the current stage, root information, epoch schedules, stake details, and fork information. The structure is designed to handle multiple epochs and peers, storing data such as total stakes, vote accounts, and fork slots. It also includes fields for managing the heaviest fork information both locally and from a coordinator, facilitating the synchronization and verification of the restart process across the network.


---
### fd\_restart\_t
- **Type**: `struct`
- **Members**:
    - `stage`: Represents the current stage of the wen-restart process.
    - `funk_root`: Stores the root slot number for the current fork.
    - `root_epoch`: Indicates the epoch number at the root slot.
    - `root_bank_hash`: Holds the hash of the bank at the root slot.
    - `epoch_schedule`: Points to the schedule of epochs used in the restart process.
    - `total_stake`: Array storing the total stake for each epoch.
    - `num_vote_accts`: Array storing the number of vote accounts for each epoch.
    - `stake_weights`: 2D array storing the stake weights for each peer in each epoch.
    - `total_stake_received`: Array storing the total stake received for each epoch.
    - `total_stake_received_and_voted`: Array storing the total stake received and voted for each epoch.
    - `last_voted_fork_slots_received`: 2D array tracking the last voted fork slots received from each peer for each epoch.
    - `slot_to_stake`: Array mapping slots to their corresponding stake values.
    - `my_pubkey`: Stores the public key of the current node.
    - `heaviest_fork_slot`: Indicates the slot number of the heaviest fork found.
    - `heaviest_fork_bank_hash`: Holds the hash of the bank at the heaviest fork slot.
    - `heaviest_fork_ready`: Flag indicating if the heaviest fork is ready.
    - `coordinator_pubkey`: Stores the public key of the wen-restart coordinator.
    - `coordinator_heaviest_fork_slot`: Indicates the slot number of the heaviest fork as determined by the coordinator.
    - `coordinator_heaviest_fork_bank_hash`: Holds the hash of the bank at the coordinator's heaviest fork slot.
    - `coordinator_heaviest_fork_ready`: Flag indicating if the coordinator's heaviest fork is ready.
- **Description**: The `fd_restart_t` structure is a comprehensive data structure used in the implementation of Solana's SIMD-0046 protocol, known as wen-restart, which automates optimistic cluster restarts. It maintains various states and parameters necessary for the protocol's operation, including the current stage of the restart process, root and heaviest fork information, epoch schedules, and stake-related data. The structure is designed to facilitate the coordination and verification of fork choices across the network, ensuring that the cluster can restart optimistically and efficiently.


# Functions

---
### fd\_restart\_align<!-- {{#callable:fd_restart_align}} -->
The `fd_restart_align` function returns the memory alignment requirement for the `fd_restart_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function calls `alignof` on the `fd_restart_t` type to determine its alignment requirement.
    - The result of the `alignof` operation is returned as the function's output.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_restart_t` structure.


---
### fd\_restart\_footprint<!-- {{#callable:fd_restart_footprint}} -->
The `fd_restart_footprint` function returns the size in bytes of the `fd_restart_t` structure, which represents the state of the wen-restart protocol.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests that the compiler should attempt to embed the function's code at the call site to reduce function call overhead.
    - The function is marked with `FD_FN_CONST`, indicating that it has no side effects and its return value depends only on its parameters (in this case, none), allowing for potential optimizations by the compiler.
    - The function simply returns the result of the `sizeof` operator applied to `fd_restart_t`, which calculates the memory footprint of the `fd_restart_t` structure.
- **Output**: The function returns an `ulong` representing the size in bytes of the `fd_restart_t` structure.


# Function Declarations (Public API)

---
### fd\_restart\_new<!-- {{#callable_declaration:fd_restart_new}} -->
Formats a memory region for use as wen-restart state.
- **Description**: This function prepares a given memory region to be used as the state for the wen-restart protocol, which is part of Solana's optimistic cluster restart automation. It should be called with a valid memory pointer that has the required alignment and footprint for the wen-restart state. The function will zero out the memory region, ensuring it is properly initialized for subsequent use. It is important to ensure that the memory is correctly aligned and non-null before calling this function, as misaligned or null pointers will result in a warning and a null return.
- **Inputs**:
    - `mem`: A pointer to the memory region to be formatted. It must not be null and must be aligned according to fd_restart_align(). If the pointer is null or misaligned, the function logs a warning and returns null.
- **Output**: Returns the pointer to the formatted memory region on success, or null if the input was invalid.
- **See also**: [`fd_restart_new`](fd_restart.c.driver.md#fd_restart_new)  (Implementation)


---
### fd\_restart\_join<!-- {{#callable_declaration:fd_restart_join}} -->
Joins the caller to the wen-restart state.
- **Description**: This function is used to join the caller to the wen-restart state by providing a pointer to the memory region that backs the wen-restart state. It is essential to ensure that the memory region is properly aligned and non-null before calling this function. This function is typically called after the memory region has been formatted for use as the wen-restart state using `fd_restart_new`. If the provided memory region is null or misaligned, the function will log a warning and return null.
- **Inputs**:
    - `restart`: A pointer to the first byte of the memory region backing the wen-restart state in the caller's address space. Must not be null and must be aligned according to `fd_restart_align()`. If these conditions are not met, the function logs a warning and returns null.
- **Output**: Returns a pointer to the wen-restart state in the local address space on success, or null if the input is invalid.
- **See also**: [`fd_restart_join`](fd_restart.c.driver.md#fd_restart_join)  (Implementation)


---
### fd\_restart\_init<!-- {{#callable_declaration:fd_restart_init}} -->
Initializes the wen-restart state with snapshot data and prepares the first gossip message.
- **Description**: This function is used to initialize the wen-restart state after a snapshot is loaded, setting up the initial conditions for the restart process. It prepares the first gossip message to be sent in the wen-restart protocol, which is crucial for the synchronization of the network. This function should be called in the replay tile after loading a snapshot, ensuring that all provided parameters are valid and correctly formatted. The function also logs important initialization details and checks for the presence of necessary vote account information for the epochs. It is essential that the memory pointed to by `out_buf` is large enough to hold the generated message, and `out_buf_len` will be updated to reflect the size of this message.
- **Inputs**:
    - `restart`: A pointer to an fd_restart_t structure that will be initialized. Must not be null.
    - `funk_root`: An unsigned long representing the root slot number for the restart. Must be a valid slot number.
    - `root_bank_hash`: A pointer to an fd_hash_t structure containing the hash of the root bank. Must not be null.
    - `epoch_stakes`: An array of pointers to fd_vote_accounts_t structures, representing the vote accounts for each epoch. Must contain valid data for the maximum number of epochs defined by FD_RESTART_EPOCHS_MAX.
    - `epoch_schedule`: A pointer to an fd_epoch_schedule_t structure that defines the epoch schedule. Must not be null.
    - `tower_checkpt_fileno`: An integer file descriptor for the tower checkpoint file. Must be valid and open for reading.
    - `slot_history`: A pointer to an fd_slot_history_t structure containing the slot history. Must not be null.
    - `my_pubkey`: A pointer to an fd_pubkey_t structure representing the public key of the current node. Must not be null.
    - `coordinator_pubkey`: A pointer to an fd_pubkey_t structure representing the public key of the coordinator node. Must not be null.
    - `out_buf`: A pointer to a buffer where the first gossip message will be written. Must be large enough to hold the message.
    - `out_buf_len`: A pointer to an unsigned long that will be updated with the length of the message written to out_buf. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime operations. Must not be null.
- **Output**: None
- **See also**: [`fd_restart_init`](fd_restart.c.driver.md#fd_restart_init)  (Implementation)


---
### fd\_restart\_recv\_gossip\_msg<!-- {{#callable_declaration:fd_restart_recv_gossip_msg}} -->
Processes a received gossip message for the wen-restart protocol.
- **Description**: This function is used to handle incoming gossip messages within the wen-restart protocol, which is part of Solana's optimistic cluster restart automation. It should be called whenever a gossip message is received. The function distinguishes between different types of messages based on a discriminant value and processes them accordingly. If the message is of type 'last_voted_fork_slots', it checks if messages have been received from more than 80% of the stake, potentially updating the restart stage and setting a flag. If the message is of type 'heaviest_fork', it records information if the message is from the coordinator. This function must be called with a valid restart state and appropriate message data.
- **Inputs**:
    - `restart`: A pointer to an fd_restart_t structure representing the current state of the wen-restart protocol. Must not be null.
    - `gossip_msg`: A pointer to the received gossip message. The message format is expected to be compatible with the wen-restart protocol. Must not be null.
    - `out_heaviest_fork_found`: A pointer to an unsigned long where the function may set a flag indicating if the heaviest fork has been found. Must not be null.
- **Output**: None
- **See also**: [`fd_restart_recv_gossip_msg`](fd_restart.c.driver.md#fd_restart_recv_gossip_msg)  (Implementation)


---
### fd\_restart\_find\_heaviest\_fork\_bank\_hash<!-- {{#callable_declaration:fd_restart_find_heaviest_fork_bank_hash}} -->
Determine if the funk root is the heaviest fork slot and update the bank hash accordingly.
- **Description**: This function checks if the current funk root is the heaviest fork slot in the wen-restart process. If the funk root is the heaviest fork slot, it copies the funk root bank hash into the heaviest fork bank hash field of the `fd_restart_t` structure and sets the `out_need_repair` flag to 0, indicating no repair is needed. If the funk root is not the heaviest fork slot, it sets `out_need_repair` to 1, signaling that a repair and replay process is required to obtain the correct bank hash. This function should be called during the FIND_HEAVIEST_FORK_BANK_HASH stage of the wen-restart protocol.
- **Inputs**:
    - `restart`: A pointer to an `fd_restart_t` structure representing the current state of the wen-restart process. Must not be null.
    - `funk`: A pointer to an `fd_funk_t` structure used to manage transactions. Must not be null.
    - `out_need_repair`: A pointer to an `ulong` where the function will store the result indicating whether a repair is needed (1) or not (0). Must not be null.
- **Output**: None
- **See also**: [`fd_restart_find_heaviest_fork_bank_hash`](fd_restart.c.driver.md#fd_restart_find_heaviest_fork_bank_hash)  (Implementation)


---
### fd\_restart\_verify\_heaviest\_fork<!-- {{#callable_declaration:fd_restart_verify_heaviest_fork}} -->
Verifies the heaviest fork in the wen-restart process.
- **Description**: This function is used during the wen-restart process to verify the heaviest fork by comparing local and coordinator fork information. It should be called repeatedly by the replay tile. The function is a no-op if the necessary fork information is not ready. When both local and coordinator fork information are available, it checks for mismatches and logs errors if discrepancies are found. If the caller is the wen-restart coordinator, it prepares a message to be sent out, indicating the heaviest fork verification is complete. This function must be called when the restart stage is FD_RESTART_STAGE_FIND_HEAVIEST_FORK_BANK_HASH.
- **Inputs**:
    - `restart`: A pointer to an fd_restart_t structure representing the current state of the wen-restart process. Must not be null.
    - `is_constipated`: A pointer to an unsigned long used to update the sequence number. Must not be null.
    - `hard_forks`: A pointer to an array of fd_slot_pair_t structures representing hard fork information. Must not be null if hard_forks_len is greater than zero.
    - `hard_forks_len`: The number of elements in the hard_forks array. Must be zero or greater.
    - `genesis_hash`: A pointer to an fd_hash_t structure representing the genesis hash. Must not be null.
    - `out_buf`: A pointer to a buffer where the function will write a message if the caller is the wen-restart coordinator. Must be large enough to hold the message.
    - `out_send`: A pointer to an unsigned long that will be set to 1 if a message is prepared to be sent, otherwise set to 0. Must not be null.
- **Output**: None
- **See also**: [`fd_restart_verify_heaviest_fork`](fd_restart.c.driver.md#fd_restart_verify_heaviest_fork)  (Implementation)


---
### fd\_restart\_convert\_runlength\_to\_raw\_bitmap<!-- {{#callable_declaration:fd_restart_convert_runlength_to_raw_bitmap}} -->
Converts a run-length encoded bitmap to a raw bitmap format.
- **Description**: This function is used to transform a bitmap from run-length encoding to a raw bitmap format, which is necessary before forwarding a gossip message to the replay tile. It ensures that the replay tile receives the bitmap in a raw format for processing. The function must be called with a valid message containing the run-length encoded bitmap, and it will populate the provided output buffer with the raw bitmap. Care should be taken to ensure that the output buffer is large enough to hold the maximum possible size of the raw bitmap, as defined by FD_RESTART_RAW_BITMAP_BYTES_MAX.
- **Inputs**:
    - `msg`: A pointer to a fd_gossip_restart_last_voted_fork_slots_t structure containing the run-length encoded bitmap. The structure must be properly initialized and contain valid data.
    - `out_bitmap`: A pointer to a uchar buffer where the raw bitmap will be stored. The buffer must be pre-allocated and have a size of at least FD_RESTART_RAW_BITMAP_BYTES_MAX bytes.
    - `out_bitmap_len`: A pointer to an ulong where the length of the raw bitmap will be stored. This will be set to the number of bytes used in the out_bitmap buffer.
- **Output**: None
- **See also**: [`fd_restart_convert_runlength_to_raw_bitmap`](fd_restart.c.driver.md#fd_restart_convert_runlength_to_raw_bitmap)  (Implementation)


---
### fd\_restart\_convert\_raw\_bitmap\_to\_runlength<!-- {{#callable_declaration:fd_restart_convert_raw_bitmap_to_runlength}} -->
Converts a raw bitmap to run-length encoding.
- **Description**: This function is used to transform a raw bitmap representation of fork slots into a run-length encoded format. It should be called when preparing to send a last_voted_fork_slots message in the gossip protocol. The function updates the provided message structure to reflect the new encoding format. Ensure that the input message contains a valid raw bitmap and that the output buffer is large enough to hold the encoded data.
- **Inputs**:
    - `msg`: A pointer to a fd_gossip_restart_last_voted_fork_slots_t structure containing the raw bitmap to be converted. The structure must be properly initialized and contain a valid raw bitmap.
    - `out_encoding`: A pointer to an fd_restart_run_length_encoding_inner_t buffer where the run-length encoded data will be stored. The buffer must be large enough to accommodate the encoded data.
- **Output**: None
- **See also**: [`fd_restart_convert_raw_bitmap_to_runlength`](fd_restart.c.driver.md#fd_restart_convert_raw_bitmap_to_runlength)  (Implementation)


---
### fd\_restart\_tower\_checkpt<!-- {{#callable_declaration:fd_restart_tower_checkpt}} -->
Checkpoints the latest sent tower into a file.
- **Description**: This function is used to save the current state of a tower vote to a specified file, ensuring that the state can be restored later if needed. It should be called every time a tower vote is sent, to maintain an up-to-date checkpoint. The function requires valid input parameters and a file descriptor that is open and writable. It handles errors by logging a warning if the checkpointing process fails.
- **Inputs**:
    - `vote_bank_hash`: A pointer to a constant fd_hash_t representing the hash of the vote bank. It must not be null and should point to a valid hash.
    - `tower`: A pointer to an fd_tower_t structure representing the tower to be checkpointed. It must not be null and should be properly initialized.
    - `ghost`: A pointer to an fd_ghost_t structure used to retrieve the vote slot history. It must not be null and should be properly initialized.
    - `root`: An unsigned long representing the root slot of the tower. It should be a valid slot number.
    - `tower_checkpt_fileno`: An integer file descriptor for the checkpoint file. It must be open and writable, and the function will seek to the beginning of the file before writing.
- **Output**: None
- **See also**: [`fd_restart_tower_checkpt`](fd_restart.c.driver.md#fd_restart_tower_checkpt)  (Implementation)


