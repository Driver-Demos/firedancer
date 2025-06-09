# Purpose
The provided C source code file is designed to facilitate the dumping of various execution contexts and states into Protocol Buffers (protobuf) format for further analysis or storage. This file is part of a larger system that appears to be involved in processing and managing transactions, accounts, and blocks, likely within a blockchain or distributed ledger context. The code includes functions to serialize different types of data structures, such as transaction contexts, block contexts, and instruction contexts, into protobuf messages. These messages are then written to binary files, which can be used for debugging, auditing, or other purposes.

The file includes a variety of utility functions and macros to handle tasks such as sorting features, managing account states, and processing transactions. It also defines several public APIs that are responsible for creating protobuf messages from the current state of the system and writing them to files. The code makes extensive use of memory management and serialization techniques, leveraging libraries like nanopb for protobuf encoding. The inclusion of headers and the structure of the functions suggest that this file is part of a larger application, possibly a blockchain node or a transaction processing system, where it plays a critical role in capturing and exporting the state of the system for external analysis.
# Imports and Dependencies

---
- `fd_dump_pb.h`
- `harness/generated/block.pb.h`
- `harness/generated/invoke.pb.h`
- `harness/generated/vm.pb.h`
- `../fd_system_ids.h`
- `../fd_runtime.h`
- `../program/fd_address_lookup_table_program.h`
- `../../../ballet/lthash/fd_lthash.h`
- `../../../ballet/nanopb/pb_encode.h`
- `errno.h`
- `stdio.h`
- `sys/mman.h`
- `unistd.h`
- `../../../util/tmpl/fd_sort.c`


# Functions

---
### dump\_sorted\_features<!-- {{#callable:dump_sorted_features}} -->
The `dump_sorted_features` function extracts enabled features from a given feature set, sorts them, and stores the sorted list in an output feature set.
- **Inputs**:
    - `features`: A pointer to a constant `fd_features_t` structure containing the feature set to be processed.
    - `output_feature_set`: A pointer to an `fd_exec_test_feature_set_t` structure where the sorted features will be stored.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the function's execution.
- **Control Flow**:
    - Allocate memory for storing unsorted features using `fd_spad_alloc` with alignment and size based on `uint64_t` and `FD_FEATURE_ID_CNT`.
    - Initialize a feature iterator using `fd_feature_iter_init` and iterate over all features using a loop until `fd_feature_iter_done` returns true.
    - For each feature, check if it is not disabled by comparing against `FD_FEATURE_DISABLED`; if enabled, add its ID to the `unsorted_features` array.
    - Allocate scratch memory for sorting using `fd_spad_alloc` with alignment and footprint determined by the number of features.
    - Sort the `unsorted_features` array using `sort_uint64_t_stable_fast`, storing the result in `sorted_features`.
    - Set the `features_count` and `features` fields of `output_feature_set` to the number of features and the sorted features array, respectively.
- **Output**: The function does not return a value but modifies the `output_feature_set` to contain the sorted list of enabled feature IDs.


---
### dump\_account\_state<!-- {{#callable:dump_account_state}} -->
The `dump_account_state` function extracts and copies the state of a transaction account into an output account structure, including address, lamports, data, executable status, rent epoch, and owner information.
- **Inputs**:
    - `txn_account`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account whose state is to be dumped.
    - `output_account`: A pointer to an `fd_exec_test_acct_state_t` structure where the extracted account state will be stored.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the dumping process.
- **Control Flow**:
    - Copy the public key from `txn_account` to `output_account->address` using `fd_memcpy`.
    - Retrieve the lamports from `txn_account` using `get_lamports` and store it in `output_account->lamports`.
    - Allocate memory for `output_account->data` using `fd_spad_alloc` and set its size using `get_data_len`.
    - Copy the data from `txn_account` to `output_account->data->bytes` using `fd_memcpy`.
    - Determine if the account is executable using `is_executable` and store the result in `output_account->executable`.
    - Retrieve the rent epoch using `get_rent_epoch` and store it in `output_account->rent_epoch`.
    - Copy the owner public key from `txn_account` to `output_account->owner` using `fd_memcpy`.
    - Set `output_account->has_seed_addr` to `false` as the seed address is not present.
- **Output**: The function does not return a value; it modifies the `output_account` structure to reflect the state of the `txn_account`.


---
### account\_already\_dumped<!-- {{#callable:account_already_dumped}} -->
The function `account_already_dumped` checks if a given account key is already present in a list of dumped accounts.
- **Inputs**:
    - `dumped_accounts`: A pointer to an array of `fd_exec_test_acct_state_t` structures representing the accounts that have already been dumped.
    - `dumped_cnt`: An unsigned long integer representing the number of accounts in the `dumped_accounts` array.
    - `account_key`: A pointer to an `fd_pubkey_t` structure representing the public key of the account to check against the dumped accounts.
- **Control Flow**:
    - Iterate over each account in the `dumped_accounts` array up to `dumped_cnt`.
    - For each account, compare the `account_key` with the `address` field of the current account using `memcmp`.
    - If a match is found, return 1 indicating the account is already dumped.
    - If no match is found after checking all accounts, return 0.
- **Output**: The function returns an `uchar` value: 1 if the account is already dumped, and 0 if it is not.


---
### dump\_account\_if\_not\_already\_dumped<!-- {{#callable:dump_account_if_not_already_dumped}} -->
The function `dump_account_if_not_already_dumped` checks if an account has already been dumped, and if not, it dumps the account state and optionally returns a borrowed account.
- **Inputs**:
    - `slot_ctx`: A pointer to a constant `fd_exec_slot_ctx_t` structure representing the execution slot context.
    - `account_key`: A pointer to a constant `fd_pubkey_t` structure representing the public key of the account to be checked and potentially dumped.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the dumping process.
    - `out_acct_states`: A pointer to an array of `fd_exec_test_acct_state_t` structures where the dumped account states are stored.
    - `out_acct_states_cnt`: A pointer to a `pb_size_t` variable that keeps track of the number of account states dumped so far.
    - `opt_out_borrowed_account`: An optional pointer to an `fd_txn_account_t` structure where the borrowed account information is stored if provided.
- **Control Flow**:
    - Declare a transaction account using `FD_TXN_ACCOUNT_DECL` macro.
    - Initialize the transaction account from a read-only funk using `fd_txn_account_init_from_funk_readonly`.
    - If the account initialization fails, return 1 indicating the account does not exist.
    - Check if the account has already been dumped using [`account_already_dumped`](#account_already_dumped).
    - If the account has not been dumped, call [`dump_account_state`](#dump_account_state) to dump the account state and increment the account states count.
    - If `opt_out_borrowed_account` is provided, copy the account information to it.
    - Return 0 indicating the account exists and has been processed.
- **Output**: The function returns an `uchar` value: 0 if the account exists and has been processed, or 1 if the account does not exist.
- **Functions called**:
    - [`account_already_dumped`](#account_already_dumped)
    - [`dump_account_state`](#dump_account_state)


---
### dump\_lut\_account\_and\_contained\_accounts<!-- {{#callable:dump_lut_account_and_contained_accounts}} -->
The function `dump_lut_account_and_contained_accounts` dumps the state of a lookup table account and all accounts it references if they haven't been dumped already.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `txn_payload`: A pointer to the transaction payload, which contains the raw data of the transaction.
    - `lookup_table`: A pointer to the lookup table structure that provides offsets for accessing account addresses within the transaction payload.
    - `spad`: A pointer to a scratchpad memory area used for temporary allocations during execution.
    - `out_account_states`: A pointer to an array where the dumped account states will be stored.
    - `out_account_states_count`: A pointer to a variable that keeps track of the number of account states that have been dumped.
- **Control Flow**:
    - Declare a transaction account for the lookup table account (ALUT).
    - Retrieve the public key of the ALUT account from the transaction payload using the offset provided by the lookup table.
    - Call [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped) to dump the ALUT account if it hasn't been dumped yet, and check if the account exists and has sufficient data length.
    - If the account doesn't exist or its data length is less than the required metadata size, return early.
    - Check if the data length of the ALUT account is aligned to 32 bytes; if not, return early.
    - Calculate the number of referenced accounts by subtracting the metadata size from the data length and dividing by 32.
    - Iterate over each referenced account and call [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped) to dump them if they haven't been dumped already.
- **Output**: The function does not return a value; it modifies the `out_account_states` and `out_account_states_count` to include the dumped account states.
- **Functions called**:
    - [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped)


---
### dump\_executable\_account\_if\_exists<!-- {{#callable:dump_executable_account_if_exists}} -->
The function `dump_executable_account_if_exists` checks if a given program account is an executable account and, if so, dumps its associated program data account if it hasn't been dumped already.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which provides context for the current execution slot.
    - `program_account`: A pointer to the program account state, which contains information about the account being checked.
    - `spad`: A pointer to a scratchpad memory area used for temporary allocations during execution.
    - `out_account_states`: A pointer to an array where the dumped account states will be stored.
    - `out_account_states_count`: A pointer to a variable that keeps track of the number of account states dumped.
- **Control Flow**:
    - The function first checks if the owner of the `program_account` matches the expected BPF loader program ID; if not, it returns immediately.
    - It decodes the program account's data into a `fd_bpf_upgradeable_loader_state_t` structure using `fd_bincode_decode_spad` and checks for errors; if an error occurs, it returns.
    - It verifies if the decoded state represents a program using `fd_bpf_upgradeable_loader_state_is_program`; if not, it returns.
    - If the account is a program, it retrieves the program data account's address from the loader state and calls [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped) to dump the program data account if it hasn't been dumped yet.
- **Output**: The function does not return a value; it modifies the `out_account_states` and `out_account_states_count` to include the dumped account state if applicable.
- **Functions called**:
    - [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped)


---
### dump\_vote\_accounts<!-- {{#callable:dump_vote_accounts}} -->
The `dump_vote_accounts` function extracts and serializes vote account information from a given set of vote accounts into a specified memory space, while also ensuring that account states are dumped if not already done.
- **Inputs**:
    - `slot_ctx`: A pointer to a constant `fd_exec_slot_ctx_t` structure representing the execution slot context.
    - `vote_accounts`: A pointer to a constant `fd_vote_accounts_t` structure containing the vote accounts to be processed.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation.
    - `out_vote_accounts`: A pointer to a pointer of `fd_exec_test_vote_account_t` where the function will store the allocated and filled vote account structures.
    - `out_vote_accounts_count`: A pointer to a `pb_size_t` where the function will store the count of vote accounts processed.
    - `out_acct_states`: A pointer to an `fd_exec_test_acct_state_t` array where account states will be stored if they are not already dumped.
    - `out_acct_states_cnt`: A pointer to a `pb_size_t` that keeps track of the number of account states dumped.
- **Control Flow**:
    - Initialize an index `idx` to 0 and determine the number of vote accounts using `fd_vote_accounts_pair_t_map_size`.
    - Allocate memory for `vote_account_out` using `fd_spad_alloc` based on the number of vote accounts.
    - Iterate over each vote account using `fd_vote_accounts_pair_t_map_minimum_const` and `fd_vote_accounts_pair_t_map_successor_const`.
    - For each vote account, populate a `fd_exec_test_vote_account_t` structure with details such as stake, lamports, rent epoch, executable status, and owner.
    - Copy the address and owner information using `fd_memcpy`.
    - Allocate and copy the account data using `fd_spad_alloc` and `fd_memcpy`.
    - Call [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped) to ensure the account state is dumped if not already done.
    - Update `out_vote_accounts` and `out_vote_accounts_count` with the processed vote accounts and their count.
- **Output**: The function outputs the processed vote accounts in `out_vote_accounts` and the count of these accounts in `out_vote_accounts_count`. It also updates `out_acct_states` and `out_acct_states_cnt` with any new account states that were dumped.
- **Functions called**:
    - [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped)


---
### dump\_sanitized\_transaction<!-- {{#callable:dump_sanitized_transaction}} -->
The `dump_sanitized_transaction` function processes a transaction descriptor and payload to populate a sanitized transaction structure with detailed transaction information, including message headers, account keys, recent blockhash, instructions, and address table lookups.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure, representing the transaction context.
    - `funk_txn`: A constant pointer to an `fd_funk_txn_t` structure, representing the specific transaction within the context.
    - `txn_descriptor`: A constant pointer to an `fd_txn_t` structure, describing the transaction details such as version, signatures, and instructions.
    - `txn_payload`: A constant pointer to an unsigned character array, containing the transaction payload data.
    - `spad`: A pointer to an `fd_spad_t` structure, used for memory allocation during the transaction processing.
    - `sanitized_transaction`: A pointer to an `fd_exec_test_sanitized_transaction_t` structure, where the sanitized transaction data will be stored.
- **Control Flow**:
    - Retrieve address lookup tables from the transaction descriptor.
    - Set the `has_message` flag to true in the sanitized transaction and initialize the message structure.
    - Determine if the transaction is legacy by checking the transaction version and set the `is_legacy` flag accordingly.
    - Populate the message header with the number of required signatures, readonly signed accounts, and readonly unsigned accounts from the transaction descriptor.
    - Allocate memory for account keys and copy them from the transaction payload to the sanitized transaction structure.
    - Retrieve and copy the recent blockhash from the transaction payload into the sanitized transaction structure.
    - Allocate memory for instructions and iterate over each instruction in the transaction descriptor to populate the compiled instructions in the sanitized transaction.
    - If the transaction is not legacy, allocate memory for address table lookups and populate them with account keys, writable indexes, and readonly indexes from the transaction payload.
    - Allocate memory for signatures and copy them from the transaction payload into the sanitized transaction structure.
- **Output**: The function does not return a value; it populates the `sanitized_transaction` structure with the processed transaction data.


---
### dump\_blockhash\_queue<!-- {{#callable:dump_blockhash_queue}} -->
The `dump_blockhash_queue` function iterates over a block hash queue, stores each block hash in a Protobuf-compatible format, and adjusts the output queue to ensure the oldest blockhash is first.
- **Inputs**:
    - `queue`: A pointer to a `fd_block_hash_queue_t` structure representing the block hash queue to be dumped.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation.
    - `output_blockhash_queue`: A pointer to an array of `pb_bytes_array_t` pointers where the block hashes will be stored.
    - `output_blockhash_queue_count`: A pointer to a `pb_size_t` variable where the count of block hashes stored in the output queue will be set.
- **Control Flow**:
    - Initialize a counter `cnt` to zero and a pointer `nn` for iterating over the queue.
    - Iterate over the block hashes in the queue using `fd_hash_hash_age_pair_t_map_minimum` and `fd_hash_hash_age_pair_t_map_successor` to traverse the map nodes.
    - For each block hash, calculate its index in the queue using `queue->last_hash_index - n->elem.val.hash_index`.
    - Allocate memory for a `pb_bytes_array_t` structure using `fd_spad_alloc`, set its size, and copy the block hash into it.
    - Store the allocated `pb_bytes_array_t` in the `output_blockhash_queue` at the position `FD_BLOCKHASH_QUEUE_MAX_ENTRIES - queue_index`.
    - Increment the counter `cnt`.
    - If the number of elements `cnt` is less than `FD_BLOCKHASH_QUEUE_MAX_ENTRIES + 1`, shift the elements in `output_blockhash_queue` to the left by `index_offset` to ensure the oldest blockhash is first.
    - Set `*output_blockhash_queue_count` to `cnt`.
- **Output**: The function outputs the block hashes in the `output_blockhash_queue` array and sets the count of these hashes in `output_blockhash_queue_count`.


---
### create\_block\_context\_protobuf\_from\_block<!-- {{#callable:create_block_context_protobuf_from_block}} -->
The function `create_block_context_protobuf_from_block` initializes a block context protobuf structure from a given block by dumping relevant account states, blockhash queue, slot context, and epoch context.
- **Inputs**:
    - `block_context`: A pointer to an `fd_exec_test_block_context_t` structure where the block context protobuf will be stored.
    - `slot_ctx`: A constant pointer to an `fd_exec_slot_ctx_t` structure containing the slot context information for the block.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the function execution.
- **Control Flow**:
    - Retrieve the epoch context from the slot context.
    - Calculate the number of sysvar entries and loaded builtins.
    - Determine the number of new and existing stake and vote accounts.
    - Calculate the total number of accounts to be dumped.
    - Allocate memory for account states in the block context using `fd_spad_alloc`.
    - Dump sysvar and builtin accounts using [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped).
    - Allocate memory for the blockhash queue and dump it using [`dump_blockhash_queue`](#dump_blockhash_queue).
    - Set slot context fields in the block context, including slot, block height, and previous slot information.
    - Set epoch context fields in the block context, including features, inflation, and genesis creation time.
    - Dump existing and new stake accounts for the current epoch.
    - Dump existing and new vote accounts for the current epoch.
    - Dump vote accounts for epochs T-1 and T-2 using [`dump_vote_accounts`](#dump_vote_accounts).
- **Output**: The function does not return a value; it modifies the `block_context` structure in place to contain the dumped block context information.
- **Functions called**:
    - [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped)
    - [`dump_blockhash_queue`](#dump_blockhash_queue)
    - [`dump_sorted_features`](#dump_sorted_features)
    - [`dump_vote_accounts`](#dump_vote_accounts)


---
### create\_block\_context\_protobuf\_from\_block\_tx\_only<!-- {{#callable:create_block_context_protobuf_from_block_tx_only}} -->
The function `create_block_context_protobuf_from_block_tx_only` initializes and populates a block context structure with transaction-only data from a given block and slot context, allocating necessary memory and processing transactions to update account states and microblocks.
- **Inputs**:
    - `block_context`: A pointer to an `fd_exec_test_block_context_t` structure that will be populated with block context data.
    - `block_info`: A constant pointer to an `fd_runtime_block_info_t` structure containing information about the block, such as microblock and transaction counts.
    - `slot_ctx`: A constant pointer to an `fd_exec_slot_ctx_t` structure providing context about the current slot, including POH and other slot-specific data.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the function's execution.
- **Control Flow**:
    - Initialize the microblocks count in the block context to zero and allocate memory for microblocks based on the block information.
    - Clear the allocated memory for microblocks using `fd_memset`.
    - Allocate additional memory for account states in the block context, preserving existing account states.
    - Copy the POH from the slot context to the block context's slot context.
    - Iterate over each microblock batch in the block information.
    - For each microblock in a batch, check if it contains transactions; if not, skip it.
    - For each transaction in a microblock, allocate memory for sanitized transactions and initialize it.
    - Dump the sanitized transaction data into the allocated memory.
    - For each transaction, dump account keys, ALUT accounts, referenced accounts, and executable accounts into the account states of the block context.
- **Output**: The function does not return a value; it modifies the `block_context` structure in place, populating it with transaction-related data and updating account states and microblocks.
- **Functions called**:
    - [`dump_sanitized_transaction`](#dump_sanitized_transaction)
    - [`dump_account_if_not_already_dumped`](#dump_account_if_not_already_dumped)
    - [`dump_lut_account_and_contained_accounts`](#dump_lut_account_and_contained_accounts)
    - [`dump_executable_account_if_exists`](#dump_executable_account_if_exists)


---
### create\_txn\_context\_protobuf\_from\_txn<!-- {{#callable:create_txn_context_protobuf_from_txn}} -->
The function `create_txn_context_protobuf_from_txn` constructs a protobuf message representing the transaction context from a given transaction context and shared data.
- **Inputs**:
    - `txn_context_msg`: A pointer to an `fd_exec_test_txn_context_t` structure where the protobuf message will be stored.
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure representing the transaction context to be converted into a protobuf message.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the conversion process.
- **Control Flow**:
    - Initialize pointers to the transaction descriptor and payload from the transaction context.
    - Define arrays of built-in program IDs and relevant sysvar IDs, and calculate their sizes.
    - Allocate memory for account shared data in the protobuf message, considering regular, LUT, executable accounts, and sysvars.
    - Iterate over regular accounts, initialize them, check if they are built-in, and dump their state if not.
    - Iterate over executable accounts, check their metadata, and dump their state if valid.
    - Iterate over LUT accounts, initialize them, and dump their state if valid.
    - Iterate over sysvar IDs, initialize them, check if they already exist in the output, and dump their state if not.
    - Set the transaction flag in the protobuf message and dump the sanitized transaction.
    - Allocate memory for the blockhash queue, dump it, and store the count in the protobuf message.
    - Set the epoch context flag, dump sorted features, and store them in the protobuf message.
    - Set the slot context flag and store the slot from the transaction context in the protobuf message.
- **Output**: The function outputs a populated `fd_exec_test_txn_context_t` structure representing the transaction context in protobuf format.
- **Functions called**:
    - [`dump_account_state`](#dump_account_state)
    - [`dump_sanitized_transaction`](#dump_sanitized_transaction)
    - [`dump_blockhash_queue`](#dump_blockhash_queue)
    - [`dump_sorted_features`](#dump_sorted_features)


---
### create\_instr\_context\_protobuf\_from\_instructions<!-- {{#callable:create_instr_context_protobuf_from_instructions}} -->
The function `create_instr_context_protobuf_from_instructions` initializes and populates an instruction context protobuf structure from given transaction and instruction data.
- **Inputs**:
    - `instr_context`: A pointer to an `fd_exec_test_instr_context_t` structure where the instruction context will be stored.
    - `txn_ctx`: A constant pointer to an `fd_exec_txn_ctx_t` structure containing transaction context information.
    - `instr`: A constant pointer to an `fd_instr_info_t` structure containing instruction information.
- **Control Flow**:
    - Initialize an array of relevant sysvar IDs and calculate the number of sysvar entries.
    - Copy the program ID from the transaction context to the instruction context.
    - Allocate memory for accounts in the instruction context and copy account information from the transaction context.
    - Iterate over sysvar IDs, initialize accounts from them, and add them to the instruction context if they don't already exist.
    - Iterate over executable accounts, initialize them, and add them to the instruction context if they don't already exist.
    - Allocate memory for instruction accounts and populate them with data from the instruction structure.
    - Allocate memory for instruction data and copy the data from the instruction structure.
    - Set available compute units from the transaction context.
    - Set slot and epoch context flags to true and dump sorted features into the epoch context.
- **Output**: The function does not return a value; it modifies the `instr_context` structure in place.
- **Functions called**:
    - [`dump_account_state`](#dump_account_state)
    - [`dump_sorted_features`](#dump_sorted_features)


---
### fd\_dump\_instr\_to\_protobuf<!-- {{#callable:fd_dump_instr_to_protobuf}} -->
The `fd_dump_instr_to_protobuf` function encodes a transaction instruction context into a protobuf format and writes it to a file, filtering by signature if specified.
- **Inputs**:
    - `txn_ctx`: A pointer to the transaction context (`fd_exec_txn_ctx_t`) containing transaction details and shared data.
    - `instr`: A pointer to the instruction information (`fd_instr_info_t`) that needs to be encoded.
    - `instruction_idx`: An unsigned short representing the index of the instruction within the transaction.
- **Control Flow**:
    - Begin a shared memory frame using `FD_SPAD_FRAME_BEGIN` with the transaction context's scratchpad (`spad`).
    - Retrieve the base58-encoded transaction signature from the transaction context.
    - Check if a signature filter is set in the capture context; if so, compare it with the encoded signature and return early if they do not match.
    - Initialize an instruction context structure (`fd_exec_test_instr_context_t`) with default values.
    - Call [`create_instr_context_protobuf_from_instructions`](#create_instr_context_protobuf_from_instructions) to populate the instruction context with data from the transaction context and instruction.
    - Allocate a buffer for the protobuf output and initialize a protobuf output stream with this buffer.
    - Encode the instruction context into the protobuf stream using `pb_encode`.
    - If encoding is successful, construct the output file path using the capture context's output directory, the encoded signature, and the instruction index.
    - Open the file for writing in binary mode and write the encoded data to the file.
    - Close the file after writing.
    - End the shared memory frame using `FD_SPAD_FRAME_END`.
- **Output**: The function does not return a value; it outputs the encoded protobuf data to a file.
- **Functions called**:
    - [`create_instr_context_protobuf_from_instructions`](#create_instr_context_protobuf_from_instructions)


---
### fd\_dump\_txn\_to\_protobuf<!-- {{#callable:fd_dump_txn_to_protobuf}} -->
The `fd_dump_txn_to_protobuf` function encodes a transaction context into a protobuf format and writes it to a file, optionally filtering by transaction signature.
- **Inputs**:
    - `txn_ctx`: A pointer to an `fd_exec_txn_ctx_t` structure representing the transaction context to be dumped.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the function execution.
- **Control Flow**:
    - Begin a memory frame using `FD_SPAD_FRAME_BEGIN` with the provided `spad`.
    - Retrieve the base58-encoded transaction signature from the transaction context.
    - If a signature filter is set in the capture context, compare it with the encoded signature and return early if they do not match.
    - Initialize a `fd_exec_test_txn_context_t` structure with default values.
    - Call [`create_txn_context_protobuf_from_txn`](#create_txn_context_protobuf_from_txn) to populate the protobuf message with transaction details.
    - Allocate a buffer for the protobuf output and create a stream from it.
    - Encode the transaction context into the protobuf stream using `pb_encode`.
    - If encoding is successful, construct the output file path using the encoded signature and the output directory from the capture context.
    - Open the file for writing, write the encoded data, and close the file.
    - End the memory frame using `FD_SPAD_FRAME_END`.
- **Output**: The function does not return a value but writes the encoded protobuf data to a file in the specified output directory.
- **Functions called**:
    - [`create_txn_context_protobuf_from_txn`](#create_txn_context_protobuf_from_txn)


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:fd_dump_block_to_protobuf_tx_only::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function initializes a frame for memory allocation and processing within a given `spad` context, ensuring necessary conditions are met before proceeding with block context creation and file output.
- **Inputs**:
    - `spad`: A pointer to the shared memory allocation descriptor used for memory management within the function.
- **Control Flow**:
    - Check if `capture_ctx` is NULL and log a warning if true, then return.
    - Check if `block_info` is NULL and log a warning if true, then return.
    - Call [`create_block_context_protobuf_from_block_tx_only`](#create_block_context_protobuf_from_block_tx_only) to populate `block_context_msg` with block transaction data.
    - Allocate a 5 GB buffer using `fd_spad_alloc` for output data.
    - Initialize a protobuf output stream with the allocated buffer.
    - Encode the `block_context_msg` into the protobuf stream.
    - Construct the output file path using `fd_cstr_init` and `fd_cstr_append_printf`.
    - Open the file at the constructed path for writing in binary mode.
    - If the file is successfully opened, write the encoded data to the file and close it.
- **Output**: The function does not return a value but writes the encoded block context data to a binary file.
- **Functions called**:
    - [`create_block_context_protobuf_from_block_tx_only`](#create_block_context_protobuf_from_block_tx_only)


---
### fd\_dump\_block\_to\_protobuf<!-- {{#callable:fd_dump_block_to_protobuf}} -->
The `fd_dump_block_to_protobuf` function converts a block context into a protobuf message format, ensuring the capture context is not null, and then calls a helper function to perform the conversion.
- **Inputs**:
    - `slot_ctx`: A pointer to a constant `fd_exec_slot_ctx_t` structure representing the execution slot context.
    - `capture_ctx`: A pointer to a constant `fd_capture_ctx_t` structure representing the capture context, which must not be NULL.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation.
    - `block_context_msg`: A pointer to an `fd_exec_test_block_context_t` structure where the output protobuf message will be stored.
- **Control Flow**:
    - Check if `capture_ctx` is NULL; if so, log a warning and return immediately.
    - Call [`create_block_context_protobuf_from_block`](#create_block_context_protobuf_from_block) with `block_context_msg`, `slot_ctx`, and `spad` to perform the conversion to protobuf format.
- **Output**: The function does not return a value but populates the `block_context_msg` with the protobuf representation of the block context.
- **Functions called**:
    - [`create_block_context_protobuf_from_block`](#create_block_context_protobuf_from_block)


---
### fd\_dump\_block\_to\_protobuf\_tx\_only<!-- {{#callable:fd_dump_block_to_protobuf_tx_only}} -->
The function `fd_dump_block_to_protobuf_tx_only` serializes block transaction data into a Protobuf format and writes it to a file.
- **Inputs**:
    - `block_info`: A pointer to `fd_runtime_block_info_t` containing information about the block to be dumped.
    - `slot_ctx`: A pointer to `fd_exec_slot_ctx_t` providing context about the execution slot.
    - `capture_ctx`: A pointer to `fd_capture_ctx_t` which contains capture settings, including the output directory for the dump.
    - `spad`: A pointer to `fd_spad_t` used for memory allocation during the function's execution.
    - `block_context_msg`: A pointer to `fd_exec_test_block_context_t` where the block context message will be stored.
- **Control Flow**:
    - Begin a SPAD frame for memory allocation using `FD_SPAD_FRAME_BEGIN` macro.
    - Check if `capture_ctx` is NULL and log a warning if true, then return.
    - Check if `block_info` is NULL and log a warning if true, then return.
    - Call [`create_block_context_protobuf_from_block_tx_only`](#create_block_context_protobuf_from_block_tx_only) to populate `block_context_msg` with transaction-only block context data.
    - Allocate a 5 GB buffer using `fd_spad_alloc` for the output data.
    - Initialize a Protobuf output stream with `pb_ostream_from_buffer`.
    - Encode the `block_context_msg` into the Protobuf stream using `pb_encode`.
    - If encoding is successful, construct the output file path using `fd_cstr_init` and `fd_cstr_append_printf`.
    - Open the file at the constructed path in write-binary mode.
    - If the file is successfully opened, write the encoded data to the file and close it.
    - End the SPAD frame using `FD_SPAD_FRAME_END` macro.
- **Output**: The function does not return a value; it outputs the serialized Protobuf data to a file.
- **Functions called**:
    - [`create_block_context_protobuf_from_block_tx_only`](#create_block_context_protobuf_from_block_tx_only)


---
### fd\_dump\_vm\_cpi\_state<!-- {{#callable:fd_dump_vm_cpi_state}} -->
The `fd_dump_vm_cpi_state` function serializes the current state of a virtual machine's CPI (Cross-Program Invocation) context to a file if it doesn't already exist.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine whose state is to be dumped.
    - `fn_name`: A constant character pointer representing the name of the function being invoked.
    - `instruction_va`: An unsigned long integer representing the virtual address of the instruction.
    - `acct_infos_va`: An unsigned long integer representing the virtual address of account information.
    - `acct_info_cnt`: An unsigned long integer representing the count of account information entries.
    - `signers_seeds_va`: An unsigned long integer representing the virtual address of signers' seeds.
    - `signers_seeds_cnt`: An unsigned long integer representing the count of signers' seeds.
- **Control Flow**:
    - Constructs a filename based on the virtual machine's context and checks if the file already exists.
    - If the file exists, the function returns immediately without doing anything further.
    - Initializes a syscall context structure with the current VM and instruction context data.
    - Copies the function name into the syscall context structure, ensuring it does not exceed the buffer size.
    - Sets various VM context fields in the syscall context structure, including instruction and account information addresses and counts.
    - Allocates memory for and copies the VM's read-only data, stack, and heap into the syscall context structure.
    - Creates an instruction context protobuf from the current instructions and transaction context.
    - Opens a file for writing, truncates it to a predefined size, and maps it into memory using `mmap`.
    - Encodes the syscall context into a protobuf format and writes it to the mapped file memory.
    - Resizes the file to the actual size of the written data and closes the file.
- **Output**: The function does not return any value; it outputs the serialized VM CPI state to a file.
- **Functions called**:
    - [`fd_dump_txn_to_protobuf::FD_SPAD_FRAME_BEGIN`](#fd_dump_txn_to_protobufFD_SPAD_FRAME_BEGIN)
    - [`create_instr_context_protobuf_from_instructions`](#create_instr_context_protobuf_from_instructions)


