# Purpose
This C header file is an automatically generated nanopb header, which defines data structures and associated metadata for protocol buffer messages used in the context of Solana's Sealevel runtime environment. The file provides a collection of struct definitions that represent various components of the Solana blockchain, such as account states, vote accounts, stake accounts, inflation parameters, and context information for epochs and slots. These structures are designed to facilitate the serialization and deserialization of data in a format compatible with nanopb, a small code-size Protocol Buffers implementation in C.

The header file includes several key components, such as `fd_exec_test_acct_state_t`, which encapsulates the state of a Solana account, and `fd_exec_test_epoch_context_t`, which provides context information scoped to an epoch, including features, inflation parameters, and vote accounts. Additionally, the file defines initializer macros for these structures, ensuring they can be easily instantiated with default or zero values. The file also includes field tags and encoding specifications for each struct, which are essential for the manual encoding and decoding processes in nanopb. This header is intended to be included in other C source files that require access to these protocol buffer definitions, serving as a bridge between the Solana blockchain's data structures and the nanopb serialization framework.
# Imports and Dependencies

---
- `../../../../../ballet/nanopb/pb_firedancer.h`


# Data Structures

---
### fd\_exec\_test\_feature\_set\_t
- **Type**: `struct`
- **Members**:
    - `features_count`: Stores the number of enabled features in the feature set.
    - `features`: A pointer to an array of 64-bit integers, each representing the first 8 bytes of a feature ID in little-endian format.
- **Description**: The `fd_exec_test_feature_set_t` structure is designed to represent a set of enabled features within a system. Each feature is identified by a unique ID, and the structure maintains a count of these features along with a pointer to an array of 64-bit integers. These integers represent the first 8 bytes of each feature ID, stored in little-endian format, allowing for efficient storage and retrieval of feature flags.


---
### fd\_exec\_test\_seed\_address\_t
- **Type**: `struct`
- **Members**:
    - `base`: The seed address base, represented as a 32-byte callback.
    - `seed`: The seed path, which is a callback with a maximum size of 32 bytes.
    - `owner`: The seed address owner, represented as a 32-byte callback.
- **Description**: The `fd_exec_test_seed_address_t` structure is designed to encapsulate information about a seed address in a Solana context. It includes three main components: the base, seed, and owner, each represented by a `pb_callback_t` type, which allows for dynamic handling of byte arrays. This structure is not a Program Derived Address (PDA) but serves to manage seed-related data, ensuring that each component can handle up to 32 bytes of data efficiently.


---
### fd\_exec\_test\_acct\_state\_t
- **Type**: `struct`
- **Members**:
    - `address`: A 32-byte array representing the account address.
    - `lamports`: A 64-bit unsigned integer representing the amount of lamports in the account.
    - `data`: A pointer to a byte array representing the account data, limited to 10 MiB on Solana mainnet.
    - `executable`: A boolean indicating if the account is executable.
    - `rent_epoch`: A 64-bit unsigned integer representing the rent epoch, deprecated as of 2024-Feb.
    - `owner`: A 32-byte array representing the address of the program that owns this account.
    - `has_seed_addr`: A boolean indicating if the account has a seed address.
    - `seed_addr`: A structure representing the seed address, which overrides `address` if present.
- **Description**: The `fd_exec_test_acct_state_t` structure represents the complete state of an account on the Solana blockchain, excluding its public key. It includes fields for the account's address, balance in lamports, associated data, and ownership details. The structure also supports an optional seed address, which can override the primary address, and includes a boolean to indicate if the account is executable. The rent epoch field is deprecated, and the structure is designed to accommodate Solana's constraints and extensions, such as the solfuzz-specific seed address extension.


---
### fd\_exec\_test\_vote\_account\_t
- **Type**: `struct`
- **Members**:
    - `has_vote_account`: Indicates whether the vote account is present.
    - `vote_account`: Represents the state of the vote account using the fd_exec_test_acct_state_t structure.
    - `stake`: Holds the amount of stake delegated to this vote account.
- **Description**: The `fd_exec_test_vote_account_t` structure is designed to encapsulate the state and stake information of a vote account within a Solana-based system. It includes a boolean flag to indicate the presence of a vote account, a nested structure to detail the account's state, and a 64-bit unsigned integer to represent the amount of stake delegated to the account. This structure is crucial for managing and tracking voting power and account status in the context of epoch and slot management.


---
### fd\_exec\_test\_stake\_account\_t
- **Type**: `struct`
- **Members**:
    - `stake_account_pubkey`: A 32-byte array representing the public key of the stake account.
    - `voter_pubkey`: A 32-byte array representing the public key of the voter to whom this stake account is delegated.
    - `stake`: A 64-bit unsigned integer representing the amount of stake.
    - `activation_epoch`: A 64-bit unsigned integer indicating the epoch when the stake was activated.
    - `deactivation_epoch`: A 64-bit unsigned integer indicating the epoch when the stake was deactivated.
    - `warmup_cooldown_rate`: A double representing the rate of warmup or cooldown for the stake.
- **Description**: The `fd_exec_test_stake_account_t` structure represents a stake account in a blockchain context, containing information about the account's public key, the delegated voter's public key, the amount of stake, and the epochs of activation and deactivation. It also includes a rate for warming up or cooling down the stake, which is crucial for managing the stake's lifecycle and its impact on the network's consensus mechanism.


---
### fd\_exec\_test\_inflation\_t
- **Type**: `struct`
- **Members**:
    - `initial`: Represents the initial inflation rate as a double.
    - `terminal`: Represents the terminal inflation rate as a double.
    - `taper`: Represents the tapering rate of inflation as a double.
    - `foundation`: Represents the foundation's share of inflation as a double.
    - `foundation_term`: Represents the term for the foundation's share of inflation as a double.
- **Description**: The `fd_exec_test_inflation_t` structure is used to define the parameters for inflation within an epoch bank context. It includes fields for the initial and terminal inflation rates, as well as the tapering rate, which describes how inflation decreases over time. Additionally, it specifies the foundation's share of the inflation and the term over which this share is applicable. This structure is crucial for managing and simulating inflation dynamics in a blockchain or ledger system.


---
### fd\_exec\_test\_epoch\_context\_t
- **Type**: `struct`
- **Members**:
    - `has_features`: Indicates if the feature set is active.
    - `features`: Represents the active feature set using a feature set structure.
    - `hashes_per_tick`: Specifies the number of hashes computed per tick.
    - `ticks_per_slot`: Defines the number of ticks that occur in a single slot.
    - `slots_per_year`: Represents the number of slots that occur in a year.
    - `has_inflation`: Indicates if inflation parameters are active.
    - `inflation`: Contains the inflation parameters using an inflation structure.
    - `genesis_creation_time`: Records the creation time of the genesis block.
    - `vote_accounts_t_1_count`: Counts the number of vote accounts for epoch T-1.
    - `vote_accounts_t_1`: Points to the vote accounts for epoch T-1.
    - `vote_accounts_t_2_count`: Counts the number of vote accounts for epoch T-2.
    - `vote_accounts_t_2`: Points to the vote accounts for epoch T-2.
- **Description**: The `fd_exec_test_epoch_context_t` structure encapsulates the context information relevant to a specific epoch in a blockchain system. It includes details about active features, hashing and slot timing parameters, inflation settings, and genesis creation time. Additionally, it maintains records of vote accounts from the two preceding epochs, providing a comprehensive snapshot of the epoch's operational context.


---
### fd\_exec\_test\_slot\_context\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the current slot number in the context.
    - `block_height`: Indicates the block height associated with the current slot.
    - `poh`: Stores the Proof of History (POH) hash as a 32-byte array.
    - `parent_bank_hash`: Holds the hash of the parent bank as a 32-byte array.
    - `parent_lt_hash`: Contains the hash of the parent ledger transaction as a 2048-byte array.
    - `prev_slot`: Records the last executed slot number.
    - `prev_lps`: Represents the lamports per signature for the last slot.
    - `prev_epoch_capitalization`: Stores the capitalization of the previous epoch.
- **Description**: The `fd_exec_test_slot_context_t` structure is designed to encapsulate context information specific to a blockchain slot within a ledger system. It includes details such as the current slot number, block height, and various cryptographic hashes (POH, parent bank, and parent ledger transaction) that are crucial for maintaining the integrity and continuity of the blockchain. Additionally, it tracks historical data like the last executed slot, lamports per signature, and the capitalization of the previous epoch, which are essential for validating transactions and ensuring the correct application of blockchain rules.


