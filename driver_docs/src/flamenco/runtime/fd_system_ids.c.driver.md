# Purpose
This C source code file defines a set of public key constants and functions related to the Solana blockchain system. The file primarily serves as a repository for various system and program identifiers, encapsulated in `fd_pubkey_t` structures, which are used to uniquely identify different system variables, programs, and features within the Solana ecosystem. These identifiers include system variables like recent block hashes, clock, slot history, and various Solana programs such as the native loader, feature program, and stake program. The file also includes perfect hash map definitions to efficiently check if a given public key is part of a predefined set of active or pending reserved keys.

The code provides a narrow but crucial functionality, focusing on the management and identification of reserved keys within the Solana blockchain. It includes functions to determine if a given public key is an active or pending reserved key, as well as a specific check for the `secp256r1` key. The use of perfect hashing ensures efficient lookup operations, which is critical for performance in blockchain systems where quick verification of keys is necessary. This file is intended to be part of a larger system, likely imported by other components that require access to these identifiers and key-checking functionalities. The inclusion of header files and the use of macros for perfect hashing indicate that this file is part of a modular system, designed to be integrated with other components of the Solana blockchain infrastructure.
# Imports and Dependencies

---
- `fd_system_ids.h`
- `fd_system_ids_pp.h`
- `../../util/tmpl/fd_map_perfect.c`


# Global Variables

---
### fd\_sysvar\_recent\_block\_hashes\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_recent_block_hashes_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a unique identifier `SYSVAR_RECENT_BLKHASH_ID` that represents the recent block hashes system variable in the Solana blockchain.
- **Use**: This variable is used to reference the recent block hashes system variable within the Solana blockchain environment.


---
### fd\_sysvar\_clock\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_clock_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a unique identifier `SYSVAR_CLOCK_ID` that is likely used to reference the system variable related to the clock in a blockchain or distributed system context.
- **Use**: This variable is used to identify and access the system clock variable within the system's public key infrastructure.


---
### fd\_sysvar\_slot\_history\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_slot_history_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a unique identifier `SYSVAR_SLOT_HIST_ID` that represents the slot history system variable in the Solana blockchain.
- **Use**: This variable is used to identify and access the slot history system variable within the Solana blockchain environment.


---
### fd\_sysvar\_slot\_hashes\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_slot_hashes_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a unique identifier `SYSVAR_SLOT_HASHES_ID` that is likely used to reference a specific system variable related to slot hashes in a blockchain or distributed ledger context.
- **Use**: This variable is used to identify and access the system variable associated with slot hashes.


---
### fd\_sysvar\_epoch\_schedule\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_epoch_schedule_id` is a constant global variable of type `fd_pubkey_t`, which is a data structure representing a public key. It is initialized with a unique identifier `SYSVAR_EPOCH_SCHED_ID` that is likely used to reference the epoch schedule system variable in a blockchain or distributed ledger context.
- **Use**: This variable is used to identify and access the epoch schedule system variable within the system.


---
### fd\_sysvar\_epoch\_rewards\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_epoch_rewards_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a specific identifier `SYSVAR_EPOCH_REWARDS_ID` that is likely used to reference the epoch rewards system variable in a blockchain or distributed ledger context.
- **Use**: This variable is used to uniquely identify the epoch rewards system variable within the system, allowing for operations or queries related to epoch rewards.


---
### fd\_sysvar\_fees\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_fees_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a unique identifier `SYSVAR_FEES_ID` that represents the system variable for fees in the context of the application.
- **Use**: This variable is used to identify and access the system variable related to fees within the application.


---
### fd\_sysvar\_rent\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_rent_id` is a global constant variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a specific identifier `SYSVAR_RENT_ID` that represents the system variable for rent in a blockchain context.
- **Use**: This variable is used to uniquely identify the rent system variable within the application, likely for accessing or managing rent-related data or operations.


---
### fd\_sysvar\_stake\_history\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_stake_history_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a specific identifier `SYSVAR_STAKE_HIST_ID` that represents the stake history system variable in the Solana blockchain environment.
- **Use**: This variable is used to uniquely identify the stake history system variable within the Solana blockchain, allowing for operations and interactions with this specific system variable.


---
### fd\_sysvar\_owner\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_owner_id` is a constant global variable of type `fd_pubkey_t`, which is a structure representing a public key. It is initialized with a unique identifier `SYSVAR_PROG_ID` that is stored in the `uc` field of the structure.
- **Use**: This variable is used to identify the owner of a system variable in the context of the program, likely for access control or identification purposes.


---
### fd\_sysvar\_last\_restart\_slot\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_last_restart_slot_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that likely represents a public key or identifier in the system. It is initialized with a unique identifier `SYSVAR_LAST_RESTART_ID`, which is presumably defined elsewhere in the code or included headers.
- **Use**: This variable is used to uniquely identify the system variable related to the last restart slot in the system.


---
### fd\_sysvar\_instructions\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_instructions_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a unique identifier `SYSVAR_INSTRUCTIONS_ID` that represents the system variable for instructions in the Solana blockchain environment.
- **Use**: This variable is used to identify and access the system variable related to instructions within the Solana blockchain.


---
### fd\_sysvar\_incinerator\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_incinerator_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a unique identifier `SYSVAR_INCINERATOR_ID` that is likely used to reference a specific system variable related to the incinerator functionality within the system.
- **Use**: This variable is used to store and provide access to the public key associated with the incinerator system variable.


---
### fd\_sysvar\_rewards\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_rewards_id` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. It is initialized with a unique identifier `SYSVAR_REWARDS_ID` that represents the rewards system variable in the Solana blockchain context.
- **Use**: This variable is used to identify and access the rewards system variable within the Solana blockchain environment.


---
### fd\_solana\_native\_loader\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_native_loader_id` is a constant global variable of type `fd_pubkey_t`, which is a structure containing a public key identifier for the Solana native loader. This identifier is used to reference the native loader program within the Solana blockchain ecosystem.
- **Use**: This variable is used to uniquely identify the Solana native loader program in various operations and checks within the system.


---
### fd\_solana\_feature\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_feature_program_id` is a constant global variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana feature program. It is initialized with a unique identifier `FEATURE_ID` that is used to reference the feature program within the Solana blockchain ecosystem.
- **Use**: This variable is used to identify and reference the Solana feature program in various operations and functions that require a public key for program identification.


---
### fd\_solana\_config\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_config_program_id` is a constant global variable of type `fd_pubkey_t`, which represents a public key associated with the Solana configuration program. It is initialized with a unique identifier `CONFIG_PROG_ID` that is likely defined elsewhere in the codebase.
- **Use**: This variable is used to identify and reference the Solana configuration program within the system.


---
### fd\_solana\_stake\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_stake_program_id` is a constant global variable of type `fd_pubkey_t`, which represents the public key identifier for the Solana Stake Program. This identifier is used to reference the stake program within the Solana blockchain ecosystem.
- **Use**: This variable is used to uniquely identify the Solana Stake Program in various operations and transactions within the Solana network.


---
### fd\_solana\_stake\_program\_config\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_stake_program_config_id` is a constant global variable of type `fd_pubkey_t`, which is a structure representing a public key in the Solana blockchain system. It is initialized with a unique identifier `STAKE_CONFIG_PROG_ID`, which is likely a predefined macro representing the public key for the Solana Stake Program configuration.
- **Use**: This variable is used to store and provide access to the public key associated with the Solana Stake Program configuration, allowing other parts of the program to reference this specific configuration ID.


---
### fd\_solana\_system\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_system_program_id` is a constant global variable of type `fd_pubkey_t`, which represents the public key identifier for the Solana System Program. This identifier is used to reference the System Program within the Solana blockchain, which is responsible for handling basic account operations and system-level instructions.
- **Use**: This variable is used to identify and interact with the Solana System Program in the blockchain environment.


---
### fd\_solana\_vote\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_vote_program_id` is a constant global variable of type `fd_pubkey_t`, which represents the public key identifier for the Solana Vote Program. This identifier is used within the Solana blockchain to reference the Vote Program, which is responsible for managing voting and consensus operations.
- **Use**: This variable is used to uniquely identify the Solana Vote Program within the system, allowing for operations and interactions specific to voting processes.


---
### fd\_solana\_bpf\_loader\_deprecated\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_bpf_loader_deprecated_program_id` is a constant global variable of type `fd_pubkey_t`, which represents a public key identifier for the deprecated BPF loader program in the Solana blockchain. It is initialized with a unique identifier `BPF_LOADER_1_PROG_ID`, indicating its association with the first version of the BPF loader program.
- **Use**: This variable is used to identify and reference the deprecated BPF loader program within the Solana blockchain system.


---
### fd\_solana\_bpf\_loader\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_bpf_loader_program_id` is a constant global variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana BPF Loader program. This identifier is used to reference the BPF Loader version 2 program within the Solana blockchain ecosystem.
- **Use**: This variable is used to identify and interact with the BPF Loader version 2 program in Solana.


---
### fd\_solana\_bpf\_loader\_upgradeable\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_bpf_loader_upgradeable_program_id` is a constant global variable of type `fd_pubkey_t`, which is a data structure representing a public key. It is initialized with a unique identifier `BPF_UPGRADEABLE_PROG_ID` that corresponds to the Solana BPF Loader Upgradeable Program.
- **Use**: This variable is used to identify and reference the Solana BPF Loader Upgradeable Program within the system.


---
### fd\_solana\_bpf\_loader\_v4\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_bpf_loader_v4_program_id` is a constant global variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana BPF Loader version 4 program. It is initialized with a unique identifier `LOADER_V4_PROG_ID` that is used to reference this specific program within the Solana blockchain ecosystem.
- **Use**: This variable is used to identify and reference the BPF Loader version 4 program in the Solana blockchain.


---
### fd\_solana\_ed25519\_sig\_verify\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_ed25519_sig_verify_program_id` is a constant global variable of type `fd_pubkey_t`, which is a data structure representing a public key. It is initialized with a specific identifier `ED25519_SV_PROG_ID`, which is likely a predefined constant representing the program ID for the Ed25519 signature verification program in the Solana blockchain ecosystem.
- **Use**: This variable is used to store the program ID for the Ed25519 signature verification program, allowing other parts of the system to reference this program by its public key.


---
### fd\_solana\_keccak\_secp\_256k\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_keccak_secp_256k_program_id` is a constant global variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana blockchain's Keccak SECP 256k1 program. This identifier is used to reference the specific program within the Solana ecosystem that utilizes the Keccak hashing algorithm and the SECP 256k1 elliptic curve for cryptographic operations.
- **Use**: This variable is used to uniquely identify and reference the Keccak SECP 256k1 program within the Solana blockchain environment.


---
### fd\_solana\_secp256r1\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_secp256r1_program_id` is a constant global variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana SECP256R1 program. It is initialized with a unique identifier `SECP256R1_PROG_ID` that is stored in the `uc` field of the `fd_pubkey_t` structure.
- **Use**: This variable is used to identify and verify the SECP256R1 program within the Solana blockchain environment.


---
### fd\_solana\_compute\_budget\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_compute_budget_program_id` is a constant global variable of type `fd_pubkey_t`, which represents the public key identifier for the Solana Compute Budget Program. This identifier is used to reference the specific program within the Solana blockchain ecosystem that manages compute budget allocations for transactions.
- **Use**: This variable is used to identify and interact with the Solana Compute Budget Program within the system.


---
### fd\_solana\_address\_lookup\_table\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_address_lookup_table_program_id` is a constant global variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana Address Lookup Table program. This identifier is used to reference the specific program within the Solana blockchain ecosystem.
- **Use**: This variable is used to uniquely identify the Address Lookup Table program in Solana, facilitating interactions and operations involving this program.


---
### fd\_solana\_spl\_native\_mint\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_spl_native_mint_id` is a constant global variable of type `fd_pubkey_t`, which is a structure representing a public key in the Solana blockchain system. It is initialized with a unique identifier `NATIVE_MINT_ID`, which is likely a predefined constant representing the native mint account in the Solana SPL (Solana Program Library) ecosystem.
- **Use**: This variable is used to identify the native mint account within the Solana SPL, facilitating operations that involve the native token.


---
### fd\_solana\_spl\_token\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_spl_token_id` is a constant global variable of type `fd_pubkey_t`, which is a structure representing a public key in the Solana blockchain system. It is initialized with a unique identifier `TOKEN_PROG_ID`, which corresponds to the Solana SPL Token program.
- **Use**: This variable is used to identify and interact with the Solana SPL Token program within the system.


---
### fd\_solana\_zk\_token\_proof\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_zk_token_proof_program_id` is a constant global variable of type `fd_pubkey_t`, which is a structure representing a public key. It is initialized with a unique identifier `ZK_TOKEN_PROG_ID`, which is likely a predefined macro or constant representing the program ID for a zero-knowledge token proof program in the Solana blockchain ecosystem.
- **Use**: This variable is used to store and provide access to the public key associated with the zero-knowledge token proof program, facilitating cryptographic operations and program identification within the Solana network.


---
### fd\_solana\_zk\_elgamal\_proof\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_zk_elgamal_proof_program_id` is a constant global variable of type `fd_pubkey_t`, which is a structure containing a public key identifier for the Solana ZK ElGamal proof program. This identifier is used to reference the specific program within the Solana blockchain ecosystem.
- **Use**: This variable is used to uniquely identify the ZK ElGamal proof program in the Solana blockchain.


---
### fd\_solana\_address\_lookup\_table\_program\_buffer\_address
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_address_lookup_table_program_buffer_address` is a constant global variable of type `fd_pubkey_t`, which is a structure that holds a public key. This specific variable is initialized with a unique identifier `ADDR_LUT_PROG_BUFFER_ID`, which is likely used to reference a specific buffer address related to the Solana address lookup table program.
- **Use**: This variable is used to store and provide access to the public key associated with the Solana address lookup table program buffer.


---
### fd\_solana\_config\_program\_buffer\_address
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_config_program_buffer_address` is a constant global variable of type `fd_pubkey_t`, which is a structure representing a public key in the Solana blockchain system. It is initialized with a unique identifier `CONFIG_PROG_BUFFER_ID`, which is likely defined elsewhere in the codebase.
- **Use**: This variable is used to store the public key address for the Solana configuration program buffer, allowing it to be referenced throughout the system.


---
### fd\_solana\_feature\_program\_buffer\_address
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_feature_program_buffer_address` is a constant global variable of type `fd_pubkey_t`, which is a structure representing a public key in the Solana blockchain system. It is initialized with a unique identifier `FEATURE_PROG_BUFFER_ID` that is likely used to reference a specific feature program buffer within the Solana network.
- **Use**: This variable is used to store and provide access to the public key associated with the feature program buffer in the Solana blockchain.


---
### fd\_solana\_stake\_program\_buffer\_address
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_stake_program_buffer_address` is a constant global variable of type `fd_pubkey_t`, which is a structure containing a public key represented by an array of unsigned characters. It is initialized with a specific identifier `STAKE_PROG_BUFFER_ID`, which is likely defined elsewhere in the codebase.
- **Use**: This variable is used to store the public key associated with the Solana stake program buffer, which is essential for identifying and interacting with the stake program buffer in the Solana blockchain environment.


---
### fd\_solana\_migration\_authority
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_migration_authority` is a constant global variable of type `fd_pubkey_t`, which is a structure representing a public key. It is initialized with a unique identifier `MIGRATION_AUTHORITY_ID` that is stored in the `uc` field of the structure.
- **Use**: This variable is used to represent the public key for the Solana migration authority, likely for authentication or access control purposes within the system.


# Functions

---
### fd\_pubkey\_is\_active\_reserved\_key<!-- {{#callable:fd_pubkey_is_active_reserved_key}} -->
The function `fd_pubkey_is_active_reserved_key` checks if a given public key is part of the active reserved keys table.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_pubkey_t` structure representing the public key to be checked.
- **Control Flow**:
    - The function calls `fd_pubkey_active_reserved_keys_tbl_contains` with the provided public key as an argument.
    - The result of the call to `fd_pubkey_active_reserved_keys_tbl_contains` is returned directly.
- **Output**: An integer value indicating whether the public key is in the active reserved keys table (non-zero if true, zero if false).


---
### fd\_pubkey\_is\_pending\_reserved\_key<!-- {{#callable:fd_pubkey_is_pending_reserved_key}} -->
The function `fd_pubkey_is_pending_reserved_key` checks if a given public key is part of the pending reserved keys table.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_pubkey_t` structure representing the public key to be checked.
- **Control Flow**:
    - The function calls `fd_pubkey_pending_reserved_keys_tbl_contains` with the provided public key as an argument.
    - The result of the call to `fd_pubkey_pending_reserved_keys_tbl_contains` is returned directly.
- **Output**: An integer value indicating whether the public key is in the pending reserved keys table (non-zero if true, zero if false).


---
### fd\_pubkey\_is\_secp256r1\_key<!-- {{#callable:fd_pubkey_is_secp256r1_key}} -->
The function `fd_pubkey_is_secp256r1_key` checks if a given public key matches the predefined Solana secp256r1 program ID.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_pubkey_t` structure representing the public key to be checked.
- **Control Flow**:
    - The function uses `memcmp` to compare the `uc` field of the input `acct` with the `key` field of the `fd_solana_secp256r1_program_id`.
    - The comparison checks if the memory content of both fields is identical over the size of `fd_pubkey_t`.
    - If the memory content is identical, `memcmp` returns 0, indicating a match.
- **Output**: The function returns an integer value: 1 if the public key matches the secp256r1 program ID, otherwise 0.


