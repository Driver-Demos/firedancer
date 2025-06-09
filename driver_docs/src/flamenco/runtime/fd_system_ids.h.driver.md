# Purpose
This C header file defines a collection of external constant variables and function prototypes related to system identifiers and reserved keys within a blockchain or distributed ledger context, likely associated with the Solana blockchain given the naming conventions. The file includes declarations for various public key identifiers (`fd_pubkey_t`) that represent system variables, native programs, and other key components within the system, such as the Solana native loader and various program IDs. Additionally, it provides function prototypes for checking if a public key is a reserved key, which is crucial for managing access and permissions within the system. The file also includes comments explaining the deprecation of certain features and the conditions under which a public key is considered reserved, reflecting the evolving nature of the system's architecture and security features.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`


# Global Variables

---
### fd\_sysvar\_clock\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_clock_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the system variable related to the clock in the Flamenco runtime environment. This identifier is used to access or reference the clock system variable within the system.
- **Use**: This variable is used to uniquely identify and access the clock system variable in the Flamenco runtime.


---
### fd\_sysvar\_slot\_history\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_slot_history_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the slot history system variable in the Flamenco runtime environment. This identifier is used to access or reference the slot history data within the system.
- **Use**: This variable is used to uniquely identify and access the slot history system variable in the Flamenco runtime.


---
### fd\_sysvar\_slot\_hashes\_id
- **Type**: `fd_pubkey_t`
- **Description**: The variable `fd_sysvar_slot_hashes_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the slot hashes system variable in the Flamenco runtime environment. This identifier is used to access or reference the slot hashes system variable, which is likely involved in tracking or managing slot hashes within the system.
- **Use**: This variable is used to uniquely identify and access the slot hashes system variable within the Flamenco runtime.


---
### fd\_sysvar\_epoch\_schedule\_id
- **Type**: `fd_pubkey_t`
- **Description**: The variable `fd_sysvar_epoch_schedule_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the epoch schedule system variable in the Flamenco runtime environment. This identifier is used to access or reference the epoch schedule data within the system.
- **Use**: This variable is used to uniquely identify and access the epoch schedule system variable in the runtime environment.


---
### fd\_sysvar\_epoch\_rewards\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_epoch_rewards_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the epoch rewards system variable in the Flamenco runtime system. This identifier is used to access or reference the epoch rewards data within the system.
- **Use**: This variable is used to uniquely identify and access the epoch rewards system variable in the Flamenco runtime environment.


---
### fd\_sysvar\_fees\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_fees_id` is a global constant of type `fd_pubkey_t`, representing a public key identifier for the fees system variable in the Flamenco runtime. This variable has been disabled and cleaned up following the activation of the `disable_fees_sysvar` feature, indicating it is no longer in active use.
- **Use**: This variable was used to identify the fees system variable, but is now deprecated due to feature changes.


---
### fd\_sysvar\_rent\_id
- **Type**: `fd_pubkey_t`
- **Description**: The variable `fd_sysvar_rent_id` is a constant of type `fd_pubkey_t`, which represents a public key identifier for the rent sysvar in the system. This identifier is used to access the rent-related system variable, which is likely involved in managing or querying rent fees or policies within the system.
- **Use**: This variable is used to reference the rent sysvar in the system, allowing for operations or queries related to rent.


---
### fd\_sysvar\_stake\_history\_id
- **Type**: `fd_pubkey_t`
- **Description**: The variable `fd_sysvar_stake_history_id` is a constant of type `fd_pubkey_t`, which represents a public key identifier for the stake history system variable in the Flamenco runtime environment. This identifier is used to access or reference the stake history data within the system.
- **Use**: This variable is used to uniquely identify and access the stake history system variable in the runtime environment.


---
### fd\_sysvar\_owner\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_owner_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the owner of a system variable in the Flamenco runtime environment. This identifier is used to reference the owner account associated with specific system variables within the system.
- **Use**: This variable is used to identify and reference the owner account of system variables in the Flamenco runtime.


---
### fd\_sysvar\_last\_restart\_slot\_id
- **Type**: `fd_pubkey_t`
- **Description**: The variable `fd_sysvar_last_restart_slot_id` is a constant of type `fd_pubkey_t`, which represents a public key identifier for the system variable related to the last restart slot in the system. This identifier is used within the system to reference the specific sysvar that holds information about the last slot at which the system was restarted.
- **Use**: This variable is used to uniquely identify and access the sysvar containing the last restart slot information within the system.


---
### fd\_sysvar\_instructions\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_instructions_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the 'instructions' system variable in the Flamenco runtime environment. This identifier is used to reference the specific system variable related to instructions within the Solana blockchain ecosystem.
- **Use**: This variable is used to uniquely identify and access the 'instructions' system variable in the Solana blockchain's runtime environment.


---
### fd\_sysvar\_incinerator\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_sysvar_incinerator_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the incinerator system variable in the Flamenco runtime system. This identifier is part of a set of system variables that are used to manage and track various aspects of the runtime environment.
- **Use**: This variable is used to uniquely identify the incinerator system variable within the Flamenco runtime, allowing for operations and checks related to this specific system variable.


---
### fd\_sysvar\_rewards\_id
- **Type**: `fd_pubkey_t`
- **Description**: The variable `fd_sysvar_rewards_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the rewards system variable in the Flamenco runtime environment. This identifier is used to access or reference the rewards-related system variable within the system.
- **Use**: This variable is used to uniquely identify and access the rewards system variable in the Flamenco runtime.


---
### fd\_solana\_native\_loader\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_native_loader_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana native loader. This identifier is used within the Solana blockchain to reference the native loader program, which is responsible for loading and executing native programs on the Solana network.
- **Use**: This variable is used to identify and reference the Solana native loader program within the system.


---
### fd\_solana\_feature\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_feature_program_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana feature program. This identifier is used within the Solana blockchain to reference the feature program, which is responsible for managing and activating new features on the network.
- **Use**: This variable is used to identify and reference the Solana feature program within the system, allowing for the management and activation of new features.


---
### fd\_solana\_config\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_config_program_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana configuration program. This identifier is used within the Solana blockchain to reference the configuration program, which is responsible for managing various configuration settings and parameters.
- **Use**: This variable is used to uniquely identify the Solana configuration program within the system, allowing for operations and interactions with the configuration program.


---
### fd\_solana\_stake\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_stake_program_id` is a global constant of type `fd_pubkey_t` that represents the public key identifier for the Solana Stake Program. This identifier is used within the Solana blockchain to reference the Stake Program, which is responsible for managing staking operations and delegations.
- **Use**: This variable is used to identify and interact with the Solana Stake Program within the blockchain's runtime environment.


---
### fd\_solana\_stake\_program\_config\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_stake_program_config_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the Solana Stake Program configuration. This identifier is used within the Solana blockchain to reference the configuration settings associated with the Stake Program.
- **Use**: This variable is used to identify and access the configuration settings of the Solana Stake Program within the blockchain system.


---
### fd\_solana\_system\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_system_program_id` is a global constant variable of type `fd_pubkey_t`, which represents the public key identifier for the Solana System Program. This program is a core component of the Solana blockchain, responsible for handling basic account operations and system-level instructions.
- **Use**: This variable is used to reference the Solana System Program's public key within the codebase, allowing for operations and interactions with the system program.


---
### fd\_solana\_vote\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_vote_program_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the Solana vote program. This identifier is used within the Solana blockchain to reference the vote program, which is responsible for managing voting operations and consensus within the network.
- **Use**: This variable is used to identify and reference the Solana vote program within the system, allowing for operations related to voting and consensus to be correctly associated with the appropriate program.


---
### fd\_solana\_bpf\_loader\_deprecated\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_bpf_loader_deprecated_program_id` is a global constant of type `fd_pubkey_t`, representing a public key identifier for a deprecated BPF loader program in the Solana blockchain ecosystem. This identifier is used to reference the specific BPF loader program that has been deprecated, indicating that it is no longer actively supported or recommended for use.
- **Use**: This variable is used to identify and reference the deprecated BPF loader program within the Solana blockchain system.


---
### fd\_solana\_bpf\_loader\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_bpf_loader_program_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the Solana BPF Loader program. This program is responsible for loading and executing BPF (Berkeley Packet Filter) bytecode on the Solana blockchain.
- **Use**: This variable is used to identify and reference the Solana BPF Loader program within the system, allowing for operations related to BPF bytecode execution.


---
### fd\_solana\_bpf\_loader\_upgradeable\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_bpf_loader_upgradeable_program_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana BPF Loader Upgradeable Program. This program allows for the deployment and management of upgradeable BPF (Berkeley Packet Filter) programs on the Solana blockchain.
- **Use**: This variable is used to identify and reference the Solana BPF Loader Upgradeable Program within the system, enabling operations related to program upgrades and management.


---
### fd\_solana\_bpf\_loader\_v4\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_bpf_loader_v4_program_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana BPF Loader version 4 program. This identifier is used within the Solana blockchain to reference the specific BPF Loader program, which is responsible for loading and executing BPF bytecode on the Solana network.
- **Use**: This variable is used to uniquely identify the BPF Loader v4 program within the Solana blockchain environment.


---
### fd\_solana\_ed25519\_sig\_verify\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_ed25519_sig_verify_program_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana Ed25519 signature verification program. This identifier is used within the Solana blockchain to reference the specific program responsible for verifying Ed25519 signatures.
- **Use**: This variable is used to identify and reference the Ed25519 signature verification program within the Solana blockchain system.


---
### fd\_solana\_keccak\_secp\_256k\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_keccak_secp_256k_program_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for a specific Solana program. This program is likely related to cryptographic operations involving the Keccak hash function and the secp256k1 elliptic curve, commonly used in blockchain technologies.
- **Use**: This variable is used to uniquely identify the Solana program that handles Keccak and secp256k1 operations within the system.


---
### fd\_solana\_secp256r1\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_secp256r1_program_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the secp256r1 program in the Solana blockchain environment. This identifier is used to reference the secp256r1 cryptographic program, which is likely involved in operations related to the secp256r1 elliptic curve, a standard used in cryptographic applications.
- **Use**: This variable is used to identify and reference the secp256r1 program within the Solana blockchain system, particularly in contexts where cryptographic operations involving the secp256r1 curve are required.


---
### fd\_solana\_compute\_budget\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_compute_budget_program_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana Compute Budget Program. This program is responsible for managing compute budgets within the Solana blockchain, which are essential for controlling the computational resources allocated to transactions and smart contracts.
- **Use**: This variable is used to uniquely identify the Solana Compute Budget Program within the system, allowing for operations and interactions specific to this program.


---
### fd\_solana\_address\_lookup\_table\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_address_lookup_table_program_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the Solana Address Lookup Table Program. This program is likely used within the Solana blockchain ecosystem to facilitate address lookups, which are essential for transaction processing and account management.
- **Use**: This variable is used to store the public key identifier for the Solana Address Lookup Table Program, allowing other parts of the system to reference this program by its unique identifier.


---
### fd\_solana\_spl\_native\_mint\_id
- **Type**: `fd_pubkey_t`
- **Description**: The variable `fd_solana_spl_native_mint_id` is a constant of type `fd_pubkey_t`, which represents a public key identifier for the Solana SPL native mint. This identifier is used within the Solana blockchain to reference the native minting program, which is responsible for creating and managing native tokens on the network.
- **Use**: This variable is used to uniquely identify the Solana SPL native mint program within the system.


---
### fd\_solana\_spl\_token\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_spl_token_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana SPL Token program. This identifier is used within the Solana blockchain to reference the SPL Token program, which is responsible for token operations such as minting, transferring, and burning tokens.
- **Use**: This variable is used to identify and interact with the Solana SPL Token program within the blockchain's runtime environment.


---
### fd\_solana\_zk\_token\_proof\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The variable `fd_solana_zk_token_proof_program_id` is a global constant of type `fd_pubkey_t`, which represents a public key identifier for the Solana Zero-Knowledge (ZK) Token Proof Program. This identifier is used within the Solana blockchain ecosystem to reference the specific program responsible for handling zero-knowledge proofs related to token transactions.
- **Use**: This variable is used to uniquely identify and reference the Solana ZK Token Proof Program within the system, allowing for operations and interactions with this program.


---
### fd\_solana\_zk\_elgamal\_proof\_program\_id
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_zk_elgamal_proof_program_id` is a global constant variable of type `fd_pubkey_t`, which represents a public key identifier for the Solana zk-ElGamal proof program. This variable is part of a collection of public key identifiers used to reference various system programs and features within the Solana blockchain ecosystem.
- **Use**: This variable is used to uniquely identify the zk-ElGamal proof program within the Solana blockchain, allowing for programmatic access and interaction with this specific program.


---
### fd\_solana\_address\_lookup\_table\_program\_buffer\_address
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_address_lookup_table_program_buffer_address` is a global constant of type `fd_pubkey_t`, which represents a public key associated with the Solana address lookup table program's buffer account. This buffer account is used in the context of BPF migrations, as indicated by the comment in the code.
- **Use**: This variable is used to store the public key for the buffer account related to the Solana address lookup table program, facilitating BPF migrations.


---
### fd\_solana\_config\_program\_buffer\_address
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_config_program_buffer_address` is a global constant variable of type `fd_pubkey_t`, which represents a public key associated with the Solana configuration program's buffer account. This buffer account is used for BPF (Berkeley Packet Filter) migrations, which are part of the Solana runtime's infrastructure for managing program updates and configurations.
- **Use**: This variable is used to identify the buffer account for the Solana configuration program during BPF migrations.


---
### fd\_solana\_feature\_program\_buffer\_address
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_feature_program_buffer_address` is a global constant variable of type `fd_pubkey_t`, which represents a public key associated with the Solana feature program buffer. This buffer is likely used for managing or migrating BPF (Berkeley Packet Filter) programs within the Solana blockchain environment.
- **Use**: This variable is used to store the public key for the Solana feature program buffer, facilitating BPF migrations.


---
### fd\_solana\_stake\_program\_buffer\_address
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_stake_program_buffer_address` is a global constant variable of type `fd_pubkey_t`, which represents a public key associated with the Solana stake program's buffer account. This buffer account is used in the context of BPF (Berkeley Packet Filter) migrations, as indicated by the comment in the code.
- **Use**: This variable is used to store the public key for the buffer account related to the Solana stake program, facilitating BPF migrations.


---
### fd\_solana\_migration\_authority
- **Type**: `fd_pubkey_t`
- **Description**: The `fd_solana_migration_authority` is a global constant variable of type `fd_pubkey_t`, which represents a public key used as the authority for BPF migrations in the Solana blockchain environment. This variable is defined as an external constant, indicating that its value is set elsewhere, likely in a linked library or another part of the codebase.
- **Use**: This variable is used to identify the authority responsible for managing BPF migrations, ensuring that only authorized entities can perform such operations.


# Function Declarations (Public API)

---
### fd\_pubkey\_is\_active\_reserved\_key<!-- {{#callable_declaration:fd_pubkey_is_active_reserved_key}} -->
Check if a public key is an active reserved key.
- **Description**: Use this function to determine if a given public key is part of the active reserved keys set. This is useful for verifying whether a public key is reserved and thus not writable in certain contexts. The function should be called with a valid public key, and it will return a boolean-like integer indicating the presence of the key in the active reserved keys set. This function is part of a broader mechanism to manage reserved account keys, which are not added to writable accounts caches.
- **Inputs**:
    - `acct`: A pointer to a constant fd_pubkey_t representing the public key to check. Must not be null. The function will return 0 if the key is not in the active reserved keys set, and 1 if it is.
- **Output**: Returns 1 if the public key is in the active reserved keys set, and 0 otherwise.
- **See also**: [`fd_pubkey_is_active_reserved_key`](fd_system_ids.c.driver.md#fd_pubkey_is_active_reserved_key)  (Implementation)


---
### fd\_pubkey\_is\_pending\_reserved\_key<!-- {{#callable_declaration:fd_pubkey_is_pending_reserved_key}} -->
Checks if a public key is a pending reserved key.
- **Description**: Use this function to determine if a given public key is part of the set of pending reserved keys. This is useful when you need to verify whether a public key is reserved and should not be added to writable accounts. The function returns a boolean-like integer indicating the presence of the public key in the pending reserved keys set. It is important to ensure that the `add_new_reserved_account_keys` feature is active if you intend to treat pending reserved keys as reserved.
- **Inputs**:
    - `acct`: A pointer to a `fd_pubkey_t` structure representing the public key to check. Must not be null. The caller retains ownership of the memory.
- **Output**: Returns 1 if the public key is in the set of pending reserved keys, and 0 otherwise.
- **See also**: [`fd_pubkey_is_pending_reserved_key`](fd_system_ids.c.driver.md#fd_pubkey_is_pending_reserved_key)  (Implementation)


---
### fd\_pubkey\_is\_secp256r1\_key<!-- {{#callable_declaration:fd_pubkey_is_secp256r1_key}} -->
Checks if a public key is the secp256r1 program ID.
- **Description**: Use this function to determine if a given public key corresponds to the secp256r1 program ID. This is useful in contexts where specific handling is required for this program ID, such as when certain features are enabled. The function returns a boolean-like integer indicating the match status. It is important to ensure that the input public key is valid and properly initialized before calling this function.
- **Inputs**:
    - `acct`: A pointer to a constant fd_pubkey_t structure representing the public key to be checked. Must not be null, and the structure should be properly initialized. If the input is invalid, the behavior is undefined.
- **Output**: Returns 1 if the public key matches the secp256r1 program ID, otherwise returns 0.
- **See also**: [`fd_pubkey_is_secp256r1_key`](fd_system_ids.c.driver.md#fd_pubkey_is_secp256r1_key)  (Implementation)


