# Purpose
The provided C source code file is designed to manage and configure a system for handling tip payments and block building in a blockchain or distributed ledger environment. It defines structures and functions to initialize, update, and manage configurations related to tip distribution and payment programs. The code includes static configurations for two types of "cranks" (fd_bundle_crank_3_t and fd_bundle_crank_2_t), which are likely used to represent different transaction or operation types within the system. These cranks are initialized with specific parameters such as program IDs, account counts, and instruction counts, which are essential for executing transactions in the blockchain context.

The file also includes functions to initialize a crank generator ([`fd_bundle_crank_gen_init`](#fd_bundle_crank_gen_init)), update epoch-related configurations ([`fd_bundle_crank_update_epoch`](#fd_bundle_crank_update_epoch)), and generate transactions ([`fd_bundle_crank_generate`](#fd_bundle_crank_generate)). The code makes use of utility functions for public key operations, such as finding program addresses, which are crucial for ensuring the correct configuration of accounts and programs in the blockchain. Additionally, the code includes a map implementation for managing account addresses, ensuring that each address is unique and correctly indexed. This file is part of a larger system, as indicated by the inclusion of external headers and utility templates, and it provides a focused functionality related to managing and executing specific blockchain operations.
# Imports and Dependencies

---
- `fd_bundle_crank.h`
- `../../flamenco/runtime/fd_pubkey_utils.h`
- `../../util/tmpl/fd_map.c`


# Global Variables

---
### fd\_bundle\_crank\_3\_base
- **Type**: ``fd_bundle_crank_3_t``
- **Description**: The `fd_bundle_crank_3_base` is a static constant array of type `fd_bundle_crank_3_t` with a single element. It is initialized with various fields that configure the crank's behavior, including signature counts, account addresses, and program configurations. This structure is used to manage and execute specific operations related to tip distribution and block building in a blockchain context.
- **Use**: This variable is used as a base configuration for initializing and managing crank operations in the `fd_bundle_crank_gen_init` function.


---
### fd\_bundle\_crank\_2\_base
- **Type**: ``fd_bundle_crank_2_t``
- **Description**: The `fd_bundle_crank_2_base` is a static constant array of type `fd_bundle_crank_2_t` with a single element. It is initialized with various fields related to signature counts, account addresses, and program configurations, which are used for managing compute budgets and changing tip receivers and block builders.
- **Use**: This variable is used as a base configuration for initializing and managing crank operations in the `fd_bundle_crank_gen_init` function.


---
### null\_addr
- **Type**: `fd_acct_addr_t`
- **Description**: The `null_addr` is a static constant of type `fd_acct_addr_t` initialized to zero. This suggests it is used as a placeholder or default value for account addresses in the system.
- **Use**: `null_addr` is used as a null or invalid key in the `pidx_map` to represent an uninitialized or default state for account addresses.


# Functions

---
### fd\_bundle\_crank\_gen\_init<!-- {{#callable:fd_bundle_crank_gen_init}} -->
The `fd_bundle_crank_gen_init` function initializes a `fd_bundle_crank_gen_t` structure with specified program addresses and commission basis points, setting up the necessary configurations for tip distribution and payment programs.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_bundle_crank_gen_t` structure will be initialized.
    - `tip_distribution_program_addr`: A constant pointer to the address of the tip distribution program.
    - `tip_payment_program_addr`: A constant pointer to the address of the tip payment program.
    - `validator_vote_acct_addr`: A constant pointer to the address of the validator vote account.
    - `merkle_root_authority_addr`: A constant pointer to the address of the Merkle root authority.
    - `commission_bps`: An unsigned long representing the commission basis points for the tip distribution account.
- **Control Flow**:
    - Cast the memory pointer to a `fd_bundle_crank_gen_t` pointer and assign it to `g`.
    - Copy base configurations from `fd_bundle_crank_3_base` and `fd_bundle_crank_2_base` into `g->crank3` and `g->crank2`, respectively.
    - Set the commission basis points in `g->crank3->init_tip_distribution_acct`.
    - Copy the provided program and account addresses into the corresponding fields in `g->crank3`.
    - Initialize `tip_payment_accounts` in `g->crank3` by generating program addresses using a seed and the `fd_pubkey_find_program_address` function.
    - Generate and set program addresses for `tip_payment_program_config` and `tip_distribution_program_config` using a common seed.
    - Copy relevant fields from `g->crank3` to `g->crank2` to ensure both cranks are synchronized.
    - Parse transactions for `g->crank3` and `g->crank2` using `fd_txn_parse`.
    - Initialize a new map for account indices and insert various account addresses with specific indices into the map.
    - Set `g->configured_epoch` to `ULONG_MAX` to indicate the configuration is complete.
    - Return the initialized `fd_bundle_crank_gen_t` pointer `g`.
- **Output**: A pointer to the initialized `fd_bundle_crank_gen_t` structure.


---
### fd\_bundle\_crank\_update\_epoch<!-- {{#callable:fd_bundle_crank_update_epoch}} -->
The `fd_bundle_crank_update_epoch` function updates the epoch and recalculates the new tip receiver address for a given crank generator.
- **Inputs**:
    - `g`: A pointer to an `fd_bundle_crank_gen_t` structure, representing the crank generator to be updated.
    - `epoch`: An unsigned long integer representing the new epoch value to be set.
- **Control Flow**:
    - A packed structure `seeds` is initialized with a fixed tip distribution account string, the validator vote account from `g->crank3`, and the provided `epoch` value.
    - The size of the `seeds` structure is asserted to be 64 bytes (24 + 32 + 8).
    - A pointer to the `seeds` structure is created and passed to `fd_pubkey_find_program_address` to find the new tip receiver address.
    - The function checks if the address finding operation is successful using `FD_TEST`.
    - The new tip receiver address is copied from `g->crank3` to `g->crank2`.
    - The `configured_epoch` of the crank generator `g` is updated to the new `epoch`.
- **Output**: The function does not return a value; it updates the state of the crank generator `g` by setting the new tip receiver address and updating the configured epoch.


---
### fd\_bundle\_crank\_get\_addresses<!-- {{#callable:fd_bundle_crank_get_addresses}} -->
The function `fd_bundle_crank_get_addresses` retrieves the tip payment program configuration and the new tip receiver addresses for a given epoch, updating the epoch if necessary.
- **Inputs**:
    - `gen`: A pointer to an `fd_bundle_crank_gen_t` structure, which contains the configuration and state for the crank generation.
    - `epoch`: An unsigned long integer representing the current epoch to be checked or updated.
    - `out_tip_payment_config`: A pointer to an `fd_acct_addr_t` structure where the tip payment program configuration address will be stored.
    - `out_tip_receiver`: A pointer to an `fd_acct_addr_t` structure where the new tip receiver address will be stored.
- **Control Flow**:
    - Check if the provided epoch is different from the configured epoch in the `gen` structure.
    - If the epochs differ, call [`fd_bundle_crank_update_epoch`](#fd_bundle_crank_update_epoch) to update the epoch in the `gen` structure.
    - Copy the tip payment program configuration address from `gen->crank3->tip_payment_program_config` to `out_tip_payment_config`.
    - Copy the new tip receiver address from `gen->crank3->new_tip_receiver` to `out_tip_receiver`.
- **Output**: The function does not return a value; it outputs the addresses through the pointers `out_tip_payment_config` and `out_tip_receiver`.
- **Functions called**:
    - [`fd_bundle_crank_update_epoch`](#fd_bundle_crank_update_epoch)


---
### fd\_bundle\_crank\_generate<!-- {{#callable:fd_bundle_crank_generate}} -->
The `fd_bundle_crank_generate` function generates a transaction payload and transaction data for a bundle crank operation, ensuring proper configuration and avoiding duplicate account issues.
- **Inputs**:
    - `gen`: A pointer to an `fd_bundle_crank_gen_t` structure, which holds the state and configuration for the bundle crank operation.
    - `old_tip_payment_config`: A pointer to a constant `fd_bundle_crank_tip_payment_config_t` structure representing the old tip payment configuration.
    - `new_block_builder`: A pointer to a constant `fd_acct_addr_t` structure representing the new block builder's account address.
    - `identity`: A pointer to a constant `fd_acct_addr_t` structure representing the identity account address.
    - `tip_receiver_owner`: A pointer to a constant `fd_acct_addr_t` structure representing the tip receiver owner's account address.
    - `epoch`: An unsigned long integer representing the current epoch.
    - `block_builder_commission`: An unsigned long integer representing the commission percentage for the block builder.
    - `out_payload`: A pointer to an unsigned char array where the generated payload will be stored.
    - `out_txn`: A pointer to an `fd_txn_t` structure where the generated transaction data will be stored.
- **Control Flow**:
    - Check if the current epoch is different from the configured epoch in `gen`, and update it if necessary.
    - Verify the discriminator of the `old_tip_payment_config` to ensure it matches the expected value; log a warning and return `ULONG_MAX` if it doesn't.
    - Determine if a swap is needed by comparing `tip_receiver_owner` with `gen->crank3->tip_distribution_program`.
    - Check if the old tip payment configuration matches the expected values; if so, return 0 indicating no changes are needed.
    - If a swap is needed, update `gen->crank3` with the new configuration values; otherwise, update `gen->crank2`.
    - Insert the `identity`, `new_tip_receiver`, and `new_block_builder` into a map to ensure they are not duplicates; remove them if they are already present and return `ULONG_MAX`.
    - Query and potentially insert the `old_tip_receiver` and `old_block_builder` into the map, handling duplicates by perturbing their values.
    - Update the account indices in `gen->crank3` and `gen->crank2` based on the map indices of the old and new accounts.
    - Remove the inserted map entries to clean up.
    - Copy the appropriate crank and transaction data to `out_payload` and `out_txn` based on whether a swap was needed, and return the size of the copied data.
- **Output**: The function returns an unsigned long integer indicating the size of the generated payload, or `ULONG_MAX` if an error occurs.
- **Functions called**:
    - [`fd_bundle_crank_update_epoch`](#fd_bundle_crank_update_epoch)


---
### fd\_bundle\_crank\_apply<!-- {{#callable:fd_bundle_crank_apply}} -->
The `fd_bundle_crank_apply` function updates the tip payment configuration and tip receiver owner based on the current epoch and block builder commission.
- **Inputs**:
    - `gen`: A pointer to an `fd_bundle_crank_gen_t` structure, which contains the current state and configuration for the crank.
    - `tip_payment_config`: A pointer to an `fd_bundle_crank_tip_payment_config_t` structure, which will be updated with the new tip receiver and block builder information.
    - `new_block_builder`: A constant pointer to an `fd_acct_addr_t` structure representing the new block builder's account address.
    - `tip_receiver_owner`: A pointer to an `fd_acct_addr_t` structure where the tip receiver owner's address will be stored.
    - `epoch`: An unsigned long integer representing the current epoch.
    - `block_builder_commission`: An unsigned long integer representing the commission percentage for the block builder.
- **Control Flow**:
    - Check if the current epoch is different from the configured epoch in `gen`; if so, call [`fd_bundle_crank_update_epoch`](#fd_bundle_crank_update_epoch) to update it.
    - Copy the tip distribution program address from `gen->crank3` to `tip_receiver_owner`.
    - Copy the new tip receiver address from `gen->crank3` to `tip_payment_config->tip_receiver`.
    - Copy the new block builder address to `tip_payment_config->block_builder`.
    - Set the commission percentage in `tip_payment_config` to `block_builder_commission`.
- **Output**: The function does not return a value; it modifies the `tip_payment_config` and `tip_receiver_owner` structures in place.
- **Functions called**:
    - [`fd_bundle_crank_update_epoch`](#fd_bundle_crank_update_epoch)


