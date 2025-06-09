# Purpose
This C header file, `fd_bundle_crank.h`, defines the structures and functions necessary for managing and generating "crank transactions" within a distributed system, likely related to blockchain or distributed ledger technology. The primary focus of this file is to facilitate the creation and updating of a "tip distribution account," which is a mechanism for distributing transaction fees or rewards to validators or other participants in the network. The file provides a clear API for initializing a crank transaction generator, retrieving necessary account addresses, generating transactions, and applying updates to the tip payment configuration.

The file defines several key structures, such as `fd_bundle_crank_gen_t`, which is used to manage the state and configuration of the crank transaction generator. It also includes detailed transaction structures, `fd_bundle_crank_3` and `fd_bundle_crank_2`, which represent different types of transactions that can be generated. The functions provided, such as [`fd_bundle_crank_gen_init`](#fd_bundle_crank_gen_init), [`fd_bundle_crank_generate`](#fd_bundle_crank_generate), and [`fd_bundle_crank_apply`](#fd_bundle_crank_apply), offer a comprehensive interface for initializing the generator, producing transactions, and applying changes to the system state. This header file is intended to be included in other C source files, providing a modular and reusable component for managing crank transactions in a distributed system.
# Imports and Dependencies

---
- `../fd_disco_base.h`
- `../../ballet/txn/fd_txn.h`
- `../../flamenco/runtime/fd_system_ids_pp.h`
- `fd_bundle_crank_constants.h`


# Global Variables

---
### fd\_bundle\_crank\_gen\_init
- **Type**: `fd_bundle_crank_gen_t *`
- **Description**: The `fd_bundle_crank_gen_init` function initializes a bundle crank generator, which is used to produce bundle crank transactions. It requires a memory region with suitable alignment and footprint for a `fd_bundle_crank_gen_t` structure, and it performs precomputation tasks that are computationally expensive, such as SHA256 calculations. The function also takes several account addresses and a commission rate as parameters, which are used in the transaction generation process.
- **Use**: This variable is used to initialize a bundle crank generator for producing transactions, ensuring that the necessary precomputations are done once per epoch rather than for each slot.


# Data Structures

---
### fd\_bundle\_crank\_gen\_t
- **Type**: `struct`
- **Members**:
    - `crank3`: An instance of fd_bundle_crank_3_t, representing a transaction that initializes and updates.
    - `crank2`: An instance of fd_bundle_crank_2_t, representing a transaction that only updates.
    - `txn3`: A byte array aligned to fd_txn_t, used to store transaction data for crank3.
    - `txn2`: A byte array aligned to fd_txn_t, used to store transaction data for crank2.
    - `configured_epoch`: Stores the epoch number for which the generator is configured.
    - `map`: An array of fd_bundle_crank_gen_pidx_t, used for mapping purposes.
- **Description**: The fd_bundle_crank_gen_t structure is a private data structure used to manage and generate bundle crank transactions, which are essential for updating and initializing tip distribution accounts in a blockchain system. It contains two main transaction types, crank3 and crank2, which handle different transaction scenarios. The structure also includes aligned byte arrays for storing transaction data, a configured epoch to track the current epoch configuration, and a mapping array for internal indexing purposes. This structure is crucial for efficiently managing the precomputation and execution of transactions related to tip distribution and payment programs.


---
### fd\_bundle\_crank\_tip\_payment\_config
- **Type**: `struct`
- **Members**:
    - `discriminator`: A unique identifier for the structure, set to 0x82ccfa1ee0aa0c9b.
    - `tip_receiver`: An array containing the address of the tip receiver account.
    - `block_builder`: An array containing the address of the block builder account.
    - `commission_pct`: The commission percentage for the tip payment.
    - `bumps`: An array of 9 unsigned characters used for internal configuration or state tracking.
- **Description**: The `fd_bundle_crank_tip_payment_config` structure is a packed data structure that defines the configuration for tip payments in a blockchain context. It includes a unique discriminator for identification, addresses for the tip receiver and block builder, a commission percentage for the payment, and a series of bump values for internal use. This structure is used to manage and configure the distribution of tips to validators and block builders within the system.


---
### fd\_bundle\_crank\_tip\_payment\_config\_t
- **Type**: `struct`
- **Members**:
    - `discriminator`: A unique identifier for the structure, set to 0x82ccfa1ee0aa0c9b.
    - `tip_receiver`: An array containing the account address of the tip receiver.
    - `block_builder`: An array containing the account address of the block builder.
    - `commission_pct`: The commission percentage for the tip payment.
    - `bumps`: An array of 9 bytes used for bumping purposes.
- **Description**: The `fd_bundle_crank_tip_payment_config_t` structure represents the layout of the tip payment configuration account on the blockchain. It includes a discriminator for identifying the structure, addresses for the tip receiver and block builder, a commission percentage, and a series of bump bytes for managing account state changes. This structure is crucial for managing and updating the tip payment configurations in a blockchain environment, ensuring that the correct accounts and commission rates are applied during transactions.


---
### fd\_bundle\_crank\_3\_t
- **Type**: `struct`
- **Members**:
    - `sig_cnt`: The number of signatures, set to 1.
    - `signature`: A 64-byte array representing the transaction signature.
    - `_sig_cnt`: A duplicate of sig_cnt, set to 1.
    - `ro_signed_cnt`: The count of read-only signed accounts, set to 0.
    - `ro_unsigned_cnt`: The count of read-only unsigned accounts, set to 5.
    - `acct_addr_cnt`: The total number of account addresses, set to 20.
    - `authorized_voter`: A 32-byte array representing the authorized voter's address.
    - `tip_payment_accounts`: An array of eight 32-byte arrays for tip payment accounts.
    - `tip_distribution_program_config`: A 32-byte array for the tip distribution program configuration.
    - `tip_payment_program_config`: A 32-byte array for the tip payment program configuration.
    - `old_tip_receiver`: A 32-byte array for the old tip receiver's address.
    - `old_block_builder`: A 32-byte array for the old block builder's address.
    - `new_tip_receiver`: A 32-byte array for the new tip receiver's address.
    - `new_block_builder`: A 32-byte array for the new block builder's address.
    - `compute_budget_program`: A 32-byte array for the compute budget program address.
    - `tip_payment_program`: A 32-byte array for the tip payment program address.
    - `validator_vote_account`: A 32-byte array for the validator vote account address.
    - `system_program`: A 32-byte array for the system program address.
    - `tip_distribution_program`: A 32-byte array for the tip distribution program address.
    - `recent_blockhash`: A 32-byte array for the recent blockhash.
    - `instr_cnt`: The number of instructions, set to 4.
    - `compute_budget_instruction`: A nested struct for the compute budget instruction.
    - `init_tip_distribution_acct`: A nested struct for initializing the tip distribution account.
    - `change_tip_receiver`: A nested struct for changing the tip receiver.
    - `change_block_builder`: A nested struct for changing the block builder.
- **Description**: The `fd_bundle_crank_3_t` structure is a packed data structure used to represent a specific type of transaction payload in a blockchain system. It includes fields for managing transaction signatures, account addresses, and various instructions related to tip distribution and block building. The structure is designed to handle both initialization and update operations for tip distribution accounts, and it contains several nested structures for specific transaction instructions, such as computing budget limits, initializing tip distribution accounts, and changing tip receivers and block builders. This structure is part of a larger system for managing crank transactions, which are used to update or initialize accounts in a blockchain network.


---
### fd\_bundle\_crank\_2\_t
- **Type**: `struct`
- **Members**:
    - `sig_cnt`: The number of signatures, set to 1.
    - `signature`: A 64-byte array holding the transaction signature.
    - `_sig_cnt`: A duplicate of sig_cnt, set to 1.
    - `ro_signed_cnt`: The count of read-only signed accounts, set to 0.
    - `ro_unsigned_cnt`: The count of read-only unsigned accounts, set to 2.
    - `acct_addr_cnt`: The total number of account addresses, set to 17.
    - `authorized_voter`: A 32-byte array for the authorized voter's public key.
    - `tip_payment_accounts`: An array of eight 32-byte arrays for tip payment accounts.
    - `tip_distribution_program_config`: A 32-byte array for the tip distribution program configuration.
    - `tip_payment_program_config`: A 32-byte array for the tip payment program configuration.
    - `old_tip_receiver`: A 32-byte array for the old tip receiver's public key.
    - `old_block_builder`: A 32-byte array for the old block builder's public key.
    - `new_tip_receiver`: A 32-byte array for the new tip receiver's public key.
    - `new_block_builder`: A 32-byte array for the new block builder's public key.
    - `compute_budget_program`: A 32-byte array for the compute budget program.
    - `tip_payment_program`: A 32-byte array for the tip payment program.
    - `recent_blockhash`: A 32-byte array for the recent blockhash.
    - `instr_cnt`: The number of instructions, set to 3.
    - `compute_budget_instruction`: A nested struct defining the compute budget instruction.
    - `change_tip_receiver`: A nested struct defining the change tip receiver instruction.
    - `change_block_builder`: A nested struct defining the change block builder instruction.
- **Description**: The `fd_bundle_crank_2_t` structure is a packed data structure used to represent a specific type of transaction that updates the tip distribution and block builder configurations without initializing new accounts. It includes fields for transaction metadata such as signature count, account addresses, and recent blockhash, as well as nested structures for specific instructions like changing the tip receiver and block builder. This structure is designed to handle the update-only transactions in a blockchain environment, ensuring efficient processing and management of account configurations.


---
### fd\_bundle\_crank\_3
- **Type**: `struct`
- **Members**:
    - `sig_cnt`: Indicates the number of signatures, initialized to 1.
    - `signature`: An array of 64 unsigned characters representing the signature.
    - `_sig_cnt`: A duplicate signature count, also initialized to 1.
    - `ro_signed_cnt`: Count of readonly signed accounts, initialized to 0.
    - `ro_unsigned_cnt`: Count of readonly unsigned accounts, initialized to 5.
    - `acct_addr_cnt`: Total number of account addresses, initialized to 20.
    - `authorized_voter`: An array of 32 unsigned characters representing the authorized voter.
    - `tip_payment_accounts`: An array of 8 arrays, each containing 32 unsigned characters for tip payment accounts.
    - `tip_distribution_program_config`: An array of 32 unsigned characters for the tip distribution program configuration.
    - `tip_payment_program_config`: An array of 32 unsigned characters for the tip payment program configuration.
    - `old_tip_receiver`: An array of 32 unsigned characters for the old tip receiver.
    - `old_block_builder`: An array of 32 unsigned characters for the old block builder.
    - `new_tip_receiver`: An array of 32 unsigned characters for the new tip receiver.
    - `new_block_builder`: An array of 32 unsigned characters for the new block builder.
    - `compute_budget_program`: An array of 32 unsigned characters for the compute budget program.
    - `tip_payment_program`: An array of 32 unsigned characters for the tip payment program.
    - `validator_vote_account`: An array of 32 unsigned characters for the validator vote account.
    - `system_program`: An array of 32 unsigned characters for the system program.
    - `tip_distribution_program`: An array of 32 unsigned characters for the tip distribution program.
    - `recent_blockhash`: An array of 32 unsigned characters for the recent blockhash.
    - `instr_cnt`: Indicates the number of instructions, initialized to 4.
    - `compute_budget_instruction`: A nested struct for compute budget instruction with program ID, account count, data size, CU limit, and CUs.
    - `init_tip_distribution_acct`: A nested struct for initializing the tip distribution account with program ID, account count, account indices, data size, discriminator, authority, commission, and bump.
    - `change_tip_receiver`: A nested struct for changing the tip receiver with program ID, account count, account indices, data size, and discriminator.
    - `change_block_builder`: A nested struct for changing the block builder with program ID, account count, account indices, data size, discriminator, and commission percentage.
- **Description**: The `fd_bundle_crank_3` structure is a packed C struct used to define a complex transaction bundle for managing tip distribution and block building in a blockchain environment. It includes fields for signature management, account addresses, and several nested structures for specific instructions such as computing budget, initializing tip distribution accounts, and changing tip receivers and block builders. The structure is designed to handle multiple accounts and instructions, facilitating the execution of transactions that involve updating or initializing tip distribution accounts and managing block builder commissions.


---
### fd\_bundle\_crank\_2
- **Type**: `struct`
- **Members**:
    - `sig_cnt`: Indicates the number of signatures, initialized to 1.
    - `signature`: An array of 64 unsigned characters representing the signature.
    - `_sig_cnt`: A duplicate of sig_cnt, also initialized to 1.
    - `ro_signed_cnt`: Indicates the count of readonly signed accounts, initialized to 0.
    - `ro_unsigned_cnt`: Indicates the count of readonly unsigned accounts, initialized to 2.
    - `acct_addr_cnt`: Indicates the total number of account addresses, initialized to 17.
    - `authorized_voter`: An array of 32 unsigned characters representing the authorized voter.
    - `tip_payment_accounts`: An 8x32 array of unsigned characters for writable non-signer tip payment accounts.
    - `tip_distribution_program_config`: An array of 32 unsigned characters for the tip distribution program configuration.
    - `tip_payment_program_config`: An array of 32 unsigned characters for the tip payment program configuration.
    - `old_tip_receiver`: An array of 32 unsigned characters for the old tip receiver.
    - `old_block_builder`: An array of 32 unsigned characters for the old block builder.
    - `new_tip_receiver`: An array of 32 unsigned characters for the new tip receiver.
    - `new_block_builder`: An array of 32 unsigned characters for the new block builder.
    - `compute_budget_program`: An array of 32 unsigned characters for the compute budget program.
    - `tip_payment_program`: An array of 32 unsigned characters for the tip payment program.
    - `recent_blockhash`: An array of 32 unsigned characters representing the recent blockhash.
    - `instr_cnt`: Indicates the number of instructions, initialized to 3.
    - `compute_budget_instruction`: A nested struct defining the compute budget instruction with program ID, account count, data size, CU limit, and CU count.
    - `change_tip_receiver`: A nested struct defining the change tip receiver instruction with program ID, account count, account indices, data size, and instruction discriminator.
    - `change_block_builder`: A nested struct defining the change block builder instruction with program ID, account count, account indices, data size, instruction discriminator, and block builder commission percentage.
- **Description**: The `fd_bundle_crank_2` structure is a packed data structure used to represent a specific type of transaction bundle in a blockchain system. It includes fields for managing signatures, account addresses, and various program configurations related to tip payments and block building. The structure also contains nested structures for specific instructions, such as computing budget limits and changing tip receivers or block builders, which are essential for executing and managing transactions within the system. This structure is designed to be compact and efficient, facilitating the update of tip distribution accounts without creating new ones.


---
### fd\_bundle\_crank\_gen\_pidx\_t
- **Type**: `struct`
- **Members**:
    - `key`: A field of type `fd_acct_addr_t` representing an account address key.
    - `idx`: An unsigned long integer representing an index.
- **Description**: The `fd_bundle_crank_gen_pidx_t` structure is a simple data structure consisting of two members: a key of type `fd_acct_addr_t` and an index of type `ulong`. It is used to map account addresses to indices, likely for efficient lookup or referencing within the context of bundle crank generation in a distributed system. This structure is part of a larger system for managing crank transactions, which are operations related to updating or creating tip distribution accounts in a blockchain environment.


---
### fd\_bundle\_crank\_gen\_private
- **Type**: `struct`
- **Members**:
    - `crank3`: An array of one fd_bundle_crank_3_t structure, representing a type of crank transaction that includes initialization and update.
    - `crank2`: An array of one fd_bundle_crank_2_t structure, representing a type of crank transaction that only includes updates.
    - `txn3`: A uchar array sized to hold a transaction with four instructions, aligned to the alignment of fd_txn_t.
    - `txn2`: A uchar array sized to hold a transaction with three instructions, aligned to the alignment of fd_txn_t.
    - `configured_epoch`: An unsigned long integer representing the epoch for which the generator is configured.
    - `map`: An array of 32 fd_bundle_crank_gen_pidx_t structures, used for mapping purposes.
- **Description**: The `fd_bundle_crank_gen_private` structure is designed to manage and generate crank transactions within a distributed system, specifically for handling tip distribution and payment updates. It contains two types of crank transaction structures (`crank3` and `crank2`), which are used for different transaction operations. The structure also includes arrays for transaction data (`txn3` and `txn2`), which are aligned to ensure proper memory access. The `configured_epoch` member tracks the epoch configuration, while the `map` array provides a mapping mechanism for transaction processing. This structure is integral to the initialization and generation of bundle crank transactions, optimizing the process by precomputing necessary data.


# Function Declarations (Public API)

---
### fd\_bundle\_crank\_gen\_init<!-- {{#callable_declaration:fd_bundle_crank_gen_init}} -->
Initialize a bundle crank generator for producing transactions.
- **Description**: This function initializes a bundle crank generator, preparing it to produce bundle crank transactions efficiently. It should be called once per epoch to avoid repeated expensive computations. The function requires a memory region with appropriate alignment and size for a `fd_bundle_crank_gen_t` structure. The function also requires non-null pointers to account addresses for the tip distribution program, tip payment program, validator vote account, and Merkle root authority. The commission rate, specified in basis points, must be between 0 and 10,000. The function returns the initialized memory region, ready for use in generating transactions.
- **Inputs**:
    - `mem`: A pointer to a memory region with suitable alignment and size for a `fd_bundle_crank_gen_t`. The caller retains ownership.
    - `tip_distribution_program_addr`: A non-null pointer to the account address of the tip distribution program. Must point to a valid 32-byte region.
    - `tip_payment_program_addr`: A non-null pointer to the account address of the tip payment program. Must point to a valid 32-byte region.
    - `validator_vote_acct_addr`: A non-null pointer to the pubkey for the validator's vote account. Must point to a valid 32-byte region.
    - `merkle_root_authority_addr`: A non-null pointer to a pubkey for the Merkle root authority. Must point to a valid 32-byte region.
    - `commission_bps`: The validator's tip commission in basis points, must be in the range [0, 10,000].
- **Output**: Returns a pointer to the initialized `fd_bundle_crank_gen_t` structure located at `mem`.
- **See also**: [`fd_bundle_crank_gen_init`](fd_bundle_crank.c.driver.md#fd_bundle_crank_gen_init)  (Implementation)


---
### fd\_bundle\_crank\_get\_addresses<!-- {{#callable_declaration:fd_bundle_crank_get_addresses}} -->
Retrieve account addresses for the current epoch.
- **Description**: Use this function to obtain the account addresses necessary for querying at the start of each slot. It should be called with a valid, initialized bundle crank generator and the current epoch number. The function will populate the provided memory locations with the tip payment configuration account address and the validator's tip receiver account address for the specified epoch. Ensure that the generator is properly initialized and that the output pointers point to valid memory regions capable of holding the addresses.
- **Inputs**:
    - `gen`: A pointer to a valid, initialized fd_bundle_crank_gen_t structure. The caller retains ownership and must ensure it is not null.
    - `epoch`: The epoch number for which the addresses are being queried. It must be a valid epoch number.
    - `out_tip_payment_config`: A pointer to a memory region where the tip payment configuration account address will be stored. Must not be null and must point to a region capable of holding a 32-byte address.
    - `out_tip_receiver`: A pointer to a memory region where the tip receiver account address will be stored. Must not be null and must point to a region capable of holding a 32-byte address.
- **Output**: None
- **See also**: [`fd_bundle_crank_get_addresses`](fd_bundle_crank.c.driver.md#fd_bundle_crank_get_addresses)  (Implementation)


---
### fd\_bundle\_crank\_generate<!-- {{#callable_declaration:fd_bundle_crank_generate}} -->
Produces the necessary bundle crank transactions.
- **Description**: This function is used to generate bundle crank transactions based on the current and desired configuration of the tip payment system. It should be called when there is a need to update or initialize the tip distribution account, typically when the leader changes or at the start of a new epoch. The function requires a valid initialized bundle crank generator and various account addresses and configurations as inputs. It writes the transaction payload and corresponding transaction structure to the provided output buffers if cranks are necessary. If no cranks are needed, the output buffers remain unmodified. The function returns the size of the transaction payload if cranks are necessary, 0 if no cranks are needed, or ULONG_MAX if an error occurs, logging a warning in such cases.
- **Inputs**:
    - `gen`: A pointer to a valid initialized fd_bundle_crank_gen_t structure. The caller retains ownership and it must not be null.
    - `old_tip_payment_config`: A pointer to a constant fd_bundle_crank_tip_payment_config_t structure representing the current tip payment configuration. The caller retains ownership and it must not be null.
    - `new_block_builder`: A pointer to a constant fd_acct_addr_t representing the desired block builder's address. The caller retains ownership and it must not be null.
    - `identity`: A pointer to a constant fd_acct_addr_t representing the current validator's identity pubkey. This must be an authorized voter for the vote account used in initialization. The caller retains ownership and it must not be null.
    - `tip_receiver_owner`: A pointer to a constant fd_acct_addr_t representing the pubkey of the on-chain account owner of the tip_receiver account. The caller retains ownership and it must not be null.
    - `epoch`: An unsigned long representing the epoch number of the slot in which the transaction will be submitted.
    - `block_builder_commission`: An unsigned long representing the block builder's commission in percentage points.
    - `out_payload`: A pointer to a uchar buffer where the transaction payload will be written if cranks are necessary. It must point to a region of at least sizeof(fd_bundle_crank_3_t) bytes.
    - `out_txn`: A pointer to a fd_txn_t structure where the transaction details will be written if cranks are necessary. It must point to a region of at least FD_TXN_MAX_SZ bytes.
- **Output**: Returns the size of the transaction payload written to out_payload if cranks are necessary, 0 if no cranks are needed, or ULONG_MAX if an error occurs.
- **See also**: [`fd_bundle_crank_generate`](fd_bundle_crank.c.driver.md#fd_bundle_crank_generate)  (Implementation)


---
### fd\_bundle\_crank\_apply<!-- {{#callable_declaration:fd_bundle_crank_apply}} -->
Updates the tip payment configuration and tip receiver owner based on the provided parameters.
- **Description**: This function is used to update the tip payment configuration and the tip receiver owner as if a transaction generated by `fd_bundle_crank_generate` with the same parameters was executed successfully. It should be called when you want to apply the changes that would result from such a transaction without actually executing it. This function assumes that the generator has been properly initialized and that the epoch is correctly configured. It modifies the provided tip payment configuration and tip receiver owner based on the new block builder and commission percentage.
- **Inputs**:
    - `gen`: A pointer to an initialized `fd_bundle_crank_gen_t` structure. It must not be null and should be properly configured for the current epoch.
    - `tip_payment_config`: A pointer to a `fd_bundle_crank_tip_payment_config_t` structure that will be updated. The caller must ensure this is a valid, non-null pointer.
    - `new_block_builder`: A pointer to a `fd_acct_addr_t` structure representing the new block builder. This must be a valid, non-null pointer.
    - `tip_receiver_owner`: A pointer to a `fd_acct_addr_t` structure that will be updated to reflect the new tip receiver owner. The caller must ensure this is a valid, non-null pointer.
    - `epoch`: An unsigned long representing the epoch number. It should match the configured epoch in the generator.
    - `block_builder_commission`: An unsigned long representing the block builder's commission percentage. It should be a valid percentage value.
- **Output**: None
- **See also**: [`fd_bundle_crank_apply`](fd_bundle_crank.c.driver.md#fd_bundle_crank_apply)  (Implementation)


