# Purpose
This C header file, `fd_genesis_create.h`, is designed for creating Solana genesis blobs, which are essential for initializing a Solana ledger. It defines a structure, `fd_genesis_options_t`, that encapsulates various configuration parameters necessary for genesis creation, such as public keys, balances, and timing configurations. The file includes a function prototype for [`fd_genesis_create`](#fd_genesis_create), which generates a genesis blob in a specified memory region based on the provided options. The function returns the size of the generated blob or zero on failure, and it is intended for development purposes rather than production use. The header also includes necessary dependencies and notes on memory requirements for intermediate data processing.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `../features/fd_features.h`


# Data Structures

---
### fd\_genesis\_options
- **Type**: `struct`
- **Members**:
    - `identity_pubkey`: The public key identifying the entity.
    - `faucet_pubkey`: The public key for the faucet account.
    - `stake_pubkey`: The public key for the stake account.
    - `vote_pubkey`: The public key for the vote account.
    - `creation_time`: The Unix timestamp indicating when the genesis was created.
    - `faucet_balance`: The initial balance of the faucet account in lamports.
    - `vote_account_stake`: The initial stake of the vote account in lamports.
    - `hashes_per_tick`: The number of hashes per tick, with 0 indicating unset.
    - `ticks_per_slot`: The number of ticks per slot.
    - `target_tick_duration_micros`: The target duration of a tick in microseconds.
    - `fund_initial_accounts`: The number of initial accounts to fund.
    - `fund_initial_amount_lamports`: The amount of lamports to fund initial accounts with.
    - `warmup_epochs`: The number of epochs for warmup.
    - `features`: A pointer to an externally owned feature map for enabling features at slot 0.
- **Description**: The `fd_genesis_options` structure is used to specify configuration parameters for creating a Solana genesis blob, which is essential for bootstrapping a Solana ledger. It includes public keys for identity, faucet, stake, and vote accounts, as well as various parameters related to timing, funding, and features. The structure allows for detailed customization of the genesis environment, including setting initial balances, stake amounts, and enabling features through an external feature map.


---
### fd\_genesis\_options\_t
- **Type**: `struct`
- **Members**:
    - `identity_pubkey`: The public key identifying the genesis entity.
    - `faucet_pubkey`: The public key for the faucet account.
    - `stake_pubkey`: The public key for the stake account.
    - `vote_pubkey`: The public key for the vote account.
    - `creation_time`: The Unix time when the genesis is created.
    - `faucet_balance`: The initial balance of the faucet account in lamports.
    - `vote_account_stake`: The initial stake for the vote account in lamports.
    - `hashes_per_tick`: The number of hashes per tick, with 0 indicating unset.
    - `ticks_per_slot`: The number of ticks per slot.
    - `target_tick_duration_micros`: The target duration of a tick in microseconds.
    - `fund_initial_accounts`: The number of initial accounts to fund.
    - `fund_initial_amount_lamports`: The amount of lamports to fund initial accounts with.
    - `warmup_epochs`: The number of warmup epochs.
    - `features`: A pointer to a feature map for enabling features at slot 0.
- **Description**: The `fd_genesis_options_t` structure is used to specify configuration options for creating a Solana genesis blob, which is essential for bootstrapping a Solana ledger. It includes public keys for various accounts, timing and balance parameters, and a pointer to a feature map for enabling features at the genesis block. This structure allows for detailed customization of the genesis creation process, including setting initial balances, stake amounts, and timing configurations.


# Function Declarations (Public API)

---
### fd\_genesis\_create<!-- {{#callable_declaration:fd_genesis_create}} -->
Create a Solana genesis blob in the specified buffer.
- **Description**: This function generates a Solana genesis blob, which is used to bootstrap a Solana ledger, and writes it into the provided buffer. It should be used in development environments to create a 'genesis.bin' compatible blob based on the specified options. The caller must ensure that the buffer is large enough to hold the resulting blob and that the function is called within a context that has access to sufficient scratch memory for intermediate data. The function is not intended for production use and will return the number of bytes written to the buffer on success, or 0 on failure, logging the error cause.
- **Inputs**:
    - `buf`: A pointer to the memory region where the genesis blob will be written. The buffer must be large enough to accommodate the blob. The caller retains ownership and must ensure the buffer is valid.
    - `bufsz`: The size of the buffer in bytes. It must be large enough to hold the resulting genesis blob. If the buffer is too small, the function will fail and return 0.
    - `options`: A pointer to a constant fd_genesis_options_t structure containing the configuration parameters for the genesis blob. This must not be null, and the caller retains ownership of the options structure.
- **Output**: Returns the number of bytes written to the buffer on success, or 0 on failure.
- **See also**: [`fd_genesis_create`](fd_genesis_create.c.driver.md#fd_genesis_create)  (Implementation)


