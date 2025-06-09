# Purpose
This C source code file is designed to handle the creation and management of a "genesis" file, specifically a `genesis.bin` file, which is a critical component in blockchain systems for initializing the state of a blockchain network. The file includes functionality to estimate the Proof of History (PoH) hash rate, create the genesis file with specific configurations, and manage the file's lifecycle, including initialization, finalization, and configuration checks. The code is structured to ensure that the genesis file is created with the correct permissions and includes features such as setting up initial account balances, configuring PoH parameters, and enabling or disabling specific blockchain features.

The file imports several external libraries and modules, indicating its reliance on shared utilities and platform-specific functions. It defines a static function [`default_enable_features`](#default_enable_features) to configure default blockchain features, and another function [`estimate_hashes_per_tick`](#estimate_hashes_per_tick) to approximate the PoH hash rate. The [`create_genesis`](#create_genesis) function is central to the file, responsible for generating the genesis file content based on provided configurations, including loading cryptographic keys and setting up initial blockchain parameters. The [`init`](#init), [`fini`](#fini), and [`check`](#check) functions manage the lifecycle of the genesis file, ensuring it is correctly created, removed, and verified. The file defines a `configure_stage_t` structure, `fd_cfg_stage_genesis`, which encapsulates these lifecycle functions, indicating that this code is part of a larger configuration management system.
# Imports and Dependencies

---
- `../../../shared/commands/configure/configure.h`
- `../../../platform/fd_file_util.h`
- `../../../shared/genesis_hash.h`
- `../../../../ballet/poh/fd_poh.h`
- `../../../../disco/keyguard/fd_keyload.h`
- `../../../../flamenco/features/fd_features.h`
- `../../../../flamenco/genesis/fd_genesis_create.h`
- `../../../../flamenco/types/fd_types_custom.h`
- `../../../../flamenco/runtime/sysvar/fd_sysvar_clock.h`
- `stdio.h`
- `unistd.h`
- `dirent.h`
- `sys/stat.h`
- `sys/wait.h`


# Global Variables

---
### fd\_cfg\_stage\_genesis
- **Type**: `configure_stage_t`
- **Description**: The `fd_cfg_stage_genesis` is a global variable of type `configure_stage_t` that represents a configuration stage for the genesis process in a distributed system. It includes function pointers for initialization (`init`), finalization (`fini`), and checking (`check`) of the genesis configuration. The `always_recreate` field is set to 1, indicating that the genesis.bin file should always be recreated due to the presence of a timestamp and variable hashes per tick, which complicate comparison.
- **Use**: This variable is used to manage the lifecycle of the genesis configuration, ensuring that the genesis.bin file is always recreated to maintain consistency.


# Functions

---
### default\_enable\_features<!-- {{#callable:default_enable_features}} -->
The `default_enable_features` function initializes a set of feature flags in a `fd_features_t` structure to their default values, primarily setting them to disabled (0UL) except for `reject_callx_r10` which is enabled (1UL).
- **Inputs**:
    - `features`: A pointer to an `fd_features_t` structure where the feature flags will be set to their default values.
- **Control Flow**:
    - The function iterates over each feature flag in the `fd_features_t` structure.
    - Each feature flag is set to 0UL, indicating it is disabled by default.
    - The `reject_callx_r10` feature is set to 1UL, indicating it is enabled by default.
- **Output**: The function does not return a value; it modifies the `fd_features_t` structure pointed to by the input argument.


---
### estimate\_hashes\_per\_tick<!-- {{#callable:estimate_hashes_per_tick}} -->
The function `estimate_hashes_per_tick` estimates the number of hashes that can be computed per tick based on a given tick rate and duration.
- **Inputs**:
    - `tick_mhz`: The target tick rate in ticks per microsecond (MHz).
    - `estimate_dur_ns`: The duration in nanoseconds for which the PoH hashing should be performed to estimate the hash rate.
- **Control Flow**:
    - Initialize a constant `batch` to 2^20 and calculate a `deadline` as the current wall clock time plus `estimate_dur_ns`.
    - Initialize a 32-byte array `poh_hash` to zero and a counter `hash_cnt` to zero.
    - Enter a loop that continues until the current wall clock time is less than `deadline`.
    - In each iteration of the loop, call `fd_poh_append` with `poh_hash` and `batch`, and increment `hash_cnt` by `batch`.
    - After the loop, calculate `hash_cnt_dbl` as the double representation of `hash_cnt` and `tick_cnt_dbl` as the double representation of `estimate_dur_ns` divided by `tick_mhz` times 1000.
    - If `tick_cnt_dbl` is less than 1.0, return 0.
    - Calculate `hashes_per_tick` as `hash_cnt_dbl` divided by `tick_cnt_dbl` and then divided by 2.
    - Return `hashes_per_tick` cast to an unsigned long.
- **Output**: The function returns an unsigned long representing the estimated number of hashes that can be computed per tick.


---
### create\_genesis<!-- {{#callable:create_genesis}} -->
The `create_genesis` function generates a genesis blob for a blockchain configuration and returns its size.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing paths and genesis configuration details.
    - `blob`: A pointer to a buffer where the genesis blob will be stored.
    - `blob_max`: The maximum size of the blob buffer.
- **Control Flow**:
    - Initialize a `fd_genesis_options_t` structure to store genesis options.
    - Load and store public keys for identity, faucet, stake, and vote accounts from specified file paths.
    - Set the creation time, faucet balance, and vote account stake using the configuration data.
    - Determine the `hashes_per_tick` based on the configuration or estimate it if not specified.
    - Set additional genesis options such as ticks per slot, target tick duration, initial account funding, and warmup epochs.
    - Disable all features and enable a cleaned-up set of features based on the default version.
    - Attach a scratch memory for temporary storage during genesis creation.
    - Call `fd_genesis_create` to serialize the genesis options into the blob buffer and check for errors.
    - Detach the scratch memory and return the size of the created blob.
- **Output**: Returns the size of the created genesis blob as an unsigned long integer.
- **Functions called**:
    - [`estimate_hashes_per_tick`](#estimate_hashes_per_tick)
    - [`default_enable_features`](#default_enable_features)


---
### init<!-- {{#callable:init}} -->
The `init` function initializes the environment by creating a ledger directory, generating a genesis file, and setting appropriate permissions for the file.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details such as paths, user IDs, and group IDs.
- **Control Flow**:
    - Check if the ledger directory can be created using `fd_file_util_mkdir_all`; log an error if it fails.
    - Create a genesis blob using [`create_genesis`](#create_genesis) and store its size.
    - Retrieve the current user and group IDs, and switch to the target user and group specified in the configuration for file creation.
    - Set a restrictive umask to ensure the genesis file is created with the correct permissions.
    - Construct the path for the genesis file and open it for writing; write the genesis blob to the file and close it.
    - Restore the previous umask.
    - Revert the user and group IDs back to the original ones.
    - Compute the genesis hash and shred version, and log the creation details.
- **Output**: The function does not return a value; it performs initialization tasks and logs information or errors as needed.
- **Functions called**:
    - [`create_genesis`](#create_genesis)


---
### fini<!-- {{#callable:fini}} -->
The `fini` function attempts to delete the 'genesis.bin' file from the specified ledger path in the configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details, specifically the path to the ledger where 'genesis.bin' is located.
    - `pre_init`: An integer that is not used in the function body, likely included for interface consistency.
- **Control Flow**:
    - The function begins by casting `pre_init` to void, indicating it is unused.
    - A character array `genesis_path` is declared to store the full path to 'genesis.bin'.
    - The function uses `fd_cstr_printf_check` to format the path to 'genesis.bin' using the ledger path from the configuration.
    - It attempts to unlink (delete) the 'genesis.bin' file using the `unlink` function.
    - If the unlink operation fails and the error is not `ENOENT` (file not found), it logs an error message and terminates the program.
- **Output**: The function does not return a value; it performs a file deletion operation and logs an error if it fails.


---
### check<!-- {{#callable:check}} -->
The `check` function verifies the existence and permissions of the `genesis.bin` file and its directory within a specified ledger path.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details, including paths and user/group IDs.
- **Control Flow**:
    - Constructs the path to the `genesis.bin` file using the ledger path from the configuration.
    - Attempts to retrieve the file status of `genesis.bin` using `stat`; if the file does not exist, it triggers a `NOT_CONFIGURED` error.
    - Checks the directory permissions of the ledger path using `check_dir` and verifies the file permissions of `genesis.bin` using `check_file`.
    - If the file exists and permissions are correct, it triggers a `PARTIALLY_CONFIGURED` status.
- **Output**: The function returns a `configure_result_t` indicating the configuration status, either `NOT_CONFIGURED` or `PARTIALLY_CONFIGURED`.


