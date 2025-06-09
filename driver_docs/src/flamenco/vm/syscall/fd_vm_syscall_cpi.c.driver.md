# Purpose
This C source code file is part of a larger system that handles cross-program invocations (CPI) within a virtual machine (VM) environment, specifically tailored for a blockchain platform similar to Solana. The file provides functionality to manage and verify instruction accounts, ensuring that the accounts involved in a transaction have the correct permissions and signatures. It includes functions to prepare instruction accounts for execution, check for privilege escalations, and validate program IDs against known precompiled programs. The code is heavily influenced by Solana's runtime and program execution model, as evidenced by the numerous references to Solana's GitHub repository.

The file defines several constants and inline functions to handle account metadata and instruction data, ensuring that the accounts are correctly serialized and deserialized within the VM's memory space. It also includes logic to handle both C and Rust ABI (Application Binary Interface) for cross-program invocations, indicating that the system supports multiple programming languages for smart contract execution. The code is structured to ensure that all account-related operations adhere to the constraints and limits defined by the blockchain platform, such as maximum instruction data length and account information limits. This file is a critical component of the VM's runtime, providing the necessary infrastructure to securely and efficiently execute cross-program invocations.
# Imports and Dependencies

---
- `fd_vm_syscall.h`
- `../../../ballet/ed25519/fd_curve25519.h`
- `../../../util/bits/fd_uwide.h`
- `../../runtime/fd_borrowed_account.h`
- `../../runtime/fd_executor.h`
- `stdio.h`
- `fd_vm_syscall_cpi_common.c`


# Global Variables

---
### decl
- **Type**: `uchar*`
- **Description**: The `decl` variable is a pointer to an unsigned character array, which is initialized using a macro that calculates a memory address slice within a virtual machine context. This address is determined by the `FD_VM_MEM_SLICE_HADDR_ST` macro, which takes into account the alignment and length of the data slice.
- **Use**: The `decl` variable is used to access a specific memory slice in the virtual machine's memory space, likely for operations involving account data or instructions.


---
### FD\_EXPAND\_THEN\_CONCAT2
- **Type**: `ulong`
- **Description**: `FD_EXPAND_THEN_CONCAT2` is a macro that appears to be used for concatenating identifiers, specifically for creating unique variable names by appending a suffix to a base name. In this context, it is used to define a variable of type `ulong` that represents the length of some data associated with a declaration (`decl`).
- **Use**: This variable is used to store the length of data associated with a specific declaration, likely for memory management or data processing purposes.


# Functions

---
### fd\_vm\_syscall\_cpi\_is\_signer<!-- {{#callable:fd_vm_syscall_cpi_is_signer}} -->
The function `fd_vm_syscall_cpi_is_signer` checks if a given account is among a list of signer accounts.
- **Inputs**:
    - `account`: A pointer to an `fd_pubkey_t` structure representing the account to be checked.
    - `signers`: A pointer to an array of `fd_pubkey_t` structures representing the list of signer accounts.
    - `signers_cnt`: An unsigned long integer representing the number of signers in the `signers` array.
- **Control Flow**:
    - Iterates over each signer in the `signers` array up to `signers_cnt`.
    - For each signer, compares the public key of the `account` with the current signer's public key using `memcmp`.
    - If a match is found, returns 1 immediately, indicating the account is a signer.
    - If no match is found after checking all signers, returns 0.
- **Output**: Returns an integer: 1 if the account is a signer, 0 otherwise.


---
### fd\_vm\_prepare\_instruction<!-- {{#callable:fd_vm_prepare_instruction}} -->
The `fd_vm_prepare_instruction` function prepares and normalizes instruction accounts for execution by de-duplicating accounts, checking privileges, and ensuring necessary signatures are present.
- **Inputs**:
    - `callee_instr`: A pointer to an `fd_instr_info_t` structure representing the callee instruction, containing account information.
    - `instr_ctx`: A pointer to an `fd_exec_instr_ctx_t` structure representing the execution context of the instruction.
    - `callee_program_id_pubkey`: A constant pointer to an `fd_pubkey_t` representing the public key of the callee program ID.
    - `instr_acct_keys`: An array of `fd_pubkey_t` representing the instruction account keys, with a maximum size of `FD_INSTR_ACCT_MAX`.
    - `instruction_accounts`: An array of `fd_instruction_account_t` to be populated with the prepared instruction accounts, with a maximum size of `FD_INSTR_ACCT_MAX`.
    - `instruction_accounts_cnt`: A pointer to an `ulong` to store the count of prepared instruction accounts.
    - `signers`: A constant pointer to an array of `fd_pubkey_t` representing the signers' public keys.
    - `signers_cnt`: An `ulong` representing the count of signers.
- **Control Flow**:
    - Initialize counters and arrays for deduplicated accounts and duplicate indices.
    - Iterate over each account in `callee_instr` to check if it references a known transaction account.
    - If an account is unknown, log an error and return `FD_EXECUTOR_INSTR_ERR_MISSING_ACC`.
    - For known accounts, check for duplicates and update flags for signer and writable status.
    - If a duplicate is found, update the existing entry; otherwise, add a new entry to the deduplicated accounts.
    - Check for privilege escalation by ensuring writable and signer permissions are consistent with the caller's permissions.
    - Copy the deduplicated accounts to the final `instruction_accounts` array and update `callee_instr` flags.
    - Check if the callee program ID is known and executable, logging errors and returning appropriate error codes if not.
    - Set the `instruction_accounts_cnt` to the count of deduplicated accounts.
    - Return 0 on successful preparation of instruction accounts.
- **Output**: Returns an integer status code, 0 on success, or an error code if any checks fail.
- **Functions called**:
    - [`fd_vm_syscall_cpi_is_signer`](#fd_vm_syscall_cpi_is_signer)


---
### get\_cpi\_max\_account\_infos<!-- {{#callable:get_cpi_max_account_infos}} -->
The function `get_cpi_max_account_infos` determines the maximum number of account info structures that can be used in a single Cross-Program Invocation (CPI) based on the transaction context.
- **Inputs**:
    - `txn_ctx`: A pointer to a constant `fd_exec_txn_ctx_t` structure representing the transaction context, which includes the slot and features information.
- **Control Flow**:
    - The function checks if the feature `increase_tx_account_lock_limit` is active for the given transaction context using `FD_FEATURE_ACTIVE`.
    - If the feature is active, it returns `FD_CPI_MAX_ACCOUNT_INFOS`, which is defined as 128.
    - If the feature is not active, it returns 64UL.
- **Output**: The function returns an unsigned long integer representing the maximum number of account info structures allowed for a CPI, either 128 or 64 depending on the active features in the transaction context.


---
### fd\_vm\_syscall\_cpi\_check\_instruction<!-- {{#callable:fd_vm_syscall_cpi_check_instruction}} -->
The function `fd_vm_syscall_cpi_check_instruction` checks if the instruction data size and account count are within allowed limits for a cross-program invocation in a virtual machine context.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `acct_cnt`: An unsigned long integer representing the number of accounts involved in the instruction.
    - `data_sz`: An unsigned long integer representing the size of the instruction data.
- **Control Flow**:
    - Check if the feature 'loosen_cpi_size_restriction' is active using `FD_FEATURE_ACTIVE` macro.
    - If the feature is active, check if `data_sz` exceeds `FD_CPI_MAX_INSTRUCTION_DATA_LEN`; if so, log a warning and return `FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_DATA_LEN_EXCEEDED`.
    - If the feature is active, check if `acct_cnt` exceeds `FD_CPI_MAX_INSTRUCTION_ACCOUNTS`; if so, log a warning and return `FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNTS_EXCEEDED`.
    - If the feature is not active, calculate `tot_sz` as the sum of the product of `FD_VM_RUST_ACCOUNT_META_SIZE` and `acct_cnt`, and `data_sz`.
    - Check if `tot_sz` exceeds `FD_VM_MAX_CPI_INSTRUCTION_SIZE`; if so, log a warning and return `FD_VM_SYSCALL_ERR_INSTRUCTION_TOO_LARGE`.
    - If none of the above conditions are met, return `FD_VM_SUCCESS`.
- **Output**: Returns an integer status code: `FD_VM_SUCCESS` if checks pass, or an error code if any check fails.


---
### fd\_vm\_syscall\_cpi\_check\_id<!-- {{#callable:fd_vm_syscall_cpi_check_id}} -->
The function `fd_vm_syscall_cpi_check_id` checks if two public keys are identical by comparing them byte-by-byte.
- **Inputs**:
    - `program_id`: A pointer to a constant `fd_pubkey_t` structure representing the program's public key.
    - `loader`: A pointer to a constant unsigned character array representing the loader's public key.
- **Control Flow**:
    - The function uses `memcmp` to compare the memory content of `program_id` and `loader` for the size of `fd_pubkey_t`.
    - It returns the negation of the result from `memcmp`, which means it returns 1 if the keys are identical and 0 otherwise.
- **Output**: An integer value indicating whether the two public keys are identical (1 if identical, 0 otherwise).


---
### fd\_vm\_syscall\_cpi\_is\_precompile<!-- {{#callable:fd_vm_syscall_cpi_is_precompile}} -->
The function `fd_vm_syscall_cpi_is_precompile` checks if a given program ID corresponds to a known precompile by comparing it against a list of predefined program IDs.
- **Inputs**:
    - `program_id`: A pointer to a `fd_pubkey_t` structure representing the program ID to be checked.
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure containing the transaction context, which includes the current slot and active features.
- **Control Flow**:
    - The function calls [`fd_vm_syscall_cpi_check_id`](#fd_vm_syscall_cpi_check_id) three times to compare the `program_id` against three known precompile program IDs: `fd_solana_keccak_secp_256k_program_id.key`, `fd_solana_ed25519_sig_verify_program_id.key`, and `fd_solana_secp256r1_program_id.key`.
    - The results of these comparisons are combined using bitwise OR operations.
    - The third comparison is further conditioned by checking if the `enable_secp256r1_precompile` feature is active in the transaction context using `FD_FEATURE_ACTIVE`.
- **Output**: The function returns an integer value that is non-zero if the `program_id` matches any of the known precompile IDs, indicating that it is a precompile.
- **Functions called**:
    - [`fd_vm_syscall_cpi_check_id`](#fd_vm_syscall_cpi_check_id)


---
### fd\_vm\_syscall\_cpi\_check\_authorized\_program<!-- {{#callable:fd_vm_syscall_cpi_check_authorized_program}} -->
The function `fd_vm_syscall_cpi_check_authorized_program` checks if a given program ID is authorized to execute a Cross-Program Invocation (CPI) call.
- **Inputs**:
    - `program_id`: A pointer to the public key of the program to be checked for authorization.
    - `txn_ctx`: A pointer to the transaction context containing information about the current transaction, including features and slot.
    - `instruction_data`: A pointer to the instruction data associated with the program.
    - `instruction_data_len`: The length of the instruction data.
- **Control Flow**:
    - The function first checks if the `program_id` matches any of the known authorized loader IDs using [`fd_vm_syscall_cpi_check_id`](#fd_vm_syscall_cpi_check_id).
    - If the `program_id` matches the `fd_solana_bpf_loader_upgradeable_program_id.key`, it further checks the `instruction_data` to ensure it is not an unauthorized instruction type (e.g., upgrade, set authority, close).
    - The function also checks if the `program_id` corresponds to a precompiled program using [`fd_vm_syscall_cpi_is_precompile`](#fd_vm_syscall_cpi_is_precompile).
    - The function returns a non-zero value if any of the checks pass, indicating the program is authorized.
- **Output**: The function returns a non-zero value if the program ID is authorized to execute a CPI call, otherwise it returns zero.
- **Functions called**:
    - [`fd_vm_syscall_cpi_check_id`](#fd_vm_syscall_cpi_check_id)
    - [`fd_vm_syscall_cpi_is_precompile`](#fd_vm_syscall_cpi_is_precompile)


---
### serialized\_pubkey\_vaddr<!-- {{#callable:serialized_pubkey_vaddr}} -->
The function `serialized_pubkey_vaddr` calculates the virtual address of a serialized public key within a virtual machine's memory map, taking into account whether the VM is using a deprecated loader.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine context, which includes a flag indicating if the VM is using a deprecated loader.
    - `acc_region_meta`: A pointer to an `fd_vm_acc_region_meta_t` structure containing metadata about the account region, including the offset within the memory map where the account's metadata starts.
- **Control Flow**:
    - The function begins by accessing the `metadata_region_offset` from the `acc_region_meta` structure.
    - It checks the `is_deprecated` flag in the `vm` structure to determine which offset to use for the serialized public key.
    - If `is_deprecated` is true, it uses `VM_SERIALIZED_UNALIGNED_PUBKEY_OFFSET`; otherwise, it uses `VM_SERIALIZED_PUBKEY_OFFSET`.
    - The function calculates the virtual address by adding the base input region start address, the metadata region offset, and the appropriate serialized public key offset.
- **Output**: The function returns an `ulong` representing the calculated virtual address of the serialized public key within the VM's memory map.


---
### serialized\_owner\_vaddr<!-- {{#callable:serialized_owner_vaddr}} -->
The `serialized_owner_vaddr` function calculates the virtual address of the serialized owner field for a given account region in a virtual machine context, considering whether the VM is deprecated.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine context, which includes information about memory regions and whether the VM is deprecated.
    - `acc_region_meta`: A pointer to an `fd_vm_acc_region_meta_t` structure containing metadata about the account region, including whether it has a data region and its index.
- **Control Flow**:
    - Check if the virtual machine (`vm`) is marked as deprecated.
    - If deprecated, determine the virtual address by checking if the account region has a data region and using the appropriate region index to calculate the offset.
    - If not deprecated, calculate the virtual address using a fixed offset from the metadata region offset.
- **Output**: Returns an `ulong` representing the virtual address of the serialized owner field for the specified account region.


---
### serialized\_lamports\_vaddr<!-- {{#callable:serialized_lamports_vaddr}} -->
The function `serialized_lamports_vaddr` calculates the virtual address of the serialized lamports field for a given account in a virtual machine.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine context, which includes information about whether the VM is using a deprecated loader.
    - `acc_region_meta`: A pointer to an `fd_vm_acc_region_meta_t` structure containing metadata about the account region, including the offset of the metadata region.
- **Control Flow**:
    - The function begins by accessing the `metadata_region_offset` from the `acc_region_meta` structure.
    - It checks the `is_deprecated` flag in the `vm` structure to determine which offset to use for the lamports field.
    - If `is_deprecated` is true, it uses `VM_SERIALIZED_UNALIGNED_LAMPORTS_OFFSET`; otherwise, it uses `VM_SERIALIZED_LAMPORTS_OFFSET`.
    - The function adds the appropriate offset to the `FD_VM_MEM_MAP_INPUT_REGION_START` and the `metadata_region_offset` to compute the final virtual address.
- **Output**: The function returns an `ulong` representing the virtual address of the serialized lamports field for the specified account.


---
### vm\_syscall\_cpi\_acc\_info\_rc\_refcell\_as\_ptr<!-- {{#callable:vm_syscall_cpi_acc_info_rc_refcell_as_ptr}} -->
The function `vm_syscall_cpi_acc_info_rc_refcell_as_ptr` returns the address of the payload within a reference-counted RefCell structure given its virtual address.
- **Inputs**:
    - `rc_refcell_vaddr`: The virtual address of the reference-counted RefCell structure.
- **Control Flow**:
    - The function casts the input virtual address to a pointer of type `fd_vm_rc_refcell_t`.
    - It then accesses the `payload` member of this structure and returns its address as an unsigned long integer.
- **Output**: The function returns the address of the `payload` within the RefCell structure as an unsigned long integer.


---
### vm\_syscall\_cpi\_data\_len\_vaddr\_c<!-- {{#callable:vm_syscall_cpi_data_len_vaddr_c}} -->
The function `vm_syscall_cpi_data_len_vaddr_c` calculates a virtual address by adjusting the account information virtual address with data length and account information host address.
- **Inputs**:
    - `acct_info_vaddr`: The virtual address of the account information.
    - `data_len_haddr`: The host address of the data length.
    - `acct_info_haddr`: The host address of the account information.
- **Control Flow**:
    - The function first adds `acct_info_vaddr` and `data_len_haddr` using `fd_ulong_sat_add` to handle potential overflow.
    - Then, it subtracts `acct_info_haddr` from the result using `fd_ulong_sat_sub` to handle potential underflow.
    - The final result is returned as the calculated virtual address.
- **Output**: The function returns an unsigned long integer representing the calculated virtual address.


