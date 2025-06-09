# Purpose
This C header file defines a set of system call (syscall) declarations and related constants for a virtual machine (VM) environment, specifically tailored for integration with the Solana blockchain. The file provides a broad range of functionality, primarily focused on facilitating interactions between the VM and the Solana runtime environment. It includes syscall declarations for operations such as logging, memory management, cryptographic functions, and cross-program invocations. The syscalls are prefixed with `sol_` to denote their association with Solana, and they are designed to handle various tasks like logging messages, managing memory, and performing cryptographic operations using specific algorithms like Blake3, Keccak256, and SHA256.

The file is structured to support the implementation of a virtual machine that can execute Solana programs, providing essential services like logging, memory operations, and cryptographic computations. It defines constants for managing program-derived addresses (PDAs) and includes detailed comments on the expected behavior and return values of each syscall. The header file is intended to be included in other C source files, serving as an interface for implementing the VM's syscall functionality. It does not define any public APIs directly but provides the necessary declarations for implementing the VM's internal syscall handling mechanisms. The file also includes several `FIXME` comments, indicating areas where further refinement or documentation is needed, suggesting that the implementation is still under development or subject to change.
# Imports and Dependencies

---
- `../fd_vm_private.h`
- `fd_vm_syscall_macros.h`
- `fd_vm_cpi.h`
- `../../runtime/fd_runtime.h`
- `../../runtime/context/fd_exec_instr_ctx.h`
- `../../log_collector/fd_log_collector.h`


# Function Declarations (Public API)

---
### fd\_vm\_prepare\_instruction<!-- {{#callable_declaration:fd_vm_prepare_instruction}} -->
Prepares an instruction by normalizing and deduplicating account references.
- **Description**: This function is used to prepare an instruction by normalizing the privileges of each account and deduplicating account references according to Solana's logic. It should be called when setting up an instruction for execution, ensuring that all account references are valid and properly normalized. The function handles cases where accounts are unknown or privileges are escalated, returning specific error codes in such scenarios. It also updates the provided instruction accounts array with the deduplicated and normalized accounts.
- **Inputs**:
    - `callee_instr`: A pointer to an fd_instr_info_t structure representing the callee instruction. It must be valid and properly initialized before calling this function.
    - `instr_ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution context of the instruction. It must be valid and properly initialized.
    - `callee_program_id_pubkey`: A pointer to a constant fd_pubkey_t representing the public key of the callee program ID. It must not be null.
    - `instr_acct_keys`: An array of fd_pubkey_t of size FD_INSTR_ACCT_MAX representing the instruction account keys. It must be valid and contain the keys referenced by the instruction.
    - `instruction_accounts`: An array of fd_instruction_account_t of size FD_INSTR_ACCT_MAX where the deduplicated and normalized instruction accounts will be stored. It must be valid and writable.
    - `instruction_accounts_cnt`: A pointer to an ulong where the count of deduplicated instruction accounts will be stored. It must be valid and writable.
    - `signers`: A pointer to an array of fd_pubkey_t representing the signers. It can be null if signers_cnt is zero.
    - `signers_cnt`: An ulong representing the number of signers. It must be zero or more.
- **Output**: Returns 0 on success. On failure, returns specific error codes indicating the type of error encountered, such as missing accounts or privilege escalation.
- **See also**: [`fd_vm_prepare_instruction`](fd_vm_syscall_cpi.c.driver.md#fd_vm_prepare_instruction)  (Implementation)


---
### fd\_vm\_derive\_pda<!-- {{#callable_declaration:fd_vm_derive_pda}} -->
Derives a Program Derived Address (PDA) using specified seeds and a program ID.
- **Description**: This function is used to derive a Program Derived Address (PDA) based on a given program ID and a set of seed values. It is typically called when a PDA needs to be generated for a program in a virtual machine context. The function requires a valid program ID and a list of seed addresses and their sizes. The number of seeds must not exceed the defined maximum, and each seed size must be within the allowed limit. Optionally, a bump seed can be included to ensure the derived address is not a valid Ed25519 curve point. The function outputs the derived PDA into the provided output parameter and returns a status code indicating success or the type of error encountered.
- **Inputs**:
    - `vm`: A pointer to the virtual machine context (fd_vm_t). Must not be null.
    - `program_id`: A pointer to the program ID (fd_pubkey_t) used in the derivation. Must not be null.
    - `seed_haddrs`: An array of pointers to seed data. Each pointer must point to a valid memory location. The array must have at least seeds_cnt elements.
    - `seed_szs`: An array of sizes corresponding to each seed in seed_haddrs. Each size must not exceed FD_VM_PDA_SEED_MEM_MAX. The array must have at least seeds_cnt elements.
    - `seeds_cnt`: The number of seeds provided. Must not exceed FD_VM_PDA_SEEDS_MAX.
    - `bump_seed`: An optional pointer to a bump seed. If provided, it must point to a valid memory location. Can be null if no bump seed is used.
    - `out`: A pointer to the output location for the derived PDA (fd_pubkey_t). Must not be null.
- **Output**: Returns an integer status code: FD_VM_SUCCESS on success, FD_VM_SYSCALL_ERR_BAD_SEEDS if seed constraints are violated, or FD_VM_SYSCALL_ERR_INVALID_PDA if the derived address is a valid Ed25519 curve point.
- **See also**: [`fd_vm_derive_pda`](fd_vm_syscall_pda.c.driver.md#fd_vm_derive_pda)  (Implementation)


---
### fd\_vm\_translate\_and\_check\_program\_address\_inputs<!-- {{#callable_declaration:fd_vm_translate_and_check_program_address_inputs}} -->
Translate and validate program address inputs for a virtual machine.
- **Description**: This function is used to translate and validate the inputs required for program address operations within a virtual machine context. It checks the validity of seed addresses and sizes, ensuring they do not exceed predefined limits. The function also optionally retrieves the program ID if requested. It is crucial to call this function with valid virtual machine and address parameters to avoid errors. The function distinguishes between syscall and non-syscall contexts, logging different errors accordingly.
- **Inputs**:
    - `vm`: A pointer to the virtual machine context. Must not be null.
    - `seeds_vaddr`: The virtual address of the seeds. Must be a valid address within the virtual machine's memory space.
    - `seeds_cnt`: The number of seeds. Must not exceed FD_VM_PDA_SEEDS_MAX. If exceeded, an error is returned.
    - `program_id_vaddr`: The virtual address of the program ID. Must be a valid address if out_program_id is not null.
    - `out_seed_haddrs`: An array to store the translated host addresses of the seeds. Must be large enough to hold seeds_cnt entries.
    - `out_seed_szs`: An array to store the sizes of the seeds. Must be large enough to hold seeds_cnt entries.
    - `out_program_id`: A pointer to store the program ID. Can be null if the program ID is not needed.
    - `is_syscall`: A flag indicating if the function is called from a syscall context. Affects error logging behavior.
- **Output**: Returns 0 on success. On failure, returns an error code indicating the type of error encountered.
- **See also**: [`fd_vm_translate_and_check_program_address_inputs`](fd_vm_syscall_pda.c.driver.md#fd_vm_translate_and_check_program_address_inputs)  (Implementation)


