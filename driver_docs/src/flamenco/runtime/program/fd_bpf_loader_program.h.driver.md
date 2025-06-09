# Purpose
This C header file, `fd_bpf_loader_program.h`, is part of a system designed to manage and execute BPF (Berkeley Packet Filter) programs, specifically focusing on the third version of a BPF loader. It defines constants related to compute units and program sizes, which are crucial for managing resources and memory allocation in BPF program execution. The file also includes a series of error codes, each represented by a unique bit-shifted value, to handle various instruction errors that may occur during program execution. Additionally, it declares several functions that facilitate the deployment and execution of BPF programs, including state retrieval and validation checks necessary for program deployment. The header file is part of a larger framework, as indicated by the inclusion of other headers and references to external documentation, suggesting its role in a modular and upgradeable BPF execution environment.
# Imports and Dependencies

---
- `../fd_borrowed_account.h`
- `fd_bpf_program_util.h`


# Global Variables

---
### read\_bpf\_upgradeable\_loader\_state\_for\_program
- **Type**: `fd_bpf_upgradeable_loader_state_t *`
- **Description**: The `read_bpf_upgradeable_loader_state_for_program` is a function that allocates and returns the BPF loader state for a specified program ID account within the context of a transaction. It takes a transaction context, a program ID, and an optional error pointer as parameters.
- **Use**: This function is used to retrieve the BPF loader state associated with a specific program ID during a transaction.


# Function Declarations (Public API)

---
### fd\_deploy\_program<!-- {{#callable_declaration:fd_deploy_program}} -->
Deploys a BPF program for execution.
- **Description**: This function is used to deploy a BPF program by loading and validating its ELF data, setting up the necessary execution environment, and ensuring the program is ready for execution. It should be called when a BPF program needs to be prepared for execution within a specific transaction context. The function requires a valid instruction context, program data, and a scratchpad memory area for temporary allocations. It handles various error conditions, such as invalid ELF data or failure to allocate necessary resources, by returning specific error codes.
- **Inputs**:
    - `instr_ctx`: A pointer to a fd_exec_instr_ctx_t structure representing the instruction context. Must not be null and should be properly initialized before calling this function.
    - `programdata`: A pointer to the program data in ELF format. Must not be null and should point to a valid ELF data buffer.
    - `programdata_size`: The size of the program data in bytes. Must be greater than zero and correspond to the actual size of the ELF data.
    - `spad`: A pointer to a fd_spad_t structure used for temporary memory allocations. Must not be null and should be initialized before use.
- **Output**: Returns an integer status code indicating success or the type of error encountered. Possible return values include FD_EXECUTOR_INSTR_SUCCESS for success, FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE for environment setup failures, and FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA for invalid program data.
- **See also**: [`fd_deploy_program`](fd_bpf_loader_program.c.driver.md#fd_deploy_program)  (Implementation)


---
### fd\_bpf\_execute<!-- {{#callable_declaration:fd_bpf_execute}} -->
Executes a validated BPF program within a specified execution context.
- **Description**: This function is used to execute a validated BPF program within a given execution context, which includes handling system calls and managing compute resources. It should be called when a BPF program needs to be run with specific execution parameters. The function requires a valid instruction context and a validated BPF program. It handles various error conditions, including program environment setup failures and execution errors, and returns appropriate error codes. The function also manages compute units and logs execution details.
- **Inputs**:
    - `instr_ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the instruction context. It must be valid and properly initialized before calling this function. The caller retains ownership.
    - `prog`: A pointer to an fd_sbpf_validated_program_t structure representing the validated BPF program to be executed. It must be valid and properly initialized. The caller retains ownership.
    - `is_deprecated`: An unsigned char indicating whether the program is deprecated. It should be set to a non-zero value if the program is deprecated, otherwise zero.
- **Output**: Returns an integer status code indicating success or the type of error encountered during execution. Common return values include FD_EXECUTOR_INSTR_SUCCESS for success and various error codes for different failure conditions.
- **See also**: [`fd_bpf_execute`](fd_bpf_loader_program.c.driver.md#fd_bpf_execute)  (Implementation)


---
### fd\_bpf\_loader\_program\_execute<!-- {{#callable_declaration:fd_bpf_loader_program_execute}} -->
Executes a BPF program within a given execution context.
- **Description**: This function is used to execute a BPF (Berkeley Packet Filter) program within the context of a transaction. It should be called when a BPF program needs to be run as part of a transaction execution. The function handles various program management instructions and checks for program validity, including whether the program is executable and whether it is in a valid state to be executed. It also manages different types of BPF loader programs, including upgradeable and deprecated ones, and ensures that only valid programs are executed. The function returns an error code if the program cannot be executed due to invalid state, unsupported program ID, or other issues.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution context. This parameter must not be null and should be properly initialized before calling the function. The context is used to manage the execution of the BPF program and contains necessary transaction and program information.
- **Output**: Returns an integer error code indicating the result of the execution. A return value of 0 indicates success, while non-zero values indicate various errors such as unsupported program ID or invalid account data.
- **See also**: [`fd_bpf_loader_program_execute`](fd_bpf_loader_program.c.driver.md#fd_bpf_loader_program_execute)  (Implementation)


---
### read\_bpf\_upgradeable\_loader\_state\_for\_program<!-- {{#callable_declaration:read_bpf_upgradeable_loader_state_for_program}} -->
Allocates and returns the BPF loader state for a specified program ID within a transaction context.
- **Description**: This function retrieves the BPF upgradeable loader state associated with a given program ID within the context of a transaction. It should be used when you need to access the loader state for a specific program during transaction processing. The function requires a valid transaction context and program ID, and it optionally returns an error code if the operation fails. It is important to ensure that the transaction context is properly initialized and that the program ID corresponds to a valid account within that context.
- **Inputs**:
    - `txn_ctx`: A pointer to a valid fd_exec_txn_ctx_t structure representing the transaction context. Must not be null.
    - `program_id`: An unsigned short representing the program ID for which the loader state is to be retrieved. Must correspond to a valid account within the transaction context.
    - `opt_err`: A pointer to an integer where an error code will be stored if the operation fails. Can be null if the caller does not need error information.
- **Output**: Returns a pointer to the fd_bpf_upgradeable_loader_state_t structure if successful, or NULL if an error occurs. If opt_err is non-null, it will contain the error code on failure.
- **See also**: [`read_bpf_upgradeable_loader_state_for_program`](fd_bpf_loader_program.c.driver.md#read_bpf_upgradeable_loader_state_for_program)  (Implementation)


---
### fd\_directly\_invoke\_loader\_v3\_deploy<!-- {{#callable_declaration:fd_directly_invoke_loader_v3_deploy}} -->
Deploys a BPF program using ELF and VM validation checks.
- **Description**: This function is used to deploy a BPF program by performing necessary ELF and VM validation checks, specifically for core native program BPF migration. It is intended to be called at the epoch boundary when a new BPF core migration feature is activated. The function requires a mock transaction and instruction context for execution, and it does not perform any funk operations directly. Instead, the BPF cache entry is created at the end of the block. This function should be used when deploying a BPF program in a runtime environment that requires these specific validation checks.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `elf`: A pointer to a constant uchar array containing the ELF data of the program to be deployed. Must not be null.
    - `elf_sz`: An unsigned long representing the size of the ELF data. Must be a valid size for the provided ELF data.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime scratchpad memory. Must not be null.
- **Output**: Returns an integer status code indicating success or failure of the deployment process.
- **See also**: [`fd_directly_invoke_loader_v3_deploy`](fd_bpf_loader_program.c.driver.md#fd_directly_invoke_loader_v3_deploy)  (Implementation)


