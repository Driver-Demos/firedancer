# Purpose
This C header file defines the interface for a configuration program within the "flamenco" runtime environment. It primarily declares a function, [`fd_config_program_execute`](#fd_config_program_execute), which serves as the entry point for processing instructions related to managing lists of public keys (pubkeys) in accounts. The program facilitates the storage and modification of these pubkey lists, requiring signatures from designated "signers" to authorize changes. The header includes necessary dependencies from the flamenco base and execution context, ensuring that the function can interact with the broader system. The file is structured to prevent multiple inclusions and provides a clear, concise API for integrating this configuration functionality into other parts of the software.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../context/fd_exec_instr_ctx.h`


# Function Declarations (Public API)

---
### fd\_config\_program\_execute<!-- {{#callable_declaration:fd_config_program_execute}} -->
Execute the instruction processing for the config program.
- **Description**: This function serves as the entry point for executing instructions in the config program, which is a native program designed to manage lists of public keys in accounts. It should be called when an instruction needs to be processed, ensuring that all designated signers have signed the instruction. The function checks for unsupported program IDs and updates compute units before processing the instruction. It is important to ensure that the context provided is properly initialized and that the program is not a migrated native program, as this will result in an error.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure that contains the execution context for the instruction. This must be a valid, non-null pointer, and the context should be properly initialized before calling this function. The caller retains ownership of the context.
- **Output**: Returns an integer status code. If the program ID is unsupported due to migration, it returns `FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID`. Otherwise, it returns the result of processing the instruction.
- **See also**: [`fd_config_program_execute`](fd_config_program.c.driver.md#fd_config_program_execute)  (Implementation)


