# Purpose
This C header file defines the interface and constants for managing the state and execution of a "loader v4" program within a specific runtime environment, likely related to a blockchain or smart contract platform. The file provides a structured approach to handle different states of a program, namely "Retracted," "Deployed," and "Finalized," each with specific characteristics and transitions. The header includes several macros that define constants related to the loader's operation, such as default compute units and deployment cooldown periods, which are crucial for maintaining the program's lifecycle and ensuring compliance with the platform's operational constraints.

The file also declares several functions that are essential for interacting with the loader v4 program's state. These functions include checking the current status of a program (whether it is deployed, retracted, or finalized) and executing the program within a given execution context. The use of type punning and specific serialization/deserialization techniques ensures compatibility with the underlying system's memory representation, which is critical for maintaining data integrity and operational correctness. This header file is intended to be included in other C source files, providing a public API for managing and executing loader v4 programs, and it plays a vital role in the broader system by facilitating program lifecycle management and execution.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../context/fd_exec_instr_ctx.h`
- `../fd_system_ids.h`
- `../fd_executor.h`
- `../sysvar/fd_sysvar_rent.h`
- `../fd_borrowed_account.h`
- `fd_bpf_loader_program.h`


# Global Variables

---
### fd\_loader\_v4\_get\_state
- **Type**: `fd_loader_v4_state_t const *`
- **Description**: The function `fd_loader_v4_get_state` returns a pointer to a constant `fd_loader_v4_state_t` structure, which represents the state of a loader v4 program. This state can be one of three possible states: Retracted, Deployed, or Finalized, each indicating a different phase in the program's lifecycle.
- **Use**: This function is used to retrieve the current state of a loader v4 program, allowing the caller to understand the program's status and act accordingly.


# Function Declarations (Public API)

---
### fd\_loader\_v4\_status\_is\_deployed<!-- {{#callable_declaration:fd_loader_v4_status_is_deployed}} -->
Check if the loader v4 program is in the deployed state.
- **Description**: Use this function to determine if a loader v4 program is currently in the deployed state, which indicates that the program is ready to be invoked. This function is useful for checking the readiness of a program before attempting to execute it. Ensure that the `state` parameter is a valid pointer to a `fd_loader_v4_state_t` structure representing the current state of the program.
- **Inputs**:
    - `state`: A pointer to a `fd_loader_v4_state_t` structure representing the current state of the loader v4 program. Must not be null. The function will return an incorrect result if the `state` does not represent a valid loader v4 state.
- **Output**: Returns a non-zero value if the program is in the deployed state, otherwise returns zero.
- **See also**: [`fd_loader_v4_status_is_deployed`](fd_loader_v4_program.c.driver.md#fd_loader_v4_status_is_deployed)  (Implementation)


---
### fd\_loader\_v4\_status\_is\_retracted<!-- {{#callable_declaration:fd_loader_v4_status_is_retracted}} -->
Check if the loader v4 program is in the retracted state.
- **Description**: Use this function to determine if a loader v4 program is currently in the retracted state, which indicates that the program is either in the process of deployment or is deployed but under maintenance and cannot be invoked. This function is useful for checking the program's status before attempting operations that require the program to be in a different state. Ensure that the `state` parameter is a valid pointer to a `fd_loader_v4_state_t` structure before calling this function.
- **Inputs**:
    - `state`: A pointer to a `fd_loader_v4_state_t` structure representing the current state of the loader v4 program. Must not be null. The function does not modify the state.
- **Output**: Returns a non-zero value if the program is in the retracted state, otherwise returns zero.
- **See also**: [`fd_loader_v4_status_is_retracted`](fd_loader_v4_program.c.driver.md#fd_loader_v4_status_is_retracted)  (Implementation)


---
### fd\_loader\_v4\_status\_is\_finalized<!-- {{#callable_declaration:fd_loader_v4_status_is_finalized}} -->
Check if the loader v4 program is in the finalized state.
- **Description**: Use this function to determine if a loader v4 program has reached the finalized state, where it becomes immutable. This function is useful when you need to verify the program's state before performing operations that require the program to be finalized. Ensure that the `state` parameter is a valid pointer to a `fd_loader_v4_state_t` structure before calling this function.
- **Inputs**:
    - `state`: A pointer to a `fd_loader_v4_state_t` structure representing the current state of the loader v4 program. Must not be null. The function assumes the pointer is valid and points to a properly initialized state structure.
- **Output**: Returns a non-zero value if the program is in the finalized state, otherwise returns zero.
- **See also**: [`fd_loader_v4_status_is_finalized`](fd_loader_v4_program.c.driver.md#fd_loader_v4_status_is_finalized)  (Implementation)


---
### fd\_loader\_v4\_get\_state<!-- {{#callable_declaration:fd_loader_v4_get_state}} -->
Retrieve the state of a loader v4 program.
- **Description**: Use this function to obtain the current state of a loader v4 program from a given program account. It is essential to ensure that the program account contains sufficient data before calling this function, as it checks if the data length meets the required offset. If the data is insufficient, an error code is set, and the function returns NULL. This function should be called when you need to inspect the state of a program, such as determining if it is deployed, retracted, or finalized.
- **Inputs**:
    - `program`: A pointer to a constant fd_txn_account_t structure representing the program account. It must not be null and should point to a valid program account with sufficient data length.
    - `err`: A pointer to an integer where the function will store the error code. It must not be null. The error code will be set to FD_EXECUTOR_INSTR_SUCCESS if successful, or FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL if the program data is insufficient.
- **Output**: Returns a pointer to a constant fd_loader_v4_state_t structure representing the program's state if successful, or NULL if the data length is insufficient.
- **See also**: [`fd_loader_v4_get_state`](fd_loader_v4_program.c.driver.md#fd_loader_v4_get_state)  (Implementation)


---
### fd\_loader\_v4\_program\_execute<!-- {{#callable_declaration:fd_loader_v4_program_execute}} -->
Executes a loader v4 program instruction.
- **Description**: This function executes a loader v4 program instruction based on the context provided. It should be called when a loader v4 program needs to be executed within a transaction context. The function checks if the loader v4 feature is active for the given transaction context and processes the instruction accordingly. It handles various instruction types such as write, copy, set program length, deploy, retract, transfer authority, and finalize. The function returns specific error codes if the program ID is unsupported or if the instruction data is invalid. It is important to ensure that the transaction context is properly initialized and that the loader v4 feature is enabled before calling this function.
- **Inputs**:
    - `instr_ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the instruction context. This parameter must not be null and should be properly initialized with a valid transaction context. The function will return an error if the loader v4 feature is not active for the given context.
- **Output**: Returns an integer status code indicating the result of the execution. Possible return values include success, unsupported program ID, and invalid instruction data.
- **See also**: [`fd_loader_v4_program_execute`](fd_loader_v4_program.c.driver.md#fd_loader_v4_program_execute)  (Implementation)


