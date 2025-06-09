# Purpose
This C header file defines constants and function prototypes related to the management of compute budgets within a runtime environment, likely part of a larger system dealing with transaction execution or resource allocation. It includes definitions for heap frame size constraints and compute unit limits, which are essential for managing memory and processing resources efficiently. The file also categorizes programs into different types, such as built-in, non-built-in, and migrating built-in, each with specific compute unit limits, reflecting their resource prioritization. Additionally, it declares two function prototypes for executing instructions and compute budget programs, indicating that these functions are integral to the runtime's operation in handling compute budgets. The inclusion of external headers suggests dependencies on broader system contexts and base functionalities.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../context/fd_exec_instr_ctx.h`


# Function Declarations (Public API)

---
### fd\_executor\_compute\_budget\_program\_execute\_instructions<!-- {{#callable_declaration:fd_executor_compute_budget_program_execute_instructions}} -->
Executes compute budget program instructions within a transaction context.
- **Description**: This function processes and executes compute budget program instructions from a raw transaction within the provided transaction context. It updates the transaction context based on the instructions, such as setting compute unit limits, heap size, and compute unit prices. The function must be called with a valid transaction context and raw transaction data. It handles duplicate instructions by returning specific error codes and ensures that any requested heap size is sanitized before updating the context. The function returns an error code if any instruction is invalid or if constraints are violated.
- **Inputs**:
    - `ctx`: A pointer to a `fd_exec_txn_ctx_t` structure representing the transaction context. Must not be null. The context is updated based on the instructions executed.
    - `txn_raw`: A pointer to a `fd_rawtxn_b_t` structure containing the raw transaction data. Must not be null. The function reads instructions from this data to execute.
- **Output**: Returns an integer status code indicating success or specific error conditions, such as invalid instructions or duplicate instructions.
- **See also**: [`fd_executor_compute_budget_program_execute_instructions`](fd_compute_budget_program.c.driver.md#fd_executor_compute_budget_program_execute_instructions)  (Implementation)


---
### fd\_compute\_budget\_program\_execute<!-- {{#callable_declaration:fd_compute_budget_program_execute}} -->
Execute a compute budget program with a given execution context.
- **Description**: This function is used to execute a compute budget program within the context provided by the caller. It updates the compute units in the execution context to a default value and returns a success status. This function should be called when a compute budget program needs to be executed as part of a larger execution flow. The execution context must be properly initialized before calling this function to ensure correct operation.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure representing the execution context. This parameter must not be null, and the context should be initialized before calling the function. The caller retains ownership of the context.
- **Output**: Returns an integer status code indicating success, specifically `FD_EXECUTOR_INSTR_SUCCESS`.
- **See also**: [`fd_compute_budget_program_execute`](fd_compute_budget_program.c.driver.md#fd_compute_budget_program_execute)  (Implementation)


