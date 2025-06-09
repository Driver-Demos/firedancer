# Purpose
This C header file, `fd_instr_harness.h`, is part of a testing framework for instruction processors within a larger system, likely related to a virtual machine or execution environment. It provides function prototypes for creating, destroying, and executing instruction contexts, which are essential for testing the behavior and effects of instructions in a runtime environment. The file includes various dependencies, such as common harness utilities, execution contexts, and program utilities, indicating its integration with a broader system for managing execution and testing. The functions defined here facilitate the setup and teardown of test contexts and the execution of instructions, with detailed handling of execution results and error logging. This header is crucial for developers who need to test and validate instruction processing within the system, ensuring that instructions execute correctly and efficiently.
# Imports and Dependencies

---
- `fd_harness_common.h`
- `../../fd_executor.h`
- `../../program/fd_bpf_program_util.h`
- `../../context/fd_exec_epoch_ctx.h`
- `../../context/fd_exec_slot_ctx.h`
- `../../context/fd_exec_txn_ctx.h`
- `../../program/fd_bpf_loader_program.h`
- `../../../fd_flamenco.h`
- `../../../fd_flamenco_base.h`
- `../../../vm/fd_vm.h`
- `../../../../funk/fd_funk.h`
- `../../../../ballet/murmur3/fd_murmur3.h`
- `../../../../ballet/sbpf/fd_sbpf_loader.h`
- `assert.h`
- `generated/invoke.pb.h`
- `generated/txn.pb.h`
- `generated/vm.pb.h`
- `generated/block.pb.h`


# Function Declarations (Public API)

---
### fd\_runtime\_fuzz\_instr\_ctx\_create<!-- {{#callable_declaration:fd_runtime_fuzz_instr_ctx_create}} -->
Creates an execution instruction context for runtime fuzz testing.
- **Description**: This function initializes an execution instruction context (`fd_exec_instr_ctx_t`) using the provided test runner and instruction context. It is designed for use in runtime fuzz testing environments. The function should be called when setting up a test scenario where instruction execution needs to be simulated. The `is_syscall` parameter determines whether certain operations and checks, relevant only for program instructions, are bypassed. It is important to pair this function with `fd_runtime_fuzz_instr_ctx_destroy` to properly release resources when the context is no longer needed.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which manages the fuzz testing environment. Must not be null.
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure, which will be initialized by the function. Must not be null.
    - `test_ctx`: A constant pointer to an `fd_exec_test_instr_context_t` structure, providing the test context for the instruction. Must not be null.
    - `is_syscall`: A boolean flag indicating whether the context is for a syscall. If true, certain operations and checks are skipped.
- **Output**: Returns 1 on successful creation of the context, or 0 if an error occurs during setup.
- **See also**: [`fd_runtime_fuzz_instr_ctx_create`](fd_instr_harness.c.driver.md#fd_runtime_fuzz_instr_ctx_create)  (Implementation)


---
### fd\_runtime\_fuzz\_instr\_ctx\_destroy<!-- {{#callable_declaration:fd_runtime_fuzz_instr_ctx_destroy}} -->
Frees an instruction context created by the corresponding creation function.
- **Description**: This function should be used to properly release resources associated with an instruction context that was previously created using `fd_runtime_fuzz_instr_ctx_create`. It is important to call this function to avoid resource leaks. The function does nothing if the provided context is null, ensuring safe repeated calls or calls with uninitialized contexts.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure. This parameter must be valid and properly initialized before calling the function. The caller retains ownership.
    - `ctx`: A pointer to an `fd_exec_instr_ctx_t` structure that represents the instruction context to be destroyed. This parameter can be null, in which case the function does nothing. If not null, it must have been previously created by `fd_runtime_fuzz_instr_ctx_create`.
- **Output**: None
- **See also**: [`fd_runtime_fuzz_instr_ctx_destroy`](fd_instr_harness.c.driver.md#fd_runtime_fuzz_instr_ctx_destroy)  (Implementation)


---
### fd\_runtime\_fuzz\_instr\_run<!-- {{#callable_declaration:fd_runtime_fuzz_instr_run}} -->
Executes an instruction context and returns the execution effects.
- **Description**: This function is used to execute a given instruction context and capture the effects of that execution. It requires a pre-allocated buffer to store the results, which are returned through a pointer. The function is designed to handle both successful executions and those that result in runtime errors, treating both as successful in terms of execution. It is important to ensure that the provided buffer is sufficiently large to store the results, as insufficient buffer size will result in a failure to execute, returning 0UL and leaving the output undefined. This function is typically used in testing environments where instruction effects need to be analyzed.
- **Inputs**:
    - `runner`: A pointer to an fd_runtime_fuzz_runner_t structure, which manages the execution context. Must not be null.
    - `input_`: A pointer to a constant input structure representing the instruction context to be executed. Must not be null.
    - `output_`: A pointer to a pointer where the address of the newly created instruction effects object will be stored. Must not be null.
    - `output_buf`: A pointer to a pre-allocated memory region where the results will be stored. Must not be null.
    - `output_bufsz`: The size of the pre-allocated memory region pointed to by output_buf. Must be large enough to store the execution results.
- **Output**: Returns the number of bytes allocated in the output buffer on successful execution, or 0UL on failure.
- **See also**: [`fd_runtime_fuzz_instr_run`](fd_instr_harness.c.driver.md#fd_runtime_fuzz_instr_run)  (Implementation)


