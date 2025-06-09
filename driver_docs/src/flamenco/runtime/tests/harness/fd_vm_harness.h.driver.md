# Purpose
This C header file, `fd_vm_harness.h`, is part of a testing framework for a virtual machine (VM) within the Flamenco runtime environment. It includes necessary dependencies and headers, such as common harness utilities, instruction harnesses, system identifiers, BPF loader serialization, and VM utilities, indicating its role in facilitating comprehensive testing. The file declares two primary functions: [`fd_runtime_fuzz_vm_interp_run`](#fd_runtime_fuzz_vm_interp_run) and [`fd_runtime_fuzz_vm_syscall_run`](#fd_runtime_fuzz_vm_syscall_run), which are designed to execute test cases against the VM's interpreter and specific syscalls, respectively. These functions are likely used to validate the VM's behavior under various conditions, ensuring robustness and correctness. The use of `FD_PROTOTYPES_BEGIN` and `FD_PROTOTYPES_END` suggests a structured approach to managing function prototypes within the framework.
# Imports and Dependencies

---
- `fd_harness_common.h`
- `fd_instr_harness.h`
- `../../fd_system_ids.h`
- `../../program/fd_bpf_loader_serialization.h`
- `../../fd_executor.h`
- `../../../vm/fd_vm.h`
- `../../../vm/test_vm_util.h`
- `generated/vm.pb.h`


# Function Declarations (Public API)

---
### fd\_runtime\_fuzz\_vm\_interp\_run<!-- {{#callable_declaration:fd_runtime_fuzz_vm_interp_run}} -->
Executes a test case against the interpreter and captures the effects.
- **Description**: This function is used to execute a single test case against a virtual machine interpreter, capturing the effects of the execution in a provided output buffer. It requires a runner context and input data, and it outputs the results into a specified buffer. The function must be called with a valid runner and input data, and the output buffer must be large enough to store the results. If the input data does not have a valid VM context, the function will return immediately with no effects captured.
- **Inputs**:
    - `runner`: A pointer to a fd_runtime_fuzz_runner_t structure, which provides the context for the execution. Must not be null.
    - `input`: A pointer to constant input data, which must conform to the expected structure for the test case. Must not be null.
    - `output`: A pointer to a location where the function will store a pointer to the effects of the execution. The caller must provide a valid pointer to a pointer.
    - `output_buf`: A pointer to a buffer where the function will store the serialized effects of the execution. Must not be null and should be large enough to hold the output.
    - `output_bufsz`: The size of the output buffer in bytes. Must be large enough to store the serialized effects; otherwise, the function will return 0.
- **Output**: Returns the number of bytes written to the output buffer, or 0 if the execution could not be performed.
- **See also**: [`fd_runtime_fuzz_vm_interp_run`](fd_vm_harness.c.driver.md#fd_runtime_fuzz_vm_interp_run)  (Implementation)


---
### fd\_runtime\_fuzz\_vm\_syscall\_run<!-- {{#callable_declaration:fd_runtime_fuzz_vm_syscall_run}} -->
Executes a test case against a target syscall within the VM.
- **Description**: This function is used to execute a single test case against a specified syscall within a virtual machine (VM) environment. It is intended for use in testing scenarios where the behavior of syscalls needs to be validated. The function requires a runner context and input data describing the syscall to be tested. It produces output data capturing the effects of the syscall execution, which is stored in a provided buffer. The function must be called with a valid runner and sufficient buffer space to store the output effects.
- **Inputs**:
    - `runner`: A pointer to an fd_runtime_fuzz_runner_t structure that manages the execution context. Must not be null.
    - `input_`: A pointer to a constant input structure describing the syscall to be tested. Must not be null.
    - `output_`: A pointer to a location where the function will store a pointer to the output effects structure. Must not be null.
    - `output_buf`: A pointer to a buffer where the output effects will be stored. Must not be null and should have sufficient space to store the effects.
    - `output_bufsz`: The size of the output buffer in bytes. Must be large enough to accommodate the output effects.
- **Output**: Returns the number of bytes written to the output buffer. Returns 0 if an error occurs during execution.
- **See also**: [`fd_runtime_fuzz_vm_syscall_run`](fd_vm_harness.c.driver.md#fd_runtime_fuzz_vm_syscall_run)  (Implementation)


