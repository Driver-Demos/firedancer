# Purpose
This C header file defines an interface for a function that loads and executes an ELF (Executable and Linkable Format) binary within a fuzz testing harness. It includes necessary dependencies such as common harness utilities, a virtual machine base, and a generated protocol buffer for ELF handling. The primary function, [`fd_runtime_fuzz_sbpf_load_run`](#fd_runtime_fuzz_sbpf_load_run), is designed to load an ELF binary from a specified input, execute it, and store the results in a provided output buffer. The function returns the number of bytes allocated in the output buffer or zero if a harness-specific failure occurs, indicating its role in testing and validating ELF binaries in a controlled environment. This file is part of a larger testing framework, likely used for validating the execution of ELF binaries in a secure and isolated manner.
# Imports and Dependencies

---
- `fd_harness_common.h`
- `../../../vm/fd_vm_base.h`
- `generated/elf.pb.h`


# Function Declarations (Public API)

---
### fd\_runtime\_fuzz\_sbpf\_load\_run<!-- {{#callable_declaration:fd_runtime_fuzz_sbpf_load_run}} -->
Loads an ELF binary and allocates the result in a specified buffer.
- **Description**: This function is used to load an ELF binary from the provided input and allocate the result into a specified output buffer. It is designed to handle fuzz testing scenarios, where the input ELF data may have intentional underflow or overflow characteristics. The function must be called with a valid runner and input structure, and it requires a pre-allocated output buffer of sufficient size. The function returns the number of bytes allocated in the output buffer, or 0 if there are any harness-specific failures. Execution failures may still result in an incomplete or undefined output, but the number of allocated bytes will be returned.
- **Inputs**:
    - `runner`: A pointer to an fd_runtime_fuzz_runner_t structure. This must be a valid, initialized runner object used for managing the fuzz testing environment.
    - `input_`: A pointer to a constant structure containing the ELF binary data to be loaded. The structure must have valid ELF data, and the caller retains ownership.
    - `output_`: A pointer to a pointer where the function will store the address of the allocated result. The caller must provide a valid pointer, and the function will update it to point to the allocated effects structure.
    - `output_buf`: A pointer to a memory region where the result will be allocated. The buffer must be pre-allocated by the caller and should be large enough to hold the expected output.
    - `output_bufsz`: The size of the output buffer in bytes. It must be a positive value indicating the maximum space available for allocation.
- **Output**: Returns the number of bytes allocated in the output buffer, or 0 on harness-specific failures. The output is stored in the memory region pointed to by output_buf, and the output_ pointer is updated to point to the allocated effects structure.
- **See also**: [`fd_runtime_fuzz_sbpf_load_run`](fd_elf_harness.c.driver.md#fd_runtime_fuzz_sbpf_load_run)  (Implementation)


