# Purpose
This C header file, `fd_exec_sol_compat.h`, defines a set of function prototypes for conducting differential testing between two systems, Agave and Firedancer. It includes functions for initializing and finalizing workspace settings, checking workspace usage, and setting up and cleaning up a fuzz testing runner. Additionally, it provides several fixture functions for testing various components such as instructions, transactions, blocks, ELF loaders, syscalls, and virtual machine interpreters. The file is structured to facilitate compatibility testing by providing a standardized interface for executing these tests, ensuring that both systems can be evaluated under similar conditions.
# Imports and Dependencies

---
- `fd_harness_common.h`


# Global Variables

---
### sol\_compat\_setup\_runner
- **Type**: `fd_runtime_fuzz_runner_t *`
- **Description**: The `sol_compat_setup_runner` is a function that returns a pointer to a `fd_runtime_fuzz_runner_t` structure. This function is likely responsible for setting up or initializing a fuzz runner used in the context of differential testing between Agave and Firedancer.
- **Use**: This function is used to initialize and return a fuzz runner for executing differential tests.


# Function Declarations (Public API)

---
### sol\_compat\_wksp\_init<!-- {{#callable_declaration:sol_compat_wksp_init}} -->
Initialize a workspace with a specified page size.
- **Description**: This function sets up a workspace for differential testing between Agave and Firedancer, using the specified page size. It should be called before any operations that require workspace allocation. The function supports two page sizes: FD_SHMEM_GIGANTIC_PAGE_SZ and FD_SHMEM_NORMAL_PAGE_SZ. If an unsupported page size is provided, the function will log an error and terminate. The workspace is initialized with memory allocations for specific features, which are categorized into hardcoded and supported features based on their activation status across clusters. This function must be called before any other operations that depend on the initialized workspace.
- **Inputs**:
    - `wksp_page_sz`: Specifies the page size for the workspace. Valid values are FD_SHMEM_GIGANTIC_PAGE_SZ and FD_SHMEM_NORMAL_PAGE_SZ. If an invalid value is provided, the function logs an error and terminates. The caller retains ownership of this parameter.
- **Output**: None
- **See also**: [`sol_compat_wksp_init`](fd_exec_sol_compat.c.driver.md#sol_compat_wksp_init)  (Implementation)


---
### sol\_compat\_fini<!-- {{#callable_declaration:sol_compat_fini}} -->
Cleans up resources used by the compatibility workspace.
- **Description**: This function should be called to release resources allocated by the compatibility workspace, typically after all operations requiring the workspace have been completed. It ensures that memory and other resources are properly freed, preventing leaks. This function should be called only after the workspace has been initialized and used, and it is not safe to call it multiple times without reinitializing the workspace.
- **Inputs**: None
- **Output**: None
- **See also**: [`sol_compat_fini`](fd_exec_sol_compat.c.driver.md#sol_compat_fini)  (Implementation)


---
### sol\_compat\_check\_wksp\_usage<!-- {{#callable_declaration:sol_compat_check_wksp_usage}} -->
Checks for memory leaks in the workspace.
- **Description**: Use this function to verify if there are any memory leaks in the current workspace by checking the usage statistics. It should be called when you need to ensure that all allocated memory has been properly freed, typically after a series of operations that involve memory allocation. If any memory is found to be leaked, an error is logged with the details of the leaked memory size and count of allocations. This function does not take any parameters and does not return any value.
- **Inputs**: None
- **Output**: None
- **See also**: [`sol_compat_check_wksp_usage`](fd_exec_sol_compat.c.driver.md#sol_compat_check_wksp_usage)  (Implementation)


---
### sol\_compat\_setup\_runner<!-- {{#callable_declaration:sol_compat_setup_runner}} -->
Sets up and returns a new fuzz test runner.
- **Description**: This function initializes and returns a new fuzz test runner, which is used for executing differential tests between Agave and Firedancer. It should be called when a new test runner is needed, typically after workspace initialization. The function allocates the necessary memory for the runner and sets it up for execution. Ensure that the workspace is properly initialized before calling this function to avoid undefined behavior.
- **Inputs**: None
- **Output**: Returns a pointer to a newly initialized `fd_runtime_fuzz_runner_t` instance, or `NULL` if the setup fails.
- **See also**: [`sol_compat_setup_runner`](fd_exec_sol_compat.c.driver.md#sol_compat_setup_runner)  (Implementation)


---
### sol\_compat\_cleanup\_runner<!-- {{#callable_declaration:sol_compat_cleanup_runner}} -->
Cleans up resources associated with a test runner.
- **Description**: Use this function to release resources allocated for a test runner when it is no longer needed. It should be called to ensure proper cleanup and avoid memory leaks after the runner has been used for its intended purpose. This function must be called with a valid runner that was previously set up using the appropriate setup function. Passing a null or invalid runner may result in undefined behavior.
- **Inputs**:
    - `runner`: A pointer to a `fd_runtime_fuzz_runner_t` structure representing the test runner to be cleaned up. This must be a valid, non-null pointer to a runner that was previously initialized. The caller retains ownership of the pointer, but the resources it points to will be freed.
- **Output**: None
- **See also**: [`sol_compat_cleanup_runner`](fd_exec_sol_compat.c.driver.md#sol_compat_cleanup_runner)  (Implementation)


---
### sol\_compat\_instr\_fixture<!-- {{#callable_declaration:sol_compat_instr_fixture}} -->
Runs a differential test on an instruction fixture.
- **Description**: This function is used to perform a differential test on an instruction fixture by decoding the input data, executing the test, and comparing the results. It should be called with a valid fuzz runner and input data that represents the instruction fixture to be tested. The function returns an integer indicating the success of the test, where a non-zero value signifies a successful comparison of effects. It is important to ensure that the runner is properly initialized before calling this function.
- **Inputs**:
    - `runner`: A pointer to a `fd_runtime_fuzz_runner_t` structure, which must be properly initialized before calling this function. The caller retains ownership and must ensure it is not null.
    - `in`: A pointer to a constant unsigned character array representing the input data for the instruction fixture. The data should be properly formatted according to the expected input structure.
    - `in_sz`: An unsigned long representing the size of the input data array. It should accurately reflect the number of bytes in the input data.
- **Output**: Returns an integer indicating the success of the test, where a non-zero value means the test passed successfully.
- **See also**: [`sol_compat_instr_fixture`](fd_exec_sol_compat.c.driver.md#sol_compat_instr_fixture)  (Implementation)


---
### sol\_compat\_txn\_fixture<!-- {{#callable_declaration:sol_compat_txn_fixture}} -->
Executes and verifies a transaction fixture using a fuzz runner.
- **Description**: This function is used to execute a transaction fixture and verify its effects using a provided fuzz runner. It is typically called as part of a differential testing process between Agave and Firedancer. The function decodes the input fixture, executes it, and compares the resulting effects against expected outcomes. It returns an integer indicating the success of the comparison. The function assumes that the runner has been properly initialized and that the input data is correctly formatted. If the input fixture is invalid, the function logs a warning and returns 0.
- **Inputs**:
    - `runner`: A pointer to an initialized fd_runtime_fuzz_runner_t structure. The caller retains ownership and must ensure it is valid and properly set up before calling this function.
    - `in`: A pointer to a buffer containing the encoded transaction fixture data. The data must be in a format expected by the function. The caller retains ownership of the buffer.
    - `in_sz`: The size of the input buffer in bytes. It must accurately reflect the size of the data pointed to by 'in'.
- **Output**: Returns an integer indicating the success of the transaction fixture execution and comparison. A return value of 0 indicates failure, while a non-zero value indicates success.
- **See also**: [`sol_compat_txn_fixture`](fd_exec_sol_compat.c.driver.md#sol_compat_txn_fixture)  (Implementation)


---
### sol\_compat\_block\_fixture<!-- {{#callable_declaration:sol_compat_block_fixture}} -->
Executes and verifies a block fixture using a fuzz runner.
- **Description**: This function is used to execute a block fixture and verify its effects using a provided fuzz runner. It is typically called as part of a differential testing process between Agave and Firedancer. The function decodes the input fixture, executes it, and compares the output against expected results. It returns an integer indicating the success of the comparison. The function assumes that the runner has been properly initialized and that the input data is correctly formatted. If the input is invalid, the function logs a warning and returns 0.
- **Inputs**:
    - `runner`: A pointer to an initialized fd_runtime_fuzz_runner_t structure. The caller retains ownership and must ensure it is valid and properly initialized before calling this function.
    - `in`: A pointer to a buffer containing the encoded block fixture data. The data must be in a format expected by the function, and the caller retains ownership.
    - `in_sz`: The size of the input buffer in bytes. It must accurately reflect the size of the data pointed to by 'in'.
- **Output**: Returns an integer indicating the success of the fixture execution and comparison. A return value of 0 indicates failure, while a non-zero value indicates success.
- **See also**: [`sol_compat_block_fixture`](fd_exec_sol_compat.c.driver.md#sol_compat_block_fixture)  (Implementation)


---
### sol\_compat\_elf\_loader\_fixture<!-- {{#callable_declaration:sol_compat_elf_loader_fixture}} -->
Runs a differential test on an ELF loader fixture.
- **Description**: This function is used to perform a differential test on an ELF loader fixture by decoding the input data, executing it, and comparing the results. It is intended to be used in a testing environment where `runner` has been properly initialized. The function returns an integer indicating the success of the test, where a non-zero value signifies a successful comparison of effects. It is important to ensure that the input data is correctly formatted and that the `runner` is set up before calling this function.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure that must be initialized before calling this function. The caller retains ownership and is responsible for its lifecycle.
    - `in`: A pointer to a constant unsigned character array representing the input data to be decoded and tested. The data must be valid and properly formatted for the test.
    - `in_sz`: An unsigned long representing the size of the input data array. It must accurately reflect the number of bytes available in `in`.
- **Output**: Returns an integer indicating the success of the test, with non-zero meaning the test passed successfully.
- **See also**: [`sol_compat_elf_loader_fixture`](fd_exec_sol_compat.c.driver.md#sol_compat_elf_loader_fixture)  (Implementation)


---
### sol\_compat\_syscall\_fixture<!-- {{#callable_declaration:sol_compat_syscall_fixture}} -->
Run a differential test for a syscall fixture using a fuzz runner.
- **Description**: This function is used to execute a differential test on a syscall fixture by utilizing a fuzz runner. It decodes the input data into a syscall fixture, executes the fixture, and compares the effects against expected outcomes. The function should be called with a properly initialized fuzz runner and valid input data. It returns an integer indicating the success or failure of the test. Ensure that the input data is correctly formatted and that the runner is set up before calling this function.
- **Inputs**:
    - `runner`: A pointer to an initialized `fd_runtime_fuzz_runner_t` structure. The caller must ensure that this is not null and that the runner is properly set up before calling the function.
    - `in`: A pointer to a constant unsigned character array representing the input data for the syscall fixture. The data must be valid and correctly formatted for decoding.
    - `in_sz`: An unsigned long representing the size of the input data array. It must accurately reflect the size of the data pointed to by `in`.
- **Output**: Returns an integer indicating the success (non-zero) or failure (zero) of the differential test.
- **See also**: [`sol_compat_syscall_fixture`](fd_exec_sol_compat.c.driver.md#sol_compat_syscall_fixture)  (Implementation)


---
### sol\_compat\_vm\_interp\_fixture<!-- {{#callable_declaration:sol_compat_vm_interp_fixture}} -->
Run a differential test using a VM interpreter fixture.
- **Description**: This function is used to run a differential test between Agave and Firedancer using a VM interpreter fixture. It should be called with a properly initialized runner and a valid input buffer containing the fixture data. The function decodes the input data, executes the test, and compares the results. It returns an integer indicating the success of the test. Ensure that the runner is set up before calling this function and that the input data is correctly formatted.
- **Inputs**:
    - `runner`: A pointer to an initialized fd_runtime_fuzz_runner_t structure. Must not be null. The caller retains ownership.
    - `in`: A pointer to a buffer containing the input data for the fixture. Must not be null. The data should be properly formatted according to the expected fixture structure.
    - `in_sz`: The size of the input buffer in bytes. Must accurately reflect the size of the data in the buffer.
- **Output**: Returns an integer indicating the success of the test: non-zero for success, zero for failure.
- **See also**: [`sol_compat_vm_interp_fixture`](fd_exec_sol_compat.c.driver.md#sol_compat_vm_interp_fixture)  (Implementation)


