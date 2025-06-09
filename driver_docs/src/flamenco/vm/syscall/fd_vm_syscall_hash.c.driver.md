# Purpose
This C source code file implements system call functions for three cryptographic hash algorithms: SHA-256, Blake3, and Keccak256. These functions are designed to be used within a virtual machine environment, as indicated by the use of the `fd_vm_t` structure and various virtual machine-specific macros and functions. Each function follows a similar structure, beginning with a check to ensure that the number of input sequences does not exceed a predefined maximum. If the input is valid, the functions proceed to initialize the respective hash algorithm, process the input data in chunks, and finally compute the hash result, which is stored in a specified memory location. The functions also update computational cost units (CU) based on the input size, reflecting the resource usage within the virtual machine.

The file is part of a broader system that likely involves cryptographic operations, as suggested by the inclusion of headers related to Keccak256 and the references to a GitHub repository that implements similar functionality in Rust. The code is not intended to be a standalone executable but rather a component of a larger system, possibly a library or module that provides cryptographic services to other parts of the software. The functions defined here do not expose public APIs directly but are likely intended to be invoked by other components within the virtual machine framework. The implementation notes suggest a deliberate choice to avoid using macros for these functions to maintain flexibility for future modifications, such as changes in computational cost parameters.
# Imports and Dependencies

---
- `fd_vm_syscall.h`
- `../../../ballet/keccak256/fd_keccak256.h`


# Functions

---
### fd\_vm\_syscall\_sol\_sha256<!-- {{#callable:fd_vm_syscall_sol_sha256}} -->
The function `fd_vm_syscall_sol_sha256` computes the SHA-256 hash of a series of input data slices and stores the result in a specified memory location.
- **Inputs**:
    - `_vm`: A pointer to the virtual machine context (fd_vm_t) used for memory operations and logging.
    - `vals_addr`: The address in memory where the input data slices are stored.
    - `vals_len`: The number of input data slices to be hashed.
    - `result_addr`: The address in memory where the resulting SHA-256 hash should be stored.
    - `r4`: Unused parameter.
    - `r5`: Unused parameter.
    - `_ret`: A pointer to a ulong where the function will store the return status.
- **Control Flow**:
    - Cast the `_vm` pointer to `fd_vm_t` type for accessing virtual machine context.
    - Check if the number of input slices (`vals_len`) exceeds the maximum allowed (`FD_VM_SHA256_MAX_SLICES`); if so, log an error and return an error code.
    - Update the virtual machine's computational unit (CU) cost with the base cost for SHA-256 operations.
    - Allocate memory for the hash result at `result_addr` with proper alignment for a 32-byte SHA-256 hash.
    - Initialize a SHA-256 context using `fd_sha256_init`.
    - If there are input slices (`vals_len > 0`), load the input data slices from memory and iterate over each slice.
    - For each slice, calculate the cost based on the length of the data and update the CU cost accordingly.
    - Append each slice's data to the SHA-256 context using `fd_sha256_append`.
    - Finalize the SHA-256 hash computation with `fd_sha256_fini`, storing the result in the allocated memory.
    - Set the return status to 0 (success) and return `FD_VM_SUCCESS`.
- **Output**: The function returns an integer status code, `FD_VM_SUCCESS` on success, or an error code if the number of slices exceeds the limit. The computed SHA-256 hash is stored at the specified `result_addr` in memory.


---
### fd\_vm\_syscall\_sol\_blake3<!-- {{#callable:fd_vm_syscall_sol_blake3}} -->
The `fd_vm_syscall_sol_blake3` function performs a Blake3 hash operation on a series of input data sequences and stores the result in a specified memory location.
- **Inputs**:
    - `_vm`: A pointer to the virtual machine context (`fd_vm_t`) used for the syscall.
    - `vals_addr`: The memory address where the input data sequences are stored.
    - `vals_len`: The number of input data sequences to be hashed.
    - `result_addr`: The memory address where the resulting hash should be stored.
    - `r4`: An unused parameter.
    - `r5`: An unused parameter.
    - `_ret`: A pointer to a variable where the function will store the return status.
- **Control Flow**:
    - Cast the `_vm` pointer to a `fd_vm_t` type to access the virtual machine context.
    - Check if the number of input sequences (`vals_len`) exceeds the maximum allowed (`FD_VM_SHA256_MAX_SLICES`).
    - If the limit is exceeded, log an error message and return an error code `FD_VM_SYSCALL_ERR_TOO_MANY_SLICES`.
    - Update the virtual machine's computational unit (CU) cost using `FD_VM_SHA256_BASE_COST`.
    - Allocate memory for the hash result at `result_addr` with a size of 32 bytes.
    - Initialize a Blake3 hash context using `fd_blake3_init`.
    - If there are input sequences, load them from memory and iterate over each sequence.
    - For each sequence, calculate the cost based on its length and update the CU cost.
    - Append the sequence data to the Blake3 hash context using `fd_blake3_append`.
    - Finalize the Blake3 hash and store the result in the allocated memory.
    - Set the return status to `0UL` indicating success and return `FD_VM_SUCCESS`.
- **Output**: The function returns an integer status code, `FD_VM_SUCCESS` on success, and updates the `_ret` pointer with `0UL`.


---
### fd\_vm\_syscall\_sol\_keccak256<!-- {{#callable:fd_vm_syscall_sol_keccak256}} -->
The `fd_vm_syscall_sol_keccak256` function computes the Keccak256 hash of a series of input data sequences and stores the result in a specified memory location.
- **Inputs**:
    - `_vm`: A pointer to the virtual machine context (fd_vm_t) used for the syscall.
    - `vals_addr`: The memory address where the input data sequences are stored.
    - `vals_len`: The number of input data sequences to be hashed.
    - `result_addr`: The memory address where the resulting hash should be stored.
    - `r4`: Unused parameter.
    - `r5`: Unused parameter.
    - `_ret`: A pointer to a ulong where the function will store the return status.
- **Control Flow**:
    - Cast the `_vm` pointer to a `fd_vm_t` type for accessing the virtual machine context.
    - Check if the number of input sequences (`vals_len`) exceeds the maximum allowed (`FD_VM_SHA256_MAX_SLICES`); if so, log an error and return an error code.
    - Update the virtual machine's computational unit (CU) cost with a base cost for the operation.
    - Allocate memory for the hash result at the specified `result_addr` with alignment for a 32-byte result.
    - Initialize a `fd_keccak256_t` structure for hashing.
    - If there are input sequences (`vals_len > 0`), load the input data from the specified `vals_addr` and iterate over each sequence.
    - For each sequence, calculate the cost based on the sequence length and update the CU cost accordingly.
    - Append each sequence to the Keccak256 hash context.
    - Finalize the hash computation and store the result in the allocated memory.
    - Set the return status to 0 (success) and return `FD_VM_SUCCESS`.
- **Output**: The function returns an integer status code, `FD_VM_SUCCESS` on success, and updates the `_ret` pointer with 0. The computed Keccak256 hash is stored at the memory location specified by `result_addr`.


