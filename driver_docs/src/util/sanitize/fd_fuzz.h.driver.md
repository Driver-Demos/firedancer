# Purpose
This code is a C header file designed for use in a fuzz testing framework, specifically tailored to integrate with LLVM's libFuzzer. It includes a conditional macro, `FD_FUZZ_MUST_BE_COVERED`, which is defined differently based on whether code coverage is enabled (`FD_HAS_COVERAGE`). This macro is likely used to ensure certain code paths are executed during fuzz testing. The file also declares a function prototype for [`LLVMFuzzerMutate`](#LLVMFuzzerMutate), which is a function used to mutate input data for fuzz testing, taking a pointer to the data, its current size, and a maximum size as parameters. The inclusion of `fd_util_base.h` suggests that this header is part of a larger utility library, and the use of `FD_PROTOTYPES_BEGIN` and `FD_PROTOTYPES_END` indicates a structured approach to managing function prototypes.
# Imports and Dependencies

---
- `../fd_util_base.h`


# Function Declarations (Public API)

---
### LLVMFuzzerMutate<!-- {{#callable_declaration:LLVMFuzzerMutate}} -->
Mutates the input data buffer for fuzz testing.
- **Description**: This function is used to mutate a given data buffer, typically for the purpose of fuzz testing. It takes a buffer and its current size, and attempts to mutate it without exceeding a specified maximum size. This function is intended to be used in environments where fuzz testing is performed, and it is expected to be overridden by a more specific implementation if needed. The function must be called with valid parameters, and the data buffer should be properly allocated and large enough to accommodate the maximum size specified.
- **Inputs**:
    - `data`: A pointer to the buffer containing the data to be mutated. The buffer must be allocated by the caller and should be large enough to hold up to 'max_sz' bytes. The caller retains ownership of the buffer.
    - `data_sz`: The current size of the data in the buffer, in bytes. It must be less than or equal to 'max_sz'.
    - `max_sz`: The maximum size, in bytes, that the buffer can grow to as a result of the mutation. It must be greater than or equal to 'data_sz'.
- **Output**: Returns the new size of the data in the buffer after mutation, which will be less than or equal to 'max_sz'.
- **See also**: [`LLVMFuzzerMutate`](fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)  (Implementation)


