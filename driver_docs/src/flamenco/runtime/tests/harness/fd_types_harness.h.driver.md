# Purpose
This code is a C header file designed for a testing harness within a runtime environment, specifically for fuzz testing types in a system named "flamenco." It includes a dependency on another header file, "fd_instr_harness.h," indicating that it likely relies on instrumentation functions or macros defined elsewhere. The file declares a single function prototype, [`fd_runtime_fuzz_type_run`](#fd_runtime_fuzz_type_run), which is intended to execute a fuzz test using a provided runner and input, and produce output within a specified buffer. The use of include guards ensures that the header's contents are only included once per compilation unit, preventing redefinition errors.
# Imports and Dependencies

---
- `fd_instr_harness.h`


# Function Declarations (Public API)

---
### fd\_runtime\_fuzz\_type\_run<!-- {{#callable_declaration:fd_runtime_fuzz_type_run}} -->
Executes a fuzz test on a given input and stores the results in an output buffer.
- **Description**: This function is used to run a fuzz test using a specified runner and input data, storing the results in a provided output buffer. It is essential to ensure that the input data is valid and non-empty before calling this function. The function will populate the output with the effects of the fuzz test, including any serialized and YAML data, if the decoding is successful. The output buffer must be large enough to accommodate the results, and the function will return the number of bytes written to the buffer. If the input is invalid or the buffer is insufficient, the function will return zero.
- **Inputs**:
    - `runner`: A pointer to an fd_runtime_fuzz_runner_t structure that manages the fuzz testing process. Must not be null.
    - `input_`: A pointer to the input data for the fuzz test. The input must be valid and contain non-empty content. If null or empty, the function returns zero.
    - `output_`: A pointer to a location where the function will store a pointer to the effects of the fuzz test. Must not be null.
    - `output_buf`: A pointer to a buffer where the function will store the output data. The buffer must be large enough to hold the results.
    - `output_bufsz`: The size of the output buffer in bytes. Must be sufficient to store the fuzz test results; otherwise, the function returns zero.
- **Output**: Returns the number of bytes written to the output buffer, or zero if the input is invalid or the buffer is insufficient.
- **See also**: [`fd_runtime_fuzz_type_run`](fd_types_harness.c.driver.md#fd_runtime_fuzz_type_run)  (Implementation)


