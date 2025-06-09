# Purpose
This C source file is designed to provide stable APIs for compatibility testing within a differential fuzzing framework. It primarily focuses on executing and verifying various test fixtures related to instruction, transaction, block, ELF loader, syscall, VM interpretation, shred parsing, and type execution. The file includes a series of functions that initialize and manage a workspace, execute test cases, and compare the results against expected outcomes. The code is structured to handle different types of test fixtures, decode input data, execute the corresponding test logic, and encode the results for further analysis.

The file imports several headers and libraries, including those for protocol buffer encoding/decoding and various components of a fuzzing framework. It defines a set of functions that serve as public APIs for executing different types of tests, such as [`sol_compat_instr_execute_v1`](#sol_compat_instr_execute_v1), [`sol_compat_txn_execute_v1`](#sol_compat_txn_execute_v1), and others. These functions are responsible for setting up the test environment, executing the test logic, and ensuring that the workspace is properly managed and cleaned up after execution. The file also includes utility functions for encoding and decoding data, managing memory allocations, and comparing test results. Overall, this file is a critical component of a testing framework aimed at ensuring compatibility and correctness of software components through differential fuzzing.
# Imports and Dependencies

---
- `fd_exec_sol_compat.h`
- `../../../../ballet/nanopb/pb_encode.h`
- `../../../../ballet/nanopb/pb_decode.h`
- `../../fd_executor_err.h`
- `../../../fd_flamenco.h`
- `../../../features/fd_features.h`
- `../../../../ballet/shred/fd_shred.h`
- `fd_instr_harness.h`
- `fd_txn_harness.h`
- `fd_block_harness.h`
- `fd_types_harness.h`
- `fd_vm_harness.h`
- `fd_pack_harness.h`
- `fd_elf_harness.h`
- `generated/elf.pb.h`
- `generated/invoke.pb.h`
- `generated/shred.pb.h`
- `generated/vm.pb.h`
- `generated/type.pb.h`


# Global Variables

---
### features
- **Type**: `sol_compat_features_t`
- **Description**: The `features` variable is a static instance of the `sol_compat_features_t` structure, which is used to store information about compatibility features in the system. It contains fields for the size of the structure, arrays of hardcoded and supported feature IDs, and their respective counts.
- **Use**: This variable is used to manage and track compatibility features, distinguishing between those that are hardcoded and those that are supported, within the compatibility testing framework.


---
### spad\_mem
- **Type**: `uchar*`
- **Description**: The `spad_mem` variable is a static global pointer to an unsigned character array, which is used to allocate and manage a specific memory region within a workspace. This memory region is intended for use in various operations related to the execution of transactions and other processes within the compatibility testing framework.
- **Use**: `spad_mem` is allocated during the workspace initialization and is used to store data required for transaction execution and testing, and is freed during cleanup.


---
### wksp
- **Type**: `fd_wksp_t *`
- **Description**: The `wksp` variable is a static pointer to an `fd_wksp_t` structure, which is initialized to `NULL`. It is used to manage a workspace for memory allocation within the compatibility testing framework. The workspace is created and managed using functions like `fd_wksp_new_anonymous` and `fd_wksp_alloc_laddr`.
- **Use**: This variable is used to allocate and manage memory for various components and features during the execution of compatibility tests.


# Data Structures

---
### sol\_compat\_features\_t
- **Type**: `struct`
- **Members**:
    - `struct_size`: Stores the size of the structure in bytes.
    - `hardcoded_features`: Pointer to an array of hardcoded feature identifiers.
    - `hardcoded_features_cnt`: Count of hardcoded features in the array.
    - `supported_features`: Pointer to an array of supported feature identifiers.
    - `supported_feature_cnt`: Count of supported features in the array.
- **Description**: The `sol_compat_features_t` structure is designed to manage compatibility features within a system. It contains information about the size of the structure, arrays of feature identifiers that are either hardcoded or supported, and their respective counts. This structure is used to track and manage features that are either universally activated or selectively supported, facilitating compatibility testing and feature management in a software environment.


# Functions

---
### sol\_compat\_init<!-- {{#callable:sol_compat_init}} -->
The `sol_compat_init` function initializes the compatibility environment for the Solana execution framework by setting up logging, bootstrapping necessary components, and initializing a workspace.
- **Inputs**:
    - `log_level`: An integer representing the desired log level for the logfile.
- **Control Flow**:
    - Initialize `argc` to 1 and `argv` to an array containing a single string "fd_exec_sol_compat" and a NULL terminator.
    - Check if the environment variable `FD_LOG_PATH` is set; if not, set it to an empty string.
    - Enable logging for unclean exits using `fd_log_enable_unclean_exit()`.
    - Call `fd_boot` with `argc` and `argv_` to perform necessary bootstrapping.
    - Set the log level for the logfile using `fd_log_level_logfile_set(log_level)`.
    - Boot the Flamenco component with `fd_flamenco_boot(NULL, NULL)`.
    - Set the core log level to 4, which aborts on `FD_LOG_ERR`, using `fd_log_level_core_set(4)`.
    - Initialize the workspace with a normal page size by calling `sol_compat_wksp_init(FD_SHMEM_NORMAL_PAGE_SZ)`.
- **Output**: The function does not return any value; it performs initialization tasks.
- **Functions called**:
    - [`sol_compat_wksp_init`](#sol_compat_wksp_init)


---
### sol\_compat\_wksp\_init<!-- {{#callable:sol_compat_wksp_init}} -->
The `sol_compat_wksp_init` function initializes a workspace with a specified page size and allocates memory for features and scratchpad memory.
- **Inputs**:
    - `wksp_page_sz`: The size of the workspace page, which determines the type of memory allocation to be used.
- **Control Flow**:
    - Retrieve the CPU index using `fd_tile_cpu_id` and `fd_tile_idx` functions.
    - Check if the CPU index is greater than or equal to the shared memory CPU count, and if so, set it to 0.
    - Use a switch statement to handle different workspace page sizes:
    - - For `FD_SHMEM_GIGANTIC_PAGE_SZ`, create a new anonymous workspace with a gigantic page size.
    - - For `FD_SHMEM_NORMAL_PAGE_SZ`, create a new anonymous workspace with a normal page size.
    - Log an error if the page size is unsupported.
    - Allocate scratchpad memory using `fd_wksp_alloc_laddr` with specific alignment and footprint.
    - Allocate memory for hardcoded and supported features using `fd_wksp_alloc_laddr`.
    - Iterate over features using `fd_feature_iter_init`, `fd_feature_iter_done`, and `fd_feature_iter_next`.
    - Skip features that are reverted or named 'revise_turbine_epoch_stakes'.
    - Copy feature IDs to hardcoded or supported features arrays based on their activation status.
- **Output**: The function does not return a value but initializes global variables `wksp`, `spad_mem`, and `features` with allocated memory and feature data.


---
### sol\_compat\_fini<!-- {{#callable:sol_compat_fini}} -->
The `sol_compat_fini` function deallocates memory and resources used by the Solana compatibility layer.
- **Inputs**: None
- **Control Flow**:
    - Calls `fd_wksp_free_laddr` to free the memory allocated for `spad_mem`.
    - Calls `fd_wksp_free_laddr` to free the memory allocated for `features.hardcoded_features`.
    - Calls `fd_wksp_free_laddr` to free the memory allocated for `features.supported_features`.
    - Calls `fd_wksp_delete_anonymous` to delete the anonymous workspace `wksp`.
    - Sets `wksp` to `NULL` to indicate that the workspace is no longer in use.
    - Sets `spad_mem` to `NULL` to indicate that the memory is no longer in use.
- **Output**: The function does not return any value.


---
### sol\_compat\_check\_wksp\_usage<!-- {{#callable:sol_compat_check_wksp_usage}} -->
The function `sol_compat_check_wksp_usage` checks for memory leaks in a workspace by examining the usage of allocated memory and logs an error if any leaks are detected.
- **Inputs**: None
- **Control Flow**:
    - Declare a `fd_wksp_usage_t` structure named `usage` to store workspace usage information.
    - Declare an array `tags` with a single element `WKSP_EXECUTE_ALLOC_TAG` to specify the tag for which usage is to be checked.
    - Call `fd_wksp_usage` with the workspace pointer `wksp`, the `tags` array, the number of tags (1), and the `usage` structure to populate `usage` with current memory usage information.
    - Check if `usage->used_sz` is non-zero, indicating that there is memory usage associated with the specified tag.
    - If there is memory usage, log an error message indicating the number of bytes leaked and the number of allocations.
- **Output**: The function does not return any value; it logs an error message if memory leaks are detected.


---
### sol\_compat\_get\_features\_v1<!-- {{#callable:sol_compat_get_features_v1}} -->
The function `sol_compat_get_features_v1` returns a pointer to a static structure containing compatibility features.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the address of the static variable `features`.
- **Output**: A pointer to a `sol_compat_features_t` structure containing compatibility features.


---
### sol\_compat\_setup\_runner<!-- {{#callable:sol_compat_setup_runner}} -->
The `sol_compat_setup_runner` function initializes and returns a new fuzz runner for runtime testing.
- **Inputs**: None
- **Control Flow**:
    - Allocate memory for the runner using `fd_wksp_alloc_laddr` with alignment and footprint specific to the fuzz runner.
    - Create a new fuzz runner instance using [`fd_runtime_fuzz_runner_new`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_new), passing the allocated memory, shared memory pointer `spad_mem`, and an allocation tag.
    - Return the newly created fuzz runner instance.
- **Output**: A pointer to a newly initialized `fd_runtime_fuzz_runner_t` instance.
- **Functions called**:
    - [`fd_runtime_fuzz_runner_align`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_align)
    - [`fd_runtime_fuzz_runner_footprint`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_footprint)
    - [`fd_runtime_fuzz_runner_new`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_new)


---
### sol\_compat\_cleanup\_runner<!-- {{#callable:sol_compat_cleanup_runner}} -->
The `sol_compat_cleanup_runner` function cleans up a test runner by freeing its allocated memory.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure that represents the test runner to be cleaned up.
- **Control Flow**:
    - Call [`fd_runtime_fuzz_runner_delete`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_delete) with the `runner` to delete the runner and get its memory address.
    - Pass the memory address returned by [`fd_runtime_fuzz_runner_delete`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_delete) to `fd_wksp_free_laddr` to free the allocated memory.
- **Output**: This function does not return any value; it performs cleanup operations on the provided runner.
- **Functions called**:
    - [`fd_runtime_fuzz_runner_delete`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_delete)


---
### sol\_compat\_decode<!-- {{#callable:sol_compat_decode}} -->
The `sol_compat_decode` function decodes a serialized input buffer into a specified data structure using a given message descriptor.
- **Inputs**:
    - `decoded`: A pointer to the memory location where the decoded data will be stored.
    - `in`: A constant pointer to the input buffer containing the serialized data to be decoded.
    - `in_sz`: The size of the input buffer in bytes.
    - `decode_type`: A constant pointer to the message descriptor that defines the structure of the data to be decoded.
- **Control Flow**:
    - Initialize a protobuf input stream (`pb_istream_t`) from the input buffer `in` with size `in_sz`.
    - Attempt to decode the input stream into the `decoded` structure using the provided `decode_type` descriptor with `pb_decode_ex`.
    - Check if the decoding was successful (`decode_ok`).
    - If decoding fails, release any allocated resources for `decoded` using `pb_release` and return `NULL`.
    - If decoding is successful, return the `decoded` pointer.
- **Output**: Returns a pointer to the decoded data structure if successful, or `NULL` if decoding fails.


---
### sol\_compat\_encode<!-- {{#callable:sol_compat_encode}} -->
The `sol_compat_encode` function encodes a given data structure into a buffer using a specified protocol buffer message descriptor.
- **Inputs**:
    - `out`: A pointer to an unsigned char buffer where the encoded data will be stored.
    - `out_sz`: A pointer to an unsigned long that initially contains the size of the buffer and will be updated to the number of bytes written after encoding.
    - `to_encode`: A pointer to the data structure that needs to be encoded.
    - `encode_type`: A pointer to a `pb_msgdesc_t` structure that describes the protocol buffer message type for encoding.
- **Control Flow**:
    - Initialize a protocol buffer output stream `ostream` using the provided buffer `out` and its size `*out_sz`.
    - Call `pb_encode` with the output stream, message descriptor `encode_type`, and data `to_encode` to perform the encoding.
    - Check if `pb_encode` was successful; if not, return `NULL`.
    - Update `*out_sz` with the number of bytes written to the buffer.
    - Return the pointer to the original data `to_encode`.
- **Output**: Returns a pointer to the original data `to_encode` if encoding is successful, otherwise returns `NULL`.


---
### sol\_compat\_execute\_wrapper<!-- {{#callable:sol_compat_execute_wrapper}} -->
The `sol_compat_execute_wrapper` function allocates a buffer and executes a test run function, storing the result in the provided output pointer.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which manages the execution environment for fuzz testing.
    - `input`: A pointer to the input data to be used by the `exec_test_run_fn` function.
    - `output`: A pointer to a pointer where the output of the `exec_test_run_fn` function will be stored.
    - `exec_test_run_fn`: A pointer to a function of type `exec_test_run_fn_t` that performs the execution logic and returns the size of the output used.
- **Control Flow**:
    - Allocate a buffer of 100 MB using `fd_spad_alloc` and store the pointer in `out0`.
    - Check if the allocated buffer size is within the maximum allowed size using `FD_TEST`.
    - Call the `exec_test_run_fn` function with the provided `runner`, `input`, `output`, `out0`, and buffer size, storing the result in `out_used`.
    - If `out_used` is zero, set the `output` pointer to `NULL`.
- **Output**: The function does not return a value, but it modifies the `output` pointer to point to the result of the execution or `NULL` if no output was used.


---
### sol\_compat\_cmp\_binary\_strict<!-- {{#callable:sol_compat_cmp_binary_strict}} -->
The `sol_compat_cmp_binary_strict` function compares two binary-encoded data structures for strict equality, including size and content, using a specified encoding type and a scratchpad memory for temporary storage.
- **Inputs**:
    - `effects`: A pointer to the first data structure to be compared, representing the actual effects.
    - `expected`: A pointer to the second data structure to be compared, representing the expected effects.
    - `encode_type`: A pointer to a `pb_msgdesc_t` structure that describes the encoding type to be used for both data structures.
    - `spad`: A pointer to a `fd_spad_t` structure used for temporary memory allocation during the comparison process.
- **Control Flow**:
    - Check if `effects` is NULL; if so, log a warning and return 0.
    - Allocate memory for the encoded output of `effects` using `fd_spad_alloc` and encode it with [`sol_compat_encode`](#sol_compat_encode); if encoding fails, log a warning and return 0.
    - Allocate memory for the encoded output of `expected` using `fd_spad_alloc` and encode it with [`sol_compat_encode`](#sol_compat_encode); if encoding fails, log a warning and return 0.
    - Compare the sizes of the encoded outputs; if they differ, log a warning and return 0.
    - Compare the content of the encoded outputs using `fd_memeq`; if they differ, log a warning and return 0.
    - If all checks pass, return 1 indicating the binary data structures are strictly equal.
- **Output**: Returns 1 if the binary-encoded data structures are strictly equal in size and content, otherwise returns 0.
- **Functions called**:
    - [`sol_compat_encode`](#sol_compat_encode)


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function compares encoded binary data of effects and expected values within a shared memory space, returning success if they match in size and content.
- **Inputs**:
    - `spad`: A pointer to a shared memory space (fd_spad_t) used for temporary allocations during the function's execution.
- **Control Flow**:
    - Check if the 'effects' pointer is NULL and log a warning if so, returning 0.
    - Allocate memory for 'out' and 'exp' using 'fd_spad_alloc' with a predefined maximum size (MAX_SZ).
    - Encode 'effects' into 'out' and 'expected' into 'exp' using 'sol_compat_encode', logging a warning and returning 0 if encoding fails.
    - Compare the sizes of 'out' and 'exp', logging a warning and returning 0 if they differ.
    - Compare the contents of 'out' and 'exp' using 'fd_memeq', logging a warning and returning 0 if they differ.
    - Return 1 if all checks pass, indicating successful comparison.
- **Output**: Returns 1 if the encoded binary data of 'effects' and 'expected' match in size and content, otherwise returns 0.
- **Functions called**:
    - [`sol_compat_encode`](#sol_compat_encode)


---
### \_diff\_txn\_acct<!-- {{#callable:_diff_txn_acct}} -->
The function `_diff_txn_acct` compares two account states and logs warnings if any discrepancies are found, returning 0 for mismatches and 1 if all fields match.
- **Inputs**:
    - `expected`: A pointer to the expected account state of type `fd_exec_test_acct_state_t`.
    - `actual`: A pointer to the actual account state of type `fd_exec_test_acct_state_t`.
- **Control Flow**:
    - Assert that the addresses of the expected and actual account states are equal using `fd_memeq`.
    - Check if the `lamports` values differ; if so, log a warning and return 0.
    - If either `data` field is non-NULL, ensure both are non-NULL, then compare their sizes and contents; log warnings and return 0 on mismatches.
    - Compare the `executable` fields; log a warning and return 0 if they differ.
    - Compare the `rent_epoch` fields; log a warning and return 0 if they differ.
    - Compare the `owner` fields using `fd_memeq`; log a warning and return 0 if they differ.
    - Return 1 if all checks pass without discrepancies.
- **Output**: Returns 1 if all fields in the expected and actual account states match, otherwise returns 0.


---
### \_diff\_resulting\_states<!-- {{#callable:_diff_resulting_states}} -->
The function `_diff_resulting_states` compares two sets of account states to ensure they match in terms of count and individual account details.
- **Inputs**:
    - `expected`: A pointer to a `fd_exec_test_resulting_state_t` structure representing the expected account states.
    - `actual`: A pointer to a `fd_exec_test_resulting_state_t` structure representing the actual account states.
- **Control Flow**:
    - Check if the number of account states in `expected` and `actual` are the same; if not, log a warning and return 0.
    - Iterate over each account in `expected` and `actual` to find matching accounts by address using `fd_memeq`.
    - For each matching account, call [`_diff_txn_acct`](#_diff_txn_acct) to compare the account details; if any comparison fails, return 0.
    - If all checks pass, return 1.
- **Output**: Returns 1 if the account states match, otherwise returns 0.
- **Functions called**:
    - [`_diff_txn_acct`](#_diff_txn_acct)


---
### sol\_compat\_cmp\_txn<!-- {{#callable:sol_compat_cmp_txn}} -->
The `sol_compat_cmp_txn` function compares two transaction results for equality, logging warnings for any mismatches and returning 0 if any differences are found, or 1 if they are identical.
- **Inputs**:
    - `expected`: A pointer to an `fd_exec_test_txn_result_t` structure representing the expected transaction result.
    - `actual`: A pointer to an `fd_exec_test_txn_result_t` structure representing the actual transaction result to compare against the expected result.
- **Control Flow**:
    - Check if the `executed` fields of `expected` and `actual` are equal; log a warning and return 0 if not.
    - Check if the `sanitization_error` fields are equal; log a warning and return 0 if not.
    - Call [`_diff_resulting_states`](#_diff_resulting_states) to compare `resulting_state` fields; return 0 if they differ.
    - Check if the `rent` fields are equal; log a warning and return 0 if not.
    - Check if the `is_ok` fields are equal; log a warning and return 0 if not.
    - Check if the `status` fields are equal; log a warning and return 0 if not.
    - Check if the `instruction_error` fields are equal; log a warning and return 0 if not.
    - If `instruction_error` is true, compare `instruction_error_index` and `custom_error` fields; log warnings and return 0 if they differ.
    - If `return_data` is not NULL in either structure, compare their sizes and contents; log warnings and return 0 if they differ.
    - Check if the `executed_units` fields are equal; log a warning and return 0 if not.
    - Check if the `has_fee_details` fields are equal; log a warning and return 0 if not.
    - If `has_fee_details` is true, compare `transaction_fee` and `prioritization_fee` fields; log warnings and return 0 if they differ.
    - Check if the `loaded_accounts_data_size` fields are equal; log a warning and return 0 if not.
    - Return 1 if all fields match.
- **Output**: Returns 1 if all fields in the `expected` and `actual` transaction results match, otherwise returns 0.
- **Functions called**:
    - [`_diff_resulting_states`](#_diff_resulting_states)


---
### sol\_compat\_instr\_fixture<!-- {{#callable:sol_compat_instr_fixture}} -->
The `sol_compat_instr_fixture` function decodes an instruction fixture, executes it using a fuzz runner, compares the execution effects with expected results, and returns a success status.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which manages the execution environment for fuzz testing.
    - `in`: A pointer to a constant unsigned character array representing the encoded input data for the instruction fixture.
    - `in_sz`: An unsigned long integer representing the size of the input data array.
- **Control Flow**:
    - Initialize a `fd_exec_test_instr_fixture_t` structure to store the decoded fixture.
    - Call [`sol_compat_decode`](#sol_compat_decode) to decode the input data into the fixture structure; if decoding fails, log a warning and return 0.
    - Begin a frame in the scratchpad memory ([`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)) associated with the runner.
    - Initialize a pointer `output` to NULL and execute the instruction using [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper), passing the runner, fixture input, and output pointer.
    - Compare the execution output with the expected output using [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict); store the result in `ok`.
    - End the scratchpad frame (`FD_SPAD_FRAME_END`).
    - Release resources associated with the fixture using `pb_release`.
    - Return the value of `ok`, indicating success or failure of the comparison.
- **Output**: An integer indicating whether the execution effects matched the expected results (1 for success, 0 for failure).
- **Functions called**:
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict)


---
### sol\_compat\_txn\_fixture<!-- {{#callable:sol_compat_txn_fixture}} -->
The `sol_compat_txn_fixture` function decodes a transaction fixture, executes it using a fuzz runner, compares the execution effects with expected results, and returns a success status.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which manages the execution environment for fuzz testing.
    - `in`: A pointer to an array of unsigned characters representing the encoded transaction fixture input data.
    - `in_sz`: An unsigned long integer representing the size of the input data array.
- **Control Flow**:
    - Initialize a `fd_exec_test_txn_fixture_t` structure to zero.
    - Decode the input data into the fixture structure using [`sol_compat_decode`](#sol_compat_decode).
    - If decoding fails, log a warning and return 0.
    - Begin a frame in the runner's scratchpad memory using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN).
    - Execute the transaction using [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper), passing the fixture's input and obtaining the output.
    - Cast the output to `fd_exec_test_txn_result_t` and compare it with the expected output using [`sol_compat_cmp_txn`](#sol_compat_cmp_txn).
    - End the scratchpad frame with `FD_SPAD_FRAME_END`.
    - Release resources associated with the fixture using `pb_release`.
    - Return the comparison result as the function's output.
- **Output**: An integer indicating whether the execution effects matched the expected results (non-zero for success, zero for failure).
- **Functions called**:
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_cmp_txn`](#sol_compat_cmp_txn)


---
### sol\_compat\_block\_fixture<!-- {{#callable:sol_compat_block_fixture}} -->
The `sol_compat_block_fixture` function decodes a block fixture, executes it using a fuzz runner, compares the execution effects with expected results, and returns a success status.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure used to manage the execution environment.
    - `in`: A pointer to an array of unsigned characters representing the input data to be decoded.
    - `in_sz`: An unsigned long integer representing the size of the input data array.
- **Control Flow**:
    - Initialize a `fd_exec_test_block_fixture_t` structure to zero.
    - Call [`sol_compat_decode`](#sol_compat_decode) to decode the input data into the fixture structure.
    - If decoding fails, log a warning and return 0.
    - Begin a frame in the runner's scratchpad memory using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN).
    - Initialize a pointer `output` to NULL.
    - Call [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper) to execute the fixture's input using the runner and store the result in `output`.
    - Call [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict) to compare the execution output with the expected output from the fixture.
    - End the scratchpad frame using `FD_SPAD_FRAME_END`.
    - Release resources associated with the fixture using `pb_release`.
    - Return the result of the comparison (1 for success, 0 for failure).
- **Output**: An integer indicating whether the execution effects matched the expected results (1 for success, 0 for failure).
- **Functions called**:
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict)


---
### sol\_compat\_elf\_loader\_fixture<!-- {{#callable:sol_compat_elf_loader_fixture}} -->
The `sol_compat_elf_loader_fixture` function decodes an ELF loader fixture, executes it using a fuzz runner, compares the execution effects with expected results, and returns the comparison result.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which is used to manage the execution environment for fuzz testing.
    - `in`: A pointer to a constant unsigned character array representing the input data to be decoded as an ELF loader fixture.
    - `in_sz`: An unsigned long integer representing the size of the input data array.
- **Control Flow**:
    - Initialize a `fd_exec_test_elf_loader_fixture_t` structure to zero.
    - Call [`sol_compat_decode`](#sol_compat_decode) to decode the input data into the fixture structure; if decoding fails, log a warning and return 0.
    - Begin a SPAD frame using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN) with the runner's SPAD.
    - Initialize a `void *` pointer `output` to NULL.
    - Call [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper) to execute the fixture's input using the fuzz runner and store the result in `output`.
    - Call [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict) to compare the execution output with the expected output stored in the fixture; store the result in `ok`.
    - End the SPAD frame using `FD_SPAD_FRAME_END`.
    - Call `pb_release` to release resources associated with the fixture structure.
    - Return the value of `ok`, indicating whether the execution effects matched the expected results.
- **Output**: An integer value indicating whether the execution effects matched the expected results (1 for match, 0 for mismatch).
- **Functions called**:
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict)


---
### sol\_compat\_syscall\_fixture<!-- {{#callable:sol_compat_syscall_fixture}} -->
The `sol_compat_syscall_fixture` function decodes a syscall fixture, executes it, compares the output effects with expected results, and returns a success status.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which manages the execution environment for fuzz testing.
    - `in`: A pointer to an array of unsigned characters representing the input data to be decoded into a syscall fixture.
    - `in_sz`: An unsigned long integer representing the size of the input data array.
- **Control Flow**:
    - Initialize a `fd_exec_test_syscall_fixture_t` structure to store the decoded fixture.
    - Attempt to decode the input data into the fixture using [`sol_compat_decode`](#sol_compat_decode); if decoding fails, log a warning and return 0.
    - Begin a frame in the shared memory area (`spad`) associated with the runner.
    - Execute the syscall using [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper), passing the decoded input and capturing the output.
    - Compare the execution output with the expected output stored in the fixture using [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict).
    - End the shared memory frame.
    - Release resources associated with the decoded fixture using `pb_release`.
- **Output**: An integer indicating success (1) if the execution output matches the expected output, or failure (0) otherwise.
- **Functions called**:
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict)


---
### sol\_compat\_vm\_interp\_fixture<!-- {{#callable:sol_compat_vm_interp_fixture}} -->
The `sol_compat_vm_interp_fixture` function decodes a syscall fixture, executes a virtual machine interpretation run, compares the execution effects with expected results, and returns a success status.
- **Inputs**:
    - `runner`: A pointer to an `fd_runtime_fuzz_runner_t` structure, which manages the execution environment for fuzz testing.
    - `in`: A pointer to an array of unsigned characters representing the input data to be decoded into a fixture.
    - `in_sz`: An unsigned long integer representing the size of the input data array.
- **Control Flow**:
    - Initialize a `fd_exec_test_syscall_fixture_t` structure to store the decoded fixture.
    - Attempt to decode the input data into the fixture using [`sol_compat_decode`](#sol_compat_decode); if decoding fails, log a warning and return 0.
    - Begin a frame in the scratchpad memory ([`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)).
    - Execute the virtual machine interpretation using [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper), passing the fixture's input and a function pointer to `fd_runtime_fuzz_vm_interp_run`.
    - Compare the execution output with the expected output from the fixture using [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict).
    - End the scratchpad memory frame (`FD_SPAD_FRAME_END`).
    - Release resources associated with the fixture using `pb_release`.
    - Return the result of the comparison (1 for success, 0 for failure).
- **Output**: An integer indicating success (1) or failure (0) of the execution and comparison process.
- **Functions called**:
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_cmp_binary_strict`](#sol_compat_cmp_binary_strict)


---
### sol\_compat\_instr\_execute\_v1<!-- {{#callable:sol_compat_instr_execute_v1}} -->
The `sol_compat_instr_execute_v1` function sets up a runtime fuzz runner, decodes input data, executes a test instruction, encodes the output effects, and performs cleanup operations.
- **Inputs**:
    - `out`: A pointer to an unsigned char array where the encoded output effects will be stored.
    - `out_sz`: A pointer to an unsigned long that will hold the size of the encoded output effects.
    - `in`: A pointer to a constant unsigned char array containing the input data to be decoded and executed.
    - `in_sz`: An unsigned long representing the size of the input data.
- **Control Flow**:
    - Initialize a runtime fuzz runner using `sol_compat_setup_runner()`.
    - Decode the input data into a `fd_exec_test_instr_context_t` structure using `sol_compat_decode()`.
    - If decoding fails, clean up the runner and return 0.
    - Begin a special memory frame using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN) for execution.
    - Execute the instruction using `sol_compat_execute_wrapper()` and store the output.
    - If there is output, encode it using `sol_compat_encode()` and update `ok` to indicate success.
    - End the memory frame with `FD_SPAD_FRAME_END`.
    - Release the decoded input data and clean up the runner using `sol_compat_cleanup_runner()`.
    - Check that workspace usage is zero using `sol_compat_check_wksp_usage()`.
    - Return the success status `ok`.
- **Output**: An integer indicating success (non-zero) or failure (zero) of the execution and encoding process.
- **Functions called**:
    - [`sol_compat_setup_runner`](#sol_compat_setup_runner)
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_encode`](#sol_compat_encode)
    - [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage)


---
### sol\_compat\_txn\_execute\_v1<!-- {{#callable:sol_compat_txn_execute_v1}} -->
The `sol_compat_txn_execute_v1` function executes a transaction using a fuzz runner, decodes the input, executes the transaction, encodes the output, and ensures no workspace memory leaks.
- **Inputs**:
    - `out`: A pointer to an unsigned character array where the encoded output will be stored.
    - `out_sz`: A pointer to an unsigned long that will hold the size of the encoded output.
    - `in`: A constant pointer to an unsigned character array containing the encoded input data.
    - `in_sz`: An unsigned long representing the size of the input data.
- **Control Flow**:
    - Initialize a fuzz runner using `sol_compat_setup_runner()`.
    - Decode the input data into a transaction context using `sol_compat_decode()`.
    - If decoding fails, clean up the runner and return 0.
    - Begin a frame in the scratchpad memory using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN).
    - Execute the transaction using `sol_compat_execute_wrapper()` and store the result in `output`.
    - If `output` is not NULL, encode the output using `sol_compat_encode()` and update `ok` based on the success of encoding.
    - End the scratchpad frame using `FD_SPAD_FRAME_END`.
    - Release the decoded input context using `pb_release()`.
    - Clean up the fuzz runner using `sol_compat_cleanup_runner()`.
    - Check for workspace memory leaks using `sol_compat_check_wksp_usage()`.
    - Return the value of `ok`, indicating success or failure of the operation.
- **Output**: An integer indicating success (non-zero) or failure (zero) of the transaction execution and encoding process.
- **Functions called**:
    - [`sol_compat_setup_runner`](#sol_compat_setup_runner)
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_encode`](#sol_compat_encode)
    - [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage)


---
### sol\_compat\_block\_execute\_v1<!-- {{#callable:sol_compat_block_execute_v1}} -->
The `sol_compat_block_execute_v1` function sets up a runtime fuzz runner, decodes input data, executes a block test, encodes the results, and performs cleanup, returning a success status.
- **Inputs**:
    - `out`: A pointer to an unsigned character array where the encoded output will be stored.
    - `out_sz`: A pointer to an unsigned long that will hold the size of the encoded output.
    - `in`: A constant pointer to an unsigned character array containing the input data to be decoded.
    - `in_sz`: An unsigned long representing the size of the input data.
- **Control Flow**:
    - Initialize a runtime fuzz runner using `sol_compat_setup_runner()`.
    - Decode the input data into a `fd_exec_test_block_context_t` structure using `sol_compat_decode()`.
    - If decoding fails, clean up the runner and return 0.
    - Begin a frame in the runner's scratchpad memory using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN).
    - Execute the block test using `sol_compat_execute_wrapper()` and store the output.
    - If there is output, encode it using `sol_compat_encode()` and update the success status `ok`.
    - End the scratchpad frame with `FD_SPAD_FRAME_END`.
    - Release the decoded input data using `pb_release()`.
    - Clean up the runner using `sol_compat_cleanup_runner()`.
    - Check for workspace usage issues with `sol_compat_check_wksp_usage()`.
    - Return the success status `ok`.
- **Output**: An integer indicating success (non-zero) or failure (zero) of the execution and encoding process.
- **Functions called**:
    - [`sol_compat_setup_runner`](#sol_compat_setup_runner)
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_encode`](#sol_compat_encode)
    - [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage)


---
### sol\_compat\_elf\_loader\_v1<!-- {{#callable:sol_compat_elf_loader_v1}} -->
The `sol_compat_elf_loader_v1` function decodes an ELF loader context, executes it using a fuzz runner, encodes the resulting effects, and returns a success status.
- **Inputs**:
    - `out`: A pointer to a buffer where the encoded output effects will be stored.
    - `out_sz`: A pointer to a variable that holds the size of the output buffer and will be updated with the size of the encoded output.
    - `in`: A pointer to the input buffer containing the encoded ELF loader context.
    - `in_sz`: The size of the input buffer.
- **Control Flow**:
    - Initialize a fuzz runner using `sol_compat_setup_runner()`.
    - Decode the input ELF loader context using `sol_compat_decode()`; if decoding fails, clean up the runner and return 0.
    - Begin a SPAD frame for memory management.
    - Execute the decoded context using `sol_compat_execute_wrapper()` and store the output.
    - If execution produces an output, encode it using `sol_compat_encode()` and set the success flag `ok`.
    - End the SPAD frame.
    - Release resources associated with the decoded input using `pb_release()`.
    - Clean up the fuzz runner using `sol_compat_cleanup_runner()`.
    - Check for workspace usage to ensure no memory leaks using `sol_compat_check_wksp_usage()`.
    - Return the success status `ok`.
- **Output**: An integer indicating success (non-zero) or failure (zero) of the operation.
- **Functions called**:
    - [`sol_compat_setup_runner`](#sol_compat_setup_runner)
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_encode`](#sol_compat_encode)
    - [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage)


---
### sol\_compat\_vm\_syscall\_execute\_v1<!-- {{#callable:sol_compat_vm_syscall_execute_v1}} -->
The function `sol_compat_vm_syscall_execute_v1` sets up a runtime environment, decodes input data, executes a syscall, encodes the results, and performs cleanup, returning a success status.
- **Inputs**:
    - `out`: A pointer to an unsigned char array where the encoded output will be stored.
    - `out_sz`: A pointer to an unsigned long that will hold the size of the encoded output.
    - `in`: A pointer to a constant unsigned char array containing the input data to be decoded and processed.
    - `in_sz`: An unsigned long representing the size of the input data.
- **Control Flow**:
    - Initialize a runtime fuzz runner using [`sol_compat_setup_runner`](#sol_compat_setup_runner).
    - Decode the input data into a syscall context using [`sol_compat_decode`](#sol_compat_decode).
    - If decoding fails, clean up the runner and return 0.
    - Begin a frame in the scratchpad memory using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN).
    - Execute the syscall using [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper), storing the result in `output`.
    - If `output` is not NULL, encode the output data using [`sol_compat_encode`](#sol_compat_encode) and update `ok` to indicate success.
    - End the scratchpad frame using `FD_SPAD_FRAME_END`.
    - Release resources associated with the decoded input using `pb_release`.
    - Clean up the runner using [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner).
    - Check for workspace usage errors using [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage).
- **Output**: Returns an integer indicating success (non-zero) or failure (zero) of the syscall execution and encoding process.
- **Functions called**:
    - [`sol_compat_setup_runner`](#sol_compat_setup_runner)
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_encode`](#sol_compat_encode)
    - [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage)


---
### sol\_compat\_vm\_interp\_v1<!-- {{#callable:sol_compat_vm_interp_v1}} -->
The `sol_compat_vm_interp_v1` function sets up a runtime fuzz runner, decodes input data, executes a virtual machine interpretation, encodes the results, and performs cleanup operations.
- **Inputs**:
    - `out`: A pointer to an unsigned char array where the encoded output will be stored.
    - `out_sz`: A pointer to an unsigned long that will hold the size of the encoded output.
    - `in`: A pointer to a constant unsigned char array containing the input data to be decoded and processed.
    - `in_sz`: An unsigned long representing the size of the input data.
- **Control Flow**:
    - Initialize a runtime fuzz runner using `sol_compat_setup_runner()`.
    - Decode the input data into a `fd_exec_test_syscall_context_t` structure using `sol_compat_decode()`.
    - If decoding fails, clean up the runner and return 0.
    - Begin a special memory frame using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN) for the runner's scratchpad memory.
    - Execute the virtual machine interpretation using `sol_compat_execute_wrapper()` with the decoded input and `fd_runtime_fuzz_vm_interp_run` function.
    - If execution produces output, encode the output using `sol_compat_encode()` and update `ok` to indicate success.
    - End the special memory frame using `FD_SPAD_FRAME_END`.
    - Release resources associated with the decoded input using `pb_release()`.
    - Clean up the runner using `sol_compat_cleanup_runner()`.
    - Check for workspace usage to ensure no memory leaks using `sol_compat_check_wksp_usage()`.
- **Output**: Returns an integer `ok`, which is 1 if the execution and encoding were successful, otherwise 0.
- **Functions called**:
    - [`sol_compat_setup_runner`](#sol_compat_setup_runner)
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_encode`](#sol_compat_encode)
    - [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage)


---
### sol\_compat\_shred\_parse\_v1<!-- {{#callable:sol_compat_shred_parse_v1}} -->
The function `sol_compat_shred_parse_v1` decodes input data, parses it to check its validity, and encodes the result back to the output buffer.
- **Inputs**:
    - `out`: A pointer to an unsigned character array where the encoded output will be stored.
    - `out_sz`: A pointer to an unsigned long that will hold the size of the encoded output.
    - `in`: A constant pointer to an unsigned character array containing the input data to be decoded.
    - `in_sz`: An unsigned long representing the size of the input data.
- **Control Flow**:
    - Initialize a `fd_exec_test_shred_binary_t` structure to hold the decoded input data.
    - Call [`sol_compat_decode`](#sol_compat_decode) to decode the input data into the `input` structure.
    - Check if the decoding was successful; if not, return 0.
    - Check if the `data` field of the decoded input is NULL; if so, release resources and return 0.
    - Initialize a `fd_exec_test_accepts_shred_t` structure to hold the output data.
    - Call `fd_shred_parse` to parse the input data and set the `valid` field of the output structure based on the result.
    - Release resources associated with the input structure.
    - Encode the output structure into the `out` buffer using [`sol_compat_encode`](#sol_compat_encode).
    - Return the result of the encoding operation as an integer.
- **Output**: An integer indicating success (non-zero) or failure (zero) of the parsing and encoding process.
- **Functions called**:
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_encode`](#sol_compat_encode)


---
### sol\_compat\_pack\_compute\_budget\_v1<!-- {{#callable:sol_compat_pack_compute_budget_v1}} -->
The function `sol_compat_pack_compute_budget_v1` decodes input data, executes a compute budget operation using a fuzz runner, encodes the result, and checks for workspace usage.
- **Inputs**:
    - `out`: A pointer to an unsigned char array where the encoded output will be stored.
    - `out_sz`: A pointer to an unsigned long that holds the size of the output buffer and will be updated with the size of the encoded output.
    - `in`: A pointer to a constant unsigned char array containing the input data to be decoded.
    - `in_sz`: An unsigned long representing the size of the input data.
- **Control Flow**:
    - Initialize a fuzz runner using [`sol_compat_setup_runner`](#sol_compat_setup_runner).
    - Decode the input data into a `fd_exec_test_pack_compute_budget_context_t` structure using [`sol_compat_decode`](#sol_compat_decode).
    - If decoding fails, clean up the runner and return 0.
    - Begin a special memory frame using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN).
    - Execute the compute budget operation using [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper).
    - If execution produces output, encode it using [`sol_compat_encode`](#sol_compat_encode) and update the `ok` flag.
    - End the special memory frame using `FD_SPAD_FRAME_END`.
    - Release the decoded input data using `pb_release`.
    - Clean up the fuzz runner using [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner).
    - Check that workspace usage is zero using [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage).
    - Return the `ok` flag indicating success or failure.
- **Output**: An integer indicating success (non-zero) or failure (zero) of the operation.
- **Functions called**:
    - [`sol_compat_setup_runner`](#sol_compat_setup_runner)
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_encode`](#sol_compat_encode)
    - [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage)


---
### sol\_compat\_type\_execute\_v1<!-- {{#callable:sol_compat_type_execute_v1}} -->
The `sol_compat_type_execute_v1` function sets up a runtime fuzz runner, decodes input data, executes a test type run, encodes the output, and cleans up resources, returning a success status.
- **Inputs**:
    - `out`: A pointer to an unsigned char array where the encoded output will be stored.
    - `out_sz`: A pointer to an unsigned long that will hold the size of the encoded output.
    - `in`: A pointer to a constant unsigned char array containing the input data to be decoded.
    - `in_sz`: An unsigned long representing the size of the input data.
- **Control Flow**:
    - Initialize a runtime fuzz runner using `sol_compat_setup_runner()`.
    - Decode the input data into a `fd_exec_test_type_context_t` structure using `sol_compat_decode()`.
    - If decoding fails, clean up the runner and return 0.
    - Begin a frame in the scratchpad memory using [`FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN).
    - Execute the test type run using `sol_compat_execute_wrapper()` and store the result in `output`.
    - If `output` is not NULL, encode the output data using `sol_compat_encode()` and update `ok` with the success status.
    - End the scratchpad frame using `FD_SPAD_FRAME_END`.
    - Release the decoded input data using `pb_release()`.
    - Clean up the runner using `sol_compat_cleanup_runner()`.
    - Check for workspace usage issues with `sol_compat_check_wksp_usage()`.
    - Return the success status `ok`.
- **Output**: An integer indicating success (non-zero) or failure (zero) of the execution and encoding process.
- **Functions called**:
    - [`sol_compat_setup_runner`](#sol_compat_setup_runner)
    - [`sol_compat_decode`](#sol_compat_decode)
    - [`sol_compat_cleanup_runner`](#sol_compat_cleanup_runner)
    - [`sol_compat_cmp_binary_strict::FD_SPAD_FRAME_BEGIN`](#sol_compat_cmp_binary_strictFD_SPAD_FRAME_BEGIN)
    - [`sol_compat_execute_wrapper`](#sol_compat_execute_wrapper)
    - [`sol_compat_encode`](#sol_compat_encode)
    - [`sol_compat_check_wksp_usage`](#sol_compat_check_wksp_usage)


