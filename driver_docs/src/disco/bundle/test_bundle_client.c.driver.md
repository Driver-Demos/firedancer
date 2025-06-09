# Purpose
This C source code file is designed to test the functionality of a mock bundle topology within a system, likely related to network packet processing or a similar domain. The file includes functions to create and destroy a test environment ([`test_bundle_env_create`](#test_bundle_env_create) and [`test_bundle_env_destroy`](#test_bundle_env_destroy)), which sets up a mock environment for testing the forwarding of packets and bundles. The code utilizes structures such as `test_bundle_env_t` and `fd_bundle_tile_t` to manage the state and context of the test environment, including memory caches (`mcache`) and data caches (`dcache`). The file also includes test functions ([`test_data_path`](#test_data_path) and [`test_missing_builder_fee_info`](#test_missing_builder_fee_info)) that simulate the reception of messages and verify the correct forwarding behavior of packets and bundles, particularly in scenarios where builder fee information is missing.

The file serves as an executable test suite, as indicated by the presence of a [`main`](#main) function, which initializes the test environment, executes the test cases, and cleans up resources. The tests are designed to ensure that the system correctly handles packet and bundle forwarding, with specific checks on metrics such as packet reception and failure counts when builder information is unavailable. The code imports binary data for testing purposes and uses macros and functions from the Firedancer library to manage shared memory and workspace resources. Overall, this file provides a focused set of tests to validate the behavior of a specific component within a larger system, ensuring reliability and correctness in handling network data.
# Imports and Dependencies

---
- `fd_bundle_tile_private.h`
- `../tiles.h`


# Global Variables

---
### fdctl\_version\_string
- **Type**: ``char const[]``
- **Description**: The `fdctl_version_string` is a global constant character array that holds the version string of the software, initialized to "0.0.0". It is marked with the `__attribute__((weak))` attribute, allowing it to be overridden by other definitions in different translation units if needed.
- **Use**: This variable is used to store and potentially display the version information of the software.


# Data Structures

---
### test\_bundle\_env
- **Type**: `struct`
- **Members**:
    - `stem`: An array of one fd_stem_context_t structure, representing the stem context.
    - `stem_seqs`: An array of one unsigned long integer, representing sequence numbers for the stem.
    - `stem_depths`: An array of one unsigned long integer, representing the depth of the stem.
    - `stem_cr_avail`: An array of one unsigned long integer, representing the available credit for the stem.
    - `out_mcache`: A pointer to fd_frag_meta_t, representing the output metadata cache.
    - `out_dcache`: A pointer to unsigned char, representing the output data cache.
    - `state`: An array of one fd_bundle_tile_t structure, representing the state of the bundle tile.
- **Description**: The `test_bundle_env` structure is designed to encapsulate the environment necessary for testing bundle operations in a networked system. It includes a stem context, sequence numbers, depths, and available credits for managing data flow, as well as pointers to metadata and data caches for handling output. Additionally, it maintains a state for the bundle tile, which is crucial for managing the lifecycle and operations of bundles within the system.


---
### test\_bundle\_env\_t
- **Type**: `struct`
- **Members**:
    - `stem`: An array of one fd_stem_context_t structure, representing the stem context.
    - `stem_seqs`: An array of one unsigned long, representing sequence numbers for the stem.
    - `stem_depths`: An array of one unsigned long, representing the depth of the stem.
    - `stem_cr_avail`: An array of one unsigned long, representing the available credit for the stem.
    - `out_mcache`: A pointer to fd_frag_meta_t, representing the output metadata cache.
    - `out_dcache`: A pointer to unsigned char, representing the output data cache.
    - `state`: An array of one fd_bundle_tile_t structure, representing the state of the bundle tile.
- **Description**: The `test_bundle_env_t` structure is designed to encapsulate the environment for testing bundle operations in a Firedancer system. It includes a stem context, sequence numbers, depths, and available credits for managing the stem, as well as pointers to metadata and data caches for output operations. Additionally, it maintains the state of the bundle tile, which is crucial for simulating and verifying the behavior of packet and bundle forwarding in the system.


# Functions

---
### test\_bundle\_env\_create<!-- {{#callable:test_bundle_env_create}} -->
The `test_bundle_env_create` function initializes a `test_bundle_env_t` structure with memory caches and a fake stem context for testing purposes.
- **Inputs**:
    - `env`: A pointer to a `test_bundle_env_t` structure that will be initialized.
    - `wksp`: A pointer to a `fd_wksp_t` workspace used for memory allocation.
- **Control Flow**:
    - The function begins by zeroing out the memory of the `env` structure using `fd_memset`.
    - It calculates the memory cache depth using the constant `FD_MCACHE_BLOCK`.
    - A memory cache (`mcache`) is created and joined using `fd_mcache_new` and `fd_mcache_join`, with memory allocated from the workspace `wksp`.
    - The function checks if the `mcache` is successfully created using `FD_TEST`.
    - It calculates the data cache size (`dcache_data_sz`) based on the maximum transmission unit (`mtu`), memory cache depth, and other parameters.
    - A data cache (`dcache`) is created and joined using `fd_dcache_new` and `fd_dcache_join`, with memory allocated from the workspace `wksp`.
    - The function checks if the `dcache` is successfully created using `FD_TEST`.
    - A fake stem context is created and assigned to the `env` structure, initializing various fields such as `out_mcache`, `out_dcache`, `stem_seqs`, `stem_depths`, and `stem_cr_avail`.
    - The `state` field of `env` is initialized with the fake stem context and a `verify_out` context, which includes the data cache and watermark settings.
    - Finally, the function returns the initialized `env` structure.
- **Output**: Returns a pointer to the initialized `test_bundle_env_t` structure.


---
### test\_bundle\_env\_destroy<!-- {{#callable:test_bundle_env_destroy}} -->
The `test_bundle_env_destroy` function deallocates and cleans up resources associated with a `test_bundle_env_t` environment.
- **Inputs**:
    - `env`: A pointer to a `test_bundle_env_t` structure that holds the environment to be destroyed.
- **Control Flow**:
    - Call `fd_mcache_leave` on `env->out_mcache` to leave the memory cache and pass the result to `fd_mcache_delete` to delete it, then pass the result to `fd_wksp_free_laddr` to free the memory location.
    - Call `fd_dcache_leave` on `env->out_dcache` to leave the data cache and pass the result to `fd_dcache_delete` to delete it, then pass the result to `fd_wksp_free_laddr` to free the memory location.
    - Use `fd_memset` to zero out the memory of the `env` structure, effectively resetting it.
- **Output**: The function does not return any value; it performs cleanup operations on the provided environment.


---
### test\_data\_path<!-- {{#callable:test_data_path}} -->
The `test_data_path` function tests the forwarding of packets and bundles in a mock bundle topology environment.
- **Inputs**:
    - `wksp`: A pointer to an `fd_wksp_t` workspace structure used for memory allocation and management.
- **Control Flow**:
    - Create a test environment using [`test_bundle_env_create`](#test_bundle_env_create) with the provided workspace.
    - Send a predefined subscribe packets message using [`fd_bundle_client_grpc_rx_msg`](fd_bundle_client.c.driver.md#fd_bundle_client_grpc_rx_msg) to simulate packet subscription.
    - Iterate over the `out_mcache` array to reset the timestamps (`tsorig` and `tspub`) to zero.
    - Define an expected array of `fd_frag_meta_t` structures to represent expected metadata for comparison.
    - Use `FD_TEST` to verify that the `out_mcache` matches the expected metadata using `fd_memeq`.
    - Set `builder_info_avail` to 1 to indicate builder information is available.
    - Send a test bundle response message using [`fd_bundle_client_grpc_rx_msg`](fd_bundle_client.c.driver.md#fd_bundle_client_grpc_rx_msg) to simulate bundle subscription.
    - Destroy the test environment using [`test_bundle_env_destroy`](#test_bundle_env_destroy) to clean up resources.
- **Output**: The function does not return a value; it performs tests and assertions to verify correct behavior of packet and bundle forwarding.
- **Functions called**:
    - [`test_bundle_env_create`](#test_bundle_env_create)
    - [`fd_bundle_client_grpc_rx_msg`](fd_bundle_client.c.driver.md#fd_bundle_client_grpc_rx_msg)
    - [`test_bundle_env_destroy`](#test_bundle_env_destroy)


---
### test\_missing\_builder\_fee\_info<!-- {{#callable:test_missing_builder_fee_info}} -->
The function `test_missing_builder_fee_info` tests the behavior of a system when builder fee information is missing, ensuring that regular packets are forwarded while bundles are not.
- **Inputs**:
    - `wksp`: A pointer to a `fd_wksp_t` workspace structure used for memory allocation and management.
- **Control Flow**:
    - Initialize a test environment using [`test_bundle_env_create`](#test_bundle_env_create) with the provided workspace.
    - Set the `builder_info_avail` flag in the state to 0, indicating that builder fee information is unavailable.
    - Send a regular packet message using [`fd_bundle_client_grpc_rx_msg`](fd_bundle_client.c.driver.md#fd_bundle_client_grpc_rx_msg) and verify that it is forwarded by checking the sequence number and packet received count.
    - Send a bundle message using [`fd_bundle_client_grpc_rx_msg`](fd_bundle_client.c.driver.md#fd_bundle_client_grpc_rx_msg) and verify that it is not forwarded by checking the sequence number and bundle received count.
    - Check that the missing builder info failure count is incremented after attempting to forward a bundle.
    - Destroy the test environment using [`test_bundle_env_destroy`](#test_bundle_env_destroy).
- **Output**: The function does not return a value; it performs tests and uses assertions to verify expected behavior.
- **Functions called**:
    - [`test_bundle_env_create`](#test_bundle_env_create)
    - [`fd_bundle_client_grpc_rx_msg`](fd_bundle_client.c.driver.md#fd_bundle_client_grpc_rx_msg)
    - [`test_bundle_env_destroy`](#test_bundle_env_destroy)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, configures shared memory workspace, runs tests on data path and builder fee information, and then cleans up before exiting.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Determine the CPU index using `fd_tile_cpu_id` and `fd_tile_idx`, and adjust if it exceeds the shared memory CPU count.
    - Extract command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Create a new anonymous workspace with `fd_wksp_new_anonymous` using the extracted parameters.
    - Verify the workspace creation with `FD_TEST`.
    - Run [`test_data_path`](#test_data_path) to test packet and bundle forwarding.
    - Run [`test_missing_builder_fee_info`](#test_missing_builder_fee_info) to test behavior when builder fee information is missing.
    - Delete the anonymous workspace with `fd_wksp_delete_anonymous`.
    - Log a notice message indicating success with `FD_LOG_NOTICE`.
    - Call `fd_halt` to terminate the program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_data_path`](#test_data_path)
    - [`test_missing_builder_fee_info`](#test_missing_builder_fee_info)


