# Purpose
This C source code file defines a set of callback functions for various components within a larger system, likely related to a runtime environment or a data processing framework. The file includes several headers from different directories, indicating that it is part of a modular system with shared configurations and utilities. The primary purpose of this file is to provide specific implementations for footprint calculation, memory alignment, and initialization (or "new" operations) for different components such as `runtime_pub`, `blockstore`, `fec_sets`, `txncache`, and `exec_spad`. Each component has a corresponding set of functions that determine its memory requirements (`footprint`), alignment constraints (`align`), and initialization logic (`new`).

The file defines these functions as static, suggesting that they are intended for use only within this compilation unit, and it registers them in `fd_topo_obj_callbacks_t` structures. This indicates that the file is part of a larger system where these components are dynamically managed, possibly in a runtime environment that requires precise control over memory and resource allocation. The use of macros and utility functions like `VAL` and `FD_TEST` suggests a focus on error handling and configuration-driven behavior, where component properties are queried and validated at runtime. Overall, this file provides a cohesive set of functionalities for managing the lifecycle and resource requirements of specific system components.
# Imports and Dependencies

---
- `../shared/fd_config.h`
- `../../util/pod/fd_pod_format.h`
- `../../flamenco/runtime/fd_txncache.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../flamenco/runtime/fd_runtime.h`
- `../../flamenco/runtime/fd_runtime_public.h`


# Global Variables

---
### fd\_obj\_cb\_runtime\_pub
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_runtime_pub` is a global variable of type `fd_topo_obj_callbacks_t`, which is a structure used to define a set of callback functions for a specific object type in a topology. This instance is specifically configured for the 'runtime_pub' object, with associated functions for footprint calculation, alignment, and initialization.
- **Use**: This variable is used to manage and interact with 'runtime_pub' objects within a topology by providing specific callback functions for their lifecycle operations.


---
### fd\_obj\_cb\_blockstore
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_blockstore` is a global variable of type `fd_topo_obj_callbacks_t`, which is a structure containing function pointers and a name for handling blockstore objects. It includes a name identifier, a function to calculate the memory footprint, a function to determine memory alignment, and a function to initialize new blockstore objects.
- **Use**: This variable is used to manage and interact with blockstore objects within the system, providing necessary callbacks for their lifecycle management.


---
### fd\_obj\_cb\_fec\_sets
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The variable `fd_obj_cb_fec_sets` is an instance of the `fd_topo_obj_callbacks_t` structure, which is used to define a set of callback functions for handling 'fec_sets' objects in the system. It includes a name identifier, a function to calculate the memory footprint, a function to determine memory alignment, and a function to initialize new instances of the object.
- **Use**: This variable is used to manage 'fec_sets' objects by providing specific callback functions for footprint calculation, alignment, and initialization.


---
### fd\_obj\_cb\_txncache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_txncache` is a global variable of type `fd_topo_obj_callbacks_t`, which is a structure used to define callback functions for handling transaction cache objects in the system. It includes a name identifier 'txncache', and function pointers for calculating the footprint, alignment, and initialization of transaction cache objects.
- **Use**: This variable is used to manage the lifecycle and memory requirements of transaction cache objects within the system's topology.


---
### fd\_obj\_cb\_exec\_spad
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_exec_spad` is a global variable of type `fd_topo_obj_callbacks_t`, which is a structure containing function pointers and a name for handling specific operations related to the 'exec_spad' object. It includes functions for determining the memory footprint, alignment, and initialization of the 'exec_spad' object.
- **Use**: This variable is used to manage the lifecycle and memory requirements of the 'exec_spad' object within the system.


# Functions

---
### runtime\_pub\_footprint<!-- {{#callable:runtime_pub_footprint}} -->
The `runtime_pub_footprint` function calculates the memory footprint required for a runtime public object using a specified maximum memory value.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration; it is not used in this function.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the topology object, used to query the maximum memory value.
- **Control Flow**:
    - The function begins by casting the `topo` parameter to void to indicate it is unused.
    - It calls the `VAL` macro with the argument "mem_max" to retrieve the maximum memory value associated with the object `obj`.
    - The `VAL` macro queries the `topo->props` for the property `obj.<id>.mem_max` and logs an error if the value is not set.
    - The retrieved memory value is then passed to the `fd_runtime_public_footprint` function.
    - The result from `fd_runtime_public_footprint` is returned as the output of the function.
- **Output**: The function returns an `ulong` representing the calculated memory footprint for the runtime public object.


---
### runtime\_pub\_align<!-- {{#callable:runtime_pub_align}} -->
The `runtime_pub_align` function returns the alignment requirement for the runtime public object.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both of which are marked as unused with the `FD_FN_UNUSED` macro.
    - It directly calls and returns the result of the `fd_runtime_public_align()` function without any additional logic or processing.
- **Output**: The function returns an `ulong` value representing the alignment requirement for the runtime public object.


---
### runtime\_pub\_new<!-- {{#callable:runtime_pub_new}} -->
The `runtime_pub_new` function initializes a new runtime public object using the topology and object information provided.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology information.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure representing the object information, including its ID.
- **Control Flow**:
    - The function calls `fd_topo_obj_laddr` with `topo` and `obj->id` to get the local address of the object.
    - It uses the `VAL` macro to query the `mem_max` property from the topology's properties for the given object ID.
    - The function then calls `fd_runtime_public_new` with the local address and the `mem_max` value.
    - The `FD_TEST` macro is used to ensure that `fd_runtime_public_new` executes successfully, otherwise it logs an error.
- **Output**: The function does not return a value; it performs initialization and checks for success using `FD_TEST`.


---
### blockstore\_footprint<!-- {{#callable:blockstore_footprint}} -->
The `blockstore_footprint` function calculates the memory footprint required for a blockstore object based on configuration values from a topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure containing topology properties.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing a specific object within the topology.
- **Control Flow**:
    - The function uses the `VAL` macro to query configuration values ('shred_max', 'block_max', 'idx_max', 'txn_max', and 'alloc_max') from the topology properties associated with the given object.
    - It calls `fd_blockstore_footprint` with the retrieved values ('shred_max', 'block_max', 'idx_max', 'txn_max') to compute part of the footprint.
    - It adds the value of 'alloc_max' to the result of `fd_blockstore_footprint` to get the total footprint.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the blockstore object.


---
### blockstore\_align<!-- {{#callable:blockstore_align}} -->
The `blockstore_align` function returns the alignment requirement for a blockstore object.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both of which are marked as unused with the `FD_FN_UNUSED` macro.
    - It directly calls and returns the result of the `fd_blockstore_align()` function without any additional logic or processing.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a blockstore object.


---
### blockstore\_new<!-- {{#callable:blockstore_new}} -->
The `blockstore_new` function initializes a new blockstore using parameters retrieved from a topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology for which the blockstore is being initialized.
- **Control Flow**:
    - The function retrieves the local address of the object using `fd_topo_obj_laddr` with `topo` and `obj->id` as arguments.
    - It uses the `VAL` macro to query several configuration parameters (`wksp_tag`, `seed`, `shred_max`, `block_max`, `idx_max`, `txn_max`) from the topology properties associated with the object.
    - The function calls `fd_blockstore_new` with the retrieved local address and configuration parameters to initialize the blockstore.
    - The `FD_TEST` macro is used to ensure that `fd_blockstore_new` executes successfully, logging an error if it does not.
- **Output**: The function does not return a value; it performs initialization and checks for success using `FD_TEST`.


---
### fec\_sets\_footprint<!-- {{#callable:fec_sets_footprint}} -->
The `fec_sets_footprint` function retrieves the footprint size of a Forward Error Correction (FEC) set from a topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific topology object for which the footprint is being queried.
- **Control Flow**:
    - The function uses the `VAL` macro to query the footprint size ('sz') from the properties of the topology object.
    - The `VAL` macro retrieves the value associated with the key 'obj.<id>.sz' from the topology's properties, where `<id>` is the identifier of the object.
    - If the queried value is `ULONG_MAX`, indicating that the property was not set, an error is logged.
    - The function returns the retrieved footprint size.
- **Output**: The function returns an `ulong` representing the footprint size of the FEC set.


---
### fec\_sets\_align<!-- {{#callable:fec_sets_align}} -->
The `fec_sets_align` function returns the alignment requirement for FEC sets by calling `fd_dcache_align`.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also not used in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both of which are marked as unused with `FD_FN_UNUSED`.
    - The function directly returns the result of the `fd_dcache_align` function call.
- **Output**: The function returns an `ulong` value representing the alignment requirement for FEC sets.


---
### fec\_sets\_new<!-- {{#callable:fec_sets_new}} -->
The `fec_sets_new` function verifies the local address of a topology object using a test macro.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, representing the topology configuration.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, representing the topology object whose local address is to be verified.
- **Control Flow**:
    - The function calls `FD_TEST` with the result of `fd_topo_obj_laddr(topo, obj->id)` to verify the local address of the object identified by `obj->id` in the given topology `topo`.
- **Output**: The function does not return any value; it performs a test operation to ensure the local address is valid.


---
### txncache\_footprint<!-- {{#callable:txncache_footprint}} -->
The `txncache_footprint` function calculates the memory footprint required for a transaction cache based on specific configuration parameters.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure containing topology properties.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing a specific topology object.
- **Control Flow**:
    - The function uses the `VAL` macro to query configuration values from the `topo` properties for the given `obj` ID, specifically 'max_rooted_slots', 'max_live_slots', 'max_txn_per_slot', and 'max_constipated_slots'.
    - If any of these values are not set, the `VAL` macro logs an error and terminates the program.
    - The function then calls `fd_txncache_footprint` with these values to compute the required memory footprint.
- **Output**: Returns an `ulong` representing the calculated memory footprint for the transaction cache.


---
### txncache\_align<!-- {{#callable:txncache_align}} -->
The `txncache_align` function returns the alignment requirement for a transaction cache.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure, which is not used in this function.
    - `obj`: A pointer to a `fd_topo_obj_t` structure, which is also not used in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both of which are marked as unused with the `FD_FN_UNUSED` macro.
    - It directly calls and returns the result of the `fd_txncache_align()` function.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a transaction cache.


---
### txncache\_new<!-- {{#callable:txncache_new}} -->
The `txncache_new` function initializes a new transaction cache using parameters derived from a topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology for which the transaction cache is being initialized.
- **Control Flow**:
    - The function calls `fd_txncache_new` with the local address of the object obtained from `fd_topo_obj_laddr` and several configuration values retrieved using the `VAL` macro.
    - The `VAL` macro queries the topology properties for specific configuration parameters related to transaction cache settings, such as `max_rooted_slots`, `max_live_slots`, `max_txn_per_slot`, and `max_constipated_slots`.
    - The `FD_TEST` macro is used to ensure that the `fd_txncache_new` function call is successful, and it will log an error if the call fails.
- **Output**: The function does not return a value; it performs initialization and checks for success using the `FD_TEST` macro.


---
### exec\_spad\_footprint<!-- {{#callable:exec_spad_footprint}} -->
The `exec_spad_footprint` function calculates the memory footprint required for the execution of a single transaction using a default footprint value.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is not used in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both of which are marked as unused with `FD_FN_UNUSED`.
    - It calls the `fd_spad_footprint` function with a predefined constant `FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT`.
    - The result of the `fd_spad_footprint` function call is returned as the output of `exec_spad_footprint`.
- **Output**: The function returns an `ulong` representing the memory footprint for transaction execution, calculated using a default value.


---
### exec\_spad\_align<!-- {{#callable:exec_spad_align}} -->
The `exec_spad_align` function returns the alignment requirement for the execution scratchpad.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is marked as unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also marked as unused in this function.
- **Control Flow**:
    - The function directly calls and returns the result of `fd_spad_align()`.
- **Output**: The function returns an `ulong` value representing the alignment requirement for the execution scratchpad.


---
### exec\_spad\_new<!-- {{#callable:exec_spad_new}} -->
The `exec_spad_new` function initializes a new SPAD (Scratchpad) object using the provided topology and object identifiers.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure representing the specific object within the topology.
- **Control Flow**:
    - The function calls `fd_topo_obj_laddr` with `topo` and `obj->id` to get the local address of the object.
    - It then calls `fd_spad_new` with the obtained local address and a default footprint value `FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT`.
    - The `FD_TEST` macro is used to ensure that `fd_spad_new` executes successfully, likely terminating the program if it fails.
- **Output**: The function does not return a value; it performs an initialization operation and relies on `FD_TEST` for error handling.


