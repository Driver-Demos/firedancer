# Purpose
This C source code file defines a set of callback functions for various types of objects within a topology framework, likely used in a distributed or networked system. The file includes several headers from different modules, indicating its reliance on a broader software ecosystem. The primary purpose of this file is to provide specific implementations for object lifecycle management functions such as footprint calculation, memory alignment, and object instantiation (via `new` functions) for different object types like `mcache`, `dcache`, `cnc`, `fseq`, `metrics`, `opaque`, `dbl_buf`, `neigh4_hmap`, `fib4`, `keyswitch`, and `tile`. Each object type has a corresponding `fd_topo_obj_callbacks_t` structure that encapsulates these functions, allowing the system to manage these objects in a modular and extensible manner.

The code is structured to facilitate the creation and management of these objects based on properties queried from a topology descriptor (`fd_topo_t`). The use of macros and inline functions, such as `VAL`, streamlines the retrieval of configuration parameters, ensuring that each object is initialized with the correct settings. The file does not define a main function, indicating that it is not an executable but rather a component intended to be integrated into a larger application. The callbacks defined here are likely part of a public API or external interface, as they provide essential functionality for interacting with the topology's objects, enabling other parts of the system to utilize these objects without needing to understand their internal workings.
# Imports and Dependencies

---
- `../../disco/topo/fd_topo.h`
- `../../util/pod/fd_pod_format.h`
- `../../disco/metrics/fd_metrics.h`
- `../../tango/cnc/fd_cnc.h`
- `../../tango/mcache/fd_mcache.h`
- `../../tango/dcache/fd_dcache.h`
- `../../tango/fseq/fd_fseq.h`
- `../../waltz/mib/fd_dbl_buf.h`
- `../../waltz/neigh/fd_neigh4_map.h`
- `../../waltz/ip/fd_fib4.h`
- `../../disco/keyguard/fd_keyswitch.h`


# Global Variables

---
### fd\_obj\_cb\_mcache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_mcache` is a global variable of type `fd_topo_obj_callbacks_t`, which is a structure used to define a set of callback functions for managing memory cache objects in a topology. It includes a name identifier, and pointers to functions that calculate the footprint, alignment, and creation of a memory cache object.
- **Use**: This variable is used to provide a standardized interface for operations related to memory cache objects within a topology, facilitating their management and integration.


---
### fd\_obj\_cb\_dcache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_dcache` is a global variable of type `fd_topo_obj_callbacks_t` that defines a set of callback functions for handling data cache (dcache) objects in a topology. It includes functions for calculating the footprint, alignment, and creation of a new dcache object.
- **Use**: This variable is used to manage dcache objects by providing specific operations such as footprint calculation, alignment, and instantiation within a topology.


---
### fd\_obj\_cb\_cnc
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_cnc` is a global variable of type `fd_topo_obj_callbacks_t`, which is a structure used to define a set of callback functions for handling 'cnc' (presumably short for 'command and control') objects in a topology. This structure includes function pointers for determining the footprint, alignment, and creation of 'cnc' objects.
- **Use**: This variable is used to manage the lifecycle and memory requirements of 'cnc' objects within a topology by providing specific callback functions for footprint calculation, alignment, and instantiation.


---
### fd\_obj\_cb\_fseq
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_fseq` is a global variable of type `fd_topo_obj_callbacks_t` that defines a set of callback functions for handling 'fseq' objects in a topology. It includes functions for determining the footprint and alignment of 'fseq' objects, as well as a function for creating new 'fseq' instances.
- **Use**: This variable is used to manage 'fseq' objects within a topology by providing necessary callbacks for their lifecycle operations.


---
### fd\_obj\_cb\_metrics
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_metrics` is a global variable of type `fd_topo_obj_callbacks_t`, which is a structure used to define a set of callback functions for handling 'metrics' objects in a topology. It includes function pointers for calculating the footprint, alignment, and creating new instances of metrics objects.
- **Use**: This variable is used to manage the lifecycle and memory requirements of metrics objects within a topology by providing specific callback functions for footprint calculation, alignment, and instantiation.


---
### fd\_obj\_cb\_opaque
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_opaque` is a global variable of type `fd_topo_obj_callbacks_t` that represents a set of callback functions for handling 'opaque' objects in a topology. It includes functions for determining the footprint and alignment of the object, as well as a function for initializing a new instance of the object.
- **Use**: This variable is used to manage 'opaque' objects within a topology by providing specific callback functions for footprint calculation, alignment, and initialization.


---
### fd\_obj\_cb\_dbl\_buf
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_dbl_buf` is a global variable of type `fd_topo_obj_callbacks_t`, which is a structure used to define a set of callback functions for handling double buffer objects in a topology. It includes function pointers for determining the footprint, alignment, and creation of a double buffer object.
- **Use**: This variable is used to manage double buffer objects by providing specific callback functions for their footprint, alignment, and instantiation.


---
### fd\_obj\_cb\_neigh4\_hmap
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The variable `fd_obj_cb_neigh4_hmap` is an instance of the `fd_topo_obj_callbacks_t` structure, which is used to define a set of callback functions for managing a 'neigh4_hmap' object in a topology. It includes function pointers for determining the footprint, alignment, and creation of the 'neigh4_hmap' object.
- **Use**: This variable is used to manage the lifecycle and memory requirements of a 'neigh4_hmap' object within a topology by providing specific callback functions for footprint calculation, alignment, and object creation.


---
### fd\_obj\_cb\_fib4
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_fib4` is a global variable of type `fd_topo_obj_callbacks_t` that defines a set of callback functions for handling 'fib4' objects in a topology. It includes functions for determining the footprint, alignment, and creation of 'fib4' objects.
- **Use**: This variable is used to manage 'fib4' objects by providing specific callback functions for their lifecycle operations within a topology.


---
### fd\_obj\_cb\_keyswitch
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_keyswitch` is a global variable of type `fd_topo_obj_callbacks_t` that defines a set of callback functions for handling a 'keyswitch' object in a topology. It includes functions for determining the footprint, alignment, and creation of a keyswitch object.
- **Use**: This variable is used to manage the lifecycle and memory requirements of keyswitch objects within a topology.


---
### fd\_obj\_cb\_tile
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_tile` is a global variable of type `fd_topo_obj_callbacks_t` that defines a set of callback functions for handling 'tile' objects in a topology. It includes functions for calculating the footprint, alignment, and loose footprint of a tile, but does not define a 'new' function for creating a new tile object.
- **Use**: This variable is used to manage and interact with 'tile' objects within a topology by providing specific callback functions for footprint, alignment, and loose footprint calculations.


# Functions

---
### mcache\_footprint<!-- {{#callable:mcache_footprint}} -->
The `mcache_footprint` function calculates the memory footprint required for an mcache object based on the depth property of a given topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology for which the footprint is being calculated.
- **Control Flow**:
    - The function uses the `VAL` macro to query the 'depth' property of the object from the topology's properties.
    - If the 'depth' property is not set, an error is logged and the program may terminate.
    - The function then calls `fd_mcache_footprint` with the retrieved depth value and a constant 0UL to calculate the footprint.
- **Output**: The function returns an `ulong` representing the calculated memory footprint for the mcache object.


---
### mcache\_align<!-- {{#callable:mcache_align}} -->
The `mcache_align` function returns the alignment requirement for an mcache object by calling the `fd_mcache_align` function.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is not used in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both marked as unused with `FD_FN_UNUSED` macro.
    - It directly calls and returns the result of the `fd_mcache_align` function without any additional logic or processing.
- **Output**: The function returns an `ulong` value representing the alignment requirement for an mcache object.


---
### mcache\_new<!-- {{#callable:mcache_new}} -->
The `mcache_new` function initializes a new memory cache object using topology and object information.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology.
- **Control Flow**:
    - The function calls `fd_topo_obj_laddr` to get the local address of the object within the topology using `topo` and `obj->id`.
    - It retrieves the 'depth' property value for the object using the `VAL` macro, which queries the topology properties.
    - The function then calls `fd_mcache_new` with the local address, the retrieved depth, and two zero values as arguments.
    - The `FD_TEST` macro is used to ensure that `fd_mcache_new` executes successfully, likely logging an error if it fails.
- **Output**: The function does not return a value; it performs an initialization operation and relies on `FD_TEST` to handle any errors.


---
### dcache\_footprint<!-- {{#callable:dcache_footprint}} -->
The `dcache_footprint` function calculates the memory footprint required for a data cache object based on its application and data sizes.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology, which contains properties used to query object sizes.
    - `obj`: A pointer to an `fd_topo_obj_t` structure representing the object for which the data cache footprint is being calculated, identified by its `id`.
- **Control Flow**:
    - Retrieve the application size (`app_sz`) for the object using `fd_pod_queryf_ulong`, defaulting to 0 if not found.
    - Retrieve the data size (`data_sz`) for the object using `fd_pod_queryf_ulong`, defaulting to `ULONG_MAX` if not found.
    - If `data_sz` is `ULONG_MAX`, calculate it using `fd_dcache_req_data_sz` with parameters `mtu`, `depth`, `burst`, and `1`, retrieved using the `VAL` macro.
    - Return the result of `fd_dcache_footprint` using the calculated `data_sz` and `app_sz`.
- **Output**: The function returns an `ulong` representing the calculated memory footprint for the data cache object.


---
### dcache\_align<!-- {{#callable:dcache_align}} -->
The `dcache_align` function returns the alignment requirement for a dcache object by calling `fd_dcache_align()`.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both marked as unused with `FD_FN_UNUSED` macro.
    - It directly calls and returns the result of the `fd_dcache_align()` function, which presumably provides the alignment requirement for a dcache object.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a dcache object.


---
### dcache\_new<!-- {{#callable:dcache_new}} -->
The `dcache_new` function initializes a new data cache object using properties from a topology object and a specific object identifier.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing properties for the data cache.
    - `obj`: A pointer to an `fd_topo_obj_t` structure representing the specific object within the topology for which the data cache is being initialized.
- **Control Flow**:
    - Retrieve the application size (`app_sz`) from the topology properties using the object's ID.
    - Retrieve the data size (`data_sz`) from the topology properties using the object's ID, defaulting to `ULONG_MAX` if not set.
    - If `data_sz` is `ULONG_MAX`, calculate the required data size using `fd_dcache_req_data_sz` with parameters `mtu`, `depth`, `burst`, and `1`.
    - Call `fd_dcache_new` to initialize the data cache at the object's local address with the determined `data_sz` and `app_sz`, and verify success with `FD_TEST`.
- **Output**: The function does not return a value; it performs initialization and validation of a data cache object.


---
### cnc\_footprint<!-- {{#callable:cnc_footprint}} -->
The `cnc_footprint` function calculates the memory footprint required for a CNC (Command and Control) object by calling `fd_cnc_footprint` with a zero argument.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both of which are marked as unused with `FD_FN_UNUSED`.
    - It directly calls the `fd_cnc_footprint` function with a single argument `0UL`.
    - The result of the `fd_cnc_footprint` call is returned as the output of the function.
- **Output**: The function returns an `ulong` value representing the memory footprint required for a CNC object.


---
### cnc\_align<!-- {{#callable:cnc_align}} -->
The `cnc_align` function returns the alignment requirement for a CNC (Command and Control) object by calling the `fd_cnc_align` function.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which represents the topology of the system; it is marked as unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which represents a topology object; it is marked as unused in this function.
- **Control Flow**:
    - The function directly calls and returns the result of the `fd_cnc_align` function without any additional logic or processing.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a CNC object.


---
### cnc\_new<!-- {{#callable:cnc_new}} -->
The `cnc_new` function initializes a CNC (Command and Control) object using the provided topology and object identifiers.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure representing the specific object within the topology to be initialized.
- **Control Flow**:
    - The function calls `fd_topo_obj_laddr` with `topo` and `obj->id` to get the local address of the object within the topology.
    - It then calls `fd_cnc_new` with the obtained local address, a zero value for the second and third parameters, and the current tick count from `fd_tickcount()`.
    - The `FD_TEST` macro is used to ensure that `fd_cnc_new` executes successfully, likely terminating the program if it fails.
- **Output**: The function does not return a value; it performs initialization and relies on `FD_TEST` to handle errors.


---
### fseq\_footprint<!-- {{#callable:fseq_footprint}} -->
The `fseq_footprint` function returns the footprint size of a sequence object by calling `fd_fseq_footprint`.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is not used in this function.
- **Control Flow**:
    - The function directly calls `fd_fseq_footprint()` without using its input parameters.
    - The result of `fd_fseq_footprint()` is returned as the output of the function.
- **Output**: The function returns an `ulong` representing the footprint size of a sequence object.


---
### fseq\_align<!-- {{#callable:fseq_align}} -->
The `fseq_align` function returns the alignment requirement for a sequence object by calling the `fd_fseq_align` function.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function directly calls and returns the result of the `fd_fseq_align` function without any additional logic or control flow.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a sequence object.


---
### fseq\_new<!-- {{#callable:fseq_new}} -->
The `fseq_new` function initializes a new fseq object using the provided topology and object identifiers.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure representing the object within the topology.
- **Control Flow**:
    - The function calls `fd_topo_obj_laddr` with `topo` and `obj->id` to get the local address of the object.
    - It then calls `fd_fseq_new` with the obtained local address and `ULONG_MAX` as arguments.
    - The `FD_TEST` macro is used to ensure that `fd_fseq_new` returns a successful result, otherwise it triggers an error.
- **Output**: The function does not return any value; it performs an initialization operation and relies on `FD_TEST` to handle errors.


---
### metrics\_footprint<!-- {{#callable:metrics_footprint}} -->
The `metrics_footprint` function calculates the memory footprint required for metrics based on input and consumer counts from a topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing a specific object within the topology.
- **Control Flow**:
    - The function uses the `VAL` macro to query the `in_cnt` and `cons_cnt` properties from the topology's properties for the given object ID.
    - If the queried values are not set (i.e., they return `ULONG_MAX`), an error is logged and the program terminates.
    - The function then calls `FD_METRICS_FOOTPRINT` with the retrieved `in_cnt` and `cons_cnt` values to compute the footprint.
- **Output**: Returns an `ulong` representing the calculated memory footprint for the metrics.


---
### metrics\_align<!-- {{#callable:metrics_align}} -->
The `metrics_align` function returns a predefined alignment value for metrics objects.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function takes two parameters, `topo` and `obj`, both of which are marked as unused.
    - It directly returns the constant `FD_METRICS_ALIGN`.
- **Output**: The function returns an `ulong` representing the alignment requirement for metrics objects, specifically the constant `FD_METRICS_ALIGN`.


---
### metrics\_new<!-- {{#callable:metrics_new}} -->
The `metrics_new` function initializes a new metrics object using topology and object information.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology.
- **Control Flow**:
    - The function calls `fd_topo_obj_laddr` to get the local address of the object within the topology using `topo` and `obj->id`.
    - It retrieves the values for "in_cnt" and "cons_cnt" using the `VAL` macro, which queries the topology properties.
    - The function then calls `fd_metrics_new` with the local address and the retrieved values for "in_cnt" and "cons_cnt".
    - The `FD_TEST` macro is used to ensure that `fd_metrics_new` executes successfully, otherwise it logs an error.
- **Output**: The function does not return a value; it performs initialization and checks for success using `FD_TEST`.


---
### opaque\_footprint<!-- {{#callable:opaque_footprint}} -->
The `opaque_footprint` function retrieves the 'footprint' property value for a given topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology, marked as unused.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the topology object, marked as unused.
- **Control Flow**:
    - The function uses the `VAL` macro to query the 'footprint' property of the object identified by `obj->id` from the topology's properties.
    - The `VAL` macro checks if the queried value is `ULONG_MAX`, indicating the property was not set, and logs an error if so.
    - The function returns the queried 'footprint' value.
- **Output**: The function returns an `ulong` representing the 'footprint' property value of the specified topology object.


---
### opaque\_align<!-- {{#callable:opaque_align}} -->
The `opaque_align` function retrieves the alignment value for an opaque object from a topology's properties.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology, which contains properties of various objects.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology for which the alignment is being queried.
- **Control Flow**:
    - The function uses the `VAL` macro to query the alignment value from the topology's properties using the object's ID.
    - If the queried alignment value is `ULONG_MAX`, an error is logged indicating that the alignment property was not set.
    - The function returns the queried alignment value.
- **Output**: The function returns an `ulong` representing the alignment value of the specified object within the topology.


---
### opaque\_new<!-- {{#callable:opaque_new}} -->
The `opaque_new` function initializes a memory region associated with a topology object to zero, based on the object's footprint size.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology.
- **Control Flow**:
    - Retrieve the local address of the object using `fd_topo_obj_laddr` with the topology and object ID.
    - Determine the footprint size of the object using the `VAL` macro, which queries the topology properties.
    - Set the memory region at the object's local address to zero using `fd_memset`, with the size determined by the footprint.
- **Output**: The function does not return a value; it performs an in-place memory initialization.


---
### dbl\_buf\_footprint<!-- {{#callable:dbl_buf_footprint}} -->
The `dbl_buf_footprint` function calculates the memory footprint required for a double buffer based on the maximum transmission unit (MTU) value from the topology properties.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology, which contains properties used to query configuration values.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the topology object, which includes an identifier used in property queries.
- **Control Flow**:
    - The function uses the `VAL` macro to query the 'mtu' property from the topology's properties using the object's ID.
    - If the 'mtu' property is not set, the `VAL` macro logs an error and the program terminates.
    - The function then calls `fd_dbl_buf_footprint` with the retrieved MTU value to calculate the footprint.
- **Output**: The function returns an `ulong` representing the calculated memory footprint for the double buffer.


---
### dbl\_buf\_align<!-- {{#callable:dbl_buf_align}} -->
The `dbl_buf_align` function returns the alignment requirement for a double buffer by calling `fd_dbl_buf_align`.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function is defined as static, meaning it is limited to the file scope.
    - It takes two parameters, `topo` and `obj`, both of which are marked as unused with `FD_FN_UNUSED`.
    - The function directly returns the result of the `fd_dbl_buf_align()` function call.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a double buffer.


---
### dbl\_buf\_new<!-- {{#callable:dbl_buf_new}} -->
The `dbl_buf_new` function initializes a double buffer using topology and object information.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology.
- **Control Flow**:
    - The function calls `fd_topo_obj_laddr` with `topo` and `obj->id` to get the local address of the object.
    - It retrieves the 'mtu' value from the topology properties using the `VAL` macro.
    - The function calls `fd_dbl_buf_new` with the local address, the retrieved 'mtu' value, and a constant `1UL`.
    - The `FD_TEST` macro is used to ensure that `fd_dbl_buf_new` executes successfully.
- **Output**: The function does not return a value; it performs an initialization operation and uses `FD_TEST` to assert success.


---
### neigh4\_hmap\_footprint<!-- {{#callable:neigh4_hmap_footprint}} -->
The `neigh4_hmap_footprint` function calculates the memory footprint required for a neighbor hash map using specific parameters from a topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology for which the footprint is being calculated.
- **Control Flow**:
    - The function uses the `VAL` macro to retrieve three configuration values: `ele_max`, `lock_cnt`, and `probe_max` from the topology properties associated with the object.
    - It calls the `fd_neigh4_hmap_footprint` function with these three values to compute the required memory footprint.
- **Output**: Returns an `ulong` representing the calculated memory footprint for the neighbor hash map.


---
### neigh4\_hmap\_align<!-- {{#callable:neigh4_hmap_align}} -->
The `neigh4_hmap_align` function returns the alignment requirement for a neighbor hash map.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function directly calls and returns the result of `fd_neigh4_hmap_align()` without using its input parameters.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a neighbor hash map.


---
### neigh4\_hmap\_new<!-- {{#callable:neigh4_hmap_new}} -->
The `neigh4_hmap_new` function initializes a new neighbor hash map using parameters derived from a topology object.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology for which the neighbor hash map is being created.
- **Control Flow**:
    - The function retrieves the local address of the object using `fd_topo_obj_laddr` with the topology and object ID.
    - It then queries several properties (`ele_max`, `lock_cnt`, `probe_max`, `seed`) from the topology's properties using the `VAL` macro, which checks for the presence of these properties and logs an error if they are not set.
    - The function calls `fd_neigh4_hmap_new` with the retrieved local address and the queried properties to create the neighbor hash map.
    - The `FD_TEST` macro is used to ensure that the `fd_neigh4_hmap_new` call is successful, and it will log an error if the call fails.
- **Output**: The function does not return a value; it performs its operations for side effects, specifically initializing a neighbor hash map.


---
### fib4\_footprint<!-- {{#callable:fib4_footprint}} -->
The `fib4_footprint` function calculates the memory footprint required for a FIB4 object based on the maximum number of routes specified in the topology properties.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure containing the topology properties.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology.
- **Control Flow**:
    - The function uses the `VAL` macro to query the maximum number of routes ('route_max') from the topology properties associated with the given object ID.
    - It then calls the `fd_fib4_footprint` function with the retrieved 'route_max' value to calculate the footprint.
- **Output**: Returns an `ulong` representing the memory footprint required for the FIB4 object.


---
### fib4\_align<!-- {{#callable:fib4_align}} -->
The `fib4_align` function returns the alignment requirement for a FIB4 object by calling the `fd_fib4_align` function.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function directly calls and returns the result of the `fd_fib4_align` function without using its input parameters.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a FIB4 object.


---
### fib4\_new<!-- {{#callable:fib4_new}} -->
The `fib4_new` function initializes a new FIB4 (Forwarding Information Base for IPv4) object using the provided topology and object information.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology to be initialized.
- **Control Flow**:
    - The function retrieves the local address of the object using `fd_topo_obj_laddr` with the topology and object ID.
    - It queries the maximum number of routes (`route_max`) for the object using the `VAL` macro, which internally uses `fd_pod_queryf_ulong` to fetch the value from the topology properties.
    - The function calls `fd_fib4_new` with the local address and `route_max` to initialize the FIB4 object.
    - The `FD_TEST` macro is used to ensure that the `fd_fib4_new` call is successful, logging an error if it fails.
- **Output**: The function does not return a value; it performs initialization and may log an error if initialization fails.


---
### keyswitch\_footprint<!-- {{#callable:keyswitch_footprint}} -->
The `keyswitch_footprint` function returns the memory footprint required for a keyswitch object.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function directly calls and returns the result of `fd_keyswitch_footprint()` without using its input parameters.
- **Output**: The function returns an `ulong` value representing the memory footprint required for a keyswitch object.


---
### keyswitch\_align<!-- {{#callable:keyswitch_align}} -->
The `keyswitch_align` function returns the alignment requirement for a keyswitch object by calling the `fd_keyswitch_align` function.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `obj`: A pointer to a constant `fd_topo_obj_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function directly calls and returns the result of `fd_keyswitch_align()` without using its input parameters.
- **Output**: The function returns an `ulong` value representing the alignment requirement for a keyswitch object.


---
### keyswitch\_new<!-- {{#callable:keyswitch_new}} -->
The `keyswitch_new` function initializes a keyswitch object in an unlocked state using the provided topology and object information.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the specific object within the topology to be initialized.
- **Control Flow**:
    - The function calls `fd_topo_obj_laddr` with `topo` and `obj->id` to get the local address of the object within the topology.
    - It then calls `fd_keyswitch_new` with the obtained local address and the constant `FD_KEYSWITCH_STATE_UNLOCKED` to initialize the keyswitch in an unlocked state.
    - The `FD_TEST` macro is used to ensure that the `fd_keyswitch_new` function call is successful.
- **Output**: The function does not return a value; it performs initialization and relies on `FD_TEST` to handle any errors.


---
### tile\_footprint<!-- {{#callable:tile_footprint}} -->
The `tile_footprint` function calculates the memory footprint required for a specific tile object within a topology.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing multiple tiles.
    - `obj`: A pointer to an `fd_topo_obj_t` structure representing the specific object whose tile footprint is to be calculated.
- **Control Flow**:
    - Initialize a pointer `tile` to `NULL`.
    - Iterate over the tiles in the topology using a loop from 0 to `topo->tile_cnt`.
    - For each tile, check if the `tile_obj_id` matches the `id` of the given object `obj`.
    - If a match is found, set `tile` to point to the current tile and break out of the loop.
    - Assert that `tile` is not `NULL` using `FD_TEST`.
    - Call [`fdctl_tile_run`](boot/fd_boot.c.driver.md#fdctl_tile_run) with the found `tile` to get a `fd_topo_run_tile_t` structure named `runner`.
    - Check if `runner.scratch_footprint` is non-zero; if so, call it with `tile` and return the result.
    - If `runner.scratch_footprint` is zero, return 0UL.
- **Output**: The function returns an `ulong` representing the memory footprint of the tile, or 0 if the footprint cannot be determined.
- **Functions called**:
    - [`fdctl_tile_run`](boot/fd_boot.c.driver.md#fdctl_tile_run)


---
### tile\_loose<!-- {{#callable:tile_loose}} -->
The `tile_loose` function retrieves the loose footprint of a tile object from a topology if available, otherwise returns zero.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology containing the tiles.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the object whose tile's loose footprint is to be retrieved.
- **Control Flow**:
    - Initialize a pointer `tile` to `NULL`.
    - Iterate over the tiles in the topology using a loop from `0` to `topo->tile_cnt`.
    - For each tile, check if the `tile_obj_id` matches the `id` of the given object `obj`.
    - If a match is found, set `tile` to point to the current tile and break out of the loop.
    - Assert that `tile` is not `NULL` using `FD_TEST`.
    - Retrieve a `fd_topo_run_tile_t` structure by calling [`fdctl_tile_run`](boot/fd_boot.c.driver.md#fdctl_tile_run) with the found `tile`.
    - Check if the `loose_footprint` function pointer in `runner` is not `NULL`.
    - If `loose_footprint` is available, call it with `tile` and return its result.
    - If `loose_footprint` is not available, return `0UL`.
- **Output**: The function returns an `ulong` representing the loose footprint of the tile if available, otherwise it returns `0UL`.
- **Functions called**:
    - [`fdctl_tile_run`](boot/fd_boot.c.driver.md#fdctl_tile_run)


---
### tile\_align<!-- {{#callable:tile_align}} -->
The `tile_align` function determines the alignment requirement for a specific tile object within a topology.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology containing the tiles.
    - `obj`: A pointer to a `fd_topo_obj_t` structure representing the object whose tile alignment is being queried.
- **Control Flow**:
    - Initialize a pointer `tile` to `NULL`.
    - Iterate over the tiles in the topology using a loop from 0 to `topo->tile_cnt`.
    - For each tile, check if the `tile_obj_id` matches the `id` of the given object `obj`.
    - If a match is found, set `tile` to point to the current tile and break out of the loop.
    - Assert that `tile` is not `NULL` using `FD_TEST`.
    - Call [`fdctl_tile_run`](boot/fd_boot.c.driver.md#fdctl_tile_run) with the found tile to get a `fd_topo_run_tile_t` structure `runner`.
    - Check if `runner.scratch_align` is non-zero using `FD_LIKELY`.
    - If `runner.scratch_align` is non-zero, return the result of calling `runner.scratch_align()`.
    - If `runner.scratch_align` is zero, return `1UL`.
- **Output**: The function returns an `ulong` representing the alignment requirement for the specified tile, either from `runner.scratch_align()` or a default value of `1UL` if not available.
- **Functions called**:
    - [`fdctl_tile_run`](boot/fd_boot.c.driver.md#fdctl_tile_run)


# Function Declarations (Public API)

---
### fdctl\_tile\_run<!-- {{#callable_declaration:fdctl_tile_run}} -->
Retrieve the run configuration for a specified tile.
- **Description**: This function is used to obtain the run configuration for a given tile identified by its name. It searches through a predefined list of tiles and returns the configuration of the tile that matches the provided name. If the tile is not found, an error is logged, and a default configuration is returned. This function should be called when a specific tile's run configuration is needed, and it assumes that the tile name provided is valid and exists in the list of tiles.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile whose run configuration is to be retrieved. The `name` field of this structure is used to identify the tile. The pointer must not be null, and the `name` must correspond to a valid tile in the system.
- **Output**: Returns an `fd_topo_run_tile_t` structure containing the run configuration of the specified tile. If the tile is not found, an error is logged, and a default-initialized `fd_topo_run_tile_t` is returned.
- **See also**: [`fdctl_tile_run`](boot/fd_boot.c.driver.md#fdctl_tile_run)  (Implementation)


