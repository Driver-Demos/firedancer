# Purpose
The provided C source code file is part of a larger system that manages shared memory workspaces and their interactions with various components, such as tiles and links, within a topology. The code is designed to handle the creation, joining, and leaving of shared memory workspaces, as well as managing the allocation and deallocation of resources within these workspaces. It provides functions to calculate memory requirements, such as the number of pages needed for different types of memory (gigantic, huge, and normal pages) and the maximum memory lock required for tiles. The code also includes functionality to log detailed information about the topology, including summaries of memory usage, workspace details, object properties, and tile configurations.

The file is not a standalone executable but rather a component of a larger system, likely intended to be compiled and linked with other parts of the system. It includes several header files that suggest it is part of a modular architecture, with dependencies on metrics, shared memory utilities, and workspace management. The functions defined in this file are primarily focused on managing the lifecycle and properties of shared memory workspaces and their associated objects, tiles, and links. The code is structured to provide detailed logging and error handling, ensuring robust management of shared resources in a multi-threaded or distributed environment.
# Imports and Dependencies

---
- `fd_topo.h`
- `../metrics/fd_metrics.h`
- `../../util/pod/fd_pod_format.h`
- `../../util/wksp/fd_wksp_private.h`
- `../../util/shmem/fd_shmem_private.h`
- `stdio.h`
- `errno.h`
- `unistd.h`
- `sys/stat.h`


# Global Variables

---
### fd\_topo\_leave\_workspace
- **Type**: `function`
- **Description**: The `fd_topo_leave_workspace` function is responsible for detaching a workspace from a topology. It checks if the workspace is currently joined and, if so, detaches it and resets its footprint values.
- **Use**: This function is used to cleanly leave a workspace by detaching it and resetting its associated footprint values.


---
### fd\_shmem\_private\_base
- **Type**: `char array`
- **Description**: `fd_shmem_private_base` is a global character array with a size defined by `FD_SHMEM_PRIVATE_BASE_MAX`. It is declared as an external variable, indicating that its definition is likely located in another source file.
- **Use**: This variable is used to store a base address or data related to shared memory operations, as suggested by its name and the context of the file.


# Functions

---
### fd\_topo\_join\_workspace<!-- {{#callable:fd_topo_join_workspace}} -->
The `fd_topo_join_workspace` function attempts to join a shared memory workspace for a given topology and workspace using a specified mode.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology.
    - `wksp`: A pointer to an `fd_topo_wksp_t` structure representing the workspace to be joined.
    - `mode`: An integer representing the mode in which to join the shared memory.
- **Control Flow**:
    - A character array `name` is declared to store the workspace name.
    - The function `fd_cstr_printf_check` is called to format the workspace name using the application name from `topo` and the workspace name from `wksp`.
    - The function `fd_shmem_join` is called with the formatted name and mode to join the shared memory, and its result is passed to `fd_wksp_join` to join the workspace.
    - If `fd_wksp_join` returns a null pointer, indicating failure, an error is logged using `FD_LOG_ERR`.
- **Output**: The function does not return a value; it modifies the `wksp` structure by setting its `wksp` member to the result of `fd_wksp_join`.


---
### tile\_needs\_wksp<!-- {{#callable:tile_needs_wksp}} -->
The `tile_needs_wksp` function determines the highest mode of workspace usage required by a tile for a specific workspace ID.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile whose workspace needs are being evaluated.
    - `wksp_id`: An unsigned long integer representing the ID of the workspace to check against the tile's requirements.
- **Control Flow**:
    - Initialize `mode` to -1, indicating no workspace is needed initially.
    - Iterate over each object used by the tile, as indicated by `tile->uses_obj_cnt`.
    - For each object, check if its workspace ID matches the given `wksp_id`.
    - If a match is found, update `mode` to the maximum of its current value and the mode of the current object (`tile->uses_obj_mode[i]`).
    - Return the final value of `mode`, which represents the highest mode of workspace usage required by the tile for the specified workspace ID.
- **Output**: An integer representing the highest mode of workspace usage required by the tile for the specified workspace ID, or -1 if the workspace is not needed.


---
### fd\_topo\_join\_tile\_workspaces<!-- {{#callable:fd_topo_join_tile_workspaces}} -->
The function `fd_topo_join_tile_workspaces` iterates over all workspaces in a topology and joins the necessary workspaces for a given tile based on its requirements.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing workspaces and other related data.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile for which workspaces need to be joined.
- **Control Flow**:
    - Iterate over each workspace in the topology using a loop that runs from 0 to `topo->wksp_cnt`.
    - For each workspace, determine if the tile needs to join the workspace by calling [`tile_needs_wksp`](#tile_needs_wksp) with the current workspace index.
    - If the tile needs to join the workspace (i.e., [`tile_needs_wksp`](#tile_needs_wksp) returns a non-negative value), call [`fd_topo_join_workspace`](#fd_topo_join_workspace) to join the workspace with the specified mode.
- **Output**: The function does not return a value; it performs operations to join workspaces as needed for the specified tile.
- **Functions called**:
    - [`tile_needs_wksp`](#tile_needs_wksp)
    - [`fd_topo_join_workspace`](#fd_topo_join_workspace)


---
### fd\_topo\_join\_workspaces<!-- {{#callable:fd_topo_join_workspaces}} -->
The `fd_topo_join_workspaces` function iterates over all workspaces in a topology and joins each one using a specified mode.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing the workspaces to be joined.
    - `mode`: An integer representing the mode in which each workspace should be joined.
- **Control Flow**:
    - The function starts a loop that iterates over each workspace in the `topo` structure, using the `wksp_cnt` field to determine the number of iterations.
    - For each workspace, it calls the [`fd_topo_join_workspace`](#fd_topo_join_workspace) function, passing the `topo` pointer, a pointer to the current workspace, and the `mode` as arguments.
- **Output**: The function does not return a value; it performs operations on the workspaces within the `topo` structure.
- **Functions called**:
    - [`fd_topo_join_workspace`](#fd_topo_join_workspace)


---
### fd\_topo\_leave\_workspaces<!-- {{#callable:fd_topo_leave_workspaces}} -->
The `fd_topo_leave_workspaces` function detaches all workspaces associated with a given topology.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology whose workspaces are to be detached.
- **Control Flow**:
    - Iterates over each workspace in the `topo` structure using a for loop.
    - For each workspace, calls `fd_topo_leave_workspace` to detach the workspace.
- **Output**: This function does not return a value; it performs operations directly on the `topo` structure.


---
### fd\_topo\_create\_workspace<!-- {{#callable:fd_topo_create_workspace}} -->
The `fd_topo_create_workspace` function creates or updates a shared memory workspace for a given topology and workspace configuration.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `wksp`: A pointer to an `fd_topo_wksp_t` structure representing the workspace configuration.
    - `update_existing`: An integer flag indicating whether to update an existing workspace (non-zero) or create a new one (zero).
- **Control Flow**:
    - Constructs a workspace name using the application name from `topo` and the workspace name from `wksp`.
    - Initializes arrays for sub-page count and CPU index based on the workspace configuration.
    - Checks if `update_existing` is true; if so, calls `fd_shmem_update_multi` to update the existing shared memory, otherwise calls `fd_shmem_create_multi` to create a new shared memory.
    - Handles errors from the shared memory operations, returning -1 if memory allocation fails or logging an error for other failures.
    - Joins the shared memory segment using `fd_shmem_join` and logs details.
    - Creates a new workspace in the shared memory using `fd_wksp_new` and logs details.
    - Joins the newly created workspace using `fd_wksp_join` and logs details.
    - If `wksp->known_footprint` is non-zero, allocates memory within the workspace and verifies the allocation offset against the expected alignment.
    - Leaves the workspace using `fd_wksp_leave`.
    - Leaves the shared memory segment using `fd_shmem_leave` and logs details.
    - Returns 0 on successful completion.
- **Output**: Returns 0 on success, or -1 if there is an out-of-memory error during shared memory operations.
- **Functions called**:
    - [`fd_topo_workspace_align`](fd_topo.h.driver.md#fd_topo_workspace_align)


---
### fd\_topo\_wksp\_new<!-- {{#callable:fd_topo_wksp_new}} -->
The `fd_topo_wksp_new` function initializes new workspace objects in a topology by invoking specific callbacks for each object that matches the workspace ID.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology containing objects to be initialized.
    - `wksp`: A pointer to a constant `fd_topo_wksp_t` structure representing the workspace to be associated with the objects.
    - `callbacks`: An array of pointers to `fd_topo_obj_callbacks_t` structures, each containing a name and a function pointer for initialization.
- **Control Flow**:
    - Iterate over each object in the topology using a loop indexed by `i`.
    - For each object, check if its workspace ID matches the given workspace's ID; if not, continue to the next object.
    - If the workspace ID matches, iterate over the callbacks array using a loop indexed by `j`.
    - For each callback, check if the callback's name matches the object's name; if not, continue to the next callback.
    - If the names match and the callback has a `new` function, invoke this function with the topology and object as arguments.
    - Break out of the callback loop after a matching callback is found and executed.
- **Output**: The function does not return a value; it performs operations through side effects by invoking callback functions.


---
### fd\_topo\_workspace\_fill<!-- {{#callable:fd_topo_workspace_fill}} -->
The `fd_topo_workspace_fill` function initializes and joins memory caches and data caches for links and metrics and sequence caches for tiles in a topology workspace.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing links and tiles.
    - `wksp`: A pointer to an `fd_topo_wksp_t` structure representing the workspace to be filled.
- **Control Flow**:
    - Iterate over each link in the topology's links array.
    - For each link, check if the link's memory cache object ID matches the workspace ID; if not, continue to the next link.
    - Join the memory cache for the link using `fd_mcache_join` and verify the join was successful.
    - If the link has a non-zero MTU, check if the link's data cache object ID matches the workspace ID; if not, continue to the next link.
    - Join the data cache for the link using `fd_dcache_join` and verify the join was successful.
    - Iterate over each tile in the topology's tiles array.
    - For each tile, check if the tile's metrics object ID matches the workspace ID; if so, join the metrics using `fd_metrics_join` and verify the join was successful.
    - Iterate over each input link sequence for the tile.
    - For each input link sequence, check if the sequence's object ID matches the workspace ID; if not, continue to the next sequence.
    - Join the input link sequence using `fd_fseq_join` and verify the join was successful.
- **Output**: The function does not return a value; it modifies the `topo` structure in place by joining caches and sequences to the appropriate links and tiles.
- **Functions called**:
    - [`fd_topo_obj_laddr`](fd_topo.h.driver.md#fd_topo_obj_laddr)


---
### fd\_topo\_fill\_tile<!-- {{#callable:fd_topo_fill_tile}} -->
The `fd_topo_fill_tile` function iterates over workspaces in a topology and fills those required by a specific tile.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing workspaces and other related data.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile for which the workspaces need to be filled.
- **Control Flow**:
    - Iterate over each workspace in the topology using a loop that runs from 0 to `topo->wksp_cnt`.
    - For each workspace, check if the tile needs the workspace by calling [`tile_needs_wksp`](#tile_needs_wksp) with the current workspace index.
    - If the tile needs the workspace (i.e., [`tile_needs_wksp`](#tile_needs_wksp) returns a value other than -1), call [`fd_topo_workspace_fill`](#fd_topo_workspace_fill) to fill the workspace.
- **Output**: The function does not return a value; it performs operations on the provided `topo` and `tile` structures.
- **Functions called**:
    - [`tile_needs_wksp`](#tile_needs_wksp)
    - [`fd_topo_workspace_fill`](#fd_topo_workspace_fill)


---
### fd\_topo\_fill<!-- {{#callable:fd_topo_fill}} -->
The `fd_topo_fill` function iterates over all workspaces in a topology and fills each one using the [`fd_topo_workspace_fill`](#fd_topo_workspace_fill) function.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing workspaces to be filled.
- **Control Flow**:
    - The function starts a loop that iterates over each workspace in the `topo` structure, using the `wksp_cnt` field to determine the number of iterations.
    - For each iteration, it calls [`fd_topo_workspace_fill`](#fd_topo_workspace_fill), passing the `topo` pointer and a pointer to the current workspace from the `workspaces` array.
- **Output**: This function does not return a value; it operates by side-effect, modifying the state of the workspaces within the `topo` structure.
- **Functions called**:
    - [`fd_topo_workspace_fill`](#fd_topo_workspace_fill)


---
### fd\_topo\_tile\_extra\_huge\_pages<!-- {{#callable:fd_topo_tile_extra_huge_pages}} -->
The function `fd_topo_tile_extra_huge_pages` calculates the number of extra huge pages required for a tile's stack.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile for which the extra huge pages are being calculated.
- **Control Flow**:
    - The function takes a single input parameter `tile`, which is not used in the function body.
    - It calculates the number of extra huge pages by dividing `FD_TILE_PRIVATE_STACK_SZ` by `FD_SHMEM_HUGE_PAGE_SZ` and adding 2 to the result.
    - The function returns this calculated value.
- **Output**: The function returns an `ulong` representing the number of extra huge pages required for the tile's stack.


---
### fd\_topo\_tile\_extra\_normal\_pages<!-- {{#callable:fd_topo_tile_extra_normal_pages}} -->
The function `fd_topo_tile_extra_normal_pages` calculates the number of extra normal memory pages required by a tile based on its name and adds one additional page for a shared lock.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing a tile in the topology.
- **Control Flow**:
    - Initialize `key_pages` to 0.
    - Check if the tile's name matches any of the specified names ('sign', 'shred', 'poh', 'quic', 'gossip', 'repair', 'storei').
    - If a match is found, set `key_pages` to 5, indicating that these tiles require additional normal pages for key material.
    - Add 1 to `key_pages` to account for the normal page needed for the `fd_log` shared lock.
    - Return the total number of normal pages calculated.
- **Output**: Returns an `ulong` representing the total number of extra normal pages required by the tile.


---
### fd\_topo\_mlock\_max\_tile1<!-- {{#callable:fd_topo_mlock_max_tile1}} -->
The function `fd_topo_mlock_max_tile1` calculates the maximum memory lock size required for a specific tile in a topology, considering both workspace and extra page requirements.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the specific tile within the topology.
- **Control Flow**:
    - Initialize `tile_mem` to 0 to accumulate memory requirements.
    - Iterate over each workspace in the topology using a loop from 0 to `topo->wksp_cnt`.
    - For each workspace, check if the tile needs the workspace using [`tile_needs_wksp`](#tile_needs_wksp); if true, add the workspace's memory size (page count multiplied by page size) to `tile_mem`.
    - Add the memory size of extra huge pages required by the tile, calculated by [`fd_topo_tile_extra_huge_pages`](#fd_topo_tile_extra_huge_pages), multiplied by the size of a huge page.
    - Add the memory size of extra normal pages required by the tile, calculated by [`fd_topo_tile_extra_normal_pages`](#fd_topo_tile_extra_normal_pages), multiplied by the size of a normal page.
    - Return the total calculated memory size.
- **Output**: The function returns an `ulong` representing the total memory size required to lock for the specified tile, including workspace and extra page requirements.
- **Functions called**:
    - [`tile_needs_wksp`](#tile_needs_wksp)
    - [`fd_topo_tile_extra_huge_pages`](#fd_topo_tile_extra_huge_pages)
    - [`fd_topo_tile_extra_normal_pages`](#fd_topo_tile_extra_normal_pages)


---
### fd\_topo\_mlock\_max\_tile<!-- {{#callable:fd_topo_mlock_max_tile}} -->
The function `fd_topo_mlock_max_tile` calculates the maximum memory lock size required by any single tile in a given topology.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology of the system, which includes information about tiles and workspaces.
- **Control Flow**:
    - Initialize `highest_tile_mem` to 0 to keep track of the maximum memory lock size found.
    - Iterate over each tile in the topology using a loop that runs from 0 to `topo->tile_cnt`.
    - For each tile, call [`fd_topo_mlock_max_tile1`](#fd_topo_mlock_max_tile1) to calculate the memory lock size required by that tile.
    - Update `highest_tile_mem` to be the maximum of its current value and the memory lock size returned by [`fd_topo_mlock_max_tile1`](#fd_topo_mlock_max_tile1).
    - After the loop, return `highest_tile_mem` as the result.
- **Output**: The function returns an `ulong` representing the maximum memory lock size required by any single tile in the topology.
- **Functions called**:
    - [`fd_topo_mlock_max_tile1`](#fd_topo_mlock_max_tile1)


---
### fd\_topo\_gigantic\_page\_cnt<!-- {{#callable:fd_topo_gigantic_page_cnt}} -->
The function `fd_topo_gigantic_page_cnt` calculates the total number of gigantic pages in a topology for a specified NUMA node index.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology, which contains information about workspaces and their configurations.
    - `numa_idx`: An unsigned long integer representing the NUMA node index for which the gigantic page count is to be calculated.
- **Control Flow**:
    - Initialize a result variable to 0.
    - Iterate over each workspace in the topology using a loop.
    - For each workspace, check if its NUMA index matches the provided `numa_idx`. If not, continue to the next workspace.
    - If the workspace's page size is equal to `FD_SHMEM_GIGANTIC_PAGE_SZ`, add its page count to the result.
    - Return the accumulated result.
- **Output**: The function returns an unsigned long integer representing the total number of gigantic pages for the specified NUMA node index.


---
### fd\_topo\_huge\_page\_cnt<!-- {{#callable:fd_topo_huge_page_cnt}} -->
The `fd_topo_huge_page_cnt` function calculates the total number of huge pages used by workspaces and tiles in a given topology for a specified NUMA node.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing workspaces and tiles.
    - `numa_idx`: An unsigned long integer representing the NUMA node index to filter workspaces by.
    - `include_anonymous`: An integer flag indicating whether to include anonymous huge pages, though currently unused in the function.
- **Control Flow**:
    - Initialize `result` to 0 to accumulate the count of huge pages.
    - Iterate over each workspace in the topology using a for loop.
    - For each workspace, check if its `numa_idx` matches the provided `numa_idx`; if not, continue to the next workspace.
    - If the workspace's page size is equal to `FD_SHMEM_HUGE_PAGE_SZ`, add its page count to `result`.
    - Iterate over each tile in the topology using another for loop.
    - For each tile, add the result of [`fd_topo_tile_extra_huge_pages`](#fd_topo_tile_extra_huge_pages) to `result`, which accounts for additional huge pages used by the tile's stack.
    - Ignore the `include_anonymous` parameter as it is not currently used in the function.
    - Return the accumulated `result` as the total count of huge pages.
- **Output**: The function returns an unsigned long integer representing the total number of huge pages used by the specified NUMA node's workspaces and tiles.
- **Functions called**:
    - [`fd_topo_tile_extra_huge_pages`](#fd_topo_tile_extra_huge_pages)


---
### fd\_topo\_normal\_page\_cnt<!-- {{#callable:fd_topo_normal_page_cnt}} -->
The function `fd_topo_normal_page_cnt` calculates the total number of normal pages required by all tiles in a given topology.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology, which contains information about tiles and their configurations.
- **Control Flow**:
    - Initialize a variable `result` to 0 to accumulate the total number of normal pages.
    - Iterate over each tile in the topology using a loop that runs from 0 to `topo->tile_cnt`.
    - For each tile, call [`fd_topo_tile_extra_normal_pages`](#fd_topo_tile_extra_normal_pages) to get the number of extra normal pages required by that tile and add it to `result`.
    - Return the accumulated `result` as the total number of normal pages.
- **Output**: The function returns an `ulong` representing the total number of normal pages required by all tiles in the topology.
- **Functions called**:
    - [`fd_topo_tile_extra_normal_pages`](#fd_topo_tile_extra_normal_pages)


---
### fd\_topo\_mlock<!-- {{#callable:fd_topo_mlock}} -->
The `fd_topo_mlock` function calculates the total memory size required to lock all workspaces in a given topology.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology containing workspaces.
- **Control Flow**:
    - Initialize a variable `result` to 0.
    - Iterate over each workspace in the topology using a loop that runs from 0 to `topo->wksp_cnt`.
    - For each workspace, multiply the number of pages (`page_cnt`) by the page size (`page_sz`) and add the result to `result`.
    - Return the accumulated `result` value.
- **Output**: The function returns an `ulong` representing the total memory size required to lock all workspaces in the topology.


---
### fd\_topo\_mem\_sz\_string<!-- {{#callable:fd_topo_mem_sz_string}} -->
The `fd_topo_mem_sz_string` function formats a given memory size in bytes into a human-readable string representation with appropriate units (GiB, MiB, KiB, or B).
- **Inputs**:
    - `sz`: The memory size in bytes to be formatted.
    - `out`: A character array with a minimum size of 24 to store the formatted string.
- **Control Flow**:
    - Check if the size `sz` is greater than or equal to `FD_SHMEM_GIGANTIC_PAGE_SZ`; if true, format `sz` in GiB and store it in `out`.
    - If the size is not gigantic, check if `sz` is greater than or equal to 1048576; if true, format `sz` in MiB and store it in `out`.
    - If the size is not in MiB, check if `sz` is greater than or equal to 1024; if true, format `sz` in KiB and store it in `out`.
    - If none of the above conditions are met, format `sz` in bytes and store it in `out`.
- **Output**: The function does not return a value but outputs a formatted string in the `out` array.


---
### fd\_topo\_print\_log<!-- {{#callable:fd_topo_print_log}} -->
The `fd_topo_print_log` function generates and logs a detailed summary of the topology configuration, including memory usage, page requirements, workspace details, object properties, link configurations, and tile information.
- **Inputs**:
    - `stdout`: An integer flag indicating whether to print the log to standard output (if non-zero) or to a notice log (if zero).
    - `topo`: A pointer to an `fd_topo_t` structure containing the topology configuration and data to be logged.
- **Control Flow**:
    - Initialize a large character buffer `message` to store the log output.
    - Define a macro `PRINT` to safely append formatted strings to the `message` buffer, checking for errors and buffer overflows.
    - Print a summary header and calculate the total memory locked, including stack pages and private key pages.
    - Calculate and print the number of required gigantic, huge, and normal pages for the topology, iterating over NUMA nodes.
    - If `topo->agave_affinity_cnt` is greater than zero, format and print the agave affinity information.
    - Iterate over each workspace in `topo->workspaces`, printing details such as page count, page size, NUMA index, and footprint.
    - Iterate over each object in `topo->objs`, printing details such as workspace ID, footprint, and additional properties from the `topo->props` POD.
    - Iterate over each link in `topo->links`, printing details such as kind ID, workspace ID, depth, MTU, and burst size.
    - Iterate over each tile in `topo->tiles`, printing details such as kind ID, workspace ID, CPU index, NUMA index, input and output links, and used objects.
    - If `stdout` is non-zero, print the `message` to standard output; otherwise, log it as a notice.
- **Output**: The function outputs a formatted log message detailing the topology configuration, either to standard output or a notice log, depending on the `stdout` flag.
- **Functions called**:
    - [`fd_topo_mlock`](#fd_topo_mlock)
    - [`fd_topo_gigantic_page_cnt`](#fd_topo_gigantic_page_cnt)
    - [`fd_topo_huge_page_cnt`](#fd_topo_huge_page_cnt)
    - [`fd_topo_normal_page_cnt`](#fd_topo_normal_page_cnt)
    - [`fd_topo_mem_sz_string`](#fd_topo_mem_sz_string)
    - [`fd_topo_mlock_max_tile1`](#fd_topo_mlock_max_tile1)


