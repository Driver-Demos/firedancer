# Purpose
The provided C code is a comprehensive implementation of a data structure referred to as a "forest," which is a collection of trees. This code is designed to manage and manipulate hierarchical data structures, specifically focusing on operations such as creation, initialization, joining, leaving, deletion, and verification of these forest structures. The code is structured to handle memory alignment and workspace management, ensuring that the forest data structure is correctly allocated and maintained within a shared memory space. The primary functions include [`fd_forest_new`](#fd_forest_new), which initializes a new forest in a given memory space, and [`fd_forest_join`](#fd_forest_join), [`fd_forest_leave`](#fd_forest_leave), and [`fd_forest_delete`](#fd_forest_delete), which manage the lifecycle of the forest structure. Additionally, the code provides mechanisms for querying, inserting, and linking elements within the forest, as well as printing the structure for debugging or visualization purposes.

The code is organized into several static and public functions, with static functions handling internal operations such as linking nodes and managing orphaned elements. The public functions define the external interface for interacting with the forest, allowing for operations like querying and inserting data shreds, advancing the frontier, and publishing new root slots. The code also includes detailed logging and error handling to ensure robustness and provide feedback during execution. The use of macros and attributes, such as `VER_INC` and `__attribute__((cleanup(ver_inc)))`, indicates a focus on maintaining version consistency and ensuring proper cleanup of resources. Overall, this code provides a specialized and efficient implementation for managing complex hierarchical data structures in a shared memory environment.
# Imports and Dependencies

---
- `fd_forest.h`
- `stdio.h`


# Functions

---
### ver\_inc<!-- {{#callable:ver_inc}} -->
The `ver_inc` function increments the version number pointed to by a given pointer to a pointer to an unsigned long integer.
- **Inputs**:
    - `ver`: A pointer to a pointer to an unsigned long integer, representing the version number to be incremented.
- **Control Flow**:
    - The function dereferences the double pointer `ver` to obtain the current version number.
    - It calls `fd_fseq_query` to retrieve the current version number value.
    - It increments the retrieved version number by 1.
    - It calls `fd_fseq_update` to update the version number with the incremented value.
- **Output**: The function does not return a value; it modifies the version number in place.


---
### fd\_forest\_new<!-- {{#callable:fd_forest_new}} -->
The `fd_forest_new` function initializes a new forest data structure in shared memory, setting up various components and ensuring proper alignment and configuration.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the forest will be initialized.
    - `ele_max`: The maximum number of elements that the forest can contain.
    - `seed`: A seed value used for initializing certain components of the forest.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL and log a warning if so, returning NULL.
    - Verify that `shmem` is properly aligned according to `fd_forest_align()` and log a warning if not, returning NULL.
    - Calculate the memory footprint required for the forest using `fd_forest_footprint(ele_max)` and log a warning if it is zero, returning NULL.
    - Ensure that `shmem` is part of a workspace by checking with `fd_wksp_containing(shmem)` and log a warning if not, returning NULL.
    - Clear the memory region pointed to by `shmem` using `fd_memset`.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT` and allocate memory for various components of the forest, including `forest`, `ver`, `pool`, `ancestry`, `frontier`, and `orphaned`.
    - Verify that the total allocated memory matches the calculated footprint using `FD_SCRATCH_ALLOC_FINI`.
    - Set initial values for the forest structure, including setting the root to `ULONG_MAX` and obtaining global addresses for various components using `fd_wksp_gaddr_fast`.
    - Set the `magic` field of the forest to `FD_FOREST_MAGIC` using memory fences to ensure proper ordering.
    - Return the `shmem` pointer.
- **Output**: Returns the `shmem` pointer if successful, or NULL if any checks fail.
- **Functions called**:
    - [`fd_forest_align`](fd_forest.h.driver.md#fd_forest_align)
    - [`fd_forest_footprint`](fd_forest.h.driver.md#fd_forest_footprint)


---
### fd\_forest\_join<!-- {{#callable:fd_forest_join}} -->
The `fd_forest_join` function validates and returns a pointer to a forest structure if it is properly aligned and part of a workspace.
- **Inputs**:
    - `shforest`: A void pointer to a shared memory region that is expected to contain a forest structure.
- **Control Flow**:
    - Cast the input `shforest` to a `fd_forest_t` pointer named `forest`.
    - Check if `forest` is NULL; if so, log a warning and return NULL.
    - Check if `forest` is aligned according to [`fd_forest_align`](fd_forest.h.driver.md#fd_forest_align); if not, log a warning and return NULL.
    - Retrieve the workspace containing `forest` using `fd_wksp_containing`; if it is not part of a workspace, log a warning and return NULL.
    - Return the `forest` pointer.
- **Output**: Returns a pointer to the `fd_forest_t` structure if all checks pass, otherwise returns NULL.
- **Functions called**:
    - [`fd_forest_align`](fd_forest.h.driver.md#fd_forest_align)


---
### fd\_forest\_leave<!-- {{#callable:fd_forest_leave}} -->
The `fd_forest_leave` function checks if a given forest pointer is valid and returns it as a void pointer if it is, or logs a warning and returns NULL if it is not.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure, representing the forest to be left.
- **Control Flow**:
    - Check if the `forest` pointer is NULL using `FD_UNLIKELY` macro.
    - If `forest` is NULL, log a warning message 'NULL forest' and return NULL.
    - If `forest` is not NULL, cast it to a void pointer and return it.
- **Output**: Returns a void pointer to the `forest` if it is not NULL, otherwise returns NULL.


---
### fd\_forest\_delete<!-- {{#callable:fd_forest_delete}} -->
The `fd_forest_delete` function checks if a given forest pointer is valid and aligned, and returns the pointer if it is, otherwise it logs a warning and returns NULL.
- **Inputs**:
    - `forest`: A pointer to the forest structure that is to be deleted.
- **Control Flow**:
    - Check if the `forest` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `forest` pointer is aligned according to [`fd_forest_align`](fd_forest.h.driver.md#fd_forest_align); if not, log a warning and return NULL.
    - Return the `forest` pointer.
- **Output**: Returns the `forest` pointer if it is valid and aligned, otherwise returns NULL.
- **Functions called**:
    - [`fd_forest_align`](fd_forest.h.driver.md#fd_forest_align)


---
### fd\_forest\_init<!-- {{#callable:fd_forest_init}} -->
The `fd_forest_init` function initializes a forest data structure by setting up its root node and updating its version.
- **Inputs**:
    - `forest`: A pointer to an `fd_forest_t` structure that represents the forest to be initialized.
    - `root_slot`: An unsigned long integer representing the slot value for the root node of the forest.
- **Control Flow**:
    - The function begins by asserting that the `forest` pointer is valid and that the forest's version is uninitialized.
    - The version of the forest is incremented using the `VER_INC` macro.
    - Pointers to the pool and frontier of the forest are obtained, and the null index for the pool is retrieved.
    - A new root element is acquired from the pool, and its fields are initialized with the provided `root_slot` and null values for its relationships (prev, parent, child, sibling).
    - The root element's buffered and complete indices are set to zero, and its index array is initialized to null values.
    - The root element is inserted into the forest's frontier, and the forest's root is set to the index of the root element in the pool.
    - Sanity checks are performed to ensure the root element is correctly initialized and inserted into the frontier.
    - The function returns the initialized `forest` pointer.
- **Output**: A pointer to the initialized `fd_forest_t` structure.
- **Functions called**:
    - [`fd_forest_ver`](fd_forest.h.driver.md#fd_forest_ver)


---
### fd\_forest\_fini<!-- {{#callable:fd_forest_fini}} -->
The `fd_forest_fini` function finalizes a forest data structure by setting its version to an uninitialized state and returns the forest pointer.
- **Inputs**:
    - `forest`: A pointer to an `fd_forest_t` structure that represents the forest to be finalized.
- **Control Flow**:
    - The function calls [`fd_forest_ver`](fd_forest.h.driver.md#fd_forest_ver) to get the version pointer of the forest.
    - It then calls `fd_fseq_update` to set the version of the forest to `FD_FOREST_VER_UNINIT`, indicating that the forest is uninitialized.
    - Finally, it returns the input `forest` pointer cast to a `void *`.
- **Output**: A `void *` pointer to the input `fd_forest_t` structure, representing the finalized forest.
- **Functions called**:
    - [`fd_forest_ver`](fd_forest.h.driver.md#fd_forest_ver)


---
### fd\_forest\_verify<!-- {{#callable:fd_forest_verify}} -->
The `fd_forest_verify` function checks the validity and integrity of a given forest data structure by performing a series of validation checks on its alignment, workspace association, magic number, initialization state, and internal structures.
- **Inputs**:
    - `forest`: A pointer to a constant `fd_forest_t` structure representing the forest to be verified.
- **Control Flow**:
    - Check if the `forest` pointer is NULL; if so, log a warning and return -1.
    - Verify if the `forest` is properly aligned using `fd_ulong_is_aligned`; if not, log a warning and return -1.
    - Determine if the `forest` is part of a workspace using `fd_wksp_containing`; if not, log a warning and return -1.
    - Check if the `forest` has the correct magic number `FD_FOREST_MAGIC`; if not, log a warning and return -1.
    - Query the forest version using `fd_fseq_query` to ensure it is not uninitialized or invalid; if it is, log a warning and return -1.
    - Retrieve the pool of elements from the forest using [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const).
    - Verify the ancestry of the forest using `fd_forest_ancestry_verify`; if it fails, return -1.
    - Verify the frontier of the forest using `fd_forest_frontier_verify`; if it fails, return -1.
    - If all checks pass, return 0 indicating the forest is valid.
- **Output**: Returns 0 if the forest is valid, otherwise returns -1 if any validation check fails.
- **Functions called**:
    - [`fd_forest_align`](fd_forest.h.driver.md#fd_forest_align)
    - [`fd_forest_ver_const`](fd_forest.h.driver.md#fd_forest_ver_const)
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)
    - [`fd_forest_ancestry_const`](fd_forest.h.driver.md#fd_forest_ancestry_const)
    - [`fd_forest_frontier_const`](fd_forest.h.driver.md#fd_forest_frontier_const)


---
### ancestry\_frontier\_query<!-- {{#callable:ancestry_frontier_query}} -->
The `ancestry_frontier_query` function retrieves a connected element from either the ancestry or frontier maps of a forest data structure, based on a given slot.
- **Inputs**:
    - `forest`: A pointer to the `fd_forest_t` structure representing the forest data structure.
    - `slot`: An unsigned long integer representing the slot key used to query the element in the forest.
- **Control Flow**:
    - Retrieve the pool of elements from the forest using `fd_forest_pool` function.
    - Initialize a pointer `ele` to NULL.
    - Query the ancestry map of the forest for an element with the given slot using `fd_forest_ancestry_ele_query`.
    - If the element is not found in the ancestry map, query the frontier map using `fd_forest_frontier_ele_query`.
    - Return the found element, or NULL if not found in both maps.
- **Output**: A pointer to the `fd_forest_ele_t` element found in either the ancestry or frontier map, or NULL if not found.


---
### ancestry\_frontier\_remove<!-- {{#callable:ancestry_frontier_remove}} -->
The `ancestry_frontier_remove` function removes and returns an element from either the ancestry or frontier maps of a forest data structure, based on a given slot.
- **Inputs**:
    - `forest`: A pointer to the `fd_forest_t` structure representing the forest from which an element is to be removed.
    - `slot`: An unsigned long integer representing the slot key of the element to be removed from the forest's ancestry or frontier maps.
- **Control Flow**:
    - Retrieve the pool of elements from the forest using `fd_forest_pool` function.
    - Attempt to remove the element from the ancestry map using `fd_forest_ancestry_ele_remove`.
    - If the element is not found in the ancestry map, attempt to remove it from the frontier map using `fd_forest_frontier_ele_remove`.
    - Return the removed element, which could be `NULL` if not found in either map.
- **Output**: A pointer to the `fd_forest_ele_t` structure representing the removed element, or `NULL` if no element was found and removed.


---
### link\_sibling<!-- {{#callable:link_sibling}} -->
The `link_sibling` function links a given element as the sibling of another element in a forest data structure.
- **Inputs**:
    - `forest`: A pointer to the forest data structure, which contains the pool of elements.
    - `sibling`: A pointer to the sibling element to which the new element will be linked.
    - `ele`: A pointer to the element that needs to be linked as a sibling.
- **Control Flow**:
    - Retrieve the pool of elements from the forest using `fd_forest_pool(forest)`.
    - Get the null index value for the pool using `fd_forest_pool_idx_null(pool)`.
    - Enter a loop that continues as long as the current sibling's sibling index is not null.
    - Within the loop, update the sibling to point to the next sibling element using `fd_forest_pool_ele(pool, sibling->sibling)`.
    - After exiting the loop, set the current sibling's sibling index to the index of the element `ele` using `fd_forest_pool_idx(pool, ele)`.
- **Output**: The function does not return any value; it modifies the sibling linkage in the forest data structure.


---
### link<!-- {{#callable:link}} -->
The `link` function connects a child element to a parent element in a forest data structure, either as a left-child or as a right-sibling, and updates the child's parent reference accordingly.
- **Inputs**:
    - `forest`: A pointer to the forest data structure (`fd_forest_t`) where the elements are being linked.
    - `parent`: A pointer to the parent element (`fd_forest_ele_t`) in the forest to which the child will be linked.
    - `child`: A pointer to the child element (`fd_forest_ele_t`) that will be linked to the parent.
- **Control Flow**:
    - Retrieve the pool of elements from the forest using `fd_forest_pool` function.
    - Get the null index value for the pool using `fd_forest_pool_idx_null`.
    - Check if the parent element's child is null (i.e., it has no children).
    - If the parent has no children, set the parent's child to the index of the child element, making it the left-child.
    - If the parent already has a child, call [`link_sibling`](#link_sibling) to add the child as a right-sibling to the existing child.
    - Set the child's parent to the index of the parent element.
- **Output**: The function does not return a value; it modifies the forest structure by linking the child to the parent.
- **Functions called**:
    - [`link_sibling`](#link_sibling)


---
### link\_orphans<!-- {{#callable:link_orphans}} -->
The `link_orphans` function performs a breadth-first search (BFS) to link orphaned elements in a forest data structure to their ancestry tree if possible, removing them from the orphaned map and adding their children to the BFS queue.
- **Inputs**:
    - `forest`: A pointer to the `fd_forest_t` structure representing the forest data structure.
    - `head`: A pointer to the `fd_forest_ele_t` structure representing the head of a linked list, which serves as the starting point for the BFS queue.
- **Control Flow**:
    - Initialize pointers to the pool, null index, ancestry, and orphaned structures from the forest.
    - Set the tail of the queue to the head and initialize a previous pointer to NULL.
    - Enter a while loop that continues as long as the head is not NULL, indicating the queue is non-empty.
    - Check if the current head is an orphan root by attempting to remove it from the orphaned map.
    - If the head is an orphan root, insert it into the ancestry map and process its children.
    - For each child of the current head, append it to the BFS queue by updating the tail's previous pointer and setting the child's sibling to null.
    - Update the head to the next element in the queue and set the previous element's previous pointer to null.
- **Output**: The function does not return a value; it modifies the forest data structure by linking orphaned elements to their ancestry tree and updating the orphaned map.


---
### advance\_frontier<!-- {{#callable:advance_frontier}} -->
The `advance_frontier` function attempts to advance the frontier of a forest data structure by processing elements in a breadth-first search manner, moving completed elements from the frontier to the ancestry and adding their children to the frontier.
- **Inputs**:
    - `forest`: A pointer to the `fd_forest_t` structure representing the forest data structure.
    - `slot`: An unsigned long integer representing the starting slot from which to advance the frontier.
    - `parent_off`: An unsigned short integer representing the offset to calculate the parent slot from the given slot.
- **Control Flow**:
    - Retrieve the pool, null index, ancestry, and frontier from the forest structure.
    - Query the frontier for the element at the given slot; if not found, query for the parent slot calculated using `parent_off`.
    - Initialize `head`, `tail`, and `prev` pointers for the BFS queue starting with the found element.
    - While the `head` is not null, check if the element's children can be processed (i.e., if the element is complete).
    - If the element is complete, remove it from the frontier and insert it into the ancestry.
    - Iterate over the element's children, removing them from the ancestry and inserting them into the frontier, updating the BFS queue accordingly.
    - Continue processing the next element in the queue by updating `head` and `prev`.
- **Output**: The function does not return a value; it modifies the forest's frontier and ancestry structures in place.


---
### query<!-- {{#callable:query}} -->
The `query` function searches for an element in a forest data structure by its slot, checking in the ancestry, frontier, and orphaned maps in sequence.
- **Inputs**:
    - `forest`: A pointer to the forest data structure where the search is conducted.
    - `slot`: The slot number used as the key to search for the element in the forest.
- **Control Flow**:
    - Retrieve the pool, ancestry, frontier, and orphaned components of the forest using helper functions.
    - Attempt to find the element in the ancestry map using `fd_forest_ancestry_ele_query`.
    - If not found in ancestry, attempt to find the element in the frontier map using `fd_forest_frontier_ele_query`.
    - If still not found, attempt to find the element in the orphaned map using `fd_forest_orphaned_ele_query`.
    - Return the found element or NULL if not found in any map.
- **Output**: A pointer to the `fd_forest_ele_t` element found in the forest, or NULL if the element is not found in any of the maps.


---
### acquire<!-- {{#callable:acquire}} -->
The `acquire` function initializes and returns a new forest element with a specified slot, setting its various indices and pointers to null or default values.
- **Inputs**:
    - `forest`: A pointer to the forest structure from which the element is to be acquired.
    - `slot`: An unsigned long integer representing the slot number to be assigned to the new element.
- **Control Flow**:
    - Retrieve the pool of elements from the forest using `fd_forest_pool` function.
    - Acquire a new element from the pool using `fd_forest_pool_ele_acquire`.
    - Retrieve the null index for the pool using `fd_forest_pool_idx_null`.
    - Set the slot of the acquired element to the provided slot value.
    - Initialize the `prev`, `next`, `parent`, `child`, and `sibling` pointers of the element to the null index.
    - Set the `buffered_idx` and `complete_idx` of the element to `UINT_MAX`.
    - Call `fd_forest_ele_idxs_null` on the `cmpl`, `fecs`, and `idxs` arrays of the element to initialize them to null values.
    - Return the initialized element.
- **Output**: A pointer to the newly acquired and initialized `fd_forest_ele_t` element.


---
### insert<!-- {{#callable:insert}} -->
The `insert` function inserts a new element into a forest data structure, linking it to its parent if the parent exists.
- **Inputs**:
    - `forest`: A pointer to the forest data structure where the element will be inserted.
    - `slot`: The slot number representing the position of the new element in the forest.
    - `parent_off`: The offset from the slot to determine the parent slot of the new element.
- **Control Flow**:
    - Retrieve the pool of elements from the forest using `fd_forest_pool` function.
    - If handholding is enabled, perform checks to ensure `parent_off` is less than or equal to `slot`, the pool has free space, and `slot` is greater than the root slot.
    - Acquire a new element from the pool for the given `slot`.
    - Calculate the `parent_slot` by subtracting `parent_off` from `slot`.
    - Query the forest for the parent element using the `parent_slot`.
    - If the parent element is found, insert the new element into the forest's ancestry and link it to the parent.
- **Output**: Returns a pointer to the newly inserted element in the forest.
- **Functions called**:
    - [`fd_forest_root_slot`](fd_forest.h.driver.md#fd_forest_root_slot)
    - [`acquire`](#acquire)
    - [`query`](#query)
    - [`link`](#link)


---
### fd\_forest\_query<!-- {{#callable:fd_forest_query}} -->
The `fd_forest_query` function retrieves a connected element from a forest data structure based on a given slot, excluding orphaned elements.
- **Inputs**:
    - `forest`: A pointer to the `fd_forest_t` structure representing the forest data structure.
    - `slot`: An unsigned long integer representing the slot key used to query the forest for a connected element.
- **Control Flow**:
    - If `FD_FOREST_USE_HANDHOLDING` is defined, the function checks if the slot is greater than the root slot of the forest to prevent caller errors.
    - The function calls the [`query`](#query) function with the provided `forest` and `slot` to retrieve the connected element.
- **Output**: Returns a pointer to the `fd_forest_ele_t` structure representing the connected element found in the forest, or NULL if no such element exists.
- **Functions called**:
    - [`fd_forest_root_slot`](fd_forest.h.driver.md#fd_forest_root_slot)
    - [`query`](#query)


---
### fd\_forest\_data\_shred\_insert<!-- {{#callable:fd_forest_data_shred_insert}} -->
The `fd_forest_data_shred_insert` function inserts a data shred into a forest data structure, handling orphaned elements and updating the forest's structure accordingly.
- **Inputs**:
    - `forest`: A pointer to the forest data structure where the shred will be inserted.
    - `slot`: The slot number where the shred is to be inserted.
    - `parent_off`: The offset to the parent slot from the current slot.
    - `shred_idx`: The index of the shred being inserted.
    - `fec_set_idx`: The index of the FEC (Forward Error Correction) set associated with the shred.
    - `data_complete`: An unused parameter indicating if the data is complete.
    - `slot_complete`: An integer indicating if the slot is complete.
- **Control Flow**:
    - Increment the version counter of the forest.
    - Query the forest for an element at the given slot; if not found, insert a new element.
    - If the element is an orphan (i.e., it has no parent), attempt to find or acquire its parent and link the orphan to its parent.
    - Insert the shred index and FEC set index into the element's index sets.
    - Update the buffered index of the element to reflect the highest contiguous shred index received.
    - Set the complete index of the element based on whether the slot is complete.
    - Advance the frontier of the forest to reflect the new state of the element.
- **Output**: Returns a pointer to the forest element where the shred was inserted.
- **Functions called**:
    - [`fd_forest_root_slot`](fd_forest.h.driver.md#fd_forest_root_slot)
    - [`query`](#query)
    - [`insert`](#insert)
    - [`acquire`](#acquire)
    - [`link`](#link)
    - [`advance_frontier`](#advance_frontier)


---
### fd\_forest\_publish<!-- {{#callable:fd_forest_publish}} -->
The `fd_forest_publish` function updates the root of a forest data structure to a new specified root slot, pruning the tree of elements that are no longer part of the ancestry of the new root.
- **Inputs**:
    - `forest`: A pointer to the `fd_forest_t` structure representing the forest to be modified.
    - `new_root_slot`: An unsigned long integer representing the slot of the new root element in the forest.
- **Control Flow**:
    - Log the function call with the new root slot for debugging purposes.
    - Increment the version of the forest using the `VER_INC` macro.
    - Retrieve the ancestry, frontier, and pool components of the forest, as well as the null index for the pool.
    - Find the current root element and the new root element using the provided slot.
    - If handholding is enabled, check that the new root element exists and its slot is greater than the old root's slot.
    - Remove the old root from the ancestry/frontier and initialize a FIFO prune queue with it.
    - Perform a breadth-first search (BFS) to traverse the tree, adding elements to the prune queue unless they are part of the new root's ancestry.
    - For each element in the prune queue, remove it from the ancestry/frontier and release it back to the pool.
    - Unlink the new root from its parent and update the forest's root to the new root slot.
- **Output**: Returns a pointer to the `fd_forest_ele_t` structure representing the new root element.
- **Functions called**:
    - [`ancestry_frontier_query`](#ancestry_frontier_query)
    - [`ancestry_frontier_remove`](#ancestry_frontier_remove)


---
### preorder<!-- {{#callable:preorder}} -->
The `preorder` function performs a preorder traversal of a tree structure, printing the slot of each node as it visits them.
- **Inputs**:
    - `forest`: A pointer to a constant `fd_forest_t` structure representing the forest containing the tree to be traversed.
    - `ele`: A pointer to a constant `fd_forest_ele_t` structure representing the current element (node) in the tree to start the traversal from.
- **Control Flow**:
    - Retrieve the pool of elements from the forest using [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const) function.
    - Get the first child of the current element using `fd_forest_pool_ele_const` function.
    - Print the slot of the current element using `printf`.
    - Enter a loop that continues as long as the current child is not NULL.
    - Within the loop, recursively call `preorder` on each child.
    - Update the child to its sibling using `fd_forest_pool_ele_const` function.
- **Output**: This function does not return a value; it outputs the slots of the nodes to the standard output as a side effect.
- **Functions called**:
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)


---
### fd\_forest\_preorder\_print<!-- {{#callable:fd_forest_preorder_print}} -->
The `fd_forest_preorder_print` function prints the elements of a forest data structure in preorder traversal.
- **Inputs**:
    - `forest`: A pointer to a constant `fd_forest_t` structure representing the forest to be traversed and printed.
- **Control Flow**:
    - Logs a notice indicating the start of preorder traversal.
    - Calls the [`preorder`](#preorder) function to recursively print the elements of the forest starting from the root.
    - Prints a newline after the traversal is complete.
- **Output**: This function does not return any value; it performs output operations by printing to the console.
- **Functions called**:
    - [`preorder`](#preorder)
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)


---
### num\_digits<!-- {{#callable:num_digits}} -->
The `num_digits` function calculates the number of digits in a given unsigned long integer by repeatedly dividing the number by 10 until it becomes zero.
- **Inputs**:
    - `slot`: An unsigned long integer whose number of digits is to be calculated.
- **Control Flow**:
    - Initialize an integer variable `digits` to 0 to keep track of the number of digits.
    - Enter a while loop that continues as long as `slot` is not zero.
    - In each iteration of the loop, increment `digits` by 1 and divide `slot` by 10 to remove the last digit.
    - Exit the loop when `slot` becomes zero.
    - Return the value of `digits`, which now contains the number of digits in the original `slot`.
- **Output**: The function returns an integer representing the number of digits in the input `slot`.


---
### ancestry\_print2<!-- {{#callable:ancestry_print2}} -->
The `ancestry_print2` function recursively prints the ancestry tree structure of a forest element, handling intervals and forks with specific formatting.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest containing the elements.
    - `ele`: A constant pointer to an `fd_forest_ele_t` structure representing the current element in the forest to be printed.
    - `prev`: A constant pointer to an `fd_forest_ele_t` structure representing the previous element in the sequence, used to determine intervals.
    - `last_printed`: An unsigned long integer representing the last printed slot number, used to manage interval printing.
    - `depth`: An integer representing the current depth in the tree, used for indentation.
    - `prefix`: A constant character pointer representing the prefix string used for formatting forks in the output.
- **Control Flow**:
    - Check if the current element `ele` is NULL; if so, return immediately.
    - Retrieve the pool of elements from the forest and calculate the number of digits in the current element's slot.
    - If a prefix is provided, print spaces for indentation based on the depth and then print the prefix.
    - If `prev` is NULL, indicating a new interval, print the opening bracket and the current element's slot, update `last_printed`, and adjust the depth.
    - Retrieve the child of the current element and determine if the interval should be closed based on non-consecutive slots or multiple children.
    - If the slots are non-consecutive or the current element has multiple children, print the appropriate closing and opening brackets, update `last_printed`, and reset `new_prev` if necessary.
    - If there are no children, print the closing bracket and return.
    - Initialize a new prefix for subsequent forks and iterate over the children, recursively calling `ancestry_print2` for each child.
    - Set up the prefix for the next iteration based on whether the current child has siblings.
- **Output**: The function does not return a value; it outputs formatted text to the standard output, representing the ancestry tree structure.
- **Functions called**:
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)
    - [`num_digits`](#num_digits)


---
### ancestry\_print<!-- {{#callable:FD_FN_UNUSED::ancestry_print}} -->
The `ancestry_print` function recursively prints the ancestry tree structure of a given element in a forest, using a specified prefix and indentation for visual representation.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest containing the elements.
    - `ele`: A constant pointer to an `fd_forest_ele_t` structure representing the current element in the forest whose ancestry is being printed.
    - `space`: An integer representing the number of spaces to indent the current element's output.
    - `prefix`: A constant character pointer representing the prefix to be used for the current element's output, indicating its position in the tree.
- **Control Flow**:
    - Check if the `ele` is NULL; if so, return immediately as there is nothing to print.
    - If `space` is greater than 0, print a newline character to separate the current element's output from the previous one.
    - Print the specified number of spaces for indentation.
    - Check if the `complete_idx` of the element is `UINT_MAX`; if so, print the element's slot and buffered index with a placeholder for the complete index, otherwise print the complete index as well.
    - Retrieve the first child of the current element using `fd_forest_pool_ele_const`.
    - Initialize a character array `new_prefix` to store the prefix for child elements.
    - Iterate over each child of the current element:
    - If the child has a sibling, set `new_prefix` to indicate a branch and recursively call `ancestry_print` with the child, increased space, and `new_prefix`.
    - If the child does not have a sibling, set `new_prefix` to indicate the end of a branch and recursively call `ancestry_print` with the child, increased space, and `new_prefix`.
    - Move to the next sibling of the current child and repeat the process.
- **Output**: The function does not return a value; it outputs the ancestry tree structure to the standard output.
- **Functions called**:
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)


---
### ancestry\_print3<!-- {{#callable:ancestry_print3}} -->
The `ancestry_print3` function recursively prints the structure of a forest element and its descendants, formatting the output to visually represent the hierarchy and relationships between elements.
- **Inputs**:
    - `forest`: A constant pointer to an `fd_forest_t` structure representing the forest containing the elements to be printed.
    - `ele`: A constant pointer to an `fd_forest_ele_t` structure representing the current element in the forest to be printed.
    - `space`: An integer representing the number of spaces to indent the current element's output.
    - `prefix`: A constant character pointer representing the prefix to be printed before the current element's slot number.
    - `prev`: A constant pointer to an `fd_forest_ele_t` structure representing the previous element in the traversal, used to track the last printed element.
    - `elide`: An integer flag indicating whether to elide (omit) the current element's slot number in the output if it is part of a consecutive sequence.
- **Control Flow**:
    - Check if the current element `ele` is NULL; if so, return immediately.
    - Retrieve the pool of elements from the forest using [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const).
    - Determine the child of the current element using `fd_forest_pool_ele_const`.
    - If `elide` is false, print a newline if `space` is greater than 0, then print the specified number of spaces, the prefix, and the current element's slot number.
    - If the current element has no children and `elide` is false, print a closing bracket and return.
    - If the current element has no children and `elide` is true, print the current slot number followed by a closing bracket and return.
    - Update `prev` to the current element and prepare a new prefix for child elements.
    - Check if the current element has exactly one child and if that child is non-consecutive; if so, handle printing and recursion accordingly.
    - If the current element has one consecutive child, recursively call `ancestry_print3` with `elide` set to true.
    - If the current element has multiple children, handle printing and recursively call `ancestry_print3` for each child, adjusting the prefix to indicate branches.
- **Output**: The function does not return a value; it outputs the formatted structure of the forest elements to the standard output.
- **Functions called**:
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)
    - [`num_digits`](#num_digits)


---
### fd\_forest\_ancestry\_print<!-- {{#callable:fd_forest_ancestry_print}} -->
The `fd_forest_ancestry_print` function prints the ancestry structure of a forest data structure starting from its root.
- **Inputs**:
    - `forest`: A pointer to a constant `fd_forest_t` structure representing the forest whose ancestry is to be printed.
- **Control Flow**:
    - Logs a notice indicating the start of ancestry printing.
    - Calls the [`ancestry_print3`](#ancestry_print3) function to recursively print the ancestry structure starting from the root of the forest.
- **Output**: This function does not return a value; it outputs the ancestry structure to the standard output.
- **Functions called**:
    - [`ancestry_print3`](#ancestry_print3)
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)


---
### fd\_forest\_frontier\_print<!-- {{#callable:fd_forest_frontier_print}} -->
The `fd_forest_frontier_print` function prints the details of each element in the frontier of a forest data structure, including its slot and indices.
- **Inputs**:
    - `forest`: A pointer to a constant `fd_forest_t` structure representing the forest whose frontier is to be printed.
- **Control Flow**:
    - Prints a header '[Frontier]' to indicate the start of the frontier section.
    - Retrieves the constant pool and frontier from the forest using [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const) and [`fd_forest_frontier_const`](fd_forest.h.driver.md#fd_forest_frontier_const).
    - Initializes an iterator for the frontier using `fd_forest_frontier_iter_init`.
    - Iterates over the frontier elements using a loop that continues until `fd_forest_frontier_iter_done` returns true.
    - For each element in the frontier, retrieves the element using `fd_forest_frontier_iter_ele_const`.
    - Prints the slot, buffered index, and complete index of each element in the frontier.
- **Output**: The function does not return a value; it outputs the frontier elements' details to the standard output.
- **Functions called**:
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)
    - [`fd_forest_frontier_const`](fd_forest.h.driver.md#fd_forest_frontier_const)


---
### fd\_forest\_orphaned\_print<!-- {{#callable:fd_forest_orphaned_print}} -->
The `fd_forest_orphaned_print` function prints the details of orphaned elements in a forest data structure.
- **Inputs**:
    - `forest`: A pointer to a constant `fd_forest_t` structure representing the forest whose orphaned elements are to be printed.
- **Control Flow**:
    - Prints a header '[Orphaned]' to indicate the start of orphaned elements output.
    - Retrieves the orphaned elements and the pool of elements from the forest.
    - Initializes an iterator to traverse through the orphaned elements.
    - Iterates over each orphaned element using the iterator until all elements are processed.
    - For each orphaned element, retrieves its constant representation and prints its ancestry using the [`ancestry_print2`](#ancestry_print2) function.
- **Output**: The function does not return any value; it outputs the details of orphaned elements to the standard output.
- **Functions called**:
    - [`fd_forest_orphaned_const`](fd_forest.h.driver.md#fd_forest_orphaned_const)
    - [`fd_forest_pool_const`](fd_forest.h.driver.md#fd_forest_pool_const)
    - [`ancestry_print2`](#ancestry_print2)


---
### fd\_forest\_print<!-- {{#callable:fd_forest_print}} -->
The `fd_forest_print` function prints the ancestry, frontier, and orphaned elements of a forest data structure if the forest is initialized.
- **Inputs**:
    - `forest`: A pointer to a constant `fd_forest_t` structure representing the forest to be printed.
- **Control Flow**:
    - Check if the forest's root is `ULONG_MAX`, indicating it is uninitialized, and return immediately if true.
    - Call [`fd_forest_ancestry_print`](#fd_forest_ancestry_print) to print the ancestry elements of the forest.
    - Call [`fd_forest_frontier_print`](#fd_forest_frontier_print) to print the frontier elements of the forest.
    - Call [`fd_forest_orphaned_print`](#fd_forest_orphaned_print) to print the orphaned elements of the forest.
    - Print two newline characters to separate the output visually.
- **Output**: The function does not return any value; it outputs the forest's structure to the standard output.
- **Functions called**:
    - [`fd_forest_ancestry_print`](#fd_forest_ancestry_print)
    - [`fd_forest_frontier_print`](#fd_forest_frontier_print)
    - [`fd_forest_orphaned_print`](#fd_forest_orphaned_print)


