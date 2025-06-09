# Purpose
This C source code file implements a weighted sampling algorithm using a specialized tree structure, which is a hybrid between a B-tree and a binary heap. The primary purpose of this code is to efficiently perform weighted sampling, where elements are selected based on their weights, and optionally, elements can be removed after sampling. The implementation uses a radix-9 tree structure, where each node stores cumulative sums of subtree weights, allowing for efficient, branchless traversal during sampling. This design is optimized for performance, particularly in scenarios where elements are frequently removed, as it minimizes branch mispredictions and leverages SIMD instructions for further optimization on AVX512-capable hardware.

The code defines a private data structure `fd_wsample_private` that encapsulates the tree and related metadata, such as total weight and count of elements. It provides a set of functions to initialize the sampler, add elements with weights, perform sampling, and handle element removal. The code also includes mechanisms for restoring the sampler to its initial state and handling "poisoned" states where sampling results become indeterminate. The file is intended to be part of a larger library, as indicated by the inclusion of external headers and the use of specific data types like `fd_chacha20rng_t` for random number generation. The implementation is designed to be flexible and extendable, with considerations for future optimizations and different use cases.
# Imports and Dependencies

---
- `fd_wsample.h`
- `math.h`
- `../../util/simd/fd_avx512.h`


# Data Structures

---
### tree\_ele
- **Type**: `struct`
- **Members**:
    - `left_sum`: An array storing the cumulative weight of the subtrees at this node, with size R-1.
- **Description**: The `tree_ele` structure is designed to represent a node in a specialized tree data structure used for efficient sampling operations. It contains a single member, `left_sum`, which is an array that holds the cumulative weights of the subtrees at the node. This structure is aligned to optimize performance, particularly in SIMD operations, and is part of a larger system that implements a high-radix tree for sampling with minimal branch mispredictions. The tree is stored implicitly in a flat array, and the `left_sum` values are used to facilitate quick navigation and sampling within the tree.


---
### tree\_ele\_t
- **Type**: `struct`
- **Members**:
    - `left_sum`: An array storing the cumulative weight of the subtrees at this node, with R-1 elements.
- **Description**: The `tree_ele_t` structure is a component of a high-performance sampling algorithm that uses a radix tree-like structure to efficiently manage and query weighted elements. Each node in this implicit tree structure, represented by `tree_ele_t`, contains an array `left_sum` that holds cumulative weights of its subtrees, facilitating quick determination of which subtree a random query value falls into. This design allows for efficient sampling operations with minimal branch mispredictions, leveraging the properties of a B-tree and binary heap, and is particularly optimized for scenarios where the tree is stored in a flat array without explicit pointers.


---
### fd\_wsample\_private
- **Type**: `struct`
- **Members**:
    - `total_cnt`: Stores the total count of elements in the sample.
    - `total_weight`: Stores the total weight of all elements in the sample.
    - `unremoved_cnt`: Tracks the count of elements that have not been removed.
    - `unremoved_weight`: Tracks the weight of elements that have not been removed.
    - `internal_node_cnt`: Stores the count of internal nodes in the tree structure.
    - `poisoned_weight`: Stores the weight used when the sample is in poisoned mode.
    - `height`: Represents the height of the tree structure.
    - `restore_enabled`: Indicates if the restore feature is enabled.
    - `poisoned_mode`: Indicates if the sample is in poisoned mode.
    - `rng`: Pointer to a random number generator used for sampling.
    - `dummy`: A dummy tree element used for safe out-of-bounds reads.
    - `tree`: An array of tree elements representing the sampling tree.
- **Description**: The `fd_wsample_private` structure is a complex data structure designed for weighted sampling without replacement. It uses a tree-based approach, similar to a B-tree with elements stored in a flat array, to efficiently manage and sample elements based on their weights. The structure includes fields to track the total and unremoved counts and weights of elements, as well as the internal node count and height of the tree. It also supports a 'poisoned mode' for handling special sampling conditions and includes a mechanism for restoring the tree to its original state if needed. The structure is aligned to 64 bytes for performance optimization, and it uses a custom random number generator for sampling operations.


---
### fd\_wsample\_t
- **Type**: `struct`
- **Members**:
    - `total_cnt`: Stores the total number of elements in the sample.
    - `total_weight`: Stores the total weight of all elements in the sample.
    - `unremoved_cnt`: Tracks the number of elements that have not been removed.
    - `unremoved_weight`: Tracks the total weight of elements that have not been removed.
    - `internal_node_cnt`: Stores the count of internal nodes in the tree structure.
    - `poisoned_weight`: Stores the weight used when the sampler is in poisoned mode.
    - `height`: Represents the height of the tree structure.
    - `restore_enabled`: Indicates if the restore feature is enabled.
    - `poisoned_mode`: Indicates if the sampler is in poisoned mode.
    - `rng`: Pointer to a random number generator used for sampling.
    - `dummy`: A dummy tree element used for safe out-of-bounds reads.
    - `tree`: An array of tree elements representing the sampling tree structure.
- **Description**: The `fd_wsample_t` structure is a private data structure used for weighted sampling without replacement. It implements a high-performance sampling algorithm using a tree-like structure similar to a B-tree, optimized for branchless search and efficient updates. The structure maintains information about the total and unremoved counts and weights of elements, as well as the internal state of the sampling process, including the height of the tree and whether the sampler is in a poisoned mode. It also includes a pointer to a random number generator for sampling operations and supports restoring the tree to its initial state if enabled.


---
### idxw\_pair\_t
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing an index within a specified range.
    - `weight`: An unsigned long integer representing the weight associated with the index.
- **Description**: The `idxw_pair_t` structure is a simple data structure used to pair an index with a corresponding weight. It is typically used in contexts where elements are associated with weights, such as in weighted sampling algorithms. The `idx` field represents the position or identifier of an element, while the `weight` field indicates the significance or frequency of that element. This structure is particularly useful in algorithms that require efficient access and manipulation of weighted elements, such as sampling without replacement.


# Functions

---
### fd\_wsample\_align<!-- {{#callable:fd_wsample_align}} -->
The `fd_wsample_align` function returns the alignment requirement for the `fd_wsample_t` structure, which is 64 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, indicating that it does not depend on any input parameters or external state.
    - It directly returns the unsigned long integer value `64UL`.
- **Output**: The function outputs an unsigned long integer representing the alignment requirement, which is 64.


---
### compute\_height<!-- {{#callable:compute_height}} -->
The `compute_height` function calculates the height and the number of internal nodes of a radix tree based on the number of leaf nodes.
- **Inputs**:
    - `leaf_cnt`: The number of leaf nodes in the tree.
    - `out_height`: A pointer to store the calculated height of the tree.
    - `out_internal_cnt`: A pointer to store the calculated number of internal nodes in the tree.
- **Control Flow**:
    - Check if `leaf_cnt` is greater than or equal to `UINT_MAX-2UL`; if so, return -1 indicating an error.
    - Initialize `height` to 0, `internal` to 0, and `powRh` to 1 (representing R^height).
    - Enter a loop that continues while `leaf_cnt` is greater than `powRh`.
    - In each iteration, add `powRh` to `internal`, multiply `powRh` by R, and increment `height`.
    - After the loop, store the calculated `height` in `out_height` and `internal` in `out_internal_cnt`.
    - Return 0 to indicate successful computation.
- **Output**: Returns 0 on success, or -1 if the input `leaf_cnt` is too large.


---
### fd\_wsample\_footprint<!-- {{#callable:fd_wsample_footprint}} -->
The `fd_wsample_footprint` function calculates the memory footprint required for a weighted sampling structure based on the number of elements and whether restoration is enabled.
- **Inputs**:
    - `ele_cnt`: The number of elements in the weighted sampling structure.
    - `restore_enabled`: A flag indicating whether restoration of the original state is enabled (1 for enabled, 0 for disabled).
- **Control Flow**:
    - Declare variables `height` and `internal_cnt` to store the height of the tree and the count of internal nodes, respectively.
    - Call [`compute_height`](#compute_height) with `ele_cnt` to calculate the height and internal node count; if it fails, return 0.
    - Calculate the memory footprint using the size of `fd_wsample_t` and the size of the tree elements, considering whether restoration is enabled.
    - Return the calculated memory footprint.
- **Output**: The function returns the calculated memory footprint as an unsigned long integer, or 0 if the height computation fails.
- **Functions called**:
    - [`compute_height`](#compute_height)


---
### fd\_wsample\_join<!-- {{#callable:fd_wsample_join}} -->
The `fd_wsample_join` function checks if a given shared memory pointer is non-null and properly aligned, and if so, casts and returns it as a `fd_wsample_t` pointer.
- **Inputs**:
    - `shmem`: A pointer to shared memory that is expected to be aligned and non-null.
- **Control Flow**:
    - Check if the `shmem` pointer is null; if so, log a warning and return NULL.
    - Check if the `shmem` pointer is aligned according to [`fd_wsample_align`](#fd_wsample_align); if not, log a warning and return NULL.
    - If both checks pass, cast the `shmem` pointer to a `fd_wsample_t` pointer and return it.
- **Output**: Returns a `fd_wsample_t` pointer if the input is valid, otherwise returns NULL.
- **Functions called**:
    - [`fd_wsample_align`](#fd_wsample_align)


---
### seed\_recursive<!-- {{#callable:seed_recursive}} -->
The `seed_recursive` function recursively assigns priority values to elements in a treap data structure based on a modified binary search rule using geometric mean.
- **Inputs**:
    - `pool`: A pointer to an array of `treap_ele_t` structures where priority values will be assigned.
    - `lo`: The lower bound index for the current recursive call.
    - `hi`: The upper bound index for the current recursive call.
    - `prio`: The priority value to be assigned to the current element in the treap.
- **Control Flow**:
    - Calculate the midpoint `mid` using the geometric mean of `lo` and `hi`, adjusted by 0.5 for rounding.
    - Check if `mid` is strictly between `lo` and `hi`.
    - If true, assign the priority `prio` to the element at index `mid-1` in the `pool`.
    - Recursively call `seed_recursive` for the left subrange `[lo, mid)` with decremented priority `prio-1`.
    - Recursively call `seed_recursive` for the right subrange `[mid, hi)` with decremented priority `prio-1`.
- **Output**: The function does not return a value; it modifies the `pool` array in place by setting priority values.


---
### fd\_wsample\_new\_init<!-- {{#callable:fd_wsample_new_init}} -->
The `fd_wsample_new_init` function initializes a weighted sampling structure in shared memory, setting up its internal state and parameters.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the sampling structure will be initialized.
    - `rng`: A pointer to a random number generator of type `fd_chacha20rng_t` used for sampling operations.
    - `ele_cnt`: The number of elements that the sampling structure will manage.
    - `restore_enabled`: An integer flag indicating whether the restore functionality is enabled (non-zero) or not (zero).
    - `opt_hint`: An optional hint parameter, currently unused in the function.
- **Control Flow**:
    - Check if `shmem` is NULL and log a warning if so, returning NULL.
    - Check if `shmem` is properly aligned using `fd_wsample_align()` and log a warning if not, returning NULL.
    - Compute the height and internal node count of the sampling tree using `compute_height()` based on `ele_cnt`; log a warning and return NULL if computation fails.
    - Cast `shmem` to a `fd_wsample_t` pointer and initialize its fields, including setting weights to zero, configuring the tree height, and setting the random number generator.
    - Initialize the tree structure in memory to zero using `fd_memset()`.
    - Return the `shmem` pointer as the initialized sampling structure.
- **Output**: Returns a pointer to the initialized sampling structure in shared memory, or NULL if initialization fails due to invalid inputs or alignment issues.
- **Functions called**:
    - [`fd_wsample_align`](#fd_wsample_align)
    - [`compute_height`](#compute_height)


---
### fd\_wsample\_new\_add<!-- {{#callable:fd_wsample_new_add}} -->
The `fd_wsample_new_add` function adds a new weighted element to a weighted sampling structure, updating the internal tree structure to reflect the new weight.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the weighted sampling structure (`fd_wsample_t`) is stored.
    - `weight`: The weight of the new element to be added to the sampling structure.
- **Control Flow**:
    - The function begins by casting the `shmem` pointer to a `fd_wsample_t` pointer named `sampler`.
    - It checks if `sampler` is NULL, returning NULL if true, indicating an error.
    - It checks if the `weight` is zero, logging a warning and returning NULL if true, as zero weight is not allowed.
    - It checks for potential overflow by ensuring that adding `weight` to `sampler->total_weight` does not wrap around, logging a warning and returning NULL if it would.
    - The function calculates the index `i` for the new element based on `sampler->internal_node_cnt` and `sampler->unremoved_cnt`.
    - It iterates over the height of the tree, updating the `left_sum` values of the parent nodes to include the new weight.
    - The `unremoved_cnt`, `total_cnt`, `unremoved_weight`, and `total_weight` of the sampler are incremented by one and the new weight, respectively.
    - Finally, the function returns the `shmem` pointer, indicating successful addition.
- **Output**: The function returns the `shmem` pointer if the addition is successful, or NULL if an error occurs.


---
### fd\_wsample\_new\_fini<!-- {{#callable:fd_wsample_new_fini}} -->
The `fd_wsample_new_fini` function finalizes the initialization of a weighted sampling structure by setting a poisoned weight and optionally copying the tree structure for fast restoration.
- **Inputs**:
    - `shmem`: A pointer to shared memory where the weighted sampler structure (`fd_wsample_t`) is stored.
    - `poisoned_weight`: An unsigned long integer representing the weight to be added as 'poisoned' weight, which is used to handle overflow scenarios.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_wsample_t` pointer named `sampler`.
    - Check if `sampler` is NULL using `FD_UNLIKELY`; if so, return NULL.
    - Check if adding `poisoned_weight` to `sampler->total_weight` causes an overflow; if so, log a warning and return NULL.
    - Set `sampler->poisoned_weight` to `poisoned_weight`.
    - If `sampler->restore_enabled` is true, copy the current tree structure to a backup location in memory to facilitate fast restoration.
    - Return the `sampler` pointer cast back to a `void *`.
- **Output**: Returns a pointer to the initialized `fd_wsample_t` structure, or NULL if an error occurs.


---
### fd\_wsample\_leave<!-- {{#callable:fd_wsample_leave}} -->
The `fd_wsample_leave` function checks if the provided sampler is non-null and returns it cast to a void pointer, or logs a warning and returns NULL if it is null.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure, representing the sampler to be checked and returned.
- **Control Flow**:
    - Check if the `sampler` is NULL using `FD_UNLIKELY`; if it is, log a warning message 'NULL sampler' and return NULL.
    - If the `sampler` is not NULL, cast it to a void pointer and return it.
- **Output**: Returns the `sampler` cast to a void pointer if it is non-null, otherwise returns NULL.


---
### fd\_wsample\_delete<!-- {{#callable:fd_wsample_delete}} -->
The `fd_wsample_delete` function checks if a given memory pointer is non-null and properly aligned, logging warnings if not, and returns the pointer if both conditions are met.
- **Inputs**:
    - `shmem`: A pointer to the shared memory that is to be checked and potentially returned.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL using `FD_UNLIKELY`; if true, log a warning and return NULL.
    - Check if the `shmem` pointer is aligned according to `fd_wsample_align()` using `FD_UNLIKELY`; if not, log a warning and return NULL.
    - If both checks pass, return the `shmem` pointer.
- **Output**: Returns the `shmem` pointer if it is non-null and properly aligned; otherwise, returns NULL.
- **Functions called**:
    - [`fd_wsample_align`](#fd_wsample_align)


---
### fd\_wsample\_get\_rng<!-- {{#callable:fd_wsample_get_rng}} -->
The `fd_wsample_get_rng` function retrieves the random number generator associated with a given weighted sampler.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure, which represents a weighted sampler.
- **Control Flow**:
    - The function takes a single argument, `sampler`, which is a pointer to an `fd_wsample_t` structure.
    - It directly accesses the `rng` field of the `sampler` structure and returns it.
- **Output**: A pointer to an `fd_chacha20rng_t` structure, which is the random number generator associated with the given sampler.


---
### fd\_wsample\_seed\_rng<!-- {{#callable:fd_wsample_seed_rng}} -->
The `fd_wsample_seed_rng` function initializes a ChaCha20 random number generator with a given seed.
- **Inputs**:
    - `rng`: A pointer to an `fd_chacha20rng_t` structure representing the random number generator to be initialized.
    - `seed`: An array of 32 unsigned characters (`uchar`) that provides the seed for initializing the random number generator.
- **Control Flow**:
    - The function calls `fd_chacha20rng_init` with the provided `rng` and `seed` as arguments.
    - There are no conditional statements or loops; the function simply delegates the initialization to `fd_chacha20rng_init`.
- **Output**: The function does not return any value; it performs the initialization in-place on the `rng` object.


---
### fd\_wsample\_restore\_all<!-- {{#callable:fd_wsample_restore_all}} -->
The `fd_wsample_restore_all` function restores a sampler to its initial state by resetting its weights and counts and copying the original tree structure back into place if restoration is enabled.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure representing the sampler to be restored.
- **Control Flow**:
    - Check if the `restore_enabled` flag in the sampler is set; if not, return NULL.
    - Reset the `unremoved_weight` to `total_weight` and `unremoved_cnt` to `total_cnt`.
    - Set `poisoned_mode` to 0, indicating the sampler is not in a poisoned state.
    - Copy the original tree structure from the backup location back to the active tree using `fd_memcpy`.
    - Return the pointer to the restored sampler.
- **Output**: Returns a pointer to the restored `fd_wsample_t` sampler, or NULL if restoration is not enabled.


---
### fd\_wsample\_map\_sample\_i<!-- {{#callable:fd_wsample_map_sample_i}} -->
The `fd_wsample_map_sample_i` function performs a weighted sampling operation on a tree structure, returning the index and weight of the sampled element based on a given query value.
- **Inputs**:
    - `sampler`: A pointer to a `fd_wsample_t` structure, which contains the tree and other metadata for the sampling operation.
    - `query`: An unsigned long integer representing the query value, which should be in the range [0, unremoved_weight) of the sampler.
- **Control Flow**:
    - Initialize the cursor to 0 and set S to the unremoved weight of the sampler.
    - Iterate over the height of the sampler's tree, performing the following steps for each level:
    - Access the current tree element using the cursor.
    - Determine the child index by comparing the query value against the left sums of the current tree element.
    - Adjust the query value by subtracting the left sum of the previous child index.
    - Update S to the difference between the current and previous left sums.
    - Update the cursor to point to the next node in the tree based on the child index.
    - After traversing the tree, calculate the index by subtracting the internal node count from the cursor.
    - Return an `idxw_pair_t` structure containing the calculated index and the final weight S.
- **Output**: An `idxw_pair_t` structure containing the index and weight of the sampled element.


---
### fd\_wsample\_map\_sample<!-- {{#callable:fd_wsample_map_sample}} -->
The `fd_wsample_map_sample` function retrieves the index of a sampled element from a weighted sample tree based on a given query value.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure representing the weighted sample tree.
    - `query`: An unsigned long integer representing the query value used to sample from the tree.
- **Control Flow**:
    - The function calls [`fd_wsample_map_sample_i`](#fd_wsample_map_sample_i) with the `sampler` and `query` as arguments.
    - [`fd_wsample_map_sample_i`](#fd_wsample_map_sample_i) performs the sampling operation and returns an `idxw_pair_t` structure containing the index and weight of the sampled element.
    - The function extracts the `idx` field from the returned `idxw_pair_t` structure.
    - The function returns the extracted index.
- **Output**: The function returns an unsigned long integer representing the index of the sampled element in the weighted sample tree.
- **Functions called**:
    - [`fd_wsample_map_sample_i`](#fd_wsample_map_sample_i)


---
### fd\_wsample\_remove<!-- {{#callable:fd_wsample_remove}} -->
The `fd_wsample_remove` function removes a specified element from a weighted sampling tree, updating the tree's internal structure and the sampler's metadata accordingly.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure representing the weighted sampling tree from which an element is to be removed.
    - `to_remove`: An `idxw_pair_t` structure containing the index and weight of the element to be removed from the sampling tree.
- **Control Flow**:
    - Calculate the initial cursor position by adding the index of the element to be removed to the internal node count of the sampler.
    - Iterate over the height of the sampler's tree, updating the left sums of the parent nodes to reflect the removal of the element's weight.
    - For each level, calculate the parent node and the child index within the parent node.
    - Depending on the compilation flags and architecture, use different methods to update the left sums, either using AVX512 instructions or a branchless subtraction loop.
    - After updating the tree structure, move the cursor to the parent node and repeat until the root is reached.
    - Decrement the `unremoved_cnt` and `unremoved_weight` of the sampler to reflect the removal of the element.
- **Output**: The function does not return a value; it modifies the sampler's tree and metadata in place.


---
### fd\_wsample\_find\_weight<!-- {{#callable:fd_wsample_find_weight}} -->
The `fd_wsample_find_weight` function calculates the weight of a specific element in a weighted sampling tree without explicitly storing the weights.
- **Inputs**:
    - `sampler`: A pointer to a `fd_wsample_t` structure representing the weighted sampling tree.
    - `idx`: An unsigned long integer representing the index of the element whose weight is to be found, within the range [0, total_cnt).
- **Control Flow**:
    - Initialize a pointer to the tree structure and set the cursor to the index plus the internal node count.
    - Initialize `lm1` to 0 and `li` to the unremoved weight of the sampler.
    - Iterate over the height of the tree, calculating the parent and child index for the current cursor position.
    - If the child index is less than R-1, calculate the weight using the left sum of the parent node and break the loop.
    - If the child index is R-1, update `lm1` with the left sum of the parent node and continue up the tree by setting the cursor to the parent.
- **Output**: Returns the calculated weight of the element at the specified index as an unsigned long integer.


---
### fd\_wsample\_remove\_idx<!-- {{#callable:fd_wsample_remove_idx}} -->
The `fd_wsample_remove_idx` function removes an element from a weighted sample structure by its index.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure representing the weighted sample from which an element is to be removed.
    - `idx`: An unsigned long integer representing the index of the element to be removed from the sample.
- **Control Flow**:
    - Call [`fd_wsample_find_weight`](#fd_wsample_find_weight) to determine the weight of the element at the specified index in the sampler.
    - Create an `idxw_pair_t` structure `r` with the index and weight of the element to be removed.
    - Call [`fd_wsample_remove`](#fd_wsample_remove) with the sampler and the `idxw_pair_t` structure `r` to remove the element from the sampler.
- **Output**: This function does not return a value; it modifies the sampler in place by removing the specified element.
- **Functions called**:
    - [`fd_wsample_find_weight`](#fd_wsample_find_weight)
    - [`fd_wsample_remove`](#fd_wsample_remove)


---
### fd\_wsample\_sample\_many<!-- {{#callable:fd_wsample_sample_many}} -->
The `fd_wsample_sample_many` function samples multiple indices from a weighted sampler and stores them in an array.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure representing the weighted sampler from which samples are drawn.
    - `idxs`: A pointer to an array of unsigned long integers where the sampled indices will be stored.
    - `cnt`: An unsigned long integer representing the number of samples to draw.
- **Control Flow**:
    - The function iterates over a loop `cnt` times.
    - In each iteration, it calls [`fd_wsample_sample`](#fd_wsample_sample) with the `sampler` to get a sampled index.
    - The sampled index is stored in the `idxs` array at the current loop index.
- **Output**: The function does not return a value; it modifies the `idxs` array in place to store the sampled indices.
- **Functions called**:
    - [`fd_wsample_sample`](#fd_wsample_sample)


---
### fd\_wsample\_sample\_and\_remove\_many<!-- {{#callable:fd_wsample_sample_and_remove_many}} -->
The `fd_wsample_sample_and_remove_many` function samples and removes multiple elements from a weighted sampler, storing the indices of the sampled elements in the provided array.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure representing the weighted sampler from which elements are sampled and removed.
    - `idxs`: A pointer to an array of `ulong` where the indices of the sampled elements will be stored.
    - `cnt`: An `ulong` representing the number of elements to sample and remove.
- **Control Flow**:
    - The function iterates over a loop `cnt` times to sample and remove elements.
    - For each iteration, it first checks if `sampler->unremoved_weight` is zero, indicating no elements are left to sample, and sets the corresponding index in `idxs` to `FD_WSAMPLE_EMPTY`.
    - It then checks if `sampler->poisoned_mode` is active, setting the index to `FD_WSAMPLE_INDETERMINATE` if true.
    - A random number `unif` is generated using `fd_chacha20rng_ulong_roll` within the range of the total weight (unremoved plus poisoned).
    - If `unif` is greater than or equal to `sampler->unremoved_weight`, the index is set to `FD_WSAMPLE_INDETERMINATE`, and `sampler->poisoned_mode` is activated.
    - Otherwise, the function maps the random number to an index using [`fd_wsample_map_sample_i`](#fd_wsample_map_sample_i), removes the sampled element with [`fd_wsample_remove`](#fd_wsample_remove), and stores the index in `idxs`.
- **Output**: The function does not return a value; it modifies the `idxs` array in place to store the indices of the sampled elements.
- **Functions called**:
    - [`fd_wsample_map_sample_i`](#fd_wsample_map_sample_i)
    - [`fd_wsample_remove`](#fd_wsample_remove)


---
### fd\_wsample\_sample<!-- {{#callable:fd_wsample_sample}} -->
The `fd_wsample_sample` function samples an index from a weighted sampler, ensuring the sampler is not empty or poisoned, and returns an indeterminate value if conditions are not met.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure representing the weighted sampler from which an index is to be sampled.
- **Control Flow**:
    - Check if the sampler's `unremoved_weight` is zero; if true, return `FD_WSAMPLE_EMPTY`.
    - Check if the sampler is in `poisoned_mode`; if true, return `FD_WSAMPLE_INDETERMINATE`.
    - Generate a random number `unif` using `fd_chacha20rng_ulong_roll` with the sampler's RNG and the sum of `unremoved_weight` and `poisoned_weight`.
    - Check if `unif` is greater than or equal to `unremoved_weight`; if true, return `FD_WSAMPLE_INDETERMINATE`.
    - Call [`fd_wsample_map_sample`](#fd_wsample_map_sample) with the sampler and `unif` to map the random number to an index, and return the result.
- **Output**: Returns an `ulong` representing the sampled index from the sampler, or a special value indicating an empty or indeterminate state.
- **Functions called**:
    - [`fd_wsample_map_sample`](#fd_wsample_map_sample)


---
### fd\_wsample\_sample\_and\_remove<!-- {{#callable:fd_wsample_sample_and_remove}} -->
The `fd_wsample_sample_and_remove` function samples an index from a weighted sampler and removes the sampled element, returning the index of the sampled element.
- **Inputs**:
    - `sampler`: A pointer to an `fd_wsample_t` structure representing the weighted sampler from which an element is to be sampled and removed.
- **Control Flow**:
    - Check if `sampler->unremoved_weight` is zero; if so, return `FD_WSAMPLE_EMPTY`.
    - Check if `sampler->poisoned_mode` is set; if so, return `FD_WSAMPLE_INDETERMINATE`.
    - Generate a random number `unif` using `fd_chacha20rng_ulong_roll` with the range of `sampler->unremoved_weight + sampler->poisoned_weight`.
    - If `unif` is greater than or equal to `sampler->unremoved_weight`, set `sampler->poisoned_mode` to 1 and return `FD_WSAMPLE_INDETERMINATE`.
    - Use [`fd_wsample_map_sample_i`](#fd_wsample_map_sample_i) to map the random number `unif` to an index-weight pair `p`.
    - Call [`fd_wsample_remove`](#fd_wsample_remove) to remove the sampled element from the sampler using the index-weight pair `p`.
    - Return the index `p.idx` of the sampled element.
- **Output**: The function returns an `ulong` representing the index of the sampled element, or special values `FD_WSAMPLE_EMPTY` or `FD_WSAMPLE_INDETERMINATE` if the sampler is empty or in a poisoned state, respectively.
- **Functions called**:
    - [`fd_wsample_map_sample_i`](#fd_wsample_map_sample_i)
    - [`fd_wsample_remove`](#fd_wsample_remove)


