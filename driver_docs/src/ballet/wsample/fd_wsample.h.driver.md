# Purpose
This C header file defines a set of functions and macros for creating and managing a weighted random sampling system, specifically tailored for use in the Solana blockchain's leader schedule and Turbine tree. The primary functionality revolves around generating weighted random samples using the ChaCha20 random number generator, which is seeded with a 32-byte seed. The sampling process involves selecting a random integer within a specified range and determining the corresponding index based on cumulative stake weights. This system is designed to handle both sampling with and without replacement, and it provides mechanisms for initializing, adding weights, finalizing, and managing the memory footprint of the sampler.

The file includes several key components: macros for alignment and footprint calculations, functions for initializing and finalizing the sampler, and methods for sampling and managing the sampled elements. It also defines hints for optimizing the sampling process based on the distribution of weights and the sampling method (with or without replacement). The header file is intended to be included in other C source files, providing a public API for creating and using weighted samplers. It facilitates efficient memory management and supports the restoration of removed elements, enhancing its utility in dynamic environments like Solana's network operations.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `../chacha20/fd_chacha20rng.h`


# Global Variables

---
### fd\_wsample\_join
- **Type**: `function pointer`
- **Description**: `fd_wsample_join` is a function that takes a pointer to a shared memory region and returns a pointer to a `fd_wsample_t` structure. This function is used to join a memory region that has been formatted as a weighted sampler.
- **Use**: This function is used to cast a shared memory region into a `fd_wsample_t` pointer, allowing operations on the weighted sampler.


---
### fd\_wsample\_leave
- **Type**: `function pointer`
- **Description**: `fd_wsample_leave` is a function pointer that takes a pointer to a `fd_wsample_t` structure as an argument and returns a `void *`. It is part of the API for managing memory regions formatted as weighted samplers.
- **Use**: This function is used to leave or unjoin a memory region that has been formatted as a weighted sampler, effectively casting the sampler back to a generic memory pointer.


---
### fd\_wsample\_delete
- **Type**: `function pointer`
- **Description**: `fd_wsample_delete` is a function pointer that points to a function designed to unformat a memory region used as a weighted sampler. This function releases all interest in the random number generator (rng) associated with the sampler.
- **Use**: This function is used to clean up and release resources associated with a weighted sampler, specifically by unformatting the memory region and disassociating it from the rng.


---
### fd\_wsample\_new\_init
- **Type**: `function pointer`
- **Description**: `fd_wsample_new_init` is a function that initializes a memory region to be used as a weighted sampler. It takes parameters such as a pointer to the memory region, a ChaCha20 RNG struct, the number of elements, a flag for restore capability, and an optional hint for weight distribution.
- **Use**: This function is used to begin the process of formatting a memory region for weighted sampling, which is part of a multi-step initialization process.


---
### fd\_wsample\_new\_add
- **Type**: `function pointer`
- **Description**: `fd_wsample_new_add` is a function that adds a weight to a partially formatted memory region used for weighted sampling. The function takes a pointer to a shared memory region (`shmem`) and a positive weight (`weight`) as its parameters.
- **Use**: This function is used during the initialization process of a weighted sampler to incrementally add weights to the memory region, ensuring the cumulative sum of weights does not exceed `ULONG_MAX`.


---
### fd\_wsample\_new\_fini
- **Type**: `function pointer`
- **Description**: `fd_wsample_new_fini` is a function that finalizes the formatting of a partially constructed memory region to be used as a weighted sampler. It takes a pointer to the memory region (`shmem`) and a `poisoned_weight` parameter, which represents an indeterminate number of unknown elements with a total weight equal to `poisoned_weight`. This function is part of a multi-step process to prepare a memory region for weighted sampling.
- **Use**: This function is used to complete the setup of a memory region for weighted sampling, ensuring it is ready for use in sampling operations.


---
### fd\_wsample\_get\_rng
- **Type**: `function pointer`
- **Description**: The `fd_wsample_get_rng` is a function that returns a pointer to a `fd_chacha20rng_t` structure. This structure represents a ChaCha20 random number generator used in the context of weighted sampling.
- **Use**: This function is used to retrieve the random number generator associated with a given weighted sampler.


---
### fd\_wsample\_restore\_all
- **Type**: `function pointer`
- **Description**: The `fd_wsample_restore_all` is a function that restores all elements that have been removed from a weighted sampler, returning them to their original weight. This function is part of a system for generating weighted random samples, specifically used in contexts like Solana's leader schedule and Turbine tree. It is designed to be more efficient than recreating the sampler from scratch, provided the sampler was initialized with restoration enabled.
- **Use**: This function is used to reset the state of a weighted sampler by restoring all previously removed elements to their original weights.


# Data Structures

---
### fd\_wsample\_t
- **Type**: `typedef struct fd_wsample_private fd_wsample_t;`
- **Members**:
    - `fd_wsample_private`: An opaque structure used internally to implement the weighted sampling functionality.
- **Description**: The `fd_wsample_t` is a typedef for an opaque structure `fd_wsample_private`, which is used to implement a weighted sampling mechanism. This data structure is designed to facilitate the generation of weighted random samples, particularly for applications like Solana's leader schedule and Turbine tree. The structure is aligned and has a footprint that depends on the number of elements and whether restoration is enabled. It supports operations such as initialization, adding weights, finalizing, sampling with or without replacement, and restoring removed elements. The structure relies on an external ChaCha20 random number generator for randomness, allowing for shared RNG usage across multiple samplers.


# Function Declarations (Public API)

---
### fd\_wsample\_align<!-- {{#callable_declaration:fd_wsample_align}} -->
Returns the alignment requirement for a weighted sampler.
- **Description**: Use this function to obtain the alignment requirement for creating a weighted sampler. This alignment value is necessary when allocating memory for a sampler to ensure proper memory access and performance. It is a constant value and does not depend on any input parameters or state.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is 64.
- **See also**: [`fd_wsample_align`](fd_wsample.c.driver.md#fd_wsample_align)  (Implementation)


---
### fd\_wsample\_footprint<!-- {{#callable_declaration:fd_wsample_footprint}} -->
Calculate the memory footprint required for a weighted sampler.
- **Description**: This function computes the memory footprint necessary to create a weighted sampler capable of handling up to `ele_cnt` stake weights. It should be used when planning memory allocation for a sampler, especially when considering whether restoration of removed elements is needed. The function requires the number of elements and a flag indicating if restoration is enabled. It returns zero if the computation of internal parameters fails, indicating an invalid input or an error in the calculation process.
- **Inputs**:
    - `ele_cnt`: The number of elements that the sampler will handle. It must be a non-negative value and less than UINT_MAX-2. Invalid values will result in a return value of zero.
    - `restore_enabled`: A flag indicating whether the sampler should support restoration of removed elements. A non-zero value enables restoration, while zero disables it, reducing the required footprint.
- **Output**: The function returns the size in bytes of the memory footprint required for the sampler. If the computation fails, it returns zero.
- **See also**: [`fd_wsample_footprint`](fd_wsample.c.driver.md#fd_wsample_footprint)  (Implementation)


---
### fd\_wsample\_join<!-- {{#callable_declaration:fd_wsample_join}} -->
Joins a memory region formatted as a weighted sampler.
- **Description**: Use this function to join a memory region that has been formatted as a weighted sampler, allowing you to interact with it as an `fd_wsample_t` object. This function should be called after the memory region has been properly initialized and formatted using the appropriate setup functions. The memory region must be aligned according to the requirements of `fd_wsample_align()`. If the provided memory pointer is null or misaligned, the function will return null and log a warning.
- **Inputs**:
    - `shmem`: A pointer to the memory region to join. Must not be null and must be aligned according to `fd_wsample_align()`. If null or misaligned, the function returns null.
- **Output**: Returns a pointer to `fd_wsample_t` if successful, or null if the input is invalid.
- **See also**: [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)  (Implementation)


---
### fd\_wsample\_leave<!-- {{#callable_declaration:fd_wsample_leave}} -->
Leaves a memory region formatted as a weighted sampler.
- **Description**: Use this function to leave a memory region that has been formatted as a weighted sampler. It is typically called after operations on the sampler are complete and you wish to release any association with the sampler. This function should be called with a valid sampler pointer that was previously joined. If the sampler pointer is NULL, the function will log a warning and return NULL, indicating that no action was taken.
- **Inputs**:
    - `sampler`: A pointer to a `fd_wsample_t` structure representing the weighted sampler to leave. Must not be NULL; if NULL, a warning is logged and NULL is returned.
- **Output**: Returns a void pointer to the sampler if successful, or NULL if the sampler is NULL.
- **See also**: [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)  (Implementation)


---
### fd\_wsample\_delete<!-- {{#callable_declaration:fd_wsample_delete}} -->
Unformats a memory region used as a weighted sampler.
- **Description**: Use this function to release a memory region that was previously formatted as a weighted sampler. It should be called when the memory region is no longer needed for sampling operations. The function checks if the provided memory pointer is non-null and properly aligned according to the required alignment for weighted samplers. If these conditions are not met, it logs a warning and returns NULL. This function does not deallocate the memory; it simply indicates that the region is no longer formatted for use as a sampler.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be unformatted. Must not be null and must be aligned according to the alignment requirements of a weighted sampler. If these conditions are not met, the function logs a warning and returns NULL. The caller retains ownership of the memory.
- **Output**: Returns the input pointer if the memory region is valid and properly aligned; otherwise, returns NULL.
- **See also**: [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)  (Implementation)


---
### fd\_wsample\_new\_init<!-- {{#callable_declaration:fd_wsample_new_init}} -->
Initialize a memory region for a weighted sampler.
- **Description**: This function begins the process of formatting a memory region to be used as a weighted sampler, which is part of a multi-step initialization process. It should be called first, followed by calls to add weights and finalize the setup. The function requires a pointer to a memory region, which must be properly aligned and have sufficient footprint as determined by the alignment and footprint functions. A ChaCha20 RNG must be provided for generating random numbers, and the number of elements to be sampled must be specified. The restore feature can be enabled or disabled, affecting the memory footprint. An optional hint can be provided to optimize performance based on the expected distribution of weights and sampling style. The function returns the memory region pointer on success or NULL on failure, such as when the memory is misaligned or the element count is invalid.
- **Inputs**:
    - `shmem`: A pointer to the first byte of the memory region to be formatted. Must not be null and must be aligned according to fd_wsample_align(). The caller retains ownership.
    - `rng`: A pointer to a ChaCha20 RNG structure that must be locally joined. The sampler will use this RNG for generating random numbers. The caller retains ownership.
    - `ele_cnt`: The number of elements that can be sampled from. Must be less than UINT_MAX. Invalid values will result in a NULL return.
    - `restore_enabled`: An integer flag indicating whether the restore feature is enabled. If set to 0, the restore feature is disabled, reducing the required memory footprint.
    - `opt_hint`: An integer hint specifying the expected distribution of weights and sampling style. Must be one of the FD_WSAMPLE_HINT_* constants. This affects performance but not correctness.
- **Output**: Returns the pointer to the memory region on success, or NULL on failure.
- **See also**: [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)  (Implementation)


---
### fd\_wsample\_new\_add<!-- {{#callable_declaration:fd_wsample_new_add}} -->
Adds a weight to a partially formatted memory region for weighted sampling.
- **Description**: Use this function to add a weight to a memory region that is being formatted for use as a weighted sampler. This function should be called after initializing the memory region with `fd_wsample_new_init` and before finalizing it with `fd_wsample_new_fini`. The memory region must be partially constructed, and the weight must be strictly positive. The cumulative sum of all weights, including the new weight, must not exceed `ULONG_MAX`. If the function encounters a zero weight or an overflow in total weight, it will return `NULL` and log a warning.
- **Inputs**:
    - `shmem`: A pointer to a partially constructed memory region, as returned by `fd_wsample_new_init` or a previous call to `fd_wsample_new_add`. Must not be `NULL`.
    - `weight`: A strictly positive unsigned long integer representing the weight to add. The cumulative sum of this weight and all other weights must not exceed `ULONG_MAX`.
- **Output**: Returns the `shmem` pointer on success, or `NULL` if the input is invalid or an error occurs.
- **See also**: [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)  (Implementation)


---
### fd\_wsample\_new\_fini<!-- {{#callable_declaration:fd_wsample_new_fini}} -->
Finalize the formatting of a weighted sampler memory region.
- **Description**: Use this function to complete the setup of a memory region intended for use as a weighted sampler. It should be called after initializing the memory region with `fd_wsample_new_init` and adding weights with `fd_wsample_new_add`. The function ensures that the memory region is properly formatted and ready for sampling operations. If a `poisoned_weight` is specified, it adds a poisoned region to the sampler, which can be useful for managing long tails in the weight distribution. The function returns the memory region on success or `NULL` if an error occurs, such as a weight overflow. Ensure that the cumulative weight, including the poisoned weight, does not exceed `ULONG_MAX`.
- **Inputs**:
    - `shmem`: A pointer to the memory region being formatted as a weighted sampler. It must be a partially constructed region, as returned by `fd_wsample_new_add_weight` or `fd_wsample_new_init`. Passing `NULL` will result in a `NULL` return.
    - `poisoned_weight`: An unsigned long representing the weight of a poisoned region to be added to the sampler. It can be zero if no poisoned region is desired. The sum of all weights and this value must not exceed `ULONG_MAX`.
- **Output**: Returns a pointer to the formatted memory region on success, or `NULL` if an error occurs, such as a weight overflow or if `shmem` is `NULL`.
- **See also**: [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)  (Implementation)


---
### fd\_wsample\_get\_rng<!-- {{#callable_declaration:fd_wsample_get_rng}} -->
Retrieve the RNG associated with a weighted sampler.
- **Description**: Use this function to access the ChaCha20 RNG that was provided during the initialization of a weighted sampler. This is useful when you need to perform operations that require the same RNG instance used by the sampler. Ensure that the sampler has been properly initialized and joined before calling this function. The function does not modify the sampler or the RNG.
- **Inputs**:
    - `sampler`: A pointer to an initialized and joined `fd_wsample_t` instance. Must not be null. If the sampler is not properly initialized, the behavior is undefined.
- **Output**: Returns a pointer to the `fd_chacha20rng_t` instance associated with the given sampler.
- **See also**: [`fd_wsample_get_rng`](fd_wsample.c.driver.md#fd_wsample_get_rng)  (Implementation)


---
### fd\_wsample\_seed\_rng<!-- {{#callable_declaration:fd_wsample_seed_rng}} -->
Seed the ChaCha20 RNG with a 32-byte seed.
- **Description**: Use this function to initialize the ChaCha20 random number generator with a specific 32-byte seed, preparing it for generating random numbers. This is particularly useful in scenarios where deterministic random number generation is required, such as in simulations or testing environments. The function must be called before using the RNG for sampling operations to ensure the RNG is properly seeded.
- **Inputs**:
    - `rng`: A pointer to an fd_chacha20rng_t structure that represents the ChaCha20 random number generator. The caller must ensure this pointer is valid and properly allocated before calling the function.
    - `seed`: A 32-byte array used to seed the RNG. The array must be exactly 32 bytes long, and the caller is responsible for providing a valid seed. The function does not handle invalid seed sizes.
- **Output**: None
- **See also**: [`fd_wsample_seed_rng`](fd_wsample.c.driver.md#fd_wsample_seed_rng)  (Implementation)


---
### fd\_wsample\_sample<!-- {{#callable_declaration:fd_wsample_sample}} -->
Generates a weighted random sample from the sampler.
- **Description**: Use this function to obtain a weighted random sample from a previously initialized sampler. It is essential that the sampler has been properly initialized and seeded with a ChaCha20 RNG before calling this function. The function will return a special value if there are no unremoved elements left to sample or if the sample falls within a poisoned region, indicating an indeterminate result. This function is suitable for scenarios where sampling with replacement is required.
- **Inputs**:
    - `sampler`: A pointer to an initialized fd_wsample_t structure. The sampler must be properly set up and must not be null. If the sampler's unremoved weight is zero, or if it is in a poisoned mode, the function will return special values indicating these states.
- **Output**: Returns an unsigned long representing the sampled index. If no unremoved elements are available, it returns FD_WSAMPLE_EMPTY. If the sample falls in a poisoned region, it returns FD_WSAMPLE_INDETERMINATE.
- **See also**: [`fd_wsample_sample`](fd_wsample.c.driver.md#fd_wsample_sample)  (Implementation)


---
### fd\_wsample\_sample\_and\_remove<!-- {{#callable_declaration:fd_wsample_sample_and_remove}} -->
Samples and removes a weighted random element from the sampler.
- **Description**: This function is used to obtain a weighted random sample from the sampler and remove it from future sampling operations. It should be called when you need to sample without replacement from a set of elements with associated weights. The function requires that the sampler has been properly initialized and contains unremoved elements. If the sampler is empty or in a poisoned state, the function will return special values indicating these conditions. The function modifies the state of the sampler by removing the sampled element.
- **Inputs**:
    - `sampler`: A pointer to an initialized fd_wsample_t structure representing the weighted sampler. Must not be null. The sampler should have been seeded and contain unremoved elements. If the sampler is empty or in a poisoned state, the function handles these cases by returning special values.
- **Output**: Returns the index of the sampled element. If the sampler is empty, returns FD_WSAMPLE_EMPTY. If the sample lands in the poisoned region, returns FD_WSAMPLE_INDETERMINATE and sets the sampler to a poisoned state.
- **See also**: [`fd_wsample_sample_and_remove`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove)  (Implementation)


---
### fd\_wsample\_sample\_many<!-- {{#callable_declaration:fd_wsample_sample_many}} -->
Generates multiple weighted random samples from a sampler.
- **Description**: Use this function to obtain multiple weighted random samples from a given sampler, storing the results in the provided index array. This function is suitable for scenarios where sampling with replacement is desired. Ensure that the sampler's RNG is properly seeded before calling this function. The function will populate the provided index array with the sampled indices, and it is important to ensure that the index array has sufficient space to store 'cnt' samples. If the sampler has no unremoved elements, the function will store FD_WSAMPLE_EMPTY in the index array. If the RNG sample lands in the poisoned region, FD_WSAMPLE_INDETERMINATE will be stored, and subsequent calls will also store FD_WSAMPLE_INDETERMINATE until the sampler is restored.
- **Inputs**:
    - `sampler`: A pointer to an fd_wsample_t structure representing the weighted sampler. Must not be null and should be properly initialized and seeded before use.
    - `idxs`: A pointer to an array of unsigned long where the sampled indices will be stored. The array must have space for at least 'cnt' elements.
    - `cnt`: The number of samples to generate. Must be a non-negative value.
- **Output**: The function populates the 'idxs' array with sampled indices. If no valid samples can be drawn, FD_WSAMPLE_EMPTY or FD_WSAMPLE_INDETERMINATE may be stored in the array.
- **See also**: [`fd_wsample_sample_many`](fd_wsample.c.driver.md#fd_wsample_sample_many)  (Implementation)


---
### fd\_wsample\_sample\_and\_remove\_many<!-- {{#callable_declaration:fd_wsample_sample_and_remove_many}} -->
Generates and removes multiple weighted random samples from a sampler.
- **Description**: Use this function to obtain multiple weighted random samples from a sampler and remove them from future sampling, effectively sampling without replacement. This function is useful when you need to draw several samples at once and ensure they are not selected again in subsequent operations. The sampler must be properly initialized and seeded before calling this function. If the sampler has no unremoved elements, the function will store a special value indicating emptiness. If a sample lands in a poisoned region, a special indeterminate value is stored, and the sampler enters a poisoned mode, affecting future samples until restored.
- **Inputs**:
    - `sampler`: A pointer to an initialized fd_wsample_t structure representing the weighted sampler. Must not be null and should be properly seeded before use.
    - `idxs`: A pointer to an array of unsigned long where the sampled indices will be stored. The array must have at least 'cnt' elements.
    - `cnt`: The number of samples to draw and remove. Must be a non-negative value.
- **Output**: The function stores the sampled indices in the provided 'idxs' array. If no unremoved elements are available, FD_WSAMPLE_EMPTY is stored. If a sample lands in a poisoned region, FD_WSAMPLE_INDETERMINATE is stored, and the sampler enters a poisoned mode.
- **See also**: [`fd_wsample_sample_and_remove_many`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove_many)  (Implementation)


---
### fd\_wsample\_remove\_idx<!-- {{#callable_declaration:fd_wsample_remove_idx}} -->
Removes an element from the sampler by its index.
- **Description**: Use this function to remove an element from the weighted sampler as if it had been selected for sampling without replacement. This operation ensures that the specified index will not be returned by any subsequent sampling methods unless all elements are restored. It is useful for managing the state of the sampler when certain elements should be excluded from future sampling operations. The function is a no-op if the element at the given index has already been removed.
- **Inputs**:
    - `sampler`: A pointer to the fd_wsample_t structure representing the weighted sampler. Must not be null, and the sampler should be properly initialized and joined.
    - `idx`: The index of the element to remove. Must be within the range [0, ele_cnt), where ele_cnt is the number of elements in the sampler. If the index is out of range, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_wsample_remove_idx`](fd_wsample.c.driver.md#fd_wsample_remove_idx)  (Implementation)


---
### fd\_wsample\_restore\_all<!-- {{#callable_declaration:fd_wsample_restore_all}} -->
Restores all previously removed elements in the sampler.
- **Description**: Use this function to restore all elements that have been removed from the sampler using sampling functions that remove elements. This is useful when you want to reset the sampler to its original state without reconstructing it from scratch, which can be more efficient. The function should only be called if the sampler was initialized with restore functionality enabled. If the restore functionality is not enabled, the function will return NULL and no elements will be restored.
- **Inputs**:
    - `sampler`: A pointer to an fd_wsample_t structure representing the weighted sampler. The sampler must have been initialized with restore functionality enabled. If the restore functionality is not enabled, the function will return NULL.
- **Output**: Returns the sampler on success, or NULL if the restore functionality is not enabled.
- **See also**: [`fd_wsample_restore_all`](fd_wsample.c.driver.md#fd_wsample_restore_all)  (Implementation)


