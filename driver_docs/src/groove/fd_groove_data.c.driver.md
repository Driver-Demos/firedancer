# Purpose
The provided C source code file is part of a memory management system, specifically designed to handle dynamic memory allocation and deallocation using a lock-free, concurrent approach. The code defines several static inline functions and public APIs that manage superblocks and objects within a memory volume, which is a contiguous block of memory. The primary functions include [`fd_groove_data_private_active_displace`](#fd_groove_data_private_active_displace), [`fd_groove_data_private_inactive_push`](#fd_groove_data_private_inactive_push), and [`fd_groove_data_private_inactive_pop`](#fd_groove_data_private_inactive_pop), which manage the active and inactive states of superblocks. These functions ensure that memory blocks are efficiently allocated and deallocated without the need for locks, thus improving performance in multi-threaded environments.

The file also includes functions for creating, joining, leaving, and deleting memory data structures ([`fd_groove_data_new`](#fd_groove_data_new), [`fd_groove_data_join`](#fd_groove_data_join), [`fd_groove_data_leave`](#fd_groove_data_leave), and [`fd_groove_data_delete`](#fd_groove_data_delete)). These functions are responsible for initializing and managing the lifecycle of memory data structures, ensuring that they are correctly aligned and configured. Additionally, the code provides mechanisms for verifying the integrity of the memory structures ([`fd_groove_data_verify`](#fd_groove_data_verify) and [`fd_groove_data_volume_verify`](#fd_groove_data_volume_verify)), which are crucial for maintaining the correctness and reliability of the memory management system. Overall, this file is a comprehensive implementation of a lock-free memory management library, providing both internal mechanisms and public interfaces for efficient memory handling in concurrent applications.
# Imports and Dependencies

---
- `fd_groove_data.h`


# Functions

---
### fd\_groove\_data\_private\_active\_displace<!-- {{#callable:fd_groove_data_private_active_displace}} -->
The function `fd_groove_data_private_active_displace` atomically sets the active superblock offset for a given sizeclass and concurrency group, returning the previous offset.
- **Inputs**:
    - `_active_slot`: A pointer to a volatile unsigned long representing the active superblock offset for a specific sizeclass and concurrency group.
    - `volume0`: A pointer to a `fd_groove_volume_t` structure, which is not used in the function.
    - `superblock_off`: An unsigned long representing the offset of the new superblock to be set as active.
- **Control Flow**:
    - The function begins by casting `volume0` to void to indicate it is unused.
    - A memory fence is applied to ensure memory operations are completed before proceeding.
    - If atomic operations are supported (`FD_HAS_ATOMIC`), the function uses an atomic exchange to set the new superblock offset and retrieve the old one.
    - If atomic operations are not supported, it manually swaps the values of `_active_slot` and `superblock_off`.
    - Another memory fence is applied to ensure the atomic operation is completed before returning.
    - The function returns the previous value of the active superblock offset.
- **Output**: The function returns the offset of the previously active superblock as an unsigned long.


---
### fd\_groove\_data\_private\_inactive\_push<!-- {{#callable:fd_groove_data_private_inactive_push}} -->
The `fd_groove_data_private_inactive_push` function performs a lock-free atomic push of a superblock onto an inactive stack, ensuring the superblock is the top of the stack upon completion.
- **Inputs**:
    - `_inactive_stack`: A pointer to a volatile unsigned long representing the inactive stack where the superblock will be pushed.
    - `volume0`: A pointer to the base of the volume, used to calculate the address of the superblock.
    - `superblock_off`: An unsigned long representing the offset of the superblock from the base of the volume.
- **Control Flow**:
    - The function begins with a compiler memory fence to ensure memory operations are not reordered.
    - It calculates the address of the superblock by adding the offset to the base volume pointer.
    - A loop is initiated to attempt the atomic push operation until it succeeds.
    - Within the loop, the current version and next offset are extracted from the inactive stack.
    - The superblock's info field is updated with the next offset.
    - A new version is calculated by incrementing the current version.
    - An atomic compare-and-swap (CAS) operation is attempted to update the inactive stack with the new version and superblock offset.
    - If the CAS operation is successful, the loop breaks; otherwise, it pauses briefly and retries.
    - The function ends with another compiler memory fence to ensure memory operations are completed.
- **Output**: The function does not return a value; it modifies the inactive stack in place to push the superblock onto it.


---
### fd\_groove\_data\_private\_inactive\_pop<!-- {{#callable:fd_groove_data_private_inactive_pop}} -->
The function `fd_groove_data_private_inactive_pop` performs a lock-free atomic pop operation on an inactive stack, returning the offset of a superblock relative to a given volume, or zero if the stack is empty.
- **Inputs**:
    - `_inactive_stack`: A pointer to a volatile unsigned long representing the inactive stack from which a superblock is to be popped.
    - `volume0`: A pointer to the base of the volume, used to calculate the address of the superblock.
- **Control Flow**:
    - The function begins with a compiler memory fence to ensure memory operations are not reordered.
    - It enters an infinite loop to attempt the pop operation until successful.
    - Within the loop, it reads the current version and offset from the inactive stack.
    - It checks if the offset is zero, indicating the stack is empty, and breaks the loop if so.
    - If the stack is not empty, it calculates the address of the superblock using the offset and volume0.
    - It prepares the next version and offset for the stack update.
    - It attempts to atomically compare and swap the stack's value with the new version and offset using `FD_ATOMIC_CAS` if atomic operations are supported, otherwise it uses a conditional assignment.
    - If the compare-and-swap is successful, it breaks the loop; otherwise, it pauses briefly and retries.
    - The function ends with another compiler memory fence before returning the offset.
- **Output**: The function returns an unsigned long representing the offset of the superblock relative to volume0, or zero if the stack was empty.


---
### fd\_groove\_data\_new<!-- {{#callable:fd_groove_data_new}} -->
The `fd_groove_data_new` function initializes a shared memory region for groove data, ensuring proper alignment and configuration, and returns a pointer to the initialized memory.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region to be initialized as groove data.
- **Control Flow**:
    - Cast the input `shmem` to a `fd_groove_data_shmem_t` pointer named `shdata`.
    - Check if `shdata` is NULL; if so, log a warning and return NULL.
    - Check if `shdata` is properly aligned using `fd_ulong_is_aligned`; if not, log a warning and return NULL.
    - Retrieve the footprint size using [`fd_groove_data_footprint`](fd_groove_data.h.driver.md#fd_groove_data_footprint) and check if it is zero; if so, log a warning and return NULL.
    - Initialize the memory region pointed to by `shdata` to zero using `memset`.
    - Attempt to initialize the volume pool within `shdata` using `fd_groove_volume_pool_new`; if it fails, return NULL.
    - Use compiler memory fences (`FD_COMPILER_MFENCE`) to ensure memory ordering, then set the `magic` field of `shdata` to `FD_GROOVE_DATA_MAGIC`.
    - Return the original `shmem` pointer.
- **Output**: A pointer to the initialized shared memory region, or NULL if initialization fails due to invalid input or configuration.
- **Functions called**:
    - [`fd_groove_data_align`](fd_groove_data.h.driver.md#fd_groove_data_align)
    - [`fd_groove_data_footprint`](fd_groove_data.h.driver.md#fd_groove_data_footprint)


---
### fd\_groove\_data\_join<!-- {{#callable:fd_groove_data_join}} -->
The `fd_groove_data_join` function initializes and joins a local groove data structure with shared memory data, setting up volume pools and aligning necessary components.
- **Inputs**:
    - `ljoin`: A pointer to the local groove data structure to be initialized and joined.
    - `shdata`: A pointer to the shared memory groove data structure.
    - `volume0`: A pointer to the initial volume for the groove data.
    - `volume_max`: The maximum volume size, which defaults to a predefined maximum if zero.
    - `cgroup_hint`: A hint for the concurrency group to be used.
- **Control Flow**:
    - The function first ensures `volume_max` is set to a valid maximum by using a helper function if it is zero.
    - It casts the `ljoin` and `shdata` pointers to their respective types, `fd_groove_data_t` and `fd_groove_data_shmem_t`.
    - The function checks if `join` (from `ljoin`) is NULL or misaligned, logging a warning and returning NULL if so.
    - It checks if `data` (from `shdata`) is NULL, misaligned, or has an incorrect magic number, logging a warning and returning NULL if any check fails.
    - It checks if `volume0` is NULL or misaligned, logging a warning and returning NULL if so.
    - The function attempts to join the volume pool using `fd_groove_volume_pool_join`, logging details and returning NULL if it fails.
    - If all checks pass, it copies the `active_slot` and `inactive_stack` from `data` to `join`, and sets `join->cgroup_hint` to `cgroup_hint`.
    - Finally, it returns the `join` pointer.
- **Output**: Returns a pointer to the initialized and joined `fd_groove_data_t` structure, or NULL if any error occurs during the process.
- **Functions called**:
    - [`fd_groove_data_align`](fd_groove_data.h.driver.md#fd_groove_data_align)


---
### fd\_groove\_data\_leave<!-- {{#callable:fd_groove_data_leave}} -->
The `fd_groove_data_leave` function safely detaches a `fd_groove_data_t` structure from its associated volume pool, ensuring proper cleanup and logging warnings if any issues occur.
- **Inputs**:
    - `join`: A pointer to a `fd_groove_data_t` structure that represents the data to be detached from the volume pool.
- **Control Flow**:
    - Check if the `join` pointer is NULL; if so, log a warning and return NULL.
    - Attempt to leave the volume pool associated with `join->volume_pool`; if this fails, log a warning and return NULL.
    - If all checks pass, return the `join` pointer.
- **Output**: Returns the `join` pointer if successful, or NULL if an error occurs.


---
### fd\_groove\_data\_delete<!-- {{#callable:fd_groove_data_delete}} -->
The `fd_groove_data_delete` function validates and deletes a shared memory data structure by resetting its magic number to zero.
- **Inputs**:
    - `shdata`: A pointer to the shared memory data structure (`fd_groove_data_shmem_t`) to be deleted.
- **Control Flow**:
    - Cast the input `shdata` to a `fd_groove_data_shmem_t` pointer named `data`.
    - Check if `data` is NULL; if so, log a warning and return NULL.
    - Check if `data` is misaligned according to [`fd_groove_data_align`](fd_groove_data.h.driver.md#fd_groove_data_align); if so, log a warning and return NULL.
    - Check if `data->magic` is not equal to `FD_GROOVE_DATA_MAGIC`; if so, log a warning and return NULL.
    - Use a compiler memory fence (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before and after setting `data->magic` to 0.
    - Return the original `shdata` pointer.
- **Output**: Returns the original `shdata` pointer if the deletion is successful, otherwise returns NULL if any validation checks fail.
- **Functions called**:
    - [`fd_groove_data_align`](fd_groove_data.h.driver.md#fd_groove_data_align)


---
### fd\_groove\_data\_private\_alloc\_obj<!-- {{#callable:fd_groove_data_private_alloc_obj}} -->
The `fd_groove_data_private_alloc_obj` function allocates an object from a specified size class superblock within a groove data structure, managing concurrency and superblock states.
- **Inputs**:
    - `data`: A pointer to the `fd_groove_data_t` structure, which contains the groove data context and state.
    - `obj_szc`: An unsigned long integer representing the size class of the object to be allocated.
    - `_obj_off`: A pointer to an unsigned long where the function will store the offset of the allocated object.
    - `_obj_idx`: A pointer to an unsigned long where the function will store the index of the allocated object within the superblock.
- **Control Flow**:
    - Retrieve the volume base address from the data structure.
    - Determine the object count, footprint, concurrency group mask, and parent size class from the configuration for the given size class.
    - Calculate the concurrency group and locate the active slot and inactive stack for the size class and concurrency group.
    - Attempt to acquire exclusive access to the active superblock for the concurrency group using a test-and-test-and-set approach.
    - If no active superblock is available, attempt to pop an inactive superblock from the stack.
    - If no inactive superblock is available, attempt to create a new superblock by acquiring a volume or a parent size class object.
    - Initialize the new superblock header and mark all objects as free if a new superblock is created.
    - Allocate a free object from the superblock, updating the free object bit field atomically.
    - If the superblock still has free objects, return it to circulation as the active superblock; otherwise, it will be returned to circulation upon freeing.
    - Calculate the object offset and index, storing them in the provided pointers.
    - Return success status.
- **Output**: Returns an integer status code, `FD_GROOVE_SUCCESS` on success, or an error code if allocation fails.
- **Functions called**:
    - [`fd_groove_data_volume0`](fd_groove_data.h.driver.md#fd_groove_data_volume0)
    - [`fd_groove_data_volume1`](fd_groove_data.h.driver.md#fd_groove_data_volume1)
    - [`fd_groove_data_private_active_displace`](#fd_groove_data_private_active_displace)
    - [`fd_groove_data_private_inactive_pop`](#fd_groove_data_private_inactive_pop)
    - [`fd_groove_data_hdr_t::fd_groove_data_hdr`](fd_groove_data.h.driver.md#fd_groove_data_hdr_tfd_groove_data_hdr)
    - [`fd_groove_data_hdr_type`](fd_groove_data.h.driver.md#fd_groove_data_hdr_type)
    - [`fd_groove_data_hdr_szc`](fd_groove_data.h.driver.md#fd_groove_data_hdr_szc)
    - [`fd_groove_data_private_inactive_push`](#fd_groove_data_private_inactive_push)


---
### fd\_groove\_data\_alloc<!-- {{#callable:fd_groove_data_alloc}} -->
The `fd_groove_data_alloc` function allocates a memory block from a specified data structure with given alignment, size, and tag, and returns a pointer to the allocated memory or NULL on failure.
- **Inputs**:
    - `data`: A pointer to an `fd_groove_data_t` structure, which represents the data structure from which memory is to be allocated.
    - `align`: An unsigned long specifying the desired alignment for the allocated memory block; if zero, a default alignment is used.
    - `sz`: An unsigned long specifying the size of the memory block to allocate.
    - `tag`: An unsigned long used to tag the allocation for identification or debugging purposes.
    - `_err`: A pointer to an integer where the function will store an error code; if NULL, a local variable is used.
- **Control Flow**:
    - Initialize a local error variable if `_err` is NULL.
    - Check if `data` is NULL and return an error if so.
    - Set `align` to a default value if it is zero, and validate the alignment value.
    - Calculate the offset and footprint for the allocation based on alignment and size, and validate them.
    - Determine the size class for the allocation footprint.
    - Attempt to allocate an object from the data structure using the determined size class.
    - If allocation fails, return the error code and NULL.
    - If successful, set up the allocation header with the provided tag and other details.
    - Set the error code to success and return a pointer to the allocated memory.
- **Output**: A pointer to the allocated memory block, or NULL if the allocation fails.
- **Functions called**:
    - [`fd_groove_data_szc`](fd_groove_data.h.driver.md#fd_groove_data_szc)
    - [`fd_groove_data_private_alloc_obj`](#fd_groove_data_private_alloc_obj)
    - [`fd_groove_data_hdr_t::fd_groove_data_hdr`](fd_groove_data.h.driver.md#fd_groove_data_hdr_tfd_groove_data_hdr)


---
### fd\_groove\_data\_private\_free<!-- {{#callable:fd_groove_data_private_free}} -->
The [`fd_groove_data_private_free`](#fd_groove_data_private_free) function is responsible for freeing a previously allocated object in a groove data structure, ensuring its validity and managing the circulation of superblocks.
- **Inputs**:
    - `data`: A pointer to the `fd_groove_data_t` structure representing the groove data context.
    - `_obj`: A pointer to the object to be freed.
    - `exp_type`: An expected type of the object, used for validation purposes.
- **Control Flow**:
    - Check if `data` or `_obj` is NULL and return an error if so.
    - Retrieve the object header and validate its alignment and address range.
    - In paranoid mode, validate the object type and size class against expected values.
    - Determine the object's size class and count of objects in the superblock.
    - In paranoid mode, validate the object's alignment, size, and footprint against expected values.
    - Mark the object as invalid and update the free objects bit field to include the object.
    - If the superblock was full before freeing, return it to circulation; if it becomes completely empty, manage its release or circulation appropriately.
    - Handle the release of completely empty superblocks or volumes, ensuring they are marked and released correctly.
- **Output**: Returns `FD_GROOVE_SUCCESS` on successful freeing of the object, or an error code if any validation or operation fails.
- **Functions called**:
    - [`fd_groove_data_volume0`](fd_groove_data.h.driver.md#fd_groove_data_volume0)
    - [`fd_groove_data_volume1`](fd_groove_data.h.driver.md#fd_groove_data_volume1)
    - [`fd_groove_data_hdr_type`](fd_groove_data.h.driver.md#fd_groove_data_hdr_type)
    - [`fd_groove_data_hdr_idx`](fd_groove_data.h.driver.md#fd_groove_data_hdr_idx)
    - [`fd_groove_data_hdr_szc`](fd_groove_data.h.driver.md#fd_groove_data_hdr_szc)
    - [`fd_groove_data_hdr_align`](fd_groove_data.h.driver.md#fd_groove_data_hdr_align)
    - [`fd_groove_data_hdr_sz`](fd_groove_data.h.driver.md#fd_groove_data_hdr_sz)
    - [`fd_groove_data_cgroup_hint`](fd_groove_data.h.driver.md#fd_groove_data_cgroup_hint)
    - [`fd_groove_data_private_active_displace`](#fd_groove_data_private_active_displace)
    - [`fd_groove_data_private_inactive_push`](#fd_groove_data_private_inactive_push)
    - [`fd_groove_data_private_inactive_pop`](#fd_groove_data_private_inactive_pop)
    - [`fd_groove_data_private_free`](#fd_groove_data_private_free)
    - [`fd_groove_strerror`](fd_groove_base.c.driver.md#fd_groove_strerror)


---
### fd\_groove\_data\_private\_verify\_superblock<!-- {{#callable:fd_groove_data_private_verify_superblock}} -->
The function `fd_groove_data_private_verify_superblock` verifies that a specified superblock within a memory volume is valid and optionally checks its descendant superblocks.
- **Inputs**:
    - `superblock_off`: The offset of the superblock within the volume, relative to `_volume0`.
    - `exp_szc`: The expected size class of the superblock.
    - `in_circulation`: A flag indicating if the superblock is in circulation, meaning it should have at least one free object.
    - `verify_descendents`: A flag indicating whether to recursively verify the descendant superblocks.
    - `_volume0`: A pointer to the start of the memory volume.
    - `_volume1`: A pointer to the end of the memory volume.
- **Control Flow**:
    - Calculate the address of the superblock header using `superblock_off` and `_volume0`.
    - Verify that the superblock header is within the bounds of `_volume0` and `_volume1` and is properly aligned.
    - Check that the superblock header type is `FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK` and its size class matches `exp_szc`.
    - Retrieve and verify the object count, footprint, and parent size class from the size class configuration.
    - Ensure the parent object index is within valid bounds.
    - Verify the alignment and size of the superblock header.
    - Check the validity of the free object bit field and ensure there is at least one free object if `in_circulation` is true.
    - Iterate over the remaining objects in the superblock, verifying each object's header type, index, size class, alignment, and footprint.
    - If `verify_descendents` is true and an object is a superblock, recursively verify its descendants.
    - Return `FD_GROOVE_SUCCESS` if all checks pass.
- **Output**: Returns `FD_GROOVE_SUCCESS` if the superblock and its objects are valid, otherwise returns an error code indicating corruption.
- **Functions called**:
    - [`fd_groove_data_hdr_type`](fd_groove_data.h.driver.md#fd_groove_data_hdr_type)
    - [`fd_groove_data_hdr_szc`](fd_groove_data.h.driver.md#fd_groove_data_hdr_szc)
    - [`fd_groove_data_hdr_idx`](fd_groove_data.h.driver.md#fd_groove_data_hdr_idx)
    - [`fd_groove_data_hdr_align`](fd_groove_data.h.driver.md#fd_groove_data_hdr_align)
    - [`fd_groove_data_hdr_sz`](fd_groove_data.h.driver.md#fd_groove_data_hdr_sz)


---
### fd\_groove\_data\_verify<!-- {{#callable:fd_groove_data_verify}} -->
The `fd_groove_data_verify` function verifies the integrity and consistency of a `fd_groove_data_t` structure, ensuring that its components and associated memory structures are correctly aligned and configured.
- **Inputs**:
    - `data`: A pointer to a `fd_groove_data_t` structure that needs to be verified.
- **Control Flow**:
    - Check if the `data` pointer is non-null and properly aligned.
    - Retrieve and verify the associated volume pool using `fd_groove_volume_pool_verify`.
    - Ensure the volume pool's shared memory and elements are correctly aligned and within bounds.
    - Iterate over the volume pool to verify each volume's magic number and index.
    - Verify the shared memory (`shdata`) associated with `data` for correct alignment and magic number.
    - Check the sizeclass configuration for valid object counts, footprints, and alignment constraints.
    - Iterate over all active superblocks, verifying their offsets and headers using [`fd_groove_data_private_verify_superblock`](#fd_groove_data_private_verify_superblock).
    - Iterate over all inactive superblocks, ensuring they are in circulation and verifying their headers.
    - Return `FD_GROOVE_SUCCESS` if all checks pass.
- **Output**: Returns `FD_GROOVE_SUCCESS` if the verification is successful, otherwise returns `FD_GROOVE_ERR_CORRUPT` if any check fails.
- **Functions called**:
    - [`fd_groove_data_shdata_const`](fd_groove_data.h.driver.md#fd_groove_data_shdata_const)
    - [`fd_groove_data_align`](fd_groove_data.h.driver.md#fd_groove_data_align)
    - [`fd_groove_data_private_verify_superblock`](#fd_groove_data_private_verify_superblock)
    - [`fd_groove_data_hdr_szc`](fd_groove_data.h.driver.md#fd_groove_data_hdr_szc)
    - [`fd_groove_data_hdr_info`](fd_groove_data.h.driver.md#fd_groove_data_hdr_info)


---
### fd\_groove\_data\_volume\_verify<!-- {{#callable:fd_groove_data_volume_verify}} -->
The `fd_groove_data_volume_verify` function verifies the integrity and validity of a specified volume within a groove data structure.
- **Inputs**:
    - `data`: A pointer to a constant `fd_groove_data_t` structure representing the groove data context.
    - `_volume`: A pointer to a constant `fd_groove_volume_t` structure representing the volume to be verified.
- **Control Flow**:
    - The function begins by asserting that the `data` pointer is valid using the `TEST` macro.
    - It retrieves the start and end pointers of the volume range (`_volume0` and `_volume1`) from the `data` structure.
    - Calculates the offset of `_volume` from `_volume0` and checks if `_volume` is within the valid range and properly aligned.
    - Extracts the `magic`, `idx`, and `info_sz` fields from `_volume` and verifies their correctness using the `TEST` macro.
    - If the `magic` field indicates the volume is active (`FD_GROOVE_VOLUME_MAGIC`), it calculates the offset for the superblock and verifies it using [`fd_groove_data_private_verify_superblock`](#fd_groove_data_private_verify_superblock).
- **Output**: The function returns `FD_GROOVE_SUCCESS` if all checks pass, indicating the volume is valid; otherwise, it returns `FD_GROOVE_ERR_CORRUPT` if any check fails.
- **Functions called**:
    - [`fd_groove_data_volume0_const`](fd_groove_data.h.driver.md#fd_groove_data_volume0_const)
    - [`fd_groove_data_volume1_const`](fd_groove_data.h.driver.md#fd_groove_data_volume1_const)
    - [`fd_groove_data_private_verify_superblock`](#fd_groove_data_private_verify_superblock)


