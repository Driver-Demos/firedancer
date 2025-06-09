# Purpose
This C source code file is designed to manage shared memory regions in a hosted environment, providing a set of functions to facilitate the joining and leaving of shared memory regions. The code is structured to handle shared memory operations such as mapping, querying, and managing reference counts for shared memory regions. It includes functions to convert region names into keys, map shared memory regions into the process's address space, and manage the lifecycle of these mappings. The file also includes mechanisms to handle anonymous shared memory joins, ensuring that memory regions are correctly aligned and locked in memory to prevent swapping.

The code defines a private API for managing shared memory, with functions like [`fd_shmem_join`](#fd_shmem_join), [`fd_shmem_leave`](#fd_shmem_leave), and [`fd_shmem_join_anonymous`](#fd_shmem_join_anonymous) that provide the core functionality for interacting with shared memory. It uses a hash map to track the state of shared memory regions, allowing for efficient querying and management of these regions. The file also includes error handling and logging to ensure robustness in the face of potential failures, such as failed memory mappings or invalid input parameters. Overall, this file is a critical component for applications that require efficient and reliable shared memory management in a multi-threaded or multi-process environment.
# Imports and Dependencies

---
- `fd_shmem_private.h`
- `errno.h`
- `unistd.h`
- `fcntl.h`
- `sys/mman.h`
- `sys/random.h`
- `../tmpl/fd_map.c`


# Global Variables

---
### fd\_shmem\_private\_key\_null
- **Type**: `fd_shmem_private_key_t const`
- **Description**: The `fd_shmem_private_key_null` is a constant of type `fd_shmem_private_key_t` that is initialized to zero at the start of a thread group. It serves as a null or default value for shared memory private keys.
- **Use**: This variable is used as a null key in shared memory operations to represent an uninitialized or default state.


---
### fd\_shmem\_private\_map
- **Type**: `fd_shmem_join_info_t array`
- **Description**: The `fd_shmem_private_map` is a static array of `fd_shmem_join_info_t` structures, with a size defined by `FD_SHMEM_PRIVATE_MAP_SLOT_CNT`. It is initialized to be empty at the start of a thread group. This array is used to store information about shared memory regions that have been joined by the application.
- **Use**: This variable is used to keep track of shared memory regions and their associated join information, allowing for efficient querying and management of these regions within the application.


---
### fd\_shmem\_private\_map\_cnt
- **Type**: `ulong`
- **Description**: `fd_shmem_private_map_cnt` is a static global variable of type `ulong` that is initialized to 0 at the start of a thread group. It is used to keep track of the number of shared memory regions currently mapped in the `fd_shmem_private_map`. This variable is crucial for managing the capacity of concurrent shared memory joins, ensuring that the number of joins does not exceed the maximum allowed (`FD_SHMEM_JOIN_MAX`).
- **Use**: This variable is used to count the number of active shared memory mappings in the `fd_shmem_private_map`.


# Functions

---
### fd\_shmem\_private\_key<!-- {{#callable:fd_shmem_private_key}} -->
The `fd_shmem_private_key` function initializes a shared memory key structure with a given name, ensuring it is a valid shared memory region name.
- **Inputs**:
    - `key`: A pointer to an `fd_shmem_private_key_t` structure where the key will be stored.
    - `name`: A constant character pointer to the name of the shared memory region to be converted into a key.
- **Control Flow**:
    - Calculate the length of the shared memory region name using [`fd_shmem_name_len`](fd_shmem_admin.c.driver.md#fd_shmem_name_len) function.
    - Check if the length is zero, indicating an invalid name, and return NULL if so.
    - Clear the `cstr` field of the `key` structure by setting all bytes to zero using `fd_memset`.
    - Copy the valid name into the `cstr` field of the `key` structure using `fd_memcpy`.
    - Return the pointer to the `key` structure.
- **Output**: Returns a pointer to the initialized `fd_shmem_private_key_t` structure on success, or NULL if the name is invalid.
- **Functions called**:
    - [`fd_shmem_name_len`](fd_shmem_admin.c.driver.md#fd_shmem_name_len)


---
### fd\_shmem\_private\_map\_query\_by\_join<!-- {{#callable:fd_shmem_private_map_query_by_join}} -->
The function `fd_shmem_private_map_query_by_join` searches a shared memory map for a join information entry that matches a given join handle and returns it, or a default value if no match is found.
- **Inputs**:
    - `map`: A pointer to an array of `fd_shmem_join_info_t` structures representing the shared memory map.
    - `join`: A constant pointer to the join handle to be matched against the entries in the map.
    - `def`: A pointer to a default `fd_shmem_join_info_t` structure to return if no matching entry is found.
- **Control Flow**:
    - Iterate over each slot in the shared memory map, indexed by `slot_idx`, from 0 to `FD_SHMEM_PRIVATE_MAP_SLOT_CNT - 1`.
    - For each slot, check if the key is valid and if the join handle in the slot matches the provided `join` handle.
    - If a match is found, return a pointer to the matching `fd_shmem_join_info_t` entry in the map.
    - If no match is found after checking all slots, return the default `def` pointer.
- **Output**: A pointer to the `fd_shmem_join_info_t` entry in the map that matches the join handle, or the default `def` pointer if no match is found.


---
### fd\_shmem\_private\_map\_query\_by\_addr<!-- {{#callable:fd_shmem_private_map_query_by_addr}} -->
The function `fd_shmem_private_map_query_by_addr` searches a shared memory map for a region that overlaps with a specified address range and returns the corresponding join information.
- **Inputs**:
    - `map`: A pointer to an array of `fd_shmem_join_info_t` structures representing the shared memory map.
    - `a0`: The starting address of the range to query.
    - `a1`: The ending address of the range to query, assumed to be greater than or equal to `a0`.
    - `def`: A default `fd_shmem_join_info_t` pointer to return if no matching region is found.
- **Control Flow**:
    - Iterate over each slot in the shared memory map up to `FD_SHMEM_PRIVATE_MAP_SLOT_CNT`.
    - For each slot, calculate the starting (`j0`) and ending (`j1`) addresses of the memory region using the `shmem`, `page_sz`, and `page_cnt` fields of the current slot.
    - Check if the current slot's key is valid and if the queried address range `[a0, a1]` overlaps with the region `[j0, j1]`.
    - If a valid overlapping region is found, return a pointer to the corresponding `fd_shmem_join_info_t` structure.
    - If no overlapping region is found after checking all slots, return the default pointer `def`.
- **Output**: A pointer to the `fd_shmem_join_info_t` structure of the overlapping region, or the default pointer `def` if no overlap is found.


---
### fd\_shmem\_private\_grab\_region<!-- {{#callable:fd_shmem_private_grab_region}} -->
The `fd_shmem_private_grab_region` function attempts to map a memory region at a specified address and size, ensuring the region is unmapped and available for use.
- **Inputs**:
    - `addr`: The starting address of the memory region to be mapped.
    - `size`: The size of the memory region to be mapped.
- **Control Flow**:
    - Call `mmap` to attempt to map the memory region at the specified address with read-only permissions and anonymous, private mapping flags.
    - Check if `mmap` failed; if so, return the failure indicator `MAP_FAILED`.
    - Verify if the returned address from `mmap` matches the requested address; if not, unmap the temporary mapping and return `MAP_FAILED`.
    - If the mapping is successful and the address matches, return the mapped address.
- **Output**: Returns a pointer to the mapped memory region if successful, or `MAP_FAILED` if the mapping fails or the address does not match.


---
### fd\_shmem\_private\_map\_rand<!-- {{#callable:fd_shmem_private_map_rand}} -->
The `fd_shmem_private_map_rand` function attempts to map a private shared memory region at a randomly generated address, aligned to a specified boundary, within 1000 attempts.
- **Inputs**:
    - `size`: The size of the memory region to map.
    - `align`: The alignment requirement for the starting address of the memory region.
- **Control Flow**:
    - Initialize `ret_addr` to 0.
    - Iterate up to 1000 times to find a suitable address.
    - In each iteration, use `getrandom` to generate a random address and store it in `ret_addr`.
    - Check if `getrandom` successfully generated the address; if not, log an error and exit.
    - Mask `ret_addr` to assume a 48-bit virtual address space.
    - Align `ret_addr` to the specified alignment using `fd_ulong_align_up`.
    - Attempt to map the memory region at `ret_addr` using [`fd_shmem_private_grab_region`](#fd_shmem_private_grab_region).
    - If the mapping is successful, return the address as a `void *`.
    - If no suitable address is found after 1000 attempts, log an error and exit.
- **Output**: Returns a pointer to the mapped memory region if successful, otherwise logs an error and does not return.
- **Functions called**:
    - [`fd_shmem_private_grab_region`](#fd_shmem_private_grab_region)


---
### fd\_shmem\_join<!-- {{#callable:fd_shmem_join}} -->
The `fd_shmem_join` function attempts to join a shared memory region by mapping it into the process's address space and managing its reference count.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory region to join.
    - `mode`: An integer specifying the access mode for the join, either read-only or read-write.
    - `join_func`: A function pointer to a custom join function that can be used to modify the join process, or NULL to use the default behavior.
    - `context`: A void pointer to a context that can be passed to the join function.
    - `opt_info`: A pointer to a `fd_shmem_join_info_t` structure where optional join information can be stored, or NULL if not needed.
- **Control Flow**:
    - The function begins by validating the input arguments, including converting the name to a key and checking the mode for validity.
    - It locks the shared memory system to ensure thread safety during the join operation.
    - The function checks if the shared memory region is already mapped by querying the private map with the generated key.
    - If the region is already mapped, it increments the reference count and returns the existing join information.
    - If the region is not mapped and there is room for a new mapping, it queries the shared memory information to determine the size and permissions.
    - The function attempts to open the shared memory file and map it into the process's address space at a randomly generated address.
    - It validates the mapping, ensuring alignment and locking the region in memory to prevent swapping.
    - If a custom join function is provided, it is called to complete the join; otherwise, the default behavior is used.
    - The function updates the join information, increments the reference count, and unlocks the shared memory system before returning the join pointer.
- **Output**: Returns a pointer to the joined shared memory region on success, or NULL on failure.
- **Functions called**:
    - [`fd_shmem_private_key`](#fd_shmem_private_key)
    - [`fd_shmem_info`](fd_shmem.h.driver.md#fd_shmem_info)
    - [`fd_shmem_private_path`](fd_shmem_private.h.driver.md#fd_shmem_private_path)
    - [`fd_shmem_private_map_rand`](#fd_shmem_private_map_rand)


---
### fd\_shmem\_leave<!-- {{#callable:fd_shmem_leave}} -->
The `fd_shmem_leave` function handles the process of leaving a shared memory region by decrementing the reference count and unmapping the memory if necessary.
- **Inputs**:
    - `join`: A pointer to the shared memory region to leave.
    - `leave_func`: A function pointer to a custom leave function that can be executed during the leave process.
    - `context`: A pointer to a context that can be passed to the leave function.
- **Control Flow**:
    - Check if the `join` pointer is NULL and log a warning if so, returning 1.
    - Acquire a lock on the shared memory management structure.
    - Check if there are any current joins; if not, log a warning and return 1.
    - Query the shared memory map for the join information using the `join` pointer.
    - If the join information is not found, log a warning and return 1.
    - Check the reference count of the join information.
    - If the reference count is greater than 1, decrement it and return 0.
    - If the reference count is -1, log a warning about a circular dependency and return 1.
    - Log a warning if the reference count is not 1, which should be impossible.
    - Store the join information details in local variables to protect against clobbering by the leave function.
    - If a leave function is provided, set the reference count to -1 to mark the leave in progress and call the leave function.
    - Attempt to unmap the shared memory using `munmap` and log a warning if it fails, setting an error flag.
    - Remove the join information from the shared memory map and decrement the map count.
    - Release the lock on the shared memory management structure.
    - Return the error flag, indicating success (0) or failure (1).
- **Output**: Returns 0 on successful leave or 1 if an error occurs during the process.
- **Functions called**:
    - [`fd_shmem_private_map_query_by_join`](#fd_shmem_private_map_query_by_join)


---
### fd\_shmem\_join\_query\_by\_name<!-- {{#callable:fd_shmem_join_query_by_name}} -->
The `fd_shmem_join_query_by_name` function queries shared memory join information by name and optionally returns it.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory region to query.
    - `opt_info`: A pointer to a `fd_shmem_join_info_t` structure where the join information will be stored if found; it can be NULL if the information is not needed.
- **Control Flow**:
    - Convert the provided name into a private key using [`fd_shmem_private_key`](#fd_shmem_private_key); if this fails, return `EINVAL`.
    - Acquire a lock on shared memory operations using `FD_SHMEM_LOCK`.
    - Check if there are any mappings in the shared memory map; if not, release the lock and return `ENOENT`.
    - Query the shared memory map for the join information using the generated key; if not found, release the lock and return `ENOENT`.
    - If `opt_info` is not NULL, copy the found join information into `opt_info`.
    - Release the lock on shared memory operations using `FD_SHMEM_UNLOCK`.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, `EINVAL` if the name is invalid, or `ENOENT` if the join information is not found.
- **Functions called**:
    - [`fd_shmem_private_key`](#fd_shmem_private_key)


---
### fd\_shmem\_join\_query\_by\_join<!-- {{#callable:fd_shmem_join_query_by_join}} -->
The function `fd_shmem_join_query_by_join` retrieves shared memory join information based on a given join handle.
- **Inputs**:
    - `join`: A pointer to the join handle for which the shared memory information is being queried.
    - `opt_info`: An optional pointer to a `fd_shmem_join_info_t` structure where the join information will be stored if found.
- **Control Flow**:
    - Check if the `join` pointer is NULL and return `EINVAL` if it is.
    - Acquire a lock on shared memory operations using `FD_SHMEM_LOCK`.
    - Check if there are any active shared memory mappings; if not, release the lock and return `ENOENT`.
    - Query the shared memory map for the join information using [`fd_shmem_private_map_query_by_join`](#fd_shmem_private_map_query_by_join).
    - If the join information is not found, release the lock and return `ENOENT`.
    - If `opt_info` is provided, copy the found join information into it.
    - Release the lock on shared memory operations.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, `EINVAL` if the `join` is NULL, or `ENOENT` if no join information is found.
- **Functions called**:
    - [`fd_shmem_private_map_query_by_join`](#fd_shmem_private_map_query_by_join)


---
### fd\_shmem\_join\_query\_by\_addr<!-- {{#callable:fd_shmem_join_query_by_addr}} -->
The `fd_shmem_join_query_by_addr` function queries shared memory join information based on a given address range and optionally returns the join information if found.
- **Inputs**:
    - `addr`: A pointer to the starting address of the memory range to query.
    - `sz`: The size of the memory range to query.
    - `opt_info`: An optional pointer to a `fd_shmem_join_info_t` structure where the join information will be stored if found.
- **Control Flow**:
    - Check if the size `sz` is zero, returning `ENOENT` if true, indicating an empty range.
    - Calculate the end address `a1` by adding `sz` to `addr` and subtracting one, and check for cyclic wrap, returning `EINVAL` if `a1` is less than `a0`.
    - Lock the shared memory map for thread safety using `FD_SHMEM_LOCK`.
    - Check if there are any mappings in the shared memory map; if not, unlock and return `ENOENT`.
    - Query the shared memory map for join information using the address range `a0` to `a1`.
    - If no join information is found, unlock and return `ENOENT`.
    - If join information is found and `opt_info` is not null, copy the join information to `opt_info`.
    - Unlock the shared memory map and return 0 to indicate success.
- **Output**: Returns 0 on success, `ENOENT` if no join information is found or the range is empty, and `EINVAL` if the address range is invalid due to cyclic wrap.
- **Functions called**:
    - [`fd_shmem_private_map_query_by_addr`](#fd_shmem_private_map_query_by_addr)


---
### fd\_shmem\_join\_anonymous<!-- {{#callable:fd_shmem_join_anonymous}} -->
The `fd_shmem_join_anonymous` function attempts to join an anonymous shared memory region with specified parameters, ensuring it is not already mapped and that there is enough room for the join.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the shared memory region to join.
    - `mode`: An integer specifying the join mode, which can be either read-only or read-write.
    - `join`: A pointer to a memory location where the join handle will be stored.
    - `mem`: A pointer to the memory location to be used for the shared memory region.
    - `page_sz`: An unsigned long representing the size of each page in the shared memory region.
    - `page_cnt`: An unsigned long representing the number of pages in the shared memory region.
- **Control Flow**:
    - The function begins by validating the input arguments, including checking the validity of the name, mode, join, mem, page size, and page count.
    - It calculates the total size of the memory region and checks for address alignment and range validity.
    - The function locks the shared memory map to ensure thread safety during the join operation.
    - It queries the shared memory map to ensure the region is not already joined, the join handle is not in use, and the memory is not already mapped.
    - If the region is not currently mapped and there is enough room, it attempts to insert the new join information into the shared memory map.
    - If successful, it updates the join information with the provided parameters and unlocks the shared memory map.
    - The function returns 0 on successful join or an error code if any validation or mapping step fails.
- **Output**: The function returns 0 on success, indicating the shared memory region was successfully joined, or an error code (EINVAL) if any validation or mapping step fails.
- **Functions called**:
    - [`fd_shmem_private_key`](#fd_shmem_private_key)
    - [`fd_shmem_is_page_sz`](fd_shmem.h.driver.md#fd_shmem_is_page_sz)
    - [`fd_shmem_private_map_query_by_join`](#fd_shmem_private_map_query_by_join)
    - [`fd_shmem_private_map_query_by_addr`](#fd_shmem_private_map_query_by_addr)
    - [`fd_shmem_info`](fd_shmem.h.driver.md#fd_shmem_info)


---
### fd\_shmem\_leave\_anonymous<!-- {{#callable:fd_shmem_leave_anonymous}} -->
The `fd_shmem_leave_anonymous` function handles the process of leaving or detaching from an anonymous shared memory region, ensuring proper cleanup and validation of the join state.
- **Inputs**:
    - `join`: A pointer to the join handle representing the shared memory region to be left.
    - `opt_info`: An optional pointer to a `fd_shmem_join_info_t` structure where information about the join can be stored before leaving.
- **Control Flow**:
    - Check if the `join` pointer is NULL and log a warning if so, returning `EINVAL`.
    - Acquire a lock on the shared memory map to ensure thread safety during the operation.
    - Verify that there is at least one active join in the shared memory map; if not, log a warning and return `EINVAL`.
    - Query the shared memory map for the join information associated with the provided `join` handle.
    - If the join information is not found, log a warning and return `EINVAL`.
    - Check if the reference count (`ref_cnt`) of the join is exactly 1; if not, log a warning and return `EINVAL`.
    - If `opt_info` is provided, copy the join information to it and set its `ref_cnt` to 0.
    - Remove the join information from the shared memory map and decrement the map count.
    - Release the lock on the shared memory map.
    - Return 0 to indicate successful completion.
- **Output**: Returns 0 on successful detachment from the shared memory region, or `EINVAL` if an error occurs during the process.
- **Functions called**:
    - [`fd_shmem_private_map_query_by_join`](#fd_shmem_private_map_query_by_join)


