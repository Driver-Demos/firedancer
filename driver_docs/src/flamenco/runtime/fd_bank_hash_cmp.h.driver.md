# Purpose
This C header file defines the structures and functions necessary for managing and comparing bank hash entries within a system, likely part of a larger software framework. The primary structure, `fd_bank_hash_cmp_entry_t`, is designed to store information about hash entries, including a slot identifier, a hash value, and arrays for storing multiple hash comparisons and associated stakes. The file also defines a map structure, `fd_bank_hash_cmp_t`, which includes a pointer to the map of entries, a lock for synchronization, and other metadata such as count and total stake. This suggests that the code is intended to handle concurrent access to a collection of hash entries, possibly in a distributed or multi-threaded environment.

The file provides a set of functions for managing the lifecycle of the hash comparison map, including creation ([`fd_bank_hash_cmp_new`](#fd_bank_hash_cmp_new)), joining ([`fd_bank_hash_cmp_join`](#fd_bank_hash_cmp_join)), leaving ([`fd_bank_hash_cmp_leave`](#fd_bank_hash_cmp_leave)), and deletion ([`fd_bank_hash_cmp_delete`](#fd_bank_hash_cmp_delete)). Additionally, it includes functions for locking and unlocking the map to ensure thread safety, inserting new hash entries, and checking for hash matches. The inclusion of these functions indicates that the file defines a public API for interacting with the hash comparison system, allowing other parts of the software to perform operations on the hash entries. The use of macros and templates from included files suggests a modular design, enabling flexibility and reuse across different components of the software.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `fd_blockstore.h`
- `../../util/tmpl/fd_map.c`


# Global Variables

---
### fd\_bank\_hash\_cmp\_new
- **Type**: `function pointer`
- **Description**: The `fd_bank_hash_cmp_new` is a function that initializes a new bank hash comparison structure in memory. It takes a pointer to a memory location as an argument and returns a pointer to the newly created structure.
- **Use**: This function is used to allocate and initialize a new `fd_bank_hash_cmp` structure in the provided memory space.


---
### fd\_bank\_hash\_cmp\_join
- **Type**: `fd_bank_hash_cmp_t *`
- **Description**: The `fd_bank_hash_cmp_join` is a function that returns a pointer to a `fd_bank_hash_cmp_t` structure. This structure is used to manage and compare bank hash entries, which include slots, hashes, and stakes, among other fields.
- **Use**: This function is used to join or access an existing `fd_bank_hash_cmp_t` structure from a given memory address.


---
### fd\_bank\_hash\_cmp\_leave
- **Type**: `function pointer`
- **Description**: The `fd_bank_hash_cmp_leave` is a function that takes a constant pointer to a `fd_bank_hash_cmp_t` structure and returns a void pointer. This function is likely used to perform cleanup or disassociation tasks related to the `fd_bank_hash_cmp_t` structure, such as releasing resources or updating internal states.
- **Use**: This function is used to leave or disassociate from a `fd_bank_hash_cmp_t` instance, potentially performing necessary cleanup operations.


---
### fd\_bank\_hash\_cmp\_delete
- **Type**: `function pointer`
- **Description**: The `fd_bank_hash_cmp_delete` is a function that takes a pointer to a `fd_bank_hash_cmp` structure and deletes or deallocates the associated resources. It is part of a set of functions managing a hash comparison bank, which is used to compare hash values and manage related data.
- **Use**: This function is used to clean up and release resources associated with a `fd_bank_hash_cmp` instance when it is no longer needed.


# Data Structures

---
### fd\_bank\_hash\_cmp\_entry
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the hash comparison entry.
    - `hash`: Stores a hash value for the entry.
    - `ours`: Holds the hash value that represents 'our' version of the data.
    - `theirs`: An array of hash values representing 'their' versions of the data, with a fixed size of 8.
    - `stakes`: An array of stake values corresponding to each of 'their' hash values, with a fixed size of 8.
    - `cnt`: Indicates the count of valid entries in the 'theirs' and 'stakes' arrays.
    - `overflow`: A flag indicating if there has been an overflow in the hash comparison process.
    - `rooted`: A flag indicating if the entry is rooted, which may relate to its stability or finality in the comparison process.
- **Description**: The `fd_bank_hash_cmp_entry` structure is designed to facilitate hash comparisons within a bank hash comparison system. It contains fields for storing a slot number, a hash value, and an 'ours' hash, along with arrays for 'theirs' hashes and corresponding stakes, each with a fixed size of 8. The structure also includes a count of valid entries, and flags for overflow and rooted status, which help manage the state and integrity of the hash comparison process.


---
### fd\_bank\_hash\_cmp\_entry\_t
- **Type**: `struct`
- **Members**:
    - `slot`: An unsigned long integer representing the slot number.
    - `hash`: An unsigned integer representing the hash value.
    - `ours`: A hash value of type fd_hash_t representing our hash.
    - `theirs`: An array of 8 fd_hash_t representing their hash values.
    - `stakes`: An array of 8 unsigned long integers representing stakes.
    - `cnt`: An unsigned long integer representing the count of entries.
    - `overflow`: An integer indicating if there is an overflow.
    - `rooted`: An integer indicating if the entry is rooted.
- **Description**: The `fd_bank_hash_cmp_entry_t` structure is designed to store and compare hash values associated with specific slots in a bank hash comparison map. It includes fields for the slot number, a hash value, our hash, an array of their hash values, stakes associated with each hash, a count of entries, and flags for overflow and rooted status. This structure is part of a larger system for managing and comparing hash values in a distributed or parallel computing environment.


---
### fd\_bank\_hash\_cmp
- **Type**: `struct`
- **Members**:
    - `map`: A pointer to an array of fd_bank_hash_cmp_entry_t structures.
    - `map_gaddr`: An unsigned long representing the global address of the map.
    - `cnt`: An unsigned long tracking the count of entries in the map.
    - `watermark`: An unsigned long used as a threshold or marker for processing.
    - `total_stake`: An unsigned long representing the total stake value across entries.
    - `lock`: A volatile integer used for synchronization, indicating if the structure is locked.
- **Description**: The `fd_bank_hash_cmp` structure is designed to manage and compare hash entries within a bank, utilizing a map of `fd_bank_hash_cmp_entry_t` entries. It includes fields for tracking the number of entries, a watermark for processing thresholds, and a total stake value. The structure also incorporates a locking mechanism to ensure thread-safe operations. This data structure is integral to managing hash comparisons and ensuring consistency within a distributed system.


---
### fd\_bank\_hash\_cmp\_t
- **Type**: `struct`
- **Members**:
    - `map`: A pointer to an array of fd_bank_hash_cmp_entry_t structures, representing the hash comparison entries.
    - `map_gaddr`: An unsigned long representing the global address of the map.
    - `cnt`: An unsigned long representing the count of entries in the map.
    - `watermark`: An unsigned long used as a threshold or marker for processing.
    - `total_stake`: An unsigned long representing the total stake associated with the hash comparisons.
    - `lock`: A volatile integer used for synchronizing access to the structure.
- **Description**: The `fd_bank_hash_cmp_t` structure is designed to manage and compare hash values associated with different slots in a bank system. It contains a map of entries, each entry holding hash values and stakes for comparison. The structure also includes fields for managing the count of entries, a watermark for processing, and a lock for synchronization, making it suitable for concurrent environments where hash comparisons are critical.


# Functions

---
### fd\_bank\_hash\_cmp\_align<!-- {{#callable:fd_bank_hash_cmp_align}} -->
The `fd_bank_hash_cmp_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as `static inline`, indicating it is intended for use within the same translation unit and suggests inlining for performance.
    - The function takes no parameters and directly returns a constant value.
    - The return value is a constant `ulong` type with a value of `128UL`.
- **Output**: The function outputs a constant `ulong` value of 128, representing an alignment size.


---
### fd\_bank\_hash\_cmp\_footprint<!-- {{#callable:fd_bank_hash_cmp_footprint}} -->
The `fd_bank_hash_cmp_footprint` function calculates the memory footprint required for a `fd_bank_hash_cmp` structure, including its alignment and map footprint.
- **Inputs**: None
- **Control Flow**:
    - The function begins by initializing the layout with `FD_LAYOUT_INIT`.
    - It appends the alignment size of `fd_bank_hash_cmp` using `fd_bank_hash_cmp_align()` and the size of `fd_bank_hash_cmp_t`.
    - It further appends the alignment size of the map using `fd_bank_hash_cmp_map_align()` and the map's footprint using `fd_bank_hash_cmp_map_footprint()`.
    - Finally, it appends the alignment size of `fd_bank_hash_cmp` again and finalizes the layout with `FD_LAYOUT_FINI`.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the `fd_bank_hash_cmp` structure, including its alignment and map footprint.
- **Functions called**:
    - [`fd_bank_hash_cmp_align`](#fd_bank_hash_cmp_align)


# Function Declarations (Public API)

---
### fd\_bank\_hash\_cmp\_new<!-- {{#callable_declaration:fd_bank_hash_cmp_new}} -->
Initializes a new bank hash comparison structure in the provided memory.
- **Description**: This function sets up a new bank hash comparison structure at the specified memory location. It should be called when a new bank hash comparison instance is needed, and the caller must ensure that the memory provided is properly aligned and of sufficient size. The function will zero-initialize the memory and set up internal structures necessary for hash comparison operations. It is important to ensure that the memory is aligned according to the requirements of `fd_bank_hash_cmp_align` and that the footprint is at least as large as `fd_bank_hash_cmp_footprint`. If the memory is null or misaligned, the function will log a warning and return null.
- **Inputs**:
    - `mem`: A pointer to the memory where the bank hash comparison structure will be initialized. The memory must be aligned to `fd_bank_hash_cmp_align` and have a size of at least `fd_bank_hash_cmp_footprint`. If the memory is null or not properly aligned, the function will return null and log a warning. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the initialized memory if successful, or null if the memory is null or misaligned.
- **See also**: [`fd_bank_hash_cmp_new`](fd_bank_hash_cmp.c.driver.md#fd_bank_hash_cmp_new)  (Implementation)


---
### fd\_bank\_hash\_cmp\_join<!-- {{#callable_declaration:fd_bank_hash_cmp_join}} -->
Joins a bank hash comparison object for use.
- **Description**: This function prepares a bank hash comparison object for use by joining it, which involves setting up necessary internal structures. It must be called with a valid, non-null pointer to a memory region that is properly aligned according to `fd_bank_hash_cmp_align()`. If the provided pointer is null or misaligned, the function will log a warning and return null. This function is typically called after creating a new bank hash comparison object with `fd_bank_hash_cmp_new()` and before performing operations on it.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to a memory region representing a bank hash comparison object. It must not be null and must be aligned to the boundary specified by `fd_bank_hash_cmp_align()`. If these conditions are not met, the function returns null.
- **Output**: Returns a pointer to the joined `fd_bank_hash_cmp_t` object if successful, or null if the input is invalid.
- **See also**: [`fd_bank_hash_cmp_join`](fd_bank_hash_cmp.c.driver.md#fd_bank_hash_cmp_join)  (Implementation)


---
### fd\_bank\_hash\_cmp\_leave<!-- {{#callable_declaration:fd_bank_hash_cmp_leave}} -->
Leaves a bank hash comparison context.
- **Description**: This function is used to leave or detach from a bank hash comparison context that was previously joined. It should be called when the operations on the bank hash comparison context are complete, allowing for any necessary cleanup or detachment. The function expects a valid pointer to a `fd_bank_hash_cmp_t` structure. If the provided pointer is null, the function logs a warning and returns null, indicating that no action was taken. This function is typically used in conjunction with `fd_bank_hash_cmp_join` and should be called after all necessary operations on the bank hash comparison context are finished.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to a `fd_bank_hash_cmp_t` structure representing the bank hash comparison context to leave. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a void pointer to the bank hash comparison context if successful, or null if the input was null.
- **See also**: [`fd_bank_hash_cmp_leave`](fd_bank_hash_cmp.c.driver.md#fd_bank_hash_cmp_leave)  (Implementation)


---
### fd\_bank\_hash\_cmp\_delete<!-- {{#callable_declaration:fd_bank_hash_cmp_delete}} -->
Deletes a bank hash comparison object.
- **Description**: Use this function to delete a bank hash comparison object when it is no longer needed. It checks if the provided pointer is non-null and properly aligned before proceeding. If the pointer is null or misaligned, a warning is logged, and the function returns null. This function should be called only after ensuring that the bank hash comparison object is no longer in use.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to the bank hash comparison object to be deleted. Must not be null and must be aligned to the alignment requirements of `fd_bank_hash_cmp_align()`. If these conditions are not met, the function logs a warning and returns null.
- **Output**: Returns the input pointer if it is valid; otherwise, returns null if the input is null or misaligned.
- **See also**: [`fd_bank_hash_cmp_delete`](fd_bank_hash_cmp.c.driver.md#fd_bank_hash_cmp_delete)  (Implementation)


---
### fd\_bank\_hash\_cmp\_lock<!-- {{#callable_declaration:fd_bank_hash_cmp_lock}} -->
Locks the bank hash comparison structure for exclusive access.
- **Description**: Use this function to acquire a lock on the `fd_bank_hash_cmp_t` structure, ensuring exclusive access to it. This is necessary when performing operations that require thread safety, such as modifying the structure's contents. The function will block until the lock is successfully acquired. It is important to call this function before any operation that modifies the structure and to release the lock using `fd_bank_hash_cmp_unlock` after the operation is complete. This function is thread-safe and will use atomic operations to acquire the lock if threading is enabled.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to an `fd_bank_hash_cmp_t` structure that is to be locked. Must not be null. The caller retains ownership of the structure.
- **Output**: None
- **See also**: [`fd_bank_hash_cmp_lock`](fd_bank_hash_cmp.c.driver.md#fd_bank_hash_cmp_lock)  (Implementation)


---
### fd\_bank\_hash\_cmp\_unlock<!-- {{#callable_declaration:fd_bank_hash_cmp_unlock}} -->
Releases the lock on a bank hash comparison structure.
- **Description**: Use this function to release a lock previously acquired on a `fd_bank_hash_cmp_t` structure, allowing other operations to proceed. It is typically called after a critical section of code that manipulates the bank hash comparison data is completed. Ensure that the lock was successfully acquired before calling this function to avoid undefined behavior. This function is thread-safe and should be used in multi-threaded environments to manage access to shared resources.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to a `fd_bank_hash_cmp_t` structure. This must not be null and should point to a valid bank hash comparison structure that is currently locked.
- **Output**: None
- **See also**: [`fd_bank_hash_cmp_unlock`](fd_bank_hash_cmp.c.driver.md#fd_bank_hash_cmp_unlock)  (Implementation)


---
### fd\_bank\_hash\_cmp\_insert<!-- {{#callable_declaration:fd_bank_hash_cmp_insert}} -->
Inserts a hash into the bank hash comparison structure for a given slot.
- **Description**: Use this function to add a hash to the bank hash comparison structure for a specific slot, either as 'ours' or as a comparison against existing hashes. This function should be called when you need to track or compare hashes for a particular slot in the bank hash comparison process. It is important to ensure that the slot number is greater than the current watermark to avoid the function returning immediately without any action. The function handles cases where the map is full by clearing entries below the watermark, and it logs warnings if there are more than the allowed number of equivocating hashes for a slot.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to the bank hash comparison structure where the hash will be inserted. Must not be null, and the structure should be properly initialized before calling this function.
    - `slot`: The slot number associated with the hash. Must be greater than the current watermark of the bank_hash_cmp structure; otherwise, the function will return without inserting the hash.
    - `hash`: A pointer to the hash to be inserted. Must not be null, and the hash should be a valid fd_hash_t object.
    - `ours`: An integer flag indicating if the hash is 'ours'. If non-zero, the hash is stored as 'ours'; otherwise, it is compared against existing hashes.
    - `stake`: The stake associated with the hash. Used to update the stake for matching hashes or to set the stake for new entries.
- **Output**: None
- **See also**: [`fd_bank_hash_cmp_insert`](fd_bank_hash_cmp.c.driver.md#fd_bank_hash_cmp_insert)  (Implementation)


---
### fd\_bank\_hash\_cmp\_check<!-- {{#callable_declaration:fd_bank_hash_cmp_check}} -->
Checks the bank hash comparison for a given slot.
- **Description**: Use this function to verify if the bank hash for a specified slot matches the expected hash based on the highest stake. It should be called when you need to confirm the integrity of the bank hash at a particular slot. The function requires that the bank hash comparison structure is properly initialized and populated with relevant data. It returns a positive result if a match is found, a negative result if there is a mismatch, and zero if the comparison cannot be performed yet. This function also logs detailed information about the comparison result and updates the internal state by removing the entry from the map if a match is found.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to an initialized fd_bank_hash_cmp_t structure. Must not be null. The caller retains ownership.
    - `slot`: The slot number to check the bank hash for. It should be a valid slot that has been previously inserted into the bank_hash_cmp structure.
- **Output**: Returns 1 if the bank hash matches, -1 if there is a mismatch, and 0 if the comparison cannot be performed yet.
- **See also**: [`fd_bank_hash_cmp_check`](fd_bank_hash_cmp.c.driver.md#fd_bank_hash_cmp_check)  (Implementation)


