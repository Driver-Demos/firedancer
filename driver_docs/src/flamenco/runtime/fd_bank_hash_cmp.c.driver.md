# Purpose
The provided C source code file implements a set of functions for managing and comparing bank hash data structures, likely used in a distributed or blockchain-based system. The primary purpose of this code is to handle the creation, manipulation, and validation of hash comparisons within a bank hash comparison context. The code includes functions to initialize ([`fd_bank_hash_cmp_new`](#fd_bank_hash_cmp_new)), join ([`fd_bank_hash_cmp_join`](#fd_bank_hash_cmp_join)), leave ([`fd_bank_hash_cmp_leave`](#fd_bank_hash_cmp_leave)), and delete ([`fd_bank_hash_cmp_delete`](#fd_bank_hash_cmp_delete)) a bank hash comparison structure. It also provides mechanisms to lock and unlock the structure for thread-safe operations ([`fd_bank_hash_cmp_lock`](#fd_bank_hash_cmp_lock) and [`fd_bank_hash_cmp_unlock`](#fd_bank_hash_cmp_unlock)), insert new hash entries ([`fd_bank_hash_cmp_insert`](#fd_bank_hash_cmp_insert)), and check the validity of hash comparisons ([`fd_bank_hash_cmp_check`](#fd_bank_hash_cmp_check)).

The code is structured around a central data structure, `fd_bank_hash_cmp_t`, which appears to manage a collection of hash entries, each associated with a slot and a stake. The functions ensure that memory is correctly aligned and initialized, and they handle potential issues such as full hash maps and hash mismatches. The [`fd_bank_hash_cmp_insert`](#fd_bank_hash_cmp_insert) function manages the insertion of new hash entries, ensuring that the map does not exceed its capacity and logging warnings if it does. The [`fd_bank_hash_cmp_check`](#fd_bank_hash_cmp_check) function evaluates the hash entries against a threshold stake percentage to determine if there is a match or mismatch, logging the results accordingly. This code is likely part of a larger system where hash integrity and consensus are critical, such as in a blockchain or distributed ledger technology.
# Imports and Dependencies

---
- `fd_bank_hash_cmp.h`
- `unistd.h`


# Functions

---
### fd\_bank\_hash\_cmp\_new<!-- {{#callable:fd_bank_hash_cmp_new}} -->
The `fd_bank_hash_cmp_new` function initializes a memory region for a bank hash comparison structure, ensuring proper alignment and setting up necessary substructures.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be initialized for the bank hash comparison structure.
- **Control Flow**:
    - Check if the input memory pointer `mem` is NULL; if so, log a warning and return NULL.
    - Check if the memory pointer `mem` is properly aligned according to [`fd_bank_hash_cmp_align`](fd_bank_hash_cmp.h.driver.md#fd_bank_hash_cmp_align); if not, log a warning and return NULL.
    - Calculate the footprint size required for the bank hash comparison structure using [`fd_bank_hash_cmp_footprint`](fd_bank_hash_cmp.h.driver.md#fd_bank_hash_cmp_footprint).
    - Initialize the memory region to zero using `fd_memset`.
    - Calculate the starting address for the map substructure by adding the size of `fd_bank_hash_cmp_t` to the base address and aligning it according to `fd_bank_hash_cmp_map_align`.
    - Initialize the map substructure using `fd_bank_hash_cmp_map_new`.
    - Adjust the address to account for the map's footprint and align it again according to [`fd_bank_hash_cmp_align`](fd_bank_hash_cmp.h.driver.md#fd_bank_hash_cmp_align).
    - Verify that the final address matches the expected end of the allocated footprint using `FD_TEST`.
    - Return the initialized memory pointer `mem`.
- **Output**: Returns the initialized memory pointer `mem` if successful, or NULL if there was an error with the input memory.
- **Functions called**:
    - [`fd_bank_hash_cmp_align`](fd_bank_hash_cmp.h.driver.md#fd_bank_hash_cmp_align)
    - [`fd_bank_hash_cmp_footprint`](fd_bank_hash_cmp.h.driver.md#fd_bank_hash_cmp_footprint)


---
### fd\_bank\_hash\_cmp\_join<!-- {{#callable:fd_bank_hash_cmp_join}} -->
The `fd_bank_hash_cmp_join` function validates and joins a `fd_bank_hash_cmp_t` structure by aligning its memory and initializing its map component.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to a memory location expected to be a `fd_bank_hash_cmp_t` structure.
- **Control Flow**:
    - Check if `bank_hash_cmp` is NULL and log a warning if so, returning NULL.
    - Check if `bank_hash_cmp` is properly aligned using `fd_bank_hash_cmp_align()` and log a warning if misaligned, returning NULL.
    - Calculate the address offset for the map component by adding the size of `fd_bank_hash_cmp_t` to the base address.
    - Cast `bank_hash_cmp` to a `fd_bank_hash_cmp_t` pointer and assign the result to `bank_hash_cmp_`.
    - Initialize the `map` field of `bank_hash_cmp_` by calling `fd_bank_hash_cmp_map_join` with the calculated address.
    - Return the original `bank_hash_cmp` pointer.
- **Output**: Returns the original `bank_hash_cmp` pointer if successful, or NULL if there are alignment or NULL pointer issues.
- **Functions called**:
    - [`fd_bank_hash_cmp_align`](fd_bank_hash_cmp.h.driver.md#fd_bank_hash_cmp_align)


---
### fd\_bank\_hash\_cmp\_leave<!-- {{#callable:fd_bank_hash_cmp_leave}} -->
The `fd_bank_hash_cmp_leave` function checks if the input pointer is non-null and returns it as a void pointer.
- **Inputs**:
    - `bank_hash_cmp`: A constant pointer to an `fd_bank_hash_cmp_t` structure, which represents a bank hash comparison object.
- **Control Flow**:
    - Check if the `bank_hash_cmp` pointer is NULL using `FD_UNLIKELY`; if it is, log a warning and return NULL.
    - If the pointer is not NULL, cast it to a void pointer and return it.
- **Output**: Returns the input `bank_hash_cmp` pointer cast to a void pointer, or NULL if the input is NULL.


---
### fd\_bank\_hash\_cmp\_delete<!-- {{#callable:fd_bank_hash_cmp_delete}} -->
The `fd_bank_hash_cmp_delete` function checks if a given `bank_hash_cmp` pointer is valid and aligned, and returns it if so, otherwise logs a warning and returns NULL.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to a bank hash comparison structure that needs to be validated and potentially deleted.
- **Control Flow**:
    - Check if `bank_hash_cmp` is NULL; if so, log a warning and return NULL.
    - Check if `bank_hash_cmp` is aligned according to [`fd_bank_hash_cmp_align`](fd_bank_hash_cmp.h.driver.md#fd_bank_hash_cmp_align); if not, log a warning and return NULL.
    - If both checks pass, return the `bank_hash_cmp` pointer.
- **Output**: Returns the `bank_hash_cmp` pointer if it is valid and aligned, otherwise returns NULL.
- **Functions called**:
    - [`fd_bank_hash_cmp_align`](fd_bank_hash_cmp.h.driver.md#fd_bank_hash_cmp_align)


---
### fd\_bank\_hash\_cmp\_lock<!-- {{#callable:fd_bank_hash_cmp_lock}} -->
The `fd_bank_hash_cmp_lock` function acquires a lock on a `fd_bank_hash_cmp_t` structure, ensuring thread-safe access.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to a `fd_bank_hash_cmp_t` structure on which the lock is to be acquired.
- **Control Flow**:
    - A pointer to the lock variable within the `fd_bank_hash_cmp_t` structure is obtained.
    - If threading is enabled (`FD_HAS_THREADS` is defined), the function enters a loop attempting to acquire the lock using an atomic compare-and-swap operation (`FD_ATOMIC_CAS`).
    - If the lock is successfully acquired (i.e., the lock was 0 and is now set to 1), the loop breaks.
    - If the lock is not acquired, the function pauses briefly (`FD_SPIN_PAUSE`) before retrying.
    - If threading is not enabled, the lock is directly set to 1.
    - A memory fence (`FD_COMPILER_MFENCE`) is issued to ensure memory operations are completed before proceeding.
- **Output**: The function does not return a value; it modifies the lock state of the `fd_bank_hash_cmp_t` structure in place.


---
### fd\_bank\_hash\_cmp\_unlock<!-- {{#callable:fd_bank_hash_cmp_unlock}} -->
The `fd_bank_hash_cmp_unlock` function releases a lock on a `fd_bank_hash_cmp_t` structure by setting its lock variable to zero.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to a `fd_bank_hash_cmp_t` structure whose lock is to be released.
- **Control Flow**:
    - Retrieve the address of the lock variable from the `bank_hash_cmp` structure.
    - Ensure memory ordering by calling `FD_COMPILER_MFENCE()`.
    - Set the lock variable to zero using `FD_VOLATILE` to release the lock.
- **Output**: This function does not return any value.


---
### fd\_bank\_hash\_cmp\_insert<!-- {{#callable:fd_bank_hash_cmp_insert}} -->
The `fd_bank_hash_cmp_insert` function inserts a hash into a bank hash comparison map, handling potential hash collisions and overflow conditions.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to the `fd_bank_hash_cmp_t` structure, which contains the bank hash comparison map and related metadata.
    - `slot`: An unsigned long integer representing the slot number where the hash is to be inserted.
    - `hash`: A constant pointer to an `fd_hash_t` structure representing the hash to be inserted.
    - `ours`: An integer flag indicating whether the hash is 'ours' (non-zero) or 'theirs' (zero).
    - `stake`: An unsigned long integer representing the stake associated with the hash.
- **Control Flow**:
    - Check if the slot is less than or equal to the watermark; if so, return immediately.
    - Query the map for an entry at the given slot; if no entry exists, check if the map is full.
    - If the map is full, clear entries below the watermark to make room for new entries.
    - Insert a new entry into the map at the given slot and initialize its count to zero.
    - If the hash is 'ours', store it in the entry and return.
    - Iterate over existing 'theirs' hashes in the entry to check for a match; if found, add the stake to the existing stake and return.
    - Check if the entry has reached its maximum capacity for 'theirs' hashes; if so, log a warning and set the overflow flag.
    - If not at capacity, add the new hash and stake to the entry and increment the count.
    - If the entry now contains more than one hash, log a warning for each equivocating hash.
- **Output**: The function does not return a value; it modifies the `fd_bank_hash_cmp_t` structure in place.


---
### fd\_bank\_hash\_cmp\_check<!-- {{#callable:fd_bank_hash_cmp_check}} -->
The `fd_bank_hash_cmp_check` function checks the bank hash comparison for a given slot and determines if the hash matches the majority stake, logging the result and updating the map accordingly.
- **Inputs**:
    - `bank_hash_cmp`: A pointer to the `fd_bank_hash_cmp_t` structure, which contains the map and other relevant data for bank hash comparison.
    - `slot`: An unsigned long integer representing the slot number to be checked in the bank hash comparison map.
- **Control Flow**:
    - Query the map for the comparison entry corresponding to the given slot.
    - If the entry is not found, return 0.
    - Check if the 'ours' hash is a null hash; if so, return 0.
    - If the entry count is zero, return 0.
    - Initialize 'theirs' to the first hash and 'stake' to the first stake value.
    - Iterate over the remaining entries to find the hash with the highest stake.
    - Calculate the percentage of the highest stake relative to the total stake.
    - If the percentage is greater than 52%, compare 'ours' with 'theirs'.
    - If they do not match, log a warning and return -1.
    - If they match, log a notice, remove the entry from the map, decrement the count, and return 1.
    - If the percentage is not greater than 52%, return 0.
- **Output**: Returns 1 if the hash matches the majority stake and is removed from the map, -1 if there is a mismatch, and 0 if no action is taken.


