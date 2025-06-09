# Purpose
The provided C header file, `fd_chkdup.h`, defines a set of functions and data structures for high-performance computing (HPC) to check for duplicate account addresses in a list. This functionality is crucial in transaction processing systems where transactions with duplicate account addresses are considered invalid and should not incur a fee. The code is designed to be highly efficient, leveraging SIMD (Single Instruction, Multiple Data) instructions such as AVX and AVX512 to perform fast initial checks that may produce false positives. If a potential duplicate is detected, a more precise, albeit slower, check is performed. This dual-path approach ensures that the system can handle large volumes of transactions quickly while maintaining accuracy.

The file is structured to facilitate inlining of functions, which is critical for performance given the computational intensity of the operations involved. It defines a private structure, `fd_chkdup_t`, to manage the state required for duplicate detection, including a hash map for slow-path checks and entropy for fast-path checks. The header also includes macros and static inline functions to manage memory alignment and footprint, ensuring that the data structures are efficiently laid out in memory. The implementation details reveal a sophisticated use of bit manipulation and hashing techniques to optimize the detection process, with a focus on minimizing false positives and computational overhead. This header file is intended to be included in other C source files, providing a specialized utility for transaction validation in systems that require high throughput and low latency.
# Imports and Dependencies

---
- `../../ballet/fd_ballet_base.h`
- `../../ballet/txn/fd_txn.h`
- `../../util/simd/fd_avx.h`
- `../../util/tmpl/fd_map.c`
- `../../util/simd/fd_avx512.h`


# Global Variables

---
### fd\_chkdup\_new
- **Type**: `function pointer`
- **Description**: `fd_chkdup_new` is a function that initializes a region of shared memory for use in duplicate address detection. It takes a pointer to the shared memory and a pointer to a random number generator (RNG) as arguments. The function formats the memory region for duplicate detection, consuming some slots of the RNG in the process, and returns the pointer to the shared memory on success or NULL on failure.
- **Use**: This function is used to prepare a memory region for duplicate address detection by formatting it appropriately and initializing necessary data structures.


---
### fd\_chkdup\_join
- **Type**: `function pointer`
- **Description**: `fd_chkdup_join` is a function that joins the caller to a formatted region of memory used for duplicate address detection. It takes a pointer to shared memory (`shmem`) as an argument and returns a pointer to `fd_chkdup_t`, which represents the joined memory region.
- **Use**: This function is used to establish a connection to a memory region that has been formatted for duplicate address detection, allowing subsequent operations to be performed on this region.


---
### fd\_chkdup\_leave
- **Type**: `function pointer`
- **Description**: `fd_chkdup_leave` is a static inline function that unjoins the caller from a `fd_chkdup_t` object, effectively reversing the join operation performed by `fd_chkdup_join`. It returns a pointer to the `chkdup` object, allowing the caller to continue using the memory region if needed.
- **Use**: This function is used to unjoin a caller from a `fd_chkdup_t` object, returning the pointer to the `chkdup` object.


---
### fd\_chkdup\_delete
- **Type**: `function pointer`
- **Description**: `fd_chkdup_delete` is a static inline function that unformats a region of memory used for duplicate address detection in high-performance computing contexts. It is part of a set of functions designed to manage memory for checking duplicate account addresses efficiently.
- **Use**: This function is used to return a pointer to the unformatted memory region, effectively cleaning up the memory after its use in duplicate detection.


---
### chkdup\_null\_addr
- **Type**: ``fd_acct_addr_t``
- **Description**: The `chkdup_null_addr` is a static constant variable of type `fd_acct_addr_t`, initialized with a zeroed-out structure. This suggests it represents a null or invalid account address in the context of the application.
- **Use**: It is used as a sentinel value to represent an invalid or uninitialized account address in the duplicate checking logic.


# Data Structures

---
### fd\_chkdup\_t
- **Type**: `typedef struct fd_chkdup_private fd_chkdup_t;`
- **Members**:
    - `fd_chkdup_private`: A private structure used internally for managing duplicate checking operations.
- **Description**: The `fd_chkdup_t` is a typedef for a private structure used in high-performance computing to check for duplicate account addresses in a list. This data structure is designed to be efficient and fast, leveraging AVX instructions for initial checks that may produce false positives, followed by a precise check if needed. It is used in scenarios where transactions with duplicate account addresses need to be identified quickly to avoid unnecessary processing fees. The structure is aligned and has a fixed size, making it suitable for stack allocation or inclusion in other structures.


---
### fd\_chkdup\_waddr
- **Type**: `struct`
- **Members**:
    - `key`: Represents an account address.
- **Description**: The `fd_chkdup_waddr` structure is a simple data structure that encapsulates a single member, `key`, which is of type `fd_acct_addr_t`. This structure is used to represent an account address within the context of duplicate checking operations. It is part of a larger system designed to efficiently detect duplicate account addresses in transaction lists, which is critical for ensuring transaction validity and preventing unnecessary fees. The structure is defined with a typedef for ease of use in the codebase.


---
### fd\_chkdup\_waddr\_t
- **Type**: `struct`
- **Members**:
    - `key`: Represents an account address.
- **Description**: The `fd_chkdup_waddr_t` structure is a simple data structure that encapsulates a single account address, represented by the `key` member of type `fd_acct_addr_t`. This structure is used within the context of duplicate detection for account addresses, where it serves as an element in a hash map to efficiently track and identify duplicate addresses in a list of transactions. The structure is part of a larger system designed to ensure that transactions do not contain duplicate account addresses, which is critical for transaction validation and fee assessment.


---
### fd\_chkdup\_private
- **Type**: `struct`
- **Members**:
    - `entropy`: An array of unsigned characters used for storing entropy values, size depends on FD_CHKDUP_IMPL.
    - `hashmap`: An array of fd_chkdup_waddr_t used as a hash map for storing account addresses.
- **Description**: The `fd_chkdup_private` structure is designed to facilitate high-performance duplicate detection of account addresses in transactions. It contains an optional entropy array, which is used for generating hash values when FD_CHKDUP_IMPL is set to 1 or higher, and a fixed-size hash map for storing account addresses. The structure is aligned according to the FD_CHKDUP_ALIGN macro, which varies based on the implementation level, ensuring efficient memory access. This structure is part of a system that checks for duplicate account addresses in transactions, which is critical for transaction validation and fee assessment.


# Functions

---
### fd\_chkdup\_footprint<!-- {{#callable:fd_chkdup_footprint}} -->
The `fd_chkdup_footprint` function returns the memory footprint required for duplicate detection in a high-performance computing context.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as an inline function, which suggests it is intended to be small and frequently called, allowing the compiler to optimize it by embedding the function code directly at the call site.
    - The function simply returns a predefined constant `FD_CHKDUP_FOOTPRINT`, which represents the size of the memory footprint needed for duplicate detection.
- **Output**: The function returns an unsigned long integer representing the memory footprint size required for duplicate detection.


---
### fd\_chkdup\_align<!-- {{#callable:fd_chkdup_align}} -->
The `fd_chkdup_align` function returns the alignment requirement for the memory used in duplicate detection operations.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as an inline function, which suggests it is intended to be expanded in place to reduce function call overhead.
    - It simply returns a preprocessor-defined constant `FD_CHKDUP_ALIGN`, which is determined based on the platform's capabilities (AVX512, AVX, or neither).
- **Output**: The function returns an unsigned long integer representing the alignment requirement for memory used in duplicate detection.


---
### fd\_chkdup\_new<!-- {{#callable:fd_chkdup_new}} -->
The `fd_chkdup_new` function initializes a memory region for duplicate address detection, optionally using a random number generator to fill entropy data.
- **Inputs**:
    - `shmem`: A pointer to the first byte of a memory region with the appropriate alignment and footprint for duplicate address detection.
    - `rng`: A pointer to a local join of a random number generator (RNG), used to fill entropy data if applicable.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_chkdup_t` pointer named `chkdup`.
    - If `FD_CHKDUP_IMPL` is greater than or equal to 1, fill the `chkdup->entropy` array with random bytes generated by `fd_rng_uchar` using the `rng` pointer.
    - Perform a compile-time check to ensure the footprint of the `chkdup->hashmap` matches the expected size using `FD_TEST`.
    - Initialize the `chkdup->hashmap` using `fd_chkdup_pmap_new`.
    - Return the `chkdup` pointer.
- **Output**: Returns a pointer to the initialized `fd_chkdup_t` structure, or `NULL` on failure if `shmem` is `NULL` or not aligned.


---
### fd\_chkdup\_join<!-- {{#callable:fd_chkdup_join}} -->
The `fd_chkdup_join` function casts a given memory pointer to a `fd_chkdup_t` pointer, effectively joining the caller to a formatted memory region for duplicate address detection.
- **Inputs**:
    - `shmem`: A pointer to a memory region that has been formatted for use in duplicate address detection.
- **Control Flow**:
    - The function takes a single input, `shmem`, which is a pointer to a memory region.
    - It casts the `shmem` pointer to a `fd_chkdup_t` pointer type.
    - The function returns the casted pointer, effectively joining the caller to the memory region.
- **Output**: A pointer of type `fd_chkdup_t` that points to the same memory location as the input `shmem`.


---
### fd\_chkdup\_leave<!-- {{#callable:fd_chkdup_leave}} -->
The `fd_chkdup_leave` function unjoins the caller from a `fd_chkdup_t` object and returns the pointer to the `fd_chkdup_t` object.
- **Inputs**:
    - `chkdup`: A pointer to a `fd_chkdup_t` object that the caller is currently joined to.
- **Control Flow**:
    - The function takes a single argument, `chkdup`, which is a pointer to a `fd_chkdup_t` object.
    - It returns the same pointer, effectively unjoining the caller from the `fd_chkdup_t` object.
- **Output**: The function returns a `void*` pointer to the `fd_chkdup_t` object that was passed in.


---
### fd\_chkdup\_delete<!-- {{#callable:fd_chkdup_delete}} -->
The `fd_chkdup_delete` function returns a pointer to the unformatted memory region that was previously used for duplicate detection.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region that was previously formatted for duplicate detection.
- **Control Flow**:
    - The function takes a single argument, `shmem`, which is a pointer to a memory region.
    - It simply returns the `shmem` pointer without performing any additional operations.
- **Output**: A pointer to the unformatted memory region, which is the same as the input `shmem`.


---
### fd\_chkdup\_check<!-- {{#callable:fd_chkdup_check}} -->
The `fd_chkdup_check` function checks for duplicate account addresses in two lists using a fast initial check and a slower precise check if needed.
- **Inputs**:
    - `chkdup`: A pointer to a valid local join of a `fd_chkdup_t` object, used for duplicate detection.
    - `list0`: A pointer to the first account address of the first sublist, which may be NULL if `list0_cnt` is 0.
    - `list0_cnt`: The number of account addresses in the first sublist.
    - `list1`: A pointer to the first account address of the second sublist, which may be NULL if `list1_cnt` is 0.
    - `list1_cnt`: The number of account addresses in the second sublist.
- **Control Flow**:
    - The function first calls [`fd_chkdup_check_fast`](#fd_chkdup_check_fast) with the provided lists and counts.
    - If [`fd_chkdup_check_fast`](#fd_chkdup_check_fast) returns 0, indicating no duplicates were found, the function returns 0 immediately.
    - If [`fd_chkdup_check_fast`](#fd_chkdup_check_fast) returns a non-zero value, indicating potential duplicates, the function calls [`fd_chkdup_check_slow`](#fd_chkdup_check_slow) for a precise check.
    - The result of [`fd_chkdup_check_slow`](#fd_chkdup_check_slow) is returned as the final result of the function.
- **Output**: The function returns 1 if there is at least one duplicate account address in the combined lists, and 0 if all account addresses are unique.
- **Functions called**:
    - [`fd_chkdup_check_fast`](#fd_chkdup_check_fast)
    - [`fd_chkdup_check_slow`](#fd_chkdup_check_slow)


---
### fd\_chkdup\_check\_slow<!-- {{#callable:fd_chkdup_check_slow}} -->
The `fd_chkdup_check_slow` function checks two lists of account addresses for duplicates using a hash map and returns 1 if any duplicates are found, otherwise 0.
- **Inputs**:
    - `chkdup`: A pointer to a valid local join of a `fd_chkdup_t` object, which contains the hash map used for duplicate detection.
    - `list0`: A pointer to the first account address of the first sublist to be checked for duplicates.
    - `list0_cnt`: The number of account addresses in the first sublist.
    - `list1`: A pointer to the first account address of the second sublist to be checked for duplicates.
    - `list1_cnt`: The number of account addresses in the second sublist.
- **Control Flow**:
    - Join the hash map associated with the `chkdup` object.
    - Initialize an array `inserted` to keep track of inserted addresses and a counter `inserted_cnt` to zero.
    - Initialize `any_duplicates` and `skipped_inval` flags to zero.
    - Iterate over `list0` and check each address for validity using `fd_chkdup_pmap_key_inval`.
    - If an address is invalid, set `skipped_inval` and check if any duplicates have been found so far.
    - If valid, attempt to insert the address into the hash map using `fd_chkdup_pmap_insert`.
    - If insertion returns NULL, set `any_duplicates` to true and adjust `inserted_cnt`.
    - Repeat the same process for `list1`.
    - Remove all inserted addresses from the hash map in reverse order of insertion.
    - Leave the hash map.
    - Return the `any_duplicates` flag.
- **Output**: Returns 1 if any duplicate account addresses are found in the combined lists, otherwise returns 0.


---
### fd\_chkdup\_check\_fast<!-- {{#callable:fd_chkdup_check_fast}} -->
The `fd_chkdup_check_fast` function is a placeholder that always returns 1, indicating a potential duplicate in the list of account addresses, without performing any actual checks.
- **Inputs**:
    - `chkdup`: A pointer to a `fd_chkdup_t` structure, which is intended to be used for duplicate detection.
    - `list0`: A pointer to the first account address in the first sublist of account addresses to be checked.
    - `list0_cnt`: The number of account addresses in the first sublist.
    - `list1`: A pointer to the first account address in the second sublist of account addresses to be checked.
    - `list1_cnt`: The number of account addresses in the second sublist.
- **Control Flow**:
    - The function takes five parameters but does not use any of them in its logic.
    - It immediately returns the integer value 1, indicating that it assumes there is at least one duplicate in the provided lists.
- **Output**: The function returns an integer value of 1, which is intended to indicate the presence of duplicates, although no actual checking is performed.


# Function Declarations (Public API)

---
### fd\_chkdup\_new<!-- {{#callable_declaration:fd_chkdup_new}} -->
Formats a memory region for duplicate address detection.
- **Description**: This function prepares a specified memory region for use in detecting duplicate account addresses. It requires a pointer to a memory region with the correct alignment and footprint, as well as a pointer to a random number generator (RNG) that is locally joined. The RNG is used to initialize entropy, but no ongoing interest in the RNG is retained after the function completes. The function returns the memory region pointer on success or NULL if the memory is not properly aligned or is NULL.
- **Inputs**:
    - `shmem`: A pointer to the first byte of a memory region with the required alignment and footprint. Must not be NULL and must be properly aligned.
    - `rng`: A pointer to a locally joined random number generator. Some RNG slots will be consumed, but the function retains no interest in the RNG after execution.
- **Output**: Returns the pointer to the formatted memory region on success, or NULL on failure if the memory is not aligned or is NULL.
- **See also**: [`fd_chkdup_new`](#fd_chkdup_new)  (Implementation)


---
### fd\_chkdup\_join<!-- {{#callable_declaration:fd_chkdup_join}} -->
Joins the caller to a formatted memory region for duplicate detection.
- **Description**: This function is used to join a caller to a pre-formatted region of memory intended for duplicate address detection. It should be called after the memory has been properly formatted using `fd_chkdup_new`. The function returns a pointer to the `fd_chkdup_t` structure, allowing the caller to interact with the memory region for duplicate checking purposes. This function assumes that the memory region is correctly aligned and formatted; otherwise, behavior is undefined.
- **Inputs**:
    - `shmem`: A pointer to the first byte of a formatted memory region. The memory must be properly aligned and formatted for duplicate detection. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the `fd_chkdup_t` structure, which is the same as the input `shmem` pointer.
- **See also**: [`fd_chkdup_join`](#fd_chkdup_join)  (Implementation)


---
### fd\_chkdup\_leave<!-- {{#callable_declaration:fd_chkdup_leave}} -->
Unjoins the caller from a chkdup object.
- **Description**: This function is used to unjoin a caller from a previously joined fd_chkdup_t object. It should be called when the caller no longer needs to interact with the chkdup object, effectively marking the end of the caller's use of the chkdup resource. This function returns the chkdup pointer, allowing the caller to confirm the operation or use the pointer for further operations if needed. It is important to ensure that the chkdup object is valid and was previously joined by the caller before calling this function.
- **Inputs**:
    - `chkdup`: A pointer to a valid fd_chkdup_t object that the caller is currently joined to. The pointer must not be null and should represent a valid join state.
- **Output**: Returns the same fd_chkdup_t pointer that was passed in, allowing for confirmation of the unjoin operation.
- **See also**: [`fd_chkdup_leave`](#fd_chkdup_leave)  (Implementation)


---
### fd\_chkdup\_delete<!-- {{#callable_declaration:fd_chkdup_delete}} -->
Unformats a region of memory used for duplicate detection.
- **Description**: Use this function to unformat a previously formatted memory region that was used for duplicate address detection. This function should be called when the memory is no longer needed for duplicate detection, effectively cleaning up the resources. It returns a pointer to the unformatted memory region, allowing for further use or deallocation. Ensure that the memory region was previously formatted using the appropriate function before calling this.
- **Inputs**:
    - `shmem`: A pointer to the first byte of a memory region that was previously formatted for duplicate detection. It must not be null and should be properly aligned and sized according to the requirements of the formatting function.
- **Output**: Returns a pointer to the unformatted memory region, which is the same as the input pointer.
- **See also**: [`fd_chkdup_delete`](#fd_chkdup_delete)  (Implementation)


---
### fd\_chkdup\_check<!-- {{#callable_declaration:fd_chkdup_check}} -->
Checks for duplicate account addresses in two lists.
- **Description**: Use this function to determine if there are any duplicate account addresses within two provided lists. It is designed to be efficient, leveraging a fast initial check that may produce false positives, followed by a precise check if needed. This function is suitable for scenarios where transaction validation is critical, as duplicate account addresses can lead to transaction failures. Ensure that the total number of addresses in both lists does not exceed 128, and that the lists do not overlap. The function should be called with a valid `chkdup` object obtained from a local join.
- **Inputs**:
    - `chkdup`: A pointer to a valid local join of a `fd_chkdup_t` object. Must not be null.
    - `list0`: A pointer to the first account address of the first sublist. Can be null if `list0_cnt` is 0.
    - `list0_cnt`: The number of account addresses in the first sublist. Must be non-negative and, together with `list1_cnt`, not exceed 128.
    - `list1`: A pointer to the first account address of the second sublist. Can be null if `list1_cnt` is 0.
    - `list1_cnt`: The number of account addresses in the second sublist. Must be non-negative and, together with `list0_cnt`, not exceed 128.
- **Output**: Returns 1 if there is at least one duplicate account address in the combined lists, and 0 if all addresses are unique.
- **See also**: [`fd_chkdup_check`](#fd_chkdup_check)  (Implementation)


---
### fd\_chkdup\_check\_slow<!-- {{#callable_declaration:fd_chkdup_check_slow}} -->
Checks for duplicate account addresses in two lists.
- **Description**: Use this function to determine if there are any duplicate account addresses within two provided lists. It is designed to be precise and should be used when an exact check is required. The function expects a valid `chkdup` object and two lists of account addresses, which are logically concatenated before checking for duplicates. Ensure that the total number of addresses does not exceed 128, and that the lists do not overlap. The function returns 1 if duplicates are found and 0 if all addresses are unique.
- **Inputs**:
    - `chkdup`: A pointer to a valid local join of a `fd_chkdup_t` object. Must not be null.
    - `list0`: A pointer to the first account address of the first sublist. Can be null if `list0_cnt` is 0.
    - `list0_cnt`: The number of account addresses in the first sublist. Must be non-negative and, when combined with `list1_cnt`, not exceed 128.
    - `list1`: A pointer to the first account address of the second sublist. Can be null if `list1_cnt` is 0.
    - `list1_cnt`: The number of account addresses in the second sublist. Must be non-negative and, when combined with `list0_cnt`, not exceed 128.
- **Output**: Returns 1 if there are duplicate addresses in the combined lists, otherwise returns 0.
- **See also**: [`fd_chkdup_check_slow`](#fd_chkdup_check_slow)  (Implementation)


