# Purpose
The provided C header file, `fd_h2_hdr_match.h`, is designed to facilitate the creation and management of lookup tables for HTTP header names, specifically within the context of HTTP/2 and HPACK encoding. This file defines a set of utilities and data structures that allow users to map HTTP header names to unique identifiers, which can be either predefined or user-defined. The primary technical components include structures for representing header keys and entries, a hash table for efficient lookup, and functions for initializing, inserting, and querying these mappings. The file also includes macros and constants for common HTTP headers, which are used to optimize the handling of frequently encountered headers.

The code is structured to be included in other C files, providing a public API for managing HTTP header mappings. It defines a matcher object that can be initialized with a seed for hash function permutation, allowing for the insertion of custom header names and their corresponding IDs. The matcher supports both compile-time static lists and dynamic additions, with constraints on the number of headers that can be added. The file also integrates with HPACK, a compression format for HTTP/2, by mapping static table indices to header IDs, thus enhancing performance by reducing the need for literal string comparisons. Overall, this header file offers a specialized utility for applications that require efficient HTTP header processing, particularly in environments where HTTP/2 is used.
# Imports and Dependencies

---
- `../../ballet/siphash13/fd_siphash13.h`
- `fd_hpack.h`
- `../../util/tmpl/fd_map.c`


# Global Variables

---
### fd\_h2\_hdr\_match\_entry\_null
- **Type**: `fd_h2_hdr_match_entry_t const`
- **Description**: The variable `fd_h2_hdr_match_entry_null` is a constant of type `fd_h2_hdr_match_entry_t`, which represents an entry in a hash table used for matching HTTP/2 header names to arbitrary IDs. This entry is likely used as a sentinel or null value in the hash table operations.
- **Use**: This variable is used as a default or null entry in hash table operations for HTTP/2 header matching.


---
### fd\_h2\_hdr\_match\_seed
- **Type**: `ulong`
- **Description**: The `fd_h2_hdr_match_seed` is a global variable of type `ulong` used as a seed for the hash function in the HTTP/2 header matching process. It is declared as an external variable, indicating that it is defined elsewhere, likely in a different source file. This seed is used to permute the hash function, providing a level of randomness and uniqueness to the hash values generated for header names.
- **Use**: This variable is used to initialize the hash function for mapping HTTP/2 header names to IDs in the header matcher.


---
### fd\_h2\_hpack\_matcher
- **Type**: `schar const[62]`
- **Description**: The `fd_h2_hpack_matcher` is a global array of signed characters that maps HPACK static table indices to common header IDs. It is aligned to 16 bytes and contains 62 elements, corresponding to the predefined indices in the HPACK static table used in HTTP/2 for efficient header representation.
- **Use**: This variable is used to quickly translate HPACK static table indices into corresponding header IDs, facilitating efficient header processing in HTTP/2.


---
### fd\_h2\_hdr\_matcher\_init
- **Type**: `fd_h2_hdr_matcher_t *`
- **Description**: The `fd_h2_hdr_matcher_init` function initializes a new HTTP/2 header matcher object. It takes a memory region and a seed value as parameters, setting up the matcher to map header names to IDs using a hash table. The seed is used to permute the hash function, ensuring unique hash values for different matcher instances.
- **Use**: This function is used to prepare a matcher object for use in mapping HTTP/2 header names to IDs, facilitating efficient header lookup operations.


---
### fd\_h2\_hdr\_matcher\_fini
- **Type**: `function pointer`
- **Description**: The `fd_h2_hdr_matcher_fini` is a function that finalizes or destroys an HTTP/2 header matcher object, which is used to map header names to IDs. It returns the underlying memory buffer back to the caller, allowing for resource cleanup.
- **Use**: This function is used to properly release resources associated with an `fd_h2_hdr_matcher_t` object when it is no longer needed.


# Data Structures

---
### fd\_h2\_hdr\_match\_key
- **Type**: `struct`
- **Members**:
    - `hdr`: A pointer to a constant character string representing the HTTP header name.
    - `hdr_len`: An unsigned short integer representing the length of the HTTP header name.
- **Description**: The `fd_h2_hdr_match_key` structure is a compact representation of an HTTP header name used in hash table lookups. It consists of a pointer to the header name string and its length, allowing efficient comparison and hashing operations for matching HTTP headers in a lookup table. This structure is part of a system designed to map header names to unique identifiers, facilitating quick access and manipulation of HTTP headers in applications.


---
### fd\_h2\_hdr\_match\_key\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: A pointer to a constant character string representing the header name.
    - `hdr_len`: An unsigned short integer representing the length of the header name.
- **Description**: The `fd_h2_hdr_match_key_t` structure is used to represent a key in an open-addressed hash table that maps HTTP header name strings to arbitrary IDs. It consists of a pointer to the header name and the length of the header name, allowing for efficient comparison and hashing of header names in the context of HTTP/2 header matching.


---
### fd\_h2\_hdr\_match\_entry
- **Type**: `struct`
- **Members**:
    - `key`: A structure of type `fd_h2_hdr_match_key_t` that holds the header name and its length.
    - `id`: A short integer representing the identifier for the header.
    - `hash`: An unsigned integer representing the hash value of the header name.
- **Description**: The `fd_h2_hdr_match_entry` structure is designed to represent an entry in a hash table used for matching HTTP header names to their corresponding identifiers. It contains a key, which is a structure holding the header name and its length, an identifier for the header, and a hash value for efficient lookup operations. This structure is aligned to 16 bytes to optimize memory access and performance.


---
### fd\_h2\_hdr\_match\_entry\_t
- **Type**: `struct`
- **Members**:
    - `key`: A structure containing the header name and its length.
    - `id`: A short integer representing the ID associated with the header.
    - `hash`: A 32-bit unsigned integer storing the hash value of the header name.
- **Description**: The `fd_h2_hdr_match_entry_t` structure is used to represent an entry in a hash table that maps HTTP header names to arbitrary IDs. It contains a key, which is a structure holding the header name and its length, an ID that uniquely identifies the header, and a hash value for efficient lookup operations. This structure is part of a system designed to facilitate quick matching and retrieval of HTTP header information, particularly in the context of HTTP/2 and HPACK.


---
### fd\_h2\_hdr\_matcher
- **Type**: `struct`
- **Members**:
    - `entry`: An array of fd_h2_hdr_match_entry_t structures used to store header entries in the hash table.
    - `seed`: A 64-bit unsigned long integer used to permute the hash function for the matcher.
    - `entry_cnt`: A 64-bit unsigned long integer representing the count of entries in the matcher, excluding HPACK entries.
- **Description**: The `fd_h2_hdr_matcher` structure is designed to facilitate the creation of a hash table for HTTP header names, allowing for efficient lookup and mapping of header names to arbitrary IDs. It is primarily intended for use with compile-time static lists of headers, and is not meant for dynamic insertion of arbitrary entries. The structure includes an array of `fd_h2_hdr_match_entry_t` to store the header entries, a `seed` to modify the hash function, and an `entry_cnt` to track the number of entries, excluding those from the HPACK static table.


---
### fd\_h2\_hdr\_matcher\_t
- **Type**: `struct`
- **Members**:
    - `entry`: An array of `fd_h2_hdr_match_entry_t` used to store header entries in the hash table.
    - `seed`: A 64-bit value used to permute the hash function for the matcher.
    - `entry_cnt`: The count of entries in the matcher, excluding HPACK entries.
- **Description**: The `fd_h2_hdr_matcher_t` structure is designed to facilitate the creation of a hash table for HTTP header names, allowing for efficient lookup and mapping of header names to user-defined IDs. It is primarily intended for use with static lists of headers that are known at compile-time, and it supports the addition of custom headers up to a predefined limit. The structure includes a seed for hash function permutation, an array to store header entries, and a count of the entries. This data structure is particularly useful in scenarios where quick header name resolution is required, such as in HTTP/2 implementations.


# Functions

---
### fd\_h2\_hdr\_match\_key\_eq<!-- {{#callable:fd_h2_hdr_match_key_eq}} -->
The function `fd_h2_hdr_match_key_eq` checks if two HTTP header match keys are equal by comparing their lengths and contents.
- **Inputs**:
    - `k1`: The first header match key, consisting of a pointer to the header string and its length.
    - `k2`: The second header match key, consisting of a pointer to the header string and its length.
- **Control Flow**:
    - The function first checks if the lengths of the two header keys (`k1.hdr_len` and `k2.hdr_len`) are equal.
    - If the lengths are equal, it then calls `fd_memeq` to compare the actual header strings (`k1.hdr` and `k2.hdr`) for equality over the length `k1.hdr_len`.
    - The function returns the result of the logical AND operation between the length comparison and the result of `fd_memeq`.
- **Output**: The function returns an integer, which is non-zero if the two header match keys are equal and zero otherwise.


---
### fd\_h2\_hdr\_match<!-- {{#callable:fd_h2_hdr_match}} -->
The `fd_h2_hdr_match` function matches an HTTP/2 header name against a pre-defined matcher map and returns the corresponding header ID.
- **Inputs**:
    - `matcher`: A pointer to an `fd_h2_hdr_matcher_t` structure that contains the header matcher map.
    - `name`: A pointer to a character array representing the header name to be matched.
    - `name_len`: An unsigned long integer representing the length of the header name.
    - `hpack_hint`: An unsigned integer providing a hint about the header, potentially indicating if the name is indexed in the HPACK static table.
- **Control Flow**:
    - Check if `hpack_hint` indicates the header name is indexed using `FD_H2_HDR_HINT_NAME_INDEXED`.
    - If indexed, extract the index and check if it is within the valid range (1 to 61).
    - If the index is valid, return the corresponding ID from `fd_h2_hpack_matcher`.
    - If `name_len` is zero, return 0 indicating an unknown header.
    - Set the global `fd_h2_hdr_match_seed` to the matcher's seed value.
    - Create a `fd_h2_hdr_match_key_t` key with the header name and length.
    - Query the matcher map using `fd_h2_hdr_map_query_const` with the key to find the corresponding entry.
    - Return the ID from the found entry.
- **Output**: The function returns an integer representing the header ID, which can be zero for unknown headers, negative for HTTP/2 built-in names, or positive for custom headers added to the matcher.


# Function Declarations (Public API)

---
### fd\_h2\_hdr\_matcher\_init<!-- {{#callable_declaration:fd_h2_hdr_matcher_init}} -->
Initialize a header matcher object with common HTTP headers.
- **Description**: This function initializes a header matcher object using a provided memory region and a seed for hash function permutation. It sets up the matcher with common HTTP headers, which are assigned negative IDs. The memory region must be properly aligned and sized to accommodate the matcher object. If the memory is null or misaligned, the function returns null. This function is typically called during application startup to prepare the matcher for subsequent header matching operations.
- **Inputs**:
    - `mem`: A pointer to a memory region that must be aligned to alignof(fd_h2_hdr_matcher_t) and have a size of sizeof(fd_h2_hdr_matcher_t). The caller retains ownership and must ensure it is not null and properly aligned.
    - `seed`: An arbitrary 64-bit value used to permute the hash function. It is typically chosen using a secure random number generator at application startup.
- **Output**: Returns a pointer to the initialized fd_h2_hdr_matcher_t object, or null if the memory is null or misaligned.
- **See also**: [`fd_h2_hdr_matcher_init`](fd_h2_hdr_match.c.driver.md#fd_h2_hdr_matcher_init)  (Implementation)


---
### fd\_h2\_hdr\_matcher\_fini<!-- {{#callable_declaration:fd_h2_hdr_matcher_fini}} -->
Destroys a matcher object and returns the underlying buffer.
- **Description**: Use this function to clean up and retrieve the memory buffer associated with a matcher object when it is no longer needed. This function should be called to properly finalize a matcher that was previously initialized, ensuring that any resources are released and the memory can be reused or freed by the caller. It is important to ensure that the matcher is not used after this function is called, as it will no longer be valid.
- **Inputs**:
    - `matcher`: A pointer to the fd_h2_hdr_matcher_t object to be finalized. Must not be null. The caller retains ownership of the memory and is responsible for ensuring the matcher is not used after finalization.
- **Output**: Returns a pointer to the underlying memory buffer that was used by the matcher, allowing the caller to reuse or free it.
- **See also**: [`fd_h2_hdr_matcher_fini`](fd_h2_hdr_match.c.driver.md#fd_h2_hdr_matcher_fini)  (Implementation)


---
### fd\_h2\_hdr\_matcher\_insert<!-- {{#callable_declaration:fd_h2_hdr_matcher_insert}} -->
Adds a custom header name to the matcher.
- **Description**: This function is used to add a custom header name to an existing matcher, allowing subsequent queries with the same name to return the specified ID. It should be used when you need to extend the matcher with additional header names beyond the predefined ones. The function requires that the ID is within a valid range and that the name is a non-empty, lowercase string with a length within specified bounds. It is important to ensure that the matcher has not exceeded its capacity for entries, as this will cause the application to abort with an error log.
- **Inputs**:
    - `matcher`: A pointer to an fd_h2_hdr_matcher_t structure where the header name will be added. Must not be null and should be properly initialized.
    - `id`: An integer representing the ID to associate with the header name. Must be in the range [1, 32767]. If out of bounds, the application will abort with an error log.
    - `name`: A pointer to a constant character array representing the header name. The name must have a static lifetime, be lowercase, and not be null. It is not null-terminated.
    - `name_len`: An unsigned long representing the length of the header name. Must be in the range [1, 65535]. If out of bounds, the application will abort with an error log.
- **Output**: None
- **See also**: [`fd_h2_hdr_matcher_insert`](fd_h2_hdr_match.c.driver.md#fd_h2_hdr_matcher_insert)  (Implementation)


