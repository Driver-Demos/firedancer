# Purpose
This C source code file provides a template for creating ultra-high-performance dynamic key-value maps with a bounded compile-time size. The code is designed to be included in other C files, allowing developers to define custom map types by specifying key and hash types, the number of slots, and other parameters. The template supports operations such as inserting, removing, and querying keys, and it is optimized for fast O(1) operations. The code uses macros to allow customization of key and hash types, as well as other map behaviors, making it flexible for various use cases.

The file defines a set of static inline functions that form the public API for interacting with the maps. These functions include `mymap_new`, `mymap_join`, `mymap_leave`, `mymap_delete`, `mymap_insert`, `mymap_remove`, `mymap_clear`, and `mymap_query`, among others. The API is designed to be used in a header-only style, meaning that the functions are defined inline and can be included in multiple compilation units without causing linkage issues. The template also supports memoization of hash values to accelerate operations, especially when key comparison is slow. The code is highly configurable, allowing users to define custom behaviors for key equality, hashing, and movement, making it suitable for a wide range of applications where performance and flexibility are critical.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `../log/fd_log.h`


# Functions

---
### MAP\_<!-- {{#callable:MAP_}} -->
The `MAP_(query_const)` function queries a constant map for a given key and returns a pointer to the map slot holding the key or a null pointer if the key is not found.
- **Inputs**:
    - `map`: A constant pointer to the map structure to be queried.
    - `key`: The key to be searched for in the map.
    - `null`: A constant pointer to be returned if the key is not found in the map.
- **Control Flow**:
    - The function calls the non-const version `MAP_(query)` with the provided map, key, and null pointers cast to non-const types.
    - The `MAP_(query)` function performs a hash-based lookup to find the key in the map.
    - If the key is found, a pointer to the map slot containing the key is returned; otherwise, the null pointer is returned.
- **Output**: A constant pointer to the map slot containing the key if found, or the null pointer if the key is not found.
- **Functions called**:
    - [`MAP_`](#MAP_)


