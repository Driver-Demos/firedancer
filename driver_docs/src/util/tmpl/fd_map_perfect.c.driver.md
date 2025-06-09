# Purpose
The provided C code is a sophisticated implementation for creating ultra-high-performance compile-time perfect hash tables. It leverages the C preprocessor to define macros and functions that facilitate the construction of perfect hash tables, which are data structures that allow for constant-time complexity in key lookups without collisions. The code is designed to ensure that if the hash function does not result in a perfect hash table, the compilation will fail, providing a safeguard against incorrect hash function definitions. This is achieved through a series of preprocessor directives and macros that manipulate the input to generate the necessary hash table structure.

The file supports both hash tables with associated values and sets, where only key containment is checked. It provides a set of customizable macros that allow users to define the characteristics of the hash table, such as the name, size, element type, and hash function. The code includes static inline functions for checking key containment, querying elements, and obtaining hash values, which are generated based on the user-defined macros. The implementation is highly flexible, allowing for multiple instantiations within a compilation unit, provided that each instantiation has a unique name. Additionally, the code supports complex keys, such as arrays, by allowing users to define custom hash functions that can handle such data types. The file is intended to be included in other C files or headers, making it a reusable component for projects requiring efficient hash table operations.
# Imports and Dependencies

---
- `../bits/fd_bits.h`


# Global Variables

---
### MAP\_PERFECT\_
- **Type**: `MAP_PERFECT_T[]`
- **Description**: `MAP_PERFECT_` is a static constant array of type `MAP_PERFECT_T`, which is used to store elements of a perfect hash table. The size of the array is determined by the macro `MAP_PERFECT_LG_TBL_SZ`, which defines the base-2 logarithm of the table size, allowing the array to hold up to 2^MAP_PERFECT_LG_TBL_SZ elements. The array is initialized using a series of macros that ensure each element is placed at the correct index based on a perfect hash function.
- **Use**: This variable is used to store and access elements in a perfect hash table, allowing for efficient containment and query operations.


# Functions

---
### MAP\_PERFECT\_<!-- {{#callable:MAP_PERFECT_}} -->
The `MAP_PERFECT_(hash_or_default)` function computes the hash of a given key using a perfect hash function and returns the hash if the key is present in the table, or `UINT_MAX` if it is not.
- **Inputs**:
    - `key`: The key of type `MAP_PERFECT_KEY_T` for which the hash is to be computed and checked for presence in the table.
- **Control Flow**:
    - Compute the hash of the input key using the `MAP_PERFECT_HASH_R` function.
    - Check if the key at the computed hash index in the table is equal to the input key using `MAP_PERFECT_KEYS_EQUAL`.
    - Return the hash if the key is present in the table, otherwise return `UINT_MAX`.
- **Output**: Returns the hash of the key if it is present in the table, otherwise returns `UINT_MAX`.
- **Functions called**:
    - [`MAP_PERFECT_`](#MAP_PERFECT_)


