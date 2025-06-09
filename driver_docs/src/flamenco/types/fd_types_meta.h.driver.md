# Purpose
This C header file, `fd_types_meta.h`, defines a set of constants and inline functions for handling and identifying types within a bincode/borsh data structure graph, which is likely used for serialization and deserialization tasks. The file includes a series of macro definitions that represent various data types and collection markers, such as primitive types (e.g., `FD_FLAMENCO_TYPE_BOOL`, `FD_FLAMENCO_TYPE_UINT`) and collection types (e.g., `FD_FLAMENCO_TYPE_ARR`, `FD_FLAMENCO_TYPE_MAP`). It provides reflection APIs that allow the user to determine whether a type is primitive or part of a collection, and whether a collection type marks the beginning or end of a collection. The use of inline functions like [`fd_flamenco_type_is_primitive`](#fd_flamenco_type_is_primitive) and [`fd_flamenco_type_is_collection`](#fd_flamenco_type_is_collection) suggests an emphasis on performance, as these functions are designed to be efficient by avoiding function call overhead. Overall, this file serves as a utility for type identification and reflection in data serialization contexts.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`
- `fd_bincode.h`


# Functions

---
### fd\_flamenco\_type\_is\_primitive<!-- {{#callable:fd_flamenco_type_is_primitive}} -->
The function `fd_flamenco_type_is_primitive` checks if a given type is a primitive type without child nodes.
- **Inputs**:
    - `type`: An integer representing the type to be checked, typically a constant defined in the Flamenco type system.
- **Control Flow**:
    - The function performs a bitwise AND operation between the input `type` and the hexadecimal value `0xe0`.
    - It then checks if the result of the bitwise operation is equal to `0x00`.
    - If the result is `0x00`, the function returns `1`, indicating the type is primitive.
    - Otherwise, it returns `0`, indicating the type is not primitive.
- **Output**: The function returns an integer `1` if the type is primitive (i.e., it does not contain any child nodes), and `0` otherwise.


---
### fd\_flamenco\_type\_is\_collection<!-- {{#callable:fd_flamenco_type_is_collection}} -->
The function `fd_flamenco_type_is_collection` checks if a given type represents the beginning or end of a collection in a data structure graph.
- **Inputs**:
    - `type`: An integer representing a node type in a bincode/borsh data structure graph.
- **Control Flow**:
    - The function performs a bitwise AND operation between the input `type` and the hexadecimal value `0xe0`.
    - It then checks if the result of the bitwise operation is equal to `0x20`.
    - If the result is `0x20`, the function returns 1, indicating the type is a collection; otherwise, it returns 0.
- **Output**: The function returns an integer: 1 if the type is a collection, and 0 otherwise.


---
### fd\_flamenco\_type\_is\_collection\_begin<!-- {{#callable:fd_flamenco_type_is_collection_begin}} -->
The function `fd_flamenco_type_is_collection_begin` checks if a given type represents the beginning of a collection in a data structure graph.
- **Inputs**:
    - `type`: An integer representing a node type in a bincode/borsh data structure graph.
- **Control Flow**:
    - The function first calls [`fd_flamenco_type_is_collection`](#fd_flamenco_type_is_collection) to check if the type is a collection type.
    - It then checks if the least significant bit of the type is 0, indicating the beginning of a collection.
- **Output**: Returns 1 if the type is a collection type and marks the beginning of a collection; otherwise, returns 0.
- **Functions called**:
    - [`fd_flamenco_type_is_collection`](#fd_flamenco_type_is_collection)


---
### fd\_flamenco\_type\_is\_collection\_end<!-- {{#callable:fd_flamenco_type_is_collection_end}} -->
The function `fd_flamenco_type_is_collection_end` checks if a given type represents the end of a collection in a data structure graph.
- **Inputs**:
    - `type`: An integer representing a node type in a bincode/borsh data structure graph.
- **Control Flow**:
    - The function first calls [`fd_flamenco_type_is_collection`](#fd_flamenco_type_is_collection) to check if the type is a collection type.
    - It then checks if the least significant bit of the type is set (i.e., `type & 1 != 0`) to determine if it is an end type.
- **Output**: Returns 1 if the type is a collection end type, otherwise returns 0.
- **Functions called**:
    - [`fd_flamenco_type_is_collection`](#fd_flamenco_type_is_collection)


