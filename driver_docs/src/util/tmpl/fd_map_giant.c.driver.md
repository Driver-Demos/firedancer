# Purpose
The provided C code is a template for generating high-performance, dynamic key-value maps capable of handling large datasets. These maps are designed to be highly efficient in terms of memory usage and can be used in various contexts, such as inter-process communication (IPC), memory relocation, and serialization/deserialization. The code allows for the creation of maps that can persist beyond the lifetime of the creating process and be used concurrently. It also includes features for adaptively optimizing the maps for recent queries by moving recently used elements to the front of their respective chains.

The code is structured as a header-only style library, which means it can be included in multiple compilation units to generate different types of maps. It provides a comprehensive set of APIs for map management, including functions for creating, joining, leaving, and deleting maps, as well as for inserting, removing, and querying keys. The template supports customization through macros, allowing users to define the map's name, element type, key type, and various other parameters. The code also includes mechanisms for verifying the integrity of the map and iterating over its elements. The use of macros and inline functions ensures that the generated maps are both flexible and efficient, making this code suitable for applications requiring high-performance data structures.
# Imports and Dependencies

---
- `../log/fd_log.h`


# Global Variables

---
### MAP\_
- **Type**: `function pointer`
- **Description**: `MAP_` is a macro used to generate function names for operations on a map data structure. It is used to concatenate the `MAP_NAME` with a specific operation, such as `push_free_ele`, to create a unique function name for that operation.
- **Use**: `MAP_` is used to create function names for map operations by concatenating the `MAP_NAME` with the operation name, ensuring unique function names for different map instances.


# Functions

---
### MAP\_<!-- {{#callable:MAP_}} -->
The `MAP_(remove)` function removes a key from a map and returns the corresponding element if found, or NULL if the key is not present.
- **Inputs**:
    - `join`: A pointer to the map structure from which the key should be removed.
    - `key`: A constant pointer to the key that needs to be removed from the map.
- **Control Flow**:
    - Retrieve the map's private structure using the `join` pointer.
    - Compute the hash of the key using `MAP_KEY_HASH` and the map's seed.
    - Determine the head of the list where the key might be located using the hash and the map's list count.
    - Iterate through the list starting from the head to find the element with the matching key.
    - If the element is found, update the list to remove the element and push the element to the free stack.
    - Decrement the map's key count.
    - Return the removed element.
    - If the key is not found, return NULL.
- **Output**: Returns a pointer to the removed element if the key is found, otherwise returns NULL.
- **Functions called**:
    - [`MAP_`](#MAP_)


