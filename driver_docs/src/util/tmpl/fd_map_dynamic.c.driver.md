# Purpose
The provided C code is a template for creating ultra-high-performance dynamic key-value maps with bounded runtime size. It is designed to be included in other C files to generate specific map types by defining certain macros such as `MAP_NAME` and `MAP_T`. The code offers a collection of static inline functions that operate as a header-only library, providing efficient operations for creating, joining, leaving, deleting, inserting, removing, and querying map entries. The maps are implemented using a hash table with linear probing, and they support customizable key and hash types, allowing for flexibility in how keys are stored and compared.

The code defines a set of public APIs that facilitate the management of these maps, including functions to calculate memory alignment and footprint, initialize and format memory regions for map usage, and perform operations like insertion and removal of keys with O(1) complexity. The template supports memoization to optimize key comparison operations and allows for different optimization strategies for query operations. The design is modular, allowing multiple map types to be instantiated within a single compilation unit, and it provides hooks for customization, such as using different hashing functions or handling non-POD (Plain Old Data) C++ structures. This makes the code highly versatile for various applications requiring efficient key-value storage and retrieval.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `stddef.h`
- `../log/fd_log.h`


# Functions

---
### MAP\_<!-- {{#callable:MAP_}} -->
The `MAP_(query)` function searches for a key in a map and returns a pointer to the map slot containing the key or a null pointer if the key is not found.
- **Inputs**:
    - `map`: A pointer to the map in which the key is being searched.
    - `key`: The key to be searched within the map.
    - `null`: A pointer to be returned if the key is not found in the map.
- **Control Flow**:
    - Check if the key is invalid and log a critical error if so (only if handholding is enabled).
    - Retrieve the slot mask from the map and compute the hash of the key.
    - Determine the starting slot for linear probing using the hash and slot mask.
    - Enter a loop to search for the key in the map using linear probing.
    - In each iteration, check if the current slot contains the key using a defined macro for key comparison.
    - If the key is found, break the loop and return the current map slot.
    - If the slot is empty (key is invalid), set the map slot to null and break the loop (or return null immediately based on optimization settings).
    - If neither condition is met, move to the next slot using a private function to handle wrap-around.
- **Output**: A pointer to the map slot containing the key if found, or the provided null pointer if the key is not found.
- **Functions called**:
    - [`MAP_`](#MAP_)


