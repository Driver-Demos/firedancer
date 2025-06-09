# Purpose
This C source code file is designed to test the functionality of a hash map implementation using a custom data structure called `pair_t`. The file includes the necessary headers and defines constants and structures to facilitate the testing process. The primary components of the code include the definition of a `pair` structure, which holds a key-value pair, and the integration of sorting and mapping functionalities through the inclusion of `fd_sort.c` and `fd_map.c`. The code is structured to test the insertion, querying, and deletion operations of the hash map, ensuring that the map can handle a maximum number of entries defined by `LG_SLOT_CNT`. The code also includes a shuffle function to randomize the order of operations, which helps in testing the robustness of the map under different scenarios.

The main function initializes a random number generator and creates arrays to hold reference and test data. It then populates these arrays with unique keys and random values, sorts the reference array, and performs a series of tests to verify the correctness of the map's operations. The tests include checking the alignment and footprint of the map, ensuring that keys can be inserted and queried correctly, and verifying that deletions are handled properly. Additionally, the code includes conditional compilation for testing under hosted environments, where it checks for critical log messages when invalid operations are attempted. This file is a comprehensive test suite for validating the behavior and performance of a hash map implementation in C.
# Imports and Dependencies

---
- `../fd_util.h`
- `sys/types.h`
- `sys/wait.h`
- `unistd.h`
- `fd_sort.c`
- `fd_map.c`


# Global Variables

---
### \_map
- **Type**: `pair_t array`
- **Description**: The variable `_map` is a global array of `pair_t` structures, with a size determined by the expression `1UL<<LG_SLOT_CNT`. The `pair_t` structure contains fields for a key (`mykey`), and a value (`val`), and optionally a hash (`myhash`) if memoization is enabled. This array is used to store key-value pairs for a map data structure.
- **Use**: The `_map` variable is used as the underlying storage for a map data structure, allowing for insertion, querying, and deletion of key-value pairs.


# Data Structures

---
### pair
- **Type**: `struct`
- **Members**:
    - `mykey`: A unique key of type unsigned long used to identify the pair.
    - `myhash`: An optional hash value of type unsigned int used for memoization, included only if MEMOIZE is enabled.
    - `val`: An unsigned integer value associated with the key.
- **Description**: The `pair` structure is a simple data structure used to store a key-value pair, where `mykey` is a unique identifier of type `ulong`, and `val` is the associated value of type `uint`. The structure optionally includes a `myhash` field for memoization purposes, which is only present if the `MEMOIZE` macro is enabled. This structure is used in conjunction with sorting and mapping functions to manage collections of key-value pairs efficiently.


---
### pair\_t
- **Type**: `struct`
- **Members**:
    - `mykey`: An unsigned long integer used as the key for the pair.
    - `myhash`: An optional unsigned integer used to store a hash of the key, included only if MEMOIZE is enabled.
    - `val`: An unsigned integer representing the value associated with the key.
- **Description**: The `pair_t` data structure is a simple struct used to represent a key-value pair, where `mykey` is the key and `val` is the associated value. The structure optionally includes a `myhash` field for storing a hash of the key when memoization is enabled, which can be used to optimize certain operations like lookups in a map. This struct is utilized in sorting and mapping operations, as indicated by its integration with sorting and mapping utilities in the provided code.


# Functions

---
### shuffle\_pair<!-- {{#callable:shuffle_pair}} -->
The `shuffle_pair` function randomly shuffles an array of `pair_t` structures using a Fisher-Yates shuffle algorithm.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` random number generator used to generate random indices for shuffling.
    - `pair`: A pointer to an array of `pair_t` structures that will be shuffled.
    - `cnt`: The number of elements in the `pair` array to shuffle.
- **Control Flow**:
    - The function iterates over the array from the second element to the last (index 1 to cnt-1).
    - For each element at index `i`, it generates a random index `j` between 0 and `i` (inclusive) using `fd_rng_ulong_roll`.
    - It swaps the elements at indices `i` and `j` in the `pair` array.
- **Output**: The function does not return a value; it modifies the input `pair` array in place to shuffle its elements.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes a random number generator, creates and tests a map data structure by inserting, querying, and deleting key-value pairs, and performs validation checks on the map's behavior.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program environment with `fd_boot` and set up a random number generator `rng`.
    - Define arrays `ref` and `tst` to hold `pair_t` structures, and calculate `max` as the maximum number of slots in the map.
    - Populate `ref` and `tst` with unique keys and random values, and sort `ref` by keys.
    - Create and join a new map using `map_new` and `map_join`, and perform initial validation checks on map properties.
    - Iterate 100 times, each time shuffling `tst`, inserting its elements into the map, and verifying the map's integrity after each insertion.
    - Shuffle `tst` again, delete its elements from the map in the new order, and verify the map's integrity after each deletion.
    - If hosted and handholding is enabled, test critical logging behavior for invalid map operations.
    - Clean up by deleting the random number generator and halting the program.
- **Output**: The function returns an integer status code, 0 on successful completion.
- **Functions called**:
    - [`shuffle_pair`](#shuffle_pair)


