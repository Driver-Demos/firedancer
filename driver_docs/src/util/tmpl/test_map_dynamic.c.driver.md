# Purpose
This C source code file is designed to test the functionality of a dynamic map (hash map) implementation, which is capable of storing and retrieving key-value pairs. The code includes a main function, indicating that it is an executable program. It utilizes two external components, `fd_sort.c` and `fd_map_dynamic.c`, to provide sorting and map functionalities, respectively. The code defines a `pair` structure to represent key-value pairs, with optional memoization for hash values, and uses this structure to test the map's ability to handle insertion, querying, and deletion of entries. The map is tested to its algorithmic limits by inserting a maximum number of unique keys, ensuring that the map can handle edge cases and maintain data integrity through various operations.

The program also includes a shuffle function to randomize the order of key-value pairs, ensuring that the map's behavior is robust under different insertion and deletion sequences. The code is structured to perform multiple iterations of insertion and deletion, verifying the map's correctness at each step. Additionally, the program includes tests for alignment and footprint requirements, ensuring that the map's memory usage is efficient. The code also contains conditional compilation for testing under hosted environments, where it checks for critical errors using process forking and signal handling. Overall, this file serves as a comprehensive test suite for validating the dynamic map's functionality and performance.
# Imports and Dependencies

---
- `../fd_util.h`
- `sys/types.h`
- `sys/wait.h`
- `unistd.h`
- `fd_sort.c`
- `fd_map_dynamic.c`


# Global Variables

---
### mem
- **Type**: `uchar array`
- **Description**: The `mem` variable is a global array of unsigned characters with a size of 16384 bytes. It is aligned to an 8-byte boundary using the `__attribute__((aligned(8)))` directive, which ensures that the starting address of the array is a multiple of 8.
- **Use**: This variable is used as a memory buffer to store data structures, specifically for the dynamic map operations in the program.


# Data Structures

---
### pair
- **Type**: `struct`
- **Members**:
    - `mykey`: An unsigned long integer serving as the key for the pair.
    - `myhash`: An optional unsigned integer used for memoization, included only if MEMOIZE is defined.
    - `val`: An unsigned integer representing the value associated with the key.
- **Description**: The `pair` structure is a simple data structure used to store a key-value pair, where `mykey` is the key and `val` is the associated value. The structure optionally includes a `myhash` field for memoization purposes, which is conditionally compiled based on the `MEMOIZE` macro. This structure is used in conjunction with sorting and mapping functionalities, as indicated by its integration with `fd_sort.c` and `fd_map_dynamic.c`.


---
### pair\_t
- **Type**: `struct`
- **Members**:
    - `mykey`: An unsigned long integer serving as the key for the pair.
    - `myhash`: An optional unsigned integer used for memoization of the hash value of the key.
    - `val`: An unsigned integer representing the value associated with the key.
- **Description**: The `pair_t` data structure is a simple struct used to represent a key-value pair, where `mykey` is the unique key of type `ulong`, `val` is the associated value of type `uint`, and `myhash` is an optional field used for storing a precomputed hash of the key when memoization is enabled. This structure is utilized in sorting and mapping operations, as seen in the accompanying code, which includes functions for sorting pairs and managing them in a dynamic map.


# Functions

---
### shuffle\_pair<!-- {{#callable:shuffle_pair}} -->
The `shuffle_pair` function randomly shuffles an array of `pair_t` structures using a Fisher-Yates shuffle algorithm.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure used for generating random numbers.
    - `pair`: A pointer to an array of `pair_t` structures that will be shuffled.
    - `cnt`: The number of elements in the `pair` array to shuffle.
- **Control Flow**:
    - The function iterates over the array from the second element to the last (index 1 to cnt-1).
    - For each element at index `i`, it generates a random index `j` such that 0 <= j <= i using `fd_rng_ulong_roll`.
    - It swaps the elements at indices `i` and `j` in the `pair` array.
- **Output**: The function does not return a value; it modifies the `pair` array in place to shuffle its elements.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes a random number generator, creates and tests a map data structure by inserting, querying, and deleting key-value pairs, and performs various checks to ensure the map's integrity and functionality.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program with `fd_boot` using command-line arguments.
    - Create a random number generator `rng` using `fd_rng_new` and `fd_rng_join`.
    - Define two arrays `ref` and `tst` of `pair_t` structures to hold key-value pairs.
    - Calculate `max` as the maximum number of slots the map can handle, ensuring it does not exceed 511.
    - Populate `ref` and `tst` arrays with unique keys and random values, and sort `ref` by keys.
    - Check memory alignment and footprint requirements for the map, logging a warning and exiting if not met.
    - Create and join a new map using `map_new` and `map_join`, and perform initial checks on the map's properties.
    - Iterate over the map slots to verify correct slot indexing.
    - Perform key validation checks to ensure keys are valid and unique.
    - Run 100 iterations of inserting and deleting key-value pairs in the map, shuffling the order each time.
    - For each iteration, insert key-value pairs into the map, ensuring no duplicates and verifying each insertion.
    - Shuffle the pairs and delete them from the map, verifying each deletion and ensuring remaining entries are intact.
    - After all iterations, leave and delete the map, ensuring proper cleanup.
    - If hosted and handholding is enabled, test critical logging scenarios with invalid map operations.
    - Delete the random number generator and log a success message before halting the program.
- **Output**: The function returns an integer status code, 0 on successful execution.
- **Functions called**:
    - [`shuffle_pair`](#shuffle_pair)


