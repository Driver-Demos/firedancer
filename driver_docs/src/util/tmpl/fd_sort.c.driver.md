# Purpose
The provided C code is a template for generating a family of high-performance sorting functions tailored for single-threaded and optionally multi-threaded environments. The template is designed to sort Plain Old Data (POD) types, such as integers or floating-point numbers, and can be customized by defining specific macros before including the template file. The key macros include `SORT_NAME` for naming the generated functions, `SORT_KEY_T` for specifying the data type to sort, and `SORT_BEFORE` for defining the sorting order. The template supports various sorting algorithms, including insertion sort, merge sort, and quicksort, and provides both stable and unstable sorting options. Additionally, it offers parallelized versions of the sorting functions if the `SORT_PARALLEL` macro is defined, leveraging a thread pool for improved performance on multi-core systems.

The code is structured to be included multiple times within a compilation unit, allowing different configurations for different sorting needs. It defines a comprehensive API for sorting operations, including functions for checking the validity of input sizes, determining scratch space requirements, and performing binary searches on sorted data. The template is highly configurable, with options to adjust thresholds for switching between sorting algorithms, optimize for specific data types, and control parallelization behavior. This flexibility makes it suitable for a wide range of applications where efficient sorting of large datasets is required.
# Imports and Dependencies

---
- `../tpool/fd_tpool.h`
- `../bits/fd_bits.h`


# Global Variables

---
### SORT\_
- **Type**: `function pointer`
- **Description**: `SORT_` is a macro that expands to a function pointer for a sorting function. It is part of a template-based sorting library that allows for the creation of custom sorting functions based on user-defined types and comparison logic.
- **Use**: `SORT_` is used to generate specific sorting function names by concatenating a base name with a suffix, allowing for flexible and reusable sorting implementations.


---
### tmp
- **Type**: `SORT_KEY_T*`
- **Description**: The variable `tmp` is a pointer to a `SORT_KEY_T` type, which is a placeholder for the data type being sorted. It is initialized by casting the third element of the `arg` array to a `SORT_KEY_T*`. This suggests that `tmp` is used as a temporary storage or workspace for sorting operations.
- **Use**: `tmp` is used as a temporary buffer in sorting functions, particularly for merge operations, to hold intermediate results during the sorting process.


---
### \_in\_l
- **Type**: `SORT_KEY_T **`
- **Description**: The variable `_in_l` is a pointer to a pointer of type `SORT_KEY_T`, which is a placeholder for the data type used in sorting operations. It is initialized by casting the first element of the `arg` array to `SORT_KEY_T **`. This suggests that `_in_l` is intended to point to an array of pointers, each pointing to a `SORT_KEY_T` element or array.
- **Use**: This variable is used to reference the left input array for a merge operation in a sorting algorithm.


---
### in\_l
- **Type**: `SORT_KEY_T*`
- **Description**: The variable `in_l` is a pointer to a `SORT_KEY_T` type, which is defined by the macro `SORT_KEY_T`. It is initialized to point to the first element of a two-dimensional array of `SORT_KEY_T` pointers, which is cast from the first element of the `arg` array.
- **Use**: `in_l` is used to access and manipulate the left portion of a data block during a merge operation in a sorting algorithm.


---
### cnt\_l
- **Type**: `long`
- **Description**: `cnt_l` is a long integer variable that represents the count of elements in the left partition of a merge operation. It is calculated as the difference between `block_is` and `block_i0`, which are indices used in the sorting process.
- **Use**: `cnt_l` is used to determine the number of elements in the left partition during a merge sort operation.


---
### \_in\_r
- **Type**: `SORT_KEY_T **`
- **Description**: The variable `_in_r` is a pointer to a pointer of type `SORT_KEY_T`, which is a placeholder for a data type used in sorting operations. It is initialized by casting another pointer `_r1` to the same type.
- **Use**: This variable is used to hold a reference to a block of data that is being processed in a merge operation within a parallel sorting algorithm.


---
### in\_r
- **Type**: `SORT_KEY_T*`
- **Description**: The variable `in_r` is a pointer to a `SORT_KEY_T` type, which is typically used to represent a key in sorting operations. It is initialized to point to the first element of an array of `SORT_KEY_T` pointers, which is dereferenced from `_in_r`. This setup is part of a merge operation in a sorting algorithm.
- **Use**: `in_r` is used to access and manipulate the right half of a data block during a merge pass in a sorting algorithm.


---
### cnt\_r
- **Type**: `long`
- **Description**: The variable `cnt_r` is a long integer that represents the difference between two block indices, `block_i1` and `block_is`. It is used in the context of sorting operations, specifically in a merge pass function.
- **Use**: `cnt_r` is used to determine the number of elements in the right block of a merge operation during sorting.


---
### out
- **Type**: `SORT_KEY_T *`
- **Description**: The variable `out` is a pointer to a `SORT_KEY_T` type, which is determined by the `SORT_KEY_T` macro definition. It is used to point to the location where the merged result of two sorted halves of an array will be stored. The pointer is conditionally assigned to either `tmp` or `key` based on whether `in_l` overlaps with `key`. This ensures that the merge operation does not overwrite the input data before it is fully processed.
- **Use**: `out` is used to store the result of merging two sorted halves of an array, ensuring the merge operation is performed safely without data corruption.


---
### FD\_FOR\_ALL\_BEGIN
- **Type**: `macro`
- **Description**: `FD_FOR_ALL_BEGIN` is a macro used to define a parallel for loop construct in the context of the sorting functions. It is part of a set of macros that facilitate parallel processing by distributing work across multiple threads in a thread pool.
- **Use**: This macro is used to initiate a parallel for loop, allowing the sorting algorithm to execute tasks concurrently across multiple threads.


# Functions

---
### SORT\_<!-- {{#callable:SORT_}} -->
The `SORT_(fast_para)` function performs a parallelized sorting of an array of keys using a sample sort approach, optimizing for multi-threaded execution.
- **Inputs**:
    - `tpool`: A pointer to a thread pool (`fd_tpool_t`) used for parallel execution.
    - `t0`: The starting index of the thread pool range to use.
    - `t1`: The ending index of the thread pool range to use.
    - `key`: A pointer to the array of keys (`SORT_KEY_T`) to be sorted.
    - `cnt`: The number of elements in the `key` array to be sorted.
    - `scratch`: A pointer to a scratch space used for temporary storage during sorting.
    - `seed`: A random seed (`ulong`) used for sampling.
    - `stable`: An integer flag indicating whether a stable sort should be used (non-zero for stable, zero for unstable).
- **Control Flow**:
    - Check if the count of elements (`cnt`) is less than 2; if so, return the `key` array as is since no sorting is needed.
    - Calculate the optimal number of threads (`t_cnt`) to use based on the size of the data and the available threads, ensuring at least two threads are used if possible.
    - Sample the keys to estimate their distribution, sort the samples, and downsample them into pivots to partition the data into groups for parallel sorting.
    - Allocate memory for partitioning and temporary storage, and use the thread pool to count and copy keys into temporary storage based on the calculated pivots.
    - Convert the counts into a partitioning scheme and scatter the keys back into the original array in subsorted order.
    - Perform parallel subsorting on each partition using the thread pool, ensuring the final sorted order of the keys.
    - Return the sorted `key` array.
- **Output**: Returns a pointer to the sorted array of keys (`SORT_KEY_T *`).
- **Functions called**:
    - [`SORT_`](#SORT_)


---
### FD\_FOR\_ALL\_BEGIN<!-- {{#callable:FD_FOR_ALL_BEGIN}} -->
The `FD_FOR_ALL_BEGIN(SORT_(private_cntcpy_para), 1L)` function is responsible for counting and copying keys into a temporary array for parallel sorting, while avoiding false sharing.
- **Inputs**:
    - `tpool_base`: The base index of the thread pool, used to calculate offsets for thread-specific operations.
    - `t_cnt`: The total number of threads involved in the sorting operation.
    - `_key_cnt`: A pointer to an array where the count of keys assigned to each thread will be stored.
    - `key`: A pointer to the array of keys that need to be sorted.
    - `tmp`: A pointer to a temporary array where keys will be copied for further processing.
    - `pivot`: A pointer to an array of pivot values used to determine the range of keys each thread is responsible for sorting.
- **Control Flow**:
    - Allocate a local scratch array `key_cnt` to store counts of keys for each thread, avoiding false sharing.
    - Initialize the `key_cnt` array to zero using `memset`.
    - Iterate over the range of keys assigned to the current thread, determined by `block_i0` and `block_i1`.
    - For each key, determine which thread is responsible for sorting it by performing a binary search over the `pivot` array.
    - Increment the count for the responsible thread in the `key_cnt` array and copy the key to the `tmp` array.
    - After processing all keys, copy the local `key_cnt` array to the global `_key_cnt` array, offset by the thread's position in the pool.
- **Output**: The function does not return a value but modifies the `_key_cnt` array to reflect the count of keys assigned to each thread and copies keys into the `tmp` array for further processing.


