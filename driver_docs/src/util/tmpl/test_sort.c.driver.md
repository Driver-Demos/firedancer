# Purpose
This C source code file is designed to test various sorting algorithms on arrays of floating-point numbers. It includes functionality for sorting arrays in both ascending and descending order using different methods, such as insertion sort, stable sort, and in-place sort. The code defines macros to facilitate the inclusion of sorting logic from an external file (`fd_sort.c`) and uses these macros to create specific sorting functions like `sort_up` and `sort_dn` for ascending and descending order, respectively. The file also includes a [`shuffle`](#shuffle) function to randomize the order of elements in an array, which is used to test the robustness of the sorting algorithms under different initial conditions.

The main function orchestrates a series of tests to validate the correctness of the sorting functions. It initializes random number generation, sets up test arrays, and performs sorting operations on these arrays, checking the results against expected outcomes using assertions. The tests cover various scenarios, including sorting already sorted arrays, reverse-sorted arrays, and randomly shuffled arrays. Additionally, the code tests the performance of the sorting algorithms with different array sizes and configurations, logging the results of each test case. This file serves as a comprehensive test suite for ensuring the reliability and efficiency of the sorting algorithms implemented in the included `fd_sort.c` file.
# Imports and Dependencies

---
- `../fd_util.h`
- `math.h`
- `fd_sort.c`


# Functions

---
### shuffle<!-- {{#callable:shuffle}} -->
The `shuffle` function randomly shuffles elements from an input array `x` into an output array `y` using a given random number generator `rng`.
- **Inputs**:
    - `rng`: A pointer to a random number generator of type `fd_rng_t` used to generate random indices for shuffling.
    - `y`: A pointer to the output array of type `TYPE` where the shuffled elements will be stored.
    - `x`: A pointer to the input array of type `TYPE` containing the elements to be shuffled.
    - `cnt`: An unsigned long integer representing the number of elements in the arrays `x` and `y` to be shuffled.
- **Control Flow**:
    - Iterate over each element index `i` from 0 to `cnt-1`.
    - Copy the element from `x[i]` to `y[i]`.
    - Generate a random index `j` using the random number generator `rng`, ensuring `j` is within the range [0, i].
    - Swap the elements `y[i]` and `y[j]` to shuffle the array.
- **Output**: Returns a pointer to the shuffled output array `y`.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes a random number generator and tests various sorting algorithms on arrays of floats, logging the results of each test.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program with `fd_boot` and set up a random number generator `rng`.
    - Declare arrays `ref`, `tst`, and `tmp` of type `TYPE` with size `MAX`.
    - Iterate over different counts (`cnt`) and test the `sort_up_insert` and `sort_dn_insert` functions with various initializations of `tst` and `ref`, logging results.
    - Repeat similar tests for `sort_up_stable_fast`, `sort_dn_stable_fast`, `sort_up_stable`, `sort_dn_stable`, `sort_up_inplace`, `sort_dn_inplace`, `sort_up_select`, and `sort_dn_select` functions, logging results for each.
    - Perform additional tests with random data for `sort_up_stable_fast`, `sort_up_stable`, `sort_up_inplace`, `sort_dn_stable_fast`, `sort_dn_stable`, and `sort_dn_inplace` functions.
    - Test the `sort_up_search_geq` function with various inputs and log results.
    - Clean up by deleting the random number generator and halting the program.
- **Output**: The function returns an integer `0` to indicate successful execution.
- **Functions called**:
    - [`shuffle`](#shuffle)


