# Purpose
This C source code file is designed as a test suite for statistical and random number generation functions. It includes functionality to test the accuracy and robustness of statistical operations such as averaging and filtering across various data types, including signed and unsigned integers, floats, and doubles. The code utilizes a random number generator to create test data, which is then used to validate the statistical functions provided by the `fd_stat` library. The tests ensure that the functions perform correctly under different conditions and data distributions, such as normal and exponential distributions.

The file is structured as an executable program, with a [`main`](#main) function that orchestrates the testing process. It includes several macros to streamline the testing of different data types and conditions, ensuring comprehensive coverage. The code also includes conditional compilation directives to handle different data types and features, such as 128-bit integers and double precision floating-point numbers, depending on the system's capabilities. The program initializes and finalizes the random number generator and logs the results of the tests, indicating whether they pass or fail. This file is not intended to be a library or header file for external use but rather a standalone executable for internal testing purposes.
# Imports and Dependencies

---
- `../fd_util.h`
- `../../util/math/fd_stat.h`
- `math.h`


# Functions

---
### fd\_rng\_float<!-- {{#callable:fd_rng_float}} -->
The `fd_rng_float` function generates a random floating-point number uniformly distributed in the range [-0.5, 0.5].
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the random number generator state.
- **Control Flow**:
    - The function calls `fd_rng_float_c` with the `rng` argument to generate a random float.
    - It subtracts 0.5 from the result of `fd_rng_float_c` to shift the range from [0, 1) to [-0.5, 0.5).
    - The function returns the adjusted random float.
- **Output**: A random float uniformly distributed in the range [-0.5, 0.5].


---
### fd\_rng\_double<!-- {{#callable:fd_rng_double}} -->
The `fd_rng_double` function generates a double-precision floating-point random number uniformly distributed in the range [-0.5, +0.5].
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the random number generator state.
- **Control Flow**:
    - The function calls `fd_rng_double_c` with the `rng` argument to generate a random double-precision floating-point number.
    - It subtracts 0.5 from the result of `fd_rng_double_c` to shift the range from [0, 1) to [-0.5, 0.5).
    - The function returns the adjusted random number.
- **Output**: A double-precision floating-point number uniformly distributed in the range [-0.5, +0.5].


---
### main<!-- {{#callable:main}} -->
The `main` function initializes a random number generator, performs a series of statistical tests on integer and floating-point data types, and logs the results.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program environment using `fd_boot` with command-line arguments.
    - Create and join a random number generator `rng`.
    - Define and execute `AVG2_INT_TEST` macro to test average calculations for various integer types.
    - Define and execute `FILT_TEST` macro to test filtering operations for various data types over 1,000,000 iterations.
    - Perform robust normal and exponential fitting tests on arrays of floats over 1,000 iterations, checking the accuracy of estimated parameters against generated data.
    - If `FD_HAS_DOUBLE` is defined, perform similar robust fitting tests on arrays of doubles.
    - Delete the random number generator and log a success message.
    - Terminate the program with `fd_halt` and return 0.
- **Output**: The function returns an integer value of 0, indicating successful execution.


