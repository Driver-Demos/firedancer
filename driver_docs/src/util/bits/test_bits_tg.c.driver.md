# Purpose
This C source code file is a comprehensive test suite designed to validate the functionality of various bit manipulation operations across different data types, including `uchar`, `ushort`, `uint`, `ulong`, and potentially `uint128` if the platform supports 128-bit integers. The code is structured as a standalone executable with a [`main`](#main) function that initializes a random number generator and systematically tests a wide range of bit manipulation functions. These functions include operations for checking power of two, bit masking, setting, clearing, flipping, extracting, and inserting bits, as well as operations for counting bits, finding least and most significant bits, and performing bitwise shifts and rotations.

The test suite is organized into sections, each dedicated to a specific data type, and employs a series of assertions to ensure that each bit manipulation function behaves as expected. The code uses macros and functions from an external utility library (`fd_util.h`) to perform these operations, indicating that the file is part of a larger codebase. The tests are extensive, covering edge cases and random scenarios to ensure robustness. The file does not define public APIs or external interfaces but rather serves as an internal validation tool to verify the correctness of bit manipulation utilities within the project.
# Imports and Dependencies

---
- `../fd_util.h`


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function initializes a random number generator and performs extensive bit manipulation tests on various data types, including uchar, ushort, uint, ulong, and others, to verify the correctness of bit manipulation functions.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program with `fd_boot` using command-line arguments.
    - Create and join a random number generator `rng` using `fd_rng_new` and `fd_rng_join`.
    - Perform bit manipulation tests for `uchar`, `ushort`, `uint`, `ulong`, and other types, including checking power of two, bit masking, setting, clearing, flipping, inserting, and extracting bits.
    - Test least significant bit (LSB) and most significant bit (MSB) operations, including finding, setting, clearing, flipping, and extracting LSBs and MSBs.
    - Test bitwise operations like blending, conditional selection (`fd_if`), absolute value, minimum, maximum, and swapping values.
    - Test bit shifting and rotating operations for various data types.
    - Delete the random number generator using `fd_rng_delete` and `fd_rng_leave`.
    - Log a success message and halt the program with `fd_halt`.
- **Output**: The function returns an integer, 0, indicating successful execution.


