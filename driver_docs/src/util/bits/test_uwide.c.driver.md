# Purpose
This C source code file is a comprehensive test suite designed to validate the functionality of operations on 128-bit unsigned integers, specifically when the `FD_HAS_INT128` capability is available. The code is structured to perform a series of arithmetic operations such as addition, subtraction, multiplication, division, and bitwise shifts on randomly generated 128-bit integers. It utilizes a custom utility library (`fd_util.h`) and a wide integer library (`fd_uwide.h`) to handle these operations. The main function initializes a random number generator and iterates through a large number of test cases, each time generating random test vectors and verifying the correctness of the operations by comparing the results of the custom wide integer functions against expected outcomes. If any discrepancies are found, detailed error logs are generated to aid in debugging.

The file is intended to be an executable test program, as indicated by the presence of a [`main`](#main) function. It does not define public APIs or external interfaces but rather serves as an internal validation tool to ensure the reliability and accuracy of the wide integer operations provided by the `fd_uwide` library. The code is structured to skip execution if the `FD_HAS_INT128` capability is not present, logging a warning instead. This ensures that the test suite is only run in environments where 128-bit integer support is available, maintaining the integrity and relevance of the tests.
# Imports and Dependencies

---
- `../fd_util.h`
- `fd_uwide.h`


# Functions

---
### split\_hi<!-- {{#callable:split_hi}} -->
The `split_hi` function extracts the higher 64 bits from a 128-bit unsigned integer.
- **Inputs**:
    - `x`: A 128-bit unsigned integer (uint128) from which the higher 64 bits are to be extracted.
- **Control Flow**:
    - The function takes a 128-bit unsigned integer `x` as input.
    - It performs a right bitwise shift of 64 positions on `x`, effectively moving the higher 64 bits to the lower 64-bit position.
    - The result of the shift is then cast to a 64-bit unsigned long integer (ulong).
- **Output**: The function returns the higher 64 bits of the input 128-bit unsigned integer as a 64-bit unsigned long integer.


---
### split\_lo<!-- {{#callable:split_lo}} -->
The `split_lo` function extracts the lower 64 bits from a 128-bit unsigned integer.
- **Inputs**:
    - `x`: A 128-bit unsigned integer (`uint128`) from which the lower 64 bits are to be extracted.
- **Control Flow**:
    - The function takes a 128-bit unsigned integer `x` as input.
    - It casts `x` to a 64-bit unsigned integer (`ulong`), effectively extracting the lower 64 bits of `x`.
- **Output**: The function returns the lower 64 bits of the input 128-bit unsigned integer as a 64-bit unsigned integer (`ulong`).


---
### join<!-- {{#callable:join}} -->
The `join` function combines two 64-bit unsigned long integers into a single 128-bit unsigned integer.
- **Inputs**:
    - `xh`: The high 64 bits of the 128-bit integer, represented as an unsigned long integer.
    - `xl`: The low 64 bits of the 128-bit integer, represented as an unsigned long integer.
- **Control Flow**:
    - The function casts the high 64-bit integer `xh` to a 128-bit integer and shifts it left by 64 bits.
    - It then casts the low 64-bit integer `xl` to a 128-bit integer.
    - The function performs a bitwise OR operation between the shifted high 128-bit integer and the low 128-bit integer to combine them into a single 128-bit integer.
- **Output**: A 128-bit unsigned integer that is the result of combining the high and low 64-bit integers.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment and logs a warning if the `FD_HAS_INT128` capability is not available, then halts the program.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with the command-line arguments.
    - Log a warning message indicating that the unit test requires `FD_HAS_INT128` capability.
    - Call `fd_halt` to terminate the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


