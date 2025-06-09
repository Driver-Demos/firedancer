# Purpose
This C source code file provides a collection of functions for computing various forms of square roots and cube roots of unsigned long integers. The primary functions include [`fd_ulong_approx_sqrt`](#fd_ulong_approx_sqrt), [`fd_ulong_round_sqrt`](#fd_ulong_round_sqrt), [`fd_ulong_floor_sqrt`](#fd_ulong_floor_sqrt), and [`fd_ulong_ceil_sqrt`](#fd_ulong_ceil_sqrt) for square roots, and [`fd_ulong_approx_cbrt`](#fd_ulong_approx_cbrt), [`fd_ulong_round_cbrt`](#fd_ulong_round_cbrt), [`fd_ulong_floor_cbrt`](#fd_ulong_floor_cbrt), and [`fd_ulong_ceil_cbrt`](#fd_ulong_ceil_cbrt) for cube roots. Each function is designed to compute the respective root with different rounding strategies: approximate, round, floor, and ceiling. The code employs mathematical techniques such as bit manipulation and Newton-Raphson iteration to achieve efficient and accurate calculations. The use of precomputed tables and integer arithmetic ensures that the operations are performed quickly and without floating-point arithmetic, which is crucial for performance in systems where floating-point operations are costly or unavailable.

The file is structured to provide a narrow but highly specialized functionality focused on root calculations, making it suitable for inclusion in larger projects where such mathematical operations are required. The functions are designed to be used as part of a library, as indicated by the inclusion of a header file (`fd_bits.h`) and the absence of a `main` function, suggesting that these functions are intended to be called from other parts of a program. The code does not define public APIs or external interfaces directly but provides a set of utility functions that can be integrated into applications requiring precise integer root calculations.
# Imports and Dependencies

---
- `fd_bits.h`


# Functions

---
### fd\_ulong\_approx\_sqrt<!-- {{#callable:fd_ulong_approx_sqrt}} -->
The `fd_ulong_approx_sqrt` function computes an approximate square root of a given unsigned long integer using bit manipulation and precomputed tables for efficiency.
- **Inputs**:
    - `x`: An unsigned long integer for which the approximate square root is to be calculated.
- **Control Flow**:
    - Check if the input x is zero; if so, return 0.
    - Find the most significant bit (MSB) position of x using [`fd_ulong_find_msb`](fd_bits_find_msb.h.driver.md#fd_ulong_find_msb).
    - Shift x left by (63 - MSB position) to obtain m, ensuring m is in the range [2^63, 2^64).
    - Calculate q as the integer division of the MSB position by 2, and r as the remainder of this division.
    - Determine the table index i using the formula i = 4*r + (m >> 61) & 3.
    - Extract the high bits h from m by shifting m right by 29 bits.
    - Use precomputed tables a and b to retrieve values based on index i.
    - Calculate the approximate square root using the formula (a[i] + b[i]*h + (1UL<<(61-q))) >> (62-q).
- **Output**: Returns an unsigned long integer representing the approximate square root of the input x.
- **Functions called**:
    - [`fd_ulong_find_msb`](fd_bits_find_msb.h.driver.md#fd_ulong_find_msb)


---
### fd\_ulong\_round\_sqrt<!-- {{#callable:fd_ulong_round_sqrt}} -->
The `fd_ulong_round_sqrt` function calculates the integer value of the square root of an unsigned long integer, rounding to the nearest integer with ties rounding towards zero.
- **Inputs**:
    - `x`: An unsigned long integer for which the square root is to be calculated and rounded.
- **Control Flow**:
    - Check if the input `x` is zero, and if so, return 0.
    - Compute an initial approximation of the square root using `fd_ulong_approx_sqrt(x)`.
    - Enter a loop to refine the approximation using a modified Newton-Raphson method until convergence is achieved.
    - In each iteration, calculate the denominator `den` as twice the current approximation `y`.
    - Calculate the numerator `num` as `x - y*y + y - 1UL`.
    - Check if `num` is within the range [0, `den`); if true, break the loop as convergence is achieved.
    - If not converged, adjust `y` by adding the result of the integer division of `num` by `den`, adjusted for negative numerators to ensure floor division.
- **Output**: The function returns the rounded integer value of the square root of the input `x`.
- **Functions called**:
    - [`fd_ulong_approx_sqrt`](#fd_ulong_approx_sqrt)


---
### fd\_ulong\_floor\_sqrt<!-- {{#callable:fd_ulong_floor_sqrt}} -->
The `fd_ulong_floor_sqrt` function calculates the largest integer `y` such that `y^2` is less than or equal to a given unsigned long integer `x`, effectively computing the floor of the square root of `x`.
- **Inputs**:
    - `x`: An unsigned long integer for which the floor of the square root is to be calculated.
- **Control Flow**:
    - Check if `x` is zero; if so, return 0 immediately as the square root of zero is zero.
    - Initialize `y` using the [`fd_ulong_approx_sqrt`](#fd_ulong_approx_sqrt) function to get an approximate square root of `x`.
    - Enter a loop to refine the value of `y` using a modified Newton-Raphson iteration: calculate `den` as `2*y + 1` and `num` as `x - y*y`.
    - Check if `num` is between 0 and `den`; if true, break the loop as the correct `y` is found.
    - If not, adjust `y` by adding the result of the integer division of `num` by `den`, ensuring the division is floor-style by adjusting `num` when negative.
    - Return the refined value of `y` as the result.
- **Output**: The function returns an unsigned long integer representing the floor of the square root of the input `x`.
- **Functions called**:
    - [`fd_ulong_approx_sqrt`](#fd_ulong_approx_sqrt)


---
### fd\_ulong\_ceil\_sqrt<!-- {{#callable:fd_ulong_ceil_sqrt}} -->
The `fd_ulong_ceil_sqrt` function calculates the smallest integer greater than or equal to the square root of a given unsigned long integer.
- **Inputs**:
    - `x`: An unsigned long integer for which the ceiling of the square root is to be calculated.
- **Control Flow**:
    - Check if the input `x` is zero; if so, return 0.
    - Initialize `y` with an approximate square root of `x` using [`fd_ulong_approx_sqrt`](#fd_ulong_approx_sqrt).
    - Enter a loop to refine `y` using a modified Newton-Raphson iteration until convergence is achieved.
    - In each iteration, calculate `tmp` as `y << 1`, `den` as `tmp - 1`, and `num` as `x - y*y + tmp - 2`.
    - Check if `num` is within the range [0, `den`); if true, break the loop as convergence is achieved.
    - If not converged, adjust `y` by adding the result of the division of `num` by `den`, adjusted for negative numerators.
- **Output**: Returns the smallest integer `y` such that `y` is greater than or equal to the square root of `x`.
- **Functions called**:
    - [`fd_ulong_approx_sqrt`](#fd_ulong_approx_sqrt)


---
### fd\_ulong\_approx\_cbrt<!-- {{#callable:fd_ulong_approx_cbrt}} -->
The `fd_ulong_approx_cbrt` function computes an approximate cube root of an unsigned long integer using bit manipulation and precomputed constants.
- **Inputs**:
    - `x`: An unsigned long integer for which the approximate cube root is to be calculated.
- **Control Flow**:
    - Check if the input `x` is zero; if so, return 0.
    - Find the most significant bit position `e` of `x` using [`fd_ulong_find_msb`](fd_bits_find_msb.h.driver.md#fd_ulong_find_msb).
    - Shift `x` left by `(63-e)` to get `m`, ensuring it is in the range [2^63, 2^64).
    - Calculate `q` as the integer division of `e` by 3, and `r` as the remainder of `e` divided by 3.
    - Determine the index `i` using `2*r + (m >> 62) & 1UL`, which is used to select precomputed constants.
    - Compute `h` by shifting `m` right by 30 bits and casting to an unsigned long.
    - Use precomputed arrays `a` and `b` to calculate the result as `(a[i] + b[i]*h + (1UL<<(61-q))) >> (62-q)`.
- **Output**: The function returns an unsigned long integer representing the approximate cube root of the input `x`.
- **Functions called**:
    - [`fd_ulong_find_msb`](fd_bits_find_msb.h.driver.md#fd_ulong_find_msb)


---
### fd\_ulong\_round\_cbrt<!-- {{#callable:fd_ulong_round_cbrt}} -->
The `fd_ulong_round_cbrt` function calculates the integer cube root of a given unsigned long integer `x`, rounding to the nearest integer.
- **Inputs**:
    - `x`: An unsigned long integer for which the cube root is to be calculated and rounded.
- **Control Flow**:
    - Check if `x` is zero; if so, return 0.
    - Initialize `y` with an approximate cube root of `x` using [`fd_ulong_approx_cbrt`](#fd_ulong_approx_cbrt).
    - Enter a loop to refine `y` using a Newton-Raphson-like method adapted for integer arithmetic.
    - Calculate `ysq` as `y*y`.
    - Compute `num` as `4*(x - y*ysq) + 6*ysq - 3*y`.
    - Compute `den` as `12*ysq + 1`.
    - Check if `num` is between 0 and `den`; if true, break the loop.
    - Adjust `y` by adding the result of the integer division of `num` by `den`, adjusted for negative values using `fd_long_if`.
    - Return the refined value of `y`.
- **Output**: The function returns the integer cube root of `x`, rounded to the nearest integer.
- **Functions called**:
    - [`fd_ulong_approx_cbrt`](#fd_ulong_approx_cbrt)


---
### fd\_ulong\_floor\_cbrt<!-- {{#callable:fd_ulong_floor_cbrt}} -->
The `fd_ulong_floor_cbrt` function calculates the largest integer cube root of a given unsigned long integer `x` that is less than or equal to `x`.
- **Inputs**:
    - `x`: An unsigned long integer for which the floor of the cube root is to be calculated.
- **Control Flow**:
    - Check if `x` is zero; if so, return 0.
    - Initialize `y` with an approximate cube root of `x` using [`fd_ulong_approx_cbrt`](#fd_ulong_approx_cbrt).
    - Enter a loop to refine `y` using a Newton-Raphson-like method for integer arithmetic.
    - Calculate `ysq` as `y*y` and `num` as `x - y*ysq`.
    - Calculate `den` as `3*(ysq+y) + 1`.
    - Check if `num` is between 0 and `den`; if true, break the loop.
    - Adjust `y` by adding the result of the integer division of `num` by `den`, adjusted for negative numerators.
    - Return the refined value of `y`.
- **Output**: The function returns the largest integer `y` such that `y^3` is less than or equal to `x`.
- **Functions called**:
    - [`fd_ulong_approx_cbrt`](#fd_ulong_approx_cbrt)


---
### fd\_ulong\_ceil\_cbrt<!-- {{#callable:fd_ulong_ceil_cbrt}} -->
The `fd_ulong_ceil_cbrt` function calculates the smallest integer greater than or equal to the cube root of a given unsigned long integer.
- **Inputs**:
    - `x`: An unsigned long integer for which the ceiling of the cube root is to be calculated.
- **Control Flow**:
    - Check if the input `x` is zero; if so, return 0 immediately as the cube root of zero is zero.
    - Initialize `y` with an approximate cube root of `x` using the [`fd_ulong_approx_cbrt`](#fd_ulong_approx_cbrt) function.
    - Enter a loop to refine the value of `y` using a Newton-Raphson-like method adapted for integer arithmetic.
    - Calculate `ysq` as the square of `y` and `tmp` as `3 * (ysq - y)`.
    - Compute `num` as `x - y * ysq + tmp` and `den` as `tmp + 1`.
    - Check if `num` is non-negative and less than `den`; if true, break the loop as the correct `y` has been found.
    - If the loop continues, adjust `y` by adding the result of the integer division of `num` by `den`, adjusted for negative numerators using `fd_long_if`.
- **Output**: The function returns an unsigned long integer representing the smallest integer greater than or equal to the cube root of the input `x`.
- **Functions called**:
    - [`fd_ulong_approx_cbrt`](#fd_ulong_approx_cbrt)


