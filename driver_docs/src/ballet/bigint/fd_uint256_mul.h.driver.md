# Purpose
This C source code file provides specialized functionality for performing arithmetic operations on 256-bit unsigned integers, specifically using Montgomery multiplication. The code is part of a larger library, as indicated by the inclusion guard that suggests it should be included via `fd_uint256.h`. The primary focus of this file is to implement efficient arithmetic operations, such as addition and multiplication, on large integers that are represented using four 64-bit limbs. The file includes utility functions for subtraction with borrow, vector multiplication, and addition with carry, which are essential for handling operations on these large numbers.

The code is designed to be highly optimized for performance, leveraging compiler-specific attributes like `__attribute__((always_inline))` and `__attribute__((optimize("unroll-loops"))` to ensure inlining and loop unrolling, respectively. This is crucial for cryptographic applications where performance and security are paramount. The file also includes conditional compilation to utilize platform-specific instructions, such as x86 intrinsics, when available. The implementation is intended to support various cryptographic field arithmetic operations, including those for bn254 and potentially for other elliptic curves like secp256k1 and ed25519, as indicated by the TODO comments. The file defines internal functions and macros, such as `FD_UINT256_FP_MUL_IMPL`, to facilitate the creation of field-specific multiplication functions, ensuring that the arithmetic operations are both efficient and reusable across different cryptographic contexts.
# Imports and Dependencies

---
- `x86intrin.h`


# Functions

---
### fd\_ulong\_sub\_borrow<!-- {{#callable:fd_ulong_sub_borrow}} -->
The `fd_ulong_sub_borrow` function performs subtraction of two unsigned long integers with an optional initial borrow and outputs the result and a borrow flag.
- **Inputs**:
    - `r`: A pointer to an unsigned long where the result of the subtraction (a0 - a1) will be stored.
    - `b`: A pointer to an integer where the borrow flag will be stored, indicating if a borrow occurred during the subtraction.
    - `a0`: The minuend, an unsigned long integer from which a1 will be subtracted.
    - `a1`: The subtrahend, an unsigned long integer to be subtracted from a0.
    - `bi`: An integer representing the initial borrow flag, which is added to a1 before subtraction if set.
- **Control Flow**:
    - Check if the platform supports x86 instructions.
    - If x86 is supported, use the `_subborrow_u64` intrinsic to perform the subtraction with borrow, storing the result in `r` and the borrow flag in `b`.
    - If x86 is not supported, increment `a1` by 1 if `bi` is true (non-zero).
    - Perform the subtraction `a0 - a1` and store the result in `r`.
    - Set the borrow flag `b` to true (1) if `a0` is less than `a1`, otherwise set it to false (0).
- **Output**: The function outputs the result of the subtraction in `r` and a borrow flag in `b` indicating whether a borrow occurred.


---
### fd\_ulong\_vec\_mul<!-- {{#callable:fd_ulong_vec_mul}} -->
The `fd_ulong_vec_mul` function performs element-wise multiplication of a 4-element unsigned long vector by a scalar, storing the lower and higher 64-bit results separately.
- **Inputs**:
    - `l`: An array of 4 unsigned long integers to store the lower 64 bits of the multiplication results.
    - `h`: An array of 4 unsigned long integers to store the higher 64 bits of the multiplication results.
    - `a`: A constant array of 4 unsigned long integers representing the vector to be multiplied.
    - `b`: An unsigned long integer scalar by which each element of the vector 'a' is multiplied.
- **Control Flow**:
    - The function iterates over each element of the input vector 'a'.
    - For each element, it calls [`fd_ulong_mul128`](#fd_ulong_mul128) to perform a 128-bit multiplication of the element with the scalar 'b'.
    - The results of the multiplication are split into lower and higher 64-bit parts, which are stored in the corresponding positions in the 'l' and 'h' arrays.
- **Output**: The function does not return a value; it modifies the 'l' and 'h' arrays in place to store the results of the multiplications.
- **Functions called**:
    - [`fd_ulong_mul128`](#fd_ulong_mul128)


---
### fd\_ulong\_add\_carry4<!-- {{#callable:fd_ulong_add_carry4}} -->
The `fd_ulong_add_carry4` function performs addition of three unsigned long integers and one unsigned char, handling carry propagation and storing the result and carry in the provided pointers.
- **Inputs**:
    - `l`: A pointer to an unsigned long where the result of the addition will be stored.
    - `h`: A pointer to an unsigned char where the carry from the addition will be stored.
    - `a0`: The first unsigned long integer to be added.
    - `a1`: The second unsigned long integer to be added.
    - `a2`: The third unsigned long integer to be added.
    - `a3`: The unsigned char to be added.
- **Control Flow**:
    - Calculate the sum of a0 and a1, storing the result in r0 and checking for carry by comparing r0 with a0.
    - Calculate the sum of a2 and a3, storing the result in r1 and checking for carry by comparing r1 with a2.
    - Add r0 and r1, storing the result in the location pointed to by l.
    - Calculate the final carry by checking if the sum of r0 and r1 is less than r0, and add the previously calculated carries c0 and c1, storing the result in the location pointed to by h.
- **Output**: The function outputs the sum of the inputs in the location pointed to by l and the carry in the location pointed to by h.


---
### fd\_ulong\_mul128<!-- {{#callable:fd_ulong_mul128}} -->
The `fd_ulong_mul128` function performs a 128-bit multiplication of two 64-bit unsigned integers and stores the result in two separate 64-bit unsigned integers representing the lower and higher parts of the product.
- **Inputs**:
    - `l`: A pointer to an unsigned long where the lower 64 bits of the product will be stored.
    - `h`: A pointer to an unsigned long where the higher 64 bits of the product will be stored.
    - `a`: A 64-bit unsigned integer representing the first operand.
    - `b`: A 64-bit unsigned integer representing the second operand.
- **Control Flow**:
    - Calculate the lower 32 bits of both operands and multiply them to get `lo_lo`.
    - Calculate the higher 32 bits of `a` and the lower 32 bits of `b`, then multiply them to get `hi_lo`.
    - Calculate the lower 32 bits of `a` and the higher 32 bits of `b`, then multiply them to get `lo_hi`.
    - Calculate the higher 32 bits of both operands and multiply them to get `hi_hi`.
    - Sum the cross products `lo_lo`, `hi_lo`, and `lo_hi` to get `cross`, ensuring no overflow occurs.
    - Calculate the upper part of the product by summing the higher parts of `hi_lo`, `cross`, and `hi_hi`.
    - Store the upper part of the product in `*h` and the lower part in `*l` by combining `cross` and `lo_lo`.
- **Output**: The function outputs the 128-bit product of `a` and `b` split into two 64-bit unsigned integers, with the lower part stored in `*l` and the higher part stored in `*h`.


