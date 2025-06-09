# Purpose
The `fd_curve25519_scalar.h` file is a C header file that provides a public API for operations on Curve25519 scalars. Curve25519 is a widely used elliptic curve for cryptographic applications, and this file specifically deals with scalar arithmetic operations, which are fundamental in elliptic curve cryptography. The file defines several constants and functions for performing arithmetic operations such as addition, subtraction, multiplication, and modular reduction on 256-bit scalars, which are represented in 32-byte little-endian form. It also includes functions for scalar validation, inversion, and batch inversion, which are crucial for cryptographic computations.

The header file is structured to offer a collection of inline functions and static constants that facilitate efficient scalar arithmetic. It includes functions like [`fd_curve25519_scalar_reduce`](#fd_curve25519_scalar_reduce), [`fd_curve25519_scalar_muladd`](#fd_curve25519_scalar_muladd), and [`fd_curve25519_scalar_validate`](#fd_curve25519_scalar_validate), which are essential for reducing scalars modulo a large prime, performing modular multiplication and addition, and validating scalar representations, respectively. The file also provides utility functions for setting scalars from 64-bit integers and computing the windowed non-adjacent form (wNAF) of scalars, which is useful for optimizing scalar multiplication. The API is designed to be used in cryptographic applications where performance and correctness are critical, and it explicitly warns against using these operations with secret data due to their variable-time nature.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_curve25519\_scalar\_zero
- **Type**: ``static const uchar[32]``
- **Description**: The `fd_curve25519_scalar_zero` is a static constant array of 32 unsigned characters, all initialized to zero. This array represents the zero scalar in the context of Curve25519 operations, which is a cryptographic curve used in various encryption protocols.
- **Use**: This variable is used as a zero scalar in arithmetic operations involving Curve25519, such as in the `fd_curve25519_scalar_mul` function to perform scalar multiplication with zero.


---
### fd\_curve25519\_scalar\_one
- **Type**: `static const uchar[32]`
- **Description**: The `fd_curve25519_scalar_one` is a 32-byte array representing the scalar value 'one' in the Curve25519 elliptic curve cryptography context. It is initialized with the first byte set to 1 and the remaining bytes set to 0, effectively representing the number 1 in little-endian format.
- **Use**: This variable is used as a constant scalar value for operations that require the identity element of multiplication in the Curve25519 scalar arithmetic.


---
### fd\_curve25519\_scalar\_minus\_one
- **Type**: `static const uchar[32]`
- **Description**: The `fd_curve25519_scalar_minus_one` is a 32-byte array representing the value of the Curve25519 scalar l-1, where l is a large prime number used in elliptic curve cryptography. This value is stored in little-endian format and is used in various scalar operations within the Curve25519 context.
- **Use**: This variable is used in scalar arithmetic operations, such as subtraction and negation, within the Curve25519 cryptographic functions.


---
### fd\_curve25519\_scalar\_reduce
- **Type**: `function pointer`
- **Description**: The `fd_curve25519_scalar_reduce` function computes the modulus of a 512-bit value `s` with respect to a large constant `l`, which is specific to the Curve25519 cryptographic operations. The input `s` is provided in a 64-byte little-endian format, and the result is stored in a 32-byte little-endian format.
- **Use**: This function is used to reduce a large scalar value to a smaller one that fits within the bounds of the Curve25519 field, ensuring compatibility with cryptographic operations.


---
### fd\_curve25519\_scalar\_muladd
- **Type**: `function pointer`
- **Description**: The `fd_curve25519_scalar_muladd` is a function that computes the result of the expression (a*b + c) modulo l, where a, b, and c are 256-bit values represented in 32-byte little-endian form. The function returns a pointer to the result, which is stored in the provided 32-byte array `s`. The modulo operation is performed with respect to the constant l, which is defined as 2^252 + 27742317777372353535851937790883648493.
- **Use**: This function is used to perform modular arithmetic operations on 256-bit scalar values in the context of Curve25519 cryptographic computations.


# Functions

---
### fd\_curve25519\_scalar\_validate<!-- {{#callable:fd_curve25519_scalar_validate}} -->
The function `fd_curve25519_scalar_validate` checks if a given 32-byte Ed25519 scalar is in its canonical form by comparing it to a predefined maximum value.
- **Inputs**:
    - `s`: A 32-byte array representing the Ed25519 scalar to be validated.
- **Control Flow**:
    - Load the 32-byte scalar `s` into four 8-byte unsigned long integers `s0`, `s1`, `s2`, and `s3`.
    - Load the predefined maximum scalar value (l-1) into four 8-byte unsigned long integers `l0`, `l1`, `l2`, and `l3`.
    - Compare `s3` with `l3`; if `s3` is less, return `s`.
    - If `s3` equals `l3`, compare `s2` with `l2`; if `s2` is less, return `s`.
    - If `s2` equals `l2`, compare `s1` with `l1`; if `s1` is less, return `s`.
    - If `s1` equals `l1`, compare `s0` with `l0`; if `s0` is less than or equal to `l0`, return `s`.
    - If none of the above conditions are met, return `NULL`.
- **Output**: Returns the input scalar `s` if it is in canonical form, otherwise returns `NULL`.


---
### fd\_curve25519\_scalar\_mul<!-- {{#callable:fd_curve25519_scalar_mul}} -->
The `fd_curve25519_scalar_mul` function performs scalar multiplication of two 256-bit values using the Curve25519 algorithm.
- **Inputs**:
    - `s`: A pointer to a 32-byte array where the result of the scalar multiplication will be stored.
    - `a`: A pointer to a 32-byte array representing the first 256-bit scalar operand in little-endian form.
    - `b`: A pointer to a 32-byte array representing the second 256-bit scalar operand in little-endian form.
- **Control Flow**:
    - The function calls [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd) with the provided arguments `s`, `a`, and `b`, and a constant zero scalar `fd_curve25519_scalar_zero` as the third operand.
    - The [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd) function computes the result of the operation `(a * b + 0) mod l`, where `l` is a predefined large constant specific to Curve25519.
    - The result of the multiplication is stored in the memory location pointed to by `s`.
- **Output**: A pointer to the 32-byte array `s` containing the result of the scalar multiplication.
- **Functions called**:
    - [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd)


---
### fd\_curve25519\_scalar\_add<!-- {{#callable:fd_curve25519_scalar_add}} -->
The `fd_curve25519_scalar_add` function computes the sum of two 256-bit scalars modulo a predefined large number, using the Curve25519 scalar arithmetic.
- **Inputs**:
    - `s`: A pointer to a 32-byte array where the result of the addition will be stored.
    - `a`: A pointer to a 32-byte array representing the first scalar operand in little-endian format.
    - `b`: A pointer to a 32-byte array representing the second scalar operand in little-endian format.
- **Control Flow**:
    - The function calls [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd) with the parameters `s`, `a`, `fd_curve25519_scalar_one`, and `b`.
    - The [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd) function computes the result of the operation `(a * 1 + b) mod l`, where `l` is a large predefined constant specific to Curve25519.
    - The result of the addition is stored in the memory location pointed to by `s`.
- **Output**: A pointer to the 32-byte array `s` containing the result of the scalar addition.
- **Functions called**:
    - [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd)


---
### fd\_curve25519\_scalar\_sub<!-- {{#callable:fd_curve25519_scalar_sub}} -->
The `fd_curve25519_scalar_sub` function computes the subtraction of two 256-bit scalar values modulo a large prime, using a multiplication-addition operation.
- **Inputs**:
    - `s`: A pointer to a 32-byte array where the result of the subtraction will be stored.
    - `a`: A pointer to a 32-byte array representing the first scalar operand in little-endian format.
    - `b`: A pointer to a 32-byte array representing the second scalar operand in little-endian format.
- **Control Flow**:
    - The function is defined as an inline static function, indicating it is intended for use within the same translation unit for performance reasons.
    - The function does not directly implement subtraction but instead calls [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd) with specific parameters to achieve the subtraction.
    - The parameters passed to [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd) are: `fd_curve25519_scalar_minus_one` as the multiplier for `b`, `b` itself, and `a` as the addend.
    - The use of `fd_curve25519_scalar_minus_one` effectively negates `b` before adding it to `a`, achieving the subtraction operation.
- **Output**: The function returns a pointer to the 32-byte array `s`, which contains the result of the subtraction operation.
- **Functions called**:
    - [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd)


---
### fd\_curve25519\_scalar\_neg<!-- {{#callable:fd_curve25519_scalar_neg}} -->
The `fd_curve25519_scalar_neg` function computes the negation of a Curve25519 scalar modulo a large prime number.
- **Inputs**:
    - `s`: A pointer to a 32-byte array where the result will be stored.
    - `a`: A pointer to a 32-byte array representing the scalar to be negated.
- **Control Flow**:
    - The function calls [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd) with parameters: the result array `s`, the constant `fd_curve25519_scalar_minus_one` representing -1, the input scalar `a`, and the constant `fd_curve25519_scalar_zero` representing 0.
    - The [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd) function computes the result of (-1 * a + 0) mod l, effectively negating the scalar `a`.
- **Output**: A pointer to the 32-byte array `s` containing the negated scalar.
- **Functions called**:
    - [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd)


---
### fd\_curve25519\_scalar\_set<!-- {{#callable:fd_curve25519_scalar_set}} -->
The function `fd_curve25519_scalar_set` copies a 32-byte scalar value from one location to another.
- **Inputs**:
    - `s`: A pointer to the destination buffer where the 32-byte scalar will be copied.
    - `a`: A pointer to the source buffer containing the 32-byte scalar to be copied.
- **Control Flow**:
    - The function calls `fd_memcpy` to copy 32 bytes from the source buffer `a` to the destination buffer `s`.
- **Output**: A pointer to the destination buffer `s` after the copy operation is completed.


---
### fd\_curve25519\_scalar\_from\_u64<!-- {{#callable:fd_curve25519_scalar_from_u64}} -->
The function `fd_curve25519_scalar_from_u64` initializes a 32-byte array to zero and sets its first 8 bytes to a given 64-bit unsigned integer.
- **Inputs**:
    - `s`: A pointer to an unsigned character array where the scalar will be stored.
    - `x`: A 64-bit unsigned integer that will be converted into a scalar and stored in the array.
- **Control Flow**:
    - The function begins by setting all 32 bytes of the array pointed to by `s` to zero using `fd_memset`.
    - The first 8 bytes of the array are then set to the value of `x` by casting `s` to a pointer to `ulong` and dereferencing it.
    - Finally, the function returns the pointer `s`.
- **Output**: The function returns the pointer to the 32-byte array `s` that now contains the scalar representation of the input `x`.


---
### fd\_curve25519\_scalar\_inv<!-- {{#callable:fd_curve25519_scalar_inv}} -->
The `fd_curve25519_scalar_inv` function computes the modular inverse of a 256-bit scalar in the Curve25519 field.
- **Inputs**:
    - `s`: A pointer to a 32-byte array where the result (the inverse of 'a') will be stored.
    - `a`: A pointer to a 32-byte array representing the scalar to be inverted.
- **Control Flow**:
    - Initialize a temporary 32-byte array 't' and copy the contents of 'a' into both 't' and 's'.
    - Square 't' and multiply 's' by 't' to handle the first two bits of the inversion process.
    - Square 't' again to handle the third bit, which is zero, so 's' is not updated.
    - Iterate from bit 3 to bit 252, squaring 't' in each iteration.
    - For each bit that is set in the precomputed 'fd_curve25519_scalar_minus_one', multiply 's' by 't'.
- **Output**: Returns a pointer to the 32-byte array 's', which contains the modular inverse of the input scalar 'a'.
- **Functions called**:
    - [`fd_curve25519_scalar_mul`](#fd_curve25519_scalar_mul)


---
### fd\_curve25519\_scalar\_batch\_inv<!-- {{#callable:fd_curve25519_scalar_batch_inv}} -->
The function `fd_curve25519_scalar_batch_inv` computes the batch inversion of a set of scalars in the Curve25519 field, storing the results in the provided arrays.
- **Inputs**:
    - `s`: An array of size 32 * sz to store the inverted scalars.
    - `allinv`: An array of size 32 to store the product of all inverses.
    - `a`: An array of size 32 * sz containing the scalars to be inverted.
    - `sz`: The number of scalars to be inverted.
- **Control Flow**:
    - Initialize an accumulator `acc` with the value of a Curve25519 scalar one.
    - Iterate over each scalar in `a`, copying the current value of `acc` to the corresponding position in `s` and updating `acc` by multiplying it with the current scalar.
    - Compute the inverse of the accumulated product `acc` and store it in `allinv`.
    - Iterate backwards over the scalars, updating each entry in `s` by multiplying it with the current `acc`, and then update `acc` by multiplying it with the current scalar.
- **Output**: The function does not return a value but modifies the `s` array to contain the batch inverses of the input scalars and `allinv` to contain the product of all inverses.
- **Functions called**:
    - [`fd_curve25519_scalar_mul`](#fd_curve25519_scalar_mul)
    - [`fd_curve25519_scalar_inv`](#fd_curve25519_scalar_inv)


# Function Declarations (Public API)

---
### fd\_curve25519\_scalar\_reduce<!-- {{#callable_declaration:fd_curve25519_scalar_reduce}} -->
Reduces a 512-bit scalar modulo a specific large prime.
- **Description**: This function reduces a 512-bit scalar, provided in a 64-byte little-endian format, modulo the large prime \( l = 2^{252} + 27742317777372353535851937790883648493 \). The result is a 256-bit scalar stored in a 32-byte little-endian format. It is essential to ensure that the input and output buffers do not overlap unless in-place operation is intended. The function does not perform any input validation, so the caller must ensure that the input is correctly formatted and that the output buffer is appropriately allocated.
- **Inputs**:
    - `out`: A pointer to a 32-byte buffer where the reduced 256-bit scalar will be stored. The caller must ensure this buffer is properly allocated and writable.
    - `in`: A pointer to a 64-byte buffer containing the 512-bit scalar in little-endian format. The caller must ensure this buffer is properly allocated and readable.
- **Output**: Returns a pointer to the output buffer containing the reduced scalar.
- **See also**: [`fd_curve25519_scalar_reduce`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_reduce)  (Implementation)


---
### fd\_curve25519\_scalar\_muladd<!-- {{#callable_declaration:fd_curve25519_scalar_muladd}} -->
Computes the scalar multiplication and addition of three 256-bit values modulo a large prime.
- **Description**: This function performs the operation s = (a * b + c) mod l, where a, b, and c are 256-bit values represented in 32-byte little-endian format. The result is stored in the 32-byte array s, which is also returned by the function. This operation is useful in cryptographic applications involving Curve25519. The function does not perform any input validation, so the caller must ensure that the inputs are correctly formatted and valid. The function can be used in-place, meaning the output array s can overlap with any of the input arrays a, b, or c.
- **Inputs**:
    - `s`: A 32-byte array where the result will be stored. The caller must ensure this array is writable and can overlap with a, b, or c.
    - `a`: A pointer to a 32-byte array representing a 256-bit value in little-endian format. The caller must ensure this pointer is valid and readable.
    - `b`: A 32-byte array representing a 256-bit value in little-endian format. The caller must ensure this array is valid and readable.
    - `c`: A 32-byte array representing a 256-bit value in little-endian format. The caller must ensure this array is valid and readable.
- **Output**: Returns a pointer to the 32-byte array s, which contains the 256-bit result of the operation.
- **See also**: [`fd_curve25519_scalar_muladd`](fd_curve25519_scalar.c.driver.md#fd_curve25519_scalar_muladd)  (Implementation)


