# Purpose
The provided C source code file implements arithmetic operations for extension fields Fp2, Fp6, and Fp12, which are used in elliptic curve cryptography, specifically for the BN254 curve. This file is part of a cryptographic library and is intended to be included in other C programs that require these mathematical operations. The code is based on research papers and reference implementations, such as those found in the eprint archives and the gnark-crypto library. The operations are performed in Montgomery form, which is a representation that allows efficient modular arithmetic, crucial for cryptographic computations.

The file defines a variety of functions for manipulating elements in these extension fields, including addition, subtraction, multiplication, squaring, inversion, and conversion between Montgomery and non-Montgomery forms. It also includes specialized operations like Frobenius endomorphisms and Karatsuba multiplication, which are optimized for the specific properties of the BN254 curve. Constants used in these operations are defined at the beginning of the file, and the functions are implemented as inline functions for performance reasons. This file does not define a public API or external interfaces directly but provides the core mathematical operations that can be used by higher-level cryptographic protocols or applications.
# Imports and Dependencies

---
- `./fd_bn254.h`


# Global Variables

---
### fd\_bn254\_const\_twist\_b\_mont
- **Type**: `fd_bn254_fp2_t`
- **Description**: The variable `fd_bn254_const_twist_b_mont` is a constant array of type `fd_bn254_fp2_t` with a single element. It represents the constant B in the twist curve equation y^2 = x^3 + b' in Montgomery form, specifically for the BN254 curve. The values are stored in a two-dimensional array format, each containing four 64-bit hexadecimal values.
- **Use**: This variable is used as a constant in cryptographic computations involving the BN254 curve, particularly in operations related to the twist curve.


---
### fd\_bn254\_const\_frob\_gamma1\_mont
- **Type**: `const fd_bn254_fp2_t[5]`
- **Description**: The variable `fd_bn254_const_frob_gamma1_mont` is a constant array of five elements, each of type `fd_bn254_fp2_t`, which represents elements in the Fp2 extension field in Montgomery form. This array contains precomputed constants used in the Frobenius endomorphism for the BN254 curve, specifically for the first power of the Frobenius map.
- **Use**: This variable is used in the implementation of the Frobenius endomorphism in the BN254 curve, which is a key operation in pairing-based cryptography.


---
### fd\_bn254\_const\_frob\_gamma2\_mont
- **Type**: `const fd_bn254_fp_t[5]`
- **Description**: The `fd_bn254_const_frob_gamma2_mont` is a constant array of five elements, each of type `fd_bn254_fp_t`, representing specific constants used in the Frobenius endomorphism squared (frob^2) in the BN254 curve. These constants are stored in Montgomery form, which is a representation used to optimize arithmetic operations in finite fields.
- **Use**: This variable is used in the implementation of the Frobenius endomorphism squared operation in the BN254 curve, specifically in the `fd_bn254_fp12_frob2` function.


# Functions

---
### fd\_bn254\_fp2\_frombytes\_be\_nm<!-- {{#callable:fd_bn254_fp2_frombytes_be_nm}} -->
The function `fd_bn254_fp2_frombytes_be_nm` converts a 64-byte big-endian buffer into an `fd_bn254_fp2_t` structure, validating the conversion and setting flags for infinity and negativity.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `buf`: A constant 64-byte array representing the big-endian encoded data to be converted.
    - `is_inf`: A pointer to an integer that will be set to indicate if the resulting number is considered infinite.
    - `is_neg`: A pointer to an integer that will be set to indicate if the resulting number is considered negative.
- **Control Flow**:
    - The function first attempts to convert the second half of the buffer (bytes 32 to 63) into the first element of the `fd_bn254_fp2_t` structure without setting any flags.
    - If the conversion fails, the function returns `NULL`.
    - Next, it attempts to convert the first half of the buffer (bytes 0 to 31) into the second element of the `fd_bn254_fp2_t` structure, setting the `is_inf` and `is_neg` flags as appropriate.
    - If this conversion fails, the function returns `NULL`.
    - If both conversions succeed, the function returns the pointer `r`.
- **Output**: The function returns a pointer to the `fd_bn254_fp2_t` structure `r` if successful, or `NULL` if any conversion fails.


---
### fd\_bn254\_fp2\_tobytes\_be\_nm<!-- {{#callable:fd_bn254_fp2_tobytes_be_nm}} -->
The function `fd_bn254_fp2_tobytes_be_nm` converts a field element in Fp2 to a big-endian byte array representation.
- **Inputs**:
    - `buf`: A 64-byte array where the big-endian byte representation of the Fp2 element will be stored.
    - `a`: A pointer to an `fd_bn254_fp2_t` structure representing the Fp2 element to be converted.
- **Control Flow**:
    - Call `fd_bn254_fp_tobytes_be_nm` to convert the second element of the Fp2 structure `a` to bytes and store it in the first 32 bytes of `buf`.
    - Call `fd_bn254_fp_tobytes_be_nm` to convert the first element of the Fp2 structure `a` to bytes and store it in the last 32 bytes of `buf`.
    - Return the `buf` array.
- **Output**: A pointer to the `buf` array containing the big-endian byte representation of the Fp2 element.


---
### fd\_bn254\_fp2\_is\_neg\_nm<!-- {{#callable:fd_bn254_fp2_is_neg_nm}} -->
The function `fd_bn254_fp2_is_neg_nm` determines if a given element in the Fp2 field is negative, considering its non-Montgomery form.
- **Inputs**:
    - `x`: A pointer to an `fd_bn254_fp2_t` structure representing the element in the Fp2 field to be checked for negativity.
- **Control Flow**:
    - Check if the second element `x->el[1]` of the Fp2 element is zero using `fd_bn254_fp_is_zero`.
    - If `x->el[1]` is zero, return the result of `fd_bn254_fp_is_neg_nm` applied to the first element `x->el[0]`.
    - If `x->el[1]` is not zero, return the result of `fd_bn254_fp_is_neg_nm` applied to the second element `x->el[1]`.
- **Output**: Returns an integer, 1 if the element is negative, and 0 otherwise.


---
### fd\_bn254\_fp2\_is\_minus\_one<!-- {{#callable:fd_bn254_fp2_is_minus_one}} -->
The function `fd_bn254_fp2_is_minus_one` checks if a given Fp2 element is equal to -1 in the Montgomery form.
- **Inputs**:
    - `a`: A pointer to a constant `fd_bn254_fp2_t` structure representing the Fp2 element to be checked.
- **Control Flow**:
    - The function first checks if the first element of the Fp2 structure `a->el[0]` is equal to the constant `fd_bn254_const_p_minus_one_mont` using `fd_uint256_eq`.
    - Then, it checks if the second element `a->el[1]` is equal to the constant `fd_bn254_const_zero` using `fd_uint256_eq`.
    - The function returns true (1) if both conditions are satisfied, indicating that the Fp2 element is -1, otherwise it returns false (0).
- **Output**: The function returns an integer value: 1 if the Fp2 element is equal to -1, and 0 otherwise.


---
### fd\_bn254\_fp2\_eq<!-- {{#callable:fd_bn254_fp2_eq}} -->
The function `fd_bn254_fp2_eq` checks if two elements in the Fp2 field are equal by comparing their respective components.
- **Inputs**:
    - `a`: A pointer to the first Fp2 element to be compared.
    - `b`: A pointer to the second Fp2 element to be compared.
- **Control Flow**:
    - The function calls `fd_bn254_fp_eq` to compare the first components of `a` and `b`.
    - It then calls `fd_bn254_fp_eq` to compare the second components of `a` and `b`.
    - The function returns the logical AND of the results from the two comparisons.
- **Output**: The function returns an integer value: 1 if both components of `a` and `b` are equal, otherwise 0.


---
### fd\_bn254\_fp2\_set<!-- {{#callable:fd_bn254_fp2_set}} -->
The `fd_bn254_fp2_set` function copies the elements of one Fp2 field element to another.
- **Inputs**:
    - `r`: A pointer to the destination `fd_bn254_fp2_t` structure where the elements will be copied to.
    - `a`: A pointer to the source `fd_bn254_fp2_t` structure from which the elements will be copied.
- **Control Flow**:
    - The function calls `fd_bn254_fp_set` to copy the first element from `a` to `r`.
    - It then calls `fd_bn254_fp_set` again to copy the second element from `a` to `r`.
    - Finally, it returns the pointer `r`.
- **Output**: The function returns a pointer to the destination `fd_bn254_fp2_t` structure `r`.


---
### fd\_bn254\_fp2\_from\_mont<!-- {{#callable:fd_bn254_fp2_from_mont}} -->
The function `fd_bn254_fp2_from_mont` converts a given element of the Fp2 field from Montgomery form to standard form.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the input element in Montgomery form.
- **Control Flow**:
    - The function calls `fd_bn254_fp_from_mont` to convert the first element of the input `a` from Montgomery form and stores the result in the first element of `r`.
    - It then calls `fd_bn254_fp_from_mont` again to convert the second element of the input `a` from Montgomery form and stores the result in the second element of `r`.
    - Finally, the function returns the pointer `r`.
- **Output**: The function returns a pointer to the `fd_bn254_fp2_t` structure `r`, which contains the converted elements.


---
### fd\_bn254\_fp2\_to\_mont<!-- {{#callable:fd_bn254_fp2_to_mont}} -->
The function `fd_bn254_fp2_to_mont` converts an element of the Fp2 field from its standard form to its Montgomery form.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the input element in standard form.
- **Control Flow**:
    - The function calls `fd_bn254_fp_to_mont` on the first element of the input `a` and stores the result in the first element of `r`.
    - The function calls `fd_bn254_fp_to_mont` on the second element of the input `a` and stores the result in the second element of `r`.
    - The function returns the pointer `r`.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the converted element in Montgomery form.


---
### fd\_bn254\_fp2\_neg\_nm<!-- {{#callable:fd_bn254_fp2_neg_nm}} -->
The function `fd_bn254_fp2_neg_nm` computes the negation of a given element in the Fp2 field, which is not in Montgomery form, and stores the result in the provided result variable.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result of the negation will be stored.
    - `x`: A constant pointer to an `fd_bn254_fp2_t` structure representing the element to be negated.
- **Control Flow**:
    - Call `fd_bn254_fp_neg_nm` to negate the first element of `x` and store the result in the first element of `r`.
    - Call `fd_bn254_fp_neg_nm` to negate the second element of `x` and store the result in the second element of `r`.
    - Return the pointer `r` containing the negated result.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the negated result of the input `x`.


---
### fd\_bn254\_fp2\_neg<!-- {{#callable:fd_bn254_fp2_neg}} -->
The `fd_bn254_fp2_neg` function computes the negation of a given element in the Fp2 field and stores the result in the provided output variable.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result of the negation will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the element in Fp2 to be negated.
- **Control Flow**:
    - Call `fd_bn254_fp_neg` to negate the first element of the input `a` and store the result in the first element of `r`.
    - Call `fd_bn254_fp_neg` to negate the second element of the input `a` and store the result in the second element of `r`.
    - Return the pointer `r` containing the negated result.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the negated result of the input `a`.


---
### fd\_bn254\_fp2\_halve<!-- {{#callable:fd_bn254_fp2_halve}} -->
The `fd_bn254_fp2_halve` function computes the element-wise halving of a given Fp2 element and stores the result in another Fp2 element.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the Fp2 element to be halved.
- **Control Flow**:
    - The function calls `fd_bn254_fp_halve` on the first element of the Fp2 structure `a` and stores the result in the first element of `r`.
    - It then calls `fd_bn254_fp_halve` on the second element of the Fp2 structure `a` and stores the result in the second element of `r`.
    - Finally, the function returns the pointer `r`.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the halved elements of `a`.


---
### fd\_bn254\_fp2\_add<!-- {{#callable:fd_bn254_fp2_add}} -->
The `fd_bn254_fp2_add` function performs element-wise addition of two Fp2 elements and stores the result in a third Fp2 element.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result of the addition will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the first operand in the addition.
    - `b`: A constant pointer to an `fd_bn254_fp2_t` structure representing the second operand in the addition.
- **Control Flow**:
    - The function calls `fd_bn254_fp_add` to add the first elements (`el[0]`) of `a` and `b`, storing the result in `r->el[0]`.
    - It then calls `fd_bn254_fp_add` again to add the second elements (`el[1]`) of `a` and `b`, storing the result in `r->el[1]`.
    - Finally, the function returns the pointer `r` containing the result of the addition.
- **Output**: The function returns a pointer to the `fd_bn254_fp2_t` structure `r` containing the result of the addition.


---
### fd\_bn254\_fp2\_sub<!-- {{#callable:fd_bn254_fp2_sub}} -->
The function `fd_bn254_fp2_sub` computes the subtraction of two elements in the Fp2 field and stores the result in a given result variable.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result of the subtraction will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the first operand in the subtraction.
    - `b`: A constant pointer to an `fd_bn254_fp2_t` structure representing the second operand in the subtraction.
- **Control Flow**:
    - The function calls `fd_bn254_fp_sub` to subtract the first element of `b` from the first element of `a`, storing the result in the first element of `r`.
    - The function calls `fd_bn254_fp_sub` to subtract the second element of `b` from the second element of `a`, storing the result in the second element of `r`.
    - The function returns the pointer `r` containing the result of the subtraction.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the result of the subtraction.


---
### fd\_bn254\_fp2\_conj<!-- {{#callable:fd_bn254_fp2_conj}} -->
The `fd_bn254_fp2_conj` function computes the conjugate of a given element in the Fp2 field.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the input element whose conjugate is to be computed.
- **Control Flow**:
    - The function sets the first element of the result `r` to the first element of the input `a` using `fd_bn254_fp_set`.
    - The function negates the second element of the input `a` and assigns it to the second element of the result `r` using `fd_bn254_fp_neg`.
    - The function returns the pointer `r` containing the conjugate of `a`.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the conjugate of the input element `a`.


---
### fd\_bn254\_fp2\_mul<!-- {{#callable:fd_bn254_fp2_mul}} -->
The `fd_bn254_fp2_mul` function performs multiplication of two elements in the Fp2 field using Karatsuba multiplication and reduction, considering i^2 = -1.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result of the multiplication will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the first operand in the Fp2 field.
    - `b`: A constant pointer to an `fd_bn254_fp2_t` structure representing the second operand in the Fp2 field.
- **Control Flow**:
    - Extract the elements a0, a1 from the first operand `a` and b0, b1 from the second operand `b`.
    - Compute the sum of a0 and a1, storing the result in `sa`.
    - Compute the sum of b0 and b1, storing the result in `sb`.
    - Multiply a0 and b0, storing the result in `a0b0`.
    - Multiply a1 and b1, storing the result in `a1b1`.
    - Multiply `sa` and `sb`, storing the result in `r1`.
    - Subtract `a1b1` from `a0b0` and store the result in `r0`, considering i^2 = -1.
    - Subtract `a0b0` and `a1b1` from `r1` to complete the calculation of the imaginary part.
    - Return the result pointer `r`.
- **Output**: The function returns a pointer to the `fd_bn254_fp2_t` structure `r`, which contains the result of the multiplication of `a` and `b` in the Fp2 field.


---
### fd\_bn254\_fp2\_sqr<!-- {{#callable:fd_bn254_fp2_sqr}} -->
The `fd_bn254_fp2_sqr` function computes the square of an element in the Fp2 field using optimized arithmetic operations.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the input element to be squared.
- **Control Flow**:
    - Initialize temporary variables `p` and `m` for intermediate calculations.
    - Compute `p` as the sum of the two elements of `a` (i.e., `a0 + a1`).
    - Compute `m` as the difference of the two elements of `a` (i.e., `a0 - a1`).
    - Calculate `r1` as twice the product of `a0` and `a1` and store it in the second element of `r`.
    - Calculate `r0` as the product of `p` and `m` and store it in the first element of `r`.
    - Return the pointer `r` containing the squared result.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the squared result of the input element `a`.


---
### fd\_bn254\_fp2\_mul\_by\_i<!-- {{#callable:fd_bn254_fp2_mul_by_i}} -->
The function `fd_bn254_fp2_mul_by_i` multiplies a given Fp2 element by the imaginary unit 'i' in the Fp2 field.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the Fp2 element to be multiplied by 'i'.
- **Control Flow**:
    - Negate the second element of the input Fp2 element `a` and store it in a temporary variable `t`.
    - Set the second element of the result `r` to the first element of `a`.
    - Set the first element of the result `r` to the negated value stored in `t`.
    - Return the pointer to the result `r`.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the result of the multiplication.


---
### fd\_bn254\_fp2\_inv<!-- {{#callable:fd_bn254_fp2_inv}} -->
The `fd_bn254_fp2_inv` function computes the multiplicative inverse of an element in the Fp2 field.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the element whose inverse is to be computed.
- **Control Flow**:
    - Initialize temporary variables `t0` and `t1` as arrays of type `fd_bn254_fp_t` with one element each.
    - Compute the square of the first element of `a` and store it in `t0`.
    - Compute the square of the second element of `a` and store it in `t1`.
    - Add `t0` and `t1` together, storing the result back in `t0`.
    - Compute the multiplicative inverse of `t0` and store it in `t1`.
    - Multiply the first element of `a` by `t1` and store the result in the first element of `r`.
    - Multiply the second element of `a` by `t1` and store the result in the second element of `r`.
    - Negate the second element of `r`.
    - Return the pointer `r`.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r`, which contains the inverse of the input element `a`.


---
### fd\_bn254\_fp2\_pow<!-- {{#callable:fd_bn254_fp2_pow}} -->
The `fd_bn254_fp2_pow` function computes the power of an element in the Fp2 field by exponentiating it with a given 256-bit integer.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the base element in Fp2.
    - `b`: A constant pointer to an `fd_uint256_t` structure representing the exponent as a 256-bit integer.
- **Control Flow**:
    - Initialize the result `r` to one in the Fp2 field using `fd_bn254_fp2_set_one`.
    - Find the most significant bit set in the exponent `b` by iterating from the highest bit (255) downwards.
    - Iterate over each bit of the exponent `b` from the most significant bit to the least significant bit.
    - For each bit, square the current result `r` using [`fd_bn254_fp2_sqr`](#fd_bn254_fp2_sqr).
    - If the current bit of `b` is set, multiply the current result `r` by the base `a` using [`fd_bn254_fp2_mul`](#fd_bn254_fp2_mul).
    - Return the result `r`.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the result of the exponentiation.
- **Functions called**:
    - [`fd_bn254_fp2_sqr`](#fd_bn254_fp2_sqr)
    - [`fd_bn254_fp2_mul`](#fd_bn254_fp2_mul)


---
### fd\_bn254\_fp2\_sqrt<!-- {{#callable:fd_bn254_fp2_sqrt}} -->
The `fd_bn254_fp2_sqrt` function computes the square root of a given element in the Fp2 field, returning one of the two possible square roots or NULL if no square root exists.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the element in Fp2 for which the square root is to be computed.
- **Control Flow**:
    - Initialize temporary variables `a0`, `a1`, `alpha`, and `x0` as `fd_bn254_fp2_t` structures.
    - Compute `a1` as `a` raised to the power of `fd_bn254_const_sqrt_exp` using [`fd_bn254_fp2_pow`](#fd_bn254_fp2_pow).
    - Square `a1` to get `alpha` and multiply it by `a` to update `alpha`.
    - Compute the conjugate of `alpha` into `a0` and multiply `a0` by `alpha`.
    - Check if `a0` is -1 using [`fd_bn254_fp2_is_minus_one`](#fd_bn254_fp2_is_minus_one); if true, return NULL as no square root exists.
    - Multiply `a1` by `a` to get `x0`.
    - Check if `alpha` is -1; if true, multiply `x0` by `i` and store the result in `r`.
    - Otherwise, set `a1` to 1, add `alpha` to `a1`, raise the result to the power of `fd_bn254_const_p_minus_one_half`, and multiply by `x0` to store the result in `r`.
    - Return `r`.
- **Output**: Returns a pointer to `fd_bn254_fp2_t` containing the square root of `a` if it exists, or NULL if no square root exists.
- **Functions called**:
    - [`fd_bn254_fp2_pow`](#fd_bn254_fp2_pow)
    - [`fd_bn254_fp2_sqr`](#fd_bn254_fp2_sqr)
    - [`fd_bn254_fp2_mul`](#fd_bn254_fp2_mul)
    - [`fd_bn254_fp2_conj`](#fd_bn254_fp2_conj)
    - [`fd_bn254_fp2_is_minus_one`](#fd_bn254_fp2_is_minus_one)
    - [`fd_bn254_fp2_mul_by_i`](#fd_bn254_fp2_mul_by_i)
    - [`fd_bn254_fp2_add`](#fd_bn254_fp2_add)


---
### fd\_bn254\_fp2\_mul\_by\_xi<!-- {{#callable:fd_bn254_fp2_mul_by_xi}} -->
The function `fd_bn254_fp2_mul_by_xi` multiplies a given Fp2 element by the constant xi, which is defined as (9 + i), and stores the result in the provided result variable.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp2_t` structure where the result of the multiplication will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp2_t` structure representing the Fp2 element to be multiplied by xi.
- **Control Flow**:
    - Initialize two temporary variables `r0` and `r1` to store intermediate results.
    - Compute `r0` as 9 times the real part of `a` minus the imaginary part of `a` using a series of additions and a subtraction.
    - Compute `r1` as 9 times the imaginary part of `a` plus the real part of `a` using a series of additions.
    - Set the real part of the result `r` to `r0`.
    - Set the imaginary part of the result `r` to `r1`.
    - Return the result pointer `r`.
- **Output**: A pointer to the `fd_bn254_fp2_t` structure `r` containing the result of the multiplication.


---
### fd\_bn254\_fp6\_set<!-- {{#callable:fd_bn254_fp6_set}} -->
The `fd_bn254_fp6_set` function copies the elements of one Fp6 field element to another.
- **Inputs**:
    - `r`: A pointer to the destination `fd_bn254_fp6_t` structure where the elements will be copied to.
    - `a`: A pointer to the source `fd_bn254_fp6_t` structure from which the elements will be copied.
- **Control Flow**:
    - The function calls [`fd_bn254_fp2_set`](#fd_bn254_fp2_set) three times to copy each of the three `fd_bn254_fp2_t` elements from the source `a` to the destination `r`.
    - Each call to [`fd_bn254_fp2_set`](#fd_bn254_fp2_set) copies one element of the Fp6 field, specifically `el[0]`, `el[1]`, and `el[2]`.
    - After copying all elements, the function returns the pointer to the destination `fd_bn254_fp6_t` structure `r`.
- **Output**: The function returns a pointer to the destination `fd_bn254_fp6_t` structure `r` after copying the elements.
- **Functions called**:
    - [`fd_bn254_fp2_set`](#fd_bn254_fp2_set)


---
### fd\_bn254\_fp6\_neg<!-- {{#callable:fd_bn254_fp6_neg}} -->
The `fd_bn254_fp6_neg` function computes the negation of a given element in the Fp6 extension field and stores the result in the provided output variable.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp6_t` structure where the result of the negation will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp6_t` structure representing the element to be negated.
- **Control Flow**:
    - The function calls [`fd_bn254_fp2_neg`](#fd_bn254_fp2_neg) three times, once for each element of the Fp6 structure (el[0], el[1], el[2]), to compute the negation of each Fp2 element in the input structure `a`.
    - Each negated Fp2 element is stored in the corresponding element of the output structure `r`.
    - The function returns the pointer `r` after storing the negated values.
- **Output**: A pointer to the `fd_bn254_fp6_t` structure `r` containing the negated Fp6 element.
- **Functions called**:
    - [`fd_bn254_fp2_neg`](#fd_bn254_fp2_neg)


---
### fd\_bn254\_fp6\_add<!-- {{#callable:fd_bn254_fp6_add}} -->
The `fd_bn254_fp6_add` function performs element-wise addition of two Fp6 elements and stores the result in a third Fp6 element.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp6_t` structure where the result of the addition will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp6_t` structure representing the first Fp6 element to be added.
    - `b`: A constant pointer to an `fd_bn254_fp6_t` structure representing the second Fp6 element to be added.
- **Control Flow**:
    - The function calls [`fd_bn254_fp2_add`](#fd_bn254_fp2_add) three times, once for each pair of corresponding elements in the Fp6 structures `a` and `b`.
    - Each call to [`fd_bn254_fp2_add`](#fd_bn254_fp2_add) adds the corresponding elements from `a` and `b` and stores the result in the corresponding element of `r`.
    - The function returns the pointer `r` after performing the additions.
- **Output**: A pointer to the `fd_bn254_fp6_t` structure `r`, which contains the result of the addition.
- **Functions called**:
    - [`fd_bn254_fp2_add`](#fd_bn254_fp2_add)


---
### fd\_bn254\_fp6\_sub<!-- {{#callable:fd_bn254_fp6_sub}} -->
The `fd_bn254_fp6_sub` function computes the element-wise subtraction of two Fp6 elements and stores the result in a third Fp6 element.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp6_t` structure where the result of the subtraction will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp6_t` structure representing the first operand in the subtraction.
    - `b`: A constant pointer to an `fd_bn254_fp6_t` structure representing the second operand in the subtraction.
- **Control Flow**:
    - The function calls [`fd_bn254_fp2_sub`](#fd_bn254_fp2_sub) three times, each time subtracting corresponding elements of `b` from `a` and storing the result in `r`.
    - The first call subtracts `b->el[0]` from `a->el[0]` and stores the result in `r->el[0]`.
    - The second call subtracts `b->el[1]` from `a->el[1]` and stores the result in `r->el[1]`.
    - The third call subtracts `b->el[2]` from `a->el[2]` and stores the result in `r->el[2]`.
    - The function returns the pointer `r` after performing the subtraction.
- **Output**: The function returns a pointer to the `fd_bn254_fp6_t` structure `r`, which contains the result of the subtraction.
- **Functions called**:
    - [`fd_bn254_fp2_sub`](#fd_bn254_fp2_sub)


---
### fd\_bn254\_fp6\_mul\_by\_gamma<!-- {{#callable:fd_bn254_fp6_mul_by_gamma}} -->
The function `fd_bn254_fp6_mul_by_gamma` multiplies an element of the Fp6 field by the constant gamma, which is represented by a specific permutation of its components.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp6_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp6_t` structure representing the input element to be multiplied by gamma.
- **Control Flow**:
    - Declare a temporary variable `t` of type `fd_bn254_fp2_t` to store intermediate results.
    - Call [`fd_bn254_fp2_mul_by_xi`](#fd_bn254_fp2_mul_by_xi) to multiply the third element of `a` by xi and store the result in `t`.
    - Set the third element of `r` to the second element of `a` using [`fd_bn254_fp2_set`](#fd_bn254_fp2_set).
    - Set the second element of `r` to the first element of `a` using [`fd_bn254_fp2_set`](#fd_bn254_fp2_set).
    - Set the first element of `r` to the value stored in `t` using [`fd_bn254_fp2_set`](#fd_bn254_fp2_set).
    - Return the pointer `r` containing the result.
- **Output**: A pointer to the `fd_bn254_fp6_t` structure `r`, which now contains the result of the multiplication.
- **Functions called**:
    - [`fd_bn254_fp2_mul_by_xi`](#fd_bn254_fp2_mul_by_xi)
    - [`fd_bn254_fp2_set`](#fd_bn254_fp2_set)


---
### fd\_bn254\_fp6\_mul<!-- {{#callable:fd_bn254_fp6_mul}} -->
The `fd_bn254_fp6_mul` function performs multiplication of two elements in the Fp6 extension field using a specific algorithm.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp6_t` structure where the result of the multiplication will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp6_t` structure representing the first operand in the multiplication.
    - `b`: A constant pointer to an `fd_bn254_fp6_t` structure representing the second operand in the multiplication.
- **Control Flow**:
    - Extract the three Fp2 elements from both input Fp6 elements `a` and `b`.
    - Compute the products of corresponding Fp2 elements: `a0b0`, `a1b1`, and `a2b2`.
    - Compute intermediate sums `sa` and `sb` for each pair of Fp2 elements from `a` and `b`.
    - Calculate `r0` by multiplying `sa` and `sb`, then adjust by subtracting `a1b1` and `a2b2`, multiply by xi, and add `a0b0`.
    - Calculate `r2` by multiplying new `sa` and `sb`, then adjust by subtracting `a0b0` and `a2b2`, and add `a1b1`.
    - Calculate `r1` by multiplying new `sa` and `sb`, then adjust by subtracting `a0b0` and `a1b1`, multiply `a2b2` by xi, and add to the result.
    - Set the result Fp6 element `r` with the computed `r0`, `r1`, and `r2`.
- **Output**: The function returns a pointer to the `fd_bn254_fp6_t` structure `r`, which contains the result of the multiplication.
- **Functions called**:
    - [`fd_bn254_fp2_mul`](#fd_bn254_fp2_mul)
    - [`fd_bn254_fp2_add`](#fd_bn254_fp2_add)
    - [`fd_bn254_fp2_sub`](#fd_bn254_fp2_sub)
    - [`fd_bn254_fp2_mul_by_xi`](#fd_bn254_fp2_mul_by_xi)
    - [`fd_bn254_fp2_set`](#fd_bn254_fp2_set)


---
### fd\_bn254\_fp6\_sqr<!-- {{#callable:fd_bn254_fp6_sqr}} -->
The `fd_bn254_fp6_sqr` function computes the square of an element in the Fp6 extension field using optimized arithmetic operations.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp6_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp6_t` structure representing the element to be squared.
- **Control Flow**:
    - Extract the three Fp2 elements (a0, a1, a2) from the input Fp6 element 'a'.
    - Compute c4 as 2 * (a0 * a1) and c5 as (a2)^2.
    - Calculate c2 as c4 - c5, then adjust c5 by multiplying it by xi and add it to c1.
    - Compute c3 as (a0)^2, then calculate c4 as (a0 - a1 + a2)^2.
    - Update c2 by adding c4 and 2 * (a1 * a2) to it, then subtract c3 from it.
    - Adjust c5 by multiplying it by xi and add it to c0.
    - Set the result Fp6 element 'r' with the computed c0, c1, and c2.
- **Output**: The function returns a pointer to the `fd_bn254_fp6_t` structure 'r' containing the squared result.
- **Functions called**:
    - [`fd_bn254_fp2_mul`](#fd_bn254_fp2_mul)
    - [`fd_bn254_fp2_add`](#fd_bn254_fp2_add)
    - [`fd_bn254_fp2_sqr`](#fd_bn254_fp2_sqr)
    - [`fd_bn254_fp2_sub`](#fd_bn254_fp2_sub)
    - [`fd_bn254_fp2_mul_by_xi`](#fd_bn254_fp2_mul_by_xi)
    - [`fd_bn254_fp2_set`](#fd_bn254_fp2_set)


---
### fd\_bn254\_fp6\_inv<!-- {{#callable:fd_bn254_fp6_inv}} -->
The `fd_bn254_fp6_inv` function computes the multiplicative inverse of an element in the Fp6 extension field.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp6_t` structure where the result (inverse of `a`) will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp6_t` structure representing the element in Fp6 to be inverted.
- **Control Flow**:
    - Initialize an array `t` of six `fd_bn254_fp2_t` elements to store intermediate results.
    - Compute the squares of the three elements of `a` and store them in `t[0]`, `t[1]`, and `t[2]`.
    - Compute the products of pairs of elements of `a` and store them in `t[3]`, `t[4]`, and `t[5]`.
    - Modify `t[0]` by subtracting `xi * t[5]` from it, where `xi` is a constant used in Fp6 construction.
    - Modify `t[2]` by subtracting `t[3]` from `xi * t[2]`.
    - Modify `t[1]` by subtracting `t[4]` from it.
    - Compute `t[3]` as the product of `a->el[0]` and `t[0]`, then add `xi * a->el[2] * t[2]` and `xi * a->el[1] * t[1]` to it.
    - Compute the inverse of `t[3]` and store it in `t[4]`.
    - Multiply `t[0]`, `t[2]`, and `t[1]` by `t[4]` and store the results in `r->el[0]`, `r->el[1]`, and `r->el[2]`, respectively.
    - Return the pointer `r`.
- **Output**: A pointer to the `fd_bn254_fp6_t` structure `r`, which now contains the inverse of the input element `a` in Fp6.
- **Functions called**:
    - [`fd_bn254_fp2_sqr`](#fd_bn254_fp2_sqr)
    - [`fd_bn254_fp2_mul`](#fd_bn254_fp2_mul)
    - [`fd_bn254_fp2_mul_by_xi`](#fd_bn254_fp2_mul_by_xi)
    - [`fd_bn254_fp2_sub`](#fd_bn254_fp2_sub)
    - [`fd_bn254_fp2_add`](#fd_bn254_fp2_add)
    - [`fd_bn254_fp2_inv`](#fd_bn254_fp2_inv)


---
### fd\_bn254\_fp12\_conj<!-- {{#callable:fd_bn254_fp12_conj}} -->
The `fd_bn254_fp12_conj` function computes the conjugate of an element in the Fp12 extension field.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp12_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp12_t` structure representing the input element whose conjugate is to be computed.
- **Control Flow**:
    - The function first sets the first element of the result `r` to the first element of the input `a` using [`fd_bn254_fp6_set`](#fd_bn254_fp6_set).
    - Then, it negates the second element of the input `a` and assigns it to the second element of the result `r` using [`fd_bn254_fp6_neg`](#fd_bn254_fp6_neg).
    - Finally, the function returns the pointer `r`.
- **Output**: A pointer to the `fd_bn254_fp12_t` structure `r` containing the conjugate of the input element `a`.
- **Functions called**:
    - [`fd_bn254_fp6_set`](#fd_bn254_fp6_set)
    - [`fd_bn254_fp6_neg`](#fd_bn254_fp6_neg)


---
### fd\_bn254\_fp12\_mul<!-- {{#callable:fd_bn254_fp12_mul}} -->
The `fd_bn254_fp12_mul` function performs multiplication of two elements in the Fp12 extension field using a specific algorithm from cryptographic literature.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp12_t` structure where the result of the multiplication will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp12_t` structure representing the first operand in the multiplication.
    - `b`: A constant pointer to an `fd_bn254_fp12_t` structure representing the second operand in the multiplication.
- **Control Flow**:
    - Extract the Fp6 components (a0, a1) from the first operand `a` and (b0, b1) from the second operand `b`.
    - Initialize pointers `r0` and `r1` to the Fp6 components of the result `r`.
    - Declare temporary Fp6 variables `a0b0`, `a1b1`, `sa`, and `sb`.
    - Compute `sa` as the sum of `a0` and `a1`, and `sb` as the sum of `b0` and `b1`.
    - Compute `a0b0` as the product of `a0` and `b0`, and `a1b1` as the product of `a1` and `b1`.
    - Compute `r1` as the product of `sa` and `sb`, then subtract `a0b0` and `a1b1` from `r1`.
    - Multiply `a1b1` by a constant gamma and add the result to `a0b0` to compute `r0`.
    - Return the result `r`.
- **Output**: The function returns a pointer to the `fd_bn254_fp12_t` structure `r`, which contains the result of the multiplication.
- **Functions called**:
    - [`fd_bn254_fp6_add`](#fd_bn254_fp6_add)
    - [`fd_bn254_fp6_mul`](#fd_bn254_fp6_mul)
    - [`fd_bn254_fp6_sub`](#fd_bn254_fp6_sub)
    - [`fd_bn254_fp6_mul_by_gamma`](#fd_bn254_fp6_mul_by_gamma)


---
### fd\_bn254\_fp12\_sqr<!-- {{#callable:fd_bn254_fp12_sqr}} -->
The `fd_bn254_fp12_sqr` function computes the square of an element in the Fp12 field using a specific algorithm from cryptographic literature.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp12_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp12_t` structure representing the input element to be squared.
- **Control Flow**:
    - Initialize temporary variables `c0`, `c2`, and `c3` of type `fd_bn254_fp6_t`.
    - Compute `c0` as the difference between the first and second elements of `a`.
    - Multiply the second element of `a` by gamma and store the result in `c3`.
    - Compute `c3` as the difference between the first element of `a` and the modified `c3`.
    - Multiply the first and second elements of `a` and store the result in `c2`.
    - Multiply `c0` and `c3` and add the result to `c2`, storing the result back in `c0`.
    - Double `c2` and store the result in the second element of `r`.
    - Multiply `c2` by gamma and add `c0` to it, storing the result in the first element of `r`.
    - Return the pointer `r`.
- **Output**: A pointer to the `fd_bn254_fp12_t` structure `r` containing the squared result.
- **Functions called**:
    - [`fd_bn254_fp6_sub`](#fd_bn254_fp6_sub)
    - [`fd_bn254_fp6_mul_by_gamma`](#fd_bn254_fp6_mul_by_gamma)
    - [`fd_bn254_fp6_mul`](#fd_bn254_fp6_mul)
    - [`fd_bn254_fp6_add`](#fd_bn254_fp6_add)


---
### fd\_bn254\_fp12\_sqr\_fast<!-- {{#callable:fd_bn254_fp12_sqr_fast}} -->
The `fd_bn254_fp12_sqr_fast` function computes the cyclotomic square of an element in the BN254 field extension Fp12, optimized for cases where the element satisfies a specific cyclotomic condition.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp12_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp12_t` structure representing the input element to be squared.
- **Control Flow**:
    - Initialize an array `t` of 9 `fd_bn254_fp2_t` elements to store intermediate results.
    - Compute the square of `a->el[1].el[1]` and store it in `t[0]`.
    - Compute the square of `a->el[0].el[0]` and store it in `t[1]`.
    - Add `a->el[1].el[1]` and `a->el[0].el[0]`, square the result, and store it in `t[6]`.
    - Subtract `t[0]` and `t[1]` from `t[6]`.
    - Compute the square of `a->el[0].el[2]` and store it in `t[2]`.
    - Compute the square of `a->el[1].el[0]` and store it in `t[3]`.
    - Add `a->el[0].el[2]` and `a->el[1].el[0]`, square the result, and store it in `t[7]`.
    - Subtract `t[2]` and `t[3]` from `t[7]`.
    - Compute the square of `a->el[1].el[2]` and store it in `t[4]`.
    - Compute the square of `a->el[0].el[1]` and store it in `t[5]`.
    - Add `a->el[1].el[2]` and `a->el[0].el[1]`, square the result, and store it in `t[8]`.
    - Subtract `t[4]` and `t[5]` from `t[8]` and multiply by xi.
    - Multiply `t[0]`, `t[2]`, and `t[4]` by xi and add respective squares to them.
    - Compute the result elements `r->el[0].el[0]`, `r->el[0].el[1]`, `r->el[0].el[2]`, `r->el[1].el[0]`, `r->el[1].el[1]`, and `r->el[1].el[2]` using the intermediate results in `t`.
- **Output**: The function returns a pointer to the `fd_bn254_fp12_t` structure `r` containing the squared result.
- **Functions called**:
    - [`fd_bn254_fp2_sqr`](#fd_bn254_fp2_sqr)
    - [`fd_bn254_fp2_add`](#fd_bn254_fp2_add)
    - [`fd_bn254_fp2_sub`](#fd_bn254_fp2_sub)
    - [`fd_bn254_fp2_mul_by_xi`](#fd_bn254_fp2_mul_by_xi)


---
### fd\_bn254\_fp12\_inv<!-- {{#callable:fd_bn254_fp12_inv}} -->
The `fd_bn254_fp12_inv` function computes the multiplicative inverse of an element in the Fp12 field.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp12_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp12_t` structure representing the element whose inverse is to be computed.
- **Control Flow**:
    - Initialize two temporary `fd_bn254_fp6_t` variables `t0` and `t1`.
    - Compute the square of the first element of `a` and store it in `t0`.
    - Compute the square of the second element of `a` and store it in `t1`.
    - Multiply `t1` by the constant gamma and store the result back in `t1`.
    - Subtract `t1` from `t0` and store the result in `t0`.
    - Compute the inverse of `t0` and store it in `t1`.
    - Multiply the first element of `a` by `t1` and store the result in the first element of `r`.
    - Multiply the second element of `a` by `t1`, negate the result, and store it in the second element of `r`.
    - Return the pointer `r`.
- **Output**: A pointer to the `fd_bn254_fp12_t` structure `r` containing the inverse of the input element `a`.
- **Functions called**:
    - [`fd_bn254_fp6_sqr`](#fd_bn254_fp6_sqr)
    - [`fd_bn254_fp6_mul_by_gamma`](#fd_bn254_fp6_mul_by_gamma)
    - [`fd_bn254_fp6_sub`](#fd_bn254_fp6_sub)
    - [`fd_bn254_fp6_inv`](#fd_bn254_fp6_inv)
    - [`fd_bn254_fp6_mul`](#fd_bn254_fp6_mul)
    - [`fd_bn254_fp6_neg`](#fd_bn254_fp6_neg)


---
### fd\_bn254\_fp12\_frob<!-- {{#callable:fd_bn254_fp12_frob}} -->
The `fd_bn254_fp12_frob` function performs the Frobenius endomorphism on an element of the Fp12 field, applying specific conjugations and multiplications with pre-defined constants.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp12_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp12_t` structure representing the input element to be transformed.
- **Control Flow**:
    - Initialize an array of `fd_bn254_fp2_t` to store intermediate conjugated values.
    - Conjugate the first element of `a` and store it directly in the result `r`.
    - Conjugate the remaining elements of `a` and store them in the temporary array `t`.
    - Multiply each conjugated element in `t` by a corresponding constant from `fd_bn254_const_frob_gamma1_mont` and store the results in `r`.
    - Return the pointer `r` containing the transformed element.
- **Output**: A pointer to the `fd_bn254_fp12_t` structure `r` containing the result of the Frobenius endomorphism.
- **Functions called**:
    - [`fd_bn254_fp2_conj`](#fd_bn254_fp2_conj)
    - [`fd_bn254_fp2_mul`](#fd_bn254_fp2_mul)


---
### fd\_bn254\_fp12\_frob2<!-- {{#callable:fd_bn254_fp12_frob2}} -->
The function `fd_bn254_fp12_frob2` performs the Frobenius endomorphism squared on an element of the Fp12 field, applying specific constants to each sub-element.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_fp12_t` structure where the result will be stored.
    - `a`: A constant pointer to an `fd_bn254_fp12_t` structure representing the input element to be transformed.
- **Control Flow**:
    - Set the first sub-element `g0` of the result `r` to the first sub-element `g0` of the input `a`.
    - Multiply each component of the second sub-element `g1` of `a` by the constant `gamma_2,2` and store the result in the corresponding component of `g1` in `r`.
    - Multiply each component of the third sub-element `g2` of `a` by the constant `gamma_2,4` and store the result in the corresponding component of `g2` in `r`.
    - Multiply each component of the fourth sub-element `h0` of `a` by the constant `gamma_2,1` and store the result in the corresponding component of `h0` in `r`.
    - Multiply each component of the fifth sub-element `h1` of `a` by the constant `gamma_2,3` and store the result in the corresponding component of `h1` in `r`.
    - Multiply each component of the sixth sub-element `h2` of `a` by the constant `gamma_2,5` and store the result in the corresponding component of `h2` in `r`.
- **Output**: The function returns a pointer to the `fd_bn254_fp12_t` structure `r`, which contains the transformed element.
- **Functions called**:
    - [`fd_bn254_fp2_set`](#fd_bn254_fp2_set)


