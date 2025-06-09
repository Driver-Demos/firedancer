# Purpose
This C source code file provides a set of functions for performing operations on elements of the G2 group in the context of elliptic curve cryptography, specifically for the BN254 curve. The file is not intended to be directly exposed to users, as indicated by the comment that G2 operations are not exposed to users, which suggests that these functions are used internally within a larger cryptographic library. The code includes functions for checking if a G2 element is zero, comparing two G2 elements for equality, setting and negating G2 elements, and performing various arithmetic operations such as doubling, addition, and scalar multiplication. Additionally, the file includes functions for handling Frobenius endomorphisms and converting byte arrays to G2 elements while checking subgroup membership.

The technical components of this file revolve around the manipulation of G2 elements, which are represented using a structure that includes coordinates in a finite field extension (fp2). The operations are implemented using a combination of basic arithmetic functions on these coordinates, such as squaring, multiplication, and addition, as well as more complex operations like Frobenius endomorphisms and subgroup membership checks. The file also includes references to external constants and functions, such as `fd_bn254_const_frob_gamma1_mont` and `fd_bn254_fp2_*` functions, which are likely defined elsewhere in the library. Overall, this file is a specialized component of a cryptographic library, providing essential functionality for working with the G2 group on the BN254 curve.
# Imports and Dependencies

---
- `./fd_bn254.h`


# Functions

---
### fd\_bn254\_g2\_is\_zero<!-- {{#callable:fd_bn254_g2_is_zero}} -->
The function `fd_bn254_g2_is_zero` checks if a given point in the G2 group is the zero point by examining its Z coordinate.
- **Inputs**:
    - `p`: A pointer to a constant `fd_bn254_g2_t` structure representing a point in the G2 group.
- **Control Flow**:
    - The function calls `fd_bn254_fp2_is_zero` with the Z coordinate of the point `p`.
- **Output**: Returns an integer indicating whether the Z coordinate of the point is zero, which implies the point is the zero point in the G2 group.


---
### fd\_bn254\_g2\_eq<!-- {{#callable:fd_bn254_g2_eq}} -->
The `fd_bn254_g2_eq` function checks if two points on the BN254 curve in the G2 group are equal.
- **Inputs**:
    - `p`: A pointer to the first point on the BN254 curve in the G2 group.
    - `q`: A pointer to the second point on the BN254 curve in the G2 group.
- **Control Flow**:
    - Check if the first point `p` is zero using [`fd_bn254_g2_is_zero`](#fd_bn254_g2_is_zero); if true, return whether the second point `q` is also zero.
    - Check if the second point `q` is zero; if true, return 0 (false).
    - Compute the square of the Z coordinates of both points and store them in `pz2` and `qz2`.
    - Multiply the X coordinate of `p` by `qz2` and the X coordinate of `q` by `pz2`, storing results in `l` and `r` respectively; if they are not equal, return 0 (false).
    - Multiply the Y coordinate of `p` by `qz2` and `q->Z`, and the Y coordinate of `q` by `pz2` and `p->Z`, storing results in `l` and `r` respectively; return whether `l` and `r` are equal.
- **Output**: Returns 1 if the points are equal, otherwise returns 0.
- **Functions called**:
    - [`fd_bn254_g2_is_zero`](#fd_bn254_g2_is_zero)


---
### fd\_bn254\_g2\_set<!-- {{#callable:fd_bn254_g2_set}} -->
The `fd_bn254_g2_set` function copies the coordinates of a G2 point from one structure to another.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g2_t` structure where the coordinates will be copied to.
    - `p`: A constant pointer to an `fd_bn254_g2_t` structure from which the coordinates will be copied.
- **Control Flow**:
    - The function calls `fd_bn254_fp2_set` to copy the X coordinate from `p` to `r`.
    - It calls `fd_bn254_fp2_set` again to copy the Y coordinate from `p` to `r`.
    - Finally, it calls `fd_bn254_fp2_set` to copy the Z coordinate from `p` to `r`.
    - The function returns the pointer `r`.
- **Output**: The function returns a pointer to the `fd_bn254_g2_t` structure `r` with the copied coordinates.


---
### fd\_bn254\_g2\_neg<!-- {{#callable:fd_bn254_g2_neg}} -->
The `fd_bn254_g2_neg` function computes the negation of a point on the BN254 curve in the G2 group.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g2_t` structure where the result will be stored.
    - `p`: A constant pointer to an `fd_bn254_g2_t` structure representing the point to be negated.
- **Control Flow**:
    - Copy the X coordinate from point `p` to result `r` using `fd_bn254_fp2_set`.
    - Negate the Y coordinate from point `p` and store it in result `r` using `fd_bn254_fp2_neg`.
    - Copy the Z coordinate from point `p` to result `r` using `fd_bn254_fp2_set`.
    - Return the pointer to the result `r`.
- **Output**: A pointer to the `fd_bn254_g2_t` structure `r` containing the negated point.


---
### fd\_bn254\_g2\_set\_zero<!-- {{#callable:fd_bn254_g2_set_zero}} -->
The `fd_bn254_g2_set_zero` function sets the Z component of a `fd_bn254_g2_t` structure to zero, effectively representing the point at infinity in projective coordinates.
- **Inputs**:
    - `r`: A pointer to a `fd_bn254_g2_t` structure that will be modified to represent the point at infinity.
- **Control Flow**:
    - The function calls `fd_bn254_fp2_set_zero` on the Z component of the `fd_bn254_g2_t` structure pointed to by `r`.
    - The function returns the pointer `r`.
- **Output**: A pointer to the modified `fd_bn254_g2_t` structure, which now represents the point at infinity.


---
### fd\_bn254\_g2\_frob<!-- {{#callable:fd_bn254_g2_frob}} -->
The `fd_bn254_g2_frob` function performs the Frobenius endomorphism on a point in the G2 group of the BN254 curve.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g2_t` structure where the result will be stored.
    - `p`: A constant pointer to an `fd_bn254_g2_t` structure representing the input point to be transformed.
- **Control Flow**:
    - Conjugate the X component of the input point `p` and store it in the X component of the result `r`.
    - Multiply the conjugated X component by a constant `fd_bn254_const_frob_gamma1_mont[1]`.
    - Conjugate the Y component of the input point `p` and store it in the Y component of the result `r`.
    - Multiply the conjugated Y component by a constant `fd_bn254_const_frob_gamma1_mont[2]`.
    - Conjugate the Z component of the input point `p` and store it in the Z component of the result `r`.
    - Return the pointer to the result `r`.
- **Output**: A pointer to the `fd_bn254_g2_t` structure `r` containing the result of the Frobenius endomorphism.


---
### fd\_bn254\_g2\_frob2<!-- {{#callable:fd_bn254_g2_frob2}} -->
The `fd_bn254_g2_frob2` function performs a Frobenius endomorphism on a point in the G2 group of the BN254 curve, specifically applying the Frobenius map twice.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g2_t` structure where the result of the Frobenius endomorphism will be stored.
    - `p`: A constant pointer to an `fd_bn254_g2_t` structure representing the input point on which the Frobenius endomorphism is applied.
- **Control Flow**:
    - Multiply the first element of the X coordinate of point `p` by a constant `fd_bn254_const_frob_gamma2_mont[1]` and store the result in the first element of the X coordinate of point `r`.
    - Multiply the second element of the X coordinate of point `p` by the same constant and store the result in the second element of the X coordinate of point `r`.
    - Multiply the first element of the Y coordinate of point `p` by a different constant `fd_bn254_const_frob_gamma2_mont[2]` and store the result in the first element of the Y coordinate of point `r`.
    - Multiply the second element of the Y coordinate of point `p` by the same constant and store the result in the second element of the Y coordinate of point `r`.
    - Copy the Z coordinate of point `p` to the Z coordinate of point `r`.
- **Output**: Returns a pointer to the `fd_bn254_g2_t` structure `r`, which contains the result of the Frobenius endomorphism applied twice to the input point `p`.


---
### fd\_bn254\_g2\_dbl<!-- {{#callable:fd_bn254_g2_dbl}} -->
The `fd_bn254_g2_dbl` function performs point doubling on an elliptic curve point in the G2 group of the BN254 curve.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g2_t` structure where the result of the doubling operation will be stored.
    - `p`: A constant pointer to an `fd_bn254_g2_t` structure representing the point to be doubled.
- **Control Flow**:
    - Check if the input point `p` is the zero point; if so, set the result `r` to zero and return.
    - Compute the square of the X, Y, and Z coordinates of the point `p`, storing them in `xx`, `yy`, and `zz` respectively.
    - Compute `y4` as the square of `yy`, which is `YY^2`.
    - Calculate `s` as `2 * ((X1 + YY)^2 - XX - YYYY)`.
    - Calculate `m` as `3 * XX` since `a` is zero in this context.
    - Compute the new X coordinate of the result `r` as `M^2 - 2 * S`.
    - Compute the new Z coordinate of the result `r` as `(Y1 + Z1)^2 - YY - ZZ`.
    - Compute the new Y coordinate of the result `r` as `M * (S - T) - 8 * YYYY`.
    - Return the result `r`.
- **Output**: A pointer to the `fd_bn254_g2_t` structure `r`, which now contains the doubled point.
- **Functions called**:
    - [`fd_bn254_g2_is_zero`](#fd_bn254_g2_is_zero)
    - [`fd_bn254_g2_set_zero`](#fd_bn254_g2_set_zero)


---
### fd\_bn254\_g2\_add\_mixed<!-- {{#callable:fd_bn254_g2_add_mixed}} -->
The `fd_bn254_g2_add_mixed` function computes the sum of two points on an elliptic curve in the Jacobian coordinate system, where the second point is assumed to have a Z-coordinate of 1.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g2_t` structure where the result of the addition will be stored.
    - `p`: A constant pointer to an `fd_bn254_g2_t` structure representing the first point on the elliptic curve.
    - `q`: A constant pointer to an `fd_bn254_g2_t` structure representing the second point on the elliptic curve, assumed to have a Z-coordinate of 1.
- **Control Flow**:
    - Check if the first point `p` is zero; if so, set `r` to `q` and return `r`.
    - Compute intermediate values `zz`, `u2`, and `s2` using the coordinates of `p` and `q`.
    - Check if `p` is equal to `q`; if so, call [`fd_bn254_g2_dbl`](#fd_bn254_g2_dbl) to double `p` and return the result.
    - Compute the difference `h` between `u2` and `p->X`, and its square `hh`.
    - Calculate `i` as four times `hh`, and `j` as the product of `h` and `i`.
    - Compute `rr` as twice the difference between `s2` and `p->Y`.
    - Calculate `v` as the product of `p->X` and `i`.
    - Compute the new X-coordinate `r->X` using `rr`, `j`, and `v`.
    - Compute the new Y-coordinate `r->Y` using `rr`, `v`, `r->X`, and `j`.
    - Compute the new Z-coordinate `r->Z` using `p->Z`, `h`, `zz`, and `hh`.
    - Return the result `r`.
- **Output**: A pointer to the `fd_bn254_g2_t` structure `r`, which contains the result of the addition.
- **Functions called**:
    - [`fd_bn254_g2_is_zero`](#fd_bn254_g2_is_zero)
    - [`fd_bn254_g2_set`](#fd_bn254_g2_set)
    - [`fd_bn254_g2_dbl`](#fd_bn254_g2_dbl)


---
### fd\_bn254\_g2\_add<!-- {{#callable:fd_bn254_g2_add}} -->
The `fd_bn254_g2_add` function performs the addition of two points on an elliptic curve in the Jacobian coordinate system.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g2_t` structure where the result of the addition will be stored.
    - `p`: A constant pointer to an `fd_bn254_g2_t` structure representing the first point to be added.
    - `q`: A constant pointer to an `fd_bn254_g2_t` structure representing the second point to be added.
- **Control Flow**:
    - Check if the point `p` is zero; if so, set `r` to `q` and return `r`.
    - Compute the squares of the Z coordinates of `p` and `q` and store them in `zz1` and `zz2`, respectively.
    - Calculate intermediate values `u1`, `s1`, `u2`, and `s2` using the X and Y coordinates of `p` and `q` and their respective Z squares.
    - Compute the difference `h` between `u2` and `u1`.
    - Calculate `i` as the square of twice `h`, and `j` as the product of `h` and `i`.
    - Compute `rr` as twice the difference between `s2` and `s1`.
    - Calculate `v` as the product of `u1` and `i`.
    - Determine the new X coordinate of `r` by subtracting `j` and twice `v` from the square of `rr`.
    - Compute the new Y coordinate of `r` using `rr`, `v`, and `i`.
    - Calculate the new Z coordinate of `r` using the sum of the Z coordinates of `p` and `q`, their squares, and `h`.
    - Return the result stored in `r`.
- **Output**: A pointer to the `fd_bn254_g2_t` structure `r`, which contains the result of the addition of points `p` and `q`.
- **Functions called**:
    - [`fd_bn254_g2_is_zero`](#fd_bn254_g2_is_zero)
    - [`fd_bn254_g2_set`](#fd_bn254_g2_set)


---
### fd\_bn254\_g2\_scalar\_mul<!-- {{#callable:fd_bn254_g2_scalar_mul}} -->
The `fd_bn254_g2_scalar_mul` function performs scalar multiplication on a point in the BN254 G2 group, multiplying the point by a scalar value.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g2_t` structure where the result of the scalar multiplication will be stored.
    - `p`: A constant pointer to an `fd_bn254_g2_t` structure representing the point to be multiplied, assumed to be in affine form (i.e., `p->Z == 1`).
    - `s`: A constant pointer to an `fd_bn254_scalar_t` structure representing the scalar by which the point `p` is to be multiplied.
- **Control Flow**:
    - Initialize an integer `i` to 255, representing the bit index of the scalar `s`.
    - Iterate from the most significant bit to the least significant bit of `s`, decrementing `i` until a set bit is found or `i` becomes negative.
    - If `i` is negative, indicating that the scalar `s` is zero, set the result `r` to the zero point using [`fd_bn254_g2_set_zero`](#fd_bn254_g2_set_zero) and return `r`.
    - Set the result `r` to the point `p` using [`fd_bn254_g2_set`](#fd_bn254_g2_set).
    - For each bit from `i-1` down to 0, double the point `r` using [`fd_bn254_g2_dbl`](#fd_bn254_g2_dbl).
    - If the current bit of `s` is set, add the point `p` to `r` using [`fd_bn254_g2_add_mixed`](#fd_bn254_g2_add_mixed).
    - Return the result `r`.
- **Output**: A pointer to the `fd_bn254_g2_t` structure `r`, which contains the result of the scalar multiplication.
- **Functions called**:
    - [`fd_bn254_g2_set_zero`](#fd_bn254_g2_set_zero)
    - [`fd_bn254_g2_set`](#fd_bn254_g2_set)
    - [`fd_bn254_g2_dbl`](#fd_bn254_g2_dbl)
    - [`fd_bn254_g2_add_mixed`](#fd_bn254_g2_add_mixed)


---
### fd\_bn254\_g2\_frombytes\_internal<!-- {{#callable:fd_bn254_g2_frombytes_internal}} -->
The `fd_bn254_g2_frombytes_internal` function converts a 128-byte input into a G2 point on the BN254 curve, handling special cases and performing basic validity checks.
- **Inputs**:
    - `p`: A pointer to an `fd_bn254_g2_t` structure where the resulting G2 point will be stored.
    - `in`: A constant 128-byte array representing the input data to be converted into a G2 point.
- **Control Flow**:
    - Check if the input `in` is all zeros, and if so, set the point `p` to the point at infinity using [`fd_bn254_g2_set_zero`](#fd_bn254_g2_set_zero) and return `p`.
    - Attempt to convert the first 64 bytes of `in` into the X coordinate of the point `p` using `fd_bn254_fp2_frombytes_be_nm`; if this fails, return `NULL`.
    - Attempt to convert the next 64 bytes of `in` into the Y coordinate of the point `p`, also checking for flags indicating infinity or negativity; if this fails, return `NULL`.
    - If the Y coordinate indicates infinity, set the point `p` to the point at infinity using [`fd_bn254_g2_set_zero`](#fd_bn254_g2_set_zero) and return `p`.
    - Set the Z coordinate of the point `p` to one using `fd_bn254_fp2_set_one`.
    - Return the pointer `p` to the resulting G2 point.
- **Output**: A pointer to the `fd_bn254_g2_t` structure `p` containing the resulting G2 point, or `NULL` if the conversion fails.
- **Functions called**:
    - [`fd_bn254_g2_set_zero`](#fd_bn254_g2_set_zero)


---
### fd\_bn254\_g2\_frombytes\_check\_subgroup<!-- {{#callable:fd_bn254_g2_frombytes_check_subgroup}} -->
The function `fd_bn254_g2_frombytes_check_subgroup` converts a byte array to a G2 point on the BN254 curve and verifies its subgroup membership.
- **Inputs**:
    - `p`: A pointer to an `fd_bn254_g2_t` structure where the resulting G2 point will be stored.
    - `in`: A constant byte array of size 128 representing the input data to be converted into a G2 point.
- **Control Flow**:
    - The function first attempts to convert the byte array `in` into a G2 point using [`fd_bn254_g2_frombytes_internal`](#fd_bn254_g2_frombytes_internal); if this fails, it returns NULL.
    - If the resulting point is the zero point, it returns the point `p`.
    - The function converts the X and Y coordinates of the point to Montgomery form and sets the Z coordinate to one.
    - It checks if the point satisfies the curve equation `y^2 = x^3 + b`; if not, it returns NULL.
    - The function performs a fast subgroup membership check using a series of scalar multiplications and Frobenius operations to ensure the point is in the correct subgroup.
    - If the subgroup check fails, it returns NULL; otherwise, it returns the point `p`.
- **Output**: Returns a pointer to the `fd_bn254_g2_t` structure `p` if the conversion and subgroup check are successful, otherwise returns NULL.
- **Functions called**:
    - [`fd_bn254_g2_frombytes_internal`](#fd_bn254_g2_frombytes_internal)
    - [`fd_bn254_g2_is_zero`](#fd_bn254_g2_is_zero)
    - [`fd_bn254_g2_scalar_mul`](#fd_bn254_g2_scalar_mul)
    - [`fd_bn254_g2_add_mixed`](#fd_bn254_g2_add_mixed)
    - [`fd_bn254_g2_frob`](#fd_bn254_g2_frob)
    - [`fd_bn254_g2_add`](#fd_bn254_g2_add)
    - [`fd_bn254_g2_frob2`](#fd_bn254_g2_frob2)
    - [`fd_bn254_g2_dbl`](#fd_bn254_g2_dbl)
    - [`fd_bn254_g2_eq`](#fd_bn254_g2_eq)


