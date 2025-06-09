# Purpose
This C source code file provides a set of functions for operations on elliptic curve points in the BN254 curve, specifically focusing on the G1 group. The file includes functions for checking if a point is the identity element (zero), setting points, converting points to affine coordinates, serializing points to bytes, and performing arithmetic operations such as addition, doubling, and scalar multiplication. The code is structured to handle points in both affine and projective coordinates, optimizing for different scenarios such as mixed addition where one point is already in affine form. The functions are designed to be efficient, using inline definitions and conditional checks to handle edge cases like point at infinity or equal points.

The file is part of a larger library, as indicated by the inclusion of a header file (`fd_bn254.h`), and it is intended to be used as a module for elliptic curve cryptography operations. The functions are not designed to be standalone executables but rather to be integrated into applications that require cryptographic operations on the BN254 curve. The code includes internal functions for byte conversion and subgroup membership checks, ensuring that points are valid and correctly represented. This file does not define public APIs directly but provides the underlying implementations that can be exposed through higher-level interfaces in the library.
# Imports and Dependencies

---
- `./fd_bn254.h`


# Functions

---
### fd\_bn254\_g1\_is\_zero<!-- {{#callable:fd_bn254_g1_is_zero}} -->
The function `fd_bn254_g1_is_zero` checks if a given point on the BN254 curve is the point at infinity by examining its Z-coordinate.
- **Inputs**:
    - `p`: A constant pointer to a `fd_bn254_g1_t` structure representing a point on the BN254 curve.
- **Control Flow**:
    - The function calls `fd_bn254_fp_is_zero` with the Z-coordinate of the point `p` to determine if it is zero.
- **Output**: An integer value, where a non-zero result indicates that the point is the point at infinity (Z-coordinate is zero), and zero indicates otherwise.


---
### fd\_bn254\_g1\_set<!-- {{#callable:fd_bn254_g1_set}} -->
The `fd_bn254_g1_set` function copies the coordinates of one elliptic curve point to another in the BN254 curve's G1 group.
- **Inputs**:
    - `r`: A pointer to the destination `fd_bn254_g1_t` structure where the point coordinates will be copied to.
    - `p`: A pointer to the source `fd_bn254_g1_t` structure from which the point coordinates will be copied.
- **Control Flow**:
    - The function calls `fd_bn254_fp_set` to copy the X coordinate from `p` to `r`.
    - It then calls `fd_bn254_fp_set` to copy the Y coordinate from `p` to `r`.
    - Finally, it calls `fd_bn254_fp_set` to copy the Z coordinate from `p` to `r`.
    - The function returns the pointer `r`.
- **Output**: The function returns a pointer to the destination `fd_bn254_g1_t` structure `r`.


---
### fd\_bn254\_g1\_set\_zero<!-- {{#callable:fd_bn254_g1_set_zero}} -->
The `fd_bn254_g1_set_zero` function sets the Z coordinate of a G1 point to zero, effectively marking it as the point at infinity.
- **Inputs**:
    - `r`: A pointer to a `fd_bn254_g1_t` structure representing a point in the G1 group, which will be modified to represent the point at infinity.
- **Control Flow**:
    - The function calls `fd_bn254_fp_set_zero` on the Z coordinate of the input point `r`, setting it to zero.
    - The function returns the modified point `r`.
- **Output**: The function returns a pointer to the modified `fd_bn254_g1_t` structure, which now represents the point at infinity.


---
### fd\_bn254\_g1\_to\_affine<!-- {{#callable:fd_bn254_g1_to_affine}} -->
The `fd_bn254_g1_to_affine` function converts a point on the BN254 curve from projective coordinates to affine coordinates.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g1_t` structure where the result will be stored.
    - `p`: A constant pointer to an `fd_bn254_g1_t` structure representing the point in projective coordinates to be converted.
- **Control Flow**:
    - Check if the Z coordinate of point `p` is zero or one, which indicates that the point is already in affine form; if so, copy `p` to `r` and return `r`.
    - Declare temporary variables `iz` and `iz2` for storing the inverse and square of the inverse of `p->Z`, respectively.
    - Calculate the inverse of `p->Z` and store it in `iz`.
    - Square `iz` and store the result in `iz2`.
    - Multiply `p->X` by `iz2` and store the result in `r->X`.
    - Multiply `p->Y` by `iz2`, then multiply the result by `iz`, and store the final result in `r->Y`.
    - Set `r->Z` to one, indicating that the result is now in affine coordinates.
    - Return the pointer `r`.
- **Output**: A pointer to the `fd_bn254_g1_t` structure `r`, which now contains the point in affine coordinates.
- **Functions called**:
    - [`fd_bn254_g1_set`](#fd_bn254_g1_set)


---
### fd\_bn254\_g1\_tobytes<!-- {{#callable:fd_bn254_g1_tobytes}} -->
The `fd_bn254_g1_tobytes` function converts a point on the BN254 curve from its internal representation to a 64-byte big-endian format.
- **Inputs**:
    - `out`: A 64-byte array where the serialized point will be stored.
    - `p`: A pointer to a `fd_bn254_g1_t` structure representing the point on the BN254 curve to be serialized.
- **Control Flow**:
    - Check if the point `p` is the zero point using [`fd_bn254_g1_is_zero`](#fd_bn254_g1_is_zero); if true, set all 64 bytes of `out` to zero and return `out`.
    - Convert the point `p` to its affine coordinates using [`fd_bn254_g1_to_affine`](#fd_bn254_g1_to_affine).
    - Convert the X and Y coordinates from Montgomery form to standard form using `fd_bn254_fp_from_mont`.
    - Serialize the X coordinate to the first 32 bytes of `out` using `fd_bn254_fp_tobytes_be_nm`.
    - Serialize the Y coordinate to the next 32 bytes of `out` using `fd_bn254_fp_tobytes_be_nm`.
    - Return the `out` array.
- **Output**: A pointer to the `out` array containing the serialized 64-byte representation of the point.
- **Functions called**:
    - [`fd_bn254_g1_is_zero`](#fd_bn254_g1_is_zero)
    - [`fd_bn254_g1_to_affine`](#fd_bn254_g1_to_affine)


---
### fd\_bn254\_g1\_affine\_add<!-- {{#callable:fd_bn254_g1_affine_add}} -->
The `fd_bn254_g1_affine_add` function computes the sum of two affine points on an elliptic curve in the BN254 G1 group and stores the result in a given output point.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g1_t` structure where the result of the addition will be stored.
    - `p`: A constant pointer to an `fd_bn254_g1_t` structure representing the first point to be added.
    - `q`: A constant pointer to an `fd_bn254_g1_t` structure representing the second point to be added.
- **Control Flow**:
    - Check if point `p` is zero; if so, set `r` to `q` and return `r`.
    - Check if point `q` is zero; if so, set `r` to `p` and return `r`.
    - Declare temporary variables `lambda`, `x`, and `y` for intermediate calculations.
    - Check if the X-coordinates of `p` and `q` are equal.
    - If the Y-coordinates are also equal, compute the point doubling using the formula for `lambda` and update `r`.
    - If the Y-coordinates are not equal, set `r` to zero as `p` and `q` are additive inverses.
    - If the X-coordinates are not equal, compute the point addition using the formula for `lambda`.
    - Calculate the new X-coordinate `x3` using `lambda`, `p->X`, and `q->X`.
    - Calculate the new Y-coordinate `y3` using `lambda`, `p->X`, `x3`, and `p->Y`.
    - Set the result point `r` with the new coordinates and set `r->Z` to one.
- **Output**: A pointer to the `fd_bn254_g1_t` structure `r` containing the result of the addition.
- **Functions called**:
    - [`fd_bn254_g1_is_zero`](#fd_bn254_g1_is_zero)
    - [`fd_bn254_g1_set`](#fd_bn254_g1_set)
    - [`fd_bn254_g1_set_zero`](#fd_bn254_g1_set_zero)


---
### fd\_bn254\_g1\_dbl<!-- {{#callable:fd_bn254_g1_dbl}} -->
The `fd_bn254_g1_dbl` function computes the doubling of a point on an elliptic curve in Jacobian coordinates.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g1_t` structure where the result of the doubling operation will be stored.
    - `p`: A constant pointer to an `fd_bn254_g1_t` structure representing the point to be doubled.
- **Control Flow**:
    - Check if the input point `p` is the point at infinity (zero point); if so, set the result `r` to the point at infinity and return.
    - Compute the square of the X, Y, and Z coordinates of the point `p`, storing them in `xx`, `yy`, and `zz` respectively.
    - Compute `y4` as the square of `yy`, which is `Y^4`.
    - Calculate `s` as `2 * ((X + YY)^2 - XX - YYYY)`.
    - Calculate `m` as `3 * XX` since the curve parameter `a` is zero.
    - Compute the new X coordinate `X3` as `M^2 - 2 * S`.
    - Compute the new Z coordinate `Z3` as `(Y + Z)^2 - YY - ZZ`.
    - Compute the new Y coordinate `Y3` as `M * (S - T) - 8 * YYYY`.
    - Return the result `r` containing the doubled point.
- **Output**: A pointer to the `fd_bn254_g1_t` structure `r`, which contains the doubled point.
- **Functions called**:
    - [`fd_bn254_g1_is_zero`](#fd_bn254_g1_is_zero)
    - [`fd_bn254_g1_set_zero`](#fd_bn254_g1_set_zero)


---
### fd\_bn254\_g1\_add\_mixed<!-- {{#callable:fd_bn254_g1_add_mixed}} -->
The `fd_bn254_g1_add_mixed` function computes the sum of two elliptic curve points `p` and `q` in Jacobian coordinates, where `q` is assumed to be in affine coordinates (i.e., `q->Z == 1`).
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g1_t` structure where the result of the addition will be stored.
    - `p`: A pointer to a constant `fd_bn254_g1_t` structure representing the first point in Jacobian coordinates.
    - `q`: A pointer to a constant `fd_bn254_g1_t` structure representing the second point in affine coordinates (Z coordinate is 1).
- **Control Flow**:
    - Check if point `p` is zero; if so, set `r` to `q` and return `r`.
    - Compute `Z1Z1` as the square of `p->Z`.
    - Compute `U2` as the product of `q->X` and `Z1Z1`.
    - Compute `S2` as the product of `q->Y`, `p->Z`, and `Z1Z1`.
    - Check if `p` equals `q` by comparing `U2` with `p->X` and `S2` with `p->Y`; if they are equal, call [`fd_bn254_g1_dbl`](#fd_bn254_g1_dbl) to double `p` and return the result.
    - Compute `H` as the difference between `U2` and `p->X`.
    - Compute `HH` as the square of `H`.
    - Compute `I` as four times `HH`.
    - Compute `J` as the product of `H` and `I`.
    - Compute `r` as twice the difference between `S2` and `p->Y`.
    - Compute `V` as the product of `p->X` and `I`.
    - Compute `X3` as the square of `r` minus `J` minus twice `V`.
    - Compute `Y3` as `r` times the difference between `V` and `X3` minus twice the product of `p->Y` and `J`.
    - Compute `Z3` as the square of the sum of `p->Z` and `H` minus `Z1Z1` and `HH`.
    - Return the result `r`.
- **Output**: The function returns a pointer to the `fd_bn254_g1_t` structure `r`, which contains the result of the addition of points `p` and `q`.
- **Functions called**:
    - [`fd_bn254_g1_is_zero`](#fd_bn254_g1_is_zero)
    - [`fd_bn254_g1_set`](#fd_bn254_g1_set)
    - [`fd_bn254_g1_dbl`](#fd_bn254_g1_dbl)


---
### fd\_bn254\_g1\_scalar\_mul<!-- {{#callable:fd_bn254_g1_scalar_mul}} -->
The `fd_bn254_g1_scalar_mul` function performs scalar multiplication on a point in the BN254 G1 group, computing the result of multiplying a point `p` by a scalar `s` and storing the result in `r`.
- **Inputs**:
    - `r`: A pointer to an `fd_bn254_g1_t` structure where the result of the scalar multiplication will be stored.
    - `p`: A constant pointer to an `fd_bn254_g1_t` structure representing the point to be multiplied, assumed to be in affine form (i.e., `p->Z == 1`).
    - `s`: A constant pointer to an `fd_bn254_scalar_t` structure representing the scalar by which the point `p` is to be multiplied.
- **Control Flow**:
    - Initialize an integer `i` to 255, representing the bit index of the scalar `s`.
    - Iterate from the most significant bit to the least significant bit of `s`, decrementing `i` until a set bit is found or `i` becomes negative.
    - If no set bit is found (i.e., `i` is negative), set `r` to the zero point using [`fd_bn254_g1_set_zero`](#fd_bn254_g1_set_zero) and return `r`.
    - Set `r` to the value of `p` using [`fd_bn254_g1_set`](#fd_bn254_g1_set).
    - For each bit from `i-1` down to 0, double the point `r` using [`fd_bn254_g1_dbl`](#fd_bn254_g1_dbl).
    - If the current bit of `s` is set, add the point `p` to `r` using [`fd_bn254_g1_add_mixed`](#fd_bn254_g1_add_mixed).
    - Return the resulting point `r`.
- **Output**: A pointer to the `fd_bn254_g1_t` structure `r`, which contains the result of the scalar multiplication.
- **Functions called**:
    - [`fd_bn254_g1_set_zero`](#fd_bn254_g1_set_zero)
    - [`fd_bn254_g1_set`](#fd_bn254_g1_set)
    - [`fd_bn254_g1_dbl`](#fd_bn254_g1_dbl)
    - [`fd_bn254_g1_add_mixed`](#fd_bn254_g1_add_mixed)


---
### fd\_bn254\_g1\_frombytes\_internal<!-- {{#callable:fd_bn254_g1_frombytes_internal}} -->
The `fd_bn254_g1_frombytes_internal` function converts a 64-byte input into a G1 point on the BN254 curve, handling special cases and performing basic validity checks.
- **Inputs**:
    - `p`: A pointer to an `fd_bn254_g1_t` structure where the resulting G1 point will be stored.
    - `in`: A constant 64-byte array representing the input data to be converted into a G1 point.
- **Control Flow**:
    - Check if the input byte array is all zeros, which indicates a point at infinity, and set the output point to zero if true.
    - Attempt to convert the first 32 bytes of the input into the X coordinate of the G1 point, returning NULL if the conversion fails.
    - Attempt to convert the next 32 bytes of the input into the Y coordinate of the G1 point, checking for flags indicating infinity or negativity, and return NULL if the conversion fails.
    - If the Y coordinate indicates infinity, set the output point to zero.
    - Set the Z coordinate of the output point to one, indicating an affine point, and return the pointer to the output point.
- **Output**: A pointer to the `fd_bn254_g1_t` structure containing the converted G1 point, or NULL if the conversion fails.
- **Functions called**:
    - [`fd_bn254_g1_set_zero`](#fd_bn254_g1_set_zero)


---
### fd\_bn254\_g1\_frombytes\_check\_subgroup<!-- {{#callable:fd_bn254_g1_frombytes_check_subgroup}} -->
The `fd_bn254_g1_frombytes_check_subgroup` function converts a byte array into a G1 group element and verifies its subgroup membership.
- **Inputs**:
    - `p`: A pointer to a `fd_bn254_g1_t` structure where the resulting G1 group element will be stored.
    - `in`: A constant byte array of 64 bytes representing the input data to be converted into a G1 group element.
- **Control Flow**:
    - Call [`fd_bn254_g1_frombytes_internal`](#fd_bn254_g1_frombytes_internal) to convert the byte array `in` into a G1 element stored in `p`; return NULL if this fails.
    - Check if the point `p` is the zero element using [`fd_bn254_g1_is_zero`](#fd_bn254_g1_is_zero); if so, return `p`.
    - Convert the X and Y coordinates of `p` to Montgomery form using `fd_bn254_fp_to_mont`.
    - Set the Z coordinate of `p` to one using `fd_bn254_fp_set_one`.
    - Compute `y^2` and `x^3 + b` to verify the curve equation `y^2 = x^3 + b`; return NULL if they are not equal.
    - Return the pointer `p` as the G1 element is valid and in the correct subgroup.
- **Output**: A pointer to the `fd_bn254_g1_t` structure `p` if the conversion and checks are successful, otherwise NULL.
- **Functions called**:
    - [`fd_bn254_g1_frombytes_internal`](#fd_bn254_g1_frombytes_internal)
    - [`fd_bn254_g1_is_zero`](#fd_bn254_g1_is_zero)


