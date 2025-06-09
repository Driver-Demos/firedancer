# Purpose
The provided code is a C header file, `fd_curve25519.h`, which defines the public API for operations on the Curve25519 elliptic curve, specifically tailored for use with the Ed25519 signature scheme. This file is part of a cryptographic library and provides a comprehensive set of functions for performing arithmetic operations on points on the Curve25519 curve. The operations include point addition, doubling, subtraction, negation, and scalar multiplication, among others. The file also includes functions for serializing and deserializing points to and from byte arrays, which is crucial for interoperability and storage. The header is designed to be included in other C source files, providing a standardized interface for cryptographic operations involving Curve25519.

The file is structured to support both reference and optimized implementations, with conditional compilation directives to include architecture-specific optimizations, such as AVX-512, if available. It defines several constants and macros, including a maximum batch size for multi-scalar multiplication (MSM), and provides inline functions for certain operations to enhance performance. The API is designed with security considerations in mind, explicitly marking constant-time operations to prevent side-channel attacks when handling secret data. The header file is a critical component of a cryptographic library, offering a robust and flexible interface for developers implementing secure communication protocols or cryptographic applications.
# Imports and Dependencies

---
- `avx512/fd_curve25519.h`
- `ref/fd_curve25519.h`


# Global Variables

---
### fd\_ed25519\_base\_point
- **Type**: `fd_ed25519_point_t`
- **Description**: The `fd_ed25519_base_point` is a static constant array of type `fd_ed25519_point_t` with a single element. It represents the base point used in elliptic curve operations for the Ed25519 curve, which is a specific point on the curve that is used as a starting point for scalar multiplication operations.
- **Use**: This variable is used as the base point in various elliptic curve operations, such as scalar multiplication, within the Ed25519 cryptographic functions.


---
### fd\_ed25519\_base\_point\_wnaf\_table
- **Type**: `fd_ed25519_point_t[128]`
- **Description**: The `fd_ed25519_base_point_wnaf_table` is a static constant array of 128 elements, each of type `fd_ed25519_point_t`. This array is used to store precomputed values of the Ed25519 base point for use in windowed non-adjacent form (wNAF) scalar multiplication, which is a technique to optimize elliptic curve point multiplication.
- **Use**: This variable is used to optimize scalar multiplication operations on the Ed25519 curve by providing precomputed base point values for the wNAF method.


---
### fd\_ed25519\_base\_point\_const\_time\_table
- **Type**: `fd_ed25519_point_t[32][8]`
- **Description**: The `fd_ed25519_base_point_const_time_table` is a static constant two-dimensional array of `fd_ed25519_point_t` structures, with dimensions 32 by 8. It is used to store precomputed values of the Ed25519 base point for constant-time scalar multiplication operations.
- **Use**: This variable is used to facilitate constant-time scalar multiplication with the Ed25519 base point, ensuring operations are secure against timing attacks.


---
### fd\_ed25519\_point\_dbln
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_point_dbln` is a function pointer that computes the result of doubling an Ed25519 point `a` a specified number of times `n`, storing the result in `r`. It is more efficient than performing the addition operation `n` times.
- **Use**: This function is used to perform multiple doublings of an Ed25519 point efficiently, which is a common operation in elliptic curve cryptography.


---
### fd\_ed25519\_point\_sub
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_point_sub` is a function that computes the subtraction of two Ed25519 points, `a` and `b`, and stores the result in the point `r`. It returns a pointer to the result point `r`. The operation is complete, meaning it can handle cases where `a` is equal to `b`. The cost of this operation is equivalent to 9 multiplications.
- **Use**: This function is used to perform point subtraction in elliptic curve operations, specifically for the Ed25519 curve.


---
### fd\_ed25519\_point\_set\_zero
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_point_set_zero` is a function that takes a pointer to an `fd_ed25519_point_t` structure and sets it to represent the point at infinity on the Ed25519 curve. This is effectively setting the point to zero in the context of elliptic curve operations.
- **Use**: This function is used to initialize or reset an Ed25519 point to the point at infinity, which is a neutral element in elliptic curve arithmetic.


---
### fd\_ed25519\_point\_set\_zero\_precomputed
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_point_set_zero_precomputed` is a function pointer that points to a function which sets a given `fd_ed25519_point_t` structure to represent the point at infinity on the Ed25519 curve. This is a special point used in elliptic curve operations.
- **Use**: This function is used to initialize or reset a point to the identity element of the elliptic curve, which is useful in various cryptographic operations.


---
### fd\_ed25519\_point\_set
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_point_set` is a function that sets the value of the point `r` to the value of the point `a`. It is part of the Curve25519 API, which is used for elliptic curve cryptography operations.
- **Use**: This function is used to copy the value of one elliptic curve point to another.


---
### fd\_ed25519\_point\_from
- **Type**: `fd_ed25519_point_t *`
- **Description**: The `fd_ed25519_point_from` function is a global function that initializes an Ed25519 point structure `r` using the provided field elements `x`, `y`, `z`, and `t`. These elements represent the coordinates of the point in projective coordinates.
- **Use**: This function is used to set the coordinates of an Ed25519 point from given field elements, effectively constructing a point in the Ed25519 curve.


---
### fd\_ed25519\_point\_neg
- **Type**: `function pointer`
- **Description**: `fd_ed25519_point_neg` is a function that computes the negation of an Ed25519 point. It takes a pointer to a destination point `r` and a constant pointer to a source point `a`, and returns a pointer to the destination point `r` after setting it to the negation of `a`. This function is part of the Curve25519 API, which is used for elliptic curve cryptography operations.
- **Use**: This function is used to compute the negation of an Ed25519 point, which is a common operation in elliptic curve cryptography.


---
### fd\_ed25519\_point\_dbl
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_point_dbl` is a function pointer that points to a function which computes the doubling of an Ed25519 point. It takes two parameters: a pointer to a `fd_ed25519_point_t` structure where the result will be stored, and a constant pointer to a `fd_ed25519_point_t` structure representing the point to be doubled.
- **Use**: This function is used to perform the mathematical operation of doubling a point on the Ed25519 elliptic curve, which is a common operation in elliptic curve cryptography.


---
### fd\_ed25519\_scalar\_mul
- **Type**: `function`
- **Description**: The `fd_ed25519_scalar_mul` function computes the scalar multiplication of an Ed25519 point by a scalar. It takes a pointer to a result point `r`, a 32-byte scalar `n`, and a pointer to an Ed25519 point `a`, and returns the result of the multiplication stored in `r`. This function is part of the Ed25519 cryptographic operations, which are used in various cryptographic protocols.
- **Use**: This function is used to perform scalar multiplication of an Ed25519 point, which is a fundamental operation in elliptic curve cryptography.


---
### fd\_ed25519\_double\_scalar\_mul\_base
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_double_scalar_mul_base` is a function that computes the result of a double scalar multiplication on the Ed25519 curve. It takes two scalars, `n1` and `n2`, and a point `a`, and computes the result as `r = n1 * a + n2 * P`, where `P` is the base point of the curve.
- **Use**: This function is used to perform a double scalar multiplication operation on the Ed25519 curve, which is a common operation in cryptographic algorithms.


---
### fd\_ed25519\_multi\_scalar\_mul
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_multi_scalar_mul` is a function that computes the result of a multi-scalar multiplication operation on a set of Ed25519 points. It takes as input a result point `r`, an array of scalars `n`, an array of points `a`, and the size `sz` of these arrays. The function returns the result point `r` after computing the sum of each scalar multiplied by its corresponding point.
- **Use**: This function is used to perform multi-scalar multiplication on Ed25519 points, which is a common operation in cryptographic algorithms and protocols.


---
### fd\_ed25519\_multi\_scalar\_mul\_base
- **Type**: `function`
- **Description**: The `fd_ed25519_multi_scalar_mul_base` function computes a multi-scalar multiplication where the first point is replaced by the base point. It takes an array of scalars `n`, an array of points `a`, and the size `sz` of these arrays, and computes the result into the point `r`. This function is part of the Ed25519 elliptic curve operations, specifically optimized for scenarios where the first point is the base point.
- **Use**: This function is used to perform multi-scalar multiplication with the base point in elliptic curve cryptography operations.


---
### fd\_ed25519\_point\_frombytes
- **Type**: `fd_ed25519_point_t *`
- **Description**: The `fd_ed25519_point_frombytes` function is a global function that deserializes a 32-byte buffer into an Ed25519 point. It takes a pointer to an `fd_ed25519_point_t` structure and a constant 32-byte buffer as input, and returns a pointer to the deserialized point on success or NULL on error.
- **Use**: This function is used to convert a serialized byte representation of an Ed25519 point into its corresponding point structure for further cryptographic operations.


---
### fd\_ed25519\_point\_tobytes
- **Type**: `function pointer`
- **Description**: The `fd_ed25519_point_tobytes` function is a global function that serializes an Ed25519 point into a 32-byte buffer. The function takes a pointer to a 32-byte output buffer and a constant pointer to an Ed25519 point structure as its parameters. The output buffer is filled with the serialized point in little-endian format, as specified by RFC 8032.
- **Use**: This function is used to convert an Ed25519 point into a byte array for storage or transmission.


---
### fd\_curve25519\_affine\_frombytes
- **Type**: `function`
- **Description**: The `fd_curve25519_affine_frombytes` function is designed to convert two 32-byte arrays representing the x and y coordinates of a point into an affine point on the Curve25519 elliptic curve. It returns a pointer to an `fd_ed25519_point_t` structure, which represents the point in affine coordinates.
- **Use**: This function is used to deserialize x and y coordinates into an affine point for operations on the Curve25519 elliptic curve.


---
### fd\_curve25519\_into\_affine
- **Type**: `function`
- **Description**: The `fd_curve25519_into_affine` function is a global function that converts a given point on the Curve25519 elliptic curve into its affine representation. The function takes a pointer to an `fd_ed25519_point_t` structure as an argument and returns a pointer to the same type, representing the affine point.
- **Use**: This function is used to transform a point into its affine form, which is often required for certain mathematical operations or optimizations in elliptic curve computations.


---
### fd\_curve25519\_affine\_add
- **Type**: `function pointer`
- **Description**: `fd_curve25519_affine_add` is a function that performs the addition of two points on the Curve25519 elliptic curve in affine coordinates. It takes three parameters: a pointer to the result point `r`, and two constant pointers to the points `a` and `b` to be added. The function returns a pointer to the resulting point `r`.
- **Use**: This function is used to compute the sum of two elliptic curve points in affine coordinates, which is a fundamental operation in elliptic curve cryptography.


---
### fd\_curve25519\_affine\_dbln
- **Type**: `function pointer`
- **Description**: `fd_curve25519_affine_dbln` is a function that computes the result of doubling an elliptic curve point `a` a specified number of times `n` and stores the result in `r`. It operates on points represented in the `fd_ed25519_point_t` structure, which is used for elliptic curve operations in the Curve25519 library.
- **Use**: This function is used to efficiently compute the multiple of a point on the elliptic curve by repeatedly doubling it.


# Functions

---
### fd\_ed25519\_affine\_is\_small\_order<!-- {{#callable:fd_ed25519_affine_is_small_order}} -->
The function `fd_ed25519_affine_is_small_order` checks if a given Ed25519 point has a small order (order ≤ 8).
- **Inputs**:
    - `a`: A pointer to an `fd_ed25519_point_t` structure representing the Ed25519 point to be checked.
- **Control Flow**:
    - The function begins by declaring four `fd_f25519_t` variables: `x`, `y`, `z`, and `t`.
    - It calls [`fd_ed25519_point_to`](avx512/fd_curve25519.h.driver.md#fd_ed25519_point_to) to convert the point `a` into its affine coordinates, storing the results in `x`, `y`, `z`, and `t`.
    - The function then checks if `x` is zero using `fd_f25519_is_zero(x)`.
    - It checks if `y` is zero using `fd_f25519_is_zero(y)`.
    - It checks if `y` is equal to a predefined constant `fd_ed25519_order8_point_y0` using `fd_f25519_eq(y, fd_ed25519_order8_point_y0)`.
    - It checks if `y` is equal to another predefined constant `fd_ed25519_order8_point_y1` using `fd_f25519_eq(y, fd_ed25519_order8_point_y1)`.
    - The function returns the logical OR of all these checks, indicating if the point is of small order.
- **Output**: The function returns an integer: 1 if the point has a small order (order ≤ 8), and 0 otherwise.
- **Functions called**:
    - [`fd_ed25519_point_to`](avx512/fd_curve25519.h.driver.md#fd_ed25519_point_to)


---
### fd\_ed25519\_scalar\_validate<!-- {{#callable:fd_ed25519_scalar_validate}} -->
The `fd_ed25519_scalar_validate` function checks if a given 32-byte Ed25519 scalar is in its canonical byte representation.
- **Inputs**:
    - `n`: A 32-byte array representing the Ed25519 scalar to be validated.
- **Control Flow**:
    - The function directly calls `fd_curve25519_scalar_validate` with the input scalar `n`.
- **Output**: Returns a pointer to the scalar `n` if it is in canonical form, otherwise returns NULL.


---
### fd\_ed25519\_point\_validate<!-- {{#callable:fd_ed25519_point_validate}} -->
The `fd_ed25519_point_validate` function checks if a 32-byte buffer represents a valid compressed Ed25519 point by attempting to decompress it.
- **Inputs**:
    - `buf`: A 32-byte buffer in little-endian form that represents a compressed Ed25519 point.
- **Control Flow**:
    - Declare a temporary variable `t` of type `fd_ed25519_point_t` to store the decompressed point.
    - Call [`fd_ed25519_point_frombytes`](fd_curve25519.c.driver.md#fd_ed25519_point_frombytes) with `t` and `buf` to attempt decompression of the point.
    - Return the result of the decompression attempt as a boolean value, where a non-zero result indicates success.
- **Output**: Returns 1 if the buffer represents a valid point, 0 otherwise.
- **Functions called**:
    - [`fd_ed25519_point_frombytes`](fd_curve25519.c.driver.md#fd_ed25519_point_frombytes)


---
### fd\_ed25519\_affine\_tobytes<!-- {{#callable:fd_ed25519_affine_tobytes}} -->
The function `fd_ed25519_affine_tobytes` serializes an affine Ed25519 point into a 32-byte buffer in little-endian format.
- **Inputs**:
    - `out`: A 32-byte buffer where the serialized point will be stored.
    - `a`: A pointer to an affine Ed25519 point to be serialized.
- **Control Flow**:
    - Declare temporary variables x, y, z, and t of type fd_f25519_t.
    - Call fd_ed25519_point_to to decompose the point 'a' into its x, y, z, and t components.
    - Serialize the y component into the output buffer 'out' using fd_f25519_tobytes.
    - Modify the last byte of 'out' by XORing it with the sign bit of x shifted left by 7 bits.
    - Return the output buffer 'out'.
- **Output**: A pointer to the 32-byte buffer 'out' containing the serialized point.
- **Functions called**:
    - [`fd_ed25519_point_to`](avx512/fd_curve25519.h.driver.md#fd_ed25519_point_to)


# Function Declarations (Public API)

---
### fd\_ed25519\_scalar\_mul<!-- {{#callable_declaration:fd_ed25519_scalar_mul}} -->
Computes the scalar multiplication of an Ed25519 point by a scalar.
- **Description**: Use this function to perform scalar multiplication of an Ed25519 point by a 32-byte scalar. This operation is essential in cryptographic protocols that utilize elliptic curve cryptography, such as key exchange and digital signatures. The function requires a valid Ed25519 point and a scalar in canonical byte representation. The result is stored in the provided point structure, which must not be null. Ensure that the scalar is validated before use, as the function does not perform constant-time operations and should not be used with secret data.
- **Inputs**:
    - `r`: A pointer to an fd_ed25519_point_t structure where the result will be stored. Must not be null. The caller retains ownership.
    - `n`: A 32-byte array representing the scalar multiplier. It should be in canonical byte representation. The function does not validate the scalar, so it should be validated before calling this function.
    - `a`: A pointer to a constant fd_ed25519_point_t structure representing the point to be multiplied. Must not be null. The caller retains ownership.
- **Output**: Returns a pointer to the result point structure, which is the same as the input parameter 'r'.
- **See also**: [`fd_ed25519_scalar_mul`](fd_curve25519.c.driver.md#fd_ed25519_scalar_mul)  (Implementation)


---
### fd\_ed25519\_double\_scalar\_mul\_base<!-- {{#callable_declaration:fd_ed25519_double_scalar_mul_base}} -->
Computes the double scalar multiplication of a point and the base point.
- **Description**: This function calculates the result of the expression n1 * a + n2 * P, where n1 and n2 are 32-byte scalars, a is an Ed25519 point, and P is the Ed25519 base point. It is used in cryptographic operations where such scalar multiplications are required. The function must be called with valid scalars and a valid point. The result is stored in the point r, which must be pre-allocated by the caller. The function returns a pointer to r, allowing for chaining of operations.
- **Inputs**:
    - `r`: A pointer to an fd_ed25519_point_t where the result will be stored. Must be pre-allocated by the caller. The caller retains ownership.
    - `n1`: A 32-byte array representing the first scalar multiplier. Must be a valid scalar.
    - `a`: A pointer to an fd_ed25519_point_t representing the point to be multiplied by n1. Must not be null.
    - `n2`: A 32-byte array representing the second scalar multiplier. Must be a valid scalar.
- **Output**: Returns a pointer to the result stored in r, which represents the computed point n1 * a + n2 * P.
- **See also**: [`fd_ed25519_double_scalar_mul_base`](fd_curve25519.c.driver.md#fd_ed25519_double_scalar_mul_base)  (Implementation)


---
### fd\_ed25519\_multi\_scalar\_mul<!-- {{#callable_declaration:fd_ed25519_multi_scalar_mul}} -->
Computes a multi-scalar multiplication of Ed25519 points.
- **Description**: This function performs a multi-scalar multiplication operation on a set of Ed25519 points and scalars, computing the result as the sum of each scalar multiplied by its corresponding point. It is useful in cryptographic operations where such computations are required. The function initializes the result point to zero and processes the input in batches, adding the results to the output point. It should be called with valid arrays of scalars and points, and the size parameter must accurately reflect the number of elements in these arrays.
- **Inputs**:
    - `r`: A pointer to an fd_ed25519_point_t where the result will be stored. The caller must ensure this is a valid, writable memory location.
    - `n`: An array of scalars, each 32 bytes in size, with a total length of sz * 32 bytes. The caller must ensure this array is valid and contains the correct number of scalars.
    - `a`: An array of fd_ed25519_point_t structures, with a total length of sz. The caller must ensure this array is valid and contains the correct number of points.
    - `sz`: The number of scalars and points in the arrays n and a, respectively. Must be a non-negative integer.
- **Output**: Returns a pointer to the result point r, which contains the computed multi-scalar multiplication result.
- **See also**: [`fd_ed25519_multi_scalar_mul`](fd_curve25519.c.driver.md#fd_ed25519_multi_scalar_mul)  (Implementation)


---
### fd\_ed25519\_multi\_scalar\_mul\_base<!-- {{#callable_declaration:fd_ed25519_multi_scalar_mul_base}} -->
Computes a multi-scalar multiplication using the base point for the first scalar.
- **Description**: This function performs a multi-scalar multiplication where the first scalar in the array is multiplied by the base point, and subsequent scalars are multiplied by the corresponding points in the provided array. It is useful for operations involving multiple scalar multiplications with a fixed base point. The function requires that the number of scalars and points, `sz`, does not exceed the maximum batch size defined by `FD_BALLET_CURVE25519_MSM_BATCH_SZ`. If `sz` exceeds this limit, the function returns `NULL`. This function should be used when the first scalar multiplication involves the base point, and the operation is not constant time, so it should not be used with secret data.
- **Inputs**:
    - `r`: A pointer to an `fd_ed25519_point_t` where the result will be stored. The caller must ensure this is a valid, writable memory location.
    - `n`: An array of scalars, each 32 bytes in size, with a total length of `sz * 32`. The first scalar is used with the base point, and subsequent scalars are used with the corresponding points in `a`. The array must not be null.
    - `a`: An array of `fd_ed25519_point_t` points, with a length of `sz`. These points are multiplied by the corresponding scalars in `n`, except for the first scalar which uses the base point. The array must not be null.
    - `sz`: The number of scalars and points in the arrays `n` and `a`. Must be a positive number not exceeding `FD_BALLET_CURVE25519_MSM_BATCH_SZ`. If `sz` is greater than this limit, the function returns `NULL`.
- **Output**: Returns a pointer to `r` containing the result of the multi-scalar multiplication, or `NULL` if `sz` exceeds the maximum batch size.
- **See also**: [`fd_ed25519_multi_scalar_mul_base`](fd_curve25519.c.driver.md#fd_ed25519_multi_scalar_mul_base)  (Implementation)


---
### fd\_ed25519\_point\_frombytes<!-- {{#callable_declaration:fd_ed25519_point_frombytes}} -->
Deserializes a 32-byte buffer into an Ed25519 point.
- **Description**: This function converts a 32-byte buffer, formatted in little-endian according to RFC 8032, into an Ed25519 point. It should be used when you need to interpret a serialized point representation as an Ed25519 point. The function returns the point on success or NULL if the buffer does not represent a valid point. This function is not constant time and should not be used with secret data.
- **Inputs**:
    - `r`: A pointer to an fd_ed25519_point_t where the deserialized point will be stored. The caller must ensure this pointer is valid and has sufficient space to store the point.
    - `buf`: A constant 32-byte array representing the serialized point in little-endian format. The buffer must not be null and should be properly formatted according to RFC 8032.
- **Output**: Returns a pointer to the deserialized point on success, or NULL if the buffer does not represent a valid point.
- **See also**: [`fd_ed25519_point_frombytes`](fd_curve25519.c.driver.md#fd_ed25519_point_frombytes)  (Implementation)


---
### fd\_ed25519\_point\_tobytes<!-- {{#callable_declaration:fd_ed25519_point_tobytes}} -->
Serializes an Ed25519 point into a 32-byte buffer.
- **Description**: This function converts an Ed25519 point into its 32-byte compressed form, suitable for storage or transmission. It should be used when you need to serialize a point for interoperability with other systems or for compact storage. The function assumes that the input point is valid and properly initialized. The output buffer must be at least 32 bytes in size, and the function will write the serialized point in little-endian format as specified by RFC 8032. The caller is responsible for ensuring that the input point is not null.
- **Inputs**:
    - `out`: A buffer of at least 32 bytes where the serialized point will be stored. The caller must ensure this buffer is valid and has sufficient space.
    - `a`: A pointer to a constant fd_ed25519_point_t structure representing the point to be serialized. This must not be null and should point to a valid Ed25519 point.
- **Output**: Returns a pointer to the output buffer containing the serialized point.
- **See also**: [`fd_ed25519_point_tobytes`](fd_curve25519.c.driver.md#fd_ed25519_point_tobytes)  (Implementation)


---
### fd\_curve25519\_affine\_add<!-- {{#callable_declaration:fd_curve25519_affine_add}} -->
Adds two Ed25519 points and converts the result to affine coordinates.
- **Description**: Use this function to compute the sum of two Ed25519 points and obtain the result in affine coordinates. This function is suitable for operations where the result needs to be in affine form, such as when building precomputation tables. Ensure that the input points are valid Ed25519 points. The function modifies the point `r` to store the result and returns it. It is important to note that the operation is not constant time and should not be used with secret data.
- **Inputs**:
    - `r`: A pointer to an `fd_ed25519_point_t` where the result will be stored. Must not be null. The caller retains ownership.
    - `a`: A pointer to a constant `fd_ed25519_point_t` representing the first point to add. Must not be null. The caller retains ownership.
    - `b`: A pointer to a constant `fd_ed25519_point_t` representing the second point to add. Must not be null. The caller retains ownership.
- **Output**: Returns a pointer to `r`, which contains the result of the addition in affine coordinates.
- **See also**: [`fd_curve25519_affine_add`](fd_curve25519.c.driver.md#fd_curve25519_affine_add)  (Implementation)


---
### fd\_curve25519\_affine\_dbln<!-- {{#callable_declaration:fd_curve25519_affine_dbln}} -->
Computes the n-fold doubling of a point and converts it to affine coordinates.
- **Description**: This function performs the n-fold doubling of an Ed25519 point and then converts the resulting point into affine coordinates. It is useful when you need the affine representation of a point after multiple doublings. The function should be called with a valid Ed25519 point and a non-negative integer specifying the number of doublings. The result is stored in the provided output parameter, which must not be null.
- **Inputs**:
    - `r`: A pointer to an fd_ed25519_point_t where the result will be stored. Must not be null. The caller retains ownership.
    - `a`: A pointer to a constant fd_ed25519_point_t representing the point to be doubled. Must not be null. The caller retains ownership.
    - `n`: An integer specifying the number of times the point should be doubled. Must be non-negative.
- **Output**: Returns a pointer to the resulting fd_ed25519_point_t in affine coordinates, which is the same as the input parameter 'r'.
- **See also**: [`fd_curve25519_affine_dbln`](fd_curve25519.c.driver.md#fd_curve25519_affine_dbln)  (Implementation)


