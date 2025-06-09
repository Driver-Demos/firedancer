# Purpose
This C header file, `fd_bn254.h`, provides utility functions for operations on the bn254 (alt_bn128) elliptic curve, which is commonly used in cryptographic applications, particularly in zero-knowledge proofs and blockchain technologies. The file defines a set of functions that facilitate arithmetic operations on points in the G1 and G2 groups of the bn254 curve, including addition, scalar multiplication, and pairing checks. It also includes functions for compressing and decompressing points in these groups, which are essential for efficient data storage and transmission. The file is structured to be included in other C source files, providing a public API for bn254 curve operations.

The header file includes other necessary headers, such as `fd_ballet_base.h`, `fd_uint256.h`, and `fd_bn254_scalar.h`, indicating dependencies on foundational and scalar arithmetic functionalities. The defined functions use big-endian byte arrays to represent points and coordinates, ensuring compatibility with various cryptographic protocols. The file also sets a constant, `FD_BN254_PAIRING_BATCH_MAX`, which likely defines a limit for batch processing of pairings, optimizing performance for applications that require multiple pairing computations. Overall, this header file is a specialized component designed to be integrated into larger cryptographic systems, providing essential operations for bn254 curve manipulation.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `../bigint/fd_uint256.h`
- `./fd_bn254_scalar.h`


# Global Variables

---
### fd\_bn254\_g1\_compress
- **Type**: `function pointer`
- **Description**: The `fd_bn254_g1_compress` is a function that compresses a point in the G1 group of the bn254 elliptic curve. It takes a 64-byte input buffer representing the point (x, y) and outputs a 32-byte buffer containing the x-coordinate with additional flags. The function returns the output buffer on success or NULL on failure.
- **Use**: This function is used to reduce the size of a point representation in the G1 group by compressing it to only include the x-coordinate and necessary flags.


---
### fd\_bn254\_g1\_decompress
- **Type**: `function pointer`
- **Description**: The `fd_bn254_g1_decompress` is a function that decompresses a point in the G1 group of the bn254 elliptic curve. It takes a 32-byte big endian buffer representing the x-coordinate of a point, with additional flags, and outputs a 64-byte big endian buffer containing the (x, y) coordinates of the point, with no flags set. The function returns the output buffer on success, or NULL on failure, and success implies that the point (x, y) is in G1.
- **Use**: This function is used to convert a compressed representation of a point in the G1 group into its full (x, y) coordinate form.


---
### fd\_bn254\_g2\_compress
- **Type**: `function pointer`
- **Description**: The `fd_bn254_g2_compress` is a function that compresses a point in the G2 group of the bn254 elliptic curve. It takes a 128-byte big endian buffer representing the point (x, y) in Fp2 as input and outputs a 64-byte big endian buffer containing the x-coordinate with appropriate flags set. The function does not verify if the point is in G2.
- **Use**: This function is used to reduce the size of a point representation in the G2 group by compressing it from 128 bytes to 64 bytes.


---
### fd\_bn254\_g2\_decompress
- **Type**: `function`
- **Description**: The `fd_bn254_g2_decompress` function is designed to decompress a point in the G2 group of the bn254 (alt_bn128) elliptic curve. It takes a 64-byte big endian buffer representing the x-coordinate of a point, with additional flags, and outputs a 128-byte big endian buffer containing the full (x, y) coordinates of the point, without flags. The function returns the output buffer on success or NULL on failure, but it does not verify that the decompressed point is actually in G2.
- **Use**: This function is used to convert a compressed representation of a point in the G2 group into its full coordinate form.


# Function Declarations (Public API)

---
### fd\_bn254\_g1\_add\_syscall<!-- {{#callable_declaration:fd_bn254_g1_add_syscall}} -->
Adds two points on the bn254 G1 curve and outputs the result.
- **Description**: This function performs an addition of two points on the bn254 G1 elliptic curve and writes the result to the provided output buffer. It expects the input to be a serialized representation of two points, each 64 bytes long, making a total of 128 bytes. If the input size exceeds 128 bytes, the function returns an error. The function validates that each point is in the correct subgroup before performing the addition. It should be used when you need to compute the sum of two G1 points and have the result serialized in a 64-byte buffer. Ensure that the input buffer is correctly formatted and that the output buffer is allocated with sufficient space before calling this function.
- **Inputs**:
    - `out`: A 64-byte buffer where the result of the point addition will be stored. The caller must ensure this buffer is allocated and has sufficient space.
    - `in`: A pointer to a buffer containing the serialized representation of two G1 points, each 64 bytes long. The buffer must not be null and should contain at most 128 bytes.
    - `in_sz`: The size of the input buffer in bytes. It must not exceed 128 bytes; otherwise, the function will return an error.
- **Output**: Returns 0 on success, indicating the points were added and the result is stored in the output buffer. Returns -1 if the input size is invalid or if the points are not in the correct subgroup.
- **See also**: [`fd_bn254_g1_add_syscall`](fd_bn254.c.driver.md#fd_bn254_g1_add_syscall)  (Implementation)


---
### fd\_bn254\_g1\_scalar\_mul\_syscall<!-- {{#callable_declaration:fd_bn254_g1_scalar_mul_syscall}} -->
Performs scalar multiplication on a G1 point of the bn254 curve.
- **Description**: This function computes the scalar multiplication of a point on the bn254 (alt_bn128) curve with a given scalar. It is used when you need to perform cryptographic operations involving elliptic curve points and scalars. The function requires a specific input format and size, and it can optionally check for the correct input size. The result of the multiplication is stored in the provided output buffer. The function must be called with valid input parameters, and it will return an error if the input size exceeds the expected limit or if the point is not in the correct subgroup.
- **Inputs**:
    - `out`: A 64-byte buffer where the result of the scalar multiplication will be stored. The caller must ensure this buffer is properly allocated and has the correct size.
    - `in`: A pointer to the input buffer containing the point and scalar. The input must be formatted correctly, with the point and scalar in big-endian format. The caller retains ownership of this buffer.
    - `in_sz`: The size of the input buffer. It must not exceed 96 bytes if `check_correct_sz` is true, or 128 bytes otherwise. If the size is larger than expected, the function returns an error.
    - `check_correct_sz`: An integer flag indicating whether to enforce a 96-byte input size check. If set to a non-zero value, the function expects the input size to be 96 bytes; otherwise, it allows up to 128 bytes.
- **Output**: Returns 0 on success, indicating the scalar multiplication was performed and the result is stored in `out`. Returns -1 on failure, such as when the input size is invalid or the point is not in the correct subgroup.
- **See also**: [`fd_bn254_g1_scalar_mul_syscall`](fd_bn254.c.driver.md#fd_bn254_g1_scalar_mul_syscall)  (Implementation)


---
### fd\_bn254\_pairing\_is\_one\_syscall<!-- {{#callable_declaration:fd_bn254_pairing_is_one_syscall}} -->
Checks if the pairing result of input points is one.
- **Description**: This function evaluates whether the pairing of a series of points, provided in the input buffer, results in the identity element (one) in the target group. It is used to verify cryptographic pairings on the bn254 curve. The function expects the input to be a sequence of serialized points, each 192 bytes long, representing elements in G1 and G2. The output is a 32-byte buffer where the last byte is set to 1 if the pairing result is one, otherwise it remains zero. The function returns an error if any point fails to deserialize or is not in the correct subgroup, and it skips pairings where either point is at infinity.
- **Inputs**:
    - `out`: A 32-byte buffer where the result is stored. The buffer is set to zero, except for the last byte, which is set to 1 if the pairing result is one. The caller must provide a valid buffer of at least 32 bytes.
    - `in`: A pointer to a buffer containing serialized points. Each point is 192 bytes long, and the buffer must contain a multiple of 192 bytes. The caller retains ownership of the buffer.
    - `in_sz`: The size of the input buffer in bytes. It must be a multiple of 192, as each point is 192 bytes. If this condition is not met, the function will not perform the check correctly.
- **Output**: Returns 0 on success, with the result stored in the 'out' buffer. Returns -1 if any point fails to deserialize or is not in the correct subgroup.
- **See also**: [`fd_bn254_pairing_is_one_syscall`](fd_bn254.c.driver.md#fd_bn254_pairing_is_one_syscall)  (Implementation)


---
### fd\_bn254\_g1\_compress<!-- {{#callable_declaration:fd_bn254_g1_compress}} -->
Compress a point in G1 to a 32-byte buffer.
- **Description**: This function compresses a point in the G1 group of the bn254 curve, represented by a 64-byte input buffer, into a 32-byte output buffer. The input buffer must contain the x and y coordinates of the point in big-endian format, along with any additional flags. The output buffer will contain the x coordinate, also in big-endian format, with appropriate flags set to indicate properties such as point at infinity or negative y-coordinate. This function does not verify if the input point is valid within G1, and it returns NULL if the compression fails.
- **Inputs**:
    - `out`: A 32-byte buffer where the compressed point will be stored. The caller must ensure this buffer is allocated and has sufficient space.
    - `in`: A 64-byte buffer containing the x and y coordinates of the point in big-endian format, along with additional flags. The input must be correctly formatted, but the function does not check if the point is valid in G1.
- **Output**: Returns the output buffer on success, or NULL if the compression fails.
- **See also**: [`fd_bn254_g1_compress`](fd_bn254.c.driver.md#fd_bn254_g1_compress)  (Implementation)


---
### fd\_bn254\_g1\_decompress<!-- {{#callable_declaration:fd_bn254_g1_decompress}} -->
Decompresses a point in G1 from its x-coordinate representation.
- **Description**: This function is used to decompress a point in the G1 group of the bn254 curve from a 32-byte big-endian buffer representing the x-coordinate, with additional flags. The output is a 64-byte big-endian buffer containing the full (x, y) coordinates of the point, with no flags set. It should be called when you need to reconstruct the full point from its compressed form. The function returns the output buffer on success, ensuring that the resulting point is valid in G1, or NULL on failure. Special handling is provided for the point at infinity, represented by an all-zero input, which results in an all-zero output.
- **Inputs**:
    - `out`: A 64-byte buffer where the decompressed (x, y) coordinates will be stored. The caller must ensure this buffer is allocated and has sufficient space.
    - `in`: A 32-byte big-endian buffer representing the x-coordinate of a point in G1, with additional flags. The input must be a valid representation of a point's x-coordinate in the bn254 curve.
- **Output**: Returns the output buffer on success, or NULL on failure. On success, the output buffer contains the decompressed (x, y) coordinates.
- **See also**: [`fd_bn254_g1_decompress`](fd_bn254.c.driver.md#fd_bn254_g1_decompress)  (Implementation)


---
### fd\_bn254\_g2\_compress<!-- {{#callable_declaration:fd_bn254_g2_compress}} -->
Compresses a point in G2 on the bn254 curve.
- **Description**: This function compresses a point in the G2 group of the bn254 elliptic curve. It takes a 128-byte input buffer representing the point (x, y) in big-endian format, with additional flags, and outputs a 64-byte buffer containing the x-coordinate with appropriate flags set. The function does not verify if the input point is valid within G2, and it returns the output buffer on success or NULL if the input cannot be processed. This function is useful for reducing the size of point representations when the full y-coordinate is not needed.
- **Inputs**:
    - `out`: A 64-byte buffer where the compressed x-coordinate and flags will be stored. The caller must ensure this buffer is allocated and has sufficient space.
    - `in`: A 128-byte buffer containing the big-endian representation of the point (x, y) with additional flags. The input must be properly formatted, but the function does not check if the point is valid in G2.
- **Output**: Returns the pointer to the output buffer on success, or NULL if the input cannot be processed.
- **See also**: [`fd_bn254_g2_compress`](fd_bn254.c.driver.md#fd_bn254_g2_compress)  (Implementation)


---
### fd\_bn254\_g2\_decompress<!-- {{#callable_declaration:fd_bn254_g2_decompress}} -->
Decompresses a point in G2 from its x-coordinate representation.
- **Description**: This function is used to decompress a point in the G2 group of the bn254 curve from a 64-byte big-endian buffer representing the x-coordinate, with additional flags, into a 128-byte buffer containing the full (x, y) coordinates. It should be used when you have a compressed representation of a point in G2 and need the full coordinates for further operations. The function does not verify if the resulting (x, y) point is actually in G2, so additional checks may be necessary depending on the use case. It handles the special case where the input is all zeros by outputting all zeros, indicating the point at infinity. The function returns NULL on failure, such as when the input does not represent a valid point.
- **Inputs**:
    - `out`: A 128-byte buffer where the decompressed (x, y) coordinates will be stored. The caller must ensure this buffer is properly allocated and has sufficient space.
    - `in`: A 64-byte big-endian buffer representing the x-coordinate of a point in G2, with additional flags. The input must be a valid representation of a point's x-coordinate in G2.
- **Output**: Returns a pointer to the output buffer on success, or NULL on failure. The output buffer will contain the decompressed (x, y) coordinates with no flags set.
- **See also**: [`fd_bn254_g2_decompress`](fd_bn254.c.driver.md#fd_bn254_g2_decompress)  (Implementation)


