# Purpose
This C source code file is designed to handle operations related to elliptic curve cryptography, specifically for the BN254 curve, which is a pairing-friendly elliptic curve. The file includes several components that provide functionality for compressing and decompressing elliptic curve points in both G1 and G2 groups, performing arithmetic operations such as point addition and scalar multiplication, and verifying pairings. The code is structured to import several internal modules, each handling specific aspects of the BN254 curve operations, such as field arithmetic and group operations, indicating a modular design aimed at maintaining clarity and separation of concerns.

The primary functions in this file include [`fd_bn254_g1_compress`](#fd_bn254_g1_compress) and [`fd_bn254_g1_decompress`](#fd_bn254_g1_decompress) for handling G1 group points, and [`fd_bn254_g2_compress`](#fd_bn254_g2_compress) and [`fd_bn254_g2_decompress`](#fd_bn254_g2_decompress) for G2 group points. These functions manage the serialization and deserialization of elliptic curve points, ensuring that points are correctly represented in a compressed format. Additionally, the file provides system call functions like [`fd_bn254_g1_add_syscall`](#fd_bn254_g1_add_syscall) and [`fd_bn254_g1_scalar_mul_syscall`](#fd_bn254_g1_scalar_mul_syscall) for performing point addition and scalar multiplication, respectively. The [`fd_bn254_pairing_is_one_syscall`](#fd_bn254_pairing_is_one_syscall) function checks if a pairing operation results in the identity element, which is crucial for cryptographic protocols that rely on pairing-based operations. Overall, this file serves as a specialized library for BN254 elliptic curve operations, providing essential cryptographic primitives for applications that require secure and efficient elliptic curve computations.
# Imports and Dependencies

---
- `./fd_bn254_internal.h`
- `./fd_bn254_field.c`
- `./fd_bn254_field_ext.c`
- `./fd_bn254_g1.c`
- `./fd_bn254_g2.c`
- `./fd_bn254_pairing.c`


# Functions

---
### fd\_bn254\_g1\_compress<!-- {{#callable:fd_bn254_g1_compress}} -->
The `fd_bn254_g1_compress` function compresses a 64-byte representation of a point on the BN254 G1 curve into a 32-byte format, handling special cases for points at infinity and negative y-coordinates.
- **Inputs**:
    - `out`: A 32-byte array where the compressed point will be stored.
    - `in`: A 64-byte array representing the point on the BN254 G1 curve to be compressed.
- **Control Flow**:
    - Initialize a point `p` and attempt to convert the input bytes to a point on the curve using `fd_bn254_g1_frombytes_internal`; return NULL if conversion fails.
    - Check if the point is at infinity using `fd_bn254_g1_is_zero`; store the infinity flag from the input.
    - If the point is at infinity, set the output to zero and set the infinity flag in the output if it was set in the input, then return the output.
    - Determine if the y-coordinate is negative using `fd_bn254_fp_is_neg_nm`.
    - Copy the first 32 bytes of the input to the output.
    - If the y-coordinate is negative, set the negative flag in the output.
    - Return the output.
- **Output**: A pointer to the 32-byte compressed point, or NULL if the input is invalid.


---
### fd\_bn254\_g1\_decompress<!-- {{#callable:fd_bn254_g1_decompress}} -->
The `fd_bn254_g1_decompress` function decompresses a compressed elliptic curve point from 32 bytes to 64 bytes, handling special cases like the point at infinity and ensuring the correct y-coordinate sign.
- **Inputs**:
    - `out`: A 64-byte array where the decompressed elliptic curve point will be stored.
    - `in`: A 32-byte array containing the compressed elliptic curve point.
- **Control Flow**:
    - Check if the input is all zeros; if so, set the output to all zeros and return it.
    - Convert the input bytes to a field element `x`, checking for special flags indicating infinity or negative y-coordinate.
    - If the point is at infinity, set the output to all zeros and return it.
    - Convert `x` to its Montgomery representation, square it, and compute `x^3 + b` in the field.
    - Attempt to compute the square root of `x^3 + b` to find the y-coordinate; return NULL if this fails.
    - Convert the y-coordinate back from Montgomery representation and adjust its sign if necessary.
    - Copy the input to the first 32 bytes of the output, masking out any flags, and store the y-coordinate in the remaining 32 bytes.
    - Return the output array.
- **Output**: A pointer to the 64-byte output array containing the decompressed elliptic curve point, or NULL if decompression fails.


---
### fd\_bn254\_g2\_compress<!-- {{#callable:fd_bn254_g2_compress}} -->
The `fd_bn254_g2_compress` function compresses a point on the BN254 G2 curve from 128 bytes to 64 bytes, handling special cases for points at infinity and negative Y coordinates.
- **Inputs**:
    - `out`: A 64-byte array where the compressed point will be stored.
    - `in`: A 128-byte array representing the point on the BN254 G2 curve to be compressed.
- **Control Flow**:
    - Initialize a BN254 G2 point `p` to zero.
    - Convert the input bytes to a BN254 G2 point using `fd_bn254_g2_frombytes_internal`; return NULL if conversion fails.
    - Check if the point is at infinity using `fd_bn254_g2_is_zero`.
    - If the point is at infinity, set the output to zero and set the infinity flag if it is set in the input, then return the output.
    - Otherwise, copy the first 64 bytes of the input to the output.
    - Check if the Y coordinate is negative using `fd_bn254_fp2_is_neg_nm`; if so, set the negative flag in the output.
    - Return the compressed output.
- **Output**: A pointer to the 64-byte compressed point, or NULL if the input point could not be converted.


---
### fd\_bn254\_g2\_decompress<!-- {{#callable:fd_bn254_g2_decompress}} -->
The `fd_bn254_g2_decompress` function decompresses a compressed point on the BN254 G2 curve from a 64-byte input to a 128-byte output.
- **Inputs**:
    - `out`: A 128-byte array where the decompressed point will be stored.
    - `in`: A 64-byte array containing the compressed point data to be decompressed.
- **Control Flow**:
    - Check if the input is all zeros; if so, set the output to all zeros and return it.
    - Convert the input bytes to a field element `x` and check for special flags indicating infinity or negativity.
    - If the point is at infinity, set the output to represent the point at infinity and return it.
    - Convert `x` to its Montgomery representation, square it, and compute `x^3 + b` where `b` is a constant specific to the curve.
    - Attempt to compute the square root of `x^3 + b` to find the y-coordinate; if this fails, return NULL.
    - Convert the y-coordinate back from its Montgomery representation.
    - If the negativity flag does not match the computed y-coordinate, negate the y-coordinate.
    - Copy the input to the output, clear any flags, and append the y-coordinate to the output.
- **Output**: A pointer to the 128-byte output array containing the decompressed point, or NULL if decompression fails.


---
### fd\_bn254\_g1\_add\_syscall<!-- {{#callable:fd_bn254_g1_add_syscall}} -->
The `fd_bn254_g1_add_syscall` function adds two elliptic curve points from the BN254 curve and outputs the result.
- **Inputs**:
    - `out`: A 64-byte array where the result of the point addition will be stored.
    - `in`: A byte array containing the serialized representation of two elliptic curve points, each 64 bytes long.
    - `in_sz`: The size of the input byte array, expected to be 128 bytes.
- **Control Flow**:
    - Check if the input size exceeds 128 bytes; if so, return -1 indicating an error.
    - Initialize a 128-byte buffer with zeros and copy the input data into this buffer.
    - Deserialize the first 64 bytes of the buffer into an elliptic curve point `a` and check its subgroup membership; return -1 if invalid.
    - Deserialize the next 64 bytes of the buffer into an elliptic curve point `b` and check its subgroup membership; return -1 if invalid.
    - Perform the elliptic curve point addition of `a` and `b`, storing the result in `r`.
    - Serialize the resulting point `r` into the output array `out`.
    - Return 0 to indicate successful completion.
- **Output**: Returns 0 on success, or -1 if the input size is invalid or if the input points are not valid subgroup members.


---
### fd\_bn254\_g1\_scalar\_mul\_syscall<!-- {{#callable:fd_bn254_g1_scalar_mul_syscall}} -->
The `fd_bn254_g1_scalar_mul_syscall` function performs a scalar multiplication on a point in the BN254 G1 group and outputs the result.
- **Inputs**:
    - `out`: A 64-byte array where the result of the scalar multiplication will be stored.
    - `in`: A constant input array containing the point and scalar for the multiplication.
    - `in_sz`: The size of the input array, expected to be either 96 or 128 bytes depending on the `check_correct_sz` flag.
    - `check_correct_sz`: A flag indicating whether to check for a 96-byte input size (if true) or a 128-byte input size (if false).
- **Control Flow**:
    - Determine the expected input size based on the `check_correct_sz` flag, setting it to 96 or 128 bytes.
    - Check if the actual input size exceeds the expected size; if so, return -1 indicating an error.
    - Initialize a 96-byte buffer and copy the input data into it, padding with zeros if necessary.
    - Validate the point in the input by checking its subgroup membership; return -1 if validation fails.
    - Convert the scalar from big-endian format without validating it.
    - Perform the scalar multiplication of the point by the scalar.
    - Serialize the result of the multiplication into the output array.
    - Return 0 to indicate successful completion.
- **Output**: Returns 0 on success, or -1 if there is an error in input size or point validation.


---
### fd\_bn254\_pairing\_is\_one\_syscall<!-- {{#callable:fd_bn254_pairing_is_one_syscall}} -->
The `fd_bn254_pairing_is_one_syscall` function checks if the result of a series of pairings on elliptic curve points is equal to one, and outputs the result as a serialized big-endian uint256.
- **Inputs**:
    - `out`: A 32-byte array where the result (0 or 1) will be stored as a big-endian uint256.
    - `in`: A byte array containing serialized elliptic curve points for pairing checks.
    - `in_sz`: The size of the input byte array, which should be a multiple of 192.
- **Control Flow**:
    - Calculate the number of elements by dividing `in_sz` by 192.
    - Initialize arrays `p` and `q` to store G1 and G2 points respectively, and set `r` to one.
    - Iterate over each element, deserializing and checking subgroup membership for G1 and G2 points.
    - Skip pairs where either point is at infinity, otherwise increment the size counter `sz`.
    - Perform the Miller loop and aggregate results into `r` when `sz` reaches the batch max or at the last element.
    - If any elements remain, perform another Miller loop and aggregate.
    - Compute the final exponentiation on `r`.
    - Set the output to 0, and if `r` is one, set the last byte of `out` to 1.
- **Output**: Returns 0 on success, with `out` containing 0 or 1 indicating if the pairing result is one.


