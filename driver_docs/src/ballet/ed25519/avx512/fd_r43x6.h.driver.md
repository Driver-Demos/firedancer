# Purpose
The provided C header file defines a set of operations for handling elements in the finite field GF(p), where p = 2^255 - 19, using a specific representation optimized for AVX-512 vector instructions. This representation, referred to as `fd_r43x6_t`, encodes field elements in a little-endian 6-limb radix 2^43 format, utilizing the first six lanes of an AVX-512 vector. The file includes a comprehensive suite of functions and macros for constructing, manipulating, and performing arithmetic operations on these field elements, such as addition, subtraction, multiplication, squaring, and inversion. It also provides utilities for converting between different representations and ensuring that results are reduced modulo p.

The header is designed to be used in high-performance computing (HPC) environments, particularly those involving cryptographic protocols that require efficient finite field arithmetic, such as the Ed25519 digital signature algorithm. The file includes detailed comments explaining the mathematical foundations and implementation strategies, such as the use of AVX-512 instructions like `madd52lo` and `madd52hi` for efficient multiplication. The code is structured to ensure deterministic timing, which is crucial for cryptographic applications to prevent timing attacks. Additionally, the file defines macros for conditional operations and swapping, ensuring that operations can be performed without branching, further enhancing performance and security.
# Imports and Dependencies

---
- `../../../util/simd/fd_avx.h`
- `../../../util/simd/fd_avx512.h`
- `fd_r43x6_inl.h`


# Functions

---
### fd\_r43x6\_unpack<!-- {{#callable:fd_r43x6_unpack}} -->
The `fd_r43x6_unpack` function converts a 256-bit integer stored in an AVX-2 vector into a 6-limb representation suitable for arithmetic in the finite field GF(p) where p = 2^255-19.
- **Inputs**:
    - `u`: An AVX-2 vector representing a 256-bit integer in a little-endian 4 ulong radix 2^64 limb format.
- **Control Flow**:
    - Initialize a zero vector `zero` and a permutation vector `perm` to rearrange bits for unpacking.
    - Define a right shift vector `rshift` to align bits correctly after permutation.
    - Define a mask `mask` to retain only the 43 least significant bits of each limb.
    - Insert the input vector `u` into the lower half of a zero-initialized 512-bit vector.
    - Permute the bits of the inserted vector using `perm` to align them for unpacking.
    - Right shift the permuted vector using `rshift` to position the bits correctly for each limb.
    - Apply the mask to zero out bits beyond the 43 least significant bits in each limb.
    - Return the result as a `fd_r43x6_t` type, representing the unpacked field element.
- **Output**: An `fd_r43x6_t` type representing the unpacked field element with limbs 0-4 in [0,2^43) and limb 5 in [0,2^41), with lanes 6 and 7 set to zero.


---
### fd\_r43x6\_pack<!-- {{#callable:fd_r43x6_pack}} -->
The `fd_r43x6_pack` function converts an unpacked `fd_r43x6_t` representation of a field element into a packed `wv_t` format.
- **Inputs**:
    - `r`: An `fd_r43x6_t` type representing a field element in a 6-limb radix 2^43 format, where each limb is a 64-bit integer.
- **Control Flow**:
    - The function begins by defining three temporary variables `t0`, `t1`, and `t2` using vector operations.
    - `t0` is calculated by right-shifting and permuting the input vector `r` to align the bits for the first packed output segment.
    - `t1` and `t2` are calculated by left-shifting and permuting the input vector `r` to align the bits for the subsequent packed output segments.
    - The function combines `t0`, `t1`, and `t2` using bitwise OR operations to form the final packed vector.
    - The packed vector is extracted and returned as a `wv_t` type, containing the packed representation of the field element.
- **Output**: The function returns a `wv_t` type, which is a packed representation of the input field element, suitable for use in cryptographic protocols.


---
### fd\_r43x6\_approx\_mod<!-- {{#callable:fd_r43x6_approx_mod}} -->
The `fd_r43x6_approx_mod` function reduces an arbitrary `fd_r43x6_t` element to a nearly reduced form using approximate and biased carry propagation techniques.
- **Inputs**:
    - `x`: An `fd_r43x6_t` type representing a GF(p) element in a 6-limb radix 2^43 representation, where each limb is a 64-bit integer.
- **Control Flow**:
    - Extracts the limbs of the input `fd_r43x6_t` element `x` into six long integers `y0` to `y5`.
    - Performs an approximate carry propagation on the extracted limbs to reduce their range, making them suitable for further processing.
    - Applies a biased carry propagation with a bias of 1 to ensure the limbs are in a nearly reduced form.
    - Reconstructs and returns a new `fd_r43x6_t` element from the processed limbs `y0` to `y5`.
- **Output**: Returns a nearly reduced `fd_r43x6_t` element with the limbs adjusted to fit within specified ranges, suitable for further arithmetic operations.


---
### fd\_r43x6\_approx\_mod\_signed<!-- {{#callable:fd_r43x6_approx_mod_signed}} -->
The `fd_r43x6_approx_mod_signed` function performs a biased carry propagation on a signed `fd_r43x6_t` input to produce a nearly reduced representation.
- **Inputs**:
    - `x`: A signed `fd_r43x6_t` element, where each limb is within specific signed ranges, representing a field element in GF(p) with p = 2^255-19.
- **Control Flow**:
    - Extracts the limbs of the input `fd_r43x6_t` x into six long integers y0 to y5 using `fd_r43x6_extract_limbs` macro.
    - Performs a biased carry propagation on the extracted limbs using `fd_r43x6_biased_carry_propagate_limbs` with a bias of 2^20.
    - Reconstructs and returns a new `fd_r43x6_t` from the modified limbs y0 to y5 using the `fd_r43x6` macro.
- **Output**: A nearly reduced `fd_r43x6_t` element, where the limbs are adjusted to fit within specified ranges suitable for further arithmetic operations.


---
### fd\_r43x6\_approx\_mod\_unsigned<!-- {{#callable:fd_r43x6_approx_mod_unsigned}} -->
The function `fd_r43x6_approx_mod_unsigned` performs an unbiased carry propagation on an unsigned `fd_r43x6_t` type to approximate its modular reduction.
- **Inputs**:
    - `x`: An `fd_r43x6_t` type representing a GF(p) element in a little-endian 6 long radix 2^43 limb representation, where each limb is a 64-bit integer.
- **Control Flow**:
    - Extracts the limbs of the input `fd_r43x6_t` type `x` into six long integers `y0` to `y5`.
    - Performs an unbiased carry propagation on the extracted limbs using `fd_r43x6_biased_carry_propagate_limbs` with a bias of 0.
    - Reconstructs and returns a new `fd_r43x6_t` type from the modified limbs `y0` to `y5`.
- **Output**: Returns a nearly reduced `fd_r43x6_t` type with the limbs adjusted to fit within specified ranges, suitable for further arithmetic operations.


---
### fd\_r43x6\_mod<!-- {{#callable:fd_r43x6_mod}} -->
The `fd_r43x6_mod` function reduces an arbitrary `fd_r43x6_t` element to its unique reduced form in the finite field GF(p) where p = 2^255-19.
- **Inputs**:
    - `x`: An `fd_r43x6_t` element representing a GF(p) element in a 6-limb radix 2^43 representation, which may not be reduced.
- **Control Flow**:
    - Extracts the limbs of the input `x` into six long integers `y0` to `y5`.
    - Performs an approximate carry propagation on the extracted limbs to reduce their range.
    - Applies a biased carry propagation with a bias of 1 to further adjust the limb values.
    - Calls `fd_r43x6_mod_nearly_reduced_limbs` to ensure the limbs are in their final reduced form.
    - Reconstructs and returns the reduced `fd_r43x6_t` element from the modified limbs.
- **Output**: A reduced `fd_r43x6_t` element representing the same GF(p) element as the input, but in its unique reduced form.


---
### fd\_r43x6\_mod\_signed<!-- {{#callable:fd_r43x6_mod_signed}} -->
The `fd_r43x6_mod_signed` function reduces a signed `fd_r43x6_t` element to its canonical form in the field GF(p) where p = 2^255-19.
- **Inputs**:
    - `x`: A signed `fd_r43x6_t` element representing a field element in GF(p) using a 6-limb radix 2^43 representation.
- **Control Flow**:
    - Extracts the limbs of the input `fd_r43x6_t` element `x` into six long variables `y0` to `y5`.
    - Applies a biased carry propagation on the extracted limbs with a bias of `1L<<20` to ensure the limbs are nearly reduced.
    - Further reduces the nearly reduced limbs to their canonical form using the `fd_r43x6_mod_nearly_reduced_limbs` function.
    - Reconstructs and returns the reduced `fd_r43x6_t` element from the modified limbs `y0` to `y5`.
- **Output**: A reduced `fd_r43x6_t` element in its canonical form in the field GF(p).


---
### fd\_r43x6\_mod\_unsigned<!-- {{#callable:fd_r43x6_mod_unsigned}} -->
The `fd_r43x6_mod_unsigned` function reduces an unsigned `fd_r43x6_t` element to its canonical form in the finite field GF(p) where p = 2^255-19.
- **Inputs**:
    - `x`: An `fd_r43x6_t` element representing a GF(p) element in a 6-long radix 2^43 limb representation, assumed to be unsigned.
- **Control Flow**:
    - Extracts the limbs of the input `x` into six long variables `y0` to `y5`.
    - Applies a biased carry propagation on the extracted limbs with a bias of 0 to ensure the limbs are nearly reduced.
    - Further reduces the nearly reduced limbs to their canonical form using the `fd_r43x6_mod_nearly_reduced_limbs` function.
    - Reconstructs and returns the reduced `fd_r43x6_t` element from the modified limbs `y0` to `y5`.
- **Output**: A reduced `fd_r43x6_t` element in GF(p) with limbs in the canonical range, suitable for further arithmetic operations.


---
### fd\_r43x6\_mod\_nearly\_reduced<!-- {{#callable:fd_r43x6_mod_nearly_reduced}} -->
The function `fd_r43x6_mod_nearly_reduced` reduces a nearly reduced `fd_r43x6_t` element to a fully reduced form in the finite field GF(p) where p = 2^255-19.
- **Inputs**:
    - `x`: A nearly reduced `fd_r43x6_t` element represented in a 6-limb radix 2^43 format.
- **Control Flow**:
    - Declare long variables y0 to y5 to hold the extracted limbs of x.
    - Use `fd_r43x6_extract_limbs` to extract the limbs of x into y0 to y5.
    - Call `fd_r43x6_mod_nearly_reduced_limbs` to reduce the nearly reduced limbs y0 to y5 to a fully reduced form.
    - Return a new `fd_r43x6_t` constructed from the reduced limbs y0 to y5.
- **Output**: A fully reduced `fd_r43x6_t` element in the finite field GF(p).


---
### fd\_r43x6\_mul\_fast<!-- {{#callable:fd_r43x6_mul_fast}} -->
The `fd_r43x6_mul_fast` function performs a fast multiplication of two unreduced `fd_r43x6_t` elements using AVX512 instructions, specifically optimized for the 43x6 limb representation.
- **Inputs**:
    - `x`: An unreduced `fd_r43x6_t` element, representing a field element in a 6-limb radix 2^43 format, with lanes 6 and 7 ignored.
    - `y`: Another unreduced `fd_r43x6_t` element, also in a 6-limb radix 2^43 format, with lanes 6 and 7 assumed to be zero.
- **Control Flow**:
    - Initialize a zero vector `wwl_t const zero` for use in operations.
    - Permute the input `x` to create six vectors `x0` to `x5`, each representing a shifted version of `x` for multiplication.
    - Compute intermediate products `t0` to `t6` using `wwl_madd52lo` and `wwl_madd52hi` instructions, which perform multiplication and addition with carry handling, followed by a shift operation.
    - Slide and combine these intermediate products into vectors `p0j` to `p6j` and `q3j` to `q6j`, aligning them for addition.
    - Sum the vectors to form `zl` and `zh`, representing the lower and higher parts of the result, respectively.
    - Perform a final reduction step by combining `zl` and `zh` into `za` and `zb`, and compute the final result using shift and add techniques to avoid slow multiplication.
- **Output**: The function returns an unsigned `fd_r43x6_t` element representing the product of `x` and `y`, with lanes 6 and 7 set to zero.


---
### fd\_r43x6\_sqr\_fast<!-- {{#callable:fd_r43x6_sqr_fast}} -->
The `fd_r43x6_sqr_fast` function computes the square of an unreduced fd_r43x6_t element using AVX-512 vector operations, optimizing for minimal shuffling and efficient lane usage.
- **Inputs**:
    - `x`: An fd_r43x6_t element representing a GF(p) element in a little-endian 6 long radix 2^43 limb representation, with lanes 6 and 7 ignored.
- **Control Flow**:
    - Initialize a zero vector `wwl_t const zero` for use in calculations.
    - Permute the input `x` into six different vectors (`x0` to `x5`) to align elements for multiplication in AVX lanes.
    - Double the non-square terms in `x0`, `x2`, and `x4` using bitwise shifts.
    - Compute the low parts of the products `p0l`, `p1l`, and `p2l` using `wwl_madd52lo` with the permuted vectors.
    - Compute the high parts of the products `p0h`, `p1h`, and `p2h` using `wwl_madd52hi` and shift them left by 9 bits.
    - Use masks to separate terms that belong in the high and low words, and compute `zll`, `zlh`, `zhl`, and `zhh` accordingly.
    - Combine the results into `zl` and `zh` using `wwl_add` and `wwl_slide` to align the results correctly.
    - Mask and slide the results to compute `za` and `zb`, which are then combined to form the final result.
- **Output**: The function returns an fd_r43x6_t element representing the square of the input, with lanes 6 and 7 set to zero, and the result fitting into a u62 range.


---
### fd\_r43x6\_scale\_fast<!-- {{#callable:fd_r43x6_scale_fast}} -->
The `fd_r43x6_scale_fast` function scales a given `fd_r43x6_t` element by a scalar `_x0` and returns the result as an unsigned `fd_r43x6_t`.
- **Inputs**:
    - `_x0`: A long integer representing the scalar value to scale the `fd_r43x6_t` element by, expected to be in the range [0, 2^47).
    - `y`: An `fd_r43x6_t` element representing a field element in a 6-limb radix 2^43 representation, with lanes 6 and 7 assumed to be zero.
- **Control Flow**:
    - Initialize a zero vector `wwl_t` for use in operations.
    - Broadcast the scalar `_x0` into a vector `x0`.
    - Compute the low part of the product using `wwl_madd52lo` with zero and `x0` multiplied by `y`, storing the result in `t0`.
    - Compute the high part of the product using `wwl_madd52hi` with zero and `x0` multiplied by `y`, shift it left by 9 bits, and store the result in `t1`.
    - Slide `t1` by 7 positions to align it with `t0`, storing the result in `p1j`.
    - Add `p0j` and `p1j` to get `zl`, the combined result of the low and high parts.
    - Mask `zl` to isolate the lower 6 limbs, storing the result in `za`.
    - Slide `zl` by 6 positions to prepare for reduction, storing the result in `zb`.
    - Combine `za` and `zb` using shifts and additions to form the final result, ensuring it fits within the expected range.
- **Output**: The function returns an `fd_r43x6_t` element representing the scaled result, with lanes 6 and 7 set to zero, and the result fitting within the range suitable for further operations.


---
### fd\_r43x6\_is\_nonzero<!-- {{#callable:fd_r43x6_is_nonzero}} -->
The `fd_r43x6_is_nonzero` function checks if a given signed `fd_r43x6_t` element is non-zero after reducing it.
- **Inputs**:
    - `x`: A signed `fd_r43x6_t` element, represented in a 6-limb radix 2^43 format, which needs to be checked for being non-zero.
- **Control Flow**:
    - Extracts the limbs of the input `fd_r43x6_t` element `x` into six long integers `l0` to `l5`.
    - Applies a biased carry propagation to the extracted limbs to make them nearly reduced.
    - Reduces the nearly reduced limbs to ensure they are in a canonical form.
    - Checks if any of the reduced limbs `l0` to `l5` are non-zero and returns the result.
- **Output**: Returns 1 if the reduced `fd_r43x6_t` element is non-zero, otherwise returns 0.


---
### fd\_r43x6\_diagnose<!-- {{#callable:fd_r43x6_diagnose}} -->
The `fd_r43x6_diagnose` function reduces a signed `fd_r43x6_t` element and returns -1 if the result is zero, otherwise it returns the least significant bit of the reduced result.
- **Inputs**:
    - `x`: A signed `fd_r43x6_t` element, which is a representation of a GF(p) element in a little-endian 6 long radix 2^43 limb format.
- **Control Flow**:
    - Extracts the limbs of the input `fd_r43x6_t` element `x` into six long variables `l0` to `l5`.
    - Applies a biased carry propagation to the extracted limbs to make them nearly reduced.
    - Reduces the nearly reduced limbs to ensure they are fully reduced.
    - Checks if all limbs are zero; if so, returns -1.
    - If not all limbs are zero, returns the least significant bit of the first limb `l0`.
- **Output**: An integer value, -1 if the reduced result is zero, otherwise the least significant bit of the reduced result.


# Function Declarations (Public API)

---
### fd\_r43x6\_invert<!-- {{#callable_declaration:fd_r43x6_invert}} -->
Returns the multiplicative inverse of a GF(p) element.
- **Description**: Use this function to compute the multiplicative inverse of an element in the finite field GF(p), where p = 2^255-19. This function is applicable when you have an unreduced fd_r43x6_t element and need its inverse for further calculations. The input must be an unreduced fd_r43x6_t, and the function will return an unreduced fd_r43x6_t as well. Ensure that the input is valid and non-zero to avoid undefined behavior.
- **Inputs**:
    - `z`: An unreduced fd_r43x6_t element representing a GF(p) element. It must be in the unreduced form, and lanes 6 and 7 should be zero. The input should not be zero to ensure a valid inverse exists.
- **Output**: Returns an unreduced fd_r43x6_t representing the multiplicative inverse of the input element in GF(p).
- **See also**: [`fd_r43x6_invert`](fd_r43x6.c.driver.md#fd_r43x6_invert)  (Implementation)


---
### fd\_r43x6\_pow22523<!-- {{#callable_declaration:fd_r43x6_pow22523}} -->
Computes z raised to the power of (2^252 - 3) in GF(p).
- **Description**: Use this function to compute the power of an element in the finite field GF(p) where p = 2^255 - 19, specifically raising the element to the power of (2^252 - 3). This operation is useful in cryptographic algorithms that require exponentiation in this field. The input must be an unreduced fd_r43x6_t, meaning its limbs are in the range [0, 2^47), and lanes 6 and 7 of the input vector must be zero. The function returns an unreduced fd_r43x6_t with lanes 6 and 7 zero, suitable for further operations in the same field.
- **Inputs**:
    - `z`: An unreduced fd_r43x6_t representing a GF(p) element with limbs in the range [0, 2^47). Lanes 6 and 7 must be zero. The function assumes valid input and does not handle invalid values.
- **Output**: Returns an unreduced fd_r43x6_t representing the result of the exponentiation, with lanes 6 and 7 zero.
- **See also**: [`fd_r43x6_pow22523`](fd_r43x6.c.driver.md#fd_r43x6_pow22523)  (Implementation)


