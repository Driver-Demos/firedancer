# Purpose
The provided C source code file is an implementation of arithmetic operations in the Montgomery domain for the BN254 scalar field, which is a specific prime field used in cryptographic applications, particularly in elliptic curve cryptography. The code is auto-generated and provides a comprehensive set of functions to perform arithmetic operations such as addition, subtraction, multiplication, and squaring of field elements, both in and out of the Montgomery domain. It also includes functions for converting between Montgomery and non-Montgomery representations, serialization and deserialization of field elements, and utility functions like conditional moves and checking for non-zero values.

The file defines several key types and functions that facilitate these operations. It uses 64-bit machine words to represent field elements and employs techniques like carry propagation and conditional selection to ensure efficient computation. The code is structured to handle the specific modulus of the BN254 scalar field, ensuring that all operations respect the field's properties. Additionally, the file includes functions for advanced operations such as computing the modular inverse using the Bernstein-Yang inversion method, which is crucial for cryptographic protocols. Overall, this file is a specialized library intended for use in cryptographic systems that require efficient and secure arithmetic in the BN254 scalar field.
# Imports and Dependencies

---
- `stdint.h`


# Global Variables

---
### fiat\_bn254\_scalar\_int128
- **Type**: ``typedef signed __int128``
- **Description**: The `fiat_bn254_scalar_int128` is a type definition for a signed 128-bit integer using the `__int128` type, which is an extension provided by GCC and Clang compilers. This type allows for operations on 128-bit signed integers, which are larger than the standard 64-bit integers.
- **Use**: This variable is used to perform arithmetic operations that require 128-bit signed integer precision, such as in cryptographic computations.


---
### fiat\_bn254\_scalar\_uint128
- **Type**: `unsigned __int128`
- **Description**: The `fiat_bn254_scalar_uint128` is a typedef for an unsigned 128-bit integer type, which is used to represent large integers that require more than the standard 64-bit integer size. This type is particularly useful in cryptographic computations where large numbers are common.
- **Use**: This variable is used in arithmetic operations that require handling of large integers, such as multiplication and addition with carry, within the context of the bn254 scalar field arithmetic.


# Functions

---
### fiat\_bn254\_scalar\_addcarryx\_u64<!-- {{#callable:fiat_bn254_scalar_addcarryx_u64}} -->
The function `fiat_bn254_scalar_addcarryx_u64` performs a 64-bit addition with carry, returning the sum modulo 2^64 and the carry-out.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result of the addition modulo 2^64 will be stored.
    - `out2`: A pointer to a fiat_bn254_scalar_uint1 where the carry-out of the addition will be stored.
    - `arg1`: A fiat_bn254_scalar_uint1 representing the initial carry-in for the addition.
    - `arg2`: A uint64_t representing the first operand of the addition.
    - `arg3`: A uint64_t representing the second operand of the addition.
- **Control Flow**:
    - Declare a 128-bit unsigned integer `x1` to hold the intermediate sum of `arg1`, `arg2`, and `arg3`.
    - Calculate `x1` as the sum of `arg1`, `arg2`, and `arg3`.
    - Extract the lower 64 bits of `x1` and store it in `x2`.
    - Extract the upper bits of `x1` (carry-out) and store it in `x3`.
    - Store `x2` in the location pointed to by `out1`.
    - Store `x3` in the location pointed to by `out2`.
- **Output**: The function outputs the sum of `arg1`, `arg2`, and `arg3` modulo 2^64 in `out1`, and the carry-out in `out2`.


---
### fiat\_bn254\_scalar\_subborrowx\_u64<!-- {{#callable:fiat_bn254_scalar_subborrowx_u64}} -->
The function `fiat_bn254_scalar_subborrowx_u64` performs a subtraction of two 64-bit unsigned integers with an additional borrow input, and outputs the result along with a borrow flag.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result of the subtraction will be stored.
    - `out2`: A pointer to a fiat_bn254_scalar_uint1 where the borrow flag will be stored.
    - `arg1`: A fiat_bn254_scalar_uint1 representing the initial borrow input.
    - `arg2`: A 64-bit unsigned integer representing the minuend.
    - `arg3`: A 64-bit unsigned integer representing the subtrahend.
- **Control Flow**:
    - Calculate the intermediate result `x1` as the difference of `arg2`, `arg1`, and `arg3` cast to a 128-bit integer.
    - Extract the borrow flag `x2` by right-shifting `x1` by 64 bits and casting to a fiat_bn254_scalar_int1.
    - Extract the lower 64 bits of `x1` as `x3` by applying a bitwise AND with `UINT64_C(0xffffffffffffffff)`.
    - Store `x3` in the location pointed to by `out1`.
    - Calculate the final borrow flag by subtracting `x2` from 0 and store it in the location pointed to by `out2`.
- **Output**: The function outputs the result of the subtraction in `out1` and the borrow flag in `out2`.


---
### fiat\_bn254\_scalar\_mulx\_u64<!-- {{#callable:fiat_bn254_scalar_mulx_u64}} -->
The function `fiat_bn254_scalar_mulx_u64` performs a 64-bit multiplication of two unsigned integers and returns the result as a 128-bit value split into two 64-bit parts.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the lower 64 bits of the result will be stored.
    - `out2`: A pointer to a uint64_t where the upper 64 bits of the result will be stored.
    - `arg1`: A uint64_t representing the first operand of the multiplication.
    - `arg2`: A uint64_t representing the second operand of the multiplication.
- **Control Flow**:
    - Declare a 128-bit unsigned integer `x1` to store the full result of the multiplication of `arg1` and `arg2`.
    - Perform the multiplication of `arg1` and `arg2`, storing the result in `x1`.
    - Extract the lower 64 bits of `x1` and store them in `x2`.
    - Extract the upper 64 bits of `x1` by right-shifting `x1` by 64 bits and store them in `x3`.
    - Assign the value of `x2` to the location pointed to by `out1`.
    - Assign the value of `x3` to the location pointed to by `out2`.
- **Output**: The function outputs two 64-bit unsigned integers through the pointers `out1` and `out2`, representing the lower and upper halves of the 128-bit multiplication result, respectively.


---
### fiat\_bn254\_scalar\_cmovznz\_u64<!-- {{#callable:fiat_bn254_scalar_cmovznz_u64}} -->
The function `fiat_bn254_scalar_cmovznz_u64` performs a conditional move operation on two 64-bit unsigned integers based on a single-bit condition.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: A single-bit unsigned integer (0 or 1) that acts as the condition for the move operation.
    - `arg2`: A 64-bit unsigned integer that will be selected if `arg1` is 0.
    - `arg3`: A 64-bit unsigned integer that will be selected if `arg1` is 1.
- **Control Flow**:
    - The function first negates `arg1` twice to ensure it is either 0 or 1, storing the result in `x1`.
    - It calculates `x2` as the bitwise AND of the negated `x1` and the maximum 64-bit unsigned integer, effectively creating a mask of all 1s if `arg1` is 1, or all 0s if `arg1` is 0.
    - The function then computes `x3` as the bitwise OR of `x2` AND `arg3` and the bitwise NOT of `x2` AND `arg2`, effectively selecting `arg3` if `arg1` is 1, or `arg2` if `arg1` is 0.
    - Finally, the result `x3` is stored in the location pointed to by `out1`.
- **Output**: The function outputs the selected 64-bit unsigned integer, either `arg2` or `arg3`, based on the value of `arg1`, and stores it in the location pointed to by `out1`.


---
### fiat\_bn254\_scalar\_mul<!-- {{#callable:fiat_bn254_scalar_mul}} -->
The function `fiat_bn254_scalar_mul` performs multiplication of two field elements in the Montgomery domain for the BN254 scalar field.
- **Inputs**:
    - `out1`: A pointer to a `fiat_bn254_scalar_montgomery_domain_field_element` where the result of the multiplication will be stored.
    - `arg1`: A constant pointer to a `fiat_bn254_scalar_montgomery_domain_field_element` representing the first operand in the Montgomery domain.
    - `arg2`: A constant pointer to a `fiat_bn254_scalar_montgomery_domain_field_element` representing the second operand in the Montgomery domain.
- **Control Flow**:
    - Initialize local variables to store intermediate results and carry bits.
    - Extract individual 64-bit words from the input field elements `arg1` and `arg2`.
    - Perform a series of 64-bit multiplications using [`fiat_bn254_scalar_mulx_u64`](#fiat_bn254_scalar_mulx_u64) to compute partial products of the input elements.
    - Use [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64) to accumulate the results of the partial products, handling carry bits appropriately.
    - Compute the Montgomery reduction by multiplying the intermediate result with a constant and reducing modulo the prime modulus using additional multiplications and additions.
    - Perform conditional subtraction using [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64) to ensure the result is within the field range.
    - Use [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64) to conditionally select the final result based on the carry from the subtraction.
    - Store the final result in the output parameter `out1`.
- **Output**: The function outputs the product of `arg1` and `arg2` in the Montgomery domain, stored in `out1`.
- **Functions called**:
    - [`fiat_bn254_scalar_mulx_u64`](#fiat_bn254_scalar_mulx_u64)
    - [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)
    - [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)


---
### fiat\_bn254\_scalar\_square<!-- {{#callable:fiat_bn254_scalar_square}} -->
The function `fiat_bn254_scalar_square` computes the square of a field element in the Montgomery domain for the BN254 scalar field.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A pointer to an array of four 64-bit unsigned integers representing the input field element in the Montgomery domain.
- **Control Flow**:
    - Initialize local variables to store intermediate results and carry bits.
    - Extract the four 64-bit words from the input array `arg1`.
    - Perform a series of multiplications and additions to compute the square of the input element, using the [`fiat_bn254_scalar_mulx_u64`](#fiat_bn254_scalar_mulx_u64) and [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64) functions to handle 64-bit arithmetic with carry.
    - Reduce the result modulo the prime modulus using Montgomery reduction, which involves further multiplications and additions.
    - Use conditional moves ([`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)) to ensure the result is less than the modulus, handling any potential overflow from the reduction.
    - Store the final result in the output array `out1`.
- **Output**: The function outputs the square of the input field element in the Montgomery domain, stored in the array `out1`.
- **Functions called**:
    - [`fiat_bn254_scalar_mulx_u64`](#fiat_bn254_scalar_mulx_u64)
    - [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)
    - [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)


---
### fiat\_bn254\_scalar\_add<!-- {{#callable:fiat_bn254_scalar_add}} -->
The function `fiat_bn254_scalar_add` adds two field elements in the Montgomery domain and reduces the result modulo the prime modulus.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the first field element in the Montgomery domain.
    - `arg2`: A constant pointer to an array of four 64-bit unsigned integers representing the second field element in the Montgomery domain.
- **Control Flow**:
    - Initialize temporary variables for intermediate results and carry flags.
    - Perform addition with carry for each corresponding pair of elements from `arg1` and `arg2`, storing results in temporary variables.
    - Perform subtraction with borrow to reduce the result modulo the prime modulus, using constants representing the modulus components.
    - Use conditional move operations to select between the reduced and non-reduced results based on the final borrow flag.
    - Store the final result in the `out1` array.
- **Output**: The function outputs the result of the addition, reduced modulo the prime, in the `out1` array.
- **Functions called**:
    - [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)
    - [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)


---
### fiat\_bn254\_scalar\_sub<!-- {{#callable:fiat_bn254_scalar_sub}} -->
The function `fiat_bn254_scalar_sub` subtracts two field elements in the Montgomery domain and ensures the result is within the field's bounds.
- **Inputs**:
    - `out1`: A pointer to a `fiat_bn254_scalar_montgomery_domain_field_element` where the result will be stored.
    - `arg1`: A `fiat_bn254_scalar_montgomery_domain_field_element` representing the minuend.
    - `arg2`: A `fiat_bn254_scalar_montgomery_domain_field_element` representing the subtrahend.
- **Control Flow**:
    - Initialize variables for intermediate results and carry/borrow flags.
    - Perform subtraction with borrow for each limb of the input arrays `arg1` and `arg2` using [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64).
    - Check if the final borrow flag indicates a negative result, and conditionally set a mask to correct the result by adding the modulus if necessary.
    - Use [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64) to add the modulus conditionally to the result if the borrow flag was set, ensuring the result is non-negative and within the field's bounds.
    - Store the final result in `out1`.
- **Output**: The function outputs the result of the subtraction in the `out1` parameter, which is a `fiat_bn254_scalar_montgomery_domain_field_element`.
- **Functions called**:
    - [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)
    - [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)


---
### fiat\_bn254\_scalar\_opp<!-- {{#callable:fiat_bn254_scalar_opp}} -->
The function `fiat_bn254_scalar_opp` computes the negation of a field element in the Montgomery domain, ensuring the result is within the field's modulus.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element to be negated.
- **Control Flow**:
    - Initialize temporary variables for intermediate calculations.
    - Perform a series of subtraction operations with borrow to compute the negation of each limb of the input field element `arg1`.
    - Use a conditional move operation to determine if the result needs to be adjusted by adding the modulus, based on the borrow flag from the last subtraction.
    - Add the modulus conditionally to ensure the result is non-negative and within the field's modulus.
    - Store the final result in the output array `out1`.
- **Output**: The function outputs the negated field element in the Montgomery domain, stored in the array `out1`.
- **Functions called**:
    - [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)
    - [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)


---
### fiat\_bn254\_scalar\_from\_montgomery<!-- {{#callable:fiat_bn254_scalar_from_montgomery}} -->
The function `fiat_bn254_scalar_from_montgomery` converts a field element from the Montgomery domain to the standard representation.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored, representing the field element in the non-Montgomery domain.
    - `arg1`: A pointer to an array of four 64-bit unsigned integers representing the field element in the Montgomery domain.
- **Control Flow**:
    - Initialize several 64-bit unsigned integers and fiat_bn254_scalar_uint1 variables for intermediate calculations.
    - Extract the first element of the input array `arg1` and perform a series of multiplications and additions to compute intermediate values.
    - Use the [`fiat_bn254_scalar_mulx_u64`](#fiat_bn254_scalar_mulx_u64) function to perform multiplications and [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64) to handle additions with carry, iterating over each element of `arg1`.
    - For each element, compute a temporary value by multiplying with a constant and then reduce it using the modulus of the field, performing carry operations as needed.
    - After processing all elements, perform a series of subtractions using [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64) to ensure the result is within the field's modulus.
    - Use conditional moves [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64) to select the correct result based on the final carry flag.
    - Store the final result in the `out1` array.
- **Output**: The function outputs a field element in the non-Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_bn254_scalar_mulx_u64`](#fiat_bn254_scalar_mulx_u64)
    - [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)
    - [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)


---
### fiat\_bn254\_scalar\_to\_montgomery<!-- {{#callable:fiat_bn254_scalar_to_montgomery}} -->
The function `fiat_bn254_scalar_to_montgomery` converts a field element from the non-Montgomery domain to the Montgomery domain for the BN254 scalar field.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result in the Montgomery domain will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the input field element in the non-Montgomery domain.
- **Control Flow**:
    - Extracts the four 64-bit words from the input array `arg1` into variables `x1`, `x2`, `x3`, and `x4`.
    - Performs a series of multiplications and additions using the extracted words and specific constants to compute intermediate results.
    - Uses the [`fiat_bn254_scalar_mulx_u64`](#fiat_bn254_scalar_mulx_u64) function to perform 64-bit multiplications and [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64) to handle additions with carry.
    - Computes the Montgomery reduction by multiplying with a constant and reducing modulo the prime modulus using a series of multiplications and additions.
    - Performs conditional moves using [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64) to ensure the result is within the field's bounds.
    - Stores the final result in the output array `out1`.
- **Output**: The function outputs the Montgomery domain representation of the input field element in the array `out1`.
- **Functions called**:
    - [`fiat_bn254_scalar_mulx_u64`](#fiat_bn254_scalar_mulx_u64)
    - [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)
    - [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)


---
### fiat\_bn254\_scalar\_nonzero<!-- {{#callable:fiat_bn254_scalar_nonzero}} -->
The function `fiat_bn254_scalar_nonzero` checks if a 4-element array of 64-bit unsigned integers is non-zero and outputs a single non-zero word if it is, or zero otherwise.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: An array of four 64-bit unsigned integers representing the input to be checked for non-zero values.
- **Control Flow**:
    - The function initializes a local variable `x1` to the bitwise OR of all elements in the input array `arg1`.
    - The result of the OR operation, `x1`, is assigned to the dereferenced pointer `out1`.
- **Output**: The function outputs a single 64-bit unsigned integer through the pointer `out1`, which is non-zero if any element of `arg1` is non-zero, and zero otherwise.


---
### fiat\_bn254\_scalar\_selectznz<!-- {{#callable:fiat_bn254_scalar_selectznz}} -->
The function `fiat_bn254_scalar_selectznz` performs a conditional selection between two 4-element arrays based on a single-bit flag.
- **Inputs**:
    - `out1`: An array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A single-bit flag (0 or 1) of type `fiat_bn254_scalar_uint1` that determines which array to select.
    - `arg2`: A 4-element array of 64-bit unsigned integers, representing the first option for selection.
    - `arg3`: A 4-element array of 64-bit unsigned integers, representing the second option for selection.
- **Control Flow**:
    - The function initializes four local variables `x1`, `x2`, `x3`, and `x4` to store the selected values from either `arg2` or `arg3` based on `arg1`.
    - It calls [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64) four times, each time selecting between corresponding elements of `arg2` and `arg3` based on `arg1`.
    - The selected values are stored in `x1`, `x2`, `x3`, and `x4`.
    - Finally, the selected values are assigned to the `out1` array.
- **Output**: The function outputs the selected 4-element array in `out1`, which is either `arg2` or `arg3` based on the value of `arg1`.
- **Functions called**:
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)


---
### fiat\_bn254\_scalar\_to\_bytes<!-- {{#callable:fiat_bn254_scalar_to_bytes}} -->
The function `fiat_bn254_scalar_to_bytes` converts a 256-bit scalar represented as four 64-bit unsigned integers into a 32-byte array in little-endian order.
- **Inputs**:
    - `out1`: A 32-element array of uint8_t where the resulting bytes will be stored.
    - `arg1`: A 4-element array of uint64_t representing the scalar to be converted to bytes.
- **Control Flow**:
    - Extract the least significant byte from each 64-bit integer in `arg1` and store it in `out1` in little-endian order.
    - Shift the 64-bit integer right by 8 bits and repeat the extraction process for the next byte, continuing until all bytes are extracted.
    - Repeat the above steps for each of the four 64-bit integers in `arg1`.
- **Output**: The function does not return a value; it populates the `out1` array with the byte representation of the input scalar.


---
### fiat\_bn254\_scalar\_from\_bytes<!-- {{#callable:fiat_bn254_scalar_from_bytes}} -->
The function `fiat_bn254_scalar_from_bytes` converts a 32-byte array into a 4-element array of 64-bit unsigned integers, representing a field element in little-endian order.
- **Inputs**:
    - `out1`: A 4-element array of 64-bit unsigned integers where the result will be stored.
    - `arg1`: A 32-element array of 8-bit unsigned integers representing the input bytes in little-endian order.
- **Control Flow**:
    - Initialize multiple 64-bit unsigned integers to store intermediate results.
    - Extract and shift each byte from the input array `arg1` to construct 64-bit integers, combining them to form four 64-bit integers.
    - Store the resulting 64-bit integers into the output array `out1`.
- **Output**: The function outputs a 4-element array of 64-bit unsigned integers representing the deserialized field element.


---
### fiat\_bn254\_scalar\_set\_one<!-- {{#callable:fiat_bn254_scalar_set_one}} -->
The function `fiat_bn254_scalar_set_one` initializes a field element in the Montgomery domain to represent the value one.
- **Inputs**:
    - `out1`: A pointer to a `fiat_bn254_scalar_montgomery_domain_field_element`, which is an array of four 64-bit unsigned integers, where the result will be stored.
- **Control Flow**:
    - The function directly assigns specific constant values to each of the four elements of the `out1` array.
    - These constants are precomputed values that represent the number one in the Montgomery domain for the bn254 scalar field.
- **Output**: The function does not return a value; it modifies the `out1` array in place to represent the number one in the Montgomery domain.


---
### fiat\_bn254\_scalar\_msat<!-- {{#callable:fiat_bn254_scalar_msat}} -->
The function `fiat_bn254_scalar_msat` initializes an array with the saturated representation of the prime modulus for the bn254_scalar curve.
- **Inputs**:
    - `out1`: An array of 5 uint64_t elements where the saturated representation of the prime modulus will be stored.
- **Control Flow**:
    - The function assigns the first element of the array `out1` to the constant `0x43e1f593f0000001`.
    - The second element of `out1` is set to `0x2833e84879b97091`.
    - The third element of `out1` is set to `0xb85045b68181585d`.
    - The fourth element of `out1` is set to `0x30644e72e131a029`.
    - The fifth element of `out1` is set to `0x0`.
- **Output**: The function does not return a value; it modifies the `out1` array in place to contain the saturated representation of the prime modulus.


---
### fiat\_bn254\_scalar\_divstep\_precomp<!-- {{#callable:fiat_bn254_scalar_divstep_precomp}} -->
The function `fiat_bn254_scalar_divstep_precomp` initializes a 4-element array with precomputed constants for the Bernstein-Yang inversion in Montgomery form.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the precomputed values will be stored.
- **Control Flow**:
    - The function assigns the first element of the array `out1` to the constant `0x99ddb8c9f8b62554`.
    - The function assigns the second element of the array `out1` to the constant `0x9d24a395a4811e46`.
    - The function assigns the third element of the array `out1` to the constant `0x241215ce0ed81b0`.
    - The function assigns the fourth element of the array `out1` to the constant `0x2e6a72a316e4cfb6`.
- **Output**: The function does not return a value; it modifies the array `out1` in place.


---
### fiat\_bn254\_scalar\_divstep<!-- {{#callable:fiat_bn254_scalar_divstep}} -->
The function `fiat_bn254_scalar_divstep` performs a division step in the context of the BN254 scalar field arithmetic, updating multiple output arrays based on the input conditions and values.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result of the division step will be stored.
    - `out2`: An array of 5 uint64_t elements that will be updated based on the division step.
    - `out3`: An array of 5 uint64_t elements that will be updated based on the division step.
    - `out4`: An array of 4 uint64_t elements that will be updated based on the division step.
    - `out5`: An array of 4 uint64_t elements that will be updated based on the division step.
    - `arg1`: A uint64_t input value used in the division step.
    - `arg2`: An array of 5 uint64_t elements representing one of the input values for the division step.
    - `arg3`: An array of 5 uint64_t elements representing another input value for the division step.
    - `arg4`: An array of 4 uint64_t elements representing one of the input values for the division step.
    - `arg5`: An array of 4 uint64_t elements representing another input value for the division step.
- **Control Flow**:
    - Initialize variables and perform bitwise operations to determine the control flow based on the least significant bit of `arg3[0]` and the sign of `arg1`.
    - Use conditional moves ([`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)) to select between `arg2` and `arg3`, and between `arg4` and `arg5`, based on the control flow condition.
    - Perform arithmetic operations including addition with carry ([`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)) and subtraction with borrow ([`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)) to compute intermediate values.
    - Update `out1` with the result of incrementing or decrementing `arg1` based on the control flow condition.
    - Update `out2`, `out3`, `out4`, and `out5` with the computed values based on the control flow condition and the results of the arithmetic operations.
- **Output**: The function updates the values pointed to by `out1`, `out2`, `out3`, `out4`, and `out5` based on the division step logic and the input arguments.
- **Functions called**:
    - [`fiat_bn254_scalar_addcarryx_u64`](#fiat_bn254_scalar_addcarryx_u64)
    - [`fiat_bn254_scalar_cmovznz_u64`](#fiat_bn254_scalar_cmovznz_u64)
    - [`fiat_bn254_scalar_subborrowx_u64`](#fiat_bn254_scalar_subborrowx_u64)


