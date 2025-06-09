# Purpose
This C source code file is an implementation of arithmetic operations in the Montgomery domain for the secp256k1 elliptic curve, specifically targeting the scalar field defined by the prime modulus \( m = 2^{256} - 432420386565659656852420866394968145599 \). The code is auto-generated and provides a comprehensive set of functions to perform arithmetic operations such as addition, subtraction, multiplication, and squaring within the Montgomery domain. It also includes functions for converting numbers to and from the Montgomery representation, as well as utility functions for conditional moves and serialization/deserialization of field elements.

The file defines several types and macros to facilitate operations on 64-bit words, leveraging compiler-specific extensions for inline assembly and type definitions. The core functionality revolves around the manipulation of field elements represented as arrays of 64-bit integers, with operations ensuring that results remain within the bounds of the prime modulus. The code is structured to support efficient computation by using carry and borrow techniques for addition and subtraction, and it includes precomputed values for optimizing division steps. This implementation is crucial for cryptographic applications that require secure and efficient arithmetic operations on elliptic curves, such as those used in Bitcoin and other blockchain technologies.
# Imports and Dependencies

---
- `stdint.h`


# Global Variables

---
### fiat\_secp256k1\_montgomery\_scalar\_int128
- **Type**: `signed __int128`
- **Description**: The `fiat_secp256k1_montgomery_scalar_int128` is a typedef for a signed 128-bit integer type, which is an extension provided by some compilers like GCC or Clang. This type allows for operations on 128-bit signed integers, which are not natively supported by all C compilers.
- **Use**: This variable is used to perform arithmetic operations that require 128-bit signed integer precision, particularly in cryptographic computations involving the secp256k1 curve.


---
### fiat\_secp256k1\_montgomery\_scalar\_uint128
- **Type**: `unsigned __int128`
- **Description**: The `fiat_secp256k1_montgomery_scalar_uint128` is a typedef for an unsigned 128-bit integer type. This type is used to represent large integers that require more than the standard 64-bit integer size, allowing for operations on numbers up to 2^128 - 1.
- **Use**: This variable is used in arithmetic operations that require handling of large numbers, such as those involved in cryptographic computations for the secp256k1 curve.


# Functions

---
### fiat\_secp256k1\_montgomery\_scalar\_value\_barrier\_u64<!-- {{#callable:fiat_secp256k1_montgomery_scalar_value_barrier_u64}} -->
The function `fiat_secp256k1_montgomery_scalar_value_barrier_u64` acts as a value barrier for a 64-bit unsigned integer, ensuring that the compiler does not optimize away certain operations involving the variable.
- **Inputs**:
    - `a`: A 64-bit unsigned integer that is passed to the function.
- **Control Flow**:
    - The function uses an inline assembly statement to create a value barrier for the input variable `a`.
    - The assembly statement is a no-operation (NOP) that uses the `+r` constraint to indicate that `a` is both an input and an output, effectively preventing the compiler from optimizing away operations involving `a`.
    - The function then returns the value of `a`.
- **Output**: The function returns the same 64-bit unsigned integer that was passed as input.


---
### fiat\_secp256k1\_montgomery\_scalar\_addcarryx\_u64<!-- {{#callable:fiat_secp256k1_montgomery_scalar_addcarryx_u64}} -->
The function `fiat_secp256k1_montgomery_scalar_addcarryx_u64` performs a 64-bit addition with carry, returning both the sum and the carry.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result of the addition will be stored.
    - `out2`: A pointer to a fiat_secp256k1_montgomery_scalar_uint1 where the carry-out of the addition will be stored.
    - `arg1`: A fiat_secp256k1_montgomery_scalar_uint1 representing the initial carry-in for the addition.
    - `arg2`: A 64-bit unsigned integer, one of the operands for the addition.
    - `arg3`: A 64-bit unsigned integer, the other operand for the addition.
- **Control Flow**:
    - The function begins by calculating the sum of `arg1`, `arg2`, and `arg3`, storing the result in a 128-bit unsigned integer `x1` to handle potential overflow.
    - The lower 64 bits of `x1` are extracted and stored in `x2`, which is then assigned to `*out1`.
    - The upper bits of `x1` (beyond 64 bits) are extracted and stored in `x3`, which is then assigned to `*out2` as the carry-out.
- **Output**: The function outputs the 64-bit sum of the inputs modulo 2^64 in `out1` and the carry-out in `out2`.


---
### fiat\_secp256k1\_montgomery\_scalar\_subborrowx\_u64<!-- {{#callable:fiat_secp256k1_montgomery_scalar_subborrowx_u64}} -->
The function `fiat_secp256k1_montgomery_scalar_subborrowx_u64` performs a subtraction of two 64-bit unsigned integers with an additional borrow input, and outputs the result along with a borrow flag.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result of the subtraction will be stored.
    - `out2`: A pointer to a fiat_secp256k1_montgomery_scalar_uint1 where the borrow flag will be stored.
    - `arg1`: A fiat_secp256k1_montgomery_scalar_uint1 representing the initial borrow input.
    - `arg2`: A 64-bit unsigned integer representing the minuend.
    - `arg3`: A 64-bit unsigned integer representing the subtrahend.
- **Control Flow**:
    - Calculate the intermediate result `x1` as `arg2 - arg1 - arg3` using 128-bit integer arithmetic to handle potential overflow.
    - Extract the borrow flag `x2` by right-shifting `x1` by 64 bits, which indicates if the subtraction resulted in a negative value.
    - Extract the lower 64 bits of `x1` as `x3`, which is the actual result of the subtraction modulo 2^64.
    - Store `x3` in the location pointed to by `out1`.
    - Store the negated borrow flag `0x0 - x2` in the location pointed to by `out2`.
- **Output**: The function outputs the result of the subtraction in `out1` and the borrow flag in `out2`, indicating if a borrow was needed.


---
### fiat\_secp256k1\_montgomery\_scalar\_mulx\_u64<!-- {{#callable:fiat_secp256k1_montgomery_scalar_mulx_u64}} -->
The function `fiat_secp256k1_montgomery_scalar_mulx_u64` performs a 64-bit multiplication of two unsigned integers and returns the result as a double-width 128-bit integer split into two 64-bit parts.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the lower 64 bits of the product will be stored.
    - `out2`: A pointer to a 64-bit unsigned integer where the upper 64 bits of the product will be stored.
    - `arg1`: A 64-bit unsigned integer representing the first operand of the multiplication.
    - `arg2`: A 64-bit unsigned integer representing the second operand of the multiplication.
- **Control Flow**:
    - Declare a 128-bit unsigned integer `x1` to store the full product of `arg1` and `arg2`.
    - Calculate the product of `arg1` and `arg2` and store it in `x1`.
    - Extract the lower 64 bits of `x1` and store them in `x2`.
    - Extract the upper 64 bits of `x1` and store them in `x3`.
    - Assign the value of `x2` to the location pointed to by `out1`.
    - Assign the value of `x3` to the location pointed to by `out2`.
- **Output**: The function outputs the lower 64 bits of the product in `out1` and the upper 64 bits in `out2`.


---
### fiat\_secp256k1\_montgomery\_scalar\_cmovznz\_u64<!-- {{#callable:fiat_secp256k1_montgomery_scalar_cmovznz_u64}} -->
The function `fiat_secp256k1_montgomery_scalar_cmovznz_u64` performs a conditional move operation on two 64-bit unsigned integers based on a single-bit condition.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: A single-bit unsigned integer (0 or 1) that acts as the condition for the move operation.
    - `arg2`: A 64-bit unsigned integer that will be selected if `arg1` is 0.
    - `arg3`: A 64-bit unsigned integer that will be selected if `arg1` is 1.
- **Control Flow**:
    - The function first negates `arg1` twice to ensure it is either 0 or 1, storing the result in `x1`.
    - It calculates `x2` as the bitwise AND of the negated `x1` and the maximum 64-bit unsigned integer value, effectively creating a mask.
    - The function then uses this mask to select between `arg2` and `arg3` using bitwise operations, storing the result in `x3`.
    - Finally, the result `x3` is stored in the location pointed to by `out1`.
- **Output**: The function outputs the selected 64-bit unsigned integer based on the condition `arg1`, storing it in the location pointed to by `out1`.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_value_barrier_u64`](#fiat_secp256k1_montgomery_scalar_value_barrier_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_mul<!-- {{#callable:fiat_secp256k1_montgomery_scalar_mul}} -->
The function `fiat_secp256k1_montgomery_scalar_mul` performs multiplication of two field elements in the Montgomery domain for the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the first operand in the Montgomery domain.
    - `arg2`: A constant pointer to an array of four 64-bit unsigned integers representing the second operand in the Montgomery domain.
- **Control Flow**:
    - Initialize local variables for intermediate calculations.
    - Extract individual elements from the input arrays `arg1` and `arg2`.
    - Perform a series of multiplications and additions using the [`fiat_secp256k1_montgomery_scalar_mulx_u64`](#fiat_secp256k1_montgomery_scalar_mulx_u64) and [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64) functions to compute the product of `arg1` and `arg2` in the Montgomery domain.
    - Compute the Montgomery reduction using the constant `0x4b0dff665588b13f` and the modulus `m` of the secp256k1 curve.
    - Perform conditional subtraction to ensure the result is within the field range.
    - Store the final result in the `out1` array.
- **Output**: The function outputs the result of the multiplication in the Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_mulx_u64`](#fiat_secp256k1_montgomery_scalar_mulx_u64)
    - [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_scalar_subborrowx_u64`](#fiat_secp256k1_montgomery_scalar_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_square<!-- {{#callable:fiat_secp256k1_montgomery_scalar_square}} -->
The function `fiat_secp256k1_montgomery_scalar_square` computes the square of a field element in the Montgomery domain for the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A pointer to an array of four 64-bit unsigned integers representing the field element to be squared, in the Montgomery domain.
- **Control Flow**:
    - Extracts the four 64-bit words from the input field element `arg1`.
    - Performs a series of multiplications and additions to compute the square of the input element, using the Montgomery multiplication technique.
    - Reduces the result modulo the prime of the secp256k1 curve using a series of multiplications and additions with precomputed constants.
    - Handles carry propagation and conditional moves to ensure the result is within the field's bounds.
    - Stores the final result in the `out1` array.
- **Output**: The function outputs the square of the input field element in the Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_mulx_u64`](#fiat_secp256k1_montgomery_scalar_mulx_u64)
    - [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_scalar_subborrowx_u64`](#fiat_secp256k1_montgomery_scalar_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_add<!-- {{#callable:fiat_secp256k1_montgomery_scalar_add}} -->
The function `fiat_secp256k1_montgomery_scalar_add` adds two field elements in the Montgomery domain and reduces the result modulo the prime modulus.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the first operand in the Montgomery domain.
    - `arg2`: A constant pointer to an array of four 64-bit unsigned integers representing the second operand in the Montgomery domain.
- **Control Flow**:
    - Initialize temporary variables for intermediate results and carry flags.
    - Perform addition with carry for each corresponding pair of elements from `arg1` and `arg2`, storing results in temporary variables.
    - Perform subtraction with borrow to reduce the result modulo the prime modulus, using constants specific to the secp256k1 curve.
    - Use conditional move operations to select between the reduced and non-reduced results based on the final borrow flag.
    - Store the final result in the `out1` array.
- **Output**: The function outputs the result of the addition in the Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_scalar_subborrowx_u64`](#fiat_secp256k1_montgomery_scalar_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_sub<!-- {{#callable:fiat_secp256k1_montgomery_scalar_sub}} -->
The function `fiat_secp256k1_montgomery_scalar_sub` subtracts two field elements in the Montgomery domain and ensures the result is within the field's bounds.
- **Inputs**:
    - `out1`: A pointer to a `fiat_secp256k1_montgomery_scalar_montgomery_domain_field_element` where the result will be stored.
    - `arg1`: A constant pointer to a `fiat_secp256k1_montgomery_scalar_montgomery_domain_field_element` representing the minuend.
    - `arg2`: A constant pointer to a `fiat_secp256k1_montgomery_scalar_montgomery_domain_field_element` representing the subtrahend.
- **Control Flow**:
    - Initialize variables for intermediate results and carry/borrow flags.
    - Perform subtraction with borrow for each 64-bit limb of the input arrays `arg1` and `arg2`, storing results in temporary variables.
    - Check if the subtraction resulted in a borrow (indicating a negative result) and conditionally set a mask to correct the result by adding the modulus.
    - Use conditional move operations to apply the correction if necessary, ensuring the result is non-negative and within the field's bounds.
    - Store the final result in the output array `out1`.
- **Output**: The function outputs the result of the subtraction in the `out1` array, which is a field element in the Montgomery domain.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_subborrowx_u64`](#fiat_secp256k1_montgomery_scalar_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)
    - [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_opp<!-- {{#callable:fiat_secp256k1_montgomery_scalar_opp}} -->
The function `fiat_secp256k1_montgomery_scalar_opp` computes the negation of a field element in the Montgomery domain for the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the input field element in the Montgomery domain.
- **Control Flow**:
    - Initialize temporary variables for intermediate calculations.
    - Perform a series of subtraction operations with borrow to compute the negation of the input field element, storing intermediate results in temporary variables.
    - Use a conditional move operation to handle the case where the subtraction results in a negative value, adjusting the result to ensure it is within the field's range.
    - Perform a series of addition operations with carry to finalize the negation result, ensuring it is within the field's range.
    - Store the final result in the output array `out1`.
- **Output**: The function outputs the negated field element in the Montgomery domain, stored in the array `out1`.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_subborrowx_u64`](#fiat_secp256k1_montgomery_scalar_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)
    - [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_from\_montgomery<!-- {{#callable:fiat_secp256k1_montgomery_scalar_from_montgomery}} -->
The function `fiat_secp256k1_montgomery_scalar_from_montgomery` converts a field element from the Montgomery domain to the standard representation.
- **Inputs**:
    - `out1`: A pointer to an array of 4 uint64_t elements where the result will be stored, representing the field element in the non-Montgomery domain.
    - `arg1`: A constant pointer to an array of 4 uint64_t elements representing the field element in the Montgomery domain.
- **Control Flow**:
    - Initialize several uint64_t and fiat_secp256k1_montgomery_scalar_uint1 variables for intermediate calculations.
    - Extract the first element of the input array `arg1` and perform a series of multiplications and additions to compute intermediate results.
    - Use the [`fiat_secp256k1_montgomery_scalar_mulx_u64`](#fiat_secp256k1_montgomery_scalar_mulx_u64) function to perform multiplications and [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64) to handle additions with carry.
    - Repeat the process for each element of `arg1`, updating the intermediate results accordingly.
    - Perform a series of conditional moves using [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64) to ensure the result is within the field's bounds.
    - Store the final results in the `out1` array.
- **Output**: The function outputs a field element in the non-Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_mulx_u64`](#fiat_secp256k1_montgomery_scalar_mulx_u64)
    - [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_scalar_subborrowx_u64`](#fiat_secp256k1_montgomery_scalar_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_to\_montgomery<!-- {{#callable:fiat_secp256k1_montgomery_scalar_to_montgomery}} -->
The function `fiat_secp256k1_montgomery_scalar_to_montgomery` converts a field element from the non-Montgomery domain to the Montgomery domain for the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored, representing the field element in the Montgomery domain.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element in the non-Montgomery domain.
- **Control Flow**:
    - Initialize several 64-bit unsigned integers and fiat_secp256k1_montgomery_scalar_uint1 variables for intermediate calculations.
    - Extract the four elements of the input array `arg1` into separate variables `x1`, `x2`, `x3`, and `x4`.
    - Perform a series of multiplications and additions using the constants specific to the secp256k1 curve to transform the input into the Montgomery domain.
    - Use the [`fiat_secp256k1_montgomery_scalar_mulx_u64`](#fiat_secp256k1_montgomery_scalar_mulx_u64) function to perform 64-bit multiplications and [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64) to handle additions with carry.
    - Compute the Montgomery reduction by multiplying with the constant `0x4b0dff665588b13f` and performing further multiplications and additions to ensure the result is reduced modulo the curve's prime.
    - Store the final result in the `out1` array, representing the input field element in the Montgomery domain.
- **Output**: The function outputs the Montgomery domain representation of the input field element in the `out1` array.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_mulx_u64`](#fiat_secp256k1_montgomery_scalar_mulx_u64)
    - [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_scalar_subborrowx_u64`](#fiat_secp256k1_montgomery_scalar_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_nonzero<!-- {{#callable:fiat_secp256k1_montgomery_scalar_nonzero}} -->
The function `fiat_secp256k1_montgomery_scalar_nonzero` checks if a given 256-bit scalar is non-zero by performing a bitwise OR operation across its four 64-bit components.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: An array of four 64-bit unsigned integers representing a 256-bit scalar.
- **Control Flow**:
    - The function initializes a 64-bit unsigned integer `x1` to store the result of the bitwise OR operation.
    - It performs a bitwise OR operation on all four elements of the input array `arg1` to determine if any of them is non-zero.
    - The result of the OR operation is stored in `x1`.
    - The value of `x1` is then assigned to the location pointed to by `out1`.
- **Output**: The function outputs a single 64-bit unsigned integer that is non-zero if any part of the input scalar is non-zero, and zero otherwise.


---
### fiat\_secp256k1\_montgomery\_scalar\_selectznz<!-- {{#callable:fiat_secp256k1_montgomery_scalar_selectznz}} -->
The function `fiat_secp256k1_montgomery_scalar_selectznz` performs a conditional selection between two 4-element arrays based on a single-bit flag.
- **Inputs**:
    - `out1`: A 4-element array of uint64_t where the result of the selection will be stored.
    - `arg1`: A single-bit flag (fiat_secp256k1_montgomery_scalar_uint1) that determines which array to select.
    - `arg2`: A 4-element array of uint64_t representing the first option for selection.
    - `arg3`: A 4-element array of uint64_t representing the second option for selection.
- **Control Flow**:
    - The function initializes four uint64_t variables (x1, x2, x3, x4) to store the results of the conditional move operations.
    - For each element in the arrays (arg2 and arg3), the function calls [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64) to perform a conditional move based on the value of arg1.
    - If arg1 is 0, the corresponding element from arg2 is selected; otherwise, the element from arg3 is selected.
    - The selected elements are stored in the variables x1, x2, x3, and x4.
    - The function then assigns these selected values to the output array out1.
- **Output**: The function outputs a 4-element array (out1) containing the selected elements from either arg2 or arg3 based on the value of arg1.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_to\_bytes<!-- {{#callable:fiat_secp256k1_montgomery_scalar_to_bytes}} -->
The function `fiat_secp256k1_montgomery_scalar_to_bytes` converts a 256-bit scalar from a 4-element array of 64-bit integers into a 32-byte array in little-endian order.
- **Inputs**:
    - `out1`: A 32-byte array where the result will be stored.
    - `arg1`: A 4-element array of 64-bit unsigned integers representing the scalar to be converted.
- **Control Flow**:
    - Extracts each 64-bit integer from the input array `arg1` and processes them individually.
    - For each 64-bit integer, it extracts each byte by masking and shifting operations.
    - Stores each extracted byte into the corresponding position in the output array `out1`.
    - The bytes are stored in little-endian order, meaning the least significant byte of each 64-bit integer is stored first.
- **Output**: The function outputs a 32-byte array `out1` containing the little-endian byte representation of the input scalar.


---
### fiat\_secp256k1\_montgomery\_scalar\_from\_bytes<!-- {{#callable:fiat_secp256k1_montgomery_scalar_from_bytes}} -->
The function `fiat_secp256k1_montgomery_scalar_from_bytes` converts a 32-byte array into a 4-element array of 64-bit unsigned integers, representing a field element not in the Montgomery domain.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A pointer to an array of 32 bytes representing the input data in little-endian order.
- **Control Flow**:
    - Initialize multiple 64-bit unsigned integers and 8-bit unsigned integers to hold intermediate values.
    - Extract each byte from the input array `arg1` and shift it to its correct position to form 64-bit integers.
    - Combine the shifted values to form four 64-bit integers, each representing a part of the field element.
    - Store the resulting 64-bit integers into the output array `out1`.
- **Output**: The function outputs a 4-element array of 64-bit unsigned integers representing the deserialized field element.


---
### fiat\_secp256k1\_montgomery\_scalar\_set\_one<!-- {{#callable:fiat_secp256k1_montgomery_scalar_set_one}} -->
The function `fiat_secp256k1_montgomery_scalar_set_one` initializes a field element in the Montgomery domain to represent the value one.
- **Inputs**:
    - `out1`: A pointer to a `fiat_secp256k1_montgomery_scalar_montgomery_domain_field_element` array where the result will be stored.
- **Control Flow**:
    - The function directly assigns specific constant values to the elements of the `out1` array.
    - The first element of `out1` is set to `0x402da1732fc9bebf`.
    - The second element of `out1` is set to `0x4551231950b75fc4`.
    - The third element of `out1` is set to `0x1`.
    - The fourth element of `out1` is set to `0x0`.
- **Output**: The function does not return a value; it modifies the `out1` array in place to represent the number one in the Montgomery domain.


---
### fiat\_secp256k1\_montgomery\_scalar\_msat<!-- {{#callable:fiat_secp256k1_montgomery_scalar_msat}} -->
The function `fiat_secp256k1_montgomery_scalar_msat` initializes an array with the saturated representation of the prime modulus for the secp256k1 curve in the Montgomery domain.
- **Inputs**:
    - `out1`: An array of 5 uint64_t elements where the saturated representation of the prime modulus will be stored.
- **Control Flow**:
    - The function assigns the first element of the array `out1` to the constant `0xbfd25e8cd0364141`.
    - The second element of the array `out1` is assigned the constant `0xbaaedce6af48a03b`.
    - The third element of the array `out1` is assigned the constant `0xfffffffffffffffe`.
    - The fourth element of the array `out1` is assigned the constant `0xffffffffffffffff`.
    - The fifth element of the array `out1` is set to `0x0`.
- **Output**: The function does not return a value; it modifies the input array `out1` in place.


---
### fiat\_secp256k1\_montgomery\_scalar\_divstep<!-- {{#callable:fiat_secp256k1_montgomery_scalar_divstep}} -->
The function `fiat_secp256k1_montgomery_scalar_divstep` computes a divstep operation for the secp256k1 curve in the Montgomery domain, adjusting the inputs based on certain conditions and producing multiple outputs.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result of the divstep operation will be stored.
    - `out2`: An array of 5 uint64_t elements where the adjusted value of arg2 or arg3 will be stored based on conditions.
    - `out3`: An array of 5 uint64_t elements where the adjusted value of arg3 or a combination of arg2 and arg3 will be stored based on conditions.
    - `out4`: An array of 4 uint64_t elements where the adjusted value of arg4 or arg5 will be stored based on conditions.
    - `out5`: An array of 4 uint64_t elements where the adjusted value of arg5 or a combination of arg4 and arg5 will be stored based on conditions.
    - `arg1`: A uint64_t input representing a scalar value used in the divstep operation.
    - `arg2`: An array of 5 uint64_t elements representing a field element in the Montgomery domain.
    - `arg3`: An array of 5 uint64_t elements representing another field element in the Montgomery domain.
    - `arg4`: An array of 4 uint64_t elements representing a field element in the Montgomery domain.
    - `arg5`: An array of 4 uint64_t elements representing another field element in the Montgomery domain.
- **Control Flow**:
    - Initialize variables and perform a conditional negation of arg1 to determine the control flow path.
    - Use conditional move operations to select between arg2 and arg3, and between arg4 and arg5, based on the condition derived from arg1 and arg3.
    - Perform arithmetic operations (addition, subtraction, and bitwise shifts) to compute intermediate values for out2, out3, out4, and out5.
    - Use conditional move operations to finalize the values of out2, out3, out4, and out5 based on the results of the arithmetic operations and conditions.
    - Store the final result of the divstep operation in out1.
- **Output**: The function outputs a uint64_t value in out1 and updates the arrays out2, out3, out4, and out5 with the results of the divstep operation.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_scalar_addcarryx_u64`](#fiat_secp256k1_montgomery_scalar_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_scalar_cmovznz_u64`](#fiat_secp256k1_montgomery_scalar_cmovznz_u64)
    - [`fiat_secp256k1_montgomery_scalar_subborrowx_u64`](#fiat_secp256k1_montgomery_scalar_subborrowx_u64)


---
### fiat\_secp256k1\_montgomery\_scalar\_divstep\_precomp<!-- {{#callable:fiat_secp256k1_montgomery_scalar_divstep_precomp}} -->
The function `fiat_secp256k1_montgomery_scalar_divstep_precomp` initializes a 4-element array with precomputed constants for Montgomery scalar division steps.
- **Inputs**:
    - `out1`: A 4-element array of type `uint64_t` where the precomputed constants will be stored.
- **Control Flow**:
    - The function assigns the first element of `out1` to the constant `0xd7431a4d2b9cb4e9`.
    - The function assigns the second element of `out1` to the constant `0xab67d35a32d9c503`.
    - The function assigns the third element of `out1` to the constant `0xadf6c7e5859ce35f`.
    - The function assigns the fourth element of `out1` to the constant `0x615441451df6c379`.
- **Output**: The function does not return a value; it modifies the input array `out1` in place.


