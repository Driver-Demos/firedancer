# Purpose
The provided C code is an implementation of arithmetic operations in the Montgomery domain for the secp256k1 elliptic curve, which is widely used in cryptographic applications such as Bitcoin. This code is specifically designed to perform efficient modular arithmetic operations using the Montgomery reduction technique, which is beneficial for cryptographic computations involving large numbers. The code includes functions for basic arithmetic operations like addition, subtraction, multiplication, and squaring, as well as conversions to and from the Montgomery domain. It also includes functions for conditional operations and serialization/deserialization of field elements.

The code is auto-generated and optimized for a 64-bit architecture, as indicated by the use of 64-bit machine words. It defines several types and macros to facilitate the implementation of these operations, such as `fiat_secp256k1_montgomery_uint1` and `fiat_secp256k1_montgomery_int128`, which are used for handling carry and overflow in arithmetic operations. The functions are marked as `static` and `inline` to suggest that they are intended for use within a single compilation unit, optimizing for performance by reducing function call overhead. The code also includes functions for computing the modular inverse using the divstep algorithm, which is crucial for cryptographic protocols that require inversion operations. Overall, this file provides a comprehensive set of tools for performing high-performance cryptographic computations on the secp256k1 curve.
# Imports and Dependencies

---
- `stdint.h`


# Global Variables

---
### fiat\_secp256k1\_montgomery\_int128
- **Type**: ``signed __int128``
- **Description**: The variable `fiat_secp256k1_montgomery_int128` is a typedef for a signed 128-bit integer type, which is an extension provided by some compilers like GCC or Clang. This type allows for operations on 128-bit signed integers, which are not natively supported by all C compilers.
- **Use**: This variable is used to perform arithmetic operations that require 128-bit signed integer precision, particularly in cryptographic computations involving the secp256k1 curve in the Montgomery domain.


---
### fiat\_secp256k1\_montgomery\_uint128
- **Type**: `unsigned __int128`
- **Description**: The `fiat_secp256k1_montgomery_uint128` is a typedef for an unsigned 128-bit integer type. It is used to represent large integers that require more than the standard 64-bit integer size, allowing for operations on numbers up to 2^128 - 1.
- **Use**: This variable is used in arithmetic operations within the secp256k1 Montgomery arithmetic implementation, particularly for handling carry and overflow in multi-word arithmetic.


# Functions

---
### fiat\_secp256k1\_montgomery\_value\_barrier\_u64<!-- {{#callable:fiat_secp256k1_montgomery_value_barrier_u64}} -->
The function `fiat_secp256k1_montgomery_value_barrier_u64` acts as a value barrier for a 64-bit unsigned integer, ensuring that the compiler does not optimize away certain operations involving the variable.
- **Inputs**:
    - `a`: A 64-bit unsigned integer that serves as the input to the function.
- **Control Flow**:
    - The function uses an inline assembly statement to create a value barrier for the input variable `a`.
    - The assembly statement is a no-operation (NOP) that uses the `+r` constraint to indicate that `a` is both an input and an output, effectively preventing the compiler from optimizing away operations involving `a`.
    - The function then returns the value of `a`.
- **Output**: The function returns the same 64-bit unsigned integer that was passed as input, `a`.


---
### fiat\_secp256k1\_montgomery\_addcarryx\_u64<!-- {{#callable:fiat_secp256k1_montgomery_addcarryx_u64}} -->
The function `fiat_secp256k1_montgomery_addcarryx_u64` performs a 64-bit addition with carry, returning both the result and the carry.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result of the addition will be stored.
    - `out2`: A pointer to a fiat_secp256k1_montgomery_uint1 where the carry-out of the addition will be stored.
    - `arg1`: A fiat_secp256k1_montgomery_uint1 representing the initial carry-in for the addition.
    - `arg2`: A uint64_t representing the first operand of the addition.
    - `arg3`: A uint64_t representing the second operand of the addition.
- **Control Flow**:
    - Declare a 128-bit unsigned integer `x1` to hold the intermediate sum of `arg1`, `arg2`, and `arg3`.
    - Calculate `x1` as the sum of `arg1`, `arg2`, and `arg3`.
    - Extract the lower 64 bits of `x1` into `x2` using a bitwise AND with `0xffffffffffffffff`.
    - Extract the upper bits of `x1` into `x3` by right-shifting `x1` by 64 bits.
    - Store `x2` in the location pointed to by `out1`.
    - Store `x3` in the location pointed to by `out2`.
- **Output**: The function outputs the 64-bit result of the addition in `out1` and the carry-out in `out2`.


---
### fiat\_secp256k1\_montgomery\_subborrowx\_u64<!-- {{#callable:fiat_secp256k1_montgomery_subborrowx_u64}} -->
The function `fiat_secp256k1_montgomery_subborrowx_u64` performs a subtraction of two 64-bit unsigned integers with a borrow, and outputs the result and the borrow flag.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result of the subtraction will be stored.
    - `out2`: A pointer to a fiat_secp256k1_montgomery_uint1 where the borrow flag will be stored.
    - `arg1`: A fiat_secp256k1_montgomery_uint1 representing the initial borrow.
    - `arg2`: A 64-bit unsigned integer, the minuend in the subtraction.
    - `arg3`: A 64-bit unsigned integer, the subtrahend in the subtraction.
- **Control Flow**:
    - Calculate the intermediate result `x1` by subtracting `arg1` and `arg3` from `arg2`, using 128-bit arithmetic to handle potential overflow.
    - Extract the borrow `x2` by right-shifting `x1` by 64 bits, which indicates if the subtraction resulted in a negative value.
    - Extract the lower 64 bits of `x1` as `x3`, which is the result of the subtraction modulo 2^64.
    - Store `x3` in the location pointed to by `out1`.
    - Store the negated borrow `x2` in the location pointed to by `out2`.
- **Output**: The function outputs the result of the subtraction in `out1` and the borrow flag in `out2`, indicating if the subtraction required borrowing.


---
### fiat\_secp256k1\_montgomery\_mulx\_u64<!-- {{#callable:fiat_secp256k1_montgomery_mulx_u64}} -->
The function `fiat_secp256k1_montgomery_mulx_u64` performs a 64-bit multiplication of two unsigned integers and returns the result as a double-width 128-bit integer, split into two 64-bit parts.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the lower 64 bits of the result will be stored.
    - `out2`: A pointer to a uint64_t where the upper 64 bits of the result will be stored.
    - `arg1`: A uint64_t representing the first operand of the multiplication.
    - `arg2`: A uint64_t representing the second operand of the multiplication.
- **Control Flow**:
    - Declare a 128-bit unsigned integer `x1` to store the full result of the multiplication of `arg1` and `arg2`.
    - Perform the multiplication of `arg1` and `arg2`, storing the result in `x1`.
    - Extract the lower 64 bits of `x1` and store them in `x2`.
    - Extract the upper 64 bits of `x1` and store them in `x3`.
    - Assign the value of `x2` to the location pointed to by `out1`.
    - Assign the value of `x3` to the location pointed to by `out2`.
- **Output**: The function outputs the result of the multiplication in two parts: `out1` receives the lower 64 bits, and `out2` receives the upper 64 bits of the 128-bit result.


---
### fiat\_secp256k1\_montgomery\_cmovznz\_u64<!-- {{#callable:fiat_secp256k1_montgomery_cmovznz_u64}} -->
The function `fiat_secp256k1_montgomery_cmovznz_u64` performs a conditional move operation on two 64-bit unsigned integers based on a single-bit condition.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: A single-bit unsigned integer (0 or 1) that acts as the condition for the move operation.
    - `arg2`: A 64-bit unsigned integer that will be selected if `arg1` is 0.
    - `arg3`: A 64-bit unsigned integer that will be selected if `arg1` is 1.
- **Control Flow**:
    - The function first negates `arg1` twice to ensure it is either 0 or 1, storing the result in `x1`.
    - It calculates `x2` as the bitwise AND of the negated `x1` and the maximum 64-bit unsigned integer value, effectively creating a mask based on `arg1`.
    - The function then uses this mask to select between `arg2` and `arg3` by performing bitwise operations: `x3` is computed as the bitwise OR of the masked `arg3` and the inverted mask applied to `arg2`.
    - Finally, the result `x3` is stored in the location pointed to by `out1`.
- **Output**: The function outputs the selected 64-bit unsigned integer, either `arg2` or `arg3`, based on the value of `arg1`, and stores it in the location pointed to by `out1`.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_value_barrier_u64`](#fiat_secp256k1_montgomery_value_barrier_u64)


---
### fiat\_secp256k1\_montgomery\_mul<!-- {{#callable:fiat_secp256k1_montgomery_mul}} -->
The function `fiat_secp256k1_montgomery_mul` performs multiplication of two field elements in the Montgomery domain for the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to a `fiat_secp256k1_montgomery_montgomery_domain_field_element` where the result of the multiplication will be stored.
    - `arg1`: A constant pointer to a `fiat_secp256k1_montgomery_montgomery_domain_field_element` representing the first operand in the Montgomery domain.
    - `arg2`: A constant pointer to a `fiat_secp256k1_montgomery_montgomery_domain_field_element` representing the second operand in the Montgomery domain.
- **Control Flow**:
    - Initialize local variables for intermediate calculations.
    - Perform multiplication of each element of `arg1` with each element of `arg2` using [`fiat_secp256k1_montgomery_mulx_u64`](#fiat_secp256k1_montgomery_mulx_u64) to get double-width results.
    - Accumulate the results using [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64) to handle carry propagation.
    - Reduce the result modulo the prime using Montgomery reduction, which involves multiplying by the constant `0xd838091dd2253531` and further reductions.
    - Use conditional moves [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64) to ensure the result is within the field bounds.
    - Store the final reduced result in `out1`.
- **Output**: The function outputs the result of the multiplication in the Montgomery domain, stored in `out1`, which is a 4-element array of 64-bit unsigned integers.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_mulx_u64`](#fiat_secp256k1_montgomery_mulx_u64)
    - [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_square<!-- {{#callable:fiat_secp256k1_montgomery_square}} -->
The function `fiat_secp256k1_montgomery_square` computes the square of a field element in the Montgomery domain for the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to a `fiat_secp256k1_montgomery_montgomery_domain_field_element` where the result will be stored.
    - `arg1`: A constant pointer to a `fiat_secp256k1_montgomery_montgomery_domain_field_element` representing the input field element to be squared.
- **Control Flow**:
    - Extracts the four 64-bit words from the input field element `arg1`.
    - Performs a series of multiplications and additions to compute the square of the input element, using the Montgomery multiplication technique.
    - Reduces the result modulo the prime `m = 2^256 - 2^32 - 977` using the Montgomery reduction method.
    - Handles carry propagation and conditional moves to ensure the result is within the field bounds.
    - Stores the final result in the output parameter `out1`.
- **Output**: The function does not return a value but stores the squared result in the `out1` parameter, which is a field element in the Montgomery domain.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_mulx_u64`](#fiat_secp256k1_montgomery_mulx_u64)
    - [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_add<!-- {{#callable:fiat_secp256k1_montgomery_add}} -->
The function `fiat_secp256k1_montgomery_add` performs addition of two field elements in the Montgomery domain and reduces the result modulo the prime of the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to a `fiat_secp256k1_montgomery_montgomery_domain_field_element` where the result will be stored.
    - `arg1`: A constant pointer to the first `fiat_secp256k1_montgomery_montgomery_domain_field_element` operand.
    - `arg2`: A constant pointer to the second `fiat_secp256k1_montgomery_montgomery_domain_field_element` operand.
- **Control Flow**:
    - Initialize temporary variables for intermediate results and carry flags.
    - Perform addition with carry for each of the four 64-bit limbs of the input field elements using [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64).
    - Subtract the prime modulus from the result using [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64) to ensure the result is within the field range.
    - Use conditional move [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64) to select the correct result based on whether the subtraction resulted in a borrow, ensuring the result is reduced modulo the prime.
    - Store the final result in the output parameter `out1`.
- **Output**: The function does not return a value but stores the result of the addition in the `out1` parameter, which is a field element in the Montgomery domain.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_sub<!-- {{#callable:fiat_secp256k1_montgomery_sub}} -->
The function `fiat_secp256k1_montgomery_sub` performs subtraction of two field elements in the Montgomery domain, ensuring the result is within the field's bounds.
- **Inputs**:
    - `out1`: A pointer to a `fiat_secp256k1_montgomery_montgomery_domain_field_element` where the result will be stored.
    - `arg1`: A constant pointer to the first `fiat_secp256k1_montgomery_montgomery_domain_field_element` operand.
    - `arg2`: A constant pointer to the second `fiat_secp256k1_montgomery_montgomery_domain_field_element` operand.
- **Control Flow**:
    - Initialize temporary variables for intermediate calculations.
    - Perform subtraction with borrow for each of the four 64-bit words of the input field elements using [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64).
    - Check if a borrow occurred after the last subtraction; if so, set a mask to the maximum 64-bit value, otherwise set it to zero.
    - Use the mask to conditionally add the modulus to the result if a borrow occurred, ensuring the result is non-negative and within the field's bounds.
    - Store the final result in the output field element `out1`.
- **Output**: The function outputs the result of the subtraction in the `out1` field element, which is a 4-element array of 64-bit unsigned integers representing the result in the Montgomery domain.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)
    - [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64)


---
### fiat\_secp256k1\_montgomery\_opp<!-- {{#callable:fiat_secp256k1_montgomery_opp}} -->
The function `fiat_secp256k1_montgomery_opp` computes the negation of a field element in the Montgomery domain for the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element to be negated.
- **Control Flow**:
    - Initialize temporary variables for intermediate calculations.
    - Perform a series of subtraction operations with borrow to compute the negation of the input field element `arg1`.
    - Use a conditional move operation to handle the case where the result of the subtraction is negative, adjusting the result to ensure it is within the field's bounds.
    - Perform addition with carry operations to finalize the negation result, ensuring it is within the field's bounds.
    - Store the final result in the output array `out1`.
- **Output**: The function outputs the negated field element in the Montgomery domain, stored in the array `out1`.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)
    - [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64)


---
### fiat\_secp256k1\_montgomery\_from\_montgomery<!-- {{#callable:fiat_secp256k1_montgomery_from_montgomery}} -->
The function `fiat_secp256k1_montgomery_from_montgomery` converts a field element from the Montgomery domain to the standard representation.
- **Inputs**:
    - `out1`: A pointer to an array of 4 uint64_t elements where the result will be stored, representing the field element in the non-Montgomery domain.
    - `arg1`: A constant pointer to an array of 4 uint64_t elements representing the field element in the Montgomery domain to be converted.
- **Control Flow**:
    - Initialize several uint64_t and fiat_secp256k1_montgomery_uint1 variables for intermediate calculations.
    - Extract the first element of the input array `arg1` and store it in `x1`.
    - Perform a series of multiplications and additions using the [`fiat_secp256k1_montgomery_mulx_u64`](#fiat_secp256k1_montgomery_mulx_u64) and [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64) functions to compute intermediate values.
    - Repeat the process for each element of `arg1`, updating the intermediate values accordingly.
    - Perform a subtraction using [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64) to ensure the result is within the field's modulus.
    - Use conditional moves [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64) to finalize the result based on the subtraction's borrow flag.
    - Store the final result in the `out1` array.
- **Output**: The function outputs a field element in the non-Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_mulx_u64`](#fiat_secp256k1_montgomery_mulx_u64)
    - [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_to\_montgomery<!-- {{#callable:fiat_secp256k1_montgomery_to_montgomery}} -->
The function `fiat_secp256k1_montgomery_to_montgomery` converts a field element from the non-Montgomery domain to the Montgomery domain for the secp256k1 curve.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored, representing a field element in the Montgomery domain.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing a field element in the non-Montgomery domain.
- **Control Flow**:
    - Extracts the four 64-bit words from the input array `arg1` into variables `x1`, `x2`, `x3`, and `x4`.
    - Performs a series of multiplications and additions using the [`fiat_secp256k1_montgomery_mulx_u64`](#fiat_secp256k1_montgomery_mulx_u64) and [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64) functions to compute intermediate results in the Montgomery domain.
    - Uses the constant `0x7a2000e90a1` for initial multiplication and `0xd838091dd2253531` for Montgomery reduction.
    - Accumulates results into variables `x5` through `x162` through a series of arithmetic operations, ensuring that the results are reduced modulo the prime `m = 2^256 - 2^32 - 977`.
    - Performs conditional subtraction using [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64) to ensure the result is within the field range.
    - Uses [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64) to conditionally select the final result based on the subtraction outcome.
    - Stores the final result in the output array `out1`.
- **Output**: The function outputs a field element in the Montgomery domain, stored in the array `out1`, which is equivalent to the input element `arg1` in the non-Montgomery domain.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_mulx_u64`](#fiat_secp256k1_montgomery_mulx_u64)
    - [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64)
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_nonzero<!-- {{#callable:fiat_secp256k1_montgomery_nonzero}} -->
The function `fiat_secp256k1_montgomery_nonzero` checks if a 256-bit number represented by four 64-bit words is non-zero and outputs a single non-zero word if it is, or zero otherwise.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: An array of four 64-bit unsigned integers representing a 256-bit number.
- **Control Flow**:
    - The function initializes a 64-bit unsigned integer `x1` to the bitwise OR of all elements in `arg1` array.
    - The result `x1` is assigned to the location pointed to by `out1`.
- **Output**: The function outputs a single 64-bit unsigned integer which is non-zero if any of the elements in `arg1` are non-zero, otherwise it outputs zero.


---
### fiat\_secp256k1\_montgomery\_selectznz<!-- {{#callable:fiat_secp256k1_montgomery_selectznz}} -->
The function `fiat_secp256k1_montgomery_selectznz` performs a conditional selection between two 4-element arrays based on a single-bit flag.
- **Inputs**:
    - `out1`: A 4-element array of uint64_t where the result of the selection will be stored.
    - `arg1`: A single-bit flag (fiat_secp256k1_montgomery_uint1) that determines which array to select.
    - `arg2`: A 4-element array of uint64_t representing the first option for selection.
    - `arg3`: A 4-element array of uint64_t representing the second option for selection.
- **Control Flow**:
    - The function initializes four uint64_t variables x1, x2, x3, and x4.
    - It calls [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64) four times, each time selecting between corresponding elements of `arg2` and `arg3` based on `arg1`.
    - The results of these selections are stored in x1, x2, x3, and x4 respectively.
    - The selected values are then assigned to the `out1` array.
- **Output**: The function outputs the selected 4-element array in `out1`, which is either `arg2` or `arg3` based on the value of `arg1`.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)


---
### fiat\_secp256k1\_montgomery\_to\_bytes<!-- {{#callable:fiat_secp256k1_montgomery_to_bytes}} -->
The function `fiat_secp256k1_montgomery_to_bytes` converts a 256-bit field element from a non-Montgomery domain representation into a 32-byte array in little-endian order.
- **Inputs**:
    - `out1`: A 32-byte array where the serialized output will be stored.
    - `arg1`: A 4-element array of 64-bit unsigned integers representing the field element to be serialized.
- **Control Flow**:
    - Extracts each 64-bit integer from the input array `arg1` and processes them individually.
    - For each 64-bit integer, it extracts each byte by masking and shifting operations to isolate each byte.
    - Stores each extracted byte into the corresponding position in the output array `out1`, ensuring the little-endian order.
- **Output**: The function outputs a 32-byte array `out1` containing the serialized representation of the input field element in little-endian order.


---
### fiat\_secp256k1\_montgomery\_from\_bytes<!-- {{#callable:fiat_secp256k1_montgomery_from_bytes}} -->
The function `fiat_secp256k1_montgomery_from_bytes` converts a 32-byte array into a 4-element array of 64-bit unsigned integers, representing a field element not in the Montgomery domain.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A pointer to an array of 32 bytes representing the input data in little-endian order.
- **Control Flow**:
    - Extracts each byte from the input array `arg1` and shifts them to their respective positions to form 64-bit integers.
    - Combines the shifted bytes to form four 64-bit integers, each representing a part of the field element.
    - Stores the resulting 64-bit integers into the output array `out1`.
- **Output**: The function outputs a 4-element array of 64-bit unsigned integers representing the deserialized field element.


---
### fiat\_secp256k1\_montgomery\_set\_one<!-- {{#callable:fiat_secp256k1_montgomery_set_one}} -->
The function `fiat_secp256k1_montgomery_set_one` initializes a field element in the Montgomery domain to represent the value one.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers, representing a field element in the Montgomery domain.
- **Control Flow**:
    - The function sets the first element of the array `out1` to the constant `0x1000003d1`, which is the Montgomery representation of one.
    - The remaining elements of the array `out1` are set to zero.
- **Output**: The function does not return a value but modifies the input array `out1` to represent the number one in the Montgomery domain.


---
### fiat\_secp256k1\_montgomery\_msat<!-- {{#callable:fiat_secp256k1_montgomery_msat}} -->
The function `fiat_secp256k1_montgomery_msat` initializes an array with the saturated representation of the prime modulus for the secp256k1 curve in the Montgomery domain.
- **Inputs**:
    - `out1`: A pointer to an array of 5 uint64_t elements where the saturated representation of the prime modulus will be stored.
- **Control Flow**:
    - The function assigns the first element of the array `out1` to the constant `0xfffffffefffffc2f`.
    - The function assigns the second, third, and fourth elements of the array `out1` to the constant `0xffffffffffffffff`.
    - The function assigns the fifth element of the array `out1` to `0x0`.
- **Output**: The function does not return a value; it modifies the array `out1` in place to contain the saturated representation of the prime modulus.


---
### fiat\_secp256k1\_montgomery\_divstep<!-- {{#callable:fiat_secp256k1_montgomery_divstep}} -->
The function `fiat_secp256k1_montgomery_divstep` performs a division step operation in the context of the secp256k1 elliptic curve using Montgomery arithmetic.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result of the division step operation will be stored.
    - `out2`: An array of 5 uint64_t elements where the updated value of arg2 or arg3 will be stored based on the condition.
    - `out3`: An array of 5 uint64_t elements where the updated value of arg3 or a modified version of arg2 will be stored based on the condition.
    - `out4`: An array of 4 uint64_t elements where the updated value of arg4 or arg5 will be stored based on the condition.
    - `out5`: An array of 4 uint64_t elements where the updated value of arg5 or a modified version of arg4 will be stored based on the condition.
    - `arg1`: A uint64_t representing a condition value used to determine the flow of the division step.
    - `arg2`: An array of 5 uint64_t elements representing one of the input values for the division step.
    - `arg3`: An array of 5 uint64_t elements representing another input value for the division step.
    - `arg4`: An array of 4 uint64_t elements representing one of the input values for the division step.
    - `arg5`: An array of 4 uint64_t elements representing another input value for the division step.
- **Control Flow**:
    - The function begins by computing a conditional negation of `arg1` and checks if `arg3[0]` is odd, storing the result in `x3`.
    - Based on `x3`, it conditionally selects between `arg1` and its negation, and between `arg2` and `arg3`, storing the results in `x6` to `x11`.
    - It computes the two's complement of `arg2` and conditionally selects between `arg3` and this complement based on `x3`, storing the results in `x22` to `x26`.
    - It conditionally selects between `arg4` and `arg5` based on `x3`, storing the results in `x27` to `x30`.
    - The function doubles the selected values from `arg4` or `arg5` and reduces them modulo the prime modulus, storing the results in `x31` to `x38`.
    - It computes the two's complement of `arg4` and conditionally selects between zero and the prime modulus based on the result, storing the results in `x62` to `x68`.
    - It conditionally selects between `arg5` and the computed values based on `x3`, storing the results in `x70` to `x73`.
    - It checks if `x22` is odd and conditionally adds the selected values from `arg2` or `arg3` to `x22` to `x26`, storing the results in `x80` to `x88`.
    - It conditionally adds the selected values from `arg4` or `arg5` to `x70` to `x73`, storing the results in `x94` to `x101`.
    - It reduces the results modulo the prime modulus, storing the results in `x102` to `x110`.
    - It computes the new value of `out1` as `x112`, and updates `out2` to `x7` to `x11`, `out3` to `x114` to `x118`, `out4` to `x119` to `x122`, and `out5` to `x123` to `x126`.
- **Output**: The function outputs the updated values of `out1`, `out2`, `out3`, `out4`, and `out5` based on the division step operation.
- **Functions called**:
    - [`fiat_secp256k1_montgomery_addcarryx_u64`](#fiat_secp256k1_montgomery_addcarryx_u64)
    - [`fiat_secp256k1_montgomery_cmovznz_u64`](#fiat_secp256k1_montgomery_cmovznz_u64)
    - [`fiat_secp256k1_montgomery_subborrowx_u64`](#fiat_secp256k1_montgomery_subborrowx_u64)


---
### fiat\_secp256k1\_montgomery\_divstep\_precomp<!-- {{#callable:fiat_secp256k1_montgomery_divstep_precomp}} -->
The function `fiat_secp256k1_montgomery_divstep_precomp` initializes a 4-element array with precomputed constants for the secp256k1 curve in Montgomery form.
- **Inputs**:
    - `out1`: A 4-element array of type `uint64_t` where the precomputed constants will be stored.
- **Control Flow**:
    - The function assigns the first element of `out1` to the constant `0xf201a41831525e0a`.
    - The function assigns the second element of `out1` to the constant `0x9953f9ddcd648d85`.
    - The function assigns the third element of `out1` to the constant `0xe86029463db210a9`.
    - The function assigns the fourth element of `out1` to the constant `0x24fb8a3104b03709`.
- **Output**: The function does not return a value; it modifies the input array `out1` in place.


