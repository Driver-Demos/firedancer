# Purpose
The provided C code is an implementation of arithmetic operations in the Montgomery domain for the 25519 scalar field, which is used in cryptographic applications such as elliptic curve cryptography. The code is auto-generated and includes a variety of functions that perform operations like multiplication, squaring, addition, subtraction, and conversion between Montgomery and non-Montgomery domains. These operations are crucial for efficient computation in cryptographic algorithms, particularly those involving elliptic curves.

The code defines several types and macros to facilitate these operations, including custom integer types for handling carry and borrow operations. It also includes functions for conditional moves and serialization/deserialization of field elements to and from byte arrays. The functions are designed to ensure that inputs and outputs remain within the bounds of the prime modulus, which is specified as \(2^{252} + 27742317777372353535851937790883648493\). This code is intended to be used as a library, providing a set of APIs for performing cryptographic computations on the 25519 scalar field, and is optimized for performance on systems using two's complement arithmetic.
# Imports and Dependencies

---
- `stdint.h`


# Global Variables

---
### fiat\_25519\_scalar\_int128
- **Type**: `signed __int128`
- **Description**: The `fiat_25519_scalar_int128` is a typedef for a signed 128-bit integer type, which is an extension provided by compilers like GCC or Clang. This type allows for operations on 128-bit signed integers, which are not natively supported by all C compilers.
- **Use**: This variable is used to perform arithmetic operations that require 128-bit signed integer precision, particularly in cryptographic computations involving the 25519 scalar field.


---
### fiat\_25519\_scalar\_uint128
- **Type**: `unsigned __int128`
- **Description**: The `fiat_25519_scalar_uint128` is a typedef for an unsigned 128-bit integer type. This type is used to represent large integers that require more than the standard 64-bit integer size, allowing for operations on numbers up to 2^128 - 1.
- **Use**: This variable is used in arithmetic operations that require handling of large numbers, such as those involved in cryptographic computations for the 25519 scalar field.


# Functions

---
### fiat\_25519\_scalar\_value\_barrier\_u64<!-- {{#callable:fiat_25519_scalar_value_barrier_u64}} -->
The function `fiat_25519_scalar_value_barrier_u64` acts as a compiler barrier for a 64-bit unsigned integer, ensuring that the value of the variable is not optimized away by the compiler.
- **Inputs**:
    - `a`: A 64-bit unsigned integer whose value is to be preserved across compiler optimizations.
- **Control Flow**:
    - The function uses an inline assembly statement to create a compiler barrier.
    - The assembly statement is empty but uses the input variable `a` as a read-write operand, preventing the compiler from optimizing away the variable.
    - The function then returns the value of `a`.
- **Output**: The function returns the same 64-bit unsigned integer `a` that was passed as input.


---
### fiat\_25519\_scalar\_addcarryx\_u64<!-- {{#callable:fiat_25519_scalar_addcarryx_u64}} -->
The function `fiat_25519_scalar_addcarryx_u64` performs addition of two 64-bit unsigned integers with an additional carry-in, producing a 64-bit result and a carry-out.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result of the addition will be stored.
    - `out2`: A pointer to a fiat_25519_scalar_uint1 where the carry-out of the addition will be stored.
    - `arg1`: A fiat_25519_scalar_uint1 representing the carry-in for the addition.
    - `arg2`: A 64-bit unsigned integer, one of the operands for the addition.
    - `arg3`: A 64-bit unsigned integer, the other operand for the addition.
- **Control Flow**:
    - The function begins by calculating the sum of `arg1`, `arg2`, and `arg3`, storing the result in a 128-bit unsigned integer `x1` to handle potential overflow.
    - The lower 64 bits of `x1` are extracted and stored in `x2`, which is then assigned to `*out1`.
    - The upper bits of `x1` (beyond 64 bits) are extracted and stored in `x3`, which is then assigned to `*out2`.
- **Output**: The function outputs the 64-bit result of the addition in `*out1` and the carry-out in `*out2`.


---
### fiat\_25519\_scalar\_subborrowx\_u64<!-- {{#callable:fiat_25519_scalar_subborrowx_u64}} -->
The function `fiat_25519_scalar_subborrowx_u64` performs a subtraction of two 64-bit unsigned integers with a borrow, and outputs the result and the borrow flag.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result of the subtraction will be stored.
    - `out2`: A pointer to a fiat_25519_scalar_uint1 where the borrow flag will be stored.
    - `arg1`: A fiat_25519_scalar_uint1 representing the initial borrow (0 or 1).
    - `arg2`: A 64-bit unsigned integer, the minuend in the subtraction.
    - `arg3`: A 64-bit unsigned integer, the subtrahend in the subtraction.
- **Control Flow**:
    - Calculate the intermediate result `x1` as `arg2 - arg1 - arg3` using 128-bit integer arithmetic to handle potential overflow.
    - Extract the borrow `x2` by right-shifting `x1` by 64 bits, which indicates if the subtraction resulted in a negative value.
    - Extract the lower 64 bits of `x1` as `x3`, which is the actual result of the subtraction modulo 2^64.
    - Store `x3` in `out1` as the result of the subtraction.
    - Store the negated borrow `x2` in `out2` to indicate if a borrow occurred.
- **Output**: The function outputs the result of the subtraction in `out1` and the borrow flag in `out2`, indicating if the subtraction required a borrow.


---
### fiat\_25519\_scalar\_mulx\_u64<!-- {{#callable:fiat_25519_scalar_mulx_u64}} -->
The function `fiat_25519_scalar_mulx_u64` performs a 64-bit multiplication of two unsigned integers and returns the result as a double-width 128-bit integer, split into two 64-bit parts.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the lower 64 bits of the result will be stored.
    - `out2`: A pointer to a uint64_t where the upper 64 bits of the result will be stored.
    - `arg1`: A uint64_t representing the first operand of the multiplication.
    - `arg2`: A uint64_t representing the second operand of the multiplication.
- **Control Flow**:
    - Declare a 128-bit unsigned integer `x1` to hold the full result of the multiplication of `arg1` and `arg2`.
    - Perform the multiplication of `arg1` and `arg2`, storing the result in `x1`.
    - Extract the lower 64 bits of `x1` and store them in `x2`.
    - Extract the upper 64 bits of `x1` and store them in `x3`.
    - Assign the value of `x2` to the location pointed to by `out1`.
    - Assign the value of `x3` to the location pointed to by `out2`.
- **Output**: The function outputs the result of the multiplication in two parts: `out1` receives the lower 64 bits, and `out2` receives the upper 64 bits of the 128-bit result.


---
### fiat\_25519\_scalar\_cmovznz\_u64<!-- {{#callable:fiat_25519_scalar_cmovznz_u64}} -->
The function `fiat_25519_scalar_cmovznz_u64` performs a conditional move operation on two 64-bit unsigned integers based on a single-bit condition.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: A single-bit unsigned integer (fiat_25519_scalar_uint1) that acts as the condition for the move operation.
    - `arg2`: A 64-bit unsigned integer that is selected if the condition is false (arg1 is 0).
    - `arg3`: A 64-bit unsigned integer that is selected if the condition is true (arg1 is 1).
- **Control Flow**:
    - The function first negates the condition `arg1` twice to ensure it is either 0 or 1, storing the result in `x1`.
    - It calculates `x2` as the bitwise AND of the negated condition and the maximum 64-bit unsigned integer value, effectively creating a mask.
    - The function then uses this mask to select between `arg2` and `arg3` using bitwise operations, storing the result in `x3`.
    - Finally, the result `x3` is stored in the location pointed to by `out1`.
- **Output**: The function outputs the selected 64-bit unsigned integer based on the condition, storing it in the location pointed to by `out1`.
- **Functions called**:
    - [`fiat_25519_scalar_value_barrier_u64`](#fiat_25519_scalar_value_barrier_u64)


---
### fiat\_25519\_scalar\_mul<!-- {{#callable:fiat_25519_scalar_mul}} -->
The function `fiat_25519_scalar_mul` performs multiplication of two field elements in the Montgomery domain and reduces the result modulo the prime modulus specific to the 25519 scalar field.
- **Inputs**:
    - `out1`: A pointer to a `fiat_25519_scalar_montgomery_domain_field_element` array where the result of the multiplication will be stored.
    - `arg1`: A constant pointer to a `fiat_25519_scalar_montgomery_domain_field_element` array representing the first operand in the Montgomery domain.
    - `arg2`: A constant pointer to a `fiat_25519_scalar_montgomery_domain_field_element` array representing the second operand in the Montgomery domain.
- **Control Flow**:
    - Initialize local variables to store intermediate results and carry bits.
    - Perform multiplication of each element of `arg1` with each element of `arg2`, storing results in temporary variables.
    - Use [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64) to perform 64-bit multiplications and [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64) to handle carry propagation during addition.
    - Reduce the intermediate results using the Montgomery reduction technique, involving multiplication with a constant and modular arithmetic.
    - Use [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64) to ensure the result is within the field by subtracting the modulus if necessary.
    - Store the final reduced result in the `out1` array.
- **Output**: The function outputs the result of the multiplication in the `out1` array, which is a field element in the Montgomery domain.
- **Functions called**:
    - [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64)
    - [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64)
    - [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64)
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)


---
### fiat\_25519\_scalar\_square<!-- {{#callable:fiat_25519_scalar_square}} -->
The function `fiat_25519_scalar_square` computes the square of a field element in the Montgomery domain, ensuring the result is within the bounds of the prime modulus.
- **Inputs**:
    - `out1`: A pointer to a `fiat_25519_scalar_montgomery_domain_field_element` array where the result will be stored.
    - `arg1`: A constant pointer to a `fiat_25519_scalar_montgomery_domain_field_element` array representing the input field element to be squared.
- **Control Flow**:
    - Initialize local variables for intermediate calculations.
    - Extract individual components of the input field element `arg1`.
    - Perform a series of multiplications using [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64) to compute partial products of the input element with itself.
    - Use [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64) to accumulate the results of the multiplications, handling carry bits appropriately.
    - Multiply the intermediate result by a constant using [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64) to adjust for the Montgomery domain.
    - Perform additional additions with carry to finalize the intermediate result.
    - Subtract the prime modulus using [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64) to ensure the result is within bounds.
    - Use [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64) to conditionally select the final result based on the subtraction outcome.
    - Store the final result in the `out1` array.
- **Output**: The function outputs the squared field element in the Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64)
    - [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64)
    - [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64)
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)


---
### fiat\_25519\_scalar\_add<!-- {{#callable:fiat_25519_scalar_add}} -->
The function `fiat_25519_scalar_add` adds two field elements in the Montgomery domain and reduces the result modulo the prime modulus.
- **Inputs**:
    - `out1`: A pointer to a `fiat_25519_scalar_montgomery_domain_field_element` array where the result will be stored.
    - `arg1`: A constant pointer to a `fiat_25519_scalar_montgomery_domain_field_element` array representing the first operand.
    - `arg2`: A constant pointer to a `fiat_25519_scalar_montgomery_domain_field_element` array representing the second operand.
- **Control Flow**:
    - Initialize temporary variables for intermediate results and carry flags.
    - Perform addition with carry for each corresponding element of `arg1` and `arg2`, storing results in temporary variables.
    - Subtract the prime modulus from the result using subtraction with borrow to ensure the result is within the field range.
    - Use conditional move operations to select the correct result based on the borrow flag, ensuring the result is reduced modulo the prime modulus.
    - Store the final result in the `out1` array.
- **Output**: The function outputs the sum of `arg1` and `arg2` in the Montgomery domain, reduced modulo the prime modulus, stored in `out1`.
- **Functions called**:
    - [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64)
    - [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64)
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)


---
### fiat\_25519\_scalar\_sub<!-- {{#callable:fiat_25519_scalar_sub}} -->
The function `fiat_25519_scalar_sub` subtracts two field elements in the Montgomery domain and ensures the result is within the valid range by conditionally adding the modulus if necessary.
- **Inputs**:
    - `out1`: A pointer to a fiat_25519_scalar_montgomery_domain_field_element where the result will be stored.
    - `arg1`: A constant pointer to a fiat_25519_scalar_montgomery_domain_field_element representing the minuend.
    - `arg2`: A constant pointer to a fiat_25519_scalar_montgomery_domain_field_element representing the subtrahend.
- **Control Flow**:
    - Initialize temporary variables for intermediate results and carry flags.
    - Perform subtraction with borrow for each 64-bit segment of the input arrays arg1 and arg2 using fiat_25519_scalar_subborrowx_u64.
    - Check if the final borrow flag indicates a negative result, and if so, set a mask to the modulus value.
    - Use fiat_25519_scalar_cmovznz_u64 to conditionally select between zero and the modulus based on the borrow flag.
    - Add the selected value to the intermediate subtraction results using fiat_25519_scalar_addcarryx_u64 to ensure the result is non-negative and within the modulus range.
    - Store the final result in the output array out1.
- **Output**: The function outputs the result of the subtraction in the Montgomery domain, stored in the array pointed to by out1.
- **Functions called**:
    - [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64)
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)
    - [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64)


---
### fiat\_25519\_scalar\_opp<!-- {{#callable:fiat_25519_scalar_opp}} -->
The function `fiat_25519_scalar_opp` computes the negation of a field element in the Montgomery domain, ensuring the result is within the field's modulus.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element to be negated.
- **Control Flow**:
    - Initialize temporary variables for intermediate calculations.
    - Perform a series of subtraction operations with borrow to compute the negation of each element in the input array `arg1`.
    - Use conditional move operations to handle potential underflow by selecting between zero and the maximum 64-bit unsigned integer.
    - Add the modulus to the result if underflow occurred, ensuring the result is within the field's modulus.
    - Store the computed negated values in the output array `out1`.
- **Output**: The function outputs the negated field element in the Montgomery domain, stored in the array `out1`.
- **Functions called**:
    - [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64)
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)
    - [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64)


---
### fiat\_25519\_scalar\_from\_montgomery<!-- {{#callable:fiat_25519_scalar_from_montgomery}} -->
The function `fiat_25519_scalar_from_montgomery` converts a field element from the Montgomery domain to the standard representation.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored, representing the field element in the non-Montgomery domain.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element in the Montgomery domain.
- **Control Flow**:
    - Initialize several 64-bit unsigned integers and fiat_25519_scalar_uint1 variables for intermediate calculations.
    - Extract the first element of the input array `arg1` and perform a series of multiplications and additions to compute intermediate values.
    - Use the [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64) function to perform multiplications and [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64) to handle additions with carry.
    - Iterate over the elements of `arg1`, performing similar operations to accumulate results into intermediate variables.
    - Perform a series of subtractions using [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64) to reduce the result modulo the prime modulus.
    - Use conditional moves [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64) to ensure the result is within the correct range.
    - Store the final result in the `out1` array.
- **Output**: The function outputs a field element in the non-Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64)
    - [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64)
    - [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64)
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)


---
### fiat\_25519\_scalar\_to\_montgomery<!-- {{#callable:fiat_25519_scalar_to_montgomery}} -->
The function `fiat_25519_scalar_to_montgomery` converts a field element from the non-Montgomery domain to the Montgomery domain for the 25519 scalar field.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored, representing the field element in the Montgomery domain.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element in the non-Montgomery domain.
- **Control Flow**:
    - Extracts the four 64-bit words from the input array `arg1` into local variables `x1`, `x2`, `x3`, and `x4`.
    - Performs a series of multiplications and additions using the extracted words and specific constants to compute intermediate results, storing them in variables `x5` to `x171`.
    - Uses the [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64) function to perform 64-bit multiplications and [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64) to handle additions with carry.
    - Applies a reduction step using the modulus of the 25519 scalar field to ensure the result is within the field's bounds, using [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64) for subtraction with borrow.
    - Uses conditional moves ([`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)) to select between the reduced and non-reduced results based on the borrow flag.
    - Stores the final result in the output array `out1`.
- **Output**: The function outputs the Montgomery domain representation of the input field element in the array `out1`.
- **Functions called**:
    - [`fiat_25519_scalar_mulx_u64`](#fiat_25519_scalar_mulx_u64)
    - [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64)
    - [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64)
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)


---
### fiat\_25519\_scalar\_nonzero<!-- {{#callable:fiat_25519_scalar_nonzero}} -->
The function `fiat_25519_scalar_nonzero` computes a single non-zero word if the input array is non-zero, and zero otherwise.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result will be stored.
    - `arg1`: An array of four uint64_t values representing the input to be checked for non-zero status.
- **Control Flow**:
    - The function initializes a local variable `x1` to the bitwise OR of all elements in the input array `arg1`.
    - It assigns the value of `x1` to the location pointed to by `out1`.
- **Output**: The function outputs a single uint64_t value through the pointer `out1`, which is non-zero if any element of `arg1` is non-zero, and zero otherwise.


---
### fiat\_25519\_scalar\_selectznz<!-- {{#callable:fiat_25519_scalar_selectznz}} -->
The function `fiat_25519_scalar_selectznz` performs a conditional selection between two 4-element arrays based on a single-bit condition.
- **Inputs**:
    - `out1`: A 4-element array of uint64_t where the result of the selection will be stored.
    - `arg1`: A single-bit condition (fiat_25519_scalar_uint1) that determines which array to select.
    - `arg2`: A 4-element array of uint64_t representing the first option for selection.
    - `arg3`: A 4-element array of uint64_t representing the second option for selection.
- **Control Flow**:
    - The function initializes four local variables x1, x2, x3, and x4 to store the selected elements.
    - It calls [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64) for each element of the arrays, passing the condition `arg1` and the corresponding elements from `arg2` and `arg3`.
    - Each call to [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64) selects an element from `arg2` if `arg1` is 0, or from `arg3` if `arg1` is 1, and stores the result in the corresponding local variable.
    - The selected elements are then assigned to the output array `out1`.
- **Output**: The function outputs the selected 4-element array in `out1`, which contains elements from either `arg2` or `arg3` based on the value of `arg1`.
- **Functions called**:
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)


---
### fiat\_25519\_scalar\_to\_bytes<!-- {{#callable:fiat_25519_scalar_to_bytes}} -->
The function `fiat_25519_scalar_to_bytes` serializes a 25519 scalar field element from a 4-element array of 64-bit unsigned integers into a 32-byte array in little-endian order.
- **Inputs**:
    - `out1`: A 32-byte array where the serialized bytes of the scalar will be stored.
    - `arg1`: A 4-element array of 64-bit unsigned integers representing the scalar field element to be serialized.
- **Control Flow**:
    - Extracts each 64-bit integer from the input array `arg1` and processes it individually.
    - For each 64-bit integer, extracts 8 bytes by repeatedly masking with 0xff and right-shifting by 8 bits.
    - Stores each extracted byte into the corresponding position in the output array `out1`.
- **Output**: A 32-byte array `out1` containing the serialized bytes of the input scalar in little-endian order.


---
### fiat\_25519\_scalar\_from\_bytes<!-- {{#callable:fiat_25519_scalar_from_bytes}} -->
The function `fiat_25519_scalar_from_bytes` converts a 32-byte array into a 4-element array of 64-bit unsigned integers, representing a scalar in the non-Montgomery domain.
- **Inputs**:
    - `out1`: A 4-element array of 64-bit unsigned integers where the result will be stored.
    - `arg1`: A 32-element array of 8-bit unsigned integers representing the input bytes in little-endian order.
- **Control Flow**:
    - Initialize multiple 64-bit unsigned integers to store intermediate results.
    - Extract and shift each byte from the input array `arg1` to form 64-bit integers, combining them to form four 64-bit integers.
    - Store the resulting 64-bit integers into the `out1` array.
- **Output**: The function outputs a 4-element array of 64-bit unsigned integers representing the scalar value derived from the input bytes.


---
### fiat\_25519\_scalar\_set\_one<!-- {{#callable:fiat_25519_scalar_set_one}} -->
The function `fiat_25519_scalar_set_one` initializes a field element in the Montgomery domain to represent the value one.
- **Inputs**:
    - `out1`: A pointer to a `fiat_25519_scalar_montgomery_domain_field_element`, which is an array of four 64-bit unsigned integers, where the result will be stored.
- **Control Flow**:
    - The function assigns the first element of `out1` to the constant `0xd6ec31748d98951d`.
    - The function assigns the second element of `out1` to the constant `0xc6ef5bf4737dcf70`.
    - The function assigns the third element of `out1` to the constant `0xfffffffffffffffe`.
    - The function assigns the fourth element of `out1` to the constant `0xfffffffffffffff`.
- **Output**: The function does not return a value; it modifies the `out1` array in place to represent the number one in the Montgomery domain.


---
### fiat\_25519\_scalar\_msat<!-- {{#callable:fiat_25519_scalar_msat}} -->
The function `fiat_25519_scalar_msat` initializes an array with the saturated representation of the prime modulus used in the 25519 scalar field arithmetic.
- **Inputs**:
    - `out1`: A pointer to an array of 5 uint64_t elements where the saturated representation of the prime modulus will be stored.
- **Control Flow**:
    - The function assigns the first element of the array `out1` to the constant `0x5812631a5cf5d3ed`.
    - The second element of the array `out1` is assigned the constant `0x14def9dea2f79cd6`.
    - The third element of the array `out1` is set to `0x0`.
    - The fourth element of the array `out1` is assigned the constant `0x1000000000000000`.
    - The fifth element of the array `out1` is set to `0x0`.
- **Output**: The function does not return a value; it modifies the array `out1` in place to contain the saturated representation of the prime modulus.


---
### fiat\_25519\_scalar\_divstep<!-- {{#callable:fiat_25519_scalar_divstep}} -->
The function `fiat_25519_scalar_divstep` performs a division step operation in the context of the Fiat-Crypto library, specifically for the 25519 scalar field, adjusting the inputs based on certain conditions and producing multiple outputs.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result of the division step operation will be stored.
    - `out2`: An array of 5 uint64_t elements where the adjusted value of arg2 or arg3 will be stored based on the condition.
    - `out3`: An array of 5 uint64_t elements where the adjusted value of arg3 or a modified version will be stored based on the condition.
    - `out4`: An array of 4 uint64_t elements where the adjusted value of arg4 or arg5 will be stored based on the condition.
    - `out5`: An array of 4 uint64_t elements where the adjusted value of arg5 or a modified version will be stored based on the condition.
    - `arg1`: A uint64_t input that is used to determine the condition for the operation.
    - `arg2`: A constant array of 5 uint64_t elements representing one of the inputs to be conditionally adjusted.
    - `arg3`: A constant array of 5 uint64_t elements representing another input to be conditionally adjusted.
    - `arg4`: A constant array of 4 uint64_t elements representing one of the inputs to be conditionally adjusted.
    - `arg5`: A constant array of 4 uint64_t elements representing another input to be conditionally adjusted.
- **Control Flow**:
    - Compute the negation of arg1 and determine a condition based on the least significant bit of arg3[0].
    - Use conditional moves to select between arg1 and its negation, and between arg2 and arg3, based on the computed condition.
    - Compute the negation of arg2 and use conditional moves to select between arg3 and the negated arg2, based on the condition.
    - Use conditional moves to select between arg4 and arg5, based on the condition.
    - Double the selected values from arg4 or arg5 and reduce them modulo a constant, storing the result in temporary variables.
    - Compute the negation of the selected values from arg4 and reduce them modulo a constant, storing the result in temporary variables.
    - Use conditional moves to select between the original and modified values of arg5, based on the condition.
    - Adjust the selected values from arg2 or arg3 by adding a carry from the least significant bit of the selected value from arg3.
    - Use conditional moves to select between the original and modified values of arg4, based on the condition.
    - Store the final results in the output parameters out1, out2, out3, out4, and out5.
- **Output**: The function outputs the results of the division step operation in the provided output parameters: out1, out2, out3, out4, and out5, which are modified in place.
- **Functions called**:
    - [`fiat_25519_scalar_addcarryx_u64`](#fiat_25519_scalar_addcarryx_u64)
    - [`fiat_25519_scalar_cmovznz_u64`](#fiat_25519_scalar_cmovznz_u64)
    - [`fiat_25519_scalar_subborrowx_u64`](#fiat_25519_scalar_subborrowx_u64)


---
### fiat\_25519\_scalar\_divstep\_precomp<!-- {{#callable:fiat_25519_scalar_divstep_precomp}} -->
The function `fiat_25519_scalar_divstep_precomp` initializes a 4-element array with precomputed constants for the Bernstein-Yang inversion in Montgomery form.
- **Inputs**:
    - `out1`: A 4-element array of type uint64_t where the precomputed constants will be stored.
- **Control Flow**:
    - The function assigns the first element of the array `out1` to the constant `0xd70af84436a7cb92`.
    - The function assigns the second element of the array `out1` to the constant `0x5f71c978b0b8b159`.
    - The function assigns the third element of the array `out1` to the constant `0xe76d816974947f1a`.
    - The function assigns the fourth element of the array `out1` to the constant `0x19a2d36f193e4ff`.
- **Output**: The function does not return a value; it modifies the input array `out1` in place.


