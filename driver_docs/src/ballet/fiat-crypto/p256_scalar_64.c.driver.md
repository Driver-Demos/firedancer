# Purpose
The provided C code is an implementation of arithmetic operations in the Montgomery domain for the P-256 scalar field, which is a part of the elliptic curve cryptography (ECC) used in cryptographic protocols. This code is specifically designed to handle operations on the scalar field defined by the prime modulus \( m = 2^{256} - 2^{224} + 2^{192} - 89188191075325690597107910205041859247 \). The file includes functions for basic arithmetic operations such as addition, subtraction, multiplication, and squaring, as well as conversions to and from the Montgomery domain. Additionally, it provides functions for conditional moves, serialization to and from bytes, and a divstep function used in modular inversion algorithms.

The code is structured to be used as a library, with functions defined as static and inline for performance optimization. It includes type definitions for handling 128-bit integers, which are necessary for intermediate calculations that exceed the standard 64-bit integer size. The functions are designed to ensure that inputs and outputs remain within the bounds of the prime modulus, maintaining the properties required for cryptographic security. The file also includes precomputed values and functions for specific operations like `divstep` and `divstep_precomp`, which are used in advanced algorithms such as the Bernstein-Yang inversion method. This implementation is intended to be integrated into larger cryptographic systems where efficient and secure scalar field arithmetic is required.
# Imports and Dependencies

---
- `stdint.h`


# Global Variables

---
### fiat\_p256\_scalar\_int128
- **Type**: `signed __int128`
- **Description**: The `fiat_p256_scalar_int128` is a typedef for a signed 128-bit integer type, which is an extension provided by compilers like GCC or Clang. This type allows for operations on 128-bit signed integers, which are larger than the standard 64-bit integer types.
- **Use**: This variable is used to perform arithmetic operations that require 128-bit signed integer precision, particularly in cryptographic computations involving the P-256 scalar field.


---
### fiat\_p256\_scalar\_uint128
- **Type**: `unsigned __int128`
- **Description**: The `fiat_p256_scalar_uint128` is a typedef for an unsigned 128-bit integer type. This type is used to represent large integers that require more than the standard 64-bit integer size, allowing for operations on very large numbers.
- **Use**: This variable is used in cryptographic computations, particularly in the context of the P-256 scalar field arithmetic, where large integer operations are necessary.


# Functions

---
### fiat\_p256\_scalar\_value\_barrier\_u64<!-- {{#callable:fiat_p256_scalar_value_barrier_u64}} -->
The function `fiat_p256_scalar_value_barrier_u64` acts as a compiler barrier for a 64-bit unsigned integer, ensuring that the value of the variable is not optimized away by the compiler.
- **Inputs**:
    - `a`: A 64-bit unsigned integer whose value is to be preserved across compiler optimizations.
- **Control Flow**:
    - The function uses inline assembly to create a compiler barrier.
    - The assembly code is an empty string, which effectively does nothing but serves as a barrier.
    - The input variable 'a' is marked as a read-write operand, ensuring the compiler treats it as used.
    - The function returns the input value 'a'.
- **Output**: The function returns the same 64-bit unsigned integer that was passed as input, ensuring its value is preserved across compiler optimizations.


---
### fiat\_p256\_scalar\_addcarryx\_u64<!-- {{#callable:fiat_p256_scalar_addcarryx_u64}} -->
The function `fiat_p256_scalar_addcarryx_u64` performs a 64-bit addition with carry, returning the sum modulo 2^64 and the carry bit.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result of the addition modulo 2^64 will be stored.
    - `out2`: A pointer to a fiat_p256_scalar_uint1 where the carry bit resulting from the addition will be stored.
    - `arg1`: A fiat_p256_scalar_uint1 representing the initial carry-in value, which can be either 0 or 1.
    - `arg2`: A uint64_t representing the first operand of the addition.
    - `arg3`: A uint64_t representing the second operand of the addition.
- **Control Flow**:
    - The function begins by calculating the sum of `arg1`, `arg2`, and `arg3`, storing the result in a 128-bit unsigned integer `x1` to accommodate potential overflow.
    - The lower 64 bits of `x1` are extracted and stored in `x2`, which is then assigned to `*out1` as the result modulo 2^64.
    - The upper bits of `x1` (beyond 64 bits) are extracted and stored in `x3`, which is then assigned to `*out2` as the carry bit.
- **Output**: The function outputs the sum of `arg1`, `arg2`, and `arg3` modulo 2^64 in `*out1` and the carry bit in `*out2`.


---
### fiat\_p256\_scalar\_subborrowx\_u64<!-- {{#callable:fiat_p256_scalar_subborrowx_u64}} -->
The function `fiat_p256_scalar_subborrowx_u64` performs a subtraction of two 64-bit unsigned integers with an additional borrow input, and outputs the result along with a borrow flag.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result of the subtraction will be stored.
    - `out2`: A pointer to a fiat_p256_scalar_uint1 where the borrow flag will be stored.
    - `arg1`: A fiat_p256_scalar_uint1 representing the initial borrow input, which can be either 0 or 1.
    - `arg2`: A 64-bit unsigned integer representing the minuend.
    - `arg3`: A 64-bit unsigned integer representing the subtrahend.
- **Control Flow**:
    - Calculate the intermediate result `x1` by subtracting `arg1` and `arg3` from `arg2`, using 128-bit arithmetic to handle potential overflow.
    - Determine the borrow flag `x2` by right-shifting `x1` by 64 bits, which indicates if the subtraction resulted in a negative value.
    - Extract the lower 64 bits of `x1` to get the result of the subtraction, and store it in `x3`.
    - Store `x3` in the location pointed to by `out1`.
    - Store the negated borrow flag `x2` in the location pointed to by `out2`.
- **Output**: The function outputs the result of the subtraction in `out1` and a borrow flag in `out2`, indicating whether a borrow was needed.


---
### fiat\_p256\_scalar\_mulx\_u64<!-- {{#callable:fiat_p256_scalar_mulx_u64}} -->
The function `fiat_p256_scalar_mulx_u64` performs a 64-bit multiplication of two unsigned integers and returns the result as a 128-bit value split into two 64-bit parts.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the lower 64 bits of the multiplication result will be stored.
    - `out2`: A pointer to a uint64_t where the upper 64 bits of the multiplication result will be stored.
    - `arg1`: A uint64_t representing the first operand of the multiplication.
    - `arg2`: A uint64_t representing the second operand of the multiplication.
- **Control Flow**:
    - The function begins by declaring three variables: x1, x2, and x3.
    - It calculates the 128-bit product of arg1 and arg2, storing the result in x1.
    - The lower 64 bits of x1 are extracted and stored in x2.
    - The upper 64 bits of x1 are extracted and stored in x3.
    - The values of x2 and x3 are then assigned to the memory locations pointed to by out1 and out2, respectively.
- **Output**: The function outputs the lower 64 bits of the product in *out1 and the upper 64 bits in *out2.


---
### fiat\_p256\_scalar\_cmovznz\_u64<!-- {{#callable:fiat_p256_scalar_cmovznz_u64}} -->
The function `fiat_p256_scalar_cmovznz_u64` performs a conditional move operation on two 64-bit unsigned integers based on a single-bit condition.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: A single-bit unsigned integer (fiat_p256_scalar_uint1) that acts as the condition for the move operation.
    - `arg2`: A 64-bit unsigned integer that is selected if the condition (arg1) is zero.
    - `arg3`: A 64-bit unsigned integer that is selected if the condition (arg1) is non-zero.
- **Control Flow**:
    - The function first negates the condition `arg1` twice to ensure it is either 0 or 1, storing the result in `x1`.
    - It calculates `x2` as the bitwise AND of the negated `x1` with the maximum 64-bit unsigned integer value, effectively creating a mask based on `arg1`.
    - The function uses [`fiat_p256_scalar_value_barrier_u64`](#fiat_p256_scalar_value_barrier_u64) to apply a value barrier to `x2` and its bitwise NOT, ensuring no unintended optimizations affect the conditional logic.
    - It computes `x3` by combining `arg3` and `arg2` using bitwise operations with the masked values, effectively selecting between `arg2` and `arg3` based on `arg1`.
    - Finally, the result `x3` is stored in the location pointed to by `out1`.
- **Output**: The function outputs the selected 64-bit unsigned integer, either `arg2` or `arg3`, based on the condition `arg1`, and stores it in the location pointed to by `out1`.
- **Functions called**:
    - [`fiat_p256_scalar_value_barrier_u64`](#fiat_p256_scalar_value_barrier_u64)


---
### fiat\_p256\_scalar\_mul<!-- {{#callable:fiat_p256_scalar_mul}} -->
The function `fiat_p256_scalar_mul` performs multiplication of two field elements in the Montgomery domain and reduces the result modulo the prime modulus of the P-256 scalar field.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the first operand in the Montgomery domain.
    - `arg2`: A constant pointer to an array of four 64-bit unsigned integers representing the second operand in the Montgomery domain.
- **Control Flow**:
    - Initialize local variables for intermediate calculations and carry flags.
    - Perform a series of multiplications and additions to compute the product of `arg1` and `arg2`, storing intermediate results in local variables.
    - Use the Montgomery reduction technique to reduce the intermediate product modulo the prime modulus of the P-256 scalar field.
    - Perform conditional moves to ensure the result is less than the modulus, handling potential overflow.
    - Store the final reduced result in the `out1` array.
- **Output**: The function outputs the result of the multiplication in the Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_p256_scalar_mulx_u64`](#fiat_p256_scalar_mulx_u64)
    - [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64)
    - [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64)
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)


---
### fiat\_p256\_scalar\_square<!-- {{#callable:fiat_p256_scalar_square}} -->
The function `fiat_p256_scalar_square` computes the square of a field element in the Montgomery domain for the P-256 scalar field.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the input field element in the Montgomery domain.
- **Control Flow**:
    - Initialize local variables to store intermediate results and carry bits.
    - Extract the four 64-bit words from the input array `arg1`.
    - Perform a series of multiplications using [`fiat_p256_scalar_mulx_u64`](#fiat_p256_scalar_mulx_u64) to compute the product of each word of `arg1` with every other word, including itself, to form the square.
    - Use [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64) to add the results of the multiplications, handling carry bits appropriately.
    - Multiply the result by a constant using [`fiat_p256_scalar_mulx_u64`](#fiat_p256_scalar_mulx_u64) to adjust for the Montgomery domain.
    - Perform additional additions with carry to accumulate the results into a final value.
    - Use [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64) to reduce the result modulo the prime of the P-256 scalar field.
    - Use [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64) to conditionally select the reduced result based on the borrow flag.
    - Store the final result in the output array `out1`.
- **Output**: The function outputs the squared field element in the Montgomery domain, stored in the array `out1`.
- **Functions called**:
    - [`fiat_p256_scalar_mulx_u64`](#fiat_p256_scalar_mulx_u64)
    - [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64)
    - [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64)
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)


---
### fiat\_p256\_scalar\_add<!-- {{#callable:fiat_p256_scalar_add}} -->
The function `fiat_p256_scalar_add` adds two field elements in the Montgomery domain and reduces the result modulo the prime modulus.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the first operand in the Montgomery domain.
    - `arg2`: A constant pointer to an array of four 64-bit unsigned integers representing the second operand in the Montgomery domain.
- **Control Flow**:
    - Initialize temporary variables for intermediate results and carry flags.
    - Perform addition with carry for each corresponding pair of elements from `arg1` and `arg2`, storing results in temporary variables.
    - Perform subtraction with borrow to reduce the result modulo the prime modulus, using constants specific to the P-256 curve.
    - Use conditional move operations to select the correct result based on the borrow flag, ensuring the result is reduced modulo the prime.
    - Store the final result in the `out1` array.
- **Output**: The function outputs the result of the addition, reduced modulo the prime, in the `out1` array.
- **Functions called**:
    - [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64)
    - [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64)
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)


---
### fiat\_p256\_scalar\_sub<!-- {{#callable:fiat_p256_scalar_sub}} -->
The function `fiat_p256_scalar_sub` subtracts two field elements in the Montgomery domain and ensures the result is within the field's bounds by conditionally adding the modulus if necessary.
- **Inputs**:
    - `out1`: A pointer to a `fiat_p256_scalar_montgomery_domain_field_element` array where the result will be stored.
    - `arg1`: A constant pointer to a `fiat_p256_scalar_montgomery_domain_field_element` array representing the minuend.
    - `arg2`: A constant pointer to a `fiat_p256_scalar_montgomery_domain_field_element` array representing the subtrahend.
- **Control Flow**:
    - Initialize temporary variables for intermediate results and carry/borrow flags.
    - Perform subtraction of corresponding elements from `arg1` and `arg2` using [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64), propagating borrow as needed.
    - Use [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64) to determine if the result is negative, setting a mask to either zero or the modulus value.
    - Conditionally add the modulus to the result using [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64) to ensure the result is non-negative and within the field's bounds.
    - Store the final result in `out1`.
- **Output**: The function outputs the result of the subtraction in the `out1` array, which is a field element in the Montgomery domain.
- **Functions called**:
    - [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64)
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)
    - [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64)


---
### fiat\_p256\_scalar\_opp<!-- {{#callable:fiat_p256_scalar_opp}} -->
The function `fiat_p256_scalar_opp` computes the negation of a field element in the Montgomery domain, ensuring the result is within the bounds of the prime modulus.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element to be negated.
- **Control Flow**:
    - Initialize temporary variables for intermediate calculations.
    - Perform a series of subtraction operations with borrow to compute the negation of each limb of the input field element `arg1`.
    - Use a conditional move operation to handle the case where the result of the subtraction is negative, adjusting the result to ensure it is within the modulus bounds.
    - Perform addition with carry operations to finalize the negation result, ensuring it is within the modulus bounds.
    - Store the computed negation result in the output array `out1`.
- **Output**: The function outputs the negated field element in the Montgomery domain, stored in the array `out1`.
- **Functions called**:
    - [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64)
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)
    - [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64)


---
### fiat\_p256\_scalar\_from\_montgomery<!-- {{#callable:fiat_p256_scalar_from_montgomery}} -->
The function `fiat_p256_scalar_from_montgomery` converts a field element from the Montgomery domain to the standard representation.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored, representing the field element in the standard domain.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element in the Montgomery domain.
- **Control Flow**:
    - Initialize several 64-bit unsigned integers and fiat_p256_scalar_uint1 variables for intermediate calculations.
    - Extract the first element of the input array `arg1` and perform a series of multiplications and additions to compute intermediate results.
    - Use the Montgomery reduction technique, which involves multiplying by a constant and reducing modulo the prime modulus, to convert the input from the Montgomery domain.
    - Repeat the process for each element of the input array `arg1`, updating the intermediate results accordingly.
    - Perform a series of conditional moves and subtractions to ensure the result is within the correct range of the prime modulus.
    - Store the final result in the output array `out1`.
- **Output**: The function outputs a field element in the standard domain, stored in the array `out1`.
- **Functions called**:
    - [`fiat_p256_scalar_mulx_u64`](#fiat_p256_scalar_mulx_u64)
    - [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64)
    - [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64)
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)


---
### fiat\_p256\_scalar\_to\_montgomery<!-- {{#callable:fiat_p256_scalar_to_montgomery}} -->
The function `fiat_p256_scalar_to_montgomery` converts a field element from the non-Montgomery domain to the Montgomery domain for the P-256 scalar field.
- **Inputs**:
    - `out1`: A pointer to an array of four 64-bit unsigned integers where the result will be stored, representing the field element in the Montgomery domain.
    - `arg1`: A constant pointer to an array of four 64-bit unsigned integers representing the field element in the non-Montgomery domain.
- **Control Flow**:
    - Initialize variables to hold intermediate results and carry flags.
    - Extract the four 64-bit words from the input array `arg1`.
    - Perform a series of multiplications and additions using constants specific to the P-256 scalar field to convert the input to the Montgomery domain.
    - Use the [`fiat_p256_scalar_mulx_u64`](#fiat_p256_scalar_mulx_u64) function to perform 64-bit multiplications and store the results in two 64-bit variables for each multiplication.
    - Use the [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64) function to perform additions with carry, updating the carry flag as needed.
    - Perform a series of conditional moves using [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64) to handle potential overflows and ensure the result is within the field's bounds.
    - Store the final result in the `out1` array.
- **Output**: The function outputs the converted field element in the Montgomery domain, stored in the `out1` array.
- **Functions called**:
    - [`fiat_p256_scalar_mulx_u64`](#fiat_p256_scalar_mulx_u64)
    - [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64)
    - [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64)
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)


---
### fiat\_p256\_scalar\_nonzero<!-- {{#callable:fiat_p256_scalar_nonzero}} -->
The function `fiat_p256_scalar_nonzero` checks if a 256-bit scalar (represented as an array of four 64-bit unsigned integers) is non-zero and outputs a single non-zero word if it is, or zero otherwise.
- **Inputs**:
    - `out1`: A pointer to a 64-bit unsigned integer where the result will be stored.
    - `arg1`: An array of four 64-bit unsigned integers representing a 256-bit scalar.
- **Control Flow**:
    - The function initializes a 64-bit unsigned integer `x1` to the bitwise OR of all elements in the input array `arg1`.
    - The result of the OR operation is stored in the location pointed to by `out1`.
- **Output**: The function outputs a single 64-bit unsigned integer that is non-zero if any part of the input array `arg1` is non-zero, otherwise it outputs zero.


---
### fiat\_p256\_scalar\_selectznz<!-- {{#callable:fiat_p256_scalar_selectznz}} -->
The function `fiat_p256_scalar_selectznz` performs a conditional selection between two 4-element arrays based on a single-bit flag.
- **Inputs**:
    - `out1`: A 4-element array of uint64_t where the result of the selection will be stored.
    - `arg1`: A single-bit flag (fiat_p256_scalar_uint1) that determines which array to select.
    - `arg2`: A 4-element array of uint64_t representing the first option for selection.
    - `arg3`: A 4-element array of uint64_t representing the second option for selection.
- **Control Flow**:
    - The function initializes four uint64_t variables (x1, x2, x3, x4) to store intermediate results.
    - It calls [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64) four times, once for each element of the arrays, passing the corresponding elements of `arg2` and `arg3` and the flag `arg1`.
    - Each call to [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64) conditionally assigns the value from `arg2` or `arg3` to the corresponding x variable based on the value of `arg1`.
    - The results stored in x1, x2, x3, and x4 are then assigned to the corresponding elements of the output array `out1`.
- **Output**: The function outputs a 4-element array of uint64_t, `out1`, which contains the selected elements from either `arg2` or `arg3` based on the value of `arg1`.
- **Functions called**:
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)


---
### fiat\_p256\_scalar\_to\_bytes<!-- {{#callable:fiat_p256_scalar_to_bytes}} -->
The function `fiat_p256_scalar_to_bytes` serializes a 256-bit scalar field element from a 4-element array of 64-bit integers into a 32-byte array in little-endian order.
- **Inputs**:
    - `out1`: A 32-byte array where the serialized bytes of the scalar field element will be stored.
    - `arg1`: A 4-element array of 64-bit unsigned integers representing the scalar field element to be serialized.
- **Control Flow**:
    - Extract the least significant byte from each 64-bit integer in `arg1` and store it in `out1` in little-endian order.
    - Shift each 64-bit integer in `arg1` right by 8 bits and repeat the extraction process until all bytes are extracted.
    - Continue this process for all four 64-bit integers in `arg1`, filling up the 32-byte `out1` array.
- **Output**: The function outputs the serialized 32-byte representation of the input scalar field element in the `out1` array.


---
### fiat\_p256\_scalar\_from\_bytes<!-- {{#callable:fiat_p256_scalar_from_bytes}} -->
The function `fiat_p256_scalar_from_bytes` converts a 32-byte array into a 4-element array of 64-bit unsigned integers, representing a field element not in the Montgomery domain.
- **Inputs**:
    - `out1`: A 4-element array of 64-bit unsigned integers where the result will be stored.
    - `arg1`: A 32-byte array representing the input bytes in little-endian order.
- **Control Flow**:
    - Initialize multiple 64-bit unsigned integers to store intermediate results.
    - Extract and shift each byte from the input array `arg1` to construct four 64-bit integers.
    - Combine the shifted bytes to form four 64-bit integers, each representing a part of the field element.
    - Store the resulting 64-bit integers into the output array `out1`.
- **Output**: A 4-element array of 64-bit unsigned integers representing the deserialized field element.


---
### fiat\_p256\_scalar\_set\_one<!-- {{#callable:fiat_p256_scalar_set_one}} -->
The function `fiat_p256_scalar_set_one` initializes a field element in the Montgomery domain to represent the value one.
- **Inputs**:
    - `out1`: A pointer to a `fiat_p256_scalar_montgomery_domain_field_element`, which is an array of four 64-bit unsigned integers, where the result will be stored.
- **Control Flow**:
    - The function assigns the constant value `0xc46353d039cdaaf` to the first element of the `out1` array.
    - The function assigns the constant value `0x4319055258e8617b` to the second element of the `out1` array.
    - The function assigns the value `0x0` to the third element of the `out1` array.
    - The function assigns the constant value `0xffffffff` to the fourth element of the `out1` array.
- **Output**: The function does not return a value; it modifies the `out1` array in place to represent the number one in the Montgomery domain.


---
### fiat\_p256\_scalar\_msat<!-- {{#callable:fiat_p256_scalar_msat}} -->
The function `fiat_p256_scalar_msat` initializes an array with the saturated representation of the prime modulus for the P-256 scalar field.
- **Inputs**:
    - `out1`: A pointer to an array of 5 uint64_t elements where the saturated representation of the prime modulus will be stored.
- **Control Flow**:
    - The function assigns the first element of the array `out1` to the constant `0xf3b9cac2fc632551`.
    - The second element of the array `out1` is assigned the constant `0xbce6faada7179e84`.
    - The third element of the array `out1` is assigned the constant `0xffffffffffffffff`.
    - The fourth element of the array `out1` is assigned the constant `0xffffffff00000000`.
    - The fifth element of the array `out1` is set to `0x0`.
- **Output**: The function does not return a value; it modifies the array `out1` in place to contain the saturated representation of the prime modulus.


---
### fiat\_p256\_scalar\_divstep<!-- {{#callable:fiat_p256_scalar_divstep}} -->
The function `fiat_p256_scalar_divstep` performs a division step operation in the context of the P-256 scalar field, updating multiple output arrays based on the inputs and specific conditions.
- **Inputs**:
    - `out1`: A pointer to a uint64_t where the result of the division step operation will be stored.
    - `out2`: An array of 5 uint64_t elements that will be updated based on the division step operation.
    - `out3`: An array of 5 uint64_t elements that will be updated based on the division step operation.
    - `out4`: An array of 4 uint64_t elements that will be updated based on the division step operation.
    - `out5`: An array of 4 uint64_t elements that will be updated based on the division step operation.
    - `arg1`: A uint64_t input representing a scalar value used in the division step operation.
    - `arg2`: An array of 5 uint64_t elements representing one of the input values for the division step operation.
    - `arg3`: An array of 5 uint64_t elements representing another input value for the division step operation.
    - `arg4`: An array of 4 uint64_t elements representing another input value for the division step operation.
    - `arg5`: An array of 4 uint64_t elements representing another input value for the division step operation.
- **Control Flow**:
    - Initialize variables and perform a conditional operation to determine if arg1 is less than or equal to zero and if the least significant bit of arg3 is set.
    - Use conditional move operations to select between arg1 and its negation, and between arg2 and arg3, based on the condition evaluated.
    - Compute the negation of arg2 and use conditional move operations to select between arg3 and the negated arg2 values.
    - Perform conditional move operations to select between arg4 and arg5 based on the condition evaluated.
    - Double the selected values from arg4 or arg5 and perform modular subtraction with constants to ensure the result is within the field bounds.
    - Compute the negation of the selected values from arg4 and perform modular addition with constants to ensure the result is within the field bounds.
    - Use conditional move operations to select between the results of the previous operations based on the condition evaluated.
    - Perform bitwise operations to compute the new values for out3 by shifting the results of the previous operations.
    - Use conditional move operations to select between the results of the previous operations for out4 and out5 based on the condition evaluated.
    - Store the final results in the output parameters out1, out2, out3, out4, and out5.
- **Output**: The function updates the output parameters out1, out2, out3, out4, and out5 with the results of the division step operation.
- **Functions called**:
    - [`fiat_p256_scalar_addcarryx_u64`](#fiat_p256_scalar_addcarryx_u64)
    - [`fiat_p256_scalar_cmovznz_u64`](#fiat_p256_scalar_cmovznz_u64)
    - [`fiat_p256_scalar_subborrowx_u64`](#fiat_p256_scalar_subborrowx_u64)


---
### fiat\_p256\_scalar\_divstep\_precomp<!-- {{#callable:fiat_p256_scalar_divstep_precomp}} -->
The function `fiat_p256_scalar_divstep_precomp` initializes a 4-element array with precomputed constants for the Bernstein-Yang inversion in Montgomery form.
- **Inputs**:
    - `out1`: A 4-element array of type uint64_t where the precomputed values will be stored.
- **Control Flow**:
    - The function assigns the first element of the array `out1` to the constant `0xd739262fb7fcfbb5`.
    - The function assigns the second element of the array `out1` to the constant `0x8ac6f75d20074414`.
    - The function assigns the third element of the array `out1` to the constant `0xc67428bfb5e3c256`.
    - The function assigns the fourth element of the array `out1` to the constant `0x444962f2eda7aedf`.
- **Output**: The function does not return a value; it modifies the input array `out1` in place.


