# Purpose
The provided C header file, `fd_bits.h`, is a comprehensive library for bit manipulation and related operations. It defines a wide range of functions and macros for manipulating bits in various data types, including `uchar`, `ushort`, `uint`, `ulong`, and `uint128` (if supported). The file is structured to provide both inline functions and macros that perform operations such as setting, clearing, flipping, and extracting bits, as well as more complex operations like bit rotation, alignment, and population count. Additionally, it includes functions for encoding and decoding integers using symmetric variable width encoding, which is useful for efficient data storage and transmission.

The file is designed to be included in other C source files, providing a set of public APIs for bit manipulation. It includes detailed comments explaining the purpose and behavior of each function, as well as the underlying rationale for certain design choices, such as the use of conditional move operations to optimize performance. The file also addresses potential issues with compiler optimizations and provides workarounds for unaligned memory access, making it suitable for use across different platforms. Overall, this header file serves as a utility library for developers needing efficient and reliable bit manipulation capabilities in their C programs.
# Imports and Dependencies

---
- `../sanitize/fd_sanitize.h`
- `fd_bits_find_lsb.h`
- `fd_bits_find_msb.h`
- `fd_bits_tg.h`


# Functions

---
### fd\_uchar\_popcnt<!-- {{#callable:fd_uchar_popcnt}} -->
Counts the number of set bits (1s) in an unsigned char.
- **Inputs**:
    - `x`: An unsigned char value whose set bits are to be counted.
- **Control Flow**:
    - The function uses the built-in function `__builtin_popcount` to count the number of set bits.
    - The input `x` is cast to an unsigned integer (`uint`) before being passed to `__builtin_popcount`.
- **Output**: Returns an integer representing the number of bits set to 1 in the input unsigned char.


---
### fd\_ushort\_popcnt<!-- {{#callable:fd_ushort_popcnt}} -->
Counts the number of set bits (1s) in a `ushort` value.
- **Inputs**:
    - `x`: A `ushort` integer whose set bits are to be counted.
- **Control Flow**:
    - The function uses the built-in function `__builtin_popcount` to count the number of set bits in the input `ushort` value.
    - The input `ushort` is cast to a `uint` before being passed to `__builtin_popcount`.
- **Output**: Returns an integer representing the number of bits set to 1 in the input `ushort`.


---
### fd\_uint\_popcnt<!-- {{#callable:fd_uint_popcnt}} -->
Counts the number of set bits (1s) in a 32-bit unsigned integer.
- **Inputs**:
    - `x`: A 32-bit unsigned integer whose set bits are to be counted.
- **Control Flow**:
    - The function directly calls the compiler built-in function `__builtin_popcount`.
    - This built-in function efficiently counts the number of 1 bits in the binary representation of the input integer.
- **Output**: Returns an integer representing the count of set bits in the input unsigned integer.


---
### fd\_ulong\_popcnt<!-- {{#callable:fd_ulong_popcnt}} -->
Counts the number of set bits (1s) in a `ulong` integer.
- **Inputs**:
    - `x`: A `ulong` integer whose set bits are to be counted.
- **Control Flow**:
    - The function directly calls the built-in function `__builtin_popcountl` with the input `x`.
    - The `__builtin_popcountl` function computes the number of 1-bits in the binary representation of `x`.
- **Output**: Returns an integer representing the count of set bits in the input `ulong`.


---
### fd\_uint128\_popcnt<!-- {{#callable:fd_uint128_popcnt}} -->
Counts the number of set bits (1s) in a `uint128` value.
- **Inputs**:
    - `x`: A `uint128` value for which the number of set bits is to be counted.
- **Control Flow**:
    - The function uses the `__builtin_popcountl` to count the number of set bits in the lower 64 bits of `x`.
    - It then shifts `x` right by 64 bits to access the upper 64 bits and counts the set bits in that portion as well.
    - The results from both counts are summed and returned.
- **Output**: Returns an integer representing the total number of bits set to 1 in the `uint128` value.


---
### fd\_uchar\_bswap<!-- {{#callable:fd_uchar_bswap}} -->
The `fd_uchar_bswap` function returns the input `uchar` value unchanged.
- **Inputs**:
    - `x`: An `uchar` value that is to be processed.
- **Control Flow**:
    - The function takes a single input argument of type `uchar`.
    - It directly returns the input value without any modification or processing.
- **Output**: The output is the same `uchar` value that was passed as input.


---
### fd\_ushort\_bswap<!-- {{#callable:fd_ushort_bswap}} -->
The `fd_ushort_bswap` function swaps the byte order of a 16-bit unsigned integer.
- **Inputs**:
    - `ushort x`: A 16-bit unsigned integer whose byte order is to be swapped.
- **Control Flow**:
    - The function directly calls the built-in function `__builtin_bswap16` to perform the byte swap.
    - No conditional logic or loops are present; the operation is performed in a single step.
- **Output**: Returns the 16-bit unsigned integer with its byte order swapped.


---
### fd\_uint\_bswap<!-- {{#callable:fd_uint_bswap}} -->
The `fd_uint_bswap` function swaps the byte order of a 32-bit unsigned integer.
- **Inputs**:
    - `x`: A 32-bit unsigned integer whose byte order is to be swapped.
- **Control Flow**:
    - The function directly calls the built-in function `__builtin_bswap32` with the input argument `x`.
    - The built-in function performs the byte swap operation and returns the result.
- **Output**: The function returns a 32-bit unsigned integer with its byte order swapped.


---
### fd\_ulong\_bswap<!-- {{#callable:fd_ulong_bswap}} -->
The `fd_ulong_bswap` function swaps the byte order of a 64-bit unsigned integer.
- **Inputs**:
    - `x`: A 64-bit unsigned integer (`ulong`) whose byte order is to be swapped.
- **Control Flow**:
    - The function directly calls the built-in function `__builtin_bswap64` to perform the byte swap.
    - No conditional statements or loops are present, making the function a straightforward one-liner.
- **Output**: Returns the 64-bit unsigned integer with its byte order swapped.


---
### fd\_uint128\_bswap<!-- {{#callable:fd_uint128_bswap}} -->
The `fd_uint128_bswap` function swaps the byte order of a `uint128` value.
- **Inputs**:
    - `x`: A `uint128` value whose byte order is to be swapped.
- **Control Flow**:
    - The function first extracts the lower 64 bits of the `uint128` value `x` into `xl`.
    - It then extracts the upper 64 bits of `x` into `xh` by right-shifting `x` by 64 bits.
    - The function calls [`fd_ulong_bswap`](#fd_ulong_bswap) on both `xl` and `xh` to swap their byte orders.
    - Finally, it combines the swapped lower and upper parts back into a `uint128` value and returns it.
- **Output**: The function returns a `uint128` value with its byte order swapped.
- **Functions called**:
    - [`fd_ulong_bswap`](#fd_ulong_bswap)


---
### fd\_uchar\_pow2\_up<!-- {{#callable:fd_uchar_pow2_up}} -->
Calculates the smallest power of 2 that is greater than or equal to a given unsigned char value.
- **Inputs**:
    - `_x`: An unsigned char value for which the next power of 2 is to be calculated.
- **Control Flow**:
    - The input `_x` is cast to a `uint` type to facilitate bit manipulation.
    - The value of `x` is decremented by 1 to prepare for the bit manipulation that will find the next power of 2.
    - Bitwise operations are performed to propagate the highest set bit to the right, effectively filling all bits below it with 1s.
    - The result is incremented by 1 to obtain the next power of 2.
    - Finally, the result is cast back to `uchar` and returned.
- **Output**: Returns the smallest power of 2 that is greater than or equal to the input value `_x`.


---
### fd\_uchar\_pow2\_dn<!-- {{#callable:fd_uchar_pow2_dn}} -->
Calculates the largest power of 2 less than or equal to a given unsigned char.
- **Inputs**:
    - `_x`: An unsigned char value for which the largest power of 2 less than or equal to it is to be calculated.
- **Control Flow**:
    - The input `_x` is cast to a `uint` type for manipulation.
    - The value is right-shifted by 1 to prepare for the calculation of the largest power of 2.
    - Bitwise OR operations are performed to propagate the highest set bit to the right, effectively filling in lower bits.
    - The result is incremented by 1 to get the next power of 2, which is then returned as an unsigned char.
- **Output**: Returns an unsigned char representing the largest power of 2 that is less than or equal to the input value.


---
### fd\_ushort\_pow2\_up<!-- {{#callable:fd_ushort_pow2_up}} -->
Calculates the smallest power of 2 that is greater than or equal to a given unsigned short value.
- **Inputs**:
    - `_x`: An unsigned short integer input for which the next power of 2 is to be calculated.
- **Control Flow**:
    - The input `_x` is cast to a `uint` type to allow for bitwise operations.
    - The value of `x` is decremented by 1 to facilitate the calculation of the next power of 2.
    - Bitwise operations are performed to propagate the highest set bit to the right, effectively creating a mask of all bits below the highest set bit.
    - The final result is obtained by incrementing `x` by 1, which gives the smallest power of 2 greater than or equal to the original input.
- **Output**: Returns an unsigned short representing the smallest power of 2 that is greater than or equal to the input value.


---
### fd\_ushort\_pow2\_dn<!-- {{#callable:fd_ushort_pow2_dn}} -->
Calculates the largest power of 2 that is less than or equal to a given unsigned short integer.
- **Inputs**:
    - `_x`: An unsigned short integer input for which the largest power of 2 less than or equal to it is to be calculated.
- **Control Flow**:
    - The input `_x` is first cast to a `uint` type to allow for bit manipulation.
    - The value of `x` is right-shifted by 1 to prepare for the calculation of the largest power of 2.
    - Bitwise OR operations are performed on `x` with progressively right-shifted versions of itself to propagate the highest set bit to the right.
    - After the bitwise operations, `x` is incremented by 1 to ensure it represents the next power of 2.
    - Finally, the result is cast back to `ushort` and returned.
- **Output**: Returns the largest power of 2 that is less than or equal to the input `_x` as an unsigned short.


---
### fd\_uint\_pow2\_up<!-- {{#callable:fd_uint_pow2_up}} -->
Calculates the smallest power of 2 that is greater than or equal to a given unsigned integer.
- **Inputs**:
    - `x`: An unsigned integer input for which the smallest power of 2 greater than or equal to it is to be calculated.
- **Control Flow**:
    - Decrement the input `x` by 1 to handle the case where `x` is already a power of 2.
    - Perform a series of bitwise OR operations with right-shifted versions of `x` to propagate the highest set bit to the right.
    - Increment `x` by 1 to obtain the next power of 2.
- **Output**: Returns the smallest power of 2 that is greater than or equal to the input `x`.


---
### fd\_uint\_pow2\_dn<!-- {{#callable:fd_uint_pow2_dn}} -->
Calculates the largest power of 2 that is less than or equal to a given unsigned integer.
- **Inputs**:
    - `x`: An unsigned integer input for which the largest power of 2 less than or equal to it is to be calculated.
- **Control Flow**:
    - The input `x` is right-shifted by 1 bit to effectively halve its value.
    - The result is then progressively OR-ed with its right-shifted versions (by 1, 2, 4, 8, and 16 bits) to propagate the highest set bit to the right.
    - After the bit propagation, the result is incremented by 1 to obtain the next power of 2.
    - The final result is returned, which is the largest power of 2 less than or equal to the original input.
- **Output**: Returns an unsigned integer representing the largest power of 2 that is less than or equal to the input `x`.


---
### fd\_ulong\_pow2\_up<!-- {{#callable:fd_ulong_pow2_up}} -->
Calculates the smallest power of 2 that is greater than or equal to a given unsigned long integer.
- **Inputs**:
    - `x`: An unsigned long integer input for which the smallest power of 2 greater than or equal to this value is to be calculated.
- **Control Flow**:
    - Decrement the input `x` by 1 to facilitate the calculation of the next power of 2.
    - Perform a series of bitwise OR operations with right-shifted versions of `x` to propagate the highest set bit to the right.
    - After the bitwise operations, increment `x` by 1 to obtain the smallest power of 2 that is greater than or equal to the original input.
- **Output**: Returns the smallest power of 2 that is greater than or equal to the input `x`. If `x` is 0, the function currently returns 0.


---
### fd\_ulong\_pow2\_dn<!-- {{#callable:fd_ulong_pow2_dn}} -->
Calculates the largest power of 2 that is less than or equal to a given unsigned long integer.
- **Inputs**:
    - `x`: An unsigned long integer input for which the largest power of 2 less than or equal to this value is to be calculated.
- **Control Flow**:
    - The function first right shifts `x` by 1 to discard the least significant bit.
    - It then performs a series of bitwise OR operations with progressively right-shifted versions of `x` to propagate the highest set bit to the right.
    - Finally, it increments the result to obtain the next power of 2, which is returned.
- **Output**: Returns the largest power of 2 that is less than or equal to the input `x`. If `x` is 0, the function returns 1.


---
### fd\_uint128\_pow2\_up<!-- {{#callable:fd_uint128_pow2_up}} -->
Calculates the smallest power of 2 that is greater than or equal to a given `uint128` value.
- **Inputs**:
    - `x`: A `uint128` value for which the smallest power of 2 greater than or equal to it is to be calculated.
- **Control Flow**:
    - Decrement `x` by 1 to handle the case where `x` is already a power of 2.
    - Perform a series of bitwise OR operations with right-shifted versions of `x` to propagate the highest set bit to the right.
    - Increment `x` by 1 to obtain the next power of 2.
- **Output**: Returns a `uint128` representing the smallest power of 2 that is greater than or equal to the input value `x`.


---
### fd\_uint128\_pow2\_dn<!-- {{#callable:fd_uint128_pow2_dn}} -->
Calculates the largest power of 2 that is less than or equal to a given `uint128` value.
- **Inputs**:
    - `x`: A `uint128` value for which the largest power of 2 less than or equal to it is to be calculated.
- **Control Flow**:
    - The function first right shifts `x` by 1 to halve its value.
    - It then uses a series of bitwise OR operations combined with right shifts to propagate the highest set bit to the right, effectively filling all bits to the right of the highest set bit.
    - Finally, it increments the result by 1 to ensure that the result is the next power of 2.
- **Output**: Returns a `uint128` representing the largest power of 2 that is less than or equal to the input value `x`.


---
### fd\_float\_if<!-- {{#callable:fd_float_if}} -->
`fd_float_if` returns one of two float values based on the evaluation of a condition.
- **Inputs**:
    - `c`: An integer condition that determines which float value to return; if non-zero, the first float is returned.
    - `t`: The float value to return if the condition `c` is true (non-zero).
    - `f`: The float value to return if the condition `c` is false (zero).
- **Control Flow**:
    - The function evaluates the condition `c`.
    - If `c` is non-zero, it returns the value `t`.
    - If `c` is zero, it returns the value `f`.
- **Output**: Returns either `t` or `f` based on the evaluation of `c`.


---
### fd\_float\_store\_if<!-- {{#callable:fd_float_store_if}} -->
Stores a float value to a specified pointer if a condition is met.
- **Inputs**:
    - `c`: An integer condition that determines whether the value should be stored.
    - `p`: A pointer to a float where the value will be stored if the condition is true.
    - `v`: The float value to be stored at the pointer if the condition is true.
- **Control Flow**:
    - The function checks the condition `c`.
    - If `c` is non-zero (true), it stores the value `v` at the address pointed to by `p`.
    - If `c` is zero (false), it does nothing, effectively preventing any storage operation.
- **Output**: The function does not return a value; it performs a conditional store operation.


---
### fd\_float\_abs<!-- {{#callable:fd_float_abs}} -->
Calculates the absolute value of a floating-point number.
- **Inputs**:
    - `x`: A floating-point number of type `float` whose absolute value is to be calculated.
- **Control Flow**:
    - The function directly calls the built-in function `__builtin_fabsf` to compute the absolute value.
    - No conditional statements or loops are present, making the function straightforward and efficient.
- **Output**: Returns the absolute value of the input floating-point number as a `float`.


---
### fd\_float\_eq<!-- {{#callable:fd_float_eq}} -->
The `fd_float_eq` function checks if two `float` values are equal by comparing their bit representations.
- **Inputs**:
    - `x`: The first `float` value to compare.
    - `y`: The second `float` value to compare.
- **Control Flow**:
    - A union is defined to hold a `float` and its corresponding `uint` representation.
    - The first `float` value `x` is assigned to the union variable `tx`, and the second `float` value `y` is assigned to the union variable `ty`.
    - The function returns the result of comparing the `uint` representations of `tx` and `ty`.
- **Output**: Returns 1 (true) if the bit representations of `x` and `y` are identical, indicating that they are equal; otherwise, returns 0 (false).


---
### fd\_double\_if<!-- {{#callable:fd_double_if}} -->
The `fd_double_if` function returns one of two double values based on the evaluation of a condition.
- **Inputs**:
    - `c`: An integer condition that determines which of the two double values to return; if non-zero, the first value is returned.
    - `t`: The double value to return if the condition `c` is true (non-zero).
    - `f`: The double value to return if the condition `c` is false (zero).
- **Control Flow**:
    - The function evaluates the condition `c`.
    - If `c` is non-zero, it returns the value `t`.
    - If `c` is zero, it returns the value `f`.
- **Output**: Returns a double value, either `t` or `f`, based on the evaluation of the condition `c`.


---
### fd\_double\_store\_if<!-- {{#callable:fd_double_store_if}} -->
Stores a double value to a specified pointer if a condition is met.
- **Inputs**:
    - `c`: An integer condition that determines whether to store the value.
    - `p`: A pointer to a double where the value will be stored if the condition is true.
    - `v`: The double value to be stored at the pointer if the condition is true.
- **Control Flow**:
    - The function checks the condition `c`.
    - If `c` is non-zero (true), it stores the value `v` at the address pointed to by `p`.
    - If `c` is zero (false), it does nothing, effectively preventing any storage operation.
- **Output**: The function does not return a value; it performs a conditional store operation.


---
### fd\_double\_abs<!-- {{#callable:fd_double_abs}} -->
Calculates the absolute value of a double-precision floating-point number.
- **Inputs**:
    - `x`: A double-precision floating-point number whose absolute value is to be calculated.
- **Control Flow**:
    - The function directly calls the built-in function `__builtin_fabs` to compute the absolute value of `x`.
    - No conditional statements or loops are present, making the function a straightforward one-liner.
- **Output**: Returns the absolute value of the input double `x`.


---
### fd\_double\_eq<!-- {{#callable:fd_double_eq}} -->
Compares two `double` values for equality by checking if their bit representations are identical.
- **Inputs**:
    - `x`: The first `double` value to compare.
    - `y`: The second `double` value to compare.
- **Control Flow**:
    - Creates a union to hold the bit representation of the `double` values.
    - Assigns the first `double` value to the union and retrieves its bit representation as an unsigned long.
    - Assigns the second `double` value to the union and retrieves its bit representation as an unsigned long.
    - Compares the two unsigned long representations for equality.
- **Output**: Returns 1 if the bit representations of the two `double` values are identical, otherwise returns 0.


---
### fd\_uchar\_load\_1<!-- {{#callable:fd_uchar_load_1}} -->
Loads a single `uchar` value from a given memory address.
- **Inputs**:
    - `p`: A pointer to the memory location from which the `uchar` value will be loaded.
- **Control Flow**:
    - The function uses a cast to interpret the input pointer `p` as a pointer to `uchar`.
    - It dereferences the pointer to retrieve the value stored at that memory location.
- **Output**: Returns the `uchar` value located at the memory address pointed to by `p`.


---
### fd\_ushort\_load\_1<!-- {{#callable:fd_ushort_load_1}} -->
The `fd_ushort_load_1` function loads a single byte from a given pointer and interprets it as an unsigned short integer.
- **Inputs**:
    - `p`: A pointer to a memory location from which a byte will be read.
- **Control Flow**:
    - The function first uses `FD_COMPILER_FORGET(p)` to inform the compiler that the pointer `p` is not used in a way that affects the program's observable behavior, allowing for potential optimizations.
    - It then dereferences the pointer `p`, treating it as a pointer to an unsigned char (`uchar`), and casts the value to an unsigned short (`ushort`).
- **Output**: The function returns the value of the byte pointed to by `p`, interpreted as an unsigned short integer.


---
### fd\_ushort\_load\_2<!-- {{#callable:fd_ushort_load_2}} -->
The `fd_ushort_load_2` function loads a 16-bit unsigned short integer from a given memory address.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 16-bit unsigned short integer will be read.
- **Control Flow**:
    - The function begins by declaring a temporary variable `t` of type `ushort`.
    - It then uses `memcpy` to copy 2 bytes from the memory location pointed to by `p` into the variable `t`.
    - Finally, it returns the value of `t`.
- **Output**: The function returns the 16-bit unsigned short integer that was read from the specified memory location.


---
### fd\_uint\_load\_1<!-- {{#callable:fd_uint_load_1}} -->
Loads a single byte from a given pointer and returns it as an unsigned integer.
- **Inputs**:
    - `p`: A pointer to the memory location from which a single byte will be read.
- **Control Flow**:
    - The function uses `FD_COMPILER_FORGET(p)` to inform the compiler that the pointer `p` is not used in any side effects.
    - It dereferences the pointer `p` as a `const uchar*` to read the byte at that memory location.
    - The byte read is then cast to a `uint` type before being returned.
- **Output**: Returns the value of the byte pointed to by `p` as an unsigned integer.


---
### fd\_uint\_load\_2<!-- {{#callable:fd_uint_load_2}} -->
The `fd_uint_load_2` function loads a 2-byte unsigned integer from a given memory address.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 2-byte unsigned integer is to be read.
- **Control Flow**:
    - The function uses a type cast to interpret the memory at the address pointed to by `p` as a pointer to an unsigned short (`ushort`).
    - It dereferences this pointer to read the value stored at that memory location.
    - The value is then cast to an unsigned integer (`uint`) before being returned.
- **Output**: Returns the 2-byte unsigned integer read from the memory location pointed to by `p`, cast to an unsigned integer.


---
### fd\_uint\_load\_3<!-- {{#callable:fd_uint_load_3}} -->
Loads a 3-byte unsigned integer from a given memory address.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 3-byte unsigned integer is to be loaded.
- **Control Flow**:
    - The function first calls [`fd_uint_load_2`](#fd_uint_load_2) to load the first 2 bytes from the memory pointed to by `p`.
    - It then calls [`fd_uint_load_1`](#fd_uint_load_1) to load the third byte, which is located 2 bytes ahead of `p`, and shifts it left by 16 bits.
    - Finally, it combines the results of the two loads using a bitwise OR operation to form the final 3-byte unsigned integer.
- **Output**: Returns the 3-byte unsigned integer as a `uint` type, with the upper byte set to zero.
- **Functions called**:
    - [`fd_uint_load_2`](#fd_uint_load_2)
    - [`fd_uint_load_1`](#fd_uint_load_1)


---
### fd\_uint\_load\_4<!-- {{#callable:fd_uint_load_4}} -->
The `fd_uint_load_4` function loads a 4-byte unsigned integer from a given memory address.
- **Inputs**:
    - `p`: A pointer to a memory location from which a 4-byte unsigned integer will be read.
- **Control Flow**:
    - The function uses a type cast to interpret the memory at the address pointed to by `p` as a pointer to a `uint`.
    - It dereferences this pointer to read the value stored at that memory location.
    - The `FD_COMPILER_FORGET(p)` macro is called to inform the compiler that the pointer `p` is not used in any further computations, potentially aiding optimization.
- **Output**: The function returns the 4-byte unsigned integer read from the memory location pointed to by `p`.


---
### fd\_ulong\_load\_1<!-- {{#callable:fd_ulong_load_1}} -->
Loads a `ulong` value from a given memory address, interpreting the first byte as an `uchar`.
- **Inputs**:
    - `p`: A pointer to the memory location from which the `ulong` value will be loaded.
- **Control Flow**:
    - The function uses `FD_COMPILER_FORGET(p)` to inform the compiler that the pointer `p` is not used in any side effects, allowing for potential optimizations.
    - It dereferences the pointer `p` as a pointer to `uchar` and retrieves the value at that address.
    - The retrieved `uchar` value is then cast to `ulong` and returned.
- **Output**: Returns the `ulong` value obtained by interpreting the first byte at the memory address pointed to by `p`.


---
### fd\_ulong\_load\_2<!-- {{#callable:fd_ulong_load_2}} -->
Loads a 2-byte unsigned long value from a given memory address.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 2-byte value will be loaded.
- **Control Flow**:
    - The function uses `FD_COMPILER_FORGET(p)` to inform the compiler that the pointer `p` is not used in a way that affects the program's observable behavior.
    - It dereferences the pointer `p` as a pointer to an unsigned short (`ushort const *`) and retrieves the value at that address.
    - The retrieved value is then cast to an unsigned long (`ulong`) before being returned.
- **Output**: Returns the 2-byte unsigned long value loaded from the memory address pointed to by `p`.


---
### fd\_ulong\_load\_3<!-- {{#callable:fd_ulong_load_3}} -->
The `fd_ulong_load_3` function loads a 3-byte unsigned long integer from a given memory address.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 3-byte unsigned long integer will be read.
- **Control Flow**:
    - The function first calls [`fd_ulong_load_2`](#fd_ulong_load_2) to read the first 2 bytes from the memory location pointed to by `p`.
    - It then calls [`fd_ulong_load_1`](#fd_ulong_load_1) to read the third byte, which is located 2 bytes ahead of `p`.
    - The result of [`fd_ulong_load_2`](#fd_ulong_load_2) is combined with the result of [`fd_ulong_load_1`](#fd_ulong_load_1) shifted left by 16 bits using a bitwise OR operation.
- **Output**: The function returns a `ulong` value that represents the 3-byte unsigned long integer read from the specified memory location.
- **Functions called**:
    - [`fd_ulong_load_2`](#fd_ulong_load_2)
    - [`fd_ulong_load_1`](#fd_ulong_load_1)


---
### fd\_ulong\_load\_4<!-- {{#callable:fd_ulong_load_4}} -->
The `fd_ulong_load_4` function loads a 4-byte unsigned long integer from a given memory address.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 4-byte unsigned long integer will be read.
- **Control Flow**:
    - The function uses a type cast to interpret the memory at the address pointed to by `p` as a pointer to a `uint`.
    - It dereferences this pointer to read the value stored at that memory location.
    - The value is then cast to `ulong` before being returned.
- **Output**: The function returns the 4-byte unsigned long integer read from the specified memory address.


---
### fd\_ulong\_load\_5<!-- {{#callable:fd_ulong_load_5}} -->
Loads a 64-bit unsigned long integer from a memory location, combining data from two separate loads.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 64-bit unsigned long integer is to be loaded.
- **Control Flow**:
    - The function first calls `fd_ulong_load_4(p)` to load the lower 32 bits of the ulong from the address pointed to by `p`.
    - Then, it calls `fd_ulong_load_1(((uchar const *)p)+4UL)` to load the next byte (the 5th byte) from the memory location, which is shifted left by 32 bits.
    - Finally, it combines the results of the two loads using a bitwise OR operation to form the final 64-bit unsigned long integer.
- **Output**: Returns the combined 64-bit unsigned long integer constructed from the loaded values.
- **Functions called**:
    - [`fd_ulong_load_4`](#fd_ulong_load_4)
    - [`fd_ulong_load_1`](#fd_ulong_load_1)


---
### fd\_ulong\_load\_6<!-- {{#callable:fd_ulong_load_6}} -->
Loads a 64-bit unsigned long integer from a memory location, combining data from two smaller loads.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 64-bit unsigned long integer is to be loaded.
- **Control Flow**:
    - The function first calls [`fd_ulong_load_4`](#fd_ulong_load_4) to load the first 4 bytes from the memory location pointed to by `p`.
    - Then, it calls [`fd_ulong_load_2`](#fd_ulong_load_2) to load the next 2 bytes, offset by 4 bytes from `p`, and shifts this value left by 32 bits.
    - Finally, it combines the results of the two loads using a bitwise OR operation to form the final 64-bit unsigned long integer.
- **Output**: Returns the combined 64-bit unsigned long integer loaded from the specified memory location.
- **Functions called**:
    - [`fd_ulong_load_4`](#fd_ulong_load_4)
    - [`fd_ulong_load_2`](#fd_ulong_load_2)


---
### fd\_ulong\_load\_7<!-- {{#callable:fd_ulong_load_7}} -->
The `fd_ulong_load_7` function loads 7 bytes from a given memory address and returns them as a `ulong` value.
- **Inputs**:
    - `p`: A pointer to the memory location from which 7 bytes will be read.
- **Control Flow**:
    - The function first calls [`fd_ulong_load_6`](#fd_ulong_load_6) to read the first 6 bytes from the memory location pointed to by `p`.
    - It then reads the 7th byte by accessing the memory location at `((uchar const *)p) + 6UL` and shifts it left by 48 bits.
    - Finally, it combines the results of the two reads using a bitwise OR operation to form the final `ulong` value.
- **Output**: Returns a `ulong` value that represents the 7 bytes read from the specified memory location.
- **Functions called**:
    - [`fd_ulong_load_6`](#fd_ulong_load_6)
    - [`fd_ulong_load_1`](#fd_ulong_load_1)


---
### fd\_ulong\_load\_8<!-- {{#callable:fd_ulong_load_8}} -->
The `fd_ulong_load_8` function loads an 8-byte unsigned long integer from a specified memory address.
- **Inputs**:
    - `p`: A pointer to a memory location from which an 8-byte unsigned long integer will be read.
- **Control Flow**:
    - The function uses the `FD_COMPILER_FORGET` macro to inform the compiler that the pointer `p` is not used in a way that affects the program's observable behavior, allowing for potential optimizations.
    - It dereferences the pointer `p` as a constant pointer to an unsigned long (`ulong const *`) and returns the value at that memory location.
- **Output**: Returns the 8-byte unsigned long integer read from the memory address pointed to by `p`.


---
### fd\_uint\_load\_3\_fast<!-- {{#callable:fd_uint_load_3_fast}} -->
The `fd_uint_load_3_fast` function loads a 3-byte unsigned integer from a given memory address and returns it as a 32-bit unsigned integer.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 3-byte unsigned integer will be read.
- **Control Flow**:
    - The function uses the `FD_COMPILER_FORGET` macro to inform the compiler that the pointer `p` is not used in a way that affects the program's observable behavior, allowing for potential optimizations.
    - It dereferences the pointer `p` to read a 4-byte unsigned integer, but only the least significant 3 bytes are relevant.
    - The function applies a bitwise AND operation with the mask `0x00ffffffU` to ensure that only the lower 3 bytes are returned, effectively discarding any higher bytes.
- **Output**: Returns a 32-bit unsigned integer representing the 3-byte value read from the memory location, with the upper byte set to zero.


---
### fd\_ulong\_load\_3\_fast<!-- {{#callable:fd_ulong_load_3_fast}} -->
Loads a 3-byte unsigned long integer from a given memory address, masking the result to ensure only the least significant 24 bits are returned.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 3-byte unsigned long integer is to be loaded.
- **Control Flow**:
    - The function begins by using `FD_COMPILER_FORGET(p)` to inform the compiler that the pointer `p` is not used in a way that affects the program's observable behavior, allowing for potential optimizations.
    - It then dereferences the pointer `p` as a pointer to a `uint` (unsigned integer) and reads the 4 bytes starting from that address.
    - The function applies a bitwise AND operation with the mask `0x0000000000ffffffUL` to ensure that only the least significant 24 bits of the loaded value are retained.
    - Finally, the masked value is returned as an unsigned long.
- **Output**: Returns a 64-bit unsigned long integer that represents the 3 bytes read from the memory location, with the upper 40 bits cleared.


---
### fd\_ulong\_load\_5\_fast<!-- {{#callable:fd_ulong_load_5_fast}} -->
The `fd_ulong_load_5_fast` function loads a 64-bit unsigned long integer from a given memory address, masking the result to return only the least significant 48 bits.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 64-bit unsigned long integer is to be loaded.
- **Control Flow**:
    - The function uses `FD_COMPILER_FORGET(p)` to inform the compiler that the pointer `p` is not used in a way that affects the program's observable behavior, allowing for potential optimizations.
    - It dereferences the pointer `p` to read the 64-bit value stored at that address.
    - The read value is then masked with `0x000000ffffffffffUL` to ensure that only the least significant 48 bits are retained.
- **Output**: The function returns a 64-bit unsigned long integer that contains the least significant 48 bits of the value read from the memory address pointed to by `p`.


---
### fd\_ulong\_load\_6\_fast<!-- {{#callable:fd_ulong_load_6_fast}} -->
The `fd_ulong_load_6_fast` function loads 6 bytes from a given memory address into a `ulong` and masks the result to return only the least significant 48 bits.
- **Inputs**:
    - `p`: A pointer to the memory location from which 6 bytes will be read.
- **Control Flow**:
    - The function begins by using `FD_COMPILER_FORGET(p)` to inform the compiler that the pointer `p` is not used in a way that affects the program's observable behavior, allowing for potential optimizations.
    - It then dereferences the pointer `p` to read the value at that memory location as a `ulong`.
    - The read value is masked with `0x0000ffffffffffffUL` to ensure that only the least significant 48 bits are retained.
    - Finally, the masked value is returned.
- **Output**: The function returns a `ulong` value that represents the 6 bytes read from the memory location, with the upper 16 bits cleared.


---
### fd\_ulong\_load\_7\_fast<!-- {{#callable:fd_ulong_load_7_fast}} -->
The `fd_ulong_load_7_fast` function loads 7 bytes from a given memory address into a `ulong` and masks the result to ensure only the least significant 56 bits are returned.
- **Inputs**:
    - `p`: A pointer to the memory location from which 7 bytes will be read.
- **Control Flow**:
    - The function begins by using `FD_COMPILER_FORGET(p)` to inform the compiler that the pointer `p` is not used in a way that affects the program's observable behavior, allowing for potential optimizations.
    - It then dereferences the pointer `p` to read the value at that memory location as a `ulong`.
    - Finally, it applies a bitwise AND operation with the mask `0x00ffffffffffffffUL` to ensure that only the least significant 56 bits of the value are retained before returning the result.
- **Output**: The function returns a `ulong` value that represents the 7 bytes read from the memory location, masked to include only the least significant 56 bits.


---
### fd\_ulong\_svw\_enc\_sz<!-- {{#callable:fd_ulong_svw_enc_sz}} -->
Calculates the number of bytes required to encode a given unsigned long integer using symmetric variable width encoding.
- **Inputs**:
    - `x`: An unsigned long integer that needs to be encoded.
- **Control Flow**:
    - The function checks the value of `x` against predefined thresholds to determine the number of bytes needed for encoding.
    - If `x` is less than 64, it returns 1 byte.
    - If `x` is less than 1024, it returns 2 bytes.
    - If `x` is less than 262144, it returns 3 bytes.
    - If `x` is less than 16777216, it returns 4 bytes.
    - If `x` is less than 4294967296, it returns 5 bytes.
    - If `x` is less than 72057594037927936, it returns 8 bytes.
    - For all other values, it returns 9 bytes.
- **Output**: Returns the number of bytes required to encode the input integer `x` as a symmetric variable width encoded integer, which can be 1, 2, 3, 4, 5, 8, or 9.


---
### fd\_ulong\_svw\_enc<!-- {{#callable:fd_ulong_svw_enc}} -->
Encodes a `ulong` value into a byte stream using symmetric variable width encoding.
- **Inputs**:
    - `b`: A pointer to the byte stream where the encoded value will be stored.
    - `x`: The `ulong` value to be encoded.
- **Control Flow**:
    - Checks if `x` is less than 2^6; if true, encodes it in 1 byte.
    - If `x` is less than 2^10, encodes it in 2 bytes using a specific format.
    - If `x` is less than 2^18, encodes it in 3 bytes with a different format.
    - If `x` is less than 2^24, encodes it in 4 bytes.
    - If `x` is less than 2^32, encodes it in 5 bytes.
    - If `x` is less than 2^56, encodes it in 8 bytes.
    - If `x` is 2^56 or greater, encodes it in 9 bytes.
- **Output**: Returns a pointer to the next location in the byte stream after the encoded value.


---
### fd\_ulong\_svw\_enc\_fixed<!-- {{#callable:fd_ulong_svw_enc_fixed}} -->
Encodes a `ulong` value into a byte stream with a fixed size determined by `csz`.
- **Inputs**:
    - `b`: A pointer to the byte stream where the encoded value will be stored.
    - `csz`: The size in bytes for the encoding, which must be one of {1,2,3,4,5,8,9}.
    - `x`: The `ulong` value to be encoded.
- **Control Flow**:
    - The function checks the value of `csz` to determine how to encode the value `x`.
    - For each possible size, it uses bit manipulation to encode `x` into the byte stream `b`.
    - The encoding format varies based on the size, with specific bit patterns used for each size.
    - The function uses `FD_STORE` to write multi-byte values into the byte stream.
- **Output**: Returns a pointer to the next position in the byte stream after the encoded value.


---
### fd\_ulong\_svw\_dec\_sz<!-- {{#callable:fd_ulong_svw_dec_sz}} -->
Calculates the size of a symmetric variable width encoded integer based on the first byte of the encoded data.
- **Inputs**:
    - `b`: A pointer to a constant array of `uchar` representing the encoded integer, where the first byte indicates the size of the encoded data.
- **Control Flow**:
    - The function extracts the least significant 4 bits from the first byte pointed to by `b`.
    - It uses a right shift operation on a predefined constant (0x9131512181314121UL) to determine the size of the encoded integer based on the extracted bits.
    - The result is masked with 15UL to obtain the final size.
- **Output**: Returns a `ulong` representing the number of bytes used to encode the integer, which can be one of the values: 1, 2, 3, 4, 5, 8, or 9.


---
### fd\_ulong\_svw\_dec\_tail\_sz<!-- {{#callable:fd_ulong_svw_dec_tail_sz}} -->
Calculates the number of bytes required for the tail of a symmetric variable width encoded integer based on the last byte of the encoded data.
- **Inputs**:
    - `b`: A pointer to the byte array where the last byte of the encoded integer is located.
- **Control Flow**:
    - The function extracts the last byte of the encoded integer from the pointer `b`.
    - It shifts the last byte right by 4 bits to determine the size category of the encoded integer.
    - Using a pre-defined bitmask, it retrieves the corresponding size in bytes for the encoded integer.
- **Output**: Returns the number of bytes required to represent the symmetric variable width encoded integer, which can be 1, 2, 3, 4, 5, 8, or 9.


---
### fd\_ulong\_svw\_dec\_fixed<!-- {{#callable:fd_ulong_svw_dec_fixed}} -->
Decodes a ulong from a symmetric variable width encoded integer based on a specified byte size.
- **Inputs**:
    - `b`: A pointer to the first byte of the encoded integer.
    - `csz`: The size of the encoded integer in bytes, expected to be one of {1,2,3,4,5,8,9}.
- **Control Flow**:
    - Checks the value of `csz` to determine how to decode the ulong.
    - For each possible size, it uses the appropriate `fd_ulong_load_n` function to read the bytes and applies bitwise operations to extract the ulong value.
    - Returns the decoded ulong value based on the specified size.
- **Output**: Returns the decoded ulong value from the encoded integer.
- **Functions called**:
    - [`fd_ulong_load_1`](#fd_ulong_load_1)
    - [`fd_ulong_load_2`](#fd_ulong_load_2)
    - [`fd_ulong_load_4`](#fd_ulong_load_4)
    - [`fd_ulong_load_8`](#fd_ulong_load_8)


---
### fd\_ulong\_svw\_dec<!-- {{#callable:fd_ulong_svw_dec}} -->
Decodes a ulong from a symmetric variable width encoded integer and updates the provided pointer to the next byte.
- **Inputs**:
    - `b`: A pointer to the byte stream containing the encoded ulong.
    - `_x`: A pointer to a ulong variable where the decoded value will be stored.
- **Control Flow**:
    - Calls [`fd_ulong_svw_dec_sz`](#fd_ulong_svw_dec_sz) to determine the size of the encoded integer in bytes.
    - Calls [`fd_ulong_svw_dec_fixed`](#fd_ulong_svw_dec_fixed) to decode the ulong value based on the determined size.
    - Increments the pointer `b` by the size of the encoded integer.
- **Output**: Returns a pointer to the next byte after the decoded ulong in the byte stream.
- **Functions called**:
    - [`fd_ulong_svw_dec_sz`](#fd_ulong_svw_dec_sz)
    - [`fd_ulong_svw_dec_fixed`](#fd_ulong_svw_dec_fixed)


---
### fd\_ulong\_svw\_dec\_tail<!-- {{#callable:fd_ulong_svw_dec_tail}} -->
Decodes a ulong encoded as a symmetric variable width encoded integer from a byte stream.
- **Inputs**:
    - `b`: A pointer to the byte stream containing the encoded integer, pointing to the first byte after the encoded integer.
    - `_x`: A pointer to a `ulong` variable where the decoded value will be stored.
- **Control Flow**:
    - Calls [`fd_ulong_svw_dec_tail_sz`](#fd_ulong_svw_dec_tail_sz) to determine the size of the encoded integer.
    - Decrements the pointer `b` by the size of the encoded integer.
    - Calls [`fd_ulong_svw_dec_fixed`](#fd_ulong_svw_dec_fixed) to decode the integer from the byte stream and store it in the variable pointed to by `_x`.
    - Returns the updated pointer `b` which now points to the first byte after the decoded integer.
- **Output**: Returns a pointer to the first byte after the decoded symmetric variable width encoded integer.
- **Functions called**:
    - [`fd_ulong_svw_dec_tail_sz`](#fd_ulong_svw_dec_tail_sz)
    - [`fd_ulong_svw_dec_fixed`](#fd_ulong_svw_dec_fixed)


# Function Declarations (Public API)

---
### fd\_ulong\_approx\_sqrt<!-- {{#callable_declaration:fd_ulong_approx_sqrt}} -->
Approximates the square root of an unsigned long integer.
- **Description**: Use this function to quickly obtain an approximate square root of a given unsigned long integer. It is designed to be fast and cross-platform deterministic, providing an approximation that is accurate to within approximately 0.4% for any input value. This function is particularly useful in scenarios where performance is critical and an exact square root is not necessary. It handles the edge case where the input is zero by returning zero.
- **Inputs**:
    - `x`: An unsigned long integer for which the square root is to be approximated. The input can be any value within the range of an unsigned long, including zero. If the input is zero, the function returns zero.
- **Output**: Returns an unsigned long integer representing the approximate square root of the input value.
- **See also**: [`fd_ulong_approx_sqrt`](fd_bits.c.driver.md#fd_ulong_approx_sqrt)  (Implementation)


---
### fd\_ulong\_floor\_sqrt<!-- {{#callable_declaration:fd_ulong_floor_sqrt}} -->
Calculates the largest integer less than or equal to the square root of a given unsigned long integer.
- **Description**: Use this function to compute the integer part of the square root of a non-negative unsigned long integer. It is particularly useful when you need to perform integer arithmetic operations that involve square roots without resorting to floating-point calculations. The function handles the edge case where the input is zero by returning zero. It is designed to be efficient and should be used when performance is a concern, such as in mathematical computations or algorithms that require precise integer square roots.
- **Inputs**:
    - `x`: An unsigned long integer for which the floor of the square root is to be calculated. The value must be non-negative, and the function will return zero if the input is zero.
- **Output**: The function returns the largest integer y such that y^2 is less than or equal to x.
- **See also**: [`fd_ulong_floor_sqrt`](fd_bits.c.driver.md#fd_ulong_floor_sqrt)  (Implementation)


---
### fd\_ulong\_round\_sqrt<!-- {{#callable_declaration:fd_ulong_round_sqrt}} -->
Calculates the rounded square root of an unsigned long integer.
- **Description**: This function computes the integer value closest to the square root of a given unsigned long integer, rounding ties towards zero. It is useful when an exact integer representation of the square root is needed, such as in mathematical computations or optimizations where floating-point precision is not required. The function should be called with a non-negative input, as it is designed to handle unsigned long integers. If the input is zero, the function returns zero.
- **Inputs**:
    - `x`: An unsigned long integer for which the rounded square root is to be calculated. The input must be non-negative, and the function handles zero by returning zero.
- **Output**: Returns the unsigned long integer closest to the square root of the input, with ties rounded towards zero.
- **See also**: [`fd_ulong_round_sqrt`](fd_bits.c.driver.md#fd_ulong_round_sqrt)  (Implementation)


---
### fd\_ulong\_ceil\_sqrt<!-- {{#callable_declaration:fd_ulong_ceil_sqrt}} -->
Calculates the smallest integer greater than or equal to the square root of a given unsigned long integer.
- **Description**: Use this function to determine the smallest integer that is greater than or equal to the square root of a given unsigned long integer. It is particularly useful when you need to ensure that the result is rounded up to the nearest whole number. The function handles the edge case where the input is zero by returning zero. It is designed to be efficient and should be used when precise integer results are required for square root calculations.
- **Inputs**:
    - `x`: An unsigned long integer for which the ceiling of the square root is to be calculated. The value must be non-negative, and the function will return zero if the input is zero.
- **Output**: Returns the smallest unsigned long integer that is greater than or equal to the square root of the input value.
- **See also**: [`fd_ulong_ceil_sqrt`](fd_bits.c.driver.md#fd_ulong_ceil_sqrt)  (Implementation)


---
### fd\_ulong\_approx\_cbrt<!-- {{#callable_declaration:fd_ulong_approx_cbrt}} -->
Approximates the cube root of an unsigned long integer.
- **Description**: Use this function to quickly estimate the cube root of a given unsigned long integer. It is designed to provide a fast approximation with an accuracy of approximately ±0.8%. This function is useful in scenarios where a precise cube root is not necessary, and performance is a priority. The function handles the edge case where the input is zero by returning zero. It is a constant function, meaning it does not modify any state or input parameters.
- **Inputs**:
    - `x`: An unsigned long integer for which the cube root is to be approximated. The input must be a non-negative integer, and the function will return zero if the input is zero.
- **Output**: Returns an unsigned long integer representing the approximate cube root of the input.
- **See also**: [`fd_ulong_approx_cbrt`](fd_bits.c.driver.md#fd_ulong_approx_cbrt)  (Implementation)


---
### fd\_ulong\_floor\_cbrt<!-- {{#callable_declaration:fd_ulong_floor_cbrt}} -->
Calculates the largest integer cube root less than or equal to a given unsigned long integer.
- **Description**: Use this function to find the largest integer y such that y^3 is less than or equal to the given unsigned long integer x. This function is useful when you need to determine the integer cube root of a number without exceeding it. It handles the edge case where x is zero by returning zero immediately. The function is designed to be efficient and should be used when precise integer cube roots are required.
- **Inputs**:
    - `x`: An unsigned long integer for which the cube root is to be calculated. The value must be non-negative, and the function handles the case where x is zero by returning zero.
- **Output**: Returns the largest unsigned long integer y such that y^3 <= x.
- **See also**: [`fd_ulong_floor_cbrt`](fd_bits.c.driver.md#fd_ulong_floor_cbrt)  (Implementation)


---
### fd\_ulong\_round\_cbrt<!-- {{#callable_declaration:fd_ulong_round_cbrt}} -->
Calculates the rounded cube root of an unsigned long integer.
- **Description**: Use this function to compute the cube root of an unsigned long integer, rounded to the nearest integer. It is suitable for cases where an exact integer result is needed for the cube root of a number. The function handles the edge case where the input is zero by returning zero. It is expected that the input is a valid unsigned long integer, and the function will return a meaningful result for any such input.
- **Inputs**:
    - `x`: An unsigned long integer for which the cube root is to be calculated. The input must be a valid ulong value, and the function will handle the case where x is zero by returning zero.
- **Output**: The function returns the cube root of the input x, rounded to the nearest integer, as an unsigned long integer.
- **See also**: [`fd_ulong_round_cbrt`](fd_bits.c.driver.md#fd_ulong_round_cbrt)  (Implementation)


---
### fd\_ulong\_ceil\_cbrt<!-- {{#callable_declaration:fd_ulong_ceil_cbrt}} -->
Calculates the smallest integer cube root greater than or equal to the given value.
- **Description**: Use this function to find the smallest integer y such that y^3 is greater than or equal to the input x. This is useful in scenarios where you need to partition a volume or space into cubic units and want to ensure that the entire space is covered. The function handles the edge case where x is zero by returning zero. It is expected that the input is a non-negative unsigned long integer.
- **Inputs**:
    - `x`: An unsigned long integer representing the value for which the ceiling of the cube root is to be calculated. Must be non-negative. If x is zero, the function returns zero.
- **Output**: Returns the smallest unsigned long integer y such that y^3 is greater than or equal to x.
- **See also**: [`fd_ulong_ceil_cbrt`](fd_bits.c.driver.md#fd_ulong_ceil_cbrt)  (Implementation)


