# Purpose
The provided C header file defines a high-quality, non-cryptographic pseudo-random number generator (PRNG) that supports various advanced features such as parallel generation, interprocess shared memory usage, checkpointing, random access, and reversibility. The file is structured to facilitate the creation and manipulation of PRNG instances, which are represented by the `fd_rng_t` type. This type is treated as an opaque handle, although its internal structure is exposed to allow for inlining of operations. The PRNG is designed to pass strict randomness tests and is based on a 64-bit integer hash function that ensures a permutation of the integer space, providing a long period and high-quality randomness.

The file includes a comprehensive set of functions for initializing, joining, and managing the lifecycle of PRNG instances, as well as generating random numbers of various types and distributions. These include uniform random integers and floating-point numbers, as well as more complex distributions like exponential and normal. The file also provides utility functions for converting random integers to floating-point numbers with different rounding modes. Additionally, the header includes a function for obtaining cryptographically secure random bytes from the platform's secure RNG, with support for Linux, FreeBSD, and macOS. The design emphasizes efficiency and robustness, with careful attention to alignment and memory footprint requirements, making it suitable for high-performance applications that require reliable random number generation.
# Imports and Dependencies

---
- `../bits/fd_bits.h`


# Global Variables

---
### fd\_rng\_secure
- **Type**: `function`
- **Description**: The `fd_rng_secure` function is designed to fill a specified memory region with cryptographically secure random bytes. It uses platform-specific secure random number generation facilities to ensure the randomness is unguessable and suitable for cryptographic purposes.
- **Use**: This function is used to obtain secure random bytes for cryptographic operations, ensuring the data is filled with high-entropy random values.


# Data Structures

---
### fd\_rng\_private
- **Type**: `struct`
- **Members**:
    - `seq`: A 64-bit unsigned long integer representing the sequence used by the random number generator.
    - `idx`: A 64-bit unsigned long integer representing the current index or position in the random number sequence.
- **Description**: The `fd_rng_private` structure is a fundamental component of a pseudo-random number generator designed for high performance and quality in non-cryptographic applications. It contains two members: `seq`, which is used to store the sequence identifier for generating random numbers, and `idx`, which tracks the current position within the sequence. This structure is aligned according to `FD_RNG_ALIGN` to ensure optimal memory access and performance. The `fd_rng_private` structure is used internally to manage the state of the random number generator, allowing for operations such as sequence expansion, contraction, and random number generation with various properties and distributions.


---
### fd\_rng\_t
- **Type**: `struct`
- **Members**:
    - `seq`: A 64-bit unsigned long representing the sequence used by the random number generator.
    - `idx`: A 64-bit unsigned long representing the current index or position in the random number sequence.
- **Description**: The `fd_rng_t` is a data structure representing a pseudo-random number generator (PRNG) that is designed for high performance and quality in non-cryptographic applications. It is implemented as a struct with two members: `seq`, which is a sequence identifier expanded from a 32-bit value to a 64-bit non-sparse value to ensure randomness and reduce correlations, and `idx`, which tracks the current position in the sequence. This PRNG supports features such as parallel generation, interprocess shared memory usage, and checkpointing, and it passes strict randomness tests. The structure is aligned to 16 bytes to facilitate efficient memory access and operations.


# Functions

---
### fd\_rng\_private\_expand<!-- {{#callable:fd_rng_private_expand}} -->
The `fd_rng_private_expand` function expands a 32-bit integer into a unique 64-bit non-sparse value using a hash function and a specific XOR constant.
- **Inputs**:
    - `seq`: A 32-bit unsigned integer that represents the sequence to be expanded into a 64-bit value.
- **Control Flow**:
    - The function takes a 32-bit unsigned integer `seq` as input.
    - It casts `seq` to a 64-bit unsigned integer and XORs it with the constant `0x900df00d00000000UL`.
    - The result of the XOR operation is passed to the `fd_ulong_hash` function, which is assumed to be a high-quality 64-bit hash function.
    - The function returns the hashed value, which is a 64-bit unsigned integer.
- **Output**: A 64-bit unsigned integer that is a non-sparse expansion of the input 32-bit integer, ensuring the original value can be recovered and that zero expands to a non-zero value.


---
### fd\_rng\_private\_contract<!-- {{#callable:fd_rng_private_contract}} -->
The `fd_rng_private_contract` function extracts the original 32-bit sequence from its expanded 64-bit value using an inverse hash function.
- **Inputs**:
    - `eseq`: A 64-bit unsigned long integer representing the expanded sequence value from which the original 32-bit sequence needs to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_hash_inverse` with `eseq` as the argument to compute the inverse hash.
    - The result of the inverse hash is cast to a 32-bit unsigned integer and returned.
- **Output**: A 32-bit unsigned integer representing the original sequence extracted from the expanded value.


---
### fd\_rng\_align<!-- {{#callable:fd_rng_align}} -->
The `fd_rng_align` function returns the memory alignment requirement for the `fd_rng_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_rng_t` type.
    - The function returns this alignment value as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the alignment requirement of the `fd_rng_t` type.


---
### fd\_rng\_footprint<!-- {{#callable:fd_rng_footprint}} -->
The `fd_rng_footprint` function returns the memory footprint size required for an `fd_rng_t` pseudo-random number generator state.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and suggests potential for inlining by the compiler.
    - It uses the `sizeof` operator to determine the size of the `fd_rng_t` structure, which represents the state of the random number generator.
- **Output**: The function returns an `ulong` representing the size in bytes of the `fd_rng_t` structure.


---
### fd\_rng\_new<!-- {{#callable:fd_rng_new}} -->
The `fd_rng_new` function initializes a memory region as a pseudo-random number generator with a specified sequence and index.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be formatted as a pseudo-random number generator; it must be non-NULL and properly aligned.
    - `seq`: A 32-bit unsigned integer representing the initial sequence for the random number generator.
    - `idx`: A 64-bit unsigned integer representing the starting index for the random number generator.
- **Control Flow**:
    - Cast the memory pointer `mem` to a `fd_rng_t` pointer `rng`.
    - Expand the 32-bit sequence `seq` to a 64-bit value using [`fd_rng_private_expand`](#fd_rng_private_expand) and assign it to `rng->seq`.
    - Assign the index `idx` to `rng->idx`.
    - Return the pointer to the initialized `fd_rng_t` structure.
- **Output**: A pointer to the initialized `fd_rng_t` structure, which is the same as the input `mem` pointer.
- **Functions called**:
    - [`fd_rng_private_expand`](#fd_rng_private_expand)


---
### fd\_rng\_join<!-- {{#callable:fd_rng_join}} -->
The `fd_rng_join` function casts a generic pointer to a specific type pointer for a pseudo-random number generator.
- **Inputs**:
    - `_rng`: A void pointer to a memory region that holds the state of a pseudo-random number generator.
- **Control Flow**:
    - The function takes a void pointer as input.
    - It casts the void pointer to a pointer of type `fd_rng_t`.
    - The function returns the casted pointer.
- **Output**: A pointer of type `fd_rng_t` that represents the joined state of the pseudo-random number generator.


---
### fd\_rng\_leave<!-- {{#callable:fd_rng_leave}} -->
The `fd_rng_leave` function returns a pointer to the memory region holding the state of a pseudo-random number generator (PRNG) after leaving the current join.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure representing the current state of the PRNG.
- **Control Flow**:
    - The function takes a pointer to an `fd_rng_t` structure as input.
    - It casts this pointer to a `void *` type.
    - The function then returns this casted pointer.
- **Output**: A `void *` pointer to the memory region holding the state of the PRNG.


---
### fd\_rng\_delete<!-- {{#callable:fd_rng_delete}} -->
The `fd_rng_delete` function returns the pointer to the memory region that was used to hold the state of a pseudo-random number generator, effectively unformatting it.
- **Inputs**:
    - `_rng`: A pointer to the memory region that holds the state of a pseudo-random number generator.
- **Control Flow**:
    - The function takes a single argument, `_rng`, which is a pointer to a memory region.
    - It simply returns the same pointer `_rng` without any modification or additional operations.
- **Output**: A pointer to the memory region that was used to hold the state of the pseudo-random number generator, effectively returning ownership of the memory to the caller.


---
### fd\_rng\_seq<!-- {{#callable:fd_rng_seq}} -->
The `fd_rng_seq` function retrieves the original 32-bit sequence identifier from the expanded sequence value stored in a pseudo-random number generator's state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of a pseudo-random number generator.
- **Control Flow**:
    - The function takes a pointer to an `fd_rng_t` structure as input.
    - It accesses the `seq` field of the `fd_rng_t` structure, which is a 64-bit expanded sequence value.
    - The function calls [`fd_rng_private_contract`](#fd_rng_private_contract) with the expanded sequence value to extract the original 32-bit sequence identifier.
    - The extracted 32-bit sequence identifier is returned as the output of the function.
- **Output**: The function returns a `uint`, which is the original 32-bit sequence identifier extracted from the expanded sequence value.
- **Functions called**:
    - [`fd_rng_private_contract`](#fd_rng_private_contract)


---
### fd\_rng\_idx<!-- {{#callable:fd_rng_idx}} -->
The `fd_rng_idx` function retrieves the current index of the next slot to be consumed by the pseudo-random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure representing the state of the pseudo-random number generator.
- **Control Flow**:
    - The function accesses the `idx` field of the `fd_rng_t` structure pointed to by `rng`.
- **Output**: The function returns the value of the `idx` field, which is an `ulong` representing the next slot index in the random number generator sequence.


---
### fd\_rng\_seq\_set<!-- {{#callable:fd_rng_seq_set}} -->
The `fd_rng_seq_set` function sets a new sequence value for a pseudo-random number generator and returns the previous sequence value.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure representing the pseudo-random number generator whose sequence is to be set.
    - `seq`: A `uint` representing the new sequence value to be set for the random number generator.
- **Control Flow**:
    - Retrieve the current sequence value from the `rng` using [`fd_rng_seq`](#fd_rng_seq) and store it in `old`.
    - Expand the new sequence value `seq` using [`fd_rng_private_expand`](#fd_rng_private_expand) and assign it to `rng->seq`.
    - Return the old sequence value stored in `old`.
- **Output**: The function returns the previous sequence value of the random number generator as a `uint`.
- **Functions called**:
    - [`fd_rng_seq`](#fd_rng_seq)
    - [`fd_rng_private_expand`](#fd_rng_private_expand)


---
### fd\_rng\_idx\_set<!-- {{#callable:fd_rng_idx_set}} -->
The `fd_rng_idx_set` function sets the index of the next slot to be consumed by a pseudo-random number generator and returns the previous index value.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure representing the pseudo-random number generator whose index is to be set.
    - `idx`: An unsigned long integer representing the new index value to be set for the random number generator.
- **Control Flow**:
    - Retrieve the current index of the random number generator using [`fd_rng_idx`](#fd_rng_idx) and store it in `old`.
    - Set the `idx` field of the `rng` structure to the new index value provided by the `idx` parameter.
    - Return the old index value stored in `old`.
- **Output**: The function returns the previous index value of the random number generator as an unsigned long integer.
- **Functions called**:
    - [`fd_rng_idx`](#fd_rng_idx)


---
### fd\_rng\_uchar<!-- {{#callable:fd_rng_uchar}} -->
The `fd_rng_uchar` function generates a pseudo-random unsigned character (uchar) using a hash function on a sequence and index from a random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which holds the state of the random number generator, including a sequence (`seq`) and an index (`idx`).
- **Control Flow**:
    - The function takes a pointer to an `fd_rng_t` structure as input.
    - It computes a hash using `fd_ulong_hash` on the XOR of the sequence (`rng->seq`) and the current index (`rng->idx`).
    - The index (`rng->idx`) is incremented after the hash computation.
    - The result of the hash is cast to an `uchar` and returned.
- **Output**: The function returns a pseudo-random `uchar` value, which is the result of hashing the XOR of the sequence and index from the RNG state.


---
### fd\_rng\_ushort<!-- {{#callable:fd_rng_ushort}} -->
The `fd_rng_ushort` function generates a pseudo-random unsigned short integer using a hash function on a sequence and index from a random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which holds the state of the pseudo-random number generator, including a sequence (`seq`) and an index (`idx`).
- **Control Flow**:
    - The function takes a pointer to an `fd_rng_t` structure as input.
    - It computes a hash using `fd_ulong_hash` on the XOR of the sequence (`rng->seq`) and the current index (`rng->idx`).
    - The index (`rng->idx`) is incremented after the hash computation.
    - The result of the hash is cast to an `ushort` and returned.
- **Output**: The function returns a pseudo-random `ushort` integer, which is the result of hashing the XOR of the sequence and index from the RNG state.


---
### fd\_rng\_uint<!-- {{#callable:fd_rng_uint}} -->
The `fd_rng_uint` function generates a pseudo-random unsigned integer using a permutation of the internal state of a random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which holds the state of the random number generator.
- **Control Flow**:
    - The function takes the `seq` field from the `rng` structure and XORs it with the `idx` field, which is then incremented.
    - The result of the XOR operation is passed to the `fd_ulong_hash` function, which returns a hashed value.
    - The hashed value is cast to an `unsigned int` and returned as the output of the function.
- **Output**: An unsigned integer that is a pseudo-random number generated from the internal state of the `rng`.


---
### fd\_rng\_ulong<!-- {{#callable:fd_rng_ulong}} -->
The `fd_rng_ulong` function generates a 64-bit unsigned long random number using a pseudo-random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - Call [`fd_rng_uint`](#fd_rng_uint) with `rng` to generate a 32-bit random number and cast it to `ulong`, storing it in `hi`.
    - Shift `hi` left by 32 bits to make space for another 32-bit number.
    - Call [`fd_rng_uint`](#fd_rng_uint) again with `rng` to generate another 32-bit random number, cast it to `ulong`, and combine it with the shifted `hi` using a bitwise OR operation.
    - Return the combined 64-bit number as the result.
- **Output**: A 64-bit unsigned long integer representing a random number generated by the pseudo-random number generator.
- **Functions called**:
    - [`fd_rng_uint`](#fd_rng_uint)


---
### fd\_rng\_schar<!-- {{#callable:fd_rng_schar}} -->
The `fd_rng_schar` function generates a pseudo-random signed character by right-shifting the result of a pseudo-random unsigned character generation.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_uchar`](#fd_rng_uchar) with the `rng` pointer to generate a pseudo-random unsigned character.
    - The result from [`fd_rng_uchar`](#fd_rng_uchar) is right-shifted by one bit to convert it into a signed character range.
    - The shifted result is cast to a `schar` type and returned.
- **Output**: A pseudo-random signed character (`schar`) in the range [0, 127].
- **Functions called**:
    - [`fd_rng_uchar`](#fd_rng_uchar)


---
### fd\_rng\_short<!-- {{#callable:fd_rng_short}} -->
The `fd_rng_short` function generates a pseudo-random short integer by right-shifting the result of [`fd_rng_ushort`](#fd_rng_ushort) by one bit.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_ushort`](#fd_rng_ushort) with the provided `rng` pointer to generate a pseudo-random unsigned short integer.
    - The result from [`fd_rng_ushort`](#fd_rng_ushort) is right-shifted by one bit to convert it into a signed short integer.
    - The function returns the resulting signed short integer.
- **Output**: A signed short integer in the range [0, 2^15), derived from the pseudo-random sequence.
- **Functions called**:
    - [`fd_rng_ushort`](#fd_rng_ushort)


---
### fd\_rng\_int<!-- {{#callable:fd_rng_int}} -->
The `fd_rng_int` function generates a pseudo-random integer in the range [0, 2^31) using a given random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which holds the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_uint`](#fd_rng_uint) with the `rng` argument to generate a 32-bit unsigned integer pseudo-random number.
    - The result from [`fd_rng_uint`](#fd_rng_uint) is right-shifted by 1 bit to convert it into a signed integer in the range [0, 2^31).
    - The shifted value is cast to an `int` type and returned as the output.
- **Output**: An `int` representing a pseudo-random number in the range [0, 2^31).
- **Functions called**:
    - [`fd_rng_uint`](#fd_rng_uint)


---
### fd\_rng\_long<!-- {{#callable:fd_rng_long}} -->
The `fd_rng_long` function generates a pseudo-random long integer by right-shifting the result of [`fd_rng_ulong`](#fd_rng_ulong) by one bit.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_ulong`](#fd_rng_ulong) with the `rng` pointer to generate a pseudo-random unsigned long integer.
    - The result from [`fd_rng_ulong`](#fd_rng_ulong) is right-shifted by one bit to convert it into a signed long integer.
    - The shifted value is cast to a `long` and returned.
- **Output**: A pseudo-random long integer in the range [0, 2^63).
- **Functions called**:
    - [`fd_rng_ulong`](#fd_rng_ulong)


---
### fd\_rng\_uint128<!-- {{#callable:fd_rng_uint128}} -->
The `fd_rng_uint128` function generates a 128-bit unsigned integer using a pseudo-random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_ulong`](#fd_rng_ulong) twice, each time generating a 64-bit unsigned integer from the random number generator state `rng`.
    - The first 64-bit integer is shifted left by 64 bits to occupy the higher half of the 128-bit result.
    - The second 64-bit integer is combined with the shifted first integer using a bitwise OR operation to form the final 128-bit unsigned integer.
- **Output**: A 128-bit unsigned integer (`uint128`) that is pseudo-randomly generated.
- **Functions called**:
    - [`fd_rng_ulong`](#fd_rng_ulong)


---
### fd\_rng\_int128<!-- {{#callable:fd_rng_int128}} -->
The `fd_rng_int128` function generates a pseudo-random signed 128-bit integer using a given random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_uint128`](#fd_rng_uint128) with the `rng` argument to generate a random unsigned 128-bit integer.
    - The result from [`fd_rng_uint128`](#fd_rng_uint128) is right-shifted by one bit to convert it into a signed 128-bit integer.
    - The shifted value is cast to `int128` and returned.
- **Output**: A signed 128-bit integer (`int128`) that is pseudo-randomly generated.
- **Functions called**:
    - [`fd_rng_uint128`](#fd_rng_uint128)


---
### fd\_rng\_uint\_to\_float\_c0<!-- {{#callable:fd_rng_uint_to_float_c0}} -->
The function `fd_rng_uint_to_float_c0` converts a 32-bit unsigned integer to a single-precision floating-point number in the range [0,1) by scaling and shifting the integer.
- **Inputs**:
    - `u`: A 32-bit unsigned integer that serves as the input to be converted into a floating-point number.
- **Control Flow**:
    - The function takes the input unsigned integer `u` and right shifts it by 8 bits (32-24) to extract the top 24 bits.
    - The extracted bits are cast to a signed integer and then to a float.
    - This float is multiplied by the constant `1.f/(1 << 24)` to scale it into the range [0,1).
    - The result is returned as the output of the function.
- **Output**: A single-precision floating-point number representing a uniformly distributed random value in the range [0,1), excluding 1.


---
### fd\_rng\_uint\_to\_float\_c1<!-- {{#callable:fd_rng_uint_to_float_c1}} -->
The `fd_rng_uint_to_float_c1` function converts a uniformly distributed unsigned integer to a floating-point number in the interval (0,1] with appropriate rounding.
- **Inputs**:
    - `u`: An unsigned integer representing a uniformly distributed random number.
- **Control Flow**:
    - The function shifts the input integer `u` right by 8 bits (32-24) to reduce its range.
    - It adds 1 to the shifted result to ensure the output is in the interval (0,1].
    - The result is cast to an integer and then to a float.
    - The float is multiplied by a constant factor (1.f/(1<<24)) to scale it to the desired range.
- **Output**: A floating-point number in the interval (0,1] representing the scaled and rounded version of the input integer.


---
### fd\_rng\_uint\_to\_float\_c<!-- {{#callable:fd_rng_uint_to_float_c}} -->
The `fd_rng_uint_to_float_c` function converts a 32-bit unsigned integer into a floating-point number in the range [0,1] using a specific rounding method.
- **Inputs**:
    - `u`: A 32-bit unsigned integer that serves as the input to be converted into a floating-point number.
- **Control Flow**:
    - The function shifts the input integer `u` right by 8 bits (32-24) to extract the top 24 bits.
    - It adds the least significant bit of `u` (using `u & 1U`) to the shifted result to determine rounding direction.
    - The result is cast to an integer and then to a float.
    - The float is multiplied by the constant `1.f/(1 << 24)` to scale it into the range [0,1].
- **Output**: A floating-point number in the range [0,1] that represents the input integer `u` converted with rounding to the nearest even interval.


---
### fd\_rng\_uint\_to\_float\_o<!-- {{#callable:fd_rng_uint_to_float_o}} -->
The `fd_rng_uint_to_float_o` function converts a 32-bit unsigned integer into a floating-point number in the open interval (0,1) with a specific rounding method.
- **Inputs**:
    - `u`: A 32-bit unsigned integer that serves as the input to be converted into a floating-point number.
- **Control Flow**:
    - The function shifts the input integer `u` right by 8 bits (32-24) to reduce its range.
    - It then performs a bitwise OR operation with `1U` to ensure the result is never zero, effectively ensuring the output is in the open interval (0,1).
    - The result is cast to an integer and then to a float.
    - The float is multiplied by the constant `1.f/(1 << 24)` to scale it into the desired range of (0,1).
- **Output**: A floating-point number in the open interval (0,1), derived from the input integer `u`.


---
### fd\_rng\_ulong\_to\_double\_c0<!-- {{#callable:fd_rng_ulong_to_double_c0}} -->
The `fd_rng_ulong_to_double_c0` function converts a 64-bit unsigned integer to a double precision floating-point number in the range [0,1) by scaling and shifting the integer's bits.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing a random number to be converted to a double in the range [0,1).
- **Control Flow**:
    - The function shifts the input `u` right by 11 bits (64-53) to extract the top 53 bits of the 64-bit integer.
    - It casts the result to a signed long integer to ensure proper conversion to a double.
    - The function then multiplies this value by the constant `1.0 / (1L << 53)` to scale it into the range [0,1).
- **Output**: A double precision floating-point number in the range [0,1), representing the scaled and shifted version of the input integer.


---
### fd\_rng\_ulong\_to\_double\_c1<!-- {{#callable:fd_rng_ulong_to_double_c1}} -->
The `fd_rng_ulong_to_double_c1` function converts a 64-bit unsigned integer to a double precision floating-point number in the interval (0,1] with appropriate rounding.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing a random number to be converted to a double.
- **Control Flow**:
    - The function shifts the input `u` right by 11 bits (64-53) to reduce its range to fit within the precision of a double.
    - It adds 1 to the shifted value to ensure the result is in the interval (0,1].
    - The result is then cast to a long and converted to a double.
    - Finally, the function multiplies this double by the constant `1/(2^53)` to scale it to the desired range.
- **Output**: A double precision floating-point number in the interval (0,1].


---
### fd\_rng\_ulong\_to\_double\_c<!-- {{#callable:fd_rng_ulong_to_double_c}} -->
The function `fd_rng_ulong_to_double_c` converts a 64-bit unsigned integer to a double precision floating-point number in the range [0,1] with rounding towards the nearest even number.
- **Inputs**:
    - `u`: A 64-bit unsigned integer that serves as the input to be converted into a double precision floating-point number.
- **Control Flow**:
    - The function shifts the input `u` right by 11 bits (64-53) to align the most significant 53 bits for conversion.
    - It adds the least significant bit of `u` to the shifted result to implement rounding towards the nearest even number.
    - The result is cast to a signed long and then to a double precision floating-point number.
    - The final result is scaled by multiplying with the constant `1.0 / (1L << 53)` to map the integer to the [0,1] range.
- **Output**: A double precision floating-point number in the range [0,1], representing the input integer `u` converted with rounding towards the nearest even number.


---
### fd\_rng\_ulong\_to\_double\_o<!-- {{#callable:fd_rng_ulong_to_double_o}} -->
The function `fd_rng_ulong_to_double_o` converts a 64-bit unsigned integer to a double precision floating-point number in the open interval (0,1).
- **Inputs**:
    - `u`: A 64-bit unsigned integer that serves as the input to be converted into a double.
- **Control Flow**:
    - The function shifts the input `u` right by 11 bits (64-53) to extract the top 53 bits.
    - It then performs a bitwise OR operation with `1UL` to ensure the result is non-zero.
    - The result is cast to a `long` and then to a `double`.
    - The double is multiplied by the constant `1.0 / (1L << 53)` to scale it into the range (0,1).
- **Output**: A double precision floating-point number representing a uniform random value in the open interval (0,1).


---
### fd\_rng\_float\_c0<!-- {{#callable:fd_rng_float_c0}} -->
The `fd_rng_float_c0` function generates a pseudo-random floating-point number in the range [0,1) using a given random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_uint`](#fd_rng_uint) with the `rng` argument to generate a random unsigned integer.
    - The resulting unsigned integer is passed to [`fd_rng_uint_to_float_c0`](#fd_rng_uint_to_float_c0), which converts it to a floating-point number in the range [0,1).
    - The converted floating-point number is returned as the output of the function.
- **Output**: A floating-point number in the range [0,1), representing a pseudo-random value generated from the input random number generator state.
- **Functions called**:
    - [`fd_rng_uint_to_float_c0`](#fd_rng_uint_to_float_c0)
    - [`fd_rng_uint`](#fd_rng_uint)


---
### fd\_rng\_float\_c1<!-- {{#callable:fd_rng_float_c1}} -->
The `fd_rng_float_c1` function generates a pseudo-random floating-point number in the interval (0,1] using a given random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_uint`](#fd_rng_uint) with the `rng` argument to generate a random unsigned integer.
    - The resulting unsigned integer is passed to [`fd_rng_uint_to_float_c1`](#fd_rng_uint_to_float_c1), which converts it to a floating-point number in the interval (0,1].
    - The converted floating-point number is returned as the output of the function.
- **Output**: A floating-point number in the interval (0,1], representing a pseudo-random value generated from the given RNG state.
- **Functions called**:
    - [`fd_rng_uint_to_float_c1`](#fd_rng_uint_to_float_c1)
    - [`fd_rng_uint`](#fd_rng_uint)


---
### fd\_rng\_float\_c<!-- {{#callable:fd_rng_float_c}} -->
The `fd_rng_float_c` function generates a pseudo-random floating-point number uniformly distributed in the range [0,1] using a specified random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_uint`](#fd_rng_uint) with the `rng` argument to generate a random unsigned integer.
    - The resulting unsigned integer is passed to [`fd_rng_uint_to_float_c`](#fd_rng_uint_to_float_c), which converts it to a floating-point number in the range [0,1].
    - The converted floating-point number is returned as the output of the function.
- **Output**: A floating-point number in the range [0,1], representing a uniformly distributed random value.
- **Functions called**:
    - [`fd_rng_uint_to_float_c`](#fd_rng_uint_to_float_c)
    - [`fd_rng_uint`](#fd_rng_uint)


---
### fd\_rng\_float\_o<!-- {{#callable:fd_rng_float_o}} -->
The `fd_rng_float_o` function generates a pseudo-random floating-point number in the open interval (0,1) using a given random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, representing the state of the random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_uint`](#fd_rng_uint) with the `rng` argument to generate a random unsigned integer.
    - The resulting unsigned integer is passed to [`fd_rng_uint_to_float_o`](#fd_rng_uint_to_float_o), which converts it to a floating-point number in the interval (0,1).
    - The converted floating-point number is returned as the output of the function.
- **Output**: A floating-point number in the open interval (0,1), generated from the random number generator state.
- **Functions called**:
    - [`fd_rng_uint_to_float_o`](#fd_rng_uint_to_float_o)
    - [`fd_rng_uint`](#fd_rng_uint)


---
### fd\_rng\_double\_c0<!-- {{#callable:fd_rng_double_c0}} -->
The `fd_rng_double_c0` function generates a pseudo-random double-precision floating-point number in the range [0,1) using a given random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_ulong`](#fd_rng_ulong) with the `rng` argument to generate a random unsigned long integer.
    - The result from [`fd_rng_ulong`](#fd_rng_ulong) is then passed to [`fd_rng_ulong_to_double_c0`](#fd_rng_ulong_to_double_c0), which converts the unsigned long integer to a double-precision floating-point number in the range [0,1).
    - The function returns the double-precision floating-point number generated by [`fd_rng_ulong_to_double_c0`](#fd_rng_ulong_to_double_c0).
- **Output**: A double-precision floating-point number in the range [0,1), representing a pseudo-random value.
- **Functions called**:
    - [`fd_rng_ulong_to_double_c0`](#fd_rng_ulong_to_double_c0)
    - [`fd_rng_ulong`](#fd_rng_ulong)


---
### fd\_rng\_double\_c1<!-- {{#callable:fd_rng_double_c1}} -->
The function `fd_rng_double_c1` generates a pseudo-random double-precision floating-point number in the interval (0,1] using a given random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, representing the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_ulong`](#fd_rng_ulong) with the `rng` argument to generate a random unsigned long integer.
    - The result from [`fd_rng_ulong`](#fd_rng_ulong) is passed to [`fd_rng_ulong_to_double_c1`](#fd_rng_ulong_to_double_c1), which converts the unsigned long integer to a double-precision floating-point number in the interval (0,1].
    - The converted double value is returned as the output of the function.
- **Output**: A double-precision floating-point number in the interval (0,1], representing a pseudo-random value.
- **Functions called**:
    - [`fd_rng_ulong_to_double_c1`](#fd_rng_ulong_to_double_c1)
    - [`fd_rng_ulong`](#fd_rng_ulong)


---
### fd\_rng\_double\_c<!-- {{#callable:fd_rng_double_c}} -->
The `fd_rng_double_c` function generates a pseudo-random double-precision floating-point number uniformly distributed over the interval [0,1].
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_ulong`](#fd_rng_ulong) with the `rng` argument to generate a random unsigned long integer.
    - The result from [`fd_rng_ulong`](#fd_rng_ulong) is then passed to [`fd_rng_ulong_to_double_c`](#fd_rng_ulong_to_double_c), which converts the unsigned long integer to a double-precision floating-point number in the range [0,1].
    - The function returns the double-precision floating-point number.
- **Output**: A double-precision floating-point number uniformly distributed over the interval [0,1].
- **Functions called**:
    - [`fd_rng_ulong_to_double_c`](#fd_rng_ulong_to_double_c)
    - [`fd_rng_ulong`](#fd_rng_ulong)


---
### fd\_rng\_double\_o<!-- {{#callable:fd_rng_double_o}} -->
The `fd_rng_double_o` function generates a pseudo-random double-precision floating-point number in the open interval (0,1) using a non-cryptographic random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - The function calls [`fd_rng_ulong`](#fd_rng_ulong) with the `rng` pointer to generate a random unsigned long integer.
    - The result from [`fd_rng_ulong`](#fd_rng_ulong) is passed to [`fd_rng_ulong_to_double_o`](#fd_rng_ulong_to_double_o), which converts the unsigned long to a double in the interval (0,1).
    - The converted double value is returned as the output of the function.
- **Output**: A double-precision floating-point number in the open interval (0,1), representing a pseudo-random value.
- **Functions called**:
    - [`fd_rng_ulong_to_double_o`](#fd_rng_ulong_to_double_o)
    - [`fd_rng_ulong`](#fd_rng_ulong)


---
### fd\_rng\_private\_roll32<!-- {{#callable:fd_rng_private_roll32}} -->
The `fd_rng_private_roll32` function generates a uniformly distributed random integer in the range [0, n) using a rejection sampling method.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, representing the state of the random number generator.
    - `n`: An unsigned integer specifying the upper bound of the range for the random number (exclusive).
- **Control Flow**:
    - Calculate `r` as `(-n) % n`, which is used to determine the rejection threshold.
    - Enter a loop where a random unsigned integer `u` is generated using `fd_rng_uint(rng)`.
    - Continue generating `u` until it is greater than or equal to `r`, ensuring `u` is uniformly distributed in the range [r, 2^32).
    - Return `u % n`, which is uniformly distributed in the range [0, n).
- **Output**: Returns a uniformly distributed random unsigned integer in the range [0, n).
- **Functions called**:
    - [`fd_rng_uint`](#fd_rng_uint)


---
### fd\_rng\_private\_roll64<!-- {{#callable:fd_rng_private_roll64}} -->
The `fd_rng_private_roll64` function generates a uniformly distributed random number in the range [0, n) using a rejection sampling method.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, representing the state of the random number generator.
    - `n`: An unsigned long integer specifying the upper bound of the range for the random number (exclusive).
- **Control Flow**:
    - Calculate `r` as `(-n) % n`, which is equivalent to `2^64 mod n` and used to determine the rejection threshold.
    - Enter a loop where a random unsigned long `u` is generated using `fd_rng_ulong(rng)`.
    - Continue generating `u` until `u` is greater than or equal to `r`, ensuring that `u` is uniformly distributed in the range [r, 2^64).
    - Return `u % n`, which is uniformly distributed in the range [0, n).
- **Output**: The function returns a uniformly distributed random unsigned long integer in the range [0, n).
- **Functions called**:
    - [`fd_rng_ulong`](#fd_rng_ulong)


---
### fd\_rng\_uchar\_roll<!-- {{#callable:fd_rng_uchar_roll}} -->
The `fd_rng_uchar_roll` function generates a random unsigned char value in the range [0, n) using a pseudo-random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, representing the state of the pseudo-random number generator.
    - `n`: An unsigned char value representing the upper bound (exclusive) for the random number generation.
- **Control Flow**:
    - The function calls [`fd_rng_private_roll32`](#fd_rng_private_roll32), passing the `rng` pointer and `n` cast to a `uint` as arguments.
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32) uses a rejection method to generate a random number in the range [0, n) by repeatedly generating random numbers until one is found that is within the desired range.
    - The result from [`fd_rng_private_roll32`](#fd_rng_private_roll32) is cast to an `uchar` and returned.
- **Output**: An unsigned char value representing a random number in the range [0, n).
- **Functions called**:
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32)


---
### fd\_rng\_ushort\_roll<!-- {{#callable:fd_rng_ushort_roll}} -->
The `fd_rng_ushort_roll` function generates a pseudo-random unsigned short integer in the range [0, n) using a given random number generator state.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, representing the state of the pseudo-random number generator.
    - `n`: An unsigned short integer specifying the upper bound (exclusive) for the random number generation.
- **Control Flow**:
    - The function casts the input `n` from `ushort` to `uint` to ensure compatibility with the [`fd_rng_private_roll32`](#fd_rng_private_roll32) function.
    - It calls the [`fd_rng_private_roll32`](#fd_rng_private_roll32) function, passing the `rng` and the casted `n` as arguments.
    - The [`fd_rng_private_roll32`](#fd_rng_private_roll32) function generates a random number in the range [0, n) using a rejection method to ensure uniform distribution.
    - The result from [`fd_rng_private_roll32`](#fd_rng_private_roll32) is cast back to `ushort` and returned.
- **Output**: The function returns a pseudo-random `ushort` integer in the range [0, n).
- **Functions called**:
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32)


---
### fd\_rng\_uint\_roll<!-- {{#callable:fd_rng_uint_roll}} -->
The `fd_rng_uint_roll` function generates a uniformly distributed random integer in the range [0, n) using a pseudo-random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, representing the state of the pseudo-random number generator.
    - `n`: An unsigned integer specifying the upper bound of the range (exclusive) for the random number to be generated.
- **Control Flow**:
    - The function calls [`fd_rng_private_roll32`](#fd_rng_private_roll32), passing the `rng` and `n` as arguments.
    - Inside [`fd_rng_private_roll32`](#fd_rng_private_roll32), a rejection sampling method is used to ensure the random number is uniformly distributed in the range [0, n).
    - The function calculates `r` as `(-n) % n` to determine the rejection threshold.
    - A loop generates random numbers using `fd_rng_uint` until a number `u` is found that is greater than or equal to `r`.
    - The function returns `u % n`, ensuring the result is within the desired range.
- **Output**: The function returns a uniformly distributed random unsigned integer in the range [0, n).
- **Functions called**:
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32)


---
### fd\_rng\_ulong\_roll<!-- {{#callable:fd_rng_ulong_roll}} -->
The `fd_rng_ulong_roll` function generates a random unsigned long integer in the range [0, n) using a pseudo-random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
    - `n`: An unsigned long integer representing the upper bound (exclusive) of the range for the random number.
- **Control Flow**:
    - The function calls [`fd_rng_private_roll64`](#fd_rng_private_roll64), passing the `rng` and `n` as arguments.
    - [`fd_rng_private_roll64`](#fd_rng_private_roll64) uses a rejection method to ensure the random number is uniformly distributed in the range [0, n).
    - The result from [`fd_rng_private_roll64`](#fd_rng_private_roll64) is cast to an `ulong` and returned.
- **Output**: An unsigned long integer that is a pseudo-random number uniformly distributed in the range [0, n).
- **Functions called**:
    - [`fd_rng_private_roll64`](#fd_rng_private_roll64)


---
### fd\_rng\_schar\_roll<!-- {{#callable:fd_rng_schar_roll}} -->
The `fd_rng_schar_roll` function generates a pseudo-random signed character (schar) in the range [0, n) using a specified random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
    - `n`: A signed character (schar) representing the upper bound of the range for the random number generation, which must be positive.
- **Control Flow**:
    - The function calls [`fd_rng_private_roll32`](#fd_rng_private_roll32), passing the `rng` and `n` cast to an unsigned integer.
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32) uses a rejection method to generate a uniform random number in the range [0, n) by repeatedly generating random numbers until one falls within the desired range.
    - The result from [`fd_rng_private_roll32`](#fd_rng_private_roll32) is cast back to a signed character (schar) and returned.
- **Output**: A pseudo-random signed character (schar) in the range [0, n).
- **Functions called**:
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32)


---
### fd\_rng\_short\_roll<!-- {{#callable:fd_rng_short_roll}} -->
The `fd_rng_short_roll` function generates a pseudo-random short integer in the range [0, n) using a rejection method based on a 32-bit random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
    - `n`: A short integer representing the upper bound (exclusive) of the range for the random number to be generated.
- **Control Flow**:
    - The function calls [`fd_rng_private_roll32`](#fd_rng_private_roll32), passing the `rng` pointer and `n` cast to an unsigned integer.
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32) uses a rejection method to generate a uniform random number in the range [0, n) by repeatedly generating random numbers until one falls within the desired range.
    - The result from [`fd_rng_private_roll32`](#fd_rng_private_roll32) is cast to a short integer and returned.
- **Output**: A short integer representing a pseudo-random number uniformly distributed in the range [0, n).
- **Functions called**:
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32)


---
### fd\_rng\_int\_roll<!-- {{#callable:fd_rng_int_roll}} -->
The `fd_rng_int_roll` function generates a random integer in the range [0, n) using a pseudo-random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
    - `n`: An integer representing the upper bound of the range (exclusive) for the random number to be generated.
- **Control Flow**:
    - The function calls [`fd_rng_private_roll32`](#fd_rng_private_roll32), passing the `rng` and `n` arguments.
    - Inside [`fd_rng_private_roll32`](#fd_rng_private_roll32), it calculates `r` as `(-n) % n` to determine the rejection threshold.
    - It enters a loop where it generates a random unsigned integer `u` using `fd_rng_uint(rng)` until `u` is greater than or equal to `r`.
    - Once a suitable `u` is found, it returns `u % n`, ensuring the result is uniformly distributed in the range [0, n).
- **Output**: The function returns a random integer in the range [0, n), uniformly distributed.
- **Functions called**:
    - [`fd_rng_private_roll32`](#fd_rng_private_roll32)


---
### fd\_rng\_long\_roll<!-- {{#callable:fd_rng_long_roll}} -->
The `fd_rng_long_roll` function generates a random long integer in the range [0, n) using a pseudo-random number generator.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
    - `n`: A long integer representing the upper bound (exclusive) of the range for the random number.
- **Control Flow**:
    - The function calls [`fd_rng_private_roll64`](#fd_rng_private_roll64), passing the `rng` pointer and `n` cast to an unsigned long.
    - [`fd_rng_private_roll64`](#fd_rng_private_roll64) uses a rejection method to generate a random number in the range [0, n) by repeatedly generating random numbers until one falls within the desired range.
    - The result from [`fd_rng_private_roll64`](#fd_rng_private_roll64) is cast to a long and returned.
- **Output**: A random long integer in the range [0, n).
- **Functions called**:
    - [`fd_rng_private_roll64`](#fd_rng_private_roll64)


---
### fd\_rng\_coin\_tosses<!-- {{#callable:fd_rng_coin_tosses}} -->
The `fd_rng_coin_tosses` function simulates tossing a fair coin until it lands on tails and returns the total number of tosses made.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which represents the state of the pseudo-random number generator.
- **Control Flow**:
    - Initialize a counter `cnt` to 1, representing the first coin toss.
    - Enter an infinite loop to simulate coin tosses.
    - Generate a random unsigned long integer `u` using [`fd_rng_uint`](#fd_rng_uint) function.
    - Check if `u` is non-zero; if true, break the loop as it represents a tails outcome.
    - If `u` is zero, increment `cnt` by 32, indicating 32 additional tosses were made.
    - After breaking the loop, add the position of the least significant bit set in `u` to `cnt` using `fd_ulong_find_lsb`.
    - Return the total count `cnt` as the number of tosses made.
- **Output**: The function returns an `ulong` representing the total number of coin tosses made until a tails outcome is achieved.
- **Functions called**:
    - [`fd_rng_uint`](#fd_rng_uint)


# Function Declarations (Public API)

---
### fd\_rng\_float\_robust<!-- {{#callable_declaration:fd_rng_float_robust}} -->
Generates a robust random float in the range [1,2].
- **Description**: This function generates a random floating-point number within the range [1,2], ensuring that the result is the closest exactly representable float in that range. It is useful when precise and robust random float generation is required, particularly in applications where rounding to the nearest even float is important. The function must be called with a valid random number generator that has been properly initialized and joined. It is designed to handle edge cases by rounding to the nearest even float, ensuring that all representable values in the range can be generated.
- **Inputs**:
    - `rng`: A pointer to an fd_rng_t structure representing the random number generator. It must be a valid, initialized, and joined RNG instance. The function will not work correctly if this parameter is null or points to an uninitialized RNG.
- **Output**: Returns a float representing a random number in the range [1,2], rounded to the nearest even float.
- **See also**: [`fd_rng_float_robust`](fd_rng.c.driver.md#fd_rng_float_robust)  (Implementation)


---
### fd\_rng\_float\_norm<!-- {{#callable_declaration:fd_rng_float_norm}} -->
Generates a normally distributed random float using a pseudo-random number generator.
- **Description**: Use this function to obtain a random floating-point number that follows a normal distribution with a mean of 0 and a standard deviation of 1. It is suitable for applications requiring normally distributed random numbers, such as simulations or statistical sampling. The function must be called with a valid, initialized `fd_rng_t` random number generator. The function is efficient and typically consumes one slot from the random number generator, but may consume more in rare cases. Ensure that the random number generator is properly initialized and joined before calling this function.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure representing the random number generator. It must be non-null and properly initialized. The caller retains ownership of the generator.
- **Output**: Returns a float representing a random number drawn from a standard normal distribution.
- **See also**: [`fd_rng_float_norm`](fd_rng.c.driver.md#fd_rng_float_norm)  (Implementation)


---
### fd\_rng\_double\_robust<!-- {{#callable_declaration:fd_rng_double_robust}} -->
Generates a robust double-precision random number in the range [0,1].
- **Description**: This function is used to generate a double-precision floating-point number that is uniformly distributed in the range [0,1]. It is designed to provide a robust random number generation, ensuring that the result is as close as possible to a true uniform distribution within the limits of double-precision representation. This function is suitable for applications requiring high-quality random numbers, such as simulations or statistical sampling. It must be called with a valid pseudo-random number generator (PRNG) state, which should be properly initialized and managed by the caller.
- **Inputs**:
    - `rng`: A pointer to an fd_rng_t structure representing the state of the pseudo-random number generator. This must not be null and should be properly initialized before calling this function. The caller retains ownership of this pointer.
- **Output**: Returns a double-precision floating-point number uniformly distributed in the range [0,1].
- **See also**: [`fd_rng_double_robust`](fd_rng.c.driver.md#fd_rng_double_robust)  (Implementation)


---
### fd\_rng\_double\_exp<!-- {{#callable_declaration:fd_rng_double_exp}} -->
Generates a random double with an exponential distribution.
- **Description**: This function generates a random double-precision floating-point number that follows an exponential distribution with a mean of 1. It is useful in simulations or applications requiring exponentially distributed random numbers. The function must be called with a valid pseudo-random number generator (PRNG) handle, which should be properly initialized and joined before use. The function consumes two slots from the PRNG sequence, and the result is a non-negative double.
- **Inputs**:
    - `rng`: A pointer to an fd_rng_t structure representing the pseudo-random number generator. It must not be null and should be properly initialized and joined before calling this function. The caller retains ownership of the PRNG.
- **Output**: Returns a double representing a random number with an exponential distribution, which is always non-negative.
- **See also**: [`fd_rng_double_exp`](fd_rng.c.driver.md#fd_rng_double_exp)  (Implementation)


---
### fd\_rng\_double\_norm<!-- {{#callable_declaration:fd_rng_double_norm}} -->
Generates a normally distributed random double.
- **Description**: This function generates a random double-precision floating-point number that follows a standard normal distribution (mean 0, standard deviation 1). It is suitable for applications requiring normally distributed random numbers, such as simulations or statistical sampling. The function must be called with a valid, initialized `fd_rng_t` random number generator. The caller is responsible for ensuring that the RNG is properly set up and joined before calling this function. The function is designed to be efficient and typically consumes a small number of random number generator slots per call.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` random number generator. This must be a valid, initialized, and joined RNG. The caller retains ownership and must ensure it is not null.
- **Output**: Returns a double representing a random value from a standard normal distribution.
- **See also**: [`fd_rng_double_norm`](fd_rng.c.driver.md#fd_rng_double_norm)  (Implementation)


