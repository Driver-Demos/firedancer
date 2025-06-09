# Purpose
The provided C header file, `fd_tango_base.h`, defines the foundational structures and functions for a messaging system that handles message fragments. This system is designed to manage messages originating from multiple sources, each identified by a unique 13-bit ID. The messages are divided into fragments, each with a 64-bit sequence number ensuring uniqueness and order. The file outlines the structure of message fragments, including metadata such as sequence numbers, signatures, and control bits for message reassembly. It also provides utility functions for handling sequence numbers and converting between chunk indices and local addresses.

The header file includes definitions for handling message fragment metadata using SIMD (Single Instruction, Multiple Data) instructions, specifically SSE and AVX, to optimize performance on compatible hardware. It defines constants for memory alignment and size, ensuring efficient data access and manipulation. The file also includes functions for comparing sequence numbers, incrementing or decrementing them, and calculating differences, all while considering potential sequence number wrapping. Additionally, it provides mechanisms for compressing and decompressing timestamps to optimize storage and processing. Overall, this header file is a critical component of a high-performance messaging system, providing the necessary infrastructure for managing and processing message fragments efficiently.
# Imports and Dependencies

---
- `../util/fd_util.h`
- `x86intrin.h`


# Data Structures

---
### fd\_frag\_meta
- **Type**: `union`
- **Members**:
    - `seq`: A 64-bit unsigned long representing the fragment sequence number, updated atomically.
    - `sig`: A 64-bit unsigned long for application-defined message signature, updated atomically with seq for optimal performance.
    - `chunk`: A 32-bit unsigned integer indicating the compressed relative location of the first byte of the fragment in the data region.
    - `sz`: A 16-bit unsigned short representing the fragment size in bytes.
    - `ctl`: A 16-bit unsigned short for message reassembly control bits, including flags for start-of-message, end-of-message, and error.
    - `tsorig`: A 32-bit unsigned integer for compressed timestamps indicating when the origin started producing the fragment.
    - `tspub`: A 32-bit unsigned integer for compressed timestamps indicating when the fragment was made available for consumers.
    - `sse0`: A 128-bit SSE register covering seq and sig, used for atomic operations when SSE is available.
    - `sse1`: A 128-bit SSE register covering chunk, sz, ctl, tsorig, and tspub, used for atomic operations when SSE is available.
    - `avx`: A 256-bit AVX register that can hold the metadata in a single register, possibly non-atomic.
- **Description**: The `fd_frag_meta` union is a data structure designed to store metadata for message fragments in a high-performance messaging system. It includes fields for sequence numbers, message signatures, fragment size, control bits for message reassembly, and timestamps for origin and publication. The structure is aligned for atomic operations, particularly leveraging SSE and AVX instructions for efficient processing on supported architectures. This design facilitates fast, atomic updates and queries of fragment metadata, crucial for maintaining order and integrity in distributed messaging environments.


---
### fd\_frag\_meta\_t
- **Type**: `union`
- **Members**:
    - `seq`: A 64-bit sequence number for the message fragment, updated atomically.
    - `sig`: A 64-bit application-defined message signature for fast consumer-side filtering.
    - `chunk`: A 32-bit compressed relative location of the first byte of the fragment in the data region.
    - `sz`: A 16-bit size of the fragment in bytes.
    - `ctl`: A 16-bit control field for message reassembly, including flags for start-of-message, end-of-message, and error.
    - `tsorig`: A 32-bit compressed timestamp indicating when the fragment's origin started producing it.
    - `tspub`: A 32-bit compressed timestamp indicating when the fragment was made available for consumers.
    - `sse0`: A 128-bit SSE register covering the seq and sig fields, updated atomically if SSE is available.
    - `sse1`: A 128-bit SSE register covering the chunk, sz, ctl, tsorig, and tspub fields, updated atomically if SSE is available.
    - `avx`: A 256-bit AVX register that can hold the entire metadata, possibly non-atomic.
- **Description**: The `fd_frag_meta_t` is a union data structure designed to store metadata for message fragments in a high-performance messaging system. It includes fields for sequence numbers, message signatures, fragment size, control bits for message reassembly, and timestamps for origin and publication. The structure is optimized for atomic updates and efficient access using SIMD instructions (SSE and AVX) when available, ensuring that metadata operations can be performed quickly and safely in concurrent environments. This design facilitates the management of message fragments, allowing for efficient filtering, reassembly, and diagnostics in distributed systems.


# Functions

---
### fd\_seq\_lt<!-- {{#callable:fd_seq_lt}} -->
The `fd_seq_lt` function compares two 64-bit sequence numbers to determine if the first is less than the second, accounting for sequence number wrapping.
- **Inputs**:
    - `a`: The first 64-bit unsigned long sequence number to compare.
    - `b`: The second 64-bit unsigned long sequence number to compare.
- **Control Flow**:
    - The function calculates the difference between the two sequence numbers by subtracting `b` from `a`.
    - The result of the subtraction is cast to a signed long integer.
    - The function returns true (non-zero) if the result is less than zero, indicating that `a` is less than `b` when considering sequence number wrapping.
- **Output**: An integer value (0 or 1) indicating whether the first sequence number is less than the second, considering wrapping.


---
### fd\_seq\_le<!-- {{#callable:fd_seq_le}} -->
The `fd_seq_le` function checks if one 64-bit sequence number is less than or equal to another, considering potential sequence number wrapping.
- **Inputs**:
    - `a`: The first 64-bit unsigned integer sequence number to compare.
    - `b`: The second 64-bit unsigned integer sequence number to compare.
- **Control Flow**:
    - The function calculates the difference between the two sequence numbers by subtracting `b` from `a`.
    - It casts the result of the subtraction to a signed long integer.
    - The function then checks if the result is less than or equal to zero, which would indicate that `a` is less than or equal to `b` considering sequence number wrapping.
- **Output**: The function returns an integer value of 1 if `a` is less than or equal to `b`, and 0 otherwise.


---
### fd\_seq\_eq<!-- {{#callable:fd_seq_eq}} -->
The `fd_seq_eq` function checks if two 64-bit unsigned integers are equal.
- **Inputs**:
    - `a`: The first 64-bit unsigned integer to compare.
    - `b`: The second 64-bit unsigned integer to compare.
- **Control Flow**:
    - The function takes two unsigned long integers as input parameters.
    - It compares the two integers using the equality operator (==).
    - The result of the comparison is returned as an integer.
- **Output**: An integer value, 1 if the two input integers are equal, otherwise 0.


---
### fd\_seq\_ne<!-- {{#callable:fd_seq_ne}} -->
The `fd_seq_ne` function checks if two 64-bit unsigned integers are not equal.
- **Inputs**:
    - `a`: A 64-bit unsigned integer representing the first sequence number.
    - `b`: A 64-bit unsigned integer representing the second sequence number.
- **Control Flow**:
    - The function takes two unsigned long integers as input.
    - It compares the two integers using the 'not equal' operator (!=).
    - The result of the comparison is returned as an integer.
- **Output**: An integer value, 1 if the two numbers are not equal, and 0 if they are equal.


---
### fd\_seq\_ge<!-- {{#callable:fd_seq_ge}} -->
The `fd_seq_ge` function checks if one 64-bit unsigned sequence number is greater than or equal to another, considering potential wrapping.
- **Inputs**:
    - `a`: The first 64-bit unsigned sequence number to compare.
    - `b`: The second 64-bit unsigned sequence number to compare.
- **Control Flow**:
    - The function calculates the difference between the two sequence numbers by subtracting `b` from `a`.
    - The result of the subtraction is cast to a signed long integer.
    - The function then checks if the resulting signed long integer is greater than or equal to zero.
- **Output**: Returns an integer value of 1 if `a` is greater than or equal to `b`, otherwise returns 0.


---
### fd\_seq\_gt<!-- {{#callable:fd_seq_gt}} -->
The `fd_seq_gt` function determines if one 64-bit sequence number is greater than another, considering potential wrapping.
- **Inputs**:
    - `a`: The first 64-bit unsigned integer sequence number to compare.
    - `b`: The second 64-bit unsigned integer sequence number to compare.
- **Control Flow**:
    - The function calculates the difference between the two sequence numbers, `a` and `b`, by subtracting `b` from `a`.
    - The result of the subtraction is cast to a signed long integer to handle potential wrapping of sequence numbers.
    - The function returns true (non-zero) if the result of the subtraction is greater than zero, indicating that `a` is greater than `b`.
- **Output**: An integer value, where a non-zero result indicates that sequence number `a` is greater than sequence number `b`, and zero indicates otherwise.


---
### fd\_seq\_inc<!-- {{#callable:fd_seq_inc}} -->
The `fd_seq_inc` function increments a given sequence number by a specified delta value.
- **Inputs**:
    - `a`: The initial sequence number to be incremented.
    - `delta`: The value by which the sequence number should be incremented.
- **Control Flow**:
    - The function takes two unsigned long integers as input parameters: 'a' and 'delta'.
    - It performs a simple arithmetic addition of 'a' and 'delta'.
    - The result of the addition is returned as the output.
- **Output**: The function returns the result of adding 'delta' to 'a', which is an unsigned long integer.


---
### fd\_seq\_dec<!-- {{#callable:fd_seq_dec}} -->
The `fd_seq_dec` function decrements a given sequence number by a specified delta value.
- **Inputs**:
    - `a`: The sequence number to be decremented, represented as an unsigned long integer.
    - `delta`: The amount by which the sequence number should be decremented, also represented as an unsigned long integer.
- **Control Flow**:
    - The function takes two unsigned long integers as input parameters: 'a' and 'delta'.
    - It performs a simple arithmetic operation to subtract 'delta' from 'a'.
    - The result of the subtraction is returned as the output of the function.
- **Output**: The function returns the result of the subtraction, which is the decremented sequence number, as an unsigned long integer.


---
### fd\_seq\_diff<!-- {{#callable:fd_seq_diff}} -->
The `fd_seq_diff` function calculates the difference between two 64-bit unsigned sequence numbers, returning how many sequence numbers the first is ahead of the second.
- **Inputs**:
    - `a`: The first 64-bit unsigned sequence number.
    - `b`: The second 64-bit unsigned sequence number.
- **Control Flow**:
    - The function takes two unsigned long integers, `a` and `b`, as input parameters.
    - It computes the difference by subtracting `b` from `a`.
    - The result of the subtraction is cast to a long integer and returned.
- **Output**: A long integer representing the difference between the two sequence numbers, indicating how many sequence numbers `a` is ahead of `b`. A positive value means `a` is in the future relative to `b`, a negative value means `a` is in the past, and zero indicates they are the same.


---
### fd\_chunk\_to\_laddr<!-- {{#callable:fd_chunk_to_laddr}} -->
The `fd_chunk_to_laddr` function calculates a local address pointer for a given chunk index based on a base address.
- **Inputs**:
    - `chunk0`: A pointer to the base address of the chunk, assumed to be aligned to `FD_CHUNK_ALIGN`.
    - `chunk`: An unsigned long integer representing the chunk index, assumed to be in the range [0, UINT_MAX].
- **Control Flow**:
    - The function takes the base address `chunk0` and casts it to an unsigned long integer.
    - It shifts the `chunk` index left by `FD_CHUNK_LG_SZ` bits, effectively multiplying it by the chunk size.
    - The shifted chunk value is added to the base address to compute the local address.
    - The result is cast back to a void pointer and returned.
- **Output**: A void pointer to the calculated local address, aligned to `FD_CHUNK_ALIGN` and within the range [chunk0, chunk0 + FD_CHUNK_SZ*(UINT_MAX+1)).


---
### fd\_chunk\_to\_laddr\_const<!-- {{#callable:fd_chunk_to_laddr_const}} -->
The `fd_chunk_to_laddr_const` function calculates a constant pointer to the local address of a specific chunk based on a base address and a chunk index.
- **Inputs**:
    - `chunk0`: A constant pointer to the base address of the chunk whose index is 0, assumed to be aligned to `FD_CHUNK_ALIGN`.
    - `chunk`: An unsigned long integer representing the index of the chunk, assumed to be in the range [0, UINT_MAX].
- **Control Flow**:
    - The function takes the base address `chunk0` and casts it to an unsigned long integer.
    - It shifts the `chunk` index left by `FD_CHUNK_LG_SZ` bits to calculate the byte offset for the chunk.
    - The function adds this offset to the base address `chunk0` to compute the address of the specified chunk.
    - The result is cast back to a constant void pointer and returned.
- **Output**: A constant void pointer to the local address of the specified chunk, aligned to `FD_CHUNK_ALIGN`.


---
### fd\_laddr\_to\_chunk<!-- {{#callable:fd_laddr_to_chunk}} -->
The `fd_laddr_to_chunk` function calculates the chunk index of a given local address relative to a base chunk address, assuming both are aligned and within a specified range.
- **Inputs**:
    - `chunk0`: A pointer to the base chunk address, assumed to be aligned to FD_CHUNK_ALIGN.
    - `laddr`: A pointer to the local address, assumed to be aligned to FD_CHUNK_ALIGN and within the range [chunk0, chunk0 + FD_CHUNK_SZ*(UINT_MAX+1)).
- **Control Flow**:
    - Convert both `laddr` and `chunk0` to unsigned long integers.
    - Subtract the base address `chunk0` from the local address `laddr`.
    - Right shift the result by `FD_CHUNK_LG_SZ` to calculate the chunk index.
- **Output**: An unsigned long integer representing the chunk index, which will be in the range [0, UINT_MAX].


---
### fd\_frag\_meta\_seq\_query<!-- {{#callable:fd_frag_meta_seq_query}} -->
The `fd_frag_meta_seq_query` function retrieves the sequence number from a given fragment metadata structure, ensuring memory consistency through compiler memory fences.
- **Inputs**:
    - `meta`: A pointer to a constant `fd_frag_meta_t` structure, assumed to be non-NULL, from which the sequence number is to be retrieved.
- **Control Flow**:
    - A compiler memory fence is executed to ensure memory operations are completed before accessing the sequence number.
    - The sequence number is read from the `seq` field of the `meta` structure using a volatile read to prevent compiler optimizations that might reorder operations.
    - Another compiler memory fence is executed to ensure memory operations are completed after accessing the sequence number.
    - The retrieved sequence number is returned.
- **Output**: The function returns an `ulong` representing the sequence number of the message fragment as observed at some point during the function's execution.


---
### fd\_frag\_meta\_seq\_sig\_query<!-- {{#callable:fd_frag_meta_seq_sig_query}} -->
The `fd_frag_meta_seq_sig_query` function atomically retrieves the sequence number and signature from a given fragment metadata structure using SSE instructions.
- **Inputs**:
    - `meta`: A pointer to a `fd_frag_meta_t` structure, assumed to be non-NULL, from which the sequence number and signature will be retrieved.
- **Control Flow**:
    - The function begins by enforcing a compiler memory fence to ensure memory operations are completed before proceeding.
    - It then loads the first 128-bit SSE word from the `meta` structure, which contains the sequence number and signature, using the `_mm_load_si128` intrinsic.
    - Another compiler memory fence is enforced to ensure the atomicity of the read operation.
    - Finally, the loaded SSE word is returned, containing the sequence number and signature.
- **Output**: The function returns a `__m128i` type, which is a 128-bit integer vector containing the sequence number and signature from the `meta` structure.


---
### fd\_frag\_meta\_ctl<!-- {{#callable:fd_frag_meta_ctl}} -->
The `fd_frag_meta_ctl` function encodes message fragment control bits and origin ID into a single unsigned long value.
- **Inputs**:
    - `orig`: An unsigned long representing the origin ID, assumed to be in the range [0, FD_FRAG_META_ORIG_MAX).
    - `som`: An integer where 0 indicates false and non-zero indicates true, representing the start-of-message flag.
    - `eom`: An integer where 0 indicates false and non-zero indicates true, representing the end-of-message flag.
    - `err`: An integer where 0 indicates false and non-zero indicates true, representing the error flag.
- **Control Flow**:
    - Convert each of the boolean flags (som, eom, err) to a boolean value (0 or 1) using double negation (!!).
    - Shift the boolean value of eom left by 1 bit and the boolean value of err left by 2 bits.
    - Shift the origin ID (orig) left by 3 bits.
    - Combine the boolean values and the shifted origin ID using bitwise OR operations to form a single unsigned long value.
- **Output**: An unsigned long value that encodes the origin ID and the control bits (SOM, EOM, ERR) into a single 16-bit value.


---
### fd\_frag\_meta\_ctl\_orig<!-- {{#callable:fd_frag_meta_ctl_orig}} -->
The `fd_frag_meta_ctl_orig` function extracts the origin ID from a control value by right-shifting the control bits.
- **Inputs**:
    - `ctl`: A 64-bit unsigned long integer representing the control value from which the origin ID is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter, `ctl`, which is a 64-bit unsigned long integer.
    - It performs a right bitwise shift operation on `ctl` by 3 bits.
    - The result of the shift operation is returned as the origin ID.
- **Output**: The function returns a 64-bit unsigned long integer representing the origin ID extracted from the control value.


---
### fd\_frag\_meta\_ctl\_som<!-- {{#callable:fd_frag_meta_ctl_som}} -->
The `fd_frag_meta_ctl_som` function extracts the Start-Of-Message (SOM) control bit from a given control value.
- **Inputs**:
    - `ctl`: An unsigned long integer representing the control value from which the SOM bit is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter `ctl`.
    - It performs a bitwise AND operation between `ctl` and `1UL` to isolate the least significant bit, which represents the SOM flag.
    - The result of the bitwise operation is cast to an integer and returned.
- **Output**: An integer value representing the SOM bit, where 0 indicates the absence of the SOM flag and 1 indicates its presence.


---
### fd\_frag\_meta\_ctl\_eom<!-- {{#callable:fd_frag_meta_ctl_eom}} -->
The `fd_frag_meta_ctl_eom` function extracts the 'end-of-message' (EOM) control bit from a given control value.
- **Inputs**:
    - `ctl`: An unsigned long integer representing the control value from which the EOM bit is to be extracted.
- **Control Flow**:
    - The function shifts the input `ctl` right by 1 bit.
    - It then performs a bitwise AND operation with `1UL` to isolate the EOM bit.
    - The result is cast to an integer and returned.
- **Output**: An integer representing the EOM bit, which is either 0 or 1.


---
### fd\_frag\_meta\_ctl\_err<!-- {{#callable:fd_frag_meta_ctl_err}} -->
The `fd_frag_meta_ctl_err` function extracts the error bit from a control value used in message fragment metadata.
- **Inputs**:
    - `ctl`: An unsigned long integer representing the control value from which the error bit is to be extracted.
- **Control Flow**:
    - The function shifts the input `ctl` right by 2 bits.
    - It then performs a bitwise AND operation with `1UL` to isolate the error bit.
    - The result is cast to an integer and returned.
- **Output**: An integer representing the error bit (0 or 1) extracted from the control value.


---
### fd\_frag\_meta\_sse0<!-- {{#callable:fd_frag_meta_sse0}} -->
The `fd_frag_meta_sse0` function creates a 128-bit SSE register containing two 64-bit integers, representing a sequence number and a signature, for efficient atomic operations on message fragment metadata.
- **Inputs**:
    - `seq`: A 64-bit unsigned long integer representing the sequence number of a message fragment.
    - `sig`: A 64-bit unsigned long integer representing the signature of a message fragment, used for application-defined purposes such as fast consumer-side filtering.
- **Control Flow**:
    - The function takes two unsigned long integers, `seq` and `sig`, as inputs.
    - It casts these inputs to signed long integers.
    - It uses the `_mm_set_epi64x` intrinsic to pack these two signed long integers into a 128-bit SSE register, with `sig` in the higher 64 bits and `seq` in the lower 64 bits.
    - The function returns the 128-bit SSE register.
- **Output**: A 128-bit SSE register (`__m128i`) containing the packed sequence number and signature.


---
### fd\_frag\_meta\_sse0\_seq<!-- {{#callable:fd_frag_meta_sse0_seq}} -->
The `fd_frag_meta_sse0_seq` function extracts the lower 64 bits from a 128-bit SSE register and returns it as an unsigned long integer.
- **Inputs**:
    - `sse0`: A 128-bit SSE register from which the lower 64 bits are extracted.
- **Control Flow**:
    - The function uses the intrinsic `_mm_extract_epi64` to extract the lower 64 bits from the `sse0` register.
    - The extracted 64 bits are cast to an `ulong` and returned.
- **Output**: The function returns the lower 64 bits of the input `__m128i` register as an `ulong`.


---
### fd\_frag\_meta\_sse0\_sig<!-- {{#callable:fd_frag_meta_sse0_sig}} -->
The `fd_frag_meta_sse0_sig` function extracts the second 64-bit integer from a 128-bit SSE register and returns it as an unsigned long.
- **Inputs**:
    - `sse0`: A 128-bit SSE register from which the second 64-bit integer is extracted.
- **Control Flow**:
    - The function uses the intrinsic `_mm_extract_epi64` to extract the 64-bit integer at index 1 from the `sse0` register.
    - The extracted 64-bit integer is cast to an `unsigned long` and returned.
- **Output**: The function returns an `unsigned long` representing the second 64-bit integer extracted from the input SSE register.


---
### fd\_frag\_meta\_sse1<!-- {{#callable:fd_frag_meta_sse1}} -->
The `fd_frag_meta_sse1` function packs fragment metadata into a 128-bit SSE register using specific bit manipulations.
- **Inputs**:
    - `chunk`: A 32-bit unsigned long representing the compressed relative location of the first byte of the fragment in the data region.
    - `sz`: A 16-bit unsigned long representing the fragment size in bytes.
    - `ctl`: A 16-bit unsigned long representing message reassembly control bits.
    - `tsorig`: A 32-bit unsigned long representing the timestamp when the origin started producing the fragment.
    - `tspub`: A 32-bit unsigned long representing the timestamp when the fragment was made available for consumers.
- **Control Flow**:
    - The function takes five unsigned long parameters: chunk, sz, ctl, tsorig, and tspub.
    - It combines tsorig and tspub into a 64-bit value by placing tsorig in the lower 32 bits and tspub in the upper 32 bits.
    - It combines chunk, sz, and ctl into another 64-bit value by placing chunk in the lower 32 bits, sz in the next 16 bits, and ctl in the upper 16 bits.
    - The function returns a 128-bit SSE register (__m128i) containing these two 64-bit values.
- **Output**: The function returns a 128-bit SSE register (__m128i) containing packed fragment metadata.


---
### fd\_frag\_meta\_sse1\_chunk<!-- {{#callable:fd_frag_meta_sse1_chunk}} -->
The `fd_frag_meta_sse1_chunk` function extracts the 32-bit integer from the lower part of a 128-bit SSE register and returns it as an unsigned long.
- **Inputs**:
    - `sse1`: A 128-bit integer (__m128i) from which the function extracts a 32-bit integer.
- **Control Flow**:
    - The function uses the intrinsic `_mm_extract_epi32` to extract the 32-bit integer from the 0th position of the `sse1` register.
    - The extracted 32-bit integer is cast to an unsigned integer and then to an unsigned long before being returned.
- **Output**: The function returns an unsigned long representing the 32-bit integer extracted from the `sse1` register.


---
### fd\_frag\_meta\_sse1\_sz<!-- {{#callable:fd_frag_meta_sse1_sz}} -->
The `fd_frag_meta_sse1_sz` function extracts and returns the size of a message fragment from a given 128-bit SSE register.
- **Inputs**:
    - `sse1`: A 128-bit SSE register (__m128i) containing packed message fragment metadata.
- **Control Flow**:
    - The function uses the intrinsic `_mm_extract_epi16` to extract the 16-bit integer at position 2 from the `sse1` register.
    - The extracted 16-bit integer is cast to an unsigned long type and returned as the size of the message fragment.
- **Output**: The function returns an unsigned long representing the size of the message fragment, extracted from the `sse1` register.


---
### fd\_frag\_meta\_sse1\_ctl<!-- {{#callable:fd_frag_meta_sse1_ctl}} -->
The `fd_frag_meta_sse1_ctl` function extracts and returns the control bits from the third 16-bit segment of a 128-bit SSE register.
- **Inputs**:
    - `sse1`: A 128-bit SSE register (__m128i) containing packed metadata from which the control bits are to be extracted.
- **Control Flow**:
    - The function uses the intrinsic `_mm_extract_epi16` to extract the 16-bit integer at index 3 from the `sse1` register.
    - The extracted 16-bit integer is cast to an unsigned long and returned.
- **Output**: An unsigned long representing the control bits extracted from the `sse1` register.


---
### fd\_frag\_meta\_sse1\_tsorig<!-- {{#callable:fd_frag_meta_sse1_tsorig}} -->
The function `fd_frag_meta_sse1_tsorig` extracts the original timestamp (`tsorig`) from the third 32-bit integer of a 128-bit SSE register.
- **Inputs**:
    - `sse1`: A 128-bit SSE register (`__m128i`) containing packed metadata, including the original timestamp (`tsorig`).
- **Control Flow**:
    - The function uses the intrinsic `_mm_extract_epi32` to extract the 32-bit integer at index 2 from the `sse1` register.
    - The extracted 32-bit integer is cast to an unsigned long integer (`ulong`) and returned as the original timestamp.
- **Output**: The function returns the original timestamp (`tsorig`) as an unsigned long integer (`ulong`).


---
### fd\_frag\_meta\_sse1\_tspub<!-- {{#callable:fd_frag_meta_sse1_tspub}} -->
The `fd_frag_meta_sse1_tspub` function extracts the `tspub` field from a 128-bit SSE register containing fragment metadata.
- **Inputs**:
    - `sse1`: A 128-bit SSE register (__m128i) containing fragment metadata, specifically the second aligned SSE word which includes fields like chunk, sz, ctl, tsorig, and tspub.
- **Control Flow**:
    - The function uses the intrinsic `_mm_extract_epi32` to extract the 32-bit integer at position 3 from the `sse1` register.
    - The extracted 32-bit integer is then cast to an unsigned long type.
- **Output**: The function returns the `tspub` field as an unsigned long integer, which is the timestamp when the fragment was made available for consumers.


---
### fd\_frag\_meta\_avx<!-- {{#callable:fd_frag_meta_avx}} -->
The `fd_frag_meta_avx` function packs various metadata fields into a 256-bit AVX register for efficient storage and processing.
- **Inputs**:
    - `seq`: A 64-bit sequence number representing the unique identifier for the message fragment.
    - `sig`: A 64-bit signature used for application-defined purposes, such as filtering.
    - `chunk`: A 32-bit value representing the compressed relative location of the first byte of the fragment in the data region.
    - `sz`: A 16-bit value representing the size of the fragment in bytes.
    - `ctl`: A 16-bit value containing control bits for message reassembly, including flags for start-of-message (SOM), end-of-message (EOM), and error (ERR).
    - `tsorig`: A 32-bit timestamp indicating when the origin started producing the fragment.
    - `tspub`: A 32-bit timestamp indicating when the fragment was made available for consumers.
- **Control Flow**:
    - The function takes seven input parameters: seq, sig, chunk, sz, ctl, tsorig, and tspub.
    - It combines tsorig and tspub into a single 64-bit value by shifting tspub 32 bits to the left and OR-ing it with tsorig.
    - It combines chunk, sz, and ctl into another 64-bit value by shifting sz 32 bits to the left, ctl 48 bits to the left, and OR-ing them with chunk.
    - The function then uses the _mm256_set_epi64x intrinsic to pack these two 64-bit values, along with sig and seq, into a 256-bit AVX register.
    - The function returns the packed 256-bit AVX register.
- **Output**: A 256-bit AVX register containing the packed metadata fields.


---
### fd\_frag\_meta\_avx\_seq<!-- {{#callable:fd_frag_meta_avx_seq}} -->
The `fd_frag_meta_avx_seq` function extracts the sequence number from a 256-bit AVX register containing message fragment metadata.
- **Inputs**:
    - `avx`: A 256-bit AVX register (__m256i) that holds message fragment metadata, including sequence number, signature, and other fields.
- **Control Flow**:
    - The function uses the `_mm256_extract_epi64` intrinsic to extract the 64-bit integer at index 0 from the AVX register.
    - The extracted 64-bit integer is cast to an unsigned long and returned as the sequence number.
- **Output**: The function returns an unsigned long representing the sequence number extracted from the AVX register.


---
### fd\_frag\_meta\_avx\_sig<!-- {{#callable:fd_frag_meta_avx_sig}} -->
The `fd_frag_meta_avx_sig` function extracts the 64-bit message signature from a 256-bit AVX register containing fragment metadata.
- **Inputs**:
    - `avx`: A 256-bit AVX register (`__m256i`) containing message fragment metadata.
- **Control Flow**:
    - The function uses the `_mm256_extract_epi64` intrinsic to extract the 64-bit integer from the second position (index 1) of the AVX register.
    - The extracted 64-bit integer is cast to an `ulong` type and returned.
- **Output**: The function returns the 64-bit message signature as an `ulong` extracted from the AVX register.


---
### fd\_frag\_meta\_avx\_chunk<!-- {{#callable:fd_frag_meta_avx_chunk}} -->
The `fd_frag_meta_avx_chunk` function extracts the 32-bit integer at position 4 from a 256-bit AVX register and returns it as an unsigned long.
- **Inputs**:
    - `avx`: A 256-bit AVX register (`__m256i`) from which a 32-bit integer will be extracted.
- **Control Flow**:
    - The function uses the `_mm256_extract_epi32` intrinsic to extract the 32-bit integer from the AVX register at position 4.
    - The extracted 32-bit integer is cast to an unsigned long before being returned.
- **Output**: An unsigned long representing the 32-bit integer extracted from the AVX register.


---
### fd\_frag\_meta\_avx\_sz<!-- {{#callable:fd_frag_meta_avx_sz}} -->
The `fd_frag_meta_avx_sz` function extracts and returns the size of a message fragment from a 256-bit AVX register.
- **Inputs**:
    - `avx`: A 256-bit AVX register (`__m256i`) containing packed message fragment metadata.
- **Control Flow**:
    - The function uses the `_mm256_extract_epi16` intrinsic to extract the 16-bit value at position 10 from the AVX register.
    - The extracted 16-bit value is cast to an unsigned long and returned as the size of the message fragment.
- **Output**: The function returns an `ulong` representing the size of the message fragment, extracted from the AVX register.


---
### fd\_frag\_meta\_avx\_ctl<!-- {{#callable:fd_frag_meta_avx_ctl}} -->
The `fd_frag_meta_avx_ctl` function extracts and returns the control bits from a 256-bit AVX register representing message fragment metadata.
- **Inputs**:
    - `avx`: A 256-bit AVX register containing message fragment metadata.
- **Control Flow**:
    - The function uses the `_mm256_extract_epi16` intrinsic to extract the 11th 16-bit integer from the AVX register.
    - The extracted 16-bit integer is cast to an unsigned long and returned.
- **Output**: The function returns an unsigned long representing the control bits of the message fragment.


---
### fd\_frag\_meta\_avx\_tsorig<!-- {{#callable:fd_frag_meta_avx_tsorig}} -->
The `fd_frag_meta_avx_tsorig` function extracts the `tsorig` timestamp from a 256-bit AVX register representing fragment metadata.
- **Inputs**:
    - `avx`: A 256-bit AVX register (`__m256i`) containing fragment metadata from which the `tsorig` timestamp is to be extracted.
- **Control Flow**:
    - The function uses the `_mm256_extract_epi32` intrinsic to extract the 32-bit integer located at the 6th position of the AVX register.
    - The extracted 32-bit integer is cast to an unsigned long integer (`ulong`) and returned as the `tsorig` timestamp.
- **Output**: The function returns the `tsorig` timestamp as an unsigned long integer (`ulong`).


---
### fd\_frag\_meta\_avx\_tspub<!-- {{#callable:fd_frag_meta_avx_tspub}} -->
The `fd_frag_meta_avx_tspub` function extracts the `tspub` field from a 256-bit AVX register representing fragment metadata.
- **Inputs**:
    - `avx`: A 256-bit AVX register (`__m256i`) containing packed fragment metadata.
- **Control Flow**:
    - The function uses the `_mm256_extract_epi32` intrinsic to extract the 32-bit integer at position 7 from the AVX register.
    - The extracted integer is cast to an unsigned long and returned.
- **Output**: The function returns the `tspub` field as an unsigned long, which is a 32-bit integer extracted from the AVX register.


---
### fd\_frag\_meta\_ts\_comp<!-- {{#callable:fd_frag_meta_ts_comp}} -->
The `fd_frag_meta_ts_comp` function compresses a timestamp into a 32-bit unsigned integer.
- **Inputs**:
    - `ts`: A long integer representing the timestamp to be compressed.
- **Control Flow**:
    - The function takes a long integer `ts` as input.
    - It casts `ts` to a 32-bit unsigned integer (`uint`).
    - The result is then cast to an unsigned long integer (`ulong`) and returned.
- **Output**: The function returns an unsigned long integer representing the compressed timestamp, which is in the range [0, UINT_MAX].


---
### fd\_frag\_meta\_ts\_decomp<!-- {{#callable:fd_frag_meta_ts_decomp}} -->
The `fd_frag_meta_ts_decomp` function decompresses a compressed timestamp using a reference timestamp to reconstruct the original timestamp value.
- **Inputs**:
    - `tscomp`: A compressed timestamp value, which is an unsigned long integer in the range [0, UINT_MAX].
    - `tsref`: A reference timestamp, which is a long integer used to aid in decompressing the compressed timestamp.
- **Control Flow**:
    - Calculate the most significant bits (msb) by adding the reference timestamp (tsref) to the result of `fd_ulong_mask_lsb(31)` and subtracting the compressed timestamp (tscomp).
    - Combine the most significant bits (msb) with the compressed timestamp (tscomp) using bitwise operations to reconstruct the original timestamp.
- **Output**: The function returns a long integer representing the decompressed original timestamp.


