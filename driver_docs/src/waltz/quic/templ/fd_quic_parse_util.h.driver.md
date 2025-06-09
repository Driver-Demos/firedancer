# Purpose
The provided C header file, `fd_quic_parse_util.h`, is a utility module designed to facilitate the encoding and decoding of QUIC (Quick UDP Internet Connections) protocol elements, specifically focusing on variable-length integers and packet header fields. This file is part of a larger QUIC implementation, as indicated by its inclusion of common QUIC headers and utility functions. The primary functionality of this file is to provide inline functions and macros for encoding and decoding QUIC variable-length integers (varints), which are used extensively in the QUIC protocol to efficiently represent integers of varying sizes. The file also includes functions to extract and manipulate specific bits and fields from QUIC packet headers, such as the header form, long packet type, packet number length, and stream type.

The technical components of this file include inline functions for determining the minimum size of a varint, encoding a varint into a buffer, and decoding a varint from a buffer. It also provides macros for safely encoding varints into buffers with bounds checking. Additionally, the file contains functions to extract specific header fields from QUIC packets, such as the header form bit, long packet type, and packet number length. These functions are designed to be efficient and are implemented using bitwise operations and byte manipulation techniques. The file does not define public APIs or external interfaces directly but provides utility functions that are likely used internally within a larger QUIC implementation to handle low-level protocol details.
# Imports and Dependencies

---
- `stddef.h`
- `../fd_quic_common.h`
- `../../../util/bits/fd_bits.h`


# Functions

---
### fd\_quic\_varint\_min\_sz\_unsafe<!-- {{#callable:fd_quic_varint_min_sz_unsafe}} -->
The `fd_quic_varint_min_sz_unsafe` function calculates the minimum size in bytes required to encode a given unsigned long integer as a QUIC variable-length integer.
- **Inputs**:
    - `val`: An unsigned long integer representing the value to be encoded as a QUIC variable-length integer.
- **Control Flow**:
    - The function first computes the most significant bit (MSB) of the value ORed with 0x3fUL using `fd_ulong_find_msb` to ensure a minimum size of 6 bits.
    - It then finds the MSB of the result incremented by 2 using `fd_uint_find_msb`, which determines the size class of the variable-length integer.
    - The size class is adjusted by subtracting 2, and the function returns 2 raised to the power of the size class, which gives the minimum size in bytes.
- **Output**: The function returns an unsigned integer representing the minimum number of bytes required to encode the input value as a QUIC variable-length integer.


---
### fd\_quic\_varint\_min\_sz<!-- {{#callable:fd_quic_varint_min_sz}} -->
The `fd_quic_varint_min_sz` function calculates the minimum size in bytes required to encode a given unsigned long integer as a QUIC variable-length integer.
- **Inputs**:
    - `val`: An unsigned long integer representing the value to be encoded as a QUIC variable-length integer.
- **Control Flow**:
    - The function first limits the input value `val` to a maximum of `0x3fffffffffffffffUL` using the `fd_ulong_min` function.
    - It then calls the [`fd_quic_varint_min_sz_unsafe`](#fd_quic_varint_min_sz_unsafe) function with the potentially adjusted value to determine the minimum size required for encoding.
- **Output**: The function returns an unsigned integer representing the minimum number of bytes needed to encode the input value as a QUIC variable-length integer.
- **Functions called**:
    - [`fd_quic_varint_min_sz_unsafe`](#fd_quic_varint_min_sz_unsafe)


---
### fd\_quic\_varint\_encode<!-- {{#callable:fd_quic_varint_encode}} -->
The `fd_quic_varint_encode` function encodes a given unsigned long integer into a QUIC variable-length integer format and stores it in an 8-byte array.
- **Inputs**:
    - `out`: An array of 8 unsigned characters where the encoded variable-length integer will be stored.
    - `val`: An unsigned long integer value to be encoded into the QUIC variable-length integer format.
- **Control Flow**:
    - The function first limits the input value `val` to a maximum of 0x3fffffffffffffffUL using `fd_ulong_min`.
    - It calculates the minimum size `sz` required to encode the value using [`fd_quic_varint_min_sz_unsafe`](#fd_quic_varint_min_sz_unsafe).
    - The value is then shifted left by a number of bytes determined by the size `sz` to align it for encoding.
    - The shifted value is byte-swapped using `fd_ulong_bswap` to prepare it for storage in the output array.
    - The function sets the length indication bits in the encoded value by clearing specific bits and setting others based on the size `sz`.
    - Finally, the encoded value is stored in the `out` array using `FD_STORE`, and the function returns the size `sz` of the encoded value.
- **Output**: The function returns an unsigned integer representing the size of the encoded variable-length integer.
- **Functions called**:
    - [`fd_quic_varint_min_sz_unsafe`](#fd_quic_varint_min_sz_unsafe)


---
### fd\_quic\_h0\_hdr\_form<!-- {{#callable:fd_quic_h0_hdr_form}} -->
The function `fd_quic_h0_hdr_form` extracts the 'Header Form' bit from the first byte of a QUIC v1 packet to determine if it is a long or short header packet.
- **Inputs**:
    - `hdr`: An unsigned character representing the first byte of a QUIC v1 packet header.
- **Control Flow**:
    - The function takes a single input, `hdr`, which is an unsigned character.
    - It performs a right bitwise shift by 7 on `hdr`, effectively isolating the most significant bit (MSB).
    - The result of the shift operation is returned, which will be either 0 or 1.
- **Output**: The function returns an unsigned character (uchar) that is either 0 or 1, indicating whether the packet is a short header (0) or a long header (1).


---
### fd\_quic\_h0\_long\_packet\_type<!-- {{#callable:fd_quic_h0_long_packet_type}} -->
The function `fd_quic_h0_long_packet_type` extracts the 'Long Packet Type' from the first byte of a QUIC v1 long header packet.
- **Inputs**:
    - `hdr`: An unsigned character representing the first byte of a QUIC v1 long header packet.
- **Control Flow**:
    - The function shifts the input byte `hdr` 4 bits to the right.
    - It then performs a bitwise AND operation with the value 3 (binary 11) to extract the two bits representing the 'Long Packet Type'.
- **Output**: An unsigned character representing the 'Long Packet Type', which is a value in the range [0, 3].


---
### fd\_quic\_h0\_pkt\_num\_len<!-- {{#callable:fd_quic_h0_pkt_num_len}} -->
The function `fd_quic_h0_pkt_num_len` extracts the packet number length from the first byte of a QUIC packet header.
- **Inputs**:
    - `h0`: An unsigned integer representing the first byte of a QUIC packet header.
- **Control Flow**:
    - The function performs a bitwise AND operation between the input `h0` and the constant `0x03`.
    - The result of the bitwise operation is cast to an `uchar` and returned.
- **Output**: The function returns an `uchar` representing the packet number length, which is the value of the two least significant bits of the input `h0`.


---
### fd\_quic\_initial\_h0<!-- {{#callable:fd_quic_initial_h0}} -->
The `fd_quic_initial_h0` function constructs the first byte of a QUIC initial packet header by combining a fixed bit pattern with a packet number length indicator.
- **Inputs**:
    - `pkt_num_len`: An unsigned integer representing the packet number length, which should be in the range [0,3].
- **Control Flow**:
    - The function takes an input `pkt_num_len` and performs a bitwise OR operation with the constant `0xc0`.
    - The result of this operation is cast to an `uchar` and returned as the output.
- **Output**: The function returns an `uchar` representing the first byte of a QUIC initial packet header, with the packet number length encoded in the least significant bits.


---
### fd\_quic\_handshake\_h0<!-- {{#callable:fd_quic_handshake_h0}} -->
The function `fd_quic_handshake_h0` generates a QUIC handshake header byte by combining a fixed bit pattern with a packet number length.
- **Inputs**:
    - `pkt_num_len`: An unsigned integer representing the packet number length, which should be in the range [0,3].
- **Control Flow**:
    - The function takes the input `pkt_num_len` and performs a bitwise OR operation with the constant `0xe0`.
    - The result of this operation is cast to an `uchar` and returned as the output.
- **Output**: The function returns an `uchar` that represents the handshake header byte for a QUIC packet, incorporating the specified packet number length.


---
### fd\_quic\_one\_rtt\_h0<!-- {{#callable:fd_quic_one_rtt_h0}} -->
The `fd_quic_one_rtt_h0` function constructs a QUIC short header byte for a 1-RTT packet using the spin bit, key phase, and packet number length.
- **Inputs**:
    - `spin_bit`: A uint value representing the spin bit, which should be either 0 or 1.
    - `key_phase`: A uint value representing the key phase, which should be either 0 or 1.
    - `pkt_num_len`: A uint value representing the packet number length, which should be in the range [0,3].
- **Control Flow**:
    - The function takes three input parameters: spin_bit, key_phase, and pkt_num_len.
    - It constructs a byte by setting the fixed bit pattern 0x40.
    - The spin_bit is shifted left by 5 positions and OR-ed into the byte.
    - The key_phase is shifted left by 2 positions and OR-ed into the byte.
    - The pkt_num_len is directly OR-ed into the byte.
    - The resulting byte is cast to an unsigned char and returned.
- **Output**: The function returns an unsigned char representing the constructed QUIC short header byte for a 1-RTT packet.


---
### fd\_quic\_one\_rtt\_spin\_bit<!-- {{#callable:fd_quic_one_rtt_spin_bit}} -->
The function `fd_quic_one_rtt_spin_bit` extracts the spin bit from a QUIC packet's header byte.
- **Inputs**:
    - `h0`: An unsigned integer representing the header byte of a QUIC packet.
- **Control Flow**:
    - The function takes the input `h0` and right shifts it by 5 bits.
    - It then performs a bitwise AND operation with 1 to isolate the spin bit.
    - The result is cast to an unsigned integer and returned.
- **Output**: An unsigned integer representing the extracted spin bit from the header byte.


---
### fd\_quic\_one\_rtt\_key\_phase<!-- {{#callable:fd_quic_one_rtt_key_phase}} -->
The `fd_quic_one_rtt_key_phase` function extracts the key phase bit from a QUIC packet's header byte.
- **Inputs**:
    - `h0`: An unsigned integer representing the first byte of a QUIC packet header.
- **Control Flow**:
    - The function shifts the input `h0` right by 2 bits.
    - It then performs a bitwise AND operation with 1 to isolate the key phase bit.
    - The result is cast to an unsigned integer and returned.
- **Output**: An unsigned integer representing the key phase bit, which is either 0 or 1.


---
### fd\_quic\_stream\_type<!-- {{#callable:fd_quic_stream_type}} -->
The `fd_quic_stream_type` function calculates and returns a stream type identifier for a QUIC stream based on the presence of offset, length, and finish flags.
- **Inputs**:
    - `has_off`: A `uint` indicating whether the stream has an offset (1 if true, 0 if false).
    - `has_len`: A `uint` indicating whether the stream has a length (1 if true, 0 if false).
    - `fin`: A `uint` indicating whether the stream is finished (1 if true, 0 if false).
- **Control Flow**:
    - The function takes three unsigned integer inputs: `has_off`, `has_len`, and `fin`.
    - It calculates the stream type by starting with a base value of `0x08`.
    - The function then adds `has_off` shifted left by 2 bits, `has_len` shifted left by 1 bit, and `fin` to the base value.
    - The result is cast to an `uchar` and returned.
- **Output**: The function returns an `uchar` representing the stream type identifier.


---
### fd\_quic\_varint\_decode<!-- {{#callable:fd_quic_varint_decode}} -->
The `fd_quic_varint_decode` function decodes a variable-length integer from a buffer based on the most significant two bits (msb2) indicating the size of the integer.
- **Inputs**:
    - `buf`: A pointer to an array of unsigned characters (uchar) from which the variable-length integer is to be decoded.
    - `msb2`: An unsigned integer indicating the size of the variable-length integer to decode, with values ranging from 0 to 3.
- **Control Flow**:
    - The function uses a switch statement to determine the size of the integer to decode based on the value of 'msb2'.
    - If 'msb2' is 3, it loads an 8-byte integer from 'buf', swaps the byte order, and masks it to 62 bits.
    - If 'msb2' is 2, it loads a 4-byte integer from 'buf', swaps the byte order, and masks it to 30 bits.
    - If 'msb2' is 1, it loads a 2-byte integer from 'buf', swaps the byte order, and masks it to 14 bits.
    - If 'msb2' is 0, it reads a single byte from 'buf' and masks it to 6 bits.
    - The default case is marked as unreachable, indicating that 'msb2' should always be within the range 0 to 3.
- **Output**: The function returns an unsigned long integer representing the decoded variable-length integer.


---
### fd\_quic\_pktnum\_decode<!-- {{#callable:fd_quic_pktnum_decode}} -->
The `fd_quic_pktnum_decode` function decodes a packet number from a buffer of bytes into an unsigned long integer.
- **Inputs**:
    - `buf`: A pointer to an array of unsigned characters (bytes) representing the encoded packet number.
    - `sz`: An unsigned long integer representing the size of the packet number in bytes, which can be between 1 and 4.
- **Control Flow**:
    - Initialize a 4-byte array `scratch` to zero and a counter `n` to zero.
    - Use a switch statement to handle different sizes (`sz`) of the packet number, from 1 to 4 bytes.
    - For each case, copy the corresponding byte from `buf` to the `scratch` array, incrementing `n` after each copy.
    - Use the `FD_LOAD` macro to load the 4-byte `scratch` array as an unsigned integer and return it.
- **Output**: The function returns an unsigned long integer representing the decoded packet number.


