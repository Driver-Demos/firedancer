# Purpose
The provided C header file, `fd_groove_meta.h`, defines a set of utilities and data structures for managing metadata associated with keys in a storage system. The primary focus of this file is the manipulation and management of a 64-bit bitfield that encodes metadata attributes such as whether a key is used, and whether its value is stored in a "cold" or "hot" storage. Additionally, it encodes the size and maximum size of the value associated with a key. The file provides inline functions to pack and unpack these metadata attributes efficiently, ensuring that the metadata is stored compactly and can be accessed quickly.

The file also defines a structure, `fd_groove_meta`, which includes a key, the metadata bitfield, and an offset for the value in cold storage. This structure is used in conjunction with a map implementation, as indicated by the macros that define map-related operations such as checking if an element is free, freeing an element, and moving elements. The inclusion of a map implementation template (`fd_map_slot_para.c`) suggests that this file is part of a larger system that manages key-value pairs, likely in a distributed or high-performance storage context. The file is designed to be included in other C source files, providing a reusable component for handling key metadata efficiently.
# Imports and Dependencies

---
- `fd_groove_base.h`
- `../util/tmpl/fd_map_slot_para.c`


# Data Structures

---
### fd\_groove\_meta\_t
- **Type**: `struct`
- **Members**:
    - `key`: Represents the key associated with the metadata.
    - `bits`: A 64-bit bitfield that compactly stores metadata about the key.
    - `val_off`: Indicates the offset in the cold store where the key's value is stored.
- **Description**: The `fd_groove_meta_t` structure is designed to store metadata for a key in a groove system, utilizing a compact 64-bit bitfield to encode various attributes such as whether the key is used, and if its value is stored in a cold or hot store. It also includes fields for the size and maximum size of the value, as well as an offset for locating the value in a cold store. This structure is part of a larger mapping system that manages key-value pairs efficiently, with operations to check, free, and move elements within the map.


# Functions

---
### fd\_groove\_meta\_bits<!-- {{#callable:fd_groove_meta_bits}} -->
The `fd_groove_meta_bits` function packs metadata flags and size information into a 64-bit bitfield.
- **Inputs**:
    - `used`: An integer indicating if the map slot contains a key-meta pair (0 or non-zero).
    - `cold`: An integer indicating if the value for the key is present in the cold store (0 or non-zero).
    - `hot`: An integer indicating if the value for the key is present in the hot store (0 or non-zero).
    - `val_sz`: An unsigned long representing the number of bytes for the key's value, assumed to be in the range [0, 2^24).
    - `val_max`: An unsigned long representing the maximum number of bytes for the key's value, also assumed to be in the range [0, 2^24).
- **Control Flow**:
    - Convert the `used` input to a boolean and cast it to an unsigned long, placing it in the least significant bit of the result.
    - Convert the `cold` input to a boolean, cast it to an unsigned long, and shift it left by 1 bit, placing it in the second least significant bit of the result.
    - Convert the `hot` input to a boolean, cast it to an unsigned long, and shift it left by 2 bits, placing it in the third least significant bit of the result.
    - Shift `val_sz` left by 16 bits and place it in the result, occupying bits 16 to 39.
    - Shift `val_max` left by 40 bits and place it in the result, occupying bits 40 to 63.
    - Combine all these components using bitwise OR operations to form the final 64-bit bitfield.
- **Output**: A 64-bit unsigned long representing the packed metadata bitfield.


---
### fd\_groove\_meta\_bits\_used<!-- {{#callable:fd_groove_meta_bits_used}} -->
The `fd_groove_meta_bits_used` function extracts the 'used' status bit from a 64-bit metadata bitfield.
- **Inputs**:
    - `bits`: A 64-bit unsigned long integer representing the metadata bitfield from which the 'used' status bit is to be extracted.
- **Control Flow**:
    - The function takes a 64-bit unsigned long integer `bits` as input.
    - It performs a bitwise AND operation between `bits` and `1UL` to isolate the least significant bit, which represents the 'used' status.
    - The result of the bitwise operation is cast to an integer and returned.
- **Output**: An integer value of either 0 or 1, indicating whether the 'used' bit in the metadata bitfield is set (1) or not (0).


---
### fd\_groove\_meta\_bits\_cold<!-- {{#callable:fd_groove_meta_bits_cold}} -->
The `fd_groove_meta_bits_cold` function extracts the 'cold' bit from a 64-bit metadata bitfield, indicating if a value for a key is present in the cold store.
- **Inputs**:
    - `bits`: A 64-bit unsigned long integer representing the metadata bitfield from which the 'cold' bit is to be extracted.
- **Control Flow**:
    - The function shifts the input `bits` right by 1 position to align the 'cold' bit with the least significant bit position.
    - It then performs a bitwise AND operation with `1UL` to isolate the 'cold' bit.
    - The result is cast to an integer and returned, representing the presence (1) or absence (0) of the 'cold' bit.
- **Output**: An integer value of either 0 or 1, indicating whether the 'cold' bit is set in the metadata bitfield.


---
### fd\_groove\_meta\_bits\_hot<!-- {{#callable:fd_groove_meta_bits_hot}} -->
The `fd_groove_meta_bits_hot` function extracts the 'hot' bit from a 64-bit metadata bitfield, indicating if a value for a key is present in the hot store.
- **Inputs**:
    - `bits`: A 64-bit unsigned long integer representing the metadata bitfield from which the 'hot' bit is to be extracted.
- **Control Flow**:
    - The function shifts the input 'bits' right by 2 positions to align the 'hot' bit to the least significant bit position.
    - It then performs a bitwise AND operation with 1UL to isolate the 'hot' bit.
    - The result is cast to an integer and returned.
- **Output**: An integer value of either 0 or 1, indicating whether the 'hot' bit is set (1) or not (0) in the metadata bitfield.


---
### fd\_groove\_meta\_bits\_val\_sz<!-- {{#callable:fd_groove_meta_bits_val_sz}} -->
The function `fd_groove_meta_bits_val_sz` extracts the `val_sz` field from a 64-bit metadata bitfield.
- **Inputs**:
    - `bits`: A 64-bit unsigned long integer representing the metadata bitfield from which the `val_sz` value is to be extracted.
- **Control Flow**:
    - The function takes a 64-bit unsigned integer `bits` as input.
    - It performs a right bitwise shift of 16 positions on `bits` to move the `val_sz` field to the least significant bits.
    - It applies a bitwise AND operation with `16777215UL` (which is `0xFFFFFF` in hexadecimal) to isolate the 24-bit `val_sz` field.
    - The resulting value, which represents the `val_sz`, is returned.
- **Output**: The function returns an unsigned long integer representing the `val_sz` field, which is the number of bytes for the key's value, extracted from the input bitfield.


---
### fd\_groove\_meta\_bits\_val\_max<!-- {{#callable:fd_groove_meta_bits_val_max}} -->
The function `fd_groove_meta_bits_val_max` extracts the maximum value size from a 64-bit metadata bitfield by shifting the bits to the right by 40 positions.
- **Inputs**:
    - `bits`: A 64-bit unsigned long integer representing the metadata bitfield from which the maximum value size is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter, `bits`, which is a 64-bit unsigned long integer.
    - It performs a right bitwise shift operation on `bits` by 40 positions.
    - The result of the shift operation is returned as the output of the function.
- **Output**: The function returns an unsigned long integer representing the maximum number of bytes allowed for a key's value, extracted from the input bitfield.


