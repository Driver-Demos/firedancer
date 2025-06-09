# Purpose
The provided C header file, `fd_disco_base.h`, is part of a larger software system and serves as a foundational component for handling network packet signatures and related operations. It defines a series of constants, macros, and inline functions that are used to manage and manipulate network packet metadata, particularly in the context of a distributed system. The file includes several other headers, indicating its reliance on external components for functionality related to transaction processing, shreds, and workspace management.

The file defines various constants for protocol types, packet types, and flags used in replay and execution processes. It also specifies maximum transmission unit (MTU) sizes for different types of network packets, such as those used in gossip and transaction processing. The inline functions provided in the file are primarily focused on creating and extracting information from packet signatures, which are used to encode metadata such as IP addresses, protocol types, slot numbers, and flags. These signatures are crucial for efficiently routing and processing packets within the system. The file is not an executable but rather a header file intended to be included in other parts of the system, providing a public API for handling network packet signatures and related operations.
# Imports and Dependencies

---
- `../tango/fd_tango.h`
- `../ballet/shred/fd_shred.h`
- `../ballet/txn/fd_txn.h`
- `../util/wksp/fd_wksp_private.h`


# Functions

---
### fd\_disco\_netmux\_sig<!-- {{#callable:fd_disco_netmux_sig}} -->
The `fd_disco_netmux_sig` function generates a network multiplexer signature by encoding various network packet attributes into a single unsigned long integer.
- **Inputs**:
    - `hash_ip_addr`: The IP address used for hashing, representing the source IP for incoming packets and the destination IP for outgoing packets.
    - `hash_port`: The port number used for hashing, representing the source port for incoming packets and the destination port for outgoing packets.
    - `dst_ip_addr`: The destination IP address of the packet.
    - `proto`: The protocol identifier for the packet.
    - `hdr_sz`: The total size of the network headers, including Ethernet, IP, and UDP headers.
- **Control Flow**:
    - Calculate a compressed header size index `hdr_sz_i` by subtracting 42 from `hdr_sz`, right-shifting by 2, and masking with 0xF.
    - Compute a hash value by combining `hash_ip_addr` and `hash_port` into a 64-bit integer, applying a hash function, and masking with 0xfffff.
    - Construct the signature by shifting and combining the hash, compressed header size index, protocol, and destination IP address into a single unsigned long integer.
- **Output**: Returns an unsigned long integer representing the network multiplexer signature, encoding the hash, header size index, protocol, and destination IP address.


---
### fd\_disco\_netmux\_sig\_hash<!-- {{#callable:fd_disco_netmux_sig_hash}} -->
The `fd_disco_netmux_sig_hash` function extracts the hash component from a network multiplexer signature by right-shifting the input signature by 44 bits.
- **Inputs**:
    - `sig`: An unsigned long integer representing the network multiplexer signature from which the hash component is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter, `sig`, which is an unsigned long integer.
    - It performs a right bitwise shift operation on `sig` by 44 bits.
    - The result of the shift operation is returned as the hash component of the signature.
- **Output**: The function returns an unsigned long integer representing the hash component extracted from the input signature.


---
### fd\_disco\_netmux\_sig\_proto<!-- {{#callable:fd_disco_netmux_sig_proto}} -->
The function `fd_disco_netmux_sig_proto` extracts the protocol identifier from a given network signature.
- **Inputs**:
    - `sig`: A 64-bit unsigned long integer representing a network signature from which the protocol identifier is to be extracted.
- **Control Flow**:
    - The function shifts the input `sig` right by 32 bits to move the protocol identifier into the least significant byte position.
    - It then applies a bitwise AND operation with `0xFFUL` to isolate the protocol identifier, which is an 8-bit value.
- **Output**: The function returns an unsigned long integer representing the protocol identifier extracted from the network signature.


---
### fd\_disco\_netmux\_sig\_dst\_ip<!-- {{#callable:fd_disco_netmux_sig_dst_ip}} -->
The function `fd_disco_netmux_sig_dst_ip` extracts the destination IP address from a network signature.
- **Inputs**:
    - `sig`: A 64-bit unsigned long integer representing a network signature from which the destination IP address is to be extracted.
- **Control Flow**:
    - The function takes a 64-bit unsigned long integer `sig` as input.
    - It performs a bitwise AND operation between `sig` and `0xFFFFFFFFUL` to mask out the lower 32 bits of `sig`.
    - The result of the bitwise operation is cast to a 32-bit unsigned integer, which represents the destination IP address.
- **Output**: A 32-bit unsigned integer representing the destination IP address extracted from the network signature.


---
### fd\_disco\_netmux\_sig\_hdr\_sz<!-- {{#callable:fd_disco_netmux_sig_hdr_sz}} -->
The function `fd_disco_netmux_sig_hdr_sz` calculates the total size of Ethernet, IP, and UDP headers from a given network signature.
- **Inputs**:
    - `sig`: A 64-bit unsigned long integer representing the network signature from which the header size is to be extracted.
- **Control Flow**:
    - Extracts a 4-bit value from the signature by right-shifting it by 40 bits and applying a mask of 0xF.
    - Multiplies the extracted 4-bit value by 4 to calculate the variable part of the header size.
    - Adds 42 to the result to account for the base header size, which includes the minimum Ethernet, IP, and UDP headers.
- **Output**: Returns an unsigned long integer representing the total size of the Ethernet, IP, and UDP headers.


---
### fd\_disco\_poh\_sig<!-- {{#callable:fd_disco_poh_sig}} -->
The `fd_disco_poh_sig` function constructs a signature by encoding a slot number, packet type, and bank tile index into a single unsigned long integer.
- **Inputs**:
    - `slot`: The slot number, which is a 64-bit unsigned long integer representing a time or sequence slot.
    - `pkt_type`: The packet type, a 64-bit unsigned long integer, where only the lowest 2 bits are used to represent the type of packet.
    - `bank_tile`: The bank tile index, a 64-bit unsigned long integer, where only the lowest 6 bits are used to represent the bank index.
- **Control Flow**:
    - Shift the slot number left by 8 bits to make room for the bank tile and packet type in the lower byte.
    - Mask the bank tile with 0x3F to extract the lowest 6 bits, then shift left by 2 bits to position it in the signature.
    - Mask the packet type with 0x3 to extract the lowest 2 bits, which are directly used in the signature.
    - Combine the shifted slot, bank tile, and packet type using bitwise OR to form the final signature.
- **Output**: The function returns a 64-bit unsigned long integer that encodes the slot, bank tile, and packet type into a single signature value.


---
### fd\_disco\_poh\_sig\_pkt\_type<!-- {{#callable:fd_disco_poh_sig_pkt_type}} -->
The `fd_disco_poh_sig_pkt_type` function extracts the packet type from a given signature by isolating the lowest two bits.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the packet type is to be extracted.
- **Control Flow**:
    - The function performs a bitwise AND operation between the input signature and the constant `0x3UL` to isolate the lowest two bits of the signature.
    - The result of this operation, which represents the packet type, is returned.
- **Output**: The function returns an unsigned long integer representing the packet type extracted from the signature.


---
### fd\_disco\_poh\_sig\_slot<!-- {{#callable:fd_disco_poh_sig_slot}} -->
The `fd_disco_poh_sig_slot` function extracts the slot number from a given signature by shifting the bits to the right by 8 positions.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the slot number is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter `sig`.
    - It performs a bitwise right shift operation on `sig` by 8 positions.
    - The result of the shift operation is returned as the slot number.
- **Output**: The function returns an unsigned long integer representing the slot number extracted from the input signature.


---
### fd\_disco\_poh\_sig\_bank\_tile<!-- {{#callable:fd_disco_poh_sig_bank_tile}} -->
The `fd_disco_poh_sig_bank_tile` function extracts the bank tile index from a given signature by shifting and masking operations.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the bank tile index is to be extracted.
- **Control Flow**:
    - The function shifts the input signature `sig` to the right by 2 bits.
    - It then applies a bitwise AND operation with the mask `0x3FUL` to extract the relevant bits for the bank tile index.
- **Output**: The function returns an unsigned long integer representing the bank tile index extracted from the input signature.


---
### fd\_disco\_bank\_sig<!-- {{#callable:fd_disco_bank_sig}} -->
The `fd_disco_bank_sig` function generates a unique signature by combining a slot number and a microblock index into a single unsigned long integer.
- **Inputs**:
    - `slot`: An unsigned long integer representing the slot number.
    - `microblock_idx`: An unsigned long integer representing the microblock index.
- **Control Flow**:
    - The function shifts the `slot` value 32 bits to the left.
    - It then performs a bitwise OR operation with `microblock_idx`.
- **Output**: The function returns an unsigned long integer that encodes both the slot and microblock index.


---
### fd\_disco\_bank\_sig\_slot<!-- {{#callable:fd_disco_bank_sig_slot}} -->
The `fd_disco_bank_sig_slot` function extracts the slot number from a given signature by shifting the bits to the right by 32 positions.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the slot number is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter, `sig`, which is an unsigned long integer.
    - It performs a bitwise right shift operation on `sig` by 32 bits.
    - The result of the shift operation is returned as the slot number.
- **Output**: The function returns an unsigned long integer representing the slot number extracted from the input signature.


---
### fd\_disco\_bank\_sig\_microblock\_idx<!-- {{#callable:fd_disco_bank_sig_microblock_idx}} -->
The function `fd_disco_bank_sig_microblock_idx` extracts the microblock index from a given signature by masking the lower 32 bits.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the microblock index is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter, `sig`, which is an unsigned long integer.
    - It applies a bitwise AND operation between `sig` and the constant `0xFFFFFFFFUL`, which is a mask for the lower 32 bits.
    - The result of this operation is returned as the microblock index.
- **Output**: The function returns an unsigned long integer representing the microblock index extracted from the lower 32 bits of the input signature.


---
### fd\_disco\_replay\_old\_sig<!-- {{#callable:fd_disco_replay_old_sig}} -->
The `fd_disco_replay_old_sig` function constructs a signature by combining a slot number and flags for a replay message.
- **Inputs**:
    - `slot`: A `ulong` representing the slot number, which occupies the higher 7 bytes of the signature.
    - `flags`: A `ulong` representing the flags for the replay message, which occupy the low byte of the signature.
- **Control Flow**:
    - The function shifts the `slot` value 8 bits to the left, effectively placing it in the higher 7 bytes of the resulting signature.
    - The `flags` value is masked with `0xFFUL` to ensure only the low byte is used.
    - The function combines the shifted `slot` and masked `flags` using a bitwise OR operation to form the final signature.
- **Output**: The function returns a `ulong` representing the combined signature of the slot and flags.


---
### fd\_disco\_replay\_old\_sig\_flags<!-- {{#callable:fd_disco_replay_old_sig_flags}} -->
The function `fd_disco_replay_old_sig_flags` extracts the flags from a replay signature by masking the lower byte of the signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the replay signature from which the flags are to be extracted.
- **Control Flow**:
    - The function takes a single input parameter `sig`.
    - It applies a bitwise AND operation between `sig` and `0xFFUL` to isolate the lower 8 bits of the signature.
    - The result of the bitwise operation, which represents the flags, is returned.
- **Output**: The function returns an unsigned long integer representing the flags extracted from the lower byte of the input signature.


---
### fd\_disco\_replay\_old\_sig\_slot<!-- {{#callable:fd_disco_replay_old_sig_slot}} -->
The function `fd_disco_replay_old_sig_slot` extracts the slot number from a given signature by shifting the bits to the right by 8 positions.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the slot number is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter `sig`.
    - It performs a bitwise right shift operation on `sig` by 8 bits.
    - The result of the shift operation is returned as the output.
- **Output**: The function returns an unsigned long integer representing the slot number extracted from the input signature.


---
### fd\_disco\_shred\_repair\_shred\_sig<!-- {{#callable:fd_disco_shred_repair_shred_sig}} -->
The `fd_disco_shred_repair_shred_sig` function constructs a signature for a shred repair message by encoding various parameters into a 64-bit unsigned long integer.
- **Inputs**:
    - `completes`: An integer indicating whether the shred marks the end of a batch or slot, converted to a boolean.
    - `slot`: An unsigned long representing the slot number, capped at UINT_MAX.
    - `fec_set_idx`: An unsigned integer representing the FEC set index, capped at FD_SHRED_BLK_MAX.
    - `is_code`: An integer indicating whether the shred is a coding shred, converted to a boolean.
    - `shred_idx_or_data_cnt`: An unsigned integer representing either the shred index or data count, capped at FD_SHRED_BLK_MAX.
- **Control Flow**:
    - Convert the `completes` and `is_code` inputs to boolean values and store them as unsigned long integers.
    - Cap the `slot`, `shred_idx_or_data_cnt`, and `fec_set_idx` inputs to their respective maximum values using `fd_ulong_min`.
    - Construct a 64-bit unsigned long integer by shifting and combining the processed inputs into specific bit positions: `completes` at bit 63, `slot` from bits 31 to 62, `fec_set_idx` from bits 16 to 30, `is_code` at bit 15, and `shred_idx_or_data_cnt` from bits 0 to 14.
    - Return the constructed 64-bit unsigned long integer as the signature.
- **Output**: A 64-bit unsigned long integer representing the constructed signature for a shred repair message.


---
### fd\_disco\_shred\_repair\_shred\_sig\_completes<!-- {{#callable:fd_disco_shred_repair_shred_sig_completes}} -->
The function `fd_disco_shred_repair_shred_sig_completes` extracts the 'completes' bit from a given signature, indicating whether a shred marks the end of a batch or slot.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the 'completes' bit is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract_bit` with the signature and the bit position 63 to extract the 'completes' bit.
    - The extracted bit is returned as the function's result.
- **Output**: An integer representing the 'completes' bit extracted from the signature, which is either 0 or 1.


---
### fd\_disco\_shred\_repair\_shred\_sig\_slot<!-- {{#callable:fd_disco_shred_repair_shred_sig_slot}} -->
The function `fd_disco_shred_repair_shred_sig_slot` extracts the slot number from a given signature for a shred repair operation.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the slot number is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with the signature `sig`, a start bit of 31, and an end bit of 62.
    - `fd_ulong_extract` extracts the bits from position 31 to 62 from the `sig`, which represent the slot number.
- **Output**: The function returns an unsigned long integer representing the extracted slot number from the signature.


---
### fd\_disco\_shred\_repair\_shred\_sig\_fec\_set\_idx<!-- {{#callable:fd_disco_shred_repair_shred_sig_fec_set_idx}} -->
The function `fd_disco_shred_repair_shred_sig_fec_set_idx` extracts the FEC set index from a given signature.
- **Inputs**:
    - `sig`: A 64-bit unsigned long integer representing the signature from which the FEC set index is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with parameters `sig`, `16`, and `30` to extract bits 16 to 30 from the signature.
    - The extracted bits are cast to an unsigned integer and returned as the FEC set index.
- **Output**: The function returns an unsigned integer representing the FEC set index extracted from the given signature.


---
### fd\_disco\_shred\_repair\_shred\_sig\_is\_code<!-- {{#callable:fd_disco_shred_repair_shred_sig_is_code}} -->
The function `fd_disco_shred_repair_shred_sig_is_code` checks if a given signature represents a coding shred by extracting a specific bit from the signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the function will extract a bit to determine if it is a coding shred.
- **Control Flow**:
    - The function calls `fd_ulong_extract_bit` with the signature and the bit position 15 to extract the bit at that position.
    - The extracted bit is returned as the result, indicating whether the signature is a coding shred (1) or not (0).
- **Output**: An integer value (0 or 1) indicating whether the signature represents a coding shred (1) or not (0).


---
### fd\_disco\_shred\_repair\_shred\_sig\_shred\_idx<!-- {{#callable:fd_disco_shred_repair_shred_sig_shred_idx}} -->
The function `fd_disco_shred_repair_shred_sig_shred_idx` extracts the shred index from a signature when the signature represents a data shred (i.e., when `is_code` is 0).
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the shred index is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract_lsb` with the signature `sig` and the number 15 as arguments.
    - The `fd_ulong_extract_lsb` function extracts the least significant 15 bits from the signature `sig`.
    - The extracted value is cast to an unsigned integer and returned.
- **Output**: The function returns an unsigned integer representing the shred index extracted from the signature.


---
### fd\_disco\_shred\_repair\_shred\_sig\_data\_cnt<!-- {{#callable:fd_disco_shred_repair_shred_sig_data_cnt}} -->
The function `fd_disco_shred_repair_shred_sig_data_cnt` extracts the data count from a signature when the signature represents a coding shred.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the data count is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract_lsb` with the signature and the number 15 as arguments.
    - The result of `fd_ulong_extract_lsb` is cast to an unsigned integer and returned.
- **Output**: The function returns an unsigned integer representing the data count extracted from the signature.


---
### fd\_disco\_shred\_repair\_fec\_sig<!-- {{#callable:fd_disco_shred_repair_fec_sig}} -->
The function `fd_disco_shred_repair_fec_sig` constructs a signature for a FEC (Forward Error Correction) set in a shred repair context by encoding various parameters into a single 64-bit unsigned long integer.
- **Inputs**:
    - `slot`: The slot number, which is a 64-bit unsigned long integer, representing a specific time or position in a sequence.
    - `fec_set_idx`: The index of the FEC set, a 32-bit unsigned integer, indicating the specific FEC set within the slot.
    - `data_cnt`: The count of data shreds, a 32-bit unsigned integer, representing the number of data shreds in the FEC set.
    - `is_slot_complete`: An integer flag indicating whether the slot is complete (non-zero if complete).
    - `is_batch_complete`: An integer flag indicating whether the batch is complete (non-zero if complete).
- **Control Flow**:
    - Convert the `slot` to a 32-bit unsigned long integer, ensuring it does not exceed `UINT_MAX`.
    - Convert `fec_set_idx` and `data_cnt` to 32-bit unsigned long integers, ensuring they do not exceed `FD_SHRED_BLK_MAX`.
    - Convert `is_slot_complete` and `is_batch_complete` to 32-bit unsigned long integers, ensuring they are either 0 or 1.
    - Construct the signature by shifting and combining the converted values into a single 64-bit unsigned long integer.
- **Output**: A 64-bit unsigned long integer representing the encoded signature for the FEC set, with fields for slot, FEC set index, data count, and completion flags.


---
### fd\_disco\_shred\_repair\_fec\_sig\_slot<!-- {{#callable:fd_disco_shred_repair_fec_sig_slot}} -->
The function `fd_disco_shred_repair_fec_sig_slot` extracts the slot number from a given FEC signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the FEC signature from which the slot number is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with the signature `sig`, a start bit of 32, and an end bit of 63.
    - The `fd_ulong_extract` function extracts the bits from position 32 to 63 from the `sig` and returns this value.
- **Output**: The function returns an unsigned long integer representing the slot number extracted from the FEC signature.


---
### fd\_disco\_shred\_repair\_fec\_sig\_fec\_set\_idx<!-- {{#callable:fd_disco_shred_repair_fec_sig_fec_set_idx}} -->
The function `fd_disco_shred_repair_fec_sig_fec_set_idx` extracts the FEC set index from a given signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the FEC set index is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with parameters `sig`, `17`, and `31` to extract bits 17 to 31 from the signature.
    - The extracted bits are cast to an unsigned integer and returned as the FEC set index.
- **Output**: The function returns an unsigned integer representing the FEC set index extracted from the signature.


---
### fd\_disco\_shred\_repair\_fec\_sig\_data\_cnt<!-- {{#callable:fd_disco_shred_repair_fec_sig_data_cnt}} -->
The function `fd_disco_shred_repair_fec_sig_data_cnt` extracts a 15-bit data count from a given signature.
- **Inputs**:
    - `sig`: A 64-bit unsigned long integer representing the signature from which the data count is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with parameters `sig`, `2`, and `16` to extract a 15-bit value starting from bit position 2.
    - The extracted value is cast to an unsigned integer and returned.
- **Output**: The function returns a 15-bit unsigned integer representing the data count extracted from the signature.


---
### fd\_disco\_shred\_repair\_fec\_sig\_is\_slot\_complete<!-- {{#callable:fd_disco_shred_repair_fec_sig_is_slot_complete}} -->
The function `fd_disco_shred_repair_fec_sig_is_slot_complete` checks if a slot is complete by extracting a specific bit from a given signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the slot completion status is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract_bit` with the signature `sig` and the bit position `1` to extract the bit indicating slot completion.
    - The result of the bit extraction is returned as the function's output.
- **Output**: An integer representing whether the slot is complete (1 if complete, 0 if not).


---
### fd\_disco\_shred\_repair\_fec\_sig\_is\_batch\_complete<!-- {{#callable:fd_disco_shred_repair_fec_sig_is_batch_complete}} -->
The function `fd_disco_shred_repair_fec_sig_is_batch_complete` checks if a batch is complete by extracting the least significant bit from a given signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the batch completion status is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract_bit` with the signature and bit position 0 to extract the least significant bit.
    - The extracted bit is returned as the result, indicating whether the batch is complete.
- **Output**: An integer representing the batch completion status, where 1 indicates the batch is complete and 0 indicates it is not.


---
### fd\_disco\_repair\_shred\_sig<!-- {{#callable:fd_disco_repair_shred_sig}} -->
The function `fd_disco_repair_shred_sig` converts a `uint` type `last_shred_idx` to an `ulong` type and returns it.
- **Inputs**:
    - `last_shred_idx`: An unsigned integer representing the last shred index to be converted to an unsigned long.
- **Control Flow**:
    - The function takes a single input parameter `last_shred_idx` of type `uint`.
    - It casts `last_shred_idx` to `ulong`.
    - The function returns the casted value.
- **Output**: The function returns the `last_shred_idx` as an `ulong`.


---
### fd\_disco\_repair\_shred\_sig\_last\_shred\_idx<!-- {{#callable:fd_disco_repair_shred_sig_last_shred_idx}} -->
The function `fd_disco_repair_shred_sig_last_shred_idx` extracts the last shred index from a given signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the last shred index is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter `sig` of type `ulong`.
    - It casts the `sig` to a `uint` type and returns it.
- **Output**: The function returns the last shred index as an unsigned integer (`uint`).


---
### fd\_disco\_repair\_replay\_sig<!-- {{#callable:fd_disco_repair_replay_sig}} -->
The `fd_disco_repair_replay_sig` function constructs a 64-bit signature by encoding a slot number, parent offset, data count, and slot completion status into specific bit positions.
- **Inputs**:
    - `slot`: A 32-bit unsigned long representing the slot number, which is limited to the maximum value of a 32-bit unsigned integer.
    - `parent_off`: A 16-bit unsigned short representing the parent offset.
    - `data_cnt`: A 15-bit unsigned integer representing the data count, limited to the maximum value defined by `FD_SHRED_BLK_MAX`.
    - `slot_complete`: An integer indicating whether the slot is complete, where any non-zero value is treated as true.
- **Control Flow**:
    - Convert `slot` to a 32-bit unsigned long, ensuring it does not exceed `UINT_MAX`.
    - Convert `parent_off` to a 16-bit unsigned long.
    - Convert `data_cnt` to a 15-bit unsigned long, ensuring it does not exceed `FD_SHRED_BLK_MAX`.
    - Convert `slot_complete` to a boolean value, where any non-zero value becomes 1.
    - Combine these values into a single 64-bit unsigned long by shifting and bitwise OR operations, placing each value in its designated bit range.
- **Output**: A 64-bit unsigned long integer that encodes the input parameters into specific bit positions for use as a signature.


---
### fd\_disco\_repair\_replay\_sig\_slot<!-- {{#callable:fd_disco_repair_replay_sig_slot}} -->
The function `fd_disco_repair_replay_sig_slot` extracts the slot number from a given signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the slot number is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with parameters `sig`, `32`, and `63` to extract bits 32 to 63 from the signature, which represent the slot number.
- **Output**: The function returns an unsigned long integer representing the extracted slot number from the signature.


---
### fd\_disco\_repair\_replay\_sig\_parent\_off<!-- {{#callable:fd_disco_repair_replay_sig_parent_off}} -->
The function `fd_disco_repair_replay_sig_parent_off` extracts the parent offset field from a given signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the parent offset is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with parameters `sig`, `16`, and `31` to extract bits 16 to 31 from the signature.
    - The extracted value is cast to a `ushort` type and returned.
- **Output**: The function returns a `ushort` representing the parent offset extracted from the signature.


---
### fd\_disco\_repair\_replay\_sig\_data\_cnt<!-- {{#callable:fd_disco_repair_replay_sig_data_cnt}} -->
The function `fd_disco_repair_replay_sig_data_cnt` extracts a 15-bit data count from a given signature.
- **Inputs**:
    - `sig`: An unsigned long integer representing the signature from which the data count is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with parameters `sig`, `1`, and `15` to extract a 15-bit segment starting from bit position 1.
    - The extracted value is cast to an unsigned integer and returned.
- **Output**: The function returns a 15-bit unsigned integer representing the data count extracted from the signature.


---
### fd\_disco\_repair\_replay\_sig\_slot\_complete<!-- {{#callable:fd_disco_repair_replay_sig_slot_complete}} -->
The function `fd_disco_repair_replay_sig_slot_complete` extracts the least significant bit from a given signature to determine if a slot is complete.
- **Inputs**:
    - `sig`: An unsigned long integer representing a signature from which the function will extract the least significant bit.
- **Control Flow**:
    - The function calls `fd_ulong_extract_bit` with the signature and the bit position 0 to extract the least significant bit.
    - The result of the bit extraction is returned as the output of the function.
- **Output**: An integer representing the least significant bit of the input signature, indicating whether a slot is complete.


---
### fd\_disco\_compact\_chunk0<!-- {{#callable:fd_disco_compact_chunk0}} -->
The `fd_disco_compact_chunk0` function calculates the starting chunk index of a workspace by right-shifting its lower global address by a predefined chunk size.
- **Inputs**:
    - `wksp`: A pointer to a workspace structure of type `fd_wksp_private`.
- **Control Flow**:
    - The function casts the input `wksp` to a pointer of type `struct fd_wksp_private`.
    - It accesses the `gaddr_lo` member of the `fd_wksp_private` structure.
    - The value of `gaddr_lo` is right-shifted by `FD_CHUNK_LG_SZ` bits.
    - The result of the right shift operation is returned as the function's output.
- **Output**: The function returns an `ulong` representing the starting chunk index of the workspace.


---
### fd\_disco\_compact\_wmark<!-- {{#callable:fd_disco_compact_wmark}} -->
The `fd_disco_compact_wmark` function calculates a watermark for a workspace based on a given maximum transmission unit (MTU).
- **Inputs**:
    - `wksp`: A pointer to a workspace structure (`fd_wksp_private`) containing the high address (`gaddr_hi`) of the workspace.
    - `mtu`: An unsigned long integer representing the maximum transmission unit size.
- **Control Flow**:
    - Calculate `chunk_mtu` by adjusting the `mtu` to account for chunk size and alignment, using bitwise operations to shift and align the value.
    - Retrieve the high address (`gaddr_hi`) from the workspace structure pointed to by `wksp`.
    - Shift the high address right by `FD_CHUNK_LG_SZ` to convert it to a chunk index.
    - Subtract `chunk_mtu` from the chunk index to compute the watermark.
- **Output**: Returns an unsigned long integer representing the calculated watermark for the workspace.


