# Purpose
The provided C header file, `fd_shred.h`, defines the structure and functionality for handling "shreds" in the context of the Solana blockchain. Shreds are the on-wire representation of Solana block data, optimized for transmission over unreliable networks such as WANs. The file outlines the layout of a shred, which is 1228 bytes long, and includes various headers and payloads. It supports different types of shreds, including data and coding shreds, with additional features like Merkle inclusion proofs and signatures for authentication. The file also defines constants and functions for parsing, validating, and manipulating shreds, including determining their type, size, and payload.

The header file provides a comprehensive API for working with shreds, including functions for parsing shreds, determining their type, and accessing their payloads and Merkle proofs. It also includes definitions for various constants related to shred sizes and types, as well as error codes specific to the Firedancer implementation. The file is intended to be included in other C source files that need to handle shreds, providing a standardized way to manage the transmission and verification of Solana block data. The use of static assertions ensures that certain protocol limits are adhered to, maintaining consistency across the codebase.
# Imports and Dependencies

---
- `../bmtree/fd_bmtree.h`
- `../fd_ballet.h`


# Global Variables

---
### fd\_shred\_parse
- **Type**: `function pointer`
- **Description**: `fd_shred_parse` is a function that parses and validates an untrusted shred stored in a byte buffer. It checks if the shred is well-formed and adheres to certain invariants, returning a pointer to the parsed shred or NULL if the shred is malformed.
- **Use**: This function is used to ensure the integrity and validity of shreds before further processing in the system.


# Data Structures

---
### fd\_shred
- **Type**: `struct`
- **Members**:
    - `signature`: An Ed25519 signature over the shred, signing either the content past this field or the first node of the inclusion proof.
    - `variant`: A shred variant specifier consisting of two four-bit fields indicating the shred type and additional properties.
    - `slot`: The slot number that this shred is part of.
    - `idx`: The index of this shred within the slot.
    - `version`: A hash of the genesis version and historical hard forks of the current chain.
    - `fec_set_idx`: Index into the vector of FEC sets for this slot, with constraints for data shreds.
    - `data`: A union member for data shreds, containing headers like parent offset, flags, and size.
    - `code`: A union member for coding shreds, containing headers like data count, code count, and index.
- **Description**: The `fd_shred` structure represents a shred, which is a unit of data used in the Solana blockchain for transmitting block data over unreliable networks. It includes a signature for authentication, a variant field to specify the type and properties of the shred, and fields for slot and index information. The structure also contains a union to differentiate between data and coding shreds, each with specific headers. Data shreds include information about parent block offsets and flags, while coding shreds include counts of data and coding shreds in the FEC set. This structure is optimized for network transmission and includes features for error correction and Merkle inclusion proofs.


---
### fd\_shred\_t
- **Type**: `struct`
- **Members**:
    - `signature`: Ed25519 signature over the shred.
    - `variant`: Shred variant specifier indicating type and Merkle proof length.
    - `slot`: Slot number that this shred is part of.
    - `idx`: Index of this shred within the slot.
    - `version`: Hash of the genesis version and historical hard forks of the current chain.
    - `fec_set_idx`: Index into the vector of FEC sets for this slot.
    - `data`: Common data shred header containing parent offset, flags, and size.
    - `code`: Common coding shred header containing data count, code count, and index.
- **Description**: The `fd_shred_t` structure represents a shred, which is a fundamental unit of data transmission in the Solana blockchain, optimized for unreliable network links. Each shred is designed to fit within a single UDP packet and can be either a data shred or a coding shred, with the latter supporting Reed-Solomon error correction. The structure includes fields for cryptographic signatures, variant types, slot and index identifiers, and headers specific to data or coding shreds. It supports advanced features like Merkle inclusion proofs for data integrity and optional resigning for secure retransmission.


# Functions

---
### fd\_shred\_type<!-- {{#callable:fd_shred_type}} -->
The `fd_shred_type` function extracts the type of a shred from its variant by masking the high four bits.
- **Inputs**:
    - `variant`: An unsigned character representing the variant of a shred, which includes both the type and additional information encoded in its bits.
- **Control Flow**:
    - The function takes a single input, `variant`, which is an unsigned character.
    - It applies a bitwise AND operation between `variant` and the hexadecimal value `0xf0`.
    - The result of this operation is returned, effectively extracting the high four bits of the `variant`.
- **Output**: The function returns an unsigned character representing the type of the shred, extracted from the high four bits of the input `variant`.


---
### fd\_shred\_variant<!-- {{#callable:fd_shred_variant}} -->
The `fd_shred_variant` function encodes a shred variant by combining the shred type with a specific merkle count based on the type.
- **Inputs**:
    - `type`: An unsigned character representing the type of the shred, which can be one of several predefined constants such as `FD_SHRED_TYPE_LEGACY_DATA` or `FD_SHRED_TYPE_LEGACY_CODE`.
    - `merkle_cnt`: An unsigned character representing the number of non-root nodes in the merkle inclusion proof, which is modified based on the shred type.
- **Control Flow**:
    - Check if the `type` is `FD_SHRED_TYPE_LEGACY_DATA`; if true, set `merkle_cnt` to 0x05.
    - Check if the `type` is `FD_SHRED_TYPE_LEGACY_CODE`; if true, set `merkle_cnt` to 0x0a.
    - Return the result of a bitwise OR operation between `type` and `merkle_cnt`.
- **Output**: The function returns an unsigned character that represents the encoded variant field, combining the shred type and the adjusted merkle count.


---
### fd\_shred\_sz<!-- {{#callable:fd_shred_sz}} -->
The `fd_shred_sz` function calculates the size of a given shred based on its type and variant.
- **Inputs**:
    - `shred`: A pointer to an `fd_shred_t` structure representing the shred whose size is to be calculated.
- **Control Flow**:
    - Retrieve the shred type by calling [`fd_shred_type`](#fd_shred_type) with the shred's variant.
    - Check if the shred type is a code type using a bitwise AND with `FD_SHRED_TYPEMASK_CODE`.
    - If it is a code type, return `FD_SHRED_MAX_SZ`.
    - If it is not a code type, check if the type is `FD_SHRED_TYPE_LEGACY_DATA`.
    - If it is `FD_SHRED_TYPE_LEGACY_DATA`, return the size from the shred's data header.
    - If it is not `FD_SHRED_TYPE_LEGACY_DATA`, return `FD_SHRED_MIN_SZ`.
- **Output**: The function returns an `ulong` representing the size of the shred in bytes.
- **Functions called**:
    - [`fd_shred_type`](#fd_shred_type)


---
### fd\_shred\_header\_sz<!-- {{#callable:fd_shred_header_sz}} -->
The `fd_shred_header_sz` function determines the header size of a shred based on its variant type.
- **Inputs**:
    - `variant`: An unsigned character representing the variant of the shred, which encodes the type and possibly other attributes of the shred.
- **Control Flow**:
    - Extract the type of the shred from the variant using the [`fd_shred_type`](#fd_shred_type) function.
    - Check if the type matches a data shred using a bitwise AND with `FD_SHRED_TYPEMASK_DATA`.
    - If it matches, return the constant `FD_SHRED_DATA_HEADER_SZ`.
    - If not, check if the type matches a code shred using a bitwise AND with `FD_SHRED_TYPEMASK_CODE`.
    - If it matches, return the constant `FD_SHRED_CODE_HEADER_SZ`.
    - If neither condition is met, return 0, indicating an invalid or unrecognized shred type.
- **Output**: The function returns an unsigned long integer representing the size of the header for the given shred variant, or 0 if the variant is invalid.
- **Functions called**:
    - [`fd_shred_type`](#fd_shred_type)


---
### fd\_shred\_merkle\_cnt<!-- {{#callable:fd_shred_merkle_cnt}} -->
The `fd_shred_merkle_cnt` function returns the number of nodes in the Merkle inclusion proof for a given shred variant, excluding the root, or zero if the shred is a legacy type.
- **Inputs**:
    - `variant`: An unsigned character representing the shred variant, which encodes the type of shred and potentially the number of non-root nodes in the Merkle inclusion proof.
- **Control Flow**:
    - Extracts the type of the shred from the variant using the [`fd_shred_type`](#fd_shred_type) function.
    - Checks if the type is either `FD_SHRED_TYPE_LEGACY_DATA` or `FD_SHRED_TYPE_LEGACY_CODE`.
    - If the type is a legacy type, returns 0.
    - Otherwise, returns the lower four bits of the variant, which represent the number of non-root nodes in the Merkle inclusion proof.
- **Output**: Returns an unsigned integer representing the number of non-root nodes in the Merkle inclusion proof, or zero if the shred is a legacy type.
- **Functions called**:
    - [`fd_shred_type`](#fd_shred_type)


---
### fd\_shred\_merkle\_sz<!-- {{#callable:fd_shred_merkle_sz}} -->
The `fd_shred_merkle_sz` function calculates the total size in bytes of the Merkle inclusion proof for a given shred variant.
- **Inputs**:
    - `variant`: An unsigned character representing the shred variant, which encodes the type of shred and the number of non-root nodes in the Merkle inclusion proof.
- **Control Flow**:
    - The function calls [`fd_shred_merkle_cnt`](#fd_shred_merkle_cnt) with the `variant` to determine the number of nodes in the Merkle inclusion proof.
    - It multiplies the result by `FD_SHRED_MERKLE_NODE_SZ` to calculate the total size in bytes of the Merkle inclusion proof.
- **Output**: The function returns an unsigned long integer representing the size in bytes of the Merkle inclusion proof for the given shred variant.
- **Functions called**:
    - [`fd_shred_merkle_cnt`](#fd_shred_merkle_cnt)


---
### fd\_shred\_is\_chained<!-- {{#callable:fd_shred_is_chained}} -->
The `fd_shred_is_chained` function checks if a given shred type corresponds to a chained Merkle data or code shred, including their resigned variants.
- **Inputs**:
    - `type`: An unsigned long integer representing the type of the shred, which is expected to be one of the predefined shred type constants.
- **Control Flow**:
    - The function evaluates whether the input `type` matches any of the predefined constants for chained Merkle data or code shreds, including their resigned variants.
    - It uses a bitwise OR operation to combine the results of comparisons against four specific shred type constants.
    - The result of the bitwise OR operation is cast to an `uchar` and returned.
- **Output**: The function returns an `uchar` value, which is non-zero (true) if the shred type is a chained Merkle data or code shred, including resigned variants, and zero (false) otherwise.


---
### fd\_shred\_is\_resigned<!-- {{#callable:fd_shred_is_resigned}} -->
The `fd_shred_is_resigned` function checks if a given shred type is a resigned Merkle data or code shred.
- **Inputs**:
    - `type`: An unsigned long integer representing the type of the shred, which is expected to be one of the predefined shred type constants.
- **Control Flow**:
    - The function evaluates whether the input `type` matches either `FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED` or `FD_SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED`.
    - It uses a bitwise OR operation to combine the results of the two equality checks, returning a non-zero value if either condition is true.
- **Output**: The function returns an unsigned char (uchar) that is non-zero if the shred type is a resigned Merkle data or code shred, and zero otherwise.


---
### fd\_shred\_is\_data<!-- {{#callable:fd_shred_is_data}} -->
The `fd_shred_is_data` function checks if a given shred type corresponds to a data shred by evaluating specific bits in the type value.
- **Inputs**:
    - `type`: An unsigned long integer representing the shred type, which is expected to be one of the predefined FD_SHRED_TYPE_* values.
- **Control Flow**:
    - The function performs a bitwise AND operation between the input `type` and the constant `0xC0UL`.
    - It then checks if the result of the bitwise operation is equal to `0x80UL`.
    - If the result is `0x80UL`, the function returns 1, indicating that the shred type is a data shred; otherwise, it returns 0.
- **Output**: The function returns an unsigned char (uchar) value of 1 if the shred type is a data shred, and 0 otherwise.


---
### fd\_shred\_is\_code<!-- {{#callable:fd_shred_is_code}} -->
The `fd_shred_is_code` function checks if a given shred type is a Merkle code shred by evaluating specific bits in the type value.
- **Inputs**:
    - `type`: An unsigned long integer representing the shred type, which is expected to be one of the predefined shred type constants.
- **Control Flow**:
    - The function performs a bitwise AND operation between the input `type` and the constant `0xC0UL` to isolate the two highest bits of the type.
    - It then compares the result of the bitwise operation to `0x40UL` to determine if the type corresponds to a Merkle code shred.
    - The function returns the result of this comparison as a boolean value (1 for true, 0 for false).
- **Output**: The function returns an unsigned char (uchar) that is 1 if the input type is a Merkle code shred, and 0 otherwise.


---
### fd\_shred\_swap\_type<!-- {{#callable:fd_shred_swap_type}} -->
The `fd_shred_swap_type` function swaps specific bits in a given type to convert between data and code shred types without altering other attributes.
- **Inputs**:
    - `type`: An unsigned long integer representing the shred type, where specific bits indicate whether it is a data or code shred, and other attributes like legacy, merkle, chained, or resigned status.
- **Control Flow**:
    - The function takes the input `type` and applies a bitwise AND operation with `0x50UL` to isolate bits 4 and 5, then shifts the result left by one position.
    - It applies a bitwise AND operation with `0xA0UL` to isolate bits 6 and 7, then shifts the result right by one position.
    - The function combines the results of the two operations using a bitwise OR operation to produce the final result.
- **Output**: The function returns an unsigned char representing the modified shred type with swapped bits, effectively converting between data and code shred types.


---
### fd\_shred\_payload\_sz<!-- {{#callable:fd_shred_payload_sz}} -->
The `fd_shred_payload_sz` function calculates the payload size of a given shred, accounting for different shred types and their associated headers and optional components.
- **Inputs**:
    - `shred`: A pointer to a `fd_shred_t` structure representing the shred whose payload size is to be calculated.
- **Control Flow**:
    - Retrieve the shred type using [`fd_shred_type`](#fd_shred_type) function on the shred's variant.
    - Check if the shred type is a data type using a bitwise AND with `FD_SHRED_TYPEMASK_DATA`.
    - If it is a data type, return the size of the data minus the data header size (`FD_SHRED_DATA_HEADER_SZ`).
    - If it is not a data type, calculate the payload size by subtracting the code header size (`FD_SHRED_CODE_HEADER_SZ`), the size of the Merkle inclusion proof ([`fd_shred_merkle_sz`](#fd_shred_merkle_sz)), and conditionally subtracting the Merkle root size (`FD_SHRED_MERKLE_ROOT_SZ`) and signature size (`FD_SHRED_SIGNATURE_SZ`) if the shred is chained or resigned, respectively, from the total shred size ([`fd_shred_sz`](#fd_shred_sz)).
- **Output**: The function returns an `ulong` representing the calculated payload size of the shred.
- **Functions called**:
    - [`fd_shred_type`](#fd_shred_type)
    - [`fd_shred_sz`](#fd_shred_sz)
    - [`fd_shred_merkle_sz`](#fd_shred_merkle_sz)
    - [`fd_shred_is_chained`](#fd_shred_is_chained)
    - [`fd_shred_is_resigned`](#fd_shred_is_resigned)


---
### fd\_shred\_merkle\_off<!-- {{#callable:fd_shred_merkle_off}} -->
The `fd_shred_merkle_off` function calculates the byte offset of the Merkle inclusion proof within a given shred.
- **Inputs**:
    - `shred`: A pointer to a constant `fd_shred_t` structure representing the shred whose Merkle inclusion proof offset is to be calculated.
- **Control Flow**:
    - Retrieve the type of the shred by calling [`fd_shred_type`](#fd_shred_type) with the shred's variant.
    - Calculate the total size of the shred using [`fd_shred_sz`](#fd_shred_sz).
    - Determine the size of the Merkle inclusion proof using [`fd_shred_merkle_sz`](#fd_shred_merkle_sz).
    - Check if the shred is resigned using [`fd_shred_is_resigned`](#fd_shred_is_resigned) and adjust the offset by subtracting `FD_SHRED_SIGNATURE_SZ` if true.
    - Subtract the Merkle inclusion proof size and the signature size (if applicable) from the total shred size to get the offset.
- **Output**: Returns an `ulong` representing the byte offset of the Merkle inclusion proof within the shred.
- **Functions called**:
    - [`fd_shred_type`](#fd_shred_type)
    - [`fd_shred_sz`](#fd_shred_sz)
    - [`fd_shred_merkle_sz`](#fd_shred_merkle_sz)
    - [`fd_shred_is_resigned`](#fd_shred_is_resigned)


---
### fd\_shred\_merkle\_nodes<!-- {{#callable:fd_shred_merkle_nodes}} -->
The `fd_shred_merkle_nodes` function returns a pointer to the Merkle proof data within a given shred.
- **Inputs**:
    - `shred`: A pointer to a `fd_shred_t` structure representing a validated shred from which the Merkle proof data is to be extracted.
- **Control Flow**:
    - Cast the input `shred` to a `uchar` pointer to facilitate byte-level operations.
    - Calculate the offset to the Merkle proof data within the shred using the [`fd_shred_merkle_off`](#fd_shred_merkle_off) function.
    - Add the calculated offset to the `uchar` pointer to position it at the start of the Merkle proof data.
    - Cast the resulting pointer to a `fd_shred_merkle_t` pointer and return it.
- **Output**: A pointer to the Merkle proof data within the shred, specifically a `fd_shred_merkle_t const *`.
- **Functions called**:
    - [`fd_shred_merkle_off`](#fd_shred_merkle_off)


---
### fd\_shred\_data\_payload<!-- {{#callable:fd_shred_data_payload}} -->
The `fd_shred_data_payload` function returns a pointer to the payload of a data shred, offset by the size of the data header.
- **Inputs**:
    - `shred`: A pointer to a constant `fd_shred_t` structure representing the shred from which the data payload is to be accessed.
- **Control Flow**:
    - The function takes a pointer to a `fd_shred_t` structure as input.
    - It casts the shred pointer to a `uchar const *` type, which is a pointer to an unsigned character array.
    - The function then adds the constant `FD_SHRED_DATA_HEADER_SZ` to this pointer, effectively skipping over the data header to point directly to the payload section of the shred.
- **Output**: A pointer to the beginning of the data payload within the shred, represented as a `uchar const *`.


---
### fd\_shred\_code\_payload<!-- {{#callable:fd_shred_code_payload}} -->
The `fd_shred_code_payload` function returns a pointer to the payload of a coding shred, offset by the size of the coding header.
- **Inputs**:
    - `shred`: A pointer to a constant `fd_shred_t` structure representing the shred from which the coding payload is to be accessed.
- **Control Flow**:
    - The function takes a pointer to a `fd_shred_t` structure as input.
    - It casts the input shred pointer to a `uchar const *` type.
    - It adds the constant `FD_SHRED_CODE_HEADER_SZ` to the cast pointer to calculate the offset to the payload.
    - The function returns the calculated pointer, which points to the start of the coding payload.
- **Output**: A pointer to the start of the coding payload within the given shred, offset by the size of the coding header.


---
### fd\_shred\_chain\_off<!-- {{#callable:fd_shred_chain_off}} -->
The `fd_shred_chain_off` function calculates the byte offset from the start of a shred to the start of the chained Merkle root for a given shred variant.
- **Inputs**:
    - `variant`: An unsigned character representing the shred variant, which encodes the type and Merkle proof length of the shred.
- **Control Flow**:
    - Retrieve the shred type by applying a bitmask to the variant using [`fd_shred_type`](#fd_shred_type) function.
    - Determine the maximum or minimum size of the shred based on whether the type is a code shred using `fd_ulong_if`.
    - Subtract the size of the Merkle root from the determined shred size.
    - Subtract the size of the Merkle inclusion proof, calculated using [`fd_shred_merkle_sz`](#fd_shred_merkle_sz), from the result.
    - Subtract the size of the signature if the shred is resigned, determined using `fd_ulong_if` and [`fd_shred_is_resigned`](#fd_shred_is_resigned).
- **Output**: Returns an unsigned long integer representing the offset in bytes from the start of the shred to the start of the chained Merkle root.
- **Functions called**:
    - [`fd_shred_type`](#fd_shred_type)
    - [`fd_shred_merkle_sz`](#fd_shred_merkle_sz)
    - [`fd_shred_is_resigned`](#fd_shred_is_resigned)


---
### fd\_shred\_retransmitter\_sig\_off<!-- {{#callable:fd_shred_retransmitter_sig_off}} -->
The function `fd_shred_retransmitter_sig_off` calculates the byte offset from the start of a shred to the start of the retransmitter signature for resigned shreds.
- **Inputs**:
    - `shred`: A pointer to a constant `fd_shred_t` structure representing the shred whose retransmitter signature offset is to be calculated.
- **Control Flow**:
    - The function calls [`fd_shred_sz`](#fd_shred_sz) to determine the total size of the shred.
    - It subtracts the constant `FD_SHRED_SIGNATURE_SZ` (64 bytes) from the total shred size to compute the offset to the retransmitter signature.
- **Output**: The function returns an `ulong` representing the byte offset from the start of the shred to the start of the retransmitter signature.
- **Functions called**:
    - [`fd_shred_sz`](#fd_shred_sz)


# Function Declarations (Public API)

---
### fd\_shred\_parse<!-- {{#callable_declaration:fd_shred_parse}} -->
Parses and validates a shred from a buffer.
- **Description**: Use this function to parse and validate a shred from a given buffer of bytes. It checks the shred's integrity and ensures it adheres to expected formats and constraints. This function should be called when you need to interpret raw shred data, typically received over a network, and verify its correctness before further processing. The buffer must contain at least the minimum size of a shred, and the function allows for additional trailing data beyond the shred's end. If the shred is malformed or violates any constraints, the function returns NULL.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the shred data. The buffer must not be null and should contain at least FD_SHRED_MIN_SZ bytes.
    - `sz`: The size of the buffer in bytes. It must be at least FD_SHRED_MIN_SZ to ensure the buffer contains a complete shred.
- **Output**: Returns a pointer to the parsed shred if successful, or NULL if the shred is malformed or violates constraints.
- **See also**: [`fd_shred_parse`](fd_shred.c.driver.md#fd_shred_parse)  (Implementation)


---
### fd\_shred\_merkle\_root<!-- {{#callable_declaration:fd_shred_merkle_root}} -->
Reconstructs the Merkle root from a Merkle variant shred.
- **Description**: This function is used to reconstruct the Merkle root from a given shred that is a Merkle variant. It should be called when you need to verify the integrity of a shred by checking its inclusion in a Merkle tree. The function requires a valid shred that has been parsed and validated, and it assumes the shred is of a Merkle variant. The function will populate the Merkle root in the provided output parameter and return a success or failure status. The output value should be ignored if the function indicates failure.
- **Inputs**:
    - `shred`: A pointer to a `fd_shred_t` structure representing the shred. It must be a valid, parsed, and validated Merkle variant shred. The caller retains ownership and it must not be null.
    - `bmtree_mem`: A pointer to memory allocated for the binary Merkle tree operations. The caller is responsible for ensuring this memory is properly allocated and managed. It must not be null.
    - `root_out`: A pointer to a `fd_bmtree_node_t` where the reconstructed Merkle root will be stored. The caller must provide a valid memory location for this output. It must not be null.
- **Output**: Returns 1 on success, indicating the Merkle root was successfully reconstructed and stored in `root_out`. Returns 0 on failure, in which case the value in `root_out` should be ignored.
- **See also**: [`fd_shred_merkle_root`](fd_shred.c.driver.md#fd_shred_merkle_root)  (Implementation)


