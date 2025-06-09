# Purpose
This C header file defines and manages the types and attributes of QUIC (Quick UDP Internet Connections) frames, which are essential components in the QUIC protocol used for secure and efficient data transport over the internet. The file provides a structured enumeration of various QUIC frame types, each associated with specific attributes such as whether they are allowed in different packet types (Initial, Handshake, 0-RTT, 1-RTT) and whether they are ACK eliciting. The macro `FD_QUIC_FRAME_TYPES` is used to define these frame types and their properties, which are then utilized in the implementation of QUIC protocol functionalities.

The file also includes a function, [`fd_quic_frame_type_allowed`](#fd_quic_frame_type_allowed), which checks if a particular frame type is permissible for a given packet type, ensuring that the frames adhere to the protocol's rules. This function is marked as `FD_FN_PURE`, indicating that it has no side effects and its return value depends only on its parameters. The header file is designed to be included in other C source files, providing a consistent interface for handling QUIC frame types across different parts of a QUIC implementation. It does not define a public API but rather serves as an internal component of a larger QUIC protocol library, facilitating the management of frame types and their attributes.
# Imports and Dependencies

---
- `../../../util/fd_util_base.h`
- `../fd_quic_enum.h`


# Global Variables

---
### fd\_quic\_frame\_type\_flags
- **Type**: `uchar const`
- **Description**: The `fd_quic_frame_type_flags` is a globally declared constant array of unsigned characters, aligned to a 32-byte boundary. It is used to store flags for each QUIC frame type, indicating the types of packets in which each frame type is allowed.
- **Use**: This variable is used to determine if a specific QUIC frame type is allowed in a given packet type by checking the corresponding flags.


# Functions

---
### fd\_quic\_frame\_type\_allowed<!-- {{#callable:fd_quic_frame_type_allowed}} -->
The `fd_quic_frame_type_allowed` function checks if a specific QUIC frame type is permitted for a given packet type.
- **Inputs**:
    - `pkt_type`: An unsigned integer representing the packet type, which should be one of FD_QUIC_PKT_TYPE_{INITIAL, HANDSHAKE, ZERO_RTT, ONE_RTT}.
    - `frame_type`: An unsigned integer representing the frame type, which should be less than FD_QUIC_FRAME_TYPE_CNT.
- **Control Flow**:
    - Check if `pkt_type` is greater than 4; if so, return 0 indicating the frame type is not allowed.
    - Check if `frame_type` is greater than or equal to FD_QUIC_FRAME_TYPE_CNT; if so, return 0 indicating the frame type is not allowed.
    - Return the result of a bitwise AND operation between `fd_quic_frame_type_flags[frame_type]` and `(1u<<pkt_type)`, converted to a boolean, indicating if the frame type is allowed for the packet type.
- **Output**: Returns 1 if the frame type is allowed for the given packet type, otherwise returns 0.


