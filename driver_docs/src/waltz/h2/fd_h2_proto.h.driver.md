# Purpose
The provided C header file, `fd_h2_proto.h`, is designed to define constants, data structures, and utility functions related to the HTTP/2 protocol. It serves as a foundational component for handling HTTP/2 frames and settings, encapsulating the protocol's specifications into a programmatically accessible format. The file includes definitions for various HTTP/2 frame types, such as DATA, HEADERS, and SETTINGS, using macros to assign specific identifiers to each frame type. Additionally, it provides structures that match the encoding of different HTTP/2 frames, such as `fd_h2_frame_hdr_t`, `fd_h2_priority_t`, and `fd_h2_ping_t`, among others. These structures are packed to ensure they align with the protocol's binary format requirements.

The file also includes inline functions for packing and unpacking frame headers, such as [`fd_h2_frame_type`](#fd_h2_frame_type), [`fd_h2_frame_length`](#fd_h2_frame_length), and [`fd_h2_frame_typlen`](#fd_h2_frame_typlen), which facilitate the manipulation of frame headers by extracting or setting the type and length fields. Furthermore, it defines functions like [`fd_h2_frame_name`](#fd_h2_frame_name) and [`fd_h2_setting_name`](#fd_h2_setting_name) to retrieve human-readable names for frame types and settings, enhancing the interpretability of the protocol's components. This header file is intended to be included in other C source files that require HTTP/2 protocol handling, providing a consistent and standardized interface for working with HTTP/2 frames and settings.
# Imports and Dependencies

---
- `fd_h2_base.h`


# Global Variables

---
### fd\_h2\_frame\_name
- **Type**: `function`
- **Description**: The `fd_h2_frame_name` function returns a static-lifetime uppercase C string representing the name of an HTTP/2 frame based on the provided frame ID. This function is designed to map frame IDs to their corresponding human-readable names, which are defined as constants in the HTTP/2 specification.
- **Use**: This function is used to retrieve the name of an HTTP/2 frame for a given frame ID, facilitating easier debugging and logging by providing a human-readable frame name.


---
### fd\_h2\_setting\_name
- **Type**: `function`
- **Description**: The `fd_h2_setting_name` function returns a constant character string representing the name of an HTTP/2 setting based on the provided setting ID. It is designed to map setting IDs to their corresponding human-readable names as defined in the HTTP/2 specifications.
- **Use**: This function is used to retrieve the name of an HTTP/2 setting for a given setting ID, facilitating easier interpretation and debugging of HTTP/2 settings.


# Data Structures

---
### fd\_h2\_frame\_hdr
- **Type**: `struct`
- **Members**:
    - `typlen`: A 32-bit unsigned integer representing the combined type and length of the HTTP/2 frame.
    - `flags`: An 8-bit unsigned character representing the flags associated with the HTTP/2 frame.
    - `r_stream_id`: A 32-bit unsigned integer representing the stream identifier for the HTTP/2 frame.
- **Description**: The `fd_h2_frame_hdr` structure is a packed data structure that represents the header of an HTTP/2 frame. It includes fields for the type and length of the frame (`typlen`), any flags associated with the frame (`flags`), and the stream identifier (`r_stream_id`). This structure is used to encode and decode the header information of HTTP/2 frames as specified in the HTTP/2 protocol, ensuring efficient communication and data transfer over the network.


---
### fd\_h2\_frame\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `typlen`: A 32-bit unsigned integer representing the combined type and length of the HTTP/2 frame.
    - `flags`: An 8-bit unsigned character representing the flags associated with the HTTP/2 frame.
    - `r_stream_id`: A 32-bit unsigned integer representing the stream identifier, with the most significant bit reserved.
- **Description**: The `fd_h2_frame_hdr_t` structure is a packed representation of an HTTP/2 frame header, as defined by the HTTP/2 specification. It encapsulates the type and length of the frame in a single 32-bit field (`typlen`), the frame's flags in an 8-bit field (`flags`), and the stream identifier in a 32-bit field (`r_stream_id`). This structure is fundamental for encoding and decoding HTTP/2 frames, ensuring that the frame headers are correctly interpreted and processed according to the protocol's requirements.


---
### fd\_h2\_priority
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that contains metadata about the HTTP/2 frame.
    - `r_stream_dep`: An unsigned integer representing the stream dependency.
    - `weight`: An unsigned character representing the weight of the stream.
- **Description**: The `fd_h2_priority` structure is used to represent the encoding of a PRIORITY frame in the HTTP/2 protocol. It includes a frame header (`hdr`) that provides metadata about the frame, a stream dependency (`r_stream_dep`) which indicates the stream that this frame depends on, and a weight (`weight`) that specifies the relative weight of the stream for prioritization purposes. This structure is packed to ensure that there is no padding between its members, which is crucial for network protocol data structures.


---
### fd\_h2\_priority\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that encodes the HTTP/2 frame header.
    - `r_stream_dep`: An unsigned integer representing the stream dependency.
    - `weight`: An unsigned character representing the weight of the stream.
- **Description**: The `fd_h2_priority_t` structure is used to represent the encoding of a PRIORITY frame in the HTTP/2 protocol. It includes a frame header (`hdr`) that provides metadata about the frame, a stream dependency (`r_stream_dep`) which indicates the stream that this frame depends on, and a weight (`weight`) that specifies the relative weight of the stream for prioritization purposes. This structure is packed to ensure that it matches the exact encoding required by the HTTP/2 specification.


---
### fd\_h2\_setting
- **Type**: `struct`
- **Members**:
    - `id`: A 16-bit unsigned short representing the setting identifier.
    - `value`: A 32-bit unsigned integer representing the value associated with the setting.
- **Description**: The `fd_h2_setting` structure is used to represent a single HTTP/2 setting in a SETTINGS frame. Each setting consists of an identifier (`id`) and a corresponding value (`value`), which are used to configure various parameters of the HTTP/2 connection, such as header table size, maximum concurrent streams, and initial window size. The structure is packed to ensure no padding is added between its fields, which is important for network protocol data structures.


---
### fd\_h2\_setting\_t
- **Type**: `struct`
- **Members**:
    - `id`: A 16-bit unsigned integer representing the setting identifier.
    - `value`: A 32-bit unsigned integer representing the value associated with the setting.
- **Description**: The `fd_h2_setting_t` structure is used to represent a single HTTP/2 setting within a SETTINGS frame. Each setting consists of an identifier (`id`) and a corresponding value (`value`), which are used to configure various parameters of the HTTP/2 connection, such as header table size, maximum concurrent streams, and initial window size. This structure is packed to ensure efficient transmission and alignment in network communications.


---
### fd\_h2\_ping
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that contains metadata about the PING frame.
    - `payload`: An unsigned long integer representing the payload of the PING frame.
- **Description**: The `fd_h2_ping` structure represents the encoding of a PING frame in the HTTP/2 protocol. It includes a frame header (`hdr`) that provides essential metadata about the frame, such as its type and length, and a `payload` field that holds the actual data being transmitted. The structure is packed to ensure that there is no padding between its members, which is crucial for network communication where precise data alignment is required.


---
### fd\_h2\_ping\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that contains metadata for the PING frame.
    - `payload`: An 8-byte payload used for the PING frame, typically for round-trip time measurement.
- **Description**: The `fd_h2_ping_t` structure represents the encoding of a PING frame in the HTTP/2 protocol. It includes a frame header (`hdr`) and an 8-byte payload (`payload`). The PING frame is used primarily for measuring round-trip time and ensuring that a connection is still active. The structure is packed to match the exact byte layout as specified in the HTTP/2 specification.


---
### fd\_h2\_goaway
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that contains metadata about the frame.
    - `last_stream_id`: The identifier of the last stream that was processed.
    - `error_code`: An error code indicating the reason for the connection closure.
- **Description**: The `fd_h2_goaway` structure represents a GOAWAY frame in the HTTP/2 protocol, which is used to initiate the graceful shutdown of a connection. It includes a frame header, the last stream ID that was successfully processed, and an error code to indicate the reason for the shutdown. Additionally, it may contain variable-length debug data following the fixed fields.


---
### fd\_h2\_goaway\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that encodes the HTTP/2 frame header.
    - `last_stream_id`: An unsigned integer representing the last stream identifier processed by the sender.
    - `error_code`: An unsigned integer indicating the error code associated with the GOAWAY frame.
- **Description**: The `fd_h2_goaway_t` structure represents the encoding of a GOAWAY frame in the HTTP/2 protocol, which is used to initiate the graceful shutdown of a connection. It includes a frame header, the last stream ID that was processed, and an error code to indicate the reason for the shutdown. Additionally, it may contain variable-length debug data following the error code.


---
### fd\_h2\_window\_update
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that contains metadata about the HTTP/2 frame.
    - `increment`: An unsigned integer representing the window size increment for flow control.
- **Description**: The `fd_h2_window_update` structure is used to represent a WINDOW_UPDATE frame in the HTTP/2 protocol, which is responsible for flow control by indicating how much the sender is allowed to send. It contains a frame header (`hdr`) and an `increment` field that specifies the number of additional bytes the sender can transmit.


---
### fd\_h2\_window\_update\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that encodes the HTTP/2 frame header.
    - `increment`: An unsigned integer representing the window size increment for the WINDOW_UPDATE frame.
- **Description**: The `fd_h2_window_update_t` structure is used to represent the WINDOW_UPDATE frame in the HTTP/2 protocol. This frame is used to implement flow control by allowing the sender to inform the receiver of the number of octets it can send on a stream or connection. The structure contains a frame header (`hdr`) and an `increment` field, which specifies the number of additional octets that the sender can transmit.


---
### fd\_h2\_rst\_stream
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that contains metadata about the frame.
    - `error_code`: An unsigned integer representing the error code associated with the RST_STREAM frame.
- **Description**: The `fd_h2_rst_stream` structure is a packed data structure that represents the RST_STREAM frame in the HTTP/2 protocol. It includes a frame header (`hdr`) and an error code (`error_code`) to indicate the reason for the stream reset. This structure is used to communicate stream errors and is part of the HTTP/2 frame encoding as specified in the protocol's RFC.


---
### fd\_h2\_rst\_stream\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: A frame header of type `fd_h2_frame_hdr_t` that encodes the HTTP/2 frame header.
    - `error_code`: An unsigned integer representing the error code associated with the RST_STREAM frame.
- **Description**: The `fd_h2_rst_stream_t` structure represents the encoding of a RST_STREAM frame in the HTTP/2 protocol, which is used to abruptly terminate a stream. It contains a frame header (`hdr`) and an error code (`error_code`) that indicates the reason for the stream reset, allowing for efficient communication of stream termination events in HTTP/2.


# Functions

---
### fd\_h2\_frame\_type<!-- {{#callable:fd_h2_frame_type}} -->
The `fd_h2_frame_type` function extracts the frame type from a 32-bit integer representing the HTTP/2 frame header's type and length field.
- **Inputs**:
    - `typlen`: A 32-bit unsigned integer representing the combined type and length field of an HTTP/2 frame header.
- **Control Flow**:
    - The function takes a 32-bit unsigned integer `typlen` as input.
    - It performs a right bitwise shift by 24 bits on `typlen` to isolate the most significant byte, which represents the frame type.
    - The result is cast to an `uchar` and returned.
- **Output**: The function returns an `uchar` representing the frame type, which is the most significant byte of the input `typlen`.


---
### fd\_h2\_frame\_length<!-- {{#callable:fd_h2_frame_length}} -->
The `fd_h2_frame_length` function extracts the 24-bit frame length from a 32-bit HTTP/2 frame header field by swapping byte order and masking.
- **Inputs**:
    - `typlen`: A 32-bit unsigned integer representing the combined type and length field of an HTTP/2 frame header.
- **Control Flow**:
    - The function takes a 32-bit unsigned integer `typlen` as input.
    - It shifts `typlen` left by 8 bits to align the length field correctly.
    - The function then calls `fd_uint_bswap` to swap the byte order of the shifted value.
    - Finally, it applies a bitwise AND operation with `0xFFFFFF` to extract the lower 24 bits, which represent the frame length.
- **Output**: A 24-bit unsigned integer representing the length of the HTTP/2 frame, extracted from the `typlen` field.


---
### fd\_h2\_frame\_typlen<!-- {{#callable:fd_h2_frame_typlen}} -->
The `fd_h2_frame_typlen` function packs the type and length of an HTTP/2 frame into a single 32-bit unsigned integer for use in a frame header.
- **Inputs**:
    - `type`: An unsigned long integer representing the frame type, expected to be in the range [0, 256).
    - `length`: An unsigned long integer representing the frame length, expected to be in the range [0, 16777216).
- **Control Flow**:
    - The function casts the `length` to a 32-bit unsigned integer and performs a byte swap using `fd_uint_bswap` to convert it to network byte order.
    - The swapped length is then right-shifted by 8 bits to align it properly within the 24 least significant bits of the result.
    - The `type` is cast to a 32-bit unsigned integer and left-shifted by 24 bits to occupy the 8 most significant bits of the result.
    - The function combines the shifted type and length using a bitwise OR operation to produce the final packed `typlen` value.
- **Output**: A 32-bit unsigned integer representing the packed type and length of an HTTP/2 frame, suitable for use in a frame header.


---
### fd\_h2\_frame\_stream\_id<!-- {{#callable:fd_h2_frame_stream_id}} -->
The function `fd_h2_frame_stream_id` converts a stream identifier from network byte order to host byte order and masks it to ensure it is a valid HTTP/2 stream identifier.
- **Inputs**:
    - `r_stream_id`: An unsigned integer representing the stream identifier in network byte order.
- **Control Flow**:
    - The function calls `fd_uint_bswap` to swap the byte order of `r_stream_id`, converting it from network byte order to host byte order.
    - The result of the byte swap is then bitwise ANDed with `0x7fffffffu` to ensure the stream identifier is within the valid range for HTTP/2 stream identifiers.
- **Output**: The function returns an unsigned integer representing the stream identifier in host byte order, masked to be a valid HTTP/2 stream identifier.


# Function Declarations (Public API)

---
### fd\_h2\_frame\_name<!-- {{#callable_declaration:fd_h2_frame_name}} -->
Return the name of an HTTP/2 frame type.
- **Description**: Use this function to obtain a human-readable name for a given HTTP/2 frame type identifier. It is useful for logging, debugging, or displaying frame type information in a user interface. The function returns a constant string corresponding to the frame type if the identifier is recognized. If the frame identifier is not recognized, it returns "unknown". This function does not modify any input and is safe to call with any unsigned integer value.
- **Inputs**:
    - `frame_id`: An unsigned integer representing the HTTP/2 frame type identifier. Valid values are defined by constants such as FD_H2_FRAME_TYPE_DATA, FD_H2_FRAME_TYPE_HEADERS, etc. Any value outside these predefined constants will result in the function returning "unknown".
- **Output**: A constant string representing the name of the HTTP/2 frame type corresponding to the given identifier, or "unknown" if the identifier is not recognized.
- **See also**: [`fd_h2_frame_name`](fd_h2_proto.c.driver.md#fd_h2_frame_name)  (Implementation)


---
### fd\_h2\_setting\_name<!-- {{#callable_declaration:fd_h2_setting_name}} -->
Returns the name of a HTTP/2 setting as a string.
- **Description**: Use this function to obtain a human-readable name for a given HTTP/2 setting identifier. This is useful for debugging or logging purposes where you need to display the setting name instead of its numeric identifier. The function returns a string with a static lifetime, meaning the caller does not need to manage the memory of the returned string. If the provided setting identifier does not match any known HTTP/2 setting, the function returns "unknown".
- **Inputs**:
    - `setting_id`: An unsigned integer representing the HTTP/2 setting identifier. Valid values are specific constants defined for HTTP/2 settings, such as FD_H2_SETTINGS_HEADER_TABLE_SIZE, FD_H2_SETTINGS_ENABLE_PUSH, etc. If the value does not correspond to a known setting, the function returns "unknown".
- **Output**: A constant character pointer to a string representing the name of the HTTP/2 setting. The string has a static lifetime and does not require the caller to free it.
- **See also**: [`fd_h2_setting_name`](fd_h2_proto.c.driver.md#fd_h2_setting_name)  (Implementation)


