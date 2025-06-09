# Purpose
This C header file defines constants, macros, and a data structure for an archiving system, likely part of a larger software project. It includes versioning and identification macros for different types of data fragments, specifically "shred" and "repair" types, which are distinguished using bit manipulation on a signature field. The file also defines a `fd_archiver_frag_header` structure, which is used to store metadata for each data fragment, including a magic number for validation, version, tile identifier, time since the previous fragment, data size, signature, and sequence number. This header is essential for managing and organizing data fragments within an archiving system, ensuring that each fragment is correctly identified and processed.
# Imports and Dependencies

---
- `../tiles.h`


# Data Structures

---
### fd\_archiver\_frag\_header
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the fragment header, used to verify its integrity.
    - `version`: Indicates the version of the fragment header format.
    - `tile_id`: Identifies the tile from which the fragment was received.
    - `ns_since_prev_fragment`: Specifies the number of nanoseconds since the previous fragment was received.
    - `sz`: Denotes the size of the fragment data portion that follows this header.
    - `sig`: Holds the signature of the fragment, used for validation and identification.
    - `seq`: Represents the sequence number of the fragment, indicating its order.
- **Description**: The `fd_archiver_frag_header` structure is a compact data structure used in the Firedance archiver system to encapsulate metadata for each fragment of data being archived. It includes fields for a magic number to ensure data integrity, a version number to track the format version, a tile identifier to specify the source of the fragment, and timing information to measure the interval since the last fragment. Additionally, it contains the size of the fragment data, a signature for validation, and a sequence number to maintain the order of fragments. This structure is crucial for managing and organizing data fragments in the archiving process.


---
### fd\_archiver\_frag\_header\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the fragment header, used to verify its integrity.
    - `version`: Indicates the version of the header format.
    - `tile_id`: Identifies the tile from which the fragment was received.
    - `ns_since_prev_fragment`: Represents the time in nanoseconds since the previous fragment was processed.
    - `sz`: Specifies the size of the fragment data that follows this header.
    - `sig`: Holds the signature of the fragment, used for validation and identification.
    - `seq`: The sequence number of the fragment, used to maintain order.
- **Description**: The `fd_archiver_frag_header_t` is a structure used in the Firedance archiver system to encapsulate metadata for each fragment written to an archive. It includes fields for a magic number to ensure data integrity, a version number for compatibility, a tile identifier to track the source, a timestamp to measure time intervals between fragments, the size of the fragment data, a signature for validation, and a sequence number to maintain the order of fragments. This structure is crucial for managing and organizing data fragments in the archiving process.


