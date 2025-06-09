# Purpose
This C header file, `fd_hpack.h`, provides an interface for handling HPACK compression and decompression, specifically tailored for HTTP/2 headers. It defines structures and functions to facilitate the reading and decoding of HPACK-encoded header blocks, with a focus on static table and Huffman string coding, while explicitly avoiding the use of a dynamic table. The file includes the definition of `fd_h2_hdr_t`, a structure representing an HTTP/2 header with fields for name, value, and hints about their encoding, such as whether they are Huffman coded or indexed. Additionally, it defines `fd_hpack_rd_t`, a structure used to manage the reading process of HPACK-encoded data, and provides functions like `fd_hpack_rd_init` and [`fd_hpack_rd_next`](#fd_hpack_rd_next) to initialize and iterate over the encoded headers. The header is designed to work under the assumption that the peer's dynamic table size is set to zero, simplifying the decoding process by focusing on static table entries.
# Imports and Dependencies

---
- `fd_h2_base.h`


# Data Structures

---
### fd\_h2\_hdr
- **Type**: `struct`
- **Members**:
    - `name`: Pointer to the name of the HTTP/2 header.
    - `value`: Pointer to the value of the HTTP/2 header.
    - `name_len`: Length of the header name.
    - `hint`: Contains flags indicating if the name or value is Huffman coded or indexed.
    - `value_len`: Length of the header value.
- **Description**: The `fd_h2_hdr` structure represents an HTTP/2 header as a name-value pair, where both the name and value are stored as pointers to character arrays. The structure includes fields for the lengths of the name and value, as well as a hint field that provides metadata about the encoding of the header, such as whether the name or value is Huffman coded or indexed from a static table. This structure is used in the context of HPACK compression and decompression, which is a part of the HTTP/2 protocol.


---
### fd\_h2\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `name`: A pointer to the name of the HTTP/2 header, which is not null-terminated.
    - `value`: A pointer to the value of the HTTP/2 header, which is not null-terminated.
    - `name_len`: The length of the header name.
    - `hint`: A bitmask providing hints about the header, such as whether it is indexed or Huffman coded.
    - `value_len`: The length of the header value.
- **Description**: The `fd_h2_hdr_t` structure represents an HTTP/2 header name-value pair, with pointers to the name and value, and additional metadata such as their lengths and encoding hints. The structure is used in the context of HPACK compression and decompression, where headers may be stored in a static table, binary frame, or scratch buffer, and may be encoded using Huffman coding. The `hint` field provides information about the encoding and indexing of the header, facilitating efficient processing of HTTP/2 headers.


---
### fd\_hpack\_rd
- **Type**: `struct`
- **Members**:
    - `src`: A pointer to the start of the HPACK-encoded data source.
    - `src_end`: A pointer to the end of the HPACK-encoded data source.
- **Description**: The `fd_hpack_rd` structure is used to manage the reading of HPACK-encoded HTTP/2 headers. It contains pointers to the start (`src`) and end (`src_end`) of the data source, allowing functions to process the encoded data within these bounds. This structure is integral to the HPACK decoding process, ensuring that the data is read correctly and efficiently.


---
### fd\_hpack\_rd\_t
- **Type**: `struct`
- **Members**:
    - `src`: A pointer to the start of the HPACK-encoded HTTP/2 headers block.
    - `src_end`: A pointer to the end of the HPACK-encoded HTTP/2 headers block.
- **Description**: The `fd_hpack_rd_t` structure is designed to facilitate the reading of HPACK-encoded HTTP/2 headers. It contains pointers to the start and end of a source buffer that holds the encoded headers, allowing functions to process and decode the headers sequentially. This structure is integral to the HPACK decoding process, ensuring that headers are read correctly and efficiently from the encoded data block.


# Functions

---
### fd\_hpack\_rd\_done<!-- {{#callable:fd_hpack_rd_done}} -->
The `fd_hpack_rd_done` function checks if all header entries have been read from an HPACK-encoded HTTP/2 header block.
- **Inputs**:
    - `rd`: A pointer to a constant `fd_hpack_rd_t` structure representing the current state of reading from an HPACK-encoded header block.
- **Control Flow**:
    - The function compares the `src` pointer of the `fd_hpack_rd_t` structure to the `src_end` pointer.
    - If `src` is greater than or equal to `src_end`, it indicates that all data has been read, and the function returns 1.
    - If `src` is less than `src_end`, it indicates that there is more data to read, and the function returns 0.
- **Output**: The function returns an integer: 1 if all header entries have been read, or 0 if there are more entries to read.


# Function Declarations (Public API)

---
### fd\_hpack\_rd\_next<!-- {{#callable_declaration:fd_hpack_rd_next}} -->
Reads the next HPACK-encoded HTTP/2 header and decodes it.
- **Description**: This function reads the next header from an HPACK-encoded HTTP/2 header block using the provided `hpack_rd` reader. It populates the `hdr` structure with pointers to the decoded header name and value, which may point into the source buffer or the provided scratch buffer. The function handles Huffman decoding if necessary, as indicated by the `hint` field in `hdr`. The `scratch` pointer is updated to reflect the next free byte in the scratch buffer. This function should be called repeatedly until all headers are read, as indicated by `fd_hpack_rd_done`. It returns an error code if decoding fails due to reasons such as Huffman coding errors or insufficient scratch space, in which case the contents of `hdr` and the scratch buffer may be invalid.
- **Inputs**:
    - `hpack_rd`: A pointer to an `fd_hpack_rd_t` structure that represents the reader for the HPACK-encoded header block. It must be initialized and valid for the duration of the read operations.
    - `hdr`: A pointer to an `fd_h2_hdr_t` structure that will be populated with the decoded header name and value. The caller should not assume the contents are valid if the function returns an error.
    - `scratch`: A pointer to a pointer to the next free byte in a scratch buffer. This is updated by the function to reflect the new free position after decoding. The buffer must have sufficient space to accommodate the decoded data.
    - `scratch_end`: A pointer to the end of the scratch buffer, indicating the limit of writable space. The function will return an error if there is insufficient space to decode the header.
- **Output**: Returns `FD_H2_SUCCESS` on successful decoding and updates `hdr` and `*scratch`. Returns `FD_H2_ERR_COMPRESSION` on failure, leaving `hdr` and `*scratch` potentially invalid.
- **See also**: [`fd_hpack_rd_next`](fd_hpack.c.driver.md#fd_hpack_rd_next)  (Implementation)


