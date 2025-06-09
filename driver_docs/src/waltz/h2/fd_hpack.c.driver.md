# Purpose
This C source code file is part of an implementation of the HPACK compression format, which is used in HTTP/2 to efficiently encode HTTP headers. The file provides functionality for reading and decoding HPACK-encoded header fields. It includes a static table of common HTTP headers and their values, which is a key component of HPACK's compression mechanism. The static table is used to quickly reference frequently used headers, reducing the size of HTTP/2 header frames. The file defines several functions that handle the initialization of HPACK reading structures, the selection of headers from the static table, and the decoding of headers, including handling Huffman-encoded data.

The code is structured to handle various types of HPACK instructions, such as indexed and literal header fields, and it includes error handling for compression errors. The functions [`fd_hpack_rd_next_raw`](#fd_hpack_rd_next_raw) and [`fd_hpack_rd_next`](#fd_hpack_rd_next) are central to the decoding process, with the latter also managing Huffman decoding using the `nghttp2_hd_huff_decode` function. The file is not a standalone executable but rather a component of a larger library, likely intended to be used in conjunction with other parts of an HTTP/2 implementation. It does not define public APIs directly but provides internal functionality that can be used by other parts of the library to decode HTTP/2 headers efficiently.
# Imports and Dependencies

---
- `fd_hpack.h`
- `fd_h2_base.h`
- `fd_hpack_private.h`
- `nghttp2_hd_huffman.h`
- `../../util/log/fd_log.h`


# Global Variables

---
### fd\_hpack\_static\_table
- **Type**: `fd_hpack_static_entry_t const[62]`
- **Description**: The `fd_hpack_static_table` is an array of 62 constant entries of type `fd_hpack_static_entry_t`. Each entry represents a predefined HTTP/2 header field with its name, name length, and value length. This table is used in the HPACK compression context to efficiently encode and decode HTTP/2 headers using a static set of common headers.
- **Use**: This variable is used to provide quick access to a set of predefined HTTP/2 headers for compression and decompression operations in the HPACK protocol.


# Functions

---
### fd\_hpack\_rd\_init<!-- {{#callable:fd_hpack_rd_init}} -->
The `fd_hpack_rd_init` function initializes an HPACK reader structure and skips over any dynamic table size updates in the source data.
- **Inputs**:
    - `rd`: A pointer to an `fd_hpack_rd_t` structure that will be initialized.
    - `src`: A pointer to the source data buffer containing HPACK encoded data.
    - `srcsz`: The size of the source data buffer in bytes.
- **Control Flow**:
    - Initialize the `rd` structure with the source data pointer and calculate the end of the source data using `srcsz`.
    - Enter a loop that continues as long as the current source pointer is less than the end of the source data.
    - In each iteration, read the first byte of the current source data.
    - Check if the byte indicates a dynamic table size update (i.e., the top three bits are `0x20`).
    - If it is a dynamic table size update, read the variable integer size using [`fd_hpack_rd_varint`](fd_hpack_private.h.driver.md#fd_hpack_rd_varint) and check if it is non-zero; if so, break the loop.
    - If the byte does not indicate a dynamic table size update, break the loop.
    - Increment the source pointer to skip the current byte if it was a dynamic table size update.
    - Return the initialized `rd` structure.
- **Output**: Returns a pointer to the initialized `fd_hpack_rd_t` structure.
- **Functions called**:
    - [`fd_hpack_rd_varint`](fd_hpack_private.h.driver.md#fd_hpack_rd_varint)


---
### fd\_hpack\_rd\_indexed<!-- {{#callable:fd_hpack_rd_indexed}} -->
The `fd_hpack_rd_indexed` function retrieves a header from the HPACK static table based on a given index and populates a header structure with the corresponding name and value.
- **Inputs**:
    - `hdr`: A pointer to an `fd_h2_hdr_t` structure where the header information will be stored.
    - `idx`: An unsigned long integer representing the index of the header in the HPACK static table.
- **Control Flow**:
    - Check if the index is out of bounds (0 or greater than 61); if so, return an error code `FD_H2_ERR_COMPRESSION`.
    - Retrieve the entry from the `fd_hpack_static_table` using the provided index.
    - Populate the `hdr` structure with the name, name length, value, value length, and a hint indicating the header is indexed.
    - Return `FD_H2_SUCCESS` to indicate successful execution.
- **Output**: Returns `FD_H2_SUCCESS` if the header is successfully retrieved and populated, or `FD_H2_ERR_COMPRESSION` if the index is invalid.


---
### fd\_hpack\_rd\_next\_raw<!-- {{#callable:fd_hpack_rd_next_raw}} -->
The `fd_hpack_rd_next_raw` function decodes the next HPACK header field from a source buffer, handling various encoding types and updating the header structure accordingly.
- **Inputs**:
    - `rd`: A pointer to an `fd_hpack_rd_t` structure representing the current state of the HPACK reader, including the source buffer and its end.
    - `hdr`: A pointer to an `fd_h2_hdr_t` structure where the decoded header field will be stored.
- **Control Flow**:
    - Check if the source pointer has reached the end of the buffer and log a critical error if so.
    - Read the first byte from the source buffer to determine the encoding type of the header field.
    - If the first byte indicates a name and value indexed header with an index in [0,63], call [`fd_hpack_rd_indexed`](#fd_hpack_rd_indexed) to decode it and set the appropriate hint.
    - If the first byte indicates a name and value literal header, read the name and value lengths using [`fd_hpack_rd_varint`](fd_hpack_private.h.driver.md#fd_hpack_rd_varint), check for buffer overflows, and update the header structure with the decoded name and value.
    - If the first byte indicates a name indexed and value literal header, read the name index and value length, check for buffer overflows, and update the header structure with the decoded value.
    - If the first byte indicates a name and value indexed header with an index >=128, read the index using [`fd_hpack_rd_varint`](fd_hpack_private.h.driver.md#fd_hpack_rd_varint) and call [`fd_hpack_rd_indexed`](#fd_hpack_rd_indexed).
    - Skip over any Dynamic Table Size Updates in the source buffer.
    - Return a compression error if an unknown HPACK instruction is encountered.
- **Output**: Returns a `uint` indicating success (`FD_H2_SUCCESS`) or an error code (`FD_H2_ERR_COMPRESSION`) if a decoding error occurs.
- **Functions called**:
    - [`fd_hpack_rd_indexed`](#fd_hpack_rd_indexed)
    - [`fd_hpack_rd_varint`](fd_hpack_private.h.driver.md#fd_hpack_rd_varint)


---
### fd\_hpack\_decoded\_sz\_max<!-- {{#callable:fd_hpack_decoded_sz_max}} -->
The `fd_hpack_decoded_sz_max` function calculates the maximum possible size of decoded data from a given encoded size using a conservative estimate for HPACK Huffman coding.
- **Inputs**:
    - `enc_sz`: The size of the encoded data in bytes, represented as an unsigned long integer.
- **Control Flow**:
    - The function takes the input `enc_sz` and multiplies it by 2 to calculate the maximum possible size of the decoded data.
    - The function returns the result of this multiplication as the output.
- **Output**: The function returns an unsigned long integer representing the maximum possible size of the decoded data, which is twice the size of the input encoded data.


---
### fd\_hpack\_rd\_next<!-- {{#callable:fd_hpack_rd_next}} -->
The `fd_hpack_rd_next` function decodes the next HPACK header field from a stream, handling Huffman decoding if necessary, and updates the header and scratch buffer accordingly.
- **Inputs**:
    - `hpack_rd`: A pointer to an `fd_hpack_rd_t` structure representing the HPACK reader state.
    - `hdr`: A pointer to an `fd_h2_hdr_t` structure where the decoded header field will be stored.
    - `scratch`: A pointer to a buffer pointer used for temporary storage during decoding.
    - `scratch_end`: A pointer to the end of the scratch buffer, used to ensure buffer bounds are not exceeded.
- **Control Flow**:
    - Call [`fd_hpack_rd_next_raw`](#fd_hpack_rd_next_raw) to read the next raw header field from the HPACK stream into `hdr` and check for errors.
    - If the header name is Huffman encoded, check if there is enough space in the scratch buffer for the decoded name, decode it using Huffman decoding, and update `hdr->name` and `hdr->name_len`.
    - If the header value is Huffman encoded, check if there is enough space in the scratch buffer for the decoded value, decode it using Huffman decoding, and update `hdr->value` and `hdr->value_len`.
    - Update the `scratch` pointer to reflect the new position after decoding.
    - Clear the Huffman hint bits in `hdr->hint` to indicate that Huffman decoding has been handled.
    - Return `FD_H2_SUCCESS` if successful, or an error code if any step fails.
- **Output**: Returns `FD_H2_SUCCESS` on successful decoding, or an error code if an error occurs during the process.
- **Functions called**:
    - [`fd_hpack_rd_next_raw`](#fd_hpack_rd_next_raw)
    - [`fd_hpack_decoded_sz_max`](#fd_hpack_decoded_sz_max)
    - [`nghttp2_hd_huff_decode_context_init`](nghttp2_hd_huffman.c.driver.md#nghttp2_hd_huff_decode_context_init)
    - [`nghttp2_hd_huff_decode`](nghttp2_hd_huffman.c.driver.md#nghttp2_hd_huff_decode)


