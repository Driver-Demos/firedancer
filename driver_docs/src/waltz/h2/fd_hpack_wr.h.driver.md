# Purpose
The provided C header file, `fd_hpack_wr.h`, defines a set of inline functions for generating HPACK header entries, which are used in HTTP/2 for header compression. The file offers a straightforward API to create various HTTP/2 headers, such as `:method`, `:scheme`, `:path`, `user-agent`, `authorization`, and `:authority`. These functions are designed to serialize headers in a simple manner, potentially at the cost of some efficiency in terms of serialization size. The file includes conditional compilation for x86 architectures to optimize certain operations using intrinsic functions.

The core functionality revolves around writing headers to a ring buffer (`fd_h2_rbuf_t`), which is a common pattern in network programming for managing data streams. The file includes functions for encoding variable-length integers, which are essential for HPACK's header compression mechanism. The functions are designed to be used internally within a larger HTTP/2 implementation, as indicated by the use of static inline functions and the absence of external linkage. The header file does not define a public API for external use but rather serves as a utility within a broader HTTP/2 handling library or application.
# Imports and Dependencies

---
- `fd_h2_base.h`
- `fd_h2_rbuf.h`
- `immintrin.h`


# Functions

---
### fd\_hpack\_wr\_varint<!-- {{#callable:fd_hpack_wr_varint}} -->
The `fd_hpack_wr_varint` function encodes a variable-length integer into a byte array using a specified prefix and addend, suitable for HPACK header compression.
- **Inputs**:
    - `code`: An array of 9 unsigned characters where the encoded integer will be stored.
    - `prefix`: An unsigned integer representing the prefix to be used in the encoding.
    - `addend`: An unsigned integer that is added to the prefix to determine the initial encoding value.
    - `number`: An unsigned long integer representing the number to be encoded, which must be in the range [0, 2^56).
- **Control Flow**:
    - Initialize a variable `sz` to store the size of the encoded integer.
    - Check if `number` is less than `addend`; if true, encode `number` directly with the prefix and set `sz` to 1.
    - If `number` is not less than `addend`, encode `addend` with the prefix and calculate the `tail` as `number - addend`.
    - If the system supports x86 with BMI2, use `_pdep_u64` to encode `tail` into a variable-length format; otherwise, manually encode `tail` using bitwise operations.
    - Find the most significant bit (MSB) of the encoded value to determine the number of bytes needed for encoding.
    - Calculate a mask to set the continuation bits in the encoded value and store the result in `code`.
    - Calculate the total size `sz` of the encoded integer based on the MSB position and return it.
- **Output**: Returns the size of the encoded integer as an unsigned long integer.


---
### fd\_hpack\_wr\_private\_indexed<!-- {{#callable:fd_hpack_wr_private_indexed}} -->
The `fd_hpack_wr_private_indexed` function writes an HPACK indexed header field representation to a buffer if there is sufficient space available.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the buffer where the HPACK indexed header field will be written.
    - `idx`: An unsigned long integer representing the index of the header field to be encoded and written to the buffer.
- **Control Flow**:
    - Check if there is enough free space in the buffer `rbuf_tx` using [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz); if not, return 0 indicating failure.
    - Create a single-byte array `code` containing the encoded index using the macro `FD_HPACK_INDEXED_SHORT(idx)`.
    - Push the `code` array into the buffer `rbuf_tx` using [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push).
    - Return 1 indicating success.
- **Output**: Returns an integer, 1 if the operation is successful (i.e., the buffer has enough space and the index is written), or 0 if there is insufficient space in the buffer.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_hpack\_wr\_private\_name\_indexed\_0<!-- {{#callable:fd_hpack_wr_private_name_indexed_0}} -->
The function `fd_hpack_wr_private_name_indexed_0` writes a header entry with a private name indexed representation into a buffer, ensuring there is enough space for the data.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the transmission buffer where the header entry will be written.
    - `key`: An unsigned long integer representing the key to be used as the first byte of the prefix.
    - `value_len`: An unsigned long integer representing the length of the value, which must be in the range [0, 128).
- **Control Flow**:
    - Initialize a prefix array with the first element set to the key cast to an unsigned char.
    - Check if the free size in the buffer `rbuf_tx` is less than the combined size of the prefix and the value length; if so, return 0 indicating failure.
    - Calculate the length of the prefix by adding 1 to the result of [`fd_hpack_wr_varint`](#fd_hpack_wr_varint), which encodes the value length as a variable-length integer starting at the second byte of the prefix.
    - Push the prefix into the buffer `rbuf_tx` using [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push).
    - Return 1 to indicate success.
- **Output**: Returns an integer, 1 if the operation is successful and 0 if there is not enough space in the buffer to write the data.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_hpack_wr_varint`](#fd_hpack_wr_varint)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_hpack\_wr\_method\_post<!-- {{#callable:fd_hpack_wr_method_post}} -->
The `fd_hpack_wr_method_post` function writes an HTTP/2 POST method header to a buffer using HPACK encoding.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the transmission buffer where the encoded header will be written.
- **Control Flow**:
    - The function calls [`fd_hpack_wr_private_indexed`](#fd_hpack_wr_private_indexed) with `rbuf_tx` and the index `0x03`, which corresponds to the POST method in the HPACK static table.
    - The [`fd_hpack_wr_private_indexed`](#fd_hpack_wr_private_indexed) function checks if there is enough space in the buffer and writes the encoded header if possible.
    - The function returns the result of [`fd_hpack_wr_private_indexed`](#fd_hpack_wr_private_indexed), which is `1` if successful and `0` if there is not enough space in the buffer.
- **Output**: An integer indicating success (`1`) or failure (`0`) of writing the POST method header to the buffer.
- **Functions called**:
    - [`fd_hpack_wr_private_indexed`](#fd_hpack_wr_private_indexed)


---
### fd\_hpack\_wr\_scheme<!-- {{#callable:fd_hpack_wr_scheme}} -->
The `fd_hpack_wr_scheme` function writes an HPACK header entry for the HTTP scheme, either 'http' or 'https', into a buffer.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the buffer where the HPACK header entry will be written.
    - `is_https`: An integer flag indicating whether the scheme is HTTPS (non-zero value) or HTTP (zero value).
- **Control Flow**:
    - The function checks if the `is_https` flag is true (non-zero).
    - If `is_https` is true, it calls [`fd_hpack_wr_private_indexed`](#fd_hpack_wr_private_indexed) with `rbuf_tx` and the index `0x07`, which corresponds to the 'https' scheme.
    - If `is_https` is false, it calls [`fd_hpack_wr_private_indexed`](#fd_hpack_wr_private_indexed) with `rbuf_tx` and the index `0x06`, which corresponds to the 'http' scheme.
- **Output**: The function returns an integer indicating success (1) or failure (0) of writing the header entry to the buffer.
- **Functions called**:
    - [`fd_hpack_wr_private_indexed`](#fd_hpack_wr_private_indexed)


---
### fd\_hpack\_wr\_path<!-- {{#callable:fd_hpack_wr_path}} -->
The `fd_hpack_wr_path` function writes an HPACK ':path' header to a buffer, ensuring the path length is within a specified range.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the buffer where the HPACK header will be written.
    - `path`: A constant character pointer to the path string to be written as the header value.
    - `path_len`: An unsigned long integer representing the length of the path string, which must be in the range [0,128).
- **Control Flow**:
    - Check if writing the path header is possible by calling [`fd_hpack_wr_private_name_indexed_0`](#fd_hpack_wr_private_name_indexed_0) with the buffer, a key of 0x04, and the path length.
    - If the above check fails (returns 0), the function returns 0, indicating failure.
    - If the check succeeds, push the path string into the buffer using [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push).
    - Return 1 to indicate successful writing of the path header.
- **Output**: The function returns an integer: 1 if the path header was successfully written to the buffer, or 0 if it failed.
- **Functions called**:
    - [`fd_hpack_wr_private_name_indexed_0`](#fd_hpack_wr_private_name_indexed_0)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_hpack\_wr\_trailers<!-- {{#callable:fd_hpack_wr_trailers}} -->
The `fd_hpack_wr_trailers` function writes the 'te: trailers' header into a buffer if there is enough space available.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` buffer where the 'te: trailers' header will be written.
- **Control Flow**:
    - Define a static character array `code` containing the serialized 'te: trailers' header.
    - Check if the free space in `rbuf_tx` is less than the size of `code` minus one; if so, return 0 indicating failure.
    - If there is enough space, push the `code` into `rbuf_tx` using [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push).
    - Return 1 indicating success.
- **Output**: Returns 1 if the 'te: trailers' header is successfully written to the buffer, otherwise returns 0 if there is insufficient space.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_hpack\_wr\_user\_agent<!-- {{#callable:fd_hpack_wr_user_agent}} -->
The `fd_hpack_wr_user_agent` function writes a 'user-agent' header to a buffer using HPACK encoding.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the buffer where the 'user-agent' header will be written.
    - `user_agent_len`: An unsigned long integer representing the length of the user-agent string, which must be in the range [0,128).
- **Control Flow**:
    - The function calls [`fd_hpack_wr_private_name_indexed_0`](#fd_hpack_wr_private_name_indexed_0) with `rbuf_tx`, a key value of `0x7a`, and `user_agent_len` as arguments.
    - The [`fd_hpack_wr_private_name_indexed_0`](#fd_hpack_wr_private_name_indexed_0) function checks if there is enough space in the buffer to write the header and the user-agent value.
    - If there is enough space, it writes the header prefix and the user-agent length to the buffer.
    - The function returns the result of [`fd_hpack_wr_private_name_indexed_0`](#fd_hpack_wr_private_name_indexed_0), which is 1 if successful and 0 if there is not enough space.
- **Output**: The function returns an integer, 1 if the 'user-agent' header was successfully written to the buffer, or 0 if there was insufficient space in the buffer.
- **Functions called**:
    - [`fd_hpack_wr_private_name_indexed_0`](#fd_hpack_wr_private_name_indexed_0)


---
### fd\_hpack\_wr\_auth\_bearer<!-- {{#callable:fd_hpack_wr_auth_bearer}} -->
The `fd_hpack_wr_auth_bearer` function writes an 'authorization: Bearer xxx' HTTP header into a buffer, using a never-indexed literal to prevent compression attacks.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the buffer where the header will be written.
    - `auth_token`: A constant character pointer to the authorization token string that will be included in the header.
    - `auth_token_len`: An unsigned long integer representing the length of the authorization token.
- **Control Flow**:
    - Initialize a prefix array with specific values to indicate a never-indexed literal header field.
    - Calculate the total length of the value, which includes the length of the 'Bearer ' string and the authorization token.
    - Check if the buffer has enough free space to accommodate the prefix and the value; if not, return 0 indicating failure.
    - Calculate the length of the prefix using the [`fd_hpack_wr_varint`](#fd_hpack_wr_varint) function to encode the value length.
    - Push the prefix, 'Bearer ' string, and the authorization token into the buffer in sequence.
    - Return 1 to indicate success.
- **Output**: The function returns an integer: 1 if the header was successfully written to the buffer, or 0 if there was insufficient space in the buffer.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_hpack_wr_varint`](#fd_hpack_wr_varint)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_hpack\_wr\_authority<!-- {{#callable:fd_hpack_wr_authority}} -->
The `fd_hpack_wr_authority` function writes an ':authority: host[:port]' header to a buffer, including the port if it is non-zero.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` buffer where the header will be written.
    - `host`: A constant character pointer representing the host name.
    - `host_len`: An unsigned long representing the length of the host name.
    - `port`: An unsigned short representing the port number, which is included in the header if non-zero.
- **Control Flow**:
    - Initialize a character array `suffix_cstr` to store the port as a string, if applicable.
    - Calculate the length of the port number in base 10 digits using `fd_ushort_base10_dig_cnt`.
    - Initialize a pointer `p` to the start of `suffix_cstr` using `fd_cstr_init`.
    - Append a colon ':' to `suffix_cstr` using `fd_cstr_append_char`.
    - Convert the port number to a string and append it to `suffix_cstr` using `fd_cstr_append_ushort_as_text`.
    - Calculate the length of the `suffix_cstr` by subtracting the start address from the current pointer `p`.
    - Finalize the C-string operations with `fd_cstr_fini`.
    - Calculate the total length of the value to be written by adding `host_len` and `suffix_len`.
    - Initialize a prefix array with a single byte set to 0x01.
    - Check if there is enough space in `rbuf_tx` to write the prefix and value; return 0 if not enough space.
    - Calculate the length of the prefix using [`fd_hpack_wr_varint`](#fd_hpack_wr_varint) and store it in `prefix_len`.
    - Push the prefix, host, and suffix (if applicable) to `rbuf_tx` using [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push).
    - Return 1 to indicate success.
- **Output**: Returns an integer 1 if the header is successfully written to the buffer, or 0 if there is insufficient space in the buffer.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_hpack_wr_varint`](#fd_hpack_wr_varint)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


