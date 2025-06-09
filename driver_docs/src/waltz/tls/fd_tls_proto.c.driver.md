# Purpose
This C source code file is part of a library that implements Transport Layer Security (TLS) protocol functionalities, specifically focusing on encoding and decoding various TLS handshake messages and extensions. The file includes functions for handling client and server hello messages, certificate messages, and various TLS extensions such as supported versions, key shares, and application-layer protocol negotiation (ALPN). The code is structured to handle the serialization and deserialization of these messages, ensuring they conform to the TLS protocol specifications, particularly TLS 1.3 as indicated by the use of constants like `FD_TLS_VERSION_TLS13`.

The file is not an executable but rather a component of a larger library, as evidenced by the absence of a `main` function and the inclusion of multiple header files that define the necessary data structures and constants. The functions defined in this file are likely intended to be used by other parts of the TLS library or by applications that require TLS communication capabilities. The code provides a narrow but essential functionality within the TLS protocol, focusing on the low-level details of message construction and parsing, which are critical for secure and reliable communication. The use of macros and helper functions suggests an emphasis on code reuse and maintainability, which is typical in protocol implementation to handle the complexity and variability of message formats.
# Imports and Dependencies

---
- `fd_tls.h`
- `fd_tls_proto.h`
- `fd_tls_serde.h`
- `fd_tls_asn1.h`
- `../../ballet/x509/fd_x509_mock.h`


# Global Variables

---
### hello\_retry\_magic
- **Type**: ``uchar const[32]``
- **Description**: The `hello_retry_magic` is a static constant array of 32 unsigned characters, representing a hardcoded value used in the TLS 1.3 protocol as specified by RFC 8446. This array contains a specific sequence of bytes that is used as the 'random' field in a RetryHelloRequest message.
- **Use**: This variable is used to identify and validate a RetryHelloRequest in the TLS handshake process.


# Data Structures

---
### tls\_u24
- **Type**: `typedef struct fd_tls_u24 tls_u24;`
- **Description**: The `tls_u24` is a typedef for a structure named `fd_tls_u24`, which is used as a helper in code generation for handling 24-bit unsigned integers in the context of TLS (Transport Layer Security) operations. This structure is likely used to facilitate the encoding and decoding of 24-bit fields within TLS messages, although the specific fields and implementation details of `fd_tls_u24` are not provided in the given code.


# Functions

---
### fd\_tls\_decode\_client\_hello<!-- {{#callable:fd_tls_decode_client_hello}} -->
The `fd_tls_decode_client_hello` function decodes a TLS ClientHello message from a wire format into a structured format, extracting various fields and extensions.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_client_hello_t` structure where the decoded ClientHello data will be stored.
    - `wire`: A constant pointer to the byte array containing the wire format of the ClientHello message.
    - `wire_sz`: The size of the wire format data in bytes.
- **Control Flow**:
    - Initialize `wire_laddr` to point to the start of the wire data.
    - Decode the static-sized part of the ClientHello, including legacy version, random bytes, and session ID size.
    - Check if the session ID size is valid and update the session ID in the output structure.
    - Decode the list of cipher suites, setting flags for supported cipher suites in the output structure.
    - Decode the static-sized part of the ClientHello related to compression methods and validate them.
    - Iterate over the extensions in the ClientHello, decoding each based on its type and updating the output structure accordingly.
    - Return the number of bytes processed from the wire data.
- **Output**: Returns the number of bytes processed from the wire data, or a negative error code if decoding fails.
- **Functions called**:
    - [`fd_tls_decode_ext_supported_versions`](#fd_tls_decode_ext_supported_versions)
    - [`fd_tls_decode_ext_server_name`](#fd_tls_decode_ext_server_name)
    - [`fd_tls_decode_ext_supported_groups`](#fd_tls_decode_ext_supported_groups)
    - [`fd_tls_decode_ext_signature_algorithms`](#fd_tls_decode_ext_signature_algorithms)
    - [`fd_tls_decode_key_share_list`](#fd_tls_decode_key_share_list)
    - [`fd_tls_decode_ext_cert_type_list`](#fd_tls_decode_ext_cert_type_list)
    - [`fd_tls_decode_ext_quic_tp`](fd_tls_proto.h.driver.md#fd_tls_decode_ext_quic_tp)
    - [`fd_tls_decode_ext_alpn`](#fd_tls_decode_ext_alpn)


---
### FD\_TLS\_DECODE\_LIST\_BEGIN<!-- {{#callable:fd_tls_decode_ext_cert_type_list::FD_TLS_DECODE_LIST_BEGIN}} -->
The `FD_TLS_DECODE_LIST_BEGIN` function initializes a decoding loop for a list of TLS certificate types, setting flags in the output structure based on the certificate type encountered.
- **Inputs**:
    - `uchar`: The data type for the certificate type being decoded.
    - `alignof(uchar)`: The alignment requirement for the `uchar` type, used to ensure proper memory alignment during decoding.
- **Control Flow**:
    - The function begins a decoding loop for a list of certificate types using the `FD_TLS_DECODE_LIST_BEGIN` macro.
    - A `uchar` variable `cert_type` is declared to store the current certificate type being decoded.
    - The `FD_TLS_DECODE_FIELD` macro is used to decode the certificate type into `cert_type`.
    - A switch statement checks the value of `cert_type` to determine the type of certificate.
    - If `cert_type` is `FD_TLS_CERTTYPE_X509`, the `x509` field in the output structure is set to 1.
    - If `cert_type` is `FD_TLS_CERTTYPE_RAW_PUBKEY`, the `raw_pubkey` field in the output structure is set to 1.
    - For unsupported certificate types, the function does nothing and continues to the next item in the list.
    - The function ends the decoding loop with the `FD_TLS_DECODE_LIST_END` macro.
- **Output**: The function does not return a value directly; it modifies the output structure by setting flags based on the certificate types encountered in the list.


---
### fd\_tls\_encode\_client\_hello<!-- {{#callable:fd_tls_encode_client_hello}} -->
The `fd_tls_encode_client_hello` function encodes a TLS client hello message into a wire format, including static fields and various extensions.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_client_hello_t` structure containing the client hello data to be encoded.
    - `wire`: A pointer to a buffer where the encoded client hello message will be stored.
    - `wire_sz`: The size of the buffer pointed to by `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of the `wire` buffer.
    - Define and initialize static fields for the client hello message, including legacy version, session ID size, cipher suite size, cipher suites, and compression method size.
    - Use the `FD_TLS_ENCODE_STATIC_BATCH` macro to encode these static fields into the `wire` buffer.
    - Define and initialize variables for encoding extensions, including supported versions, key share, supported groups, and signature algorithms.
    - Use the `FD_TLS_ENCODE_STATIC_BATCH` macro to encode these extension fields into the `wire` buffer.
    - Check if ALPN (Application-Layer Protocol Negotiation) data is present in the input structure and encode it if available using `FD_TLS_ENCODE_SUB`.
    - Check if QUIC transport parameters are present in the input structure and encode them if available using `FD_TLS_ENCODE_STATIC_BATCH`.
    - Calculate the total size of the extensions and store it in the `extension_tot_sz` field.
    - Return the total number of bytes written to the `wire` buffer.
- **Output**: Returns the total number of bytes written to the `wire` buffer as a `long` integer.


---
### fd\_tls\_decode\_server\_hello<!-- {{#callable:fd_tls_decode_server_hello}} -->
The `fd_tls_decode_server_hello` function decodes a TLS server hello message from a wire format into a structured format, verifying protocol compliance and extracting necessary extensions.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_server_hello_t` structure where the decoded server hello message will be stored.
    - `wire`: A pointer to the byte array containing the server hello message in wire format.
    - `wire_sz`: The size of the `wire` byte array.
- **Control Flow**:
    - Initialize `wire_laddr` to point to the start of the `wire` array.
    - Decode the static-sized part of the server hello message, including legacy version, session ID size, cipher suite, and compression method.
    - Check if the legacy version is TLS 1.2, session ID size is 0, and compression method is 0; return a protocol version alert if not.
    - Verify that the cipher suite is AES_128_GCM_SHA256; return an illegal parameter alert if not.
    - Check if the server hello is a HelloRetryRequest by comparing the random field to a known magic value; return an illegal parameter alert if it matches.
    - Begin decoding the list of extensions, reading each extension's type and size.
    - For each extension, verify the size does not exceed remaining wire size; return a decode error alert if it does.
    - Decode extension data based on its type: supported versions, key share, or QUIC transport parameters.
    - For supported versions, ensure the chosen version is TLS 1.3; return a protocol version alert if not.
    - For key share, call [`fd_tls_decode_key_share`](#fd_tls_decode_key_share) to decode the key share data.
    - Reject any unsolicited extensions by returning an illegal parameter alert.
    - Ensure the key share extension includes X25519; return a missing extension alert if not.
    - Return the number of bytes processed from the wire.
- **Output**: Returns the number of bytes processed from the wire on success, or a negative value indicating a specific TLS alert error on failure.
- **Functions called**:
    - [`fd_tls_decode_key_share`](#fd_tls_decode_key_share)


---
### fd\_tls\_encode\_server\_hello<!-- {{#callable:fd_tls_encode_server_hello}} -->
The `fd_tls_encode_server_hello` function encodes a TLS server hello message into a wire format, including static fields and extensions.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_server_hello_t` structure containing the server hello data to be encoded.
    - `wire`: A pointer to a buffer where the encoded server hello message will be written.
    - `wire_sz`: The size of the buffer pointed to by `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of the `wire` buffer.
    - Define and initialize static fields for the server hello message, including `legacy_version`, `legacy_session_id_sz`, `cipher_suite`, and `legacy_compression_method`.
    - Use the `FD_TLS_ENCODE_STATIC_BATCH` macro to encode the static fields into the `wire` buffer.
    - Define and initialize variables for encoding extensions, including `extension_tot_sz`, `extension_start`, `ext_supported_versions_ext_type`, `ext_supported_versions`, `ext_key_share_ext_type`, `ext_key_share_group`, and `ext_key_share_sz`.
    - Use the `FD_TLS_ENCODE_STATIC_BATCH` macro to encode the extensions into the `wire` buffer.
    - Calculate the total size of the extensions and store it in `extension_tot_sz` after byte-swapping.
    - Return the total number of bytes written to the `wire` buffer.
- **Output**: Returns the number of bytes written to the `wire` buffer as a `long` integer.


---
### fd\_tls\_encode\_hello\_retry\_request<!-- {{#callable:fd_tls_encode_hello_retry_request}} -->
The `fd_tls_encode_hello_retry_request` function encodes a TLS HelloRetryRequest message into a wire format.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_server_hello_t` structure containing the server hello data to be encoded.
    - `wire`: A pointer to a buffer where the encoded message will be stored.
    - `wire_sz`: The size of the buffer pointed to by `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of the `wire` buffer.
    - Set up static fields for the HelloRetryRequest message, including legacy version, session ID size, cipher suite, and compression method.
    - Use the `FD_TLS_ENCODE_STATIC_BATCH` macro to encode these static fields into the `wire` buffer.
    - Initialize extension-related variables and calculate the starting address for extensions.
    - Define and encode supported versions and key share extensions using the `FD_TLS_ENCODE_STATIC_BATCH` macro.
    - Calculate the total size of the extensions and store it in `extension_tot_sz`.
    - Return the total number of bytes written to the `wire` buffer.
- **Output**: Returns the number of bytes written to the `wire` buffer as a `long` integer.


---
### fd\_tls\_decode\_enc\_ext<!-- {{#callable:fd_tls_decode_enc_ext}} -->
The `fd_tls_decode_enc_ext` function decodes TLS encoded extension data from a wire format into a structured format, handling specific extension types and performing bounds checks.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_enc_ext_t` structure where the decoded extension data will be stored.
    - `wire`: A pointer to the input byte array containing the encoded extension data.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for processing.
    - Begin decoding a list of extensions using `FD_TLS_DECODE_LIST_BEGIN`.
    - For each extension, read the `ext_type` and `ext_sz` fields using `FD_TLS_DECODE_STATIC_BATCH`.
    - Check if the extension data exceeds the bounds of the input data; if so, return a decode error.
    - Switch on `ext_type` to handle specific extension types:
    - For `FD_TLS_EXT_ALPN`, call [`fd_tls_decode_ext_alpn`](#fd_tls_decode_ext_alpn) and check for errors.
    - For `FD_TLS_EXT_QUIC_TRANSPORT_PARAMS`, check size and store buffer and size in `out->quic_tp`.
    - For `FD_TLS_EXT_SERVER_CERT_TYPE` and `FD_TLS_EXT_CLIENT_CERT_TYPE`, check size and store the certificate type.
    - Ignore unknown extensions by default.
    - Advance `wire_laddr` and reduce `wire_sz` by `ext_sz` for the next iteration.
    - End the decoding list with `FD_TLS_DECODE_LIST_END`.
    - Return the number of bytes processed from the input `wire`.
- **Output**: Returns the number of bytes processed from the input `wire`, or a negative error code if a decode error occurs.
- **Functions called**:
    - [`fd_tls_decode_ext_alpn`](#fd_tls_decode_ext_alpn)


---
### fd\_tls\_encode\_cert\_x509<!-- {{#callable:fd_tls_encode_cert_x509}} -->
The `fd_tls_encode_cert_x509` function encodes an X.509 certificate into a TLS certificate message format and writes it to a provided buffer.
- **Inputs**:
    - `x509`: A pointer to the X.509 certificate data to be encoded.
    - `x509_sz`: The size of the X.509 certificate data in bytes.
    - `wire`: A pointer to the buffer where the encoded TLS certificate message will be written.
    - `wire_sz`: The size of the buffer in bytes.
- **Control Flow**:
    - Initialize a local variable `wire_laddr` to the address of the `wire` buffer.
    - Define and initialize the TLS message type as a certificate message.
    - Calculate the sizes for the TLS message, certificate list, and certificate using the [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24) function.
    - Set the certificate request context size to zero, as server certificates do not have a request context.
    - Set the extension size to zero, indicating no certificate extensions are present.
    - Use the `FD_TLS_ENCODE_STATIC_BATCH` macro to encode the message type, message size, certificate request context size, certificate list size, certificate size, the X.509 certificate data, and the extension size into the `wire` buffer.
- **Output**: Returns the number of bytes written to the `wire` buffer as a long integer.
- **Functions called**:
    - [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24)


---
### fd\_tls\_encode\_enc\_ext<!-- {{#callable:fd_tls_encode_enc_ext}} -->
The `fd_tls_encode_enc_ext` function encodes various TLS extensions into a wire format for transmission.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_enc_ext_t` structure containing the TLS extensions to be encoded.
    - `wire`: A pointer to a buffer where the encoded extensions will be written.
    - `wire_sz`: The size of the buffer pointed to by `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for tracking the current position in the buffer.
    - Check if the ALPN extension is present in `in` and encode it using `fd_tls_encode_ext_hdr` and `fd_tls_encode_ext_alpn`.
    - Check if the QUIC transport parameters are present in `in` and encode them using `FD_TLS_ENCODE_STATIC_BATCH`.
    - Check if the server certificate type is present in `in` and encode it using `FD_TLS_ENCODE_STATIC_BATCH`.
    - Check if the client certificate type is present in `in` and encode it using `FD_TLS_ENCODE_STATIC_BATCH`.
    - Return the number of bytes written to the buffer by calculating the difference between `wire_laddr` and the original `wire` address.
- **Output**: Returns the number of bytes written to the `wire` buffer as a `long` integer.


---
### fd\_tls\_encode\_raw\_public\_key<!-- {{#callable:fd_tls_encode_raw_public_key}} -->
The `fd_tls_encode_raw_public_key` function encodes a raw public key into a TLS certificate message format and writes it to a provided buffer.
- **Inputs**:
    - `key`: A pointer to a 32-byte Ed25519 public key that needs to be encoded.
    - `wire`: A pointer to the buffer where the encoded TLS certificate message will be written.
    - `wire_sz`: The size of the buffer pointed to by `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of the `wire` buffer.
    - Set `msg_type` to `FD_TLS_MSG_CERT` to indicate a certificate message.
    - Calculate the size of the raw public key (`rpk_sz`) including the ASN.1 prefix and the 32-byte key.
    - Convert the sizes of the message, certificate list, and certificate to 24-bit TLS format using [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24).
    - Define a zero-size `certificate_request_context_sz` since server certificates do not have a request context.
    - Define `ext_sz` as zero since there are no certificate extensions.
    - Use the `FD_TLS_ENCODE_STATIC_BATCH` macro to encode the message type, message size, certificate request context size, certificate list size, certificate size, ASN.1 prefix, the public key, and extension size into the `wire` buffer.
    - Return the number of bytes written to the `wire` buffer.
- **Output**: The function returns the number of bytes written to the `wire` buffer as a `long` integer.
- **Functions called**:
    - [`fd_uint_to_tls_u24`](fd_tls_proto.h.driver.md#fd_uint_to_tls_u24)


---
### fd\_tls\_decode\_cert\_verify<!-- {{#callable:fd_tls_decode_cert_verify}} -->
The `fd_tls_decode_cert_verify` function decodes a TLS CertificateVerify message, extracting the signature algorithm and signature, and validates the signature algorithm and size.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_cert_verify_t` structure where the decoded signature algorithm and signature will be stored.
    - `wire`: A pointer to the input byte array containing the encoded CertificateVerify message.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for tracking the current position in the input data.
    - Define a local variable `sig_sz` to store the size of the signature.
    - Use the `FD_TLS_DECODE_STATIC_BATCH` macro to decode the signature algorithm, signature size, and signature from the input data into `out->sig_alg`, `sig_sz`, and `out->sig` respectively.
    - Check if the decoded signature algorithm is `FD_TLS_SIGNATURE_ED25519` and if the signature size is 64 bytes (0x40).
    - If the checks fail, return a negative value indicating an illegal parameter alert.
    - If the checks pass, return the number of bytes processed from the input data.
- **Output**: Returns the number of bytes processed from the input data if successful, or a negative value indicating an illegal parameter alert if the signature algorithm or size is invalid.


---
### fd\_tls\_encode\_cert\_verify<!-- {{#callable:fd_tls_encode_cert_verify}} -->
The `fd_tls_encode_cert_verify` function encodes a TLS certificate verify message into a wire format.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_cert_verify_t` structure containing the signature algorithm and signature to be encoded.
    - `wire`: A pointer to a buffer where the encoded message will be written.
    - `wire_sz`: The size of the buffer pointed to by `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for tracking the current position in the buffer.
    - Define a fixed signature size `sig_sz` of 64 bytes.
    - Use the `FD_TLS_ENCODE_STATIC_BATCH` macro to encode the fields: signature algorithm, signature size, and the signature itself into the buffer.
    - Return the number of bytes written to the buffer, calculated as the difference between the current `wire_laddr` and the initial `wire` address.
- **Output**: The function returns the number of bytes written to the `wire` buffer as a `long` integer.


---
### fd\_tls\_decode\_ext\_server\_name<!-- {{#callable:fd_tls_decode_ext_server_name}} -->
The `fd_tls_decode_ext_server_name` function decodes a TLS extension for server names from a wire format into a structured format.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_server_name_t` structure where the decoded server name will be stored.
    - `wire`: A pointer to the input byte array containing the server name extension data in wire format.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to point to the start of the `wire` data.
    - Begin decoding a list of server names using `FD_TLS_DECODE_LIST_BEGIN`.
    - For each server name, read the `name_type` and `name_sz` fields using `FD_TLS_DECODE_STATIC_BATCH`.
    - Check if the name size exceeds the bounds of the list; if so, return a decode error.
    - If the name type is DNS, the name size is less than 254, and no host name has been set in `out`, copy the name to `out->host_name` and set `out->host_name_len`.
    - Advance `wire_laddr` and `wire_sz` to the next name in the list.
    - End the decoding list with `FD_TLS_DECODE_LIST_END`.
- **Output**: Returns the number of bytes processed from the `wire` data, or a negative error code if decoding fails.


---
### fd\_tls\_decode\_ext\_supported\_groups<!-- {{#callable:fd_tls_decode_ext_supported_groups}} -->
The function `fd_tls_decode_ext_supported_groups` decodes a list of supported groups from a TLS extension and updates the output structure to indicate support for specific groups, such as X25519.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_supported_groups_t` structure where the decoded supported groups will be stored.
    - `wire`: A pointer to the input byte array containing the encoded supported groups data.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for tracking the current position in the input data.
    - Begin decoding a list of `ushort` values using the `FD_TLS_DECODE_LIST_BEGIN` macro, which handles list iteration and bounds checking.
    - For each `ushort` value decoded, check if it matches the constant `FD_TLS_GROUP_X25519`.
    - If a match is found, set the `x25519` field of the `out` structure to 1, indicating support for the X25519 group.
    - Ignore any unsupported groups by default.
    - End the list decoding with the `FD_TLS_DECODE_LIST_END` macro.
    - Return the number of bytes processed by subtracting the initial `wire` address from the current `wire_laddr`.
- **Output**: The function returns the number of bytes processed as a `long`, which is the difference between the current position and the start of the input data.


---
### fd\_tls\_decode\_ext\_supported\_versions<!-- {{#callable:fd_tls_decode_ext_supported_versions}} -->
The function `fd_tls_decode_ext_supported_versions` decodes a list of supported TLS versions from a wire format and updates the output structure to indicate support for TLS 1.3 if present.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_supported_versions_t` structure where the decoded supported versions will be stored.
    - `wire`: A pointer to the input byte array containing the wire format data to be decoded.
    - `wire_sz`: The size of the input wire data in bytes.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of the input `wire` data.
    - Begin decoding a list of `uchar` elements aligned to `ushort` boundaries using `FD_TLS_DECODE_LIST_BEGIN`.
    - For each element, decode a `ushort` value into `group` using `FD_TLS_DECODE_FIELD`.
    - Check if the decoded `group` is equal to `FD_TLS_VERSION_TLS13`.
    - If it is, set the `tls13` field of the `out` structure to 1, indicating support for TLS 1.3.
    - Ignore any unsupported TLS versions by doing nothing in the default case of the switch statement.
    - End the decoding list with `FD_TLS_DECODE_LIST_END`.
- **Output**: Returns the number of bytes processed from the input wire data as a `long` integer.


---
### fd\_tls\_decode\_ext\_signature\_algorithms<!-- {{#callable:fd_tls_decode_ext_signature_algorithms}} -->
The function `fd_tls_decode_ext_signature_algorithms` decodes a list of signature algorithms from a wire format and updates the output structure to indicate support for the ED25519 algorithm if present.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_signature_algorithms_t` structure where the decoded signature algorithms will be stored.
    - `wire`: A pointer to the input byte array containing the encoded signature algorithms.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for tracking the current position in the input data.
    - Begin decoding a list of `ushort` values using the `FD_TLS_DECODE_LIST_BEGIN` macro.
    - For each `ushort` value decoded, store it in the variable `group`.
    - Check if the `group` corresponds to `FD_TLS_SIGNATURE_ED25519`.
    - If it matches, set the `ed25519` field of the `out` structure to 1, indicating support for ED25519.
    - Ignore any unsupported signature algorithms by doing nothing in the default case of the switch statement.
    - End the decoding list with the `FD_TLS_DECODE_LIST_END` macro.
    - Return the number of bytes processed by subtracting the initial `wire` address from the current `wire_laddr`.
- **Output**: The function returns a `long` indicating the number of bytes processed from the input `wire`.


---
### fd\_tls\_decode\_key\_share<!-- {{#callable:fd_tls_decode_key_share}} -->
The `fd_tls_decode_key_share` function decodes a key share from a TLS wire format into a structured format, specifically handling the X25519 key exchange group.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_key_share_t` structure where the decoded key share will be stored.
    - `wire`: A pointer to the input byte array containing the encoded key share data.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for processing.
    - Decode the key share type and length using `FD_TLS_DECODE_STATIC_BATCH`.
    - Check if the decoded key exchange data size `kex_data_sz` exceeds `wire_sz`; if so, return a decode error.
    - Switch on the `group` to handle specific key exchange groups.
    - For `FD_TLS_GROUP_X25519`, verify the key exchange data size is 32 bytes, set `has_x25519` to 1, and copy the key data to `out->x25519`.
    - Advance `wire_laddr` by `kex_data_sz` to point to the next group in the wire data.
    - Return the number of bytes processed from the input `wire`.
- **Output**: Returns the number of bytes processed from the input `wire`, or a negative error code if decoding fails.


---
### fd\_tls\_decode\_key\_share\_list<!-- {{#callable:fd_tls_decode_key_share_list}} -->
The `fd_tls_decode_key_share_list` function decodes a list of key shares from a given wire format into a structured format.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_key_share_t` structure where the decoded key shares will be stored.
    - `wire`: A pointer to the input byte array containing the encoded key share list.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for tracking the current position in the input data.
    - Begin decoding a list of key shares using the `FD_TLS_DECODE_LIST_BEGIN` macro, specifying `ushort` as the type and `alignof(uchar)` for alignment.
    - For each key share in the list, call `fd_tls_decode_key_share` to decode the individual key share and store it in `out`.
    - End the decoding process with the `FD_TLS_DECODE_LIST_END` macro.
    - Calculate the number of bytes processed by subtracting the original `wire` address from `wire_laddr`.
- **Output**: Returns the number of bytes processed as a `long`, which is the difference between the current position and the start of the input data.


---
### fd\_tls\_decode\_ext\_cert\_type\_list<!-- {{#callable:fd_tls_decode_ext_cert_type_list}} -->
The `fd_tls_decode_ext_cert_type_list` function decodes a list of certificate types from a given wire format and updates the output structure to indicate which certificate types are present.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_cert_type_list_t` structure where the decoded certificate types will be stored.
    - `wire`: A pointer to the input byte array containing the wire format data to be decoded.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for tracking the current position in the input data.
    - Set the `present` field of the `out` structure to 1, indicating that the extension is present.
    - Begin decoding a list of `uchar` elements using the `FD_TLS_DECODE_LIST_BEGIN` macro.
    - For each `cert_type` decoded from the wire data, check its value and set the corresponding field in the `out` structure (`x509` or `raw_pubkey`) to 1 if it matches a known certificate type.
    - Ignore any unsupported certificate types by doing nothing in the default case of the switch statement.
    - End the list decoding with the `FD_TLS_DECODE_LIST_END` macro.
    - Return the number of bytes processed by subtracting the original `wire` address from the current `wire_laddr`.
- **Output**: The function returns a `long` integer representing the number of bytes processed from the input `wire` data.


---
### fd\_tls\_encode\_ext\_cert\_type\_list<!-- {{#callable:fd_tls_encode_ext_cert_type_list}} -->
The function `fd_tls_encode_ext_cert_type_list` encodes a list of certificate types into a wire format for TLS communication.
- **Inputs**:
    - `in`: A `fd_tls_ext_cert_type_list_t` structure containing the certificate types to be encoded.
    - `wire`: A pointer to a constant unsigned character array where the encoded data will be stored.
    - `wire_sz`: An unsigned long representing the size of the wire buffer.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` for tracking the current position in the buffer.
    - Calculate the number of certificate types to encode using `fd_uchar_popcnt` on `in.uc` and store it in `cnt`.
    - Encode the count of certificate types (`cnt`) into the wire buffer using `FD_TLS_ENCODE_FIELD`.
    - Allocate space for the certificate type fields using `FD_TLS_SKIP_FIELDS` based on the count `cnt`.
    - If `in.x509` is set, encode `FD_TLS_CERTTYPE_X509` into the fields buffer.
    - If `in.raw_pubkey` is set, encode `FD_TLS_CERTTYPE_RAW_PUBKEY` into the fields buffer.
    - Return the number of bytes written to the wire buffer as the difference between the current and initial wire addresses.
- **Output**: The function returns a `long` indicating the number of bytes written to the wire buffer.


---
### fd\_tls\_decode\_ext\_cert\_type<!-- {{#callable:fd_tls_decode_ext_cert_type}} -->
The function `fd_tls_decode_ext_cert_type` decodes a single certificate type from a TLS extension field and updates the output structure with the decoded value.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_cert_type_t` structure where the decoded certificate type will be stored.
    - `wire`: A pointer to the input byte array containing the encoded certificate type data.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of the input `wire`.
    - Use the macro `FD_TLS_DECODE_FIELD` to decode a single `uchar` value from `wire` and store it in `out->cert_type`.
    - Calculate the number of bytes processed by subtracting the original `wire` address from the updated `wire_laddr`.
- **Output**: Returns the number of bytes processed as a `long`, which is the difference between the updated `wire_laddr` and the original `wire` address.


---
### fd\_tls\_encode\_ext\_cert\_type<!-- {{#callable:fd_tls_encode_ext_cert_type}} -->
The `fd_tls_encode_ext_cert_type` function encodes a certificate type into a wire format for TLS communication.
- **Inputs**:
    - `in`: A `fd_tls_ext_cert_type_t` structure containing the certificate type to be encoded.
    - `wire`: A pointer to a constant unsigned character array where the encoded data will be stored.
    - `wire_sz`: An unsigned long representing the size of the wire buffer.
- **Control Flow**:
    - Initialize `wire_laddr` to the address of `wire` cast to an unsigned long.
    - Use the macro `FD_TLS_ENCODE_FIELD` to encode the `cert_type` from the `in` structure into the `wire` buffer as an unsigned character.
    - Return the difference between the current `wire_laddr` and the original `wire` address cast to a long.
- **Output**: The function returns a long integer representing the number of bytes written to the `wire` buffer.


---
### fd\_tls\_decode\_ext\_opaque<!-- {{#callable:fd_tls_decode_ext_opaque}} -->
The `fd_tls_decode_ext_opaque` function assigns a buffer and its size from a given wire data to a `fd_tls_ext_opaque_t` structure and returns the size of the wire data.
- **Inputs**:
    - `out`: A pointer to a `fd_tls_ext_opaque_t` structure where the buffer and its size will be stored.
    - `wire`: A constant pointer to an unsigned character array representing the wire data to be decoded.
    - `wire_sz`: An unsigned long integer representing the size of the wire data.
- **Control Flow**:
    - Assigns the `wire` pointer to the `buf` field of the `out` structure.
    - Assigns the `wire_sz` value to the `bufsz` field of the `out` structure.
    - Returns the size of the wire data as a long integer.
- **Output**: The function returns the size of the wire data as a long integer.


---
### fd\_tls\_decode\_ext\_alpn<!-- {{#callable:fd_tls_decode_ext_alpn}} -->
The `fd_tls_decode_ext_alpn` function decodes the ALPN (Application-Layer Protocol Negotiation) extension from a given wire format into a structured format.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_alpn_t` structure where the decoded ALPN extension will be stored.
    - `wire`: A pointer to the input byte array containing the ALPN extension data in wire format.
    - `wire_sz`: The size of the input byte array `wire`.
- **Control Flow**:
    - Convert the `wire` pointer to an unsigned long integer `wire_laddr` for address arithmetic.
    - Decode the size of the ALPN extension into `alpn_sz` using the `FD_TLS_DECODE_FIELD` macro.
    - Check if the decoded `alpn_sz` matches the provided `wire_sz`; if not, return a negative error code indicating a decode error.
    - Call [`fd_tls_decode_ext_opaque`](#fd_tls_decode_ext_opaque) to decode the opaque ALPN data and add 2 to its result to account for the size field, returning the total length of the decoded data.
- **Output**: Returns the total length of the decoded ALPN extension data, or a negative error code if a decode error occurs.
- **Functions called**:
    - [`fd_tls_decode_ext_opaque`](#fd_tls_decode_ext_opaque)


---
### fd\_tls\_encode\_ext\_alpn<!-- {{#callable:fd_tls_encode_ext_alpn}} -->
The `fd_tls_encode_ext_alpn` function encodes an ALPN (Application-Layer Protocol Negotiation) extension into a wire format buffer.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_ext_alpn_t` structure containing the ALPN data to be encoded.
    - `wire`: A pointer to a buffer where the encoded ALPN extension will be written.
    - `wire_sz`: The size of the buffer pointed to by `wire`.
- **Control Flow**:
    - Calculate the total size needed for the ALPN extension, which is 2 bytes for the size field plus the size of the ALPN buffer (`in->bufsz`).
    - Check if the calculated size exceeds the provided buffer size (`wire_sz`). If it does, return a negative error code indicating an internal error.
    - Write the size of the ALPN buffer into the first two bytes of the `wire` buffer in big-endian format.
    - Copy the ALPN buffer (`in->buf`) into the `wire` buffer starting at the third byte.
    - Return the total size of the encoded ALPN extension.
- **Output**: Returns the total size of the encoded ALPN extension on success, or a negative error code if the buffer is too small.


---
### fd\_tls\_client\_handle\_x509<!-- {{#callable:fd_tls_client_handle_x509}} -->
The `fd_tls_client_handle_x509` function extracts the Ed25519 subject public key from an ASN.1 DER-encoded X.509 certificate and returns it through a pointer.
- **Inputs**:
    - `cert`: A pointer to the ASN.1 DER-encoded X.509 certificate data.
    - `cert_sz`: The size of the certificate data in bytes.
    - `out_pubkey`: A pointer to a location where the extracted public key will be stored if successful.
- **Control Flow**:
    - Call `fd_x509_mock_pubkey` with `cert` and `cert_sz` to attempt to extract the public key.
    - Check if the returned `pubkey` is NULL, indicating failure to extract the public key.
    - If `pubkey` is NULL, return `FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE`.
    - If `pubkey` is not NULL, store the public key in `out_pubkey` and return 0.
- **Output**: Returns 0 on success, indicating the public key was successfully extracted and stored in `out_pubkey`; returns `FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE` on failure.


---
### fd\_tls\_extract\_cert\_pubkey\_<!-- {{#callable:fd_tls_extract_cert_pubkey_}} -->
The function `fd_tls_extract_cert_pubkey_` extracts the public key from the first certificate in a given certificate chain, handling both X.509 and raw public key formats.
- **Inputs**:
    - `res`: A pointer to a `fd_tls_extract_cert_pubkey_res_t` structure where the result of the extraction will be stored.
    - `cert_chain`: A pointer to the certificate chain data from which the public key is to be extracted.
    - `cert_chain_sz`: The size of the certificate chain data in bytes.
    - `cert_type`: An unsigned integer indicating the type of certificate, either X.509 or raw public key.
- **Control Flow**:
    - Initialize the result structure `res` to zero using `fd_memset`.
    - Set `wire_laddr` and `wire_sz` to point to the start and size of the certificate chain, respectively.
    - Skip the 'opaque certificate_request_context' field using `FD_TLS_SKIP_FIELD` and `FD_TLS_SKIP_FIELDS`.
    - Extract the size of the certificate list and check if it is zero, setting an alert and reason in `res` if so, and return -1.
    - Extract the size of the first certificate and check if it exceeds the available data, setting an alert and reason in `res` if so, and return -1.
    - Depending on `cert_type`, handle the certificate as either X.509 or raw public key:
    - For X.509, call [`fd_tls_client_handle_x509`](#fd_tls_client_handle_x509) to extract the public key, setting an alert and reason in `res` if it fails, and return -1.
    - For raw public key, call [`fd_ed25519_public_key_from_asn1`](fd_tls_asn1.c.driver.md#fd_ed25519_public_key_from_asn1) to extract the public key, setting an alert and reason in `res` if it fails, and return -1.
    - Return 0 on successful extraction of the public key.
- **Output**: Returns a long integer, 0 on success or -1 on failure, with `res` populated with the extracted public key or error details.
- **Functions called**:
    - [`fd_tls_u24_bswap`](fd_tls_proto.h.driver.md#fd_tls_u24_bswap)
    - [`fd_tls_u24_to_uint`](fd_tls_proto.h.driver.md#fd_tls_u24_to_uint)
    - [`fd_tls_client_handle_x509`](#fd_tls_client_handle_x509)
    - [`fd_ed25519_public_key_from_asn1`](fd_tls_asn1.c.driver.md#fd_ed25519_public_key_from_asn1)


---
### fd\_tls\_extract\_cert\_pubkey<!-- {{#callable:fd_tls_extract_cert_pubkey}} -->
The `fd_tls_extract_cert_pubkey` function extracts the public key from a certificate chain based on the specified certificate type.
- **Inputs**:
    - `cert_chain`: A pointer to the certificate chain data, represented as an array of unsigned characters.
    - `cert_chain_sz`: The size of the certificate chain data, given as an unsigned long integer.
    - `cert_type`: An unsigned integer indicating the type of certificate, such as X.509 or raw public key.
- **Control Flow**:
    - Initialize a result structure `res` of type `fd_tls_extract_cert_pubkey_res_t`.
    - Call the helper function [`fd_tls_extract_cert_pubkey_`](#fd_tls_extract_cert_pubkey_) with the result structure and input parameters to perform the actual extraction of the public key.
    - Ignore the return value of the helper function as it is not used.
    - Return the result structure `res` containing the extracted public key or error information.
- **Output**: The function returns a structure of type `fd_tls_extract_cert_pubkey_res_t`, which contains the extracted public key or error information if the extraction fails.
- **Functions called**:
    - [`fd_tls_extract_cert_pubkey_`](#fd_tls_extract_cert_pubkey_)


