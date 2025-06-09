# Purpose
The provided C header file, `fd_tls_proto.h`, is part of a library that defines data structures and functions for handling the Transport Layer Security (TLS) protocol, specifically version 1.3. This file is designed to facilitate the encoding and decoding of TLS messages and extensions from and to their wire formats, which are the formats used for data transmission over a network. The file includes definitions for various TLS message types, such as `ClientHello` and `ServerHello`, and extensions like supported versions, server name indication, and supported groups. It also provides macros and inline functions for handling static serialization and deserialization of these structures, ensuring that data is correctly formatted for network transmission, including handling endianness.

The file is structured to support both static and dynamic data layouts, with specific functions for encoding and decoding each type of TLS message and extension. It includes a series of macros and inline functions to handle common operations, such as byte-swapping for endianness conversion and converting between different data representations. The header file also defines a set of constants representing various TLS protocol elements, such as version numbers, cipher suite IDs, and alert codes, which are used throughout the TLS protocol to ensure secure communication. This file is intended to be included in other C source files that implement the TLS protocol, providing a comprehensive API for managing TLS data structures and their serialization.
# Imports and Dependencies

---
- `../fd_waltz_base.h`
- `stddef.h`


# Global Variables

---
### fd\_tls\_finished\_bswap
- **Type**: `function`
- **Description**: `fd_tls_finished_bswap` is a static inline function that is intended to perform a byte swap operation on a `fd_tls_finished_t` structure, which represents the wire format of a TLS Finished message. However, the function is currently empty and does not perform any operations.
- **Use**: This function is used as part of the serialization and deserialization process for TLS messages, specifically to handle endianness conversion for the `fd_tls_finished_t` structure.


# Data Structures

---
### fd\_tls\_ext\_hdr
- **Type**: `struct`
- **Members**:
    - `type`: A 16-bit unsigned short representing the type of the TLS extension.
    - `sz`: A 16-bit unsigned short representing the size of the TLS extension data.
- **Description**: The `fd_tls_ext_hdr` structure is a packed C struct used to represent the header of a TLS extension in a static layout. It contains two fields: `type`, which specifies the type of the TLS extension, and `sz`, which indicates the size of the extension data. This structure is used in the context of encoding and decoding TLS extensions in a wire format, where the header provides essential metadata for processing the extension data.


---
### fd\_tls\_ext\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `type`: A 16-bit unsigned short representing the type of the TLS extension.
    - `sz`: A 16-bit unsigned short representing the size of the TLS extension data.
- **Description**: The `fd_tls_ext_hdr_t` structure is a packed C struct used to represent the header of a TLS extension in the TLS v1.3 protocol. It contains two fields: `type`, which specifies the type of the extension, and `sz`, which indicates the size of the extension data. This structure is used in the encoding and decoding of TLS extensions, facilitating the handling of extension headers in a standardized manner.


---
### fd\_tls\_ext\_supported\_versions
- **Type**: `struct`
- **Members**:
    - `tls13`: A 1-bit field indicating support for TLS 1.3.
- **Description**: The `fd_tls_ext_supported_versions` structure is a simple data structure used to represent the supported versions of the TLS protocol, specifically indicating whether TLS 1.3 is supported. It contains a single 1-bit field, `tls13`, which is used as a boolean flag to denote the presence or absence of TLS 1.3 support. This structure is part of the TLS extension handling, as defined in RFC 8446, and is used in the context of negotiating supported protocol versions during the TLS handshake process.


---
### fd\_tls\_ext\_supported\_versions\_t
- **Type**: `struct`
- **Members**:
    - `tls13`: A 1-bit field indicating support for TLS 1.3.
- **Description**: The `fd_tls_ext_supported_versions_t` structure is a packed C struct used to represent the supported versions of the TLS protocol, specifically indicating support for TLS 1.3. It is part of the TLS v1.3 extension data structures, which are used to encode and decode various protocol extensions in a dynamic manner. This structure is particularly used in the context of the TLS handshake to communicate the supported protocol versions between the client and server.


---
### fd\_tls\_ext\_server\_name
- **Type**: `struct`
- **Members**:
    - `host_name_len`: Length of the hostname string, excluding the null terminator.
    - `host_name`: Character array to store the hostname, with a maximum length of 254 characters.
- **Description**: The `fd_tls_ext_server_name` structure is used to represent the Server Name Indication (SNI) extension in TLS, as specified in RFC 6066. It contains a length field and a character array to store the server's hostname, which is used during the TLS handshake to indicate the server name the client is attempting to connect to. This structure is part of the TLS extension handling in the protocol implementation.


---
### fd\_tls\_ext\_server\_name\_t
- **Type**: `struct`
- **Members**:
    - `host_name_len`: Length of the hostname string, excluding the null terminator.
    - `host_name`: Character array to store the hostname, with a maximum length of 254 characters.
- **Description**: The `fd_tls_ext_server_name_t` structure is used to represent the Server Name Indication (SNI) extension in TLS, as defined in RFC 6066. It contains a length field and a character array to store the hostname, which allows a client to specify the server name it is trying to connect to. This is particularly useful in scenarios where multiple virtual servers are hosted on a single IP address, enabling the server to present the correct certificate during the TLS handshake.


---
### fd\_tls\_ext\_supported\_groups
- **Type**: `struct`
- **Members**:
    - `x25519`: A 1-bit field indicating support for the x25519 elliptic curve group.
- **Description**: The `fd_tls_ext_supported_groups` structure is a compact representation used in the context of TLS (Transport Layer Security) to indicate support for specific elliptic curve groups, specifically the x25519 group, which is commonly used for key exchange in secure communications. This structure is part of the TLS extensions and is used to communicate supported cryptographic groups between a client and server during the TLS handshake process.


---
### fd\_tls\_ext\_supported\_groups\_t
- **Type**: `struct`
- **Members**:
    - `x25519`: A bit field indicating support for the x25519 elliptic curve group.
- **Description**: The `fd_tls_ext_supported_groups_t` structure is a packed C struct used in the context of TLS (Transport Layer Security) to represent supported elliptic curve groups, specifically indicating support for the x25519 group. This structure is part of the TLS extension mechanism, which allows clients and servers to negotiate additional capabilities and features during the TLS handshake. The use of a bit field allows for efficient representation of support for specific groups, which is crucial for the performance and flexibility of the TLS protocol.


---
### fd\_tls\_ext\_signature\_algorithms
- **Type**: `struct`
- **Members**:
    - `ed25519`: A 1-bit field indicating support for the Ed25519 signature algorithm.
- **Description**: The `fd_tls_ext_signature_algorithms` structure is a compact representation used in TLS v1.3 to indicate support for specific signature algorithms, specifically the Ed25519 algorithm in this case. It is part of the TLS extension mechanism that allows clients and servers to negotiate the use of various cryptographic algorithms. The structure uses a bit field to efficiently represent the presence or absence of support for the Ed25519 signature algorithm.


---
### fd\_tls\_ext\_signature\_algorithms\_t
- **Type**: `struct`
- **Members**:
    - `ed25519`: A 1-bit field indicating support for the Ed25519 signature algorithm.
- **Description**: The `fd_tls_ext_signature_algorithms_t` structure is a packed C struct used in the context of TLS v1.3 to represent supported signature algorithms. It contains a single 1-bit field, `ed25519`, which indicates whether the Ed25519 signature algorithm is supported. This structure is part of the TLS extension for signature algorithms, which is used to negotiate the cryptographic algorithms that will be used in a TLS session.


---
### fd\_tls\_key\_share
- **Type**: `struct`
- **Members**:
    - `has_x25519`: A 1-bit field indicating whether the x25519 key share is present.
    - `x25519`: An array of 32 unsigned characters representing the x25519 key share.
- **Description**: The `fd_tls_key_share` structure is used in the context of TLS (Transport Layer Security) to represent a key share, specifically for the x25519 elliptic curve. It contains a flag to indicate the presence of the x25519 key share and an array to store the key share itself. This structure is part of the TLS 1.3 protocol implementation, which involves key exchange mechanisms to establish secure communication channels.


---
### fd\_tls\_key\_share\_t
- **Type**: `struct`
- **Members**:
    - `has_x25519`: A flag indicating if the x25519 key share is present.
    - `x25519`: An array of 32 bytes representing the x25519 key share.
- **Description**: The `fd_tls_key_share_t` structure is used in the context of TLS (Transport Layer Security) to represent a key share, specifically for the x25519 elliptic curve Diffie-Hellman key exchange. It contains a flag to indicate the presence of the x25519 key share and an array to store the key share itself. This structure is part of the TLS 1.3 protocol implementation, which involves secure communication over a computer network.


---
### fd\_tls\_ext\_cert\_type\_list
- **Type**: `union`
- **Members**:
    - `present`: A 1-bit field indicating if the extension is present (1) or missing (0).
    - `x509`: A 1-bit field indicating if the X.509 certificate type is supported.
    - `raw_pubkey`: A 1-bit field indicating if the raw public key certificate type is supported.
    - `uc`: An 8-bit unsigned character providing an alternative way to access the union's data.
- **Description**: The `fd_tls_ext_cert_type_list` is a union data structure used in TLS v1.3 to represent the certificate type extension list. It provides a compact way to store and access information about the presence and types of certificate extensions supported, specifically X.509 and raw public key types. The union allows for both bit-field access to individual certificate type flags and byte-level access through the `uc` member, facilitating efficient encoding and decoding operations in TLS protocols.


---
### fd\_tls\_ext\_cert\_type\_list\_t
- **Type**: `union`
- **Members**:
    - `present`: Indicates if the extension is present (1) or missing (0).
    - `x509`: Indicates if the X.509 certificate type is supported (1) or not (0).
    - `raw_pubkey`: Indicates if the raw public key certificate type is supported (1) or not (0).
    - `uc`: A uchar representation of the union for easy manipulation.
- **Description**: The `fd_tls_ext_cert_type_list_t` is a union data structure used in TLS v1.3 to represent a list of supported certificate types in a compact form. It allows for the representation of whether certain certificate types, such as X.509 or raw public keys, are supported by using bit fields. This union is part of the TLS extension mechanism, which enables clients and servers to negotiate the use of specific certificate types during the handshake process. The `uc` member provides a uchar representation of the union, facilitating operations that require treating the entire union as a single byte.


---
### fd\_tls\_ext\_cert\_type
- **Type**: `struct`
- **Members**:
    - `cert_type`: A single unsigned character representing the certificate type.
- **Description**: The `fd_tls_ext_cert_type` structure is a simple data structure used in the context of TLS (Transport Layer Security) to represent a certificate type extension. It contains a single member, `cert_type`, which is an unsigned character that specifies the type of certificate being used, such as X.509 or raw public key. This structure is part of the TLS extension handling, which allows for the negotiation of various protocol options between a client and server.


---
### fd\_tls\_ext\_cert\_type\_t
- **Type**: `struct`
- **Members**:
    - `cert_type`: Represents the type of certificate used in the TLS extension.
- **Description**: The `fd_tls_ext_cert_type_t` structure is a simple data structure used in the context of TLS (Transport Layer Security) to represent the type of certificate being used in a TLS extension. It contains a single member, `cert_type`, which is an unsigned character that indicates the specific type of certificate, such as X.509 or raw public key, as defined in the TLS protocol specifications. This structure is part of the broader TLS extension handling in the code, which involves encoding and decoding various TLS extension types.


---
### fd\_tls\_ext\_opaque
- **Type**: `struct`
- **Members**:
    - `buf`: A pointer to a constant unsigned character array representing the opaque serialized extension data.
    - `bufsz`: An unsigned long integer representing the size of the buffer pointed to by buf.
- **Description**: The `fd_tls_ext_opaque` structure is used to hold a pointer to opaque serialized extension data in the context of TLS v1.3. It consists of a buffer pointer and its size, which can indicate the presence and size of an extension. The structure can represent three states: an extension present with non-zero size, an extension present with zero size, or an extension absent. The lifetime of the buffer depends on the context in which this structure is used, and it is crucial to refer to specific documentation for its usage.


---
### fd\_tls\_ext\_opaque\_t
- **Type**: `struct`
- **Members**:
    - `buf`: A pointer to opaque serialized extension data.
    - `bufsz`: The size of the buffer pointed to by buf.
- **Description**: The `fd_tls_ext_opaque_t` structure is used to hold a pointer to serialized extension data in a TLS context. It is designed to handle opaque data, where the actual content and size of the data can vary. The structure uses two fields: `buf`, which is a pointer to the data, and `bufsz`, which indicates the size of the data. The presence and size of the extension data are determined by the values of these fields, with specific conditions indicating whether the extension is present and its size. This structure is versatile and can represent extensions with non-zero size, zero size, or indicate the absence of an extension.


---
### fd\_tls\_ext\_quic\_tp\_t
- **Type**: `typedef struct fd_tls_ext_opaque fd_tls_ext_quic_tp_t;`
- **Members**:
    - `buf`: A pointer to opaque serialized extension data.
    - `bufsz`: The size of the buffer pointed to by buf.
- **Description**: The `fd_tls_ext_quic_tp_t` is a typedef for the `fd_tls_ext_opaque` structure, which is used to hold a pointer to opaque serialized extension data in the context of TLS extensions. The structure can represent three states: an extension present with non-zero size, an extension present with zero size, or an extension absent. The lifetime of the buffer pointed to by `buf` depends on the context in which this structure is used.


---
### fd\_tls\_ext\_alpn\_t
- **Type**: `typedef struct fd_tls_ext_opaque fd_tls_ext_alpn_t;`
- **Members**:
    - `buf`: A pointer to opaque serialized extension data.
    - `bufsz`: The size of the buffer pointed to by buf.
- **Description**: The `fd_tls_ext_alpn_t` is a typedef for the `fd_tls_ext_opaque` structure, which is used to hold a pointer to opaque serialized extension data in the context of TLS extensions. The structure can represent three states: an extension present with non-zero size, an extension present with zero size, or an extension absent. The `buf` member points to the serialized data, while `bufsz` indicates the size of this data. The lifetime of the buffer depends on the context in which it is used, and the structure is used to manage the ALPN (Application-Layer Protocol Negotiation) extension in TLS.


---
### fd\_tls\_u24
- **Type**: `struct`
- **Members**:
    - `v`: An array of 3 unsigned characters representing a 24-bit integer in big-endian format.
- **Description**: The `fd_tls_u24` structure is a simple data structure used to represent a 24-bit unsigned integer, which is stored as an array of three bytes (`uchar`). This structure is specifically designed to match the wire representation of a 24-bit integer in big-endian format, which is commonly used in network protocols like TLS (Transport Layer Security). The structure is used to facilitate the encoding and decoding of such integers when handling TLS messages.


---
### fd\_tls\_u24\_t
- **Type**: `struct`
- **Members**:
    - `v`: An array of 3 unsigned characters representing a 24-bit integer in big-endian format.
- **Description**: The `fd_tls_u24_t` structure is a custom data type used to represent a 24-bit integer, which is stored as an array of three bytes in big-endian order. This structure is specifically designed to match the wire representation of a 24-bit integer in the TLS protocol, allowing for efficient serialization and deserialization of data when communicating over a network. The use of a 24-bit integer is common in network protocols where space efficiency is important, and this structure facilitates the handling of such data within the TLS implementation.


---
### fd\_tls\_msg\_hdr
- **Type**: `struct`
- **Members**:
    - `type`: An unsigned character representing the type of the TLS message, defined by FD_TLS_MSG_{...} constants.
    - `sz`: A 24-bit unsigned integer (fd_tls_u24_t) representing the byte size of fields following this header.
- **Description**: The `fd_tls_msg_hdr` structure is a packed C struct used in the TLS v1.3 protocol to define the header for all message types. It contains a `type` field that specifies the message type and a `sz` field that indicates the size of the message body that follows the header. This structure is designed to match the wire format of TLS messages, ensuring efficient serialization and deserialization during communication.


---
### fd\_tls\_msg\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `type`: A single byte indicating the type of the TLS message.
    - `sz`: A 24-bit big-endian integer representing the byte size of the fields following this header.
- **Description**: The `fd_tls_msg_hdr_t` structure is a packed C struct that serves as a common header for all TLS message types. It contains a `type` field, which specifies the type of the TLS message, and a `sz` field, which is a 24-bit integer indicating the size of the message body that follows the header. This structure is used to facilitate the encoding and decoding of TLS messages in a consistent manner, ensuring that the message type and size are clearly defined and easily accessible.


---
### fd\_tls\_client\_hello
- **Type**: `struct`
- **Members**:
    - `random`: An array of 32 unsigned characters used for random data in the ClientHello message.
    - `cipher_suites`: A bitfield structure indicating supported cipher suites, currently only aes_128_gcm_sha256 is defined.
    - `session_id`: An opaque structure holding the session ID extension data.
    - `supported_versions`: A structure indicating supported TLS versions, specifically TLS 1.3.
    - `server_name`: A structure containing the server name indication extension data.
    - `supported_groups`: A structure indicating supported ECDHE groups, such as x25519.
    - `signature_algorithms`: A structure indicating supported signature algorithms, such as ed25519.
    - `key_share`: A structure containing key share information, including x25519 key data.
    - `server_cert_types`: A union indicating supported server certificate types, such as x509 or raw public key.
    - `client_cert_types`: A union indicating supported client certificate types, such as x509 or raw public key.
    - `quic_tp`: An opaque structure holding QUIC transport parameters extension data.
    - `alpn`: An opaque structure holding the ALPN (Application-Layer Protocol Negotiation) extension data.
- **Description**: The `fd_tls_client_hello` structure represents a TLS v1.3 ClientHello message as defined in RFC 8446, Section 4.1.2. It includes fields for random data, supported cipher suites, session ID, supported TLS versions, server name indication, supported ECDHE groups, signature algorithms, key share information, server and client certificate types, QUIC transport parameters, and ALPN data. This structure is used to initiate a TLS handshake by specifying the client's capabilities and preferences.


---
### fd\_tls\_client\_hello\_t
- **Type**: `struct`
- **Members**:
    - `random`: A 32-byte array representing the random value in the ClientHello message.
    - `cipher_suites`: A bitfield structure indicating supported cipher suites, such as aes_128_gcm_sha256.
    - `session_id`: An opaque structure holding the session ID data.
    - `supported_versions`: A structure indicating supported TLS versions.
    - `server_name`: A structure containing the server name indication.
    - `supported_groups`: A structure indicating supported ECDHE groups.
    - `signature_algorithms`: A structure indicating supported signature algorithms.
    - `key_share`: A structure containing key share information.
    - `server_cert_types`: A union indicating supported server certificate types.
    - `client_cert_types`: A union indicating supported client certificate types.
    - `quic_tp`: An opaque structure for QUIC transport parameters.
    - `alpn`: An opaque structure for Application-Layer Protocol Negotiation data.
- **Description**: The `fd_tls_client_hello_t` structure represents a TLS v1.3 ClientHello message as defined in RFC 8446, Section 4.1.2. It includes various fields such as a random value, supported cipher suites, session ID, supported TLS versions, server name indication, supported ECDHE groups, signature algorithms, key share information, and certificate types for both server and client. Additionally, it holds opaque data for QUIC transport parameters and ALPN, making it a comprehensive representation of the ClientHello message used during the TLS handshake process.


---
### fd\_tls\_server\_hello
- **Type**: `struct`
- **Members**:
    - `random`: An array of 32 unsigned characters used to store a random value for the ServerHello message.
    - `cipher_suite`: A 16-bit unsigned integer representing the cipher suite chosen by the server.
    - `session_id`: An opaque structure holding the session ID for the TLS session.
    - `key_share`: A structure containing key share information for the TLS handshake.
- **Description**: The `fd_tls_server_hello` structure represents a TLS 1.3 ServerHello message, which is part of the TLS handshake process. It includes a random value, the cipher suite selected by the server, a session ID, and key share information. This structure is used to communicate the server's cryptographic parameters to the client, facilitating the establishment of a secure communication channel.


---
### fd\_tls\_server\_hello\_t
- **Type**: `struct`
- **Members**:
    - `random`: A 32-byte array representing the server's random value.
    - `cipher_suite`: A 16-bit unsigned integer indicating the cipher suite chosen by the server.
    - `session_id`: An opaque structure holding the session ID, which may be absent or have zero size.
    - `key_share`: A structure containing key share information, including whether x25519 is used and its corresponding data.
- **Description**: The `fd_tls_server_hello_t` structure represents a TLS v1.3 ServerHello message as defined in RFC 8446, Section 4.1.3. It includes a 32-byte random value generated by the server, a cipher suite identifier indicating the cryptographic algorithms selected, an optional session ID for session resumption, and key share information for key exchange. This structure is part of the TLS handshake process, where the server responds to the client's initial hello message with its own parameters for establishing a secure connection.


---
### fd\_tls\_enc\_ext
- **Type**: `struct`
- **Members**:
    - `server_cert`: Represents the server's certificate type in the TLS extension.
    - `client_cert`: Represents the client's certificate type in the TLS extension.
    - `quic_tp`: Holds opaque serialized data for QUIC transport parameters.
    - `alpn`: Holds opaque serialized data for Application-Layer Protocol Negotiation (ALPN).
- **Description**: The `fd_tls_enc_ext` structure is used to represent the EncryptedExtensions message in TLS v1.3, as defined in RFC 8446, Section 4.3.1. It contains fields for server and client certificate types, as well as opaque data for QUIC transport parameters and ALPN, which are essential for negotiating additional parameters and protocols during the TLS handshake.


---
### fd\_tls\_enc\_ext\_t
- **Type**: `struct`
- **Members**:
    - `server_cert`: Represents the server's certificate type in the EncryptedExtensions message.
    - `client_cert`: Represents the client's certificate type in the EncryptedExtensions message.
    - `quic_tp`: Holds opaque serialized data for QUIC transport parameters.
    - `alpn`: Holds opaque serialized data for Application-Layer Protocol Negotiation.
- **Description**: The `fd_tls_enc_ext_t` structure is used to represent a TLS 1.3 EncryptedExtensions message as defined in RFC 8446, Section 4.3.1. This structure contains fields for server and client certificate types, as well as opaque data for QUIC transport parameters and ALPN, which are extensions that can be included in the EncryptedExtensions message. The structure is designed to handle the dynamic nature of TLS extensions, allowing for flexible encoding and decoding of these extensions.


---
### fd\_tls\_cert\_verify
- **Type**: `struct`
- **Members**:
    - `sig_alg`: A 16-bit unsigned short representing the signature algorithm used, denoted by FD_TLS_SIGNATURE_{...}.
    - `sig`: A 64-byte array holding the signature data.
- **Description**: The `fd_tls_cert_verify` structure is used in the context of TLS v1.3 to represent a CertificateVerify message, as specified in RFC 8446, Section 4.4.3. This structure is specifically designed to support TLS signature algorithms that produce a 64-byte signature, such as Ed25519. The `sig_alg` field indicates the signature algorithm used, while the `sig` field contains the actual signature data. This structure is part of the static layout types in the TLS protocol implementation, allowing for efficient serialization and deserialization.


---
### fd\_tls\_cert\_verify\_t
- **Type**: `struct`
- **Members**:
    - `sig_alg`: A 16-bit unsigned integer representing the signature algorithm used.
    - `sig`: A 64-byte array holding the signature data.
- **Description**: The `fd_tls_cert_verify_t` structure represents a CertificateVerify message in TLS 1.3, as specified in RFC 8446, Section 4.4.3. It is designed to support TLS signature algorithms that produce a 64-byte signature, such as Ed25519. The structure contains a `sig_alg` field to specify the signature algorithm and a `sig` field to store the actual signature. This structure is used during the TLS handshake to verify the authenticity of the certificate presented by the peer.


---
### fd\_tls\_finished
- **Type**: `struct`
- **Members**:
    - `verify`: An array of 32 unsigned characters used for verification purposes.
- **Description**: The `fd_tls_finished` structure is a packed C struct that represents the 'Finished' message in the TLS v1.3 protocol, as specified in RFC 8446, Section 4.4.4. It contains a single member, `verify`, which is a 32-byte array used to hold the hash output for verification purposes. This structure is designed to match the wire representation of the Finished message, ensuring compatibility with the TLS protocol's requirements for message integrity and authenticity.


---
### fd\_tls\_finished\_t
- **Type**: `struct`
- **Members**:
    - `verify`: An array of 32 unsigned characters used to store the verification data for the Finished message.
- **Description**: The `fd_tls_finished_t` structure is a packed C struct that represents the wire format of the TLS 1.3 Finished message as specified in RFC 8446, Section 4.4.4. It is designed to support only TLS cipher suites with a 32-byte hash output size, and it contains a single member, `verify`, which holds the verification data necessary for the Finished message in the TLS handshake process.


---
### fd\_tls\_extract\_cert\_pubkey\_res
- **Type**: `struct`
- **Members**:
    - `pubkey`: A pointer to the extracted public key from a TLS certificate.
    - `alert`: An unsigned integer representing a TLS alert code.
    - `reason`: An unsigned short indicating the reason for the alert.
- **Description**: The `fd_tls_extract_cert_pubkey_res` structure is used to store the result of extracting a public key from a TLS certificate. It contains a pointer to the public key, an alert code to indicate any issues encountered during extraction, and a reason code providing additional context for the alert.


---
### fd\_tls\_extract\_cert\_pubkey\_res\_t
- **Type**: `struct`
- **Members**:
    - `pubkey`: A pointer to the public key extracted from a TLS certificate.
    - `alert`: An unsigned integer representing a TLS alert code.
    - `reason`: A 16-bit unsigned integer indicating the reason for extraction failure, if any.
- **Description**: The `fd_tls_extract_cert_pubkey_res_t` structure is used to store the result of extracting a public key from a TLS certificate. It contains a pointer to the extracted public key, a TLS alert code indicating any issues encountered during extraction, and a reason code providing additional context for any failure. This structure is part of the TLS protocol handling, specifically for managing certificate public key extraction.


# Functions

---
### fd\_tls\_u24\_bswap<!-- {{#callable:fd_tls_u24_bswap}} -->
The `fd_tls_u24_bswap` function swaps the byte order of a 24-bit integer represented by the `fd_tls_u24_t` structure.
- **Inputs**:
    - `x`: A `fd_tls_u24_t` structure representing a 24-bit integer whose byte order is to be swapped.
- **Control Flow**:
    - The function takes a `fd_tls_u24_t` structure `x` as input.
    - It creates a new `fd_tls_u24_t` structure `ret` with the bytes of `x` reordered from `x.v[2], x.v[1], x.v[0]` to `ret.v[0], ret.v[1], ret.v[2]`.
    - The function returns the `ret` structure with the swapped byte order.
- **Output**: A `fd_tls_u24_t` structure with the byte order of the input 24-bit integer reversed.


---
### fd\_tls\_u24\_to\_uint<!-- {{#callable:fd_tls_u24_to_uint}} -->
The `fd_tls_u24_to_uint` function converts a 24-bit big-endian integer stored in a `fd_tls_u24_t` structure to a standard 32-bit unsigned integer.
- **Inputs**:
    - `x`: A `fd_tls_u24_t` structure containing a 24-bit big-endian integer represented as an array of three unsigned characters.
- **Control Flow**:
    - The function calls `fd_uint_load_3` with the 3-byte array `x.v` as an argument.
    - `fd_uint_load_3` interprets the 3-byte array as a big-endian integer and converts it to a 32-bit unsigned integer.
    - The resulting 32-bit unsigned integer is returned.
- **Output**: A 32-bit unsigned integer representing the value of the 24-bit big-endian integer from the input `fd_tls_u24_t` structure.


---
### fd\_uint\_to\_tls\_u24<!-- {{#callable:fd_uint_to_tls_u24}} -->
The function `fd_uint_to_tls_u24` converts a 32-bit unsigned integer into a 24-bit TLS-compliant big-endian format.
- **Inputs**:
    - `x`: A 32-bit unsigned integer that needs to be converted to a 24-bit TLS format.
- **Control Flow**:
    - The function takes a 32-bit unsigned integer `x` as input.
    - It initializes a `fd_tls_u24_t` structure `ret` with three bytes, each representing a portion of the input integer `x`.
    - The first byte is the least significant byte of `x`, the second byte is the next 8 bits, and the third byte is the next 8 bits after that.
    - The function returns the `fd_tls_u24_t` structure `ret`.
- **Output**: A `fd_tls_u24_t` structure containing the 24-bit big-endian representation of the input integer.


---
### fd\_tls\_ext\_hdr\_bswap<!-- {{#callable:fd_tls_ext_hdr_bswap}} -->
The `fd_tls_ext_hdr_bswap` function performs an endianness conversion on the `type` and `sz` fields of a `fd_tls_ext_hdr_t` structure.
- **Inputs**:
    - `x`: A pointer to a `fd_tls_ext_hdr_t` structure whose `type` and `sz` fields need to be byte-swapped.
- **Control Flow**:
    - The function takes a pointer to a `fd_tls_ext_hdr_t` structure as input.
    - It calls `fd_ushort_bswap` on the `type` field of the structure to swap its byte order.
    - It calls `fd_ushort_bswap` on the `sz` field of the structure to swap its byte order.
- **Output**: The function does not return a value; it modifies the `fd_tls_ext_hdr_t` structure in place.


---
### fd\_tls\_msg\_hdr\_bswap<!-- {{#callable:fd_tls_msg_hdr_bswap}} -->
The `fd_tls_msg_hdr_bswap` function performs an endianness conversion on the size field of a TLS message header.
- **Inputs**:
    - `x`: A pointer to an `fd_tls_msg_hdr_t` structure, which represents a TLS message header.
- **Control Flow**:
    - The function takes a pointer to a `fd_tls_msg_hdr_t` structure as input.
    - It calls the [`fd_tls_u24_bswap`](#fd_tls_u24_bswap) function on the `sz` field of the structure, which is a 24-bit size field, to convert its endianness.
- **Output**: The function does not return a value; it modifies the `sz` field of the input structure in place.
- **Functions called**:
    - [`fd_tls_u24_bswap`](#fd_tls_u24_bswap)


---
### fd\_tls\_cert\_verify\_bswap<!-- {{#callable:fd_tls_cert_verify_bswap}} -->
The `fd_tls_cert_verify_bswap` function performs an endianness conversion on the `sig_alg` field of a `fd_tls_cert_verify_t` structure.
- **Inputs**:
    - `x`: A pointer to a `fd_tls_cert_verify_t` structure whose `sig_alg` field needs to be byte-swapped.
- **Control Flow**:
    - The function takes a pointer to a `fd_tls_cert_verify_t` structure as input.
    - It calls the `fd_ushort_bswap` function on the `sig_alg` field of the structure to perform a byte swap, converting the field from one endianness to another.
- **Output**: The function does not return a value; it modifies the `sig_alg` field of the input structure in place.


---
### fd\_tls\_decode\_ext\_quic\_tp<!-- {{#callable:fd_tls_decode_ext_quic_tp}} -->
The `fd_tls_decode_ext_quic_tp` function decodes a QUIC transport parameters extension from a wire format into a structured format.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_quic_tp_t` structure where the decoded data will be stored.
    - `wire`: A pointer to the input buffer containing the wire format data to be decoded.
    - `wire_sz`: The size of the input buffer in bytes.
- **Control Flow**:
    - The function calls [`fd_tls_decode_ext_opaque`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_opaque) with the provided `out`, `wire`, and `wire_sz` parameters.
    - The [`fd_tls_decode_ext_opaque`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_opaque) function sets the `buf` and `bufsz` fields of the `out` structure to point to the `wire` and `wire_sz`, respectively.
- **Output**: Returns the result of [`fd_tls_decode_ext_opaque`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_opaque), which is the number of bytes read from the wire on success, or a negated TLS error code on failure.
- **Functions called**:
    - [`fd_tls_decode_ext_opaque`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_opaque)


# Function Declarations (Public API)

---
### fd\_tls\_decode\_client\_hello<!-- {{#callable_declaration:fd_tls_decode_client_hello}} -->
Decodes a TLS ClientHello message from wire format.
- **Description**: This function is used to decode a TLS v1.3 ClientHello message from its wire format into a structured format. It should be called when you need to parse a ClientHello message received over a network. The function requires the output structure to be zero-initialized before calling. It processes the message, including its cipher suites and extensions, and populates the provided `fd_tls_client_hello_t` structure. The function returns the number of bytes read from the wire on success, or a negative TLS alert code on failure, indicating issues such as decode errors or illegal parameters.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_client_hello_t` structure where the decoded ClientHello message will be stored. Must be zero-initialized before calling. The caller retains ownership.
    - `wire`: A pointer to the buffer containing the wire format of the ClientHello message. Must not be null. The buffer may be modified for endianness conversion.
    - `wire_sz`: The size of the buffer pointed to by `wire`. Must be sufficient to contain the entire ClientHello message.
- **Output**: Returns the number of bytes read from the wire on success. On failure, returns a negative TLS alert code indicating the type of error.
- **See also**: [`fd_tls_decode_client_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_client_hello)  (Implementation)


---
### fd\_tls\_encode\_client\_hello<!-- {{#callable_declaration:fd_tls_encode_client_hello}} -->
Encodes a TLS ClientHello message into a wire format.
- **Description**: This function serializes a TLS v1.3 ClientHello message into a wire format suitable for transmission over a network. It should be used when preparing a ClientHello message for sending during the TLS handshake process. The function requires a properly initialized `fd_tls_client_hello_t` structure as input, and a buffer with sufficient size to hold the encoded message. The buffer size must be checked to ensure it can accommodate the encoded data, as insufficient buffer size will result in an error. The function returns the number of bytes written to the buffer on success, or a negative error code if encoding fails.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_client_hello_t` structure containing the ClientHello data to encode. The structure must be fully initialized and valid.
    - `wire`: A pointer to a buffer where the encoded ClientHello message will be written. The buffer must be large enough to hold the encoded data.
    - `wire_sz`: The size of the buffer pointed to by `wire`. It must be sufficient to store the entire encoded message; otherwise, the function will return an error.
- **Output**: Returns the number of bytes written to the `wire` buffer on success, or a negative error code if encoding fails.
- **See also**: [`fd_tls_encode_client_hello`](fd_tls_proto.c.driver.md#fd_tls_encode_client_hello)  (Implementation)


---
### fd\_tls\_decode\_server\_hello<!-- {{#callable_declaration:fd_tls_decode_server_hello}} -->
Decodes a TLS ServerHello message from wire format.
- **Description**: This function is used to decode a TLS v1.3 ServerHello message from its wire format into a structured format. It should be called when a ServerHello message is received and needs to be processed. The function expects the input buffer to contain a valid ServerHello message and will populate the provided `fd_tls_server_hello_t` structure with the decoded data. It handles various protocol checks and will return specific error codes if the message does not conform to expected standards, such as unsupported protocol versions or missing required extensions. The function assumes that the `out` parameter is properly initialized before calling.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_server_hello_t` structure where the decoded ServerHello message will be stored. Must not be null and should be zero-initialized before calling.
    - `wire`: A pointer to the buffer containing the wire format of the ServerHello message. Must not be null.
    - `wire_sz`: The size of the `wire` buffer in bytes. Must be large enough to contain a complete ServerHello message.
- **Output**: Returns the number of bytes read from the `wire` buffer on success. On failure, returns a negative value corresponding to a TLS alert error code.
- **See also**: [`fd_tls_decode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_decode_server_hello)  (Implementation)


---
### fd\_tls\_encode\_server\_hello<!-- {{#callable_declaration:fd_tls_encode_server_hello}} -->
Encodes a TLS ServerHello message into a wire format.
- **Description**: This function serializes a TLS v1.3 ServerHello message into a provided buffer in wire format. It is used during the TLS handshake to prepare the ServerHello message for transmission. The function requires a properly initialized `fd_tls_server_hello_t` structure as input and a buffer with sufficient size to hold the encoded message. The buffer size must be checked to ensure it can accommodate the encoded data, as insufficient buffer size will result in an error. The function returns the number of bytes written to the buffer on success, or a negative error code on failure.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_server_hello_t` structure containing the ServerHello data to be encoded. The structure must be fully initialized and valid.
    - `wire`: A pointer to a buffer where the encoded ServerHello message will be written. The buffer must be large enough to hold the encoded message.
    - `wire_sz`: The size of the buffer pointed to by `wire`. It must be sufficient to store the entire encoded message; otherwise, the function will return an error.
- **Output**: Returns the number of bytes written to the buffer on success, or a negative error code if encoding fails.
- **See also**: [`fd_tls_encode_server_hello`](fd_tls_proto.c.driver.md#fd_tls_encode_server_hello)  (Implementation)


---
### fd\_tls\_encode\_hello\_retry\_request<!-- {{#callable_declaration:fd_tls_encode_hello_retry_request}} -->
Encodes a TLS HelloRetryRequest message into a wire format.
- **Description**: This function is used to serialize a TLS HelloRetryRequest message from a given `fd_tls_server_hello_t` structure into a wire format suitable for transmission. It should be called when a server needs to respond to a client with a HelloRetryRequest during the TLS handshake process. The function requires a buffer to write the encoded message and the size of this buffer. It returns the number of bytes written to the buffer or a negative error code if the encoding fails. Ensure the buffer is large enough to hold the encoded message to avoid errors.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_server_hello_t` structure containing the data to be encoded. The structure must be properly initialized and populated with valid data before calling this function.
    - `wire`: A pointer to a buffer where the encoded message will be written. The buffer must be allocated by the caller and should be large enough to hold the encoded message.
    - `wire_sz`: The size of the buffer pointed to by `wire`. It must be sufficient to accommodate the entire encoded message; otherwise, the function will return an error.
- **Output**: Returns the number of bytes written to the buffer on success, or a negative error code on failure.
- **See also**: [`fd_tls_encode_hello_retry_request`](fd_tls_proto.c.driver.md#fd_tls_encode_hello_retry_request)  (Implementation)


---
### fd\_tls\_decode\_enc\_ext<!-- {{#callable_declaration:fd_tls_decode_enc_ext}} -->
Decodes a TLS EncryptedExtensions message from wire format.
- **Description**: This function is used to decode a TLS EncryptedExtensions message from its wire format into a structured format. It should be called when you have a buffer containing the wire format of a TLS EncryptedExtensions message and you need to extract its components into a `fd_tls_enc_ext_t` structure. The function expects the output structure to be zero-initialized before calling. It processes known extension types and populates the corresponding fields in the output structure. If the wire format contains unknown extensions, they are ignored. The function returns the number of bytes read from the wire buffer on success, or a negative TLS alert code on failure, such as when the wire format is invalid or an extension size exceeds the buffer size.
- **Inputs**:
    - `out`: A pointer to a `fd_tls_enc_ext_t` structure where the decoded extensions will be stored. Must be zero-initialized before calling. The caller retains ownership.
    - `wire`: A pointer to the buffer containing the wire format of the TLS EncryptedExtensions message. Must not be null.
    - `wire_sz`: The size of the wire buffer in bytes. Must be large enough to contain the entire message; otherwise, a decode error is returned.
- **Output**: Returns the number of bytes read from the wire buffer on success, or a negative TLS alert code on failure.
- **See also**: [`fd_tls_decode_enc_ext`](fd_tls_proto.c.driver.md#fd_tls_decode_enc_ext)  (Implementation)


---
### fd\_tls\_encode\_enc\_ext<!-- {{#callable_declaration:fd_tls_encode_enc_ext}} -->
Encodes a TLS EncryptedExtensions message into wire format.
- **Description**: This function serializes a TLS EncryptedExtensions message, represented by the `fd_tls_enc_ext_t` structure, into a wire format suitable for transmission. It should be used when preparing a TLS EncryptedExtensions message for network communication. The function requires a buffer to write the encoded data and the size of this buffer. It returns the number of bytes written to the buffer, or a negative error code if encoding fails. Ensure the buffer is large enough to hold the encoded message to avoid errors.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_enc_ext_t` structure containing the TLS EncryptedExtensions data to encode. The structure must be properly initialized and populated with valid data before calling this function.
    - `wire`: A pointer to a buffer where the encoded data will be written. The buffer must be allocated by the caller and should be large enough to hold the encoded message.
    - `wire_sz`: The size of the buffer pointed to by `wire`. It must be sufficient to accommodate the encoded data; otherwise, the function may return an error.
- **Output**: Returns the number of bytes written to the `wire` buffer on success, or a negative error code if encoding fails.
- **See also**: [`fd_tls_encode_enc_ext`](fd_tls_proto.c.driver.md#fd_tls_encode_enc_ext)  (Implementation)


---
### fd\_tls\_encode\_cert\_x509<!-- {{#callable_declaration:fd_tls_encode_cert_x509}} -->
Encodes an X.509 certificate into a TLS wire format.
- **Description**: This function is used to encode an X.509 certificate into the TLS wire format, preparing it for transmission over a network. It should be called when you need to send a certificate as part of a TLS handshake. The function requires a buffer to write the encoded data into, and it is important to ensure that this buffer is large enough to hold the encoded certificate. The function returns the number of bytes written to the buffer, or a negative value indicating an error if the buffer is too small.
- **Inputs**:
    - `x509`: A pointer to the X.509 certificate data to be encoded. The data must be valid and the pointer must not be null.
    - `x509_sz`: The size of the X.509 certificate data in bytes. Must accurately reflect the size of the data pointed to by x509.
    - `wire`: A pointer to the buffer where the encoded certificate will be written. The buffer must be large enough to hold the encoded data.
    - `wire_sz`: The size of the buffer pointed to by wire in bytes. Must be sufficient to hold the encoded certificate data.
- **Output**: Returns the number of bytes written to the wire buffer on success, or a negative value indicating an error if the buffer is too small.
- **See also**: [`fd_tls_encode_cert_x509`](fd_tls_proto.c.driver.md#fd_tls_encode_cert_x509)  (Implementation)


---
### fd\_tls\_encode\_raw\_public\_key<!-- {{#callable_declaration:fd_tls_encode_raw_public_key}} -->
Encodes an Ed25519 public key into a TLS raw public key format.
- **Description**: This function is used to encode an Ed25519 public key into a TLS raw public key format, suitable for transmission over a network. It should be called when you need to serialize a public key for inclusion in a TLS handshake. The function requires a buffer to write the encoded data, and the buffer must be large enough to hold the encoded key. The function returns the number of bytes written to the buffer, or a negative value indicating an error if the buffer is too small.
- **Inputs**:
    - `key`: A pointer to a 32-byte Ed25519 public key. The caller must ensure this pointer is valid and points to a properly formatted key.
    - `wire`: A pointer to a buffer where the encoded key will be written. The buffer must be large enough to hold the encoded data.
    - `wire_sz`: The size of the buffer pointed to by 'wire'. It must be large enough to accommodate the encoded key, otherwise the function will return an error.
- **Output**: Returns the number of bytes written to the buffer on success, or a negative value indicating an error if the buffer is too small.
- **See also**: [`fd_tls_encode_raw_public_key`](fd_tls_proto.c.driver.md#fd_tls_encode_raw_public_key)  (Implementation)


---
### fd\_tls\_decode\_cert\_verify<!-- {{#callable_declaration:fd_tls_decode_cert_verify}} -->
Decodes a CertificateVerify message from wire format.
- **Description**: This function decodes a TLS CertificateVerify message from its wire format into a structured format. It should be used when you need to interpret a CertificateVerify message received over a TLS connection. The function expects the input buffer to contain a valid CertificateVerify message and the output structure to be zero-initialized. It checks that the signature algorithm is Ed25519 and that the signature size is exactly 64 bytes. If these conditions are not met, the function returns a negative error code indicating an illegal parameter.
- **Inputs**:
    - `out`: A pointer to an fd_tls_cert_verify_t structure where the decoded CertificateVerify message will be stored. Must be zero-initialized before calling this function. The caller retains ownership.
    - `wire`: A pointer to the buffer containing the wire format of the CertificateVerify message. Must not be null.
    - `wire_sz`: The size of the wire buffer in bytes. Must be sufficient to contain a valid CertificateVerify message.
- **Output**: Returns the number of bytes read from the wire buffer on success. On failure, returns a negative TLS error code, specifically FD_TLS_ALERT_ILLEGAL_PARAMETER if the signature algorithm is not Ed25519 or the signature size is not 64 bytes.
- **See also**: [`fd_tls_decode_cert_verify`](fd_tls_proto.c.driver.md#fd_tls_decode_cert_verify)  (Implementation)


---
### fd\_tls\_encode\_cert\_verify<!-- {{#callable_declaration:fd_tls_encode_cert_verify}} -->
Encodes a CertificateVerify structure into a wire format.
- **Description**: This function serializes a given CertificateVerify structure into a specified buffer in wire format, suitable for transmission over a network. It is used when preparing a CertificateVerify message for a TLS handshake. The function requires a valid input structure and a sufficiently large buffer to store the encoded data. It returns the number of bytes written to the buffer, or a negative error code if the buffer is too small.
- **Inputs**:
    - `in`: A pointer to a constant fd_tls_cert_verify_t structure containing the CertificateVerify data to be encoded. The structure must be properly initialized and must not be null.
    - `wire`: A pointer to a buffer where the encoded data will be written. The buffer must be large enough to hold the encoded data, and the caller retains ownership.
    - `wire_sz`: The size of the buffer pointed to by wire. It must be at least 66 bytes to accommodate the encoded data.
- **Output**: Returns the number of bytes written to the buffer on success, or a negative error code if the buffer is too small.
- **See also**: [`fd_tls_encode_cert_verify`](fd_tls_proto.c.driver.md#fd_tls_encode_cert_verify)  (Implementation)


---
### fd\_tls\_decode\_ext\_server\_name<!-- {{#callable_declaration:fd_tls_decode_ext_server_name}} -->
Decodes a TLS server name extension from wire format.
- **Description**: This function decodes a TLS server name extension from a wire format buffer into a structured format. It is used when processing TLS handshake messages to extract the server name information. The function must be called with a valid buffer containing the encoded server name extension data. The output structure must be zero-initialized before calling this function. The function returns the number of bytes read from the buffer on success, or a negative TLS error code if decoding fails, such as when the buffer is too small or the data is malformed.
- **Inputs**:
    - `out`: A pointer to a fd_tls_ext_server_name_t structure where the decoded server name will be stored. Must be zero-initialized before calling the function. The caller retains ownership.
    - `wire`: A pointer to the buffer containing the encoded server name extension data. Must not be null. The buffer should be at least as large as the data it contains.
    - `wire_sz`: The size of the buffer pointed to by wire, in bytes. Must be large enough to contain the encoded server name extension data.
- **Output**: Returns the number of bytes read from the wire buffer on success, or a negative TLS error code on failure.
- **See also**: [`fd_tls_decode_ext_server_name`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_server_name)  (Implementation)


---
### fd\_tls\_decode\_ext\_supported\_groups<!-- {{#callable_declaration:fd_tls_decode_ext_supported_groups}} -->
Decodes supported TLS groups from wire format.
- **Description**: This function decodes a list of supported TLS groups from a wire format buffer into a `fd_tls_ext_supported_groups_t` structure. It is used to interpret the supported groups extension in a TLS handshake, specifically identifying if the X25519 group is supported. The function must be called with a valid buffer containing the wire format data and the size of this buffer. The output structure must be properly initialized before calling this function. The function returns the number of bytes read from the wire buffer, allowing the caller to handle the remaining data if necessary.
- **Inputs**:
    - `out`: A pointer to a `fd_tls_ext_supported_groups_t` structure where the decoded information will be stored. The structure must be initialized before calling the function. The caller retains ownership.
    - `wire`: A pointer to a buffer containing the wire format data to be decoded. The buffer must be valid and contain at least `wire_sz` bytes. The caller retains ownership.
    - `wire_sz`: The size of the wire buffer in bytes. It must accurately reflect the number of bytes available in the `wire` buffer.
- **Output**: Returns the number of bytes read from the wire buffer as a long integer. If the function encounters an error, it returns a negative TLS error code.
- **See also**: [`fd_tls_decode_ext_supported_groups`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_supported_groups)  (Implementation)


---
### fd\_tls\_decode\_ext\_supported\_versions<!-- {{#callable_declaration:fd_tls_decode_ext_supported_versions}} -->
Decodes the supported TLS versions from a wire format.
- **Description**: This function decodes the supported TLS versions from a given wire format buffer and updates the provided `fd_tls_ext_supported_versions_t` structure to indicate support for TLS 1.3 if present. It should be used when parsing TLS extension data to determine which TLS versions are supported by the peer. The function assumes that the `out` parameter is a valid pointer to a zero-initialized structure. The `wire` buffer should contain the encoded data, and its size is specified by `wire_sz`. The function returns the number of bytes read from the wire buffer, or a negative value indicating an error if the decoding fails.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_ext_supported_versions_t` structure that will be updated to reflect the supported TLS versions. Must not be null and should be zero-initialized before calling.
    - `wire`: A pointer to a buffer containing the wire format data to decode. Must not be null.
    - `wire_sz`: The size of the `wire` buffer in bytes. Must be sufficient to contain the encoded data.
- **Output**: Returns the number of bytes read from the `wire` buffer on success, or a negative value indicating an error if decoding fails.
- **See also**: [`fd_tls_decode_ext_supported_versions`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_supported_versions)  (Implementation)


---
### fd\_tls\_decode\_ext\_signature\_algorithms<!-- {{#callable_declaration:fd_tls_decode_ext_signature_algorithms}} -->
Decodes a TLS signature algorithms extension from wire format.
- **Description**: Use this function to decode a TLS signature algorithms extension from its wire format into a structured format. This function is typically called when processing TLS handshake messages that include signature algorithm extensions. The output structure must be zero-initialized before calling this function. The function processes the input wire data and updates the output structure to indicate the presence of supported signature algorithms, such as Ed25519. It returns the number of bytes read from the wire data, which can be used to verify the amount of data processed.
- **Inputs**:
    - `out`: A pointer to a fd_tls_ext_signature_algorithms_t structure that will be populated with the decoded data. Must be zero-initialized before calling this function. The caller retains ownership.
    - `wire`: A pointer to the input buffer containing the wire format data. This buffer must be at least wire_sz bytes long. The caller retains ownership.
    - `wire_sz`: The size of the wire buffer in bytes. Must be large enough to contain the encoded data.
- **Output**: Returns the number of bytes read from the wire data on success. If the function fails, it returns a negated TLS error code.
- **See also**: [`fd_tls_decode_ext_signature_algorithms`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_signature_algorithms)  (Implementation)


---
### fd\_tls\_decode\_key\_share<!-- {{#callable_declaration:fd_tls_decode_key_share}} -->
Decodes a TLS key share from a wire format.
- **Description**: This function is used to decode a TLS key share from a given wire format buffer into a structured format. It is typically called when processing TLS handshake messages that include key share information. The function expects the input buffer to contain a valid key share structure, and it will populate the provided `fd_tls_key_share_t` structure with the decoded data. The function must be called with a non-null `out` parameter, and the `wire` buffer must be large enough to contain the encoded key share data. If the key share group is unsupported or the data is malformed, the function returns a negative error code indicating a decode error.
- **Inputs**:
    - `out`: A pointer to an `fd_tls_key_share_t` structure where the decoded key share will be stored. Must not be null. The caller retains ownership.
    - `wire`: A pointer to a buffer containing the wire format of the key share. Must not be null and should point to a valid encoded key share.
    - `wire_sz`: The size of the `wire` buffer in bytes. Must be large enough to contain the encoded key share data.
- **Output**: Returns the number of bytes read from the `wire` buffer on success. On failure, returns a negative value corresponding to a TLS decode error code.
- **See also**: [`fd_tls_decode_key_share`](fd_tls_proto.c.driver.md#fd_tls_decode_key_share)  (Implementation)


---
### fd\_tls\_decode\_key\_share\_list<!-- {{#callable_declaration:fd_tls_decode_key_share_list}} -->
Decodes a list of TLS key shares from a wire format.
- **Description**: This function is used to decode a list of TLS key shares from a given wire format into a structured format. It is typically called when processing TLS messages that include key share extensions, such as during a TLS handshake. The function requires the output structure to be zero-initialized before calling. It reads from the provided wire buffer and populates the output structure with the decoded key shares. The function returns the number of bytes consumed from the wire buffer, or a negative TLS error code if decoding fails. The wire buffer may be altered during the decoding process, so it should not be reused after this function is called.
- **Inputs**:
    - `out`: A pointer to an fd_tls_key_share_t structure where the decoded key shares will be stored. Must be zero-initialized before calling. The caller retains ownership.
    - `wire`: A pointer to the buffer containing the wire format data to decode. Must not be null. The buffer may be modified during decoding.
    - `wire_sz`: The size of the wire buffer in bytes. Must be large enough to contain the encoded key share list.
- **Output**: Returns the number of bytes read from the wire buffer on success, or a negative TLS error code on failure.
- **See also**: [`fd_tls_decode_key_share_list`](fd_tls_proto.c.driver.md#fd_tls_decode_key_share_list)  (Implementation)


---
### fd\_tls\_decode\_ext\_cert\_type\_list<!-- {{#callable_declaration:fd_tls_decode_ext_cert_type_list}} -->
Decodes a TLS certificate type extension list from wire format.
- **Description**: This function decodes a TLS certificate type extension list from a wire format buffer into a structured format. It should be used when you need to interpret the certificate types supported by a TLS extension from a serialized data stream. The function expects the output structure to be zero-initialized before calling. It processes the input buffer to identify supported certificate types, such as X.509 and raw public keys, and sets corresponding flags in the output structure. Unsupported certificate types in the input are ignored. The function returns the number of bytes read from the input buffer, or a negative value indicating a decode error if the input is invalid.
- **Inputs**:
    - `out`: A pointer to a fd_tls_ext_cert_type_list_t structure where the decoded certificate types will be stored. Must be zero-initialized before calling. The caller retains ownership.
    - `wire`: A pointer to the input buffer containing the wire format data. Must not be null.
    - `wire_sz`: The size of the input buffer in bytes. Must be sufficient to contain the encoded data.
- **Output**: Returns the number of bytes read from the input buffer on success, or a negative value indicating a decode error on failure.
- **See also**: [`fd_tls_decode_ext_cert_type_list`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_cert_type_list)  (Implementation)


---
### fd\_tls\_encode\_ext\_cert\_type\_list<!-- {{#callable_declaration:fd_tls_encode_ext_cert_type_list}} -->
Encodes a certificate type list into a wire format.
- **Description**: This function serializes a given certificate type list into a specified wire buffer, which is used in TLS communications. It should be called when you need to encode the certificate types supported by a client or server into a format suitable for transmission over a network. The function requires a valid certificate type list and a sufficiently large buffer to hold the encoded data. It returns the number of bytes written to the buffer, allowing the caller to handle the encoded data appropriately.
- **Inputs**:
    - `in`: A certificate type list to be encoded, represented by a `fd_tls_ext_cert_type_list_t` structure. It indicates which certificate types are present and should be encoded.
    - `wire`: A pointer to the buffer where the encoded data will be written. This buffer must be large enough to hold the encoded certificate type list. The caller retains ownership and must ensure the buffer is valid.
    - `wire_sz`: The size of the buffer pointed to by `wire`. It must be large enough to accommodate the encoded data; otherwise, the function may not encode the data correctly.
- **Output**: Returns the number of bytes written to the `wire` buffer. If the buffer is too small, the function may not encode the data correctly, but this behavior is not explicitly defined in the header.
- **See also**: [`fd_tls_encode_ext_cert_type_list`](fd_tls_proto.c.driver.md#fd_tls_encode_ext_cert_type_list)  (Implementation)


---
### fd\_tls\_decode\_ext\_cert\_type<!-- {{#callable_declaration:fd_tls_decode_ext_cert_type}} -->
Decodes a TLS certificate type extension from wire format.
- **Description**: This function is used to decode a TLS certificate type extension from its wire format into a structured format. It should be called when you need to interpret the certificate type from a received TLS message. The function requires a valid pointer to a `fd_tls_ext_cert_type_t` structure where the decoded certificate type will be stored. The input wire data must be a valid encoded certificate type extension and should not be reused for decoding again as it may be altered during the process. The function returns the number of bytes read from the wire on success, or a negative TLS error code if the decoding fails.
- **Inputs**:
    - `out`: A pointer to a `fd_tls_ext_cert_type_t` structure where the decoded certificate type will be stored. Must not be null.
    - `wire`: A pointer to the wire format data representing the certificate type extension. Must not be null and should point to a valid encoded extension.
    - `wire_sz`: The size of the wire data in bytes. Must be sufficient to contain a valid encoded certificate type extension.
- **Output**: Returns the number of bytes read from the wire on success, or a negative TLS error code on failure.
- **See also**: [`fd_tls_decode_ext_cert_type`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_cert_type)  (Implementation)


---
### fd\_tls\_encode\_ext\_cert\_type<!-- {{#callable_declaration:fd_tls_encode_ext_cert_type}} -->
Encodes a TLS certificate type extension into wire format.
- **Description**: This function is used to serialize a TLS certificate type extension into a wire format buffer. It is typically called when preparing TLS handshake messages that include certificate type extensions. The function requires a valid certificate type structure and a sufficiently large buffer to hold the encoded data. It returns the number of bytes written to the buffer, allowing the caller to handle the encoded data appropriately.
- **Inputs**:
    - `in`: A structure representing the TLS certificate type to be encoded. The structure must be properly initialized and contain valid data.
    - `wire`: A pointer to the buffer where the encoded data will be written. The buffer must be large enough to hold the encoded data.
    - `wire_sz`: The size of the buffer pointed to by 'wire'. It must be sufficient to accommodate the encoded data; otherwise, the function may return an error.
- **Output**: Returns the number of bytes written to the buffer on success. If the buffer is too small, it returns a negated TLS error code.
- **See also**: [`fd_tls_encode_ext_cert_type`](fd_tls_proto.c.driver.md#fd_tls_encode_ext_cert_type)  (Implementation)


---
### fd\_tls\_decode\_ext\_opaque<!-- {{#callable_declaration:fd_tls_decode_ext_opaque}} -->
Assigns wire data to an opaque extension structure.
- **Description**: This function is used to decode opaque TLS extension data by assigning the provided wire data and its size to the specified opaque extension structure. It is typically called when the extension data is already in a serialized form and needs to be represented in a structured format. The function does not perform any validation or transformation on the input data, so it should be used when the wire data is known to be valid and correctly formatted. The lifetime of the data in the output structure is tied to the lifetime of the input wire data.
- **Inputs**:
    - `out`: A pointer to an fd_tls_ext_opaque_t structure where the wire data and its size will be stored. The caller must ensure this pointer is valid and that the structure is properly initialized.
    - `wire`: A pointer to the serialized extension data. This must not be null, and the data should be valid for the duration of its use in the output structure.
    - `wire_sz`: The size of the wire data in bytes. It should accurately reflect the size of the data pointed to by wire.
- **Output**: Returns the size of the wire data as a long integer, indicating the number of bytes processed.
- **See also**: [`fd_tls_decode_ext_opaque`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_opaque)  (Implementation)


---
### fd\_tls\_decode\_ext\_alpn<!-- {{#callable_declaration:fd_tls_decode_ext_alpn}} -->
Decodes an ALPN extension from wire format.
- **Description**: This function decodes an Application-Layer Protocol Negotiation (ALPN) extension from its wire format into a structured format. It should be used when processing TLS extensions that include ALPN data. The function expects the input buffer to contain a valid ALPN extension and checks that the size of the ALPN data matches the expected size. If the size does not match, it returns a negative error code indicating a decode error. The function must be called with a properly initialized output structure and a valid input buffer.
- **Inputs**:
    - `out`: A pointer to an fd_tls_ext_alpn_t structure where the decoded ALPN data will be stored. The caller must ensure this is a valid, non-null pointer.
    - `wire`: A pointer to the buffer containing the wire format of the ALPN extension. This must not be null and should point to a buffer of at least wire_sz bytes.
    - `wire_sz`: The size of the wire buffer in bytes. It must match the size of the ALPN data specified in the buffer.
- **Output**: Returns the number of bytes read from the wire buffer on success, or a negative error code if the decoding fails.
- **See also**: [`fd_tls_decode_ext_alpn`](fd_tls_proto.c.driver.md#fd_tls_decode_ext_alpn)  (Implementation)


---
### fd\_tls\_encode\_ext\_alpn<!-- {{#callable_declaration:fd_tls_encode_ext_alpn}} -->
Encodes an ALPN extension into a wire format buffer.
- **Description**: This function serializes an ALPN (Application-Layer Protocol Negotiation) extension into a provided buffer in wire format. It is used when preparing TLS messages that include ALPN extensions. The function requires that the buffer is large enough to hold the serialized data, which includes a 2-byte length field followed by the ALPN data. If the buffer is too small, the function returns a negative error code indicating an internal error. This function should be called when you need to encode ALPN data for transmission over a network.
- **Inputs**:
    - `in`: A pointer to a `fd_tls_ext_alpn_t` structure containing the ALPN data to be encoded. The structure must be properly initialized and contain valid data. The caller retains ownership of this data.
    - `wire`: A pointer to a buffer where the encoded ALPN data will be written. The buffer must be large enough to hold the encoded data, which is 2 bytes plus the size of the ALPN data.
    - `wire_sz`: The size of the `wire` buffer in bytes. It must be at least 2 bytes plus the size of the ALPN data to avoid an error.
- **Output**: Returns the number of bytes written to the `wire` buffer on success. On failure, returns a negative value indicating an internal error.
- **See also**: [`fd_tls_encode_ext_alpn`](fd_tls_proto.c.driver.md#fd_tls_encode_ext_alpn)  (Implementation)


---
### fd\_tls\_extract\_cert\_pubkey<!-- {{#callable_declaration:fd_tls_extract_cert_pubkey}} -->
Extracts the public key from a TLS certificate message.
- **Description**: Use this function to extract the public key from a given TLS certificate message. It is useful when you need to verify the authenticity of a certificate by accessing its public key. Ensure that the certificate chain is correctly formatted and that the certificate type is supported before calling this function. The function returns a structure containing the public key and any relevant alerts or reasons if extraction fails.
- **Inputs**:
    - `cert`: A pointer to the certificate chain from which the public key is to be extracted. It must not be null and should point to a valid memory location containing the certificate data.
    - `cert_sz`: The size of the certificate chain in bytes. It should accurately reflect the size of the data pointed to by 'cert'.
    - `cert_type`: An unsigned integer representing the type of certificate. It should be a valid certificate type as defined by the TLS protocol.
- **Output**: Returns a structure of type 'fd_tls_extract_cert_pubkey_res_t' containing the extracted public key, an alert code, and a reason code if applicable.
- **See also**: [`fd_tls_extract_cert_pubkey`](fd_tls_proto.c.driver.md#fd_tls_extract_cert_pubkey)  (Implementation)


