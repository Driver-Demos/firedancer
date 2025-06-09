# Purpose
This C header file, `fd_quic_common.h`, is part of a larger codebase related to the QUIC protocol, which is a transport layer network protocol. It primarily serves as a collection of type definitions and constants that are used across the QUIC implementation. The file defines several forward declarations for structures related to QUIC connections, configurations, and TLS (Transport Layer Security) components, indicating its role in managing QUIC's complex state and security features. Additionally, it defines a `fd_quic_range` structure, which is used to represent a range with a lower and upper offset, likely for managing data packet sequences or stream offsets. The constants `FD_QUIC_PARSE_FAIL` and `FD_QUIC_ENCODE_FAIL` are defined to represent failure states in parsing and encoding operations, respectively, and a limit on the maximum number of supported versions in a version packet is set with `FD_QUIC_MAX_VERSIONS`.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`


# Data Structures

---
### fd\_quic\_t
- **Type**: `typedef struct fd_quic fd_quic_t;`
- **Description**: The `fd_quic_t` is a forward declaration of a structure in C, indicating that it is a custom data type related to the QUIC protocol, but its internal structure and members are not defined in the provided code. This suggests that `fd_quic_t` is likely used to represent a QUIC connection or context, but further details would be found in the full definition elsewhere in the codebase.


---
### fd\_quic\_conn\_t
- **Type**: `typedef struct fd_quic_conn fd_quic_conn_t;`
- **Description**: The `fd_quic_conn_t` is a forward declaration of a structure in the QUIC protocol implementation, which likely represents a connection in the QUIC protocol. The actual definition of the structure is not provided in the given code, indicating that it is defined elsewhere. This structure is part of a larger set of types related to QUIC, a transport layer network protocol designed for multiplexed connections over UDP.


---
### fd\_quic\_config\_t
- **Type**: `typedef struct fd_quic_config fd_quic_config_t;`
- **Description**: The `fd_quic_config_t` is a forward declaration of a structure used in the QUIC protocol implementation, likely intended to hold configuration settings for QUIC connections. The actual definition of the structure is not provided in the given code, indicating that it is defined elsewhere, possibly containing fields related to network settings, security parameters, or other configuration options necessary for establishing and managing QUIC connections.


---
### fd\_quic\_tls\_cfg\_t
- **Type**: `typedef struct fd_quic_tls_cfg fd_quic_tls_cfg_t;`
- **Description**: The `fd_quic_tls_cfg_t` is a forward declaration of a structure intended to represent the configuration settings for TLS (Transport Layer Security) within the QUIC protocol implementation. As a forward declaration, the actual structure definition is not provided in the given code, indicating that it is defined elsewhere in the codebase. This structure is likely used to encapsulate various parameters and settings necessary for establishing and managing secure TLS connections in the context of QUIC.


---
### fd\_quic\_tls\_t
- **Type**: `typedef struct fd_quic_tls fd_quic_tls_t;`
- **Description**: The `fd_quic_tls_t` is a forward declaration of a structure used in the QUIC protocol implementation, specifically related to TLS (Transport Layer Security) operations. The actual definition of the structure is not provided in the given code, indicating that it is likely defined elsewhere in the codebase. This structure is part of a larger set of types and configurations used to manage QUIC connections and their security aspects.


---
### fd\_quic\_tls\_hs\_t
- **Type**: `typedef struct fd_quic_tls_hs fd_quic_tls_hs_t;`
- **Description**: The `fd_quic_tls_hs_t` is a forward declaration of a structure used in the QUIC protocol implementation, specifically related to TLS handshake operations. The actual definition of the structure is not provided in the given code, indicating that it is likely defined elsewhere in the codebase. This structure is part of a set of types that facilitate the handling of QUIC connections, configurations, and TLS operations.


---
### fd\_quic\_tls\_secret\_t
- **Type**: `typedef struct fd_quic_tls_secret`
- **Description**: The `fd_quic_tls_secret_t` is a forward-declared data structure in the QUIC protocol implementation, likely used to handle TLS secrets within the QUIC connection process. The actual definition and members of this structure are not provided in the given code, indicating that it is defined elsewhere, possibly in a more detailed implementation file. This structure is part of a set of types related to QUIC and TLS, suggesting its role in managing cryptographic secrets necessary for secure communication.


---
### fd\_quic\_tls\_hs\_data\_t
- **Type**: `typedef struct fd_quic_tls_hs_data fd_quic_tls_hs_data_t;`
- **Description**: The `fd_quic_tls_hs_data_t` is a forward declaration of a structure in C, indicating that it is a type used within the QUIC protocol implementation, specifically related to TLS handshake data. However, the actual definition of the structure is not provided in the given code, so the specific fields and their purposes are not described here.


---
### fd\_quic\_pkt\_t
- **Type**: `typedef struct fd_quic_pkt fd_quic_pkt_t;`
- **Description**: The `fd_quic_pkt_t` is a forward declaration of a structure in the QUIC protocol implementation, indicating that it is a custom data type used to represent a QUIC packet. The actual definition of the structure is not provided in the given code, suggesting that it is defined elsewhere in the codebase. This structure is likely used to encapsulate the data and metadata associated with a QUIC packet, which is a fundamental unit of data transmission in the QUIC protocol.


---
### fd\_quic\_range
- **Type**: `struct`
- **Members**:
    - `offset_lo`: The lower bound of the range, inclusive.
    - `offset_hi`: The upper bound of the range, exclusive.
- **Description**: The `fd_quic_range` structure defines a range with a lower bound `offset_lo` and an upper bound `offset_hi`, where the range includes all offsets from `offset_lo` up to, but not including, `offset_hi`. This structure is aligned to 16 bytes and is used to represent a range of offsets, with a zero-initialized range being empty, represented as [0,0).


---
### fd\_quic\_range\_t
- **Type**: `struct`
- **Members**:
    - `offset_lo`: The lower bound of the range, inclusive.
    - `offset_hi`: The upper bound of the range, exclusive.
- **Description**: The `fd_quic_range_t` structure defines a range with a lower and upper bound, represented by `offset_lo` and `offset_hi` respectively. This range is used to determine if a given offset falls within the specified bounds, where the range is inclusive of `offset_lo` and exclusive of `offset_hi`. A zero-initialized range, with both bounds set to zero, represents an empty range.


