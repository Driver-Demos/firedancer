# Purpose
This C header file, `fd_quic_retry_private.h`, is part of a QUIC protocol implementation, specifically dealing with the Retry packet mechanism. It defines constants and a function prototype related to the encoding and handling of QUIC Retry packets. The file includes other headers and a source file, suggesting it relies on shared definitions and implementations for QUIC protocol operations. Key constants defined include `FD_QUIC_RETRY_MAX_PSEUDO_SZ` and `FD_QUIC_RETRY_MAX_SZ`, which specify the maximum sizes for encoded Retry pseudo headers and packets, respectively. Additionally, `FD_QUIC_RETRY_EXPIRE_SHIFT` is defined to manage timestamp precision by right-shifting expiry timestamps, although it notes a potential issue with slower clocks. The function [`fd_quic_retry_pseudo`](#fd_quic_retry_pseudo) is declared to generate a pseudo header for a Retry packet, indicating its role in packet processing.
# Imports and Dependencies

---
- `fd_quic_retry.h`
- `fd_quic_proto.h`
- `fd_quic_proto.c`


# Function Declarations (Public API)

---
### fd\_quic\_retry\_pseudo<!-- {{#callable_declaration:fd_quic_retry_pseudo}} -->
Constructs a QUIC Retry pseudo-packet.
- **Description**: This function constructs a QUIC Retry pseudo-packet and writes it to the provided output buffer. It should be used when a Retry pseudo-packet needs to be generated for a QUIC connection, typically during the handling of a Retry packet. The function requires a valid Retry packet and the original destination connection ID. The size of the Retry packet must be greater than the size of a QUIC crypto tag and less than or equal to the maximum allowed Retry packet size. The function returns the size of the constructed pseudo-packet.
- **Inputs**:
    - `out`: A buffer where the constructed pseudo-packet will be written. It must have a size of at least FD_QUIC_RETRY_MAX_PSEUDO_SZ bytes. The caller retains ownership.
    - `retry_pkt`: A pointer to the Retry packet data. It must not be null, and the data should be valid and properly formatted.
    - `retry_pkt_sz`: The size of the Retry packet in bytes. It must be greater than FD_QUIC_CRYPTO_TAG_SZ and less than or equal to FD_QUIC_RETRY_MAX_SZ. If the size is outside this range, the function will return FD_QUIC_PARSE_FAIL.
    - `orig_dst_conn_id`: A pointer to the original destination connection ID structure. It must not be null, and the structure should contain a valid connection ID.
- **Output**: The function returns the size of the constructed pseudo-packet in bytes. If the input Retry packet size is invalid, it returns FD_QUIC_PARSE_FAIL.
- **See also**: [`fd_quic_retry_pseudo`](fd_quic_retry.c.driver.md#fd_quic_retry_pseudo)  (Implementation)


