# Purpose
This C header file, `fd_pcapng_private.h`, is designed to define internal structures and constants for handling PCAP Next Generation (PCAPNG) file formats. PCAPNG is a format used for storing network packet data, and this file provides the necessary definitions to parse and manipulate various block types within a PCAPNG file. The file includes definitions for different block types such as Section Header Block (SHB), Interface Description Block (IDB), Simple Packet Block (SPB), Enhanced Packet Block (EPB), and Decryption Secrets Block (DSB). Each block type is represented by a corresponding structure, which includes fields for block type identifiers, block sizes, and other relevant metadata.

The file also defines several constants and structures for handling options within these blocks, such as option types and sizes. The use of packed structures ensures that the data is aligned correctly for network data processing. This header file is intended for internal use within a larger library or application that processes PCAPNG files, as indicated by the inclusion of the `fd_pcapng.h` header and the use of private naming conventions. It does not define public APIs or external interfaces, but rather provides the foundational components necessary for implementing PCAPNG file parsing and manipulation functionality.
# Imports and Dependencies

---
- `fd_pcapng.h`


# Data Structures

---
### fd\_pcapng\_option
- **Type**: `struct`
- **Members**:
    - `type`: A 16-bit unsigned short indicating the type of the option, typically defined by constants like FD_PCAPNG_*_OPT_*.
    - `sz`: A 16-bit unsigned short representing the size in bytes of the option data pointed to by the value member.
    - `value`: A pointer to the first byte of the option data, which is variable-length and its type depends on the option type.
- **Description**: The `fd_pcapng_option` structure is used to represent an option in the PCAP Next Generation (pcapng) file format. Each option consists of a type, a size, and a pointer to the option's data. The type field specifies the kind of option, the sz field indicates the size of the data in bytes, and the value field points to the actual data. This structure allows for flexible handling of various option types, including strings and other data, within pcapng blocks.


---
### fd\_pcapng\_option\_t
- **Type**: `struct`
- **Members**:
    - `type`: A 16-bit unsigned short indicating the type of the option.
    - `sz`: A 16-bit unsigned short representing the byte size of the option data at the value pointer.
    - `value`: A pointer to the first byte of the option data, which is variable-length.
- **Description**: The `fd_pcapng_option_t` structure is used to represent a variable-length option within a PCAP Next Generation (PCAPNG) file format. Each option is identified by a type and has a size indicating the length of the data it holds. The `value` pointer points to the actual data of the option, which can vary in type and is not null-terminated if it is a string. This structure is essential for handling optional metadata in PCAPNG blocks, allowing for flexible and extensible data representation.


---
### fd\_pcapng\_block\_hdr
- **Type**: `struct`
- **Members**:
    - `block_type`: An unsigned integer representing the type of the block.
    - `block_sz`: An unsigned integer representing the size of the block.
- **Description**: The `fd_pcapng_block_hdr` structure is a packed data structure used to define the common header for blocks in the PCAP Next Generation (pcapng) file format. It contains two members: `block_type`, which specifies the type of block (e.g., Section Header Block, Interface Description Block), and `block_sz`, which indicates the total size of the block including its content. This structure is fundamental for parsing and handling different types of blocks within a pcapng file.


---
### fd\_pcapng\_block\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `block_type`: An unsigned integer representing the type of the block.
    - `block_sz`: An unsigned integer representing the size of the block in bytes.
- **Description**: The `fd_pcapng_block_hdr_t` is a packed structure that serves as a common header for various types of blocks in the PCAP Next Generation (PCAPNG) file format. It contains two fields: `block_type`, which identifies the type of block (e.g., Section Header Block, Interface Description Block), and `block_sz`, which specifies the total size of the block including the header. This structure is used as a base for more specific block types, ensuring a consistent format for block identification and size specification.


---
### fd\_pcapng\_shb
- **Type**: `struct`
- **Members**:
    - `block_type`: Specifies the type of block, set to FD_PCAPNG_BLOCK_TYPE_SHB.
    - `block_sz`: Indicates the size of the block, equal to the size of fd_pcapng_shb_t.
    - `byte_order_magic`: A magic number used to identify the byte order, set to FD_PCAPNG_BYTE_ORDER_MAGIC.
    - `version_major`: Major version number of the Section Header Block, set to 1.
    - `version_minor`: Minor version number of the Section Header Block, set to 0.
    - `section_sz`: Size of the section, set to ULONG_MAX indicating it is undefined.
- **Description**: The `fd_pcapng_shb` structure represents a Section Header Block (SHB) in the PCAP Next Generation (PCAPNG) file format. It is used to define the beginning of a section in a PCAPNG file, containing metadata about the file's byte order, version, and section size. The structure is packed to ensure no padding is added between its fields, which is crucial for maintaining the correct format when writing to or reading from a file. The fields include identifiers for block type and size, a magic number for byte order verification, version information, and an undefined section size.


---
### fd\_pcapng\_shb\_t
- **Type**: `struct`
- **Members**:
    - `block_type`: Specifies the block type, which is always FD_PCAPNG_BLOCK_TYPE_SHB for this structure.
    - `block_sz`: Indicates the size of the block, which is equal to the size of the fd_pcapng_shb_t structure.
    - `byte_order_magic`: A constant value used to identify the byte order of the data, set to FD_PCAPNG_BYTE_ORDER_MAGIC.
    - `version_major`: The major version number of the Section Header Block, set to 1.
    - `version_minor`: The minor version number of the Section Header Block, set to 0.
    - `section_sz`: Represents the size of the section, set to ULONG_MAX indicating it is undefined.
- **Description**: The fd_pcapng_shb_t structure represents a Section Header Block in the PCAP Next Generation (pcapng) file format. It is used to define the start of a section in a pcapng file, providing metadata about the section such as the byte order, version, and size. The structure includes fields for the block type, block size, byte order magic number, version numbers, and section size, which are essential for interpreting the data within the section.


---
### fd\_pcapng\_idb
- **Type**: `struct`
- **Members**:
    - `block_type`: Specifies the block type, which is always FD_PCAPNG_BLOCK_TYPE_IDB for this structure.
    - `block_sz`: Indicates the size of the block, which is equal to the size of the fd_pcapng_idb_t structure.
    - `link_type`: Defines the link type, which is set to FD_PCAPNG_LINKTYPE_ETHERNET.
    - `_pad_0a`: A padding field set to 0 to align the structure.
    - `snap_len`: Specifies the maximum packet payload size limit, with 0 indicating no limit.
- **Description**: The `fd_pcapng_idb` structure represents an Interface Description Block (IDB) in the PCAP Next Generation (pcapng) file format. It contains metadata about a network interface, including the block type, block size, link type, and a snap length that limits the size of captured packets. The structure is packed to ensure no padding is added by the compiler, and it includes a padding field to maintain alignment.


---
### fd\_pcapng\_idb\_t
- **Type**: `struct`
- **Members**:
    - `block_type`: Indicates the block type, specifically set to FD_PCAPNG_BLOCK_TYPE_IDB for Interface Description Block.
    - `block_sz`: Specifies the size of the block, equal to the size of the fd_pcapng_idb_t structure.
    - `link_type`: Defines the link type, typically set to FD_PCAPNG_LINKTYPE_ETHERNET.
    - `_pad_0a`: A padding field set to 0 to align the structure.
    - `snap_len`: Specifies the maximum packet payload size limit, with 0 indicating no limit.
- **Description**: The `fd_pcapng_idb_t` structure represents an Interface Description Block (IDB) in the PCAP Next Generation (pcapng) file format. It is used to describe the characteristics of a network interface on which packets are captured. The structure includes fields for the block type, block size, link type, and a padding field for alignment. Additionally, it contains a field for the snapshot length, which defines the maximum size of packet data that can be captured. This structure is crucial for interpreting packet data in pcapng files, as it provides context about the network interface used during capture.


---
### fd\_pcapng\_spb
- **Type**: `struct`
- **Members**:
    - `block_type`: Indicates the type of block, specifically FD_PCAPNG_BLOCK_TYPE_SPB for Simple Packet Block.
    - `block_sz`: Specifies the size of the block, which must be greater than or equal to the size of fd_pcapng_spb_t.
    - `orig_len`: Represents the original size of the packet in bytes.
- **Description**: The `fd_pcapng_spb` structure is a packed data structure used to represent a Simple Packet Block (SPB) in the PCAP Next Generation (pcapng) file format. It contains three fields: `block_type`, which identifies the block as a Simple Packet Block; `block_sz`, which indicates the size of the block and must be at least the size of the structure itself; and `orig_len`, which records the original size of the packet in bytes. This structure is used to store packet data in a serialized format for network packet capture and analysis.


---
### fd\_pcapng\_spb\_t
- **Type**: `struct`
- **Members**:
    - `block_type`: Indicates the block type, specifically for Simple Packet Block (SPB).
    - `block_sz`: Specifies the size of the block, which must be at least the size of the fd_pcapng_spb_t structure.
    - `orig_len`: Represents the original size of the packet in bytes.
- **Description**: The `fd_pcapng_spb_t` structure is a representation of a Simple Packet Block (SPB) in the PCAP Next Generation (pcapng) file format. It is used to store packet data with minimal metadata, primarily focusing on the original size of the packet. The structure includes a block type identifier, a block size to ensure the block is large enough to contain the necessary data, and the original length of the packet, which is crucial for understanding the packet's size before any potential truncation during capture.


---
### fd\_pcapng\_epb
- **Type**: `struct`
- **Members**:
    - `block_type`: Indicates the type of block, specifically the Enhanced Packet Block (EPB).
    - `block_sz`: Specifies the size of the block, which must be at least the size of the fd_pcapng_epb_t structure.
    - `if_idx`: Index of the related Interface Description Block (IDB) within the section.
    - `ts_hi`: The high 32 bits of the timestamp for the packet.
    - `ts_lo`: The low 32 bits of the timestamp for the packet.
    - `cap_len`: The size of the captured packet in bytes.
    - `orig_len`: The original size of the packet in bytes.
- **Description**: The `fd_pcapng_epb` structure represents an Enhanced Packet Block (EPB) in the PCAP Next Generation (pcapng) file format. It is used to store detailed information about a captured network packet, including its type, size, interface index, timestamp, and both captured and original lengths. This structure is packed to ensure no padding is added between its fields, which is crucial for accurate data representation in network packet capture files.


---
### fd\_pcapng\_epb\_t
- **Type**: `struct`
- **Members**:
    - `block_type`: Indicates the block type, specifically for Enhanced Packet Block (EPB).
    - `block_sz`: Specifies the size of the block, which must be at least the size of the fd_pcapng_epb_t structure.
    - `if_idx`: Index of the related Interface Description Block (IDB) within the section.
    - `ts_hi`: High 32 bits of the timestamp for the packet.
    - `ts_lo`: Low 32 bits of the timestamp for the packet.
    - `cap_len`: Size of the captured packet in bytes.
    - `orig_len`: Original size of the packet in bytes before any truncation.
- **Description**: The `fd_pcapng_epb_t` structure represents an Enhanced Packet Block (EPB) in the PCAP Next Generation (pcapng) file format. It is used to store detailed information about a captured network packet, including its type, size, interface index, timestamp, and both the captured and original lengths of the packet. This structure is crucial for accurately recording and analyzing network traffic, as it provides precise timing and size information for each packet captured.


---
### fd\_pcapng\_dsb
- **Type**: `struct`
- **Members**:
    - `block_type`: Indicates the type of block, specifically set to FD_PCAPNG_BLOCK_TYPE_DSB.
    - `block_sz`: Specifies the size of the block, which must be at least the size of the fd_pcapng_dsb_t structure.
    - `secret_type`: Denotes the type of secret, which corresponds to a predefined constant like FD_PCAPNG_SECRET_TYPE_*.
    - `secret_sz`: Represents the size in bytes of the secrets data contained within the block.
- **Description**: The `fd_pcapng_dsb` structure is a packed data structure used to represent a Decryption Secrets Block in the PCAP Next Generation (PCAPNG) file format. It contains metadata about the block, including its type, size, the type of secret it holds, and the size of the secret data. This structure is crucial for handling encrypted data within PCAPNG files, allowing for the storage and identification of decryption secrets necessary for interpreting encrypted packet data.


---
### fd\_pcapng\_dsb\_t
- **Type**: `struct`
- **Members**:
    - `block_type`: This field indicates the type of the block, which should be FD_PCAPNG_BLOCK_TYPE_DSB for a Decryption Secrets Block.
    - `block_sz`: This field specifies the size of the block, which must be greater than or equal to the size of the fd_pcapng_dsb_t structure.
    - `secret_type`: This field indicates the type of secret, which should match one of the predefined secret types such as FD_PCAPNG_SECRET_TYPE_TLS.
    - `secret_sz`: This field specifies the size in bytes of the secret data contained within the block.
- **Description**: The fd_pcapng_dsb_t structure represents a Decryption Secrets Block in the PCAP Next Generation (PCAPNG) file format. It is used to store decryption secrets necessary for interpreting encrypted packet data. The structure includes fields for identifying the block type, the size of the block, the type of secret, and the size of the secret data. This allows for the secure storage and retrieval of decryption keys or other sensitive information needed to decrypt packet data within a PCAPNG file.


---
### fd\_pcapng\_idb\_desc
- **Type**: `struct`
- **Members**:
    - `link_type`: Specifies the type of link layer for the interface.
    - `opts`: Holds options related to the interface description block.
- **Description**: The `fd_pcapng_idb_desc` structure is used to describe an interface in a PCAP Next Generation (pcapng) file format. It contains a `link_type` field that specifies the type of link layer used by the interface, and an `opts` field that holds various options related to the interface description block, allowing for detailed configuration and description of network interfaces in pcapng files.


---
### fd\_pcapng\_idb\_desc\_t
- **Type**: `struct`
- **Members**:
    - `link_type`: Specifies the type of link layer for the interface.
    - `opts`: Holds the options associated with the interface description block.
- **Description**: The `fd_pcapng_idb_desc_t` structure is used to describe an interface in a PCAP Next Generation (pcapng) file format. It contains a `link_type` field that specifies the type of link layer used by the interface, and an `opts` field that holds various options related to the interface, encapsulated in a `fd_pcapng_idb_opts_t` type. This structure is part of the internal representation of pcapng data, facilitating the parsing and handling of interface description blocks within the pcapng file.


---
### fd\_pcapng\_iter
- **Type**: `struct`
- **Members**:
    - `stream`: A pointer to the stream being iterated over.
    - `error`: An integer representing the error state of the iterator.
    - `iface`: An array of interface description blocks with a fixed size of 16.
    - `iface_cnt`: An unsigned integer representing the count of interfaces in the array.
- **Description**: The `fd_pcapng_iter` structure is designed to facilitate iteration over a PCAP Next Generation (PCAPNG) stream. It maintains a pointer to the stream, an error state, and an array of interface description blocks (`iface`) with a maximum count of 16, tracked by `iface_cnt`. This structure is aligned according to `FD_PCAPNG_ITER_ALIGN` to ensure proper memory alignment for efficient access.


