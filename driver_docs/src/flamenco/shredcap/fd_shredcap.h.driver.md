# Purpose
The provided C header file, `fdshredcap.h`, defines the structure and functionality for handling a capture format known as "fd_shredcap" for Solana ledgers. This format is designed to store all shreds (data fragments) for a given block together, facilitating testing and replay of blockchain data. The file outlines the structure of the capture format, including the manifest and capture files, which are used to organize and access the data efficiently. The manifest file provides a quick lookup for file ranges, while the capture files store the actual data, organized by slots and shreds. The header file also defines constants, data structures, and function prototypes necessary for managing these files, such as ingesting data from a RocksDB database, seeking specific data ranges, verifying file integrity, and populating a blockstore with data from the capture files.

The code provides a specialized functionality focused on the storage and retrieval of blockchain data in a structured format. It includes detailed definitions for various components of the fd_shredcap format, such as manifest headers, file headers, slot headers, and shred headers, each with specific fields and alignment requirements. The header file also declares several functions that operate on these data structures, enabling tasks like data ingestion, range seeking, verification, and blockstore population. This file is intended to be included in other C source files, providing a public API for interacting with the fd_shredcap format, and it is crucial for applications that need to handle Solana ledger data in a structured and efficient manner.
# Imports and Dependencies

---
- `unistd.h`
- `sys/types.h`
- `sys/stat.h`
- `fcntl.h`
- `../../flamenco/runtime/fd_blockstore.h`


# Data Structures

---
### fd\_shredcap\_manifest\_cap\_V1
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the manifest structure.
    - `version`: Specifies the version of the manifest structure.
    - `num_files`: Indicates the number of files in the manifest.
    - `start_slot`: The starting slot number for the range covered by the manifest.
    - `end_slot`: The ending slot number for the range covered by the manifest.
- **Description**: The `fd_shredcap_manifest_cap_V1` structure is a packed and aligned data structure used to define the header of a manifest file in the fd_shredcap format, which is designed for capturing Solana ledger data. This structure includes fields for a magic number to identify the structure, a version number to indicate the format version, the number of files included in the manifest, and the start and end slots that define the range of data covered by the manifest. This structure is crucial for organizing and accessing the captured data efficiently.


---
### fd\_shredcap\_manifest\_hdr\_t
- **Type**: `typedef struct fd_shredcap_manifest_cap_V1 fd_shredcap_manifest_hdr_t;`
- **Members**:
    - `magic`: A unique identifier for the manifest header.
    - `version`: The version number of the manifest format.
    - `num_files`: The number of files described in the manifest.
    - `start_slot`: The starting slot number for the range covered by the manifest.
    - `end_slot`: The ending slot number for the range covered by the manifest.
- **Description**: The `fd_shredcap_manifest_hdr_t` is a typedef for a structure that represents the header of a manifest in the fd_shredcap capture format. This header contains metadata about the capture, including a magic number for identification, the version of the format, the number of files included in the manifest, and the range of slots (start and end) that the manifest covers. This structure is crucial for organizing and accessing the captured data efficiently.


---
### fd\_shredcap\_manifest\_ftr\_t
- **Type**: `typedef struct fd_shredcap_manifest_cap_V1 fd_shredcap_manifest_ftr_t;`
- **Members**:
    - `magic`: A unique identifier for the manifest footer structure.
    - `version`: The version number of the manifest footer structure.
    - `num_files`: The number of files described in the manifest.
    - `start_slot`: The starting slot number for the range covered by the manifest.
    - `end_slot`: The ending slot number for the range covered by the manifest.
- **Description**: The `fd_shredcap_manifest_ftr_t` is a typedef for the `fd_shredcap_manifest_cap_V1` structure, which represents the footer of a manifest in the fd_shredcap capture format. This structure is used to store metadata about the capture, including a magic number for identification, the version of the format, the number of files included in the manifest, and the range of slots (start and end) that the manifest covers. It is aligned to a 16-byte boundary for efficient memory access.


---
### fd\_shredcap\_manifest\_entry\_V1
- **Type**: `struct`
- **Members**:
    - `start_slot`: The starting slot number for the file range.
    - `end_slot`: The ending slot number for the file range.
    - `path`: A character array representing the relative path to the file.
- **Description**: The `fd_shredcap_manifest_entry_V1` structure is part of the fd_shredcap capture format used for Solana ledgers. It represents an entry in the manifest file, which provides a fast lookup for file ranges. Each entry contains the start and end slot numbers that define the range of slots covered by a particular file, as well as the relative path to the file. This structure is packed and aligned according to the `FD_SHREDCAP_ALIGN` specification to ensure efficient storage and access.


---
### fd\_shredcap\_manifest\_entry\_t
- **Type**: `typedef struct fd_shredcap_manifest_entry_V1 fd_shredcap_manifest_entry_t;`
- **Members**:
    - `start_slot`: The starting slot number for the file range.
    - `end_slot`: The ending slot number for the file range.
    - `path`: A character array representing the relative path to the file.
- **Description**: The `fd_shredcap_manifest_entry_t` is a data structure used in the fd_shredcap system to represent an entry in the manifest file. Each entry contains information about a specific file's slot range, including the starting and ending slots, and the relative path to the file. This structure is crucial for efficiently locating and accessing specific file ranges within the fd_shredcap capture format, which is used for storing and replaying Solana ledger data.


---
### fd\_shredcap\_file\_cap\_V1
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the file format, used to verify the integrity and type of the file.
    - `version`: Indicates the version of the file format, allowing for compatibility checks.
    - `start_slot`: The starting slot number for the range of data contained in the file.
    - `end_slot`: The ending slot number for the range of data contained in the file.
    - `num_blocks`: The total number of blocks contained within the specified slot range in the file.
- **Description**: The `fd_shredcap_file_cap_V1` structure is a packed and aligned data structure used to define the header and footer of a capture file in the fd_shredcap format, which is designed for storing Solana ledger shreds. It contains metadata about the file, including a magic number for format identification, a version number for compatibility, and information about the range of slots and the number of blocks included in the file. This structure ensures that the file is correctly interpreted and processed within the fd_shredcap system.


---
### fd\_shredcap\_file\_hdr\_t
- **Type**: `typedef struct fd_shredcap_file_cap_V1 fd_shredcap_file_hdr_t;`
- **Members**:
    - `magic`: A unique identifier for the file header format.
    - `version`: Specifies the version of the file header format.
    - `start_slot`: Indicates the starting slot number for the data in the file.
    - `end_slot`: Indicates the ending slot number for the data in the file.
    - `num_blocks`: Represents the number of blocks contained within the file.
- **Description**: The `fd_shredcap_file_hdr_t` is a data structure used as a header for files in the fd_shredcap capture format, which is designed for storing Solana ledger shreds. It contains metadata such as a magic number for identification, a version number, and information about the range of slots and the number of blocks included in the file. This structure ensures that each file in the capture format is properly identified and can be processed correctly.


---
### fd\_shredcap\_file\_ftr\_t
- **Type**: `typedef struct fd_shredcap_file_cap_V1 fd_shredcap_file_ftr_t;`
- **Members**:
    - `magic`: A unique identifier for the file footer structure.
    - `version`: Indicates the version of the file footer structure.
    - `start_slot`: The starting slot number for the data in the file.
    - `end_slot`: The ending slot number for the data in the file.
    - `num_blocks`: The number of blocks contained within the file.
- **Description**: The `fd_shredcap_file_ftr_t` is a typedef for the `fd_shredcap_file_cap_V1` structure, which represents the footer of a capture file in the fd_shredcap format. This structure is used to store metadata about the file, including a magic number for identification, the version of the structure, and the range of slots (start and end) that the file covers. Additionally, it records the number of blocks contained within the file, providing essential information for managing and accessing the captured data.


---
### fd\_shredcap\_slot\_hdr\_V1
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the slot header structure.
    - `version`: Indicates the version of the slot header structure.
    - `payload_sz`: Specifies the size of the payload associated with the slot.
    - `slot`: Represents the slot number for which this header is relevant.
    - `consumed`: Tracks the number of shreds that have been consumed.
    - `received`: Tracks the number of shreds that have been received.
    - `first_shred_timestamp`: Records the timestamp of the first shred in the slot.
    - `last_index`: Indicates the last index of the shred in the slot.
    - `parent_slot`: References the parent slot number.
- **Description**: The `fd_shredcap_slot_hdr_V1` structure is a packed and aligned data structure used in the fd_shredcap capture format for Solana ledgers. It serves as a header for a slot, containing metadata such as the slot number, payload size, and timestamps related to the shreds within the slot. This structure is crucial for managing and organizing the data associated with each slot in the capture process, ensuring efficient storage and retrieval of ledger information.


---
### fd\_shredcap\_slot\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the slot header structure.
    - `version`: Indicates the version of the slot header structure.
    - `payload_sz`: Specifies the size of the payload associated with the slot.
    - `slot`: Represents the slot number for which this header is relevant.
    - `consumed`: Tracks the number of shreds consumed in this slot.
    - `received`: Tracks the number of shreds received in this slot.
    - `first_shred_timestamp`: Records the timestamp of the first shred in this slot.
    - `last_index`: Indicates the last index of the shred in this slot.
    - `parent_slot`: Refers to the parent slot number of this slot.
- **Description**: The `fd_shredcap_slot_hdr_t` structure is a packed and aligned data structure used in the fd_shredcap capture format for Solana ledgers. It serves as a header for each slot, containing metadata such as the slot number, payload size, and various counters for shreds consumed and received. Additionally, it includes timestamps and indices to facilitate the organization and retrieval of shreds within a slot, ensuring efficient data management and replay capabilities.


---
### fd\_shredcap\_slot\_ftr\_V1
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, used for validation or versioning.
    - `payload_sz`: The size of the payload associated with the slot footer.
- **Description**: The `fd_shredcap_slot_ftr_V1` structure is a packed and aligned data structure used in the fd_shredcap capture format for Solana ledgers. It serves as a footer for a slot, containing metadata such as a magic number for identification and the size of the payload, ensuring data integrity and facilitating the processing of slot data within the capture files.


---
### fd\_shredcap\_slot\_ftr\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the slot footer structure.
    - `payload_sz`: The size of the payload associated with the slot.
- **Description**: The `fd_shredcap_slot_ftr_t` structure is a packed and aligned data structure used in the fd_shredcap capture format to represent the footer of a slot. It contains metadata about the slot, specifically a magic number for identification and the size of the payload, ensuring the integrity and completeness of the data captured for a specific slot in the Solana ledger.


---
### fd\_shredcap\_shred\_hdr\_V1
- **Type**: `struct`
- **Members**:
    - `hdr_sz`: The size of the header, equal to FD_SHREDCAP_SHRED_HDR_FOOTPRINT.
    - `shred_sz`: The size of the shred.
    - `shred_boundary_sz`: The size of the padded shred without the header.
- **Description**: The `fd_shredcap_shred_hdr_V1` structure is a packed and aligned data structure used in the fd_shredcap capture format for Solana ledgers. It defines the header for a shred, which is a unit of data storage in the ledger. The structure includes fields for the header size, the size of the shred, and the size of the padded shred without the header. This structure is followed by a dynamically sized shred, allowing for flexible data storage.


---
### fd\_shredcap\_shred\_hdr\_t
- **Type**: `typedef struct fd_shredcap_shred_hdr_V1 fd_shredcap_shred_hdr_t;`
- **Members**:
    - `hdr_sz`: The size of the shred header, equal to FD_SHREDCAP_SHRED_HDR_FOOTPRINT.
    - `shred_sz`: The size of the shred.
    - `shred_boundary_sz`: The size of the padded shred without the header.
- **Description**: The `fd_shredcap_shred_hdr_t` structure is a packed and aligned data structure used in the fd_shredcap capture format for Solana ledgers. It defines the header for a shred, which includes the size of the header, the size of the shred, and the size of the padded shred without the header. This structure is followed by a dynamically sized shred, allowing for flexible storage of shred data within the capture format.


---
### fd\_shredcap\_bank\_hash\_cap\_V1
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, used for validation.
    - `version`: Indicates the version of the structure format.
    - `start_slot`: The starting slot number for the range of blocks.
    - `end_slot`: The ending slot number for the range of blocks.
    - `num_blocks`: The total number of blocks within the specified slot range.
- **Description**: The `fd_shredcap_bank_hash_cap_V1` structure is a packed and aligned data structure used in the fd_shredcap system to represent metadata about a range of blocks in a Solana ledger. It includes fields for a magic number to ensure data integrity, a version number to track the format version, and slot range information to specify the start and end of the block range. Additionally, it records the number of blocks within this range, facilitating efficient data management and retrieval in the context of bank hash operations.


---
### fd\_shredcap\_bank\_hash\_hdr\_t
- **Type**: `typedef struct fd_shredcap_bank_hash_cap_V1 fd_shredcap_bank_hash_hdr_t;`
- **Members**:
    - `magic`: A unique identifier for the bank hash header structure.
    - `version`: Indicates the version of the bank hash header structure.
    - `start_slot`: The starting slot number for the bank hash range.
    - `end_slot`: The ending slot number for the bank hash range.
    - `num_blocks`: The number of blocks included in the bank hash range.
- **Description**: The `fd_shredcap_bank_hash_hdr_t` is a structure used in the fd_shredcap system to represent the header of a bank hash file. It contains metadata about the bank hash, including a magic number for identification, a version number, and the range of slots (start and end) that the bank hash covers. Additionally, it includes the number of blocks within this range, which is crucial for managing and verifying the integrity of the bank hash data during operations such as replay and testing of Solana ledgers.


---
### fd\_shredcap\_bank\_hash\_ftr\_t
- **Type**: `typedef struct fd_shredcap_bank_hash_cap_V1 fd_shredcap_bank_hash_ftr_t;`
- **Members**:
    - `magic`: A unique identifier for the bank hash structure.
    - `version`: Indicates the version of the bank hash structure.
    - `start_slot`: The starting slot number for the bank hash.
    - `end_slot`: The ending slot number for the bank hash.
    - `num_blocks`: The number of blocks included in the bank hash.
- **Description**: The `fd_shredcap_bank_hash_ftr_t` is a typedef for the `fd_shredcap_bank_hash_cap_V1` structure, which is part of the fd_shredcap system used for capturing Solana ledger data. This structure is specifically used to store metadata about bank hashes, including a magic number for identification, a version number, and details about the range of slots and number of blocks it covers. It is aligned to 16 bytes and packed to ensure efficient storage and access.


---
### fd\_shredcap\_bank\_hash\_entry\_V1
- **Type**: `struct`
- **Members**:
    - `slot`: An unsigned long integer representing the slot number.
    - `bank_hash`: A hash value associated with the bank, represented by the type fd_hash_t.
- **Description**: The `fd_shredcap_bank_hash_entry_V1` structure is a compact and aligned data structure used to store information about a specific slot and its associated bank hash within the fd_shredcap system. It is part of the bank hash component of the fd_shredcap format, which is used for capturing and replaying Solana ledger data. The structure is designed to be packed and aligned according to the `FD_SHREDCAP_ALIGN` specification, ensuring efficient storage and access.


---
### fd\_shredcap\_bank\_hash\_entry\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the bank hash entry.
    - `bank_hash`: Stores the hash value for the bank at the specified slot.
- **Description**: The `fd_shredcap_bank_hash_entry_t` is a data structure used to represent an entry in the bank hash file within the fd_shredcap capture format. It consists of a slot number and a corresponding bank hash, which are used to verify and manage the integrity of the bank data during replay operations. This structure is part of the broader fd_shredcap system, which is designed to capture and replay Solana ledger data efficiently.


# Function Declarations (Public API)

---
### fd\_shredcap\_ingest\_rocksdb\_to\_capture<!-- {{#callable_declaration:fd_shredcap_ingest_rocksdb_to_capture}} -->
Ingests data from a RocksDB directory and outputs it to a shredcap capture directory.
- **Description**: This function is used to convert data stored in a RocksDB directory into a shredcap capture format, which is stored in a specified capture directory. It processes data within a specified slot range and outputs files that are capped at a maximum size. The function must be called with valid directory paths and a valid slot range, where the end slot is greater than or equal to the start slot. It creates necessary directories and files, including a manifest and bank hash file, and handles errors related to file operations and data processing.
- **Inputs**:
    - `rocksdb_dir`: The path to the RocksDB directory containing the data to be ingested. Must be a valid directory path. The caller retains ownership.
    - `capture_dir`: The path to the directory where the shredcap capture files will be stored. Must be a valid directory path. The caller retains ownership.
    - `max_file_sz`: The maximum size for each output file in bytes. If less than the minimum required size for a block, it will be adjusted to fit at least one block.
    - `start_slot`: The starting slot number for the data to be ingested. Must be less than or equal to end_slot.
    - `end_slot`: The ending slot number for the data to be ingested. Must be greater than or equal to start_slot.
- **Output**: None
- **See also**: [`fd_shredcap_ingest_rocksdb_to_capture`](fd_shredcap.c.driver.md#fd_shredcap_ingest_rocksdb_to_capture)  (Implementation)


---
### fd\_shredcap\_manifest\_seek\_range<!-- {{#callable_declaration:fd_shredcap_manifest_seek_range}} -->
Iterate through the manifest to determine file indices for a given slot range.
- **Description**: This function is used to find the start and end file indices in a capture's manifest file that correspond to a specified range of slots. It should be called when you need to identify which files in a capture directory contain data for a given slot range. The function opens the manifest file in the specified capture directory, reads its header, and performs a binary search to locate the files that cover the specified slot range. It requires valid slot numbers within the range specified by the manifest header and will log errors if the slots are out of bounds or if file operations fail.
- **Inputs**:
    - `capture_dir`: The directory path where the capture's manifest file is located. Must be a valid directory path.
    - `manifest_buf`: A buffer to store manifest data read from the file. Must be large enough to hold the manifest header and entry data.
    - `start_slot`: The starting slot number of the range to search for. Must be within the range specified by the manifest header.
    - `end_slot`: The ending slot number of the range to search for. Must be within the range specified by the manifest header.
    - `start_file_idx`: A pointer to store the index of the first file covering the start_slot. Must not be null.
    - `end_file_idx`: A pointer to store the index of the last file covering the end_slot. Must not be null.
    - `manifest_fd`: A pointer to an integer where the file descriptor of the opened manifest file will be stored. Must not be null.
- **Output**: None
- **See also**: [`fd_shredcap_manifest_seek_range`](fd_shredcap.c.driver.md#fd_shredcap_manifest_seek_range)  (Implementation)


---
### fd\_shredcap\_bank\_hash\_seek\_first<!-- {{#callable_declaration:fd_shredcap_bank_hash_seek_first}} -->
Finds the first bank hash entry within a specified slot range.
- **Description**: This function searches through a bank hash file located in the specified capture directory to find the first bank hash entry that falls within the given slot range [start_slot, end_slot]. It opens the bank hash file for reading and performs a binary search to efficiently locate the desired entry. The function must be called with valid slot range parameters, and the capture directory must contain a valid bank hash file. It returns the index of the first slot within the range and a file descriptor for the opened bank hash file. The caller is responsible for ensuring the capture directory is correctly set up and for handling the file descriptor after use.
- **Inputs**:
    - `capture_dir`: The directory path where the bank hash file is located. Must not be null and should point to a valid directory containing the bank hash file.
    - `bank_hash_buf`: A buffer to store the bank hash data read from the file. Must be large enough to hold at least one bank hash entry.
    - `start_slot`: The starting slot of the range to search for. Must be within the valid range of slots in the bank hash file.
    - `end_slot`: The ending slot of the range to search for. Must be within the valid range of slots in the bank hash file.
    - `first_slot_idx`: A pointer to store the index of the first slot found within the specified range. Must not be null.
    - `bank_hash_fd`: A pointer to an integer where the file descriptor of the opened bank hash file will be stored. Must not be null.
- **Output**: None
- **See also**: [`fd_shredcap_bank_hash_seek_first`](fd_shredcap.c.driver.md#fd_shredcap_bank_hash_seek_first)  (Implementation)


---
### fd\_shredcap\_verify<!-- {{#callable_declaration:fd_shredcap_verify}} -->
Verify the integrity of manifest, capture, and bank hash files in a shredcap capture directory.
- **Description**: Use this function to ensure that the files within a specified capture directory conform to the expected shredcap format and contain valid data. This function should be called when you need to verify the integrity of the capture files, manifest, and bank hash files, either as a standalone operation or as part of a larger validation process. It checks that the file format specifications are adhered to and that the slots within the files are valid. The function assumes that the capture directory and blockstore have been properly initialized and that the manifest and bank hash files exist within the directory.
- **Inputs**:
    - `capture_dir`: A string representing the path to the directory containing the shredcap capture files. Must not be null and should point to a valid directory containing the necessary files.
    - `blockstore`: A pointer to an fd_blockstore_t structure. This parameter is used to verify the capture files against the blockstore. Must not be null, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_shredcap_verify`](fd_shredcap.c.driver.md#fd_shredcap_verify)  (Implementation)


---
### fd\_shredcap\_populate\_blockstore<!-- {{#callable_declaration:fd_shredcap_populate_blockstore}} -->
Populate a blockstore with blocks from a specified range in a shredcap capture.
- **Description**: This function is used to populate a blockstore with blocks from a specified range of slots within a shredcap capture directory. It should be called when you need to load blocks from a capture into a blockstore for processing or analysis. The function requires a valid capture directory and a blockstore to populate. The start_slot must be less than or equal to the end_slot, otherwise, an error is logged. This function reads from the manifest and bank hash files in the capture directory to determine the relevant files and slots to process.
- **Inputs**:
    - `capture_dir`: A string representing the path to the directory containing the shredcap capture files. Must not be null.
    - `blockstore`: A pointer to an fd_blockstore_t structure where the blocks will be populated. Must not be null and should be properly initialized before calling this function.
    - `start_slot`: An unsigned long representing the starting slot number of the range to populate. Must be less than or equal to end_slot.
    - `end_slot`: An unsigned long representing the ending slot number of the range to populate. Must be greater than or equal to start_slot.
- **Output**: None
- **See also**: [`fd_shredcap_populate_blockstore`](fd_shredcap.c.driver.md#fd_shredcap_populate_blockstore)  (Implementation)


