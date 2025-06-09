# Purpose
This document is a technical specification for handling Solana blockchain snapshots, detailing the format and structure of snapshot files. These snapshots encapsulate the "bank" state and account data, crucial for restoring the blockchain's state at a specific point in time. The file format is a Zstandard compressed TAR stream, containing a version file, a manifest file, and multiple account vector files. The manifest file holds essential metadata, including the bank state and consensus information, while account vector files store account data, potentially with multiple revisions. The document outlines various implementation details and pitfalls, emphasizing the importance of correctly handling account revisions and potential data anomalies. This specification is vital for developers working with Solana's blockchain infrastructure, ensuring accurate snapshot loading and restoration processes.
# Content Summary
The document provides a comprehensive overview of the snapshot handling mechanism in the Solana blockchain, specifically focusing on the format and structure of snapshot files, as well as the intricacies involved in loading and managing these snapshots. 

### Snapshot File Format

Snapshots in Solana are serialized representations of the "bank" state and account data, compressed using Zstandard and stored in a TAR archive. The format, as of version 1.2.0, mandates that the TAR stream only includes regular files with path lengths not exceeding 99 characters. While a snapshot can technically be a single large Zstandard frame, it is recommended to use multiple frames, each up to 100 MB, to facilitate multi-threaded decompression.

### Key Components

1. **Version File**: The first file in the archive, located at the path `version`, contains the ASCII string `1.2.0`, indicating the snapshot version.

2. **Manifest File**: Found at `snapshots/<slot>/<slot>`, this file is a large Bincode blob (~300 MB) that includes the bank state, consensus information, and details about subsequent account vec files. It is crucial for understanding the structure and content of the snapshot.

3. **Account Vec Files**: These files, located at `accounts/<slot>.<id>`, contain vectors of accounts. Each account may appear in multiple vecs, but with different slot numbers. The highest slot number determines the final state of an account. The files may contain trailing data beyond the specified offset in the manifest.

### Implementation Details

- **Solana Labs**: Typically produces account vec files with multiple revisions for different slots, and as of version 1.16, may include trailing garbage data.
- **Firedancer**: Includes each account only once and sets the slot number to `0`.

### Pitfalls and Edge Cases

The document outlines several potential pitfalls when loading snapshots, such as handling different revisions of the same account, managing deleted accounts, and dealing with trailing garbage data. It emphasizes the importance of rejecting snapshots with invalid slot numbers and highlights the need for careful memory management due to the unbounded nature of the snapshot manifest.

### Snapshot Operations

- **Restore**: Currently, snapshot loading is single-threaded in Firedancer, which supports snapshots from both Solana Labs and Firedancer.
- **Create**: Firedancer does not yet support snapshot creation.

Overall, the document serves as a detailed guide for developers working with Solana snapshots, providing essential information on file structure, potential issues, and implementation specifics to ensure correct handling and processing of snapshot data.
