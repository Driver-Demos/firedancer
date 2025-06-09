# Purpose
This Lua script is a Wireshark plugin designed to dissect and analyze network packets related to Firedancer Tango messages. The primary purpose of this file is to define a custom protocol dissector for Wireshark, which allows users to inspect the details of Tango Frag messages and related data structures within the Wireshark interface. The script sets up the plugin information, including version, author, and license, and provides installation instructions for integrating the plugin into Wireshark.

The script defines several custom protocols and fields, such as `fd_tango`, `fd_txn_t`, `fd_poh_shred`, `fd_shred34_t`, and `fd_became_leader_t`, each with specific fields that represent different aspects of the network data being analyzed. These fields include sequence numbers, timestamps, control flags, and various other data points relevant to the Firedancer Tango protocol. The dissector functions for each protocol parse the packet data and add the parsed information to the Wireshark packet tree, allowing users to view detailed information about each packet.

Additionally, the script includes logic to handle different types of link names and their corresponding dissectors, such as `eth_withoutfcs`, `solana.tpu.udp`, and others. This allows the plugin to correctly interpret and display the contents of the packets based on their specific protocol and structure. The script also registers the custom dissector with a specific UDP port, enabling Wireshark to automatically apply the dissector to packets received on that port. Overall, this file provides a comprehensive set of tools for analyzing Firedancer Tango messages within Wireshark, enhancing the user's ability to troubleshoot and understand network traffic related to this protocol.
# Imports and Dependencies

---
- `Proto`
- `ProtoField`
- `Dissector`
- `DissectorTable`
- `NSTime`


# Data Structures

---
### tango
- **Type**: `Proto`
- **Members**:
    - `tango_seq`: Represents the sequence number of the Tango message.
    - `tango_sig`: Represents the signature of the Tango message.
    - `tango_chunk`: Represents the chunk of the Tango message.
    - `tango_sz`: Represents the size of the Tango message.
    - `tango_ctl`: Represents the control field of the Tango message.
    - `tango_ctl_som`: Indicates the start-of-message in the control field.
    - `tango_ctl_eom`: Indicates the end-of-message in the control field.
    - `tango_ctl_err`: Indicates an error in the control field.
    - `tango_ctl_orig`: Indicates the origin in the control field.
    - `tango_tsorig`: Represents the origin timestamp of the Tango message.
    - `tango_tspub`: Represents the publish timestamp of the Tango message.
    - `tango_link`: Represents the link hash of the Tango message.
    - `tango_link_name`: Represents the link name of the Tango message.
    - `tango_contents`: Represents the DCache contents of the Tango message.
    - `tpu_payload_sz`: Represents the payload size in the TPU context.
    - `tpu_txn`: Represents the transaction in the TPU context.
    - `tpu_requested_cus`: Represents the requested compute units in the TPU context.
    - `tpu_executed_cus`: Represents the executed compute units in the TPU context.
    - `tpu_flags`: Represents the flags in the TPU context.
- **Description**: The `tango` data structure is a protocol definition for dissecting Tango Frag messages in Wireshark. It includes various fields that represent different components of a Tango message, such as sequence number, signature, chunk, size, control information, timestamps, link hash, and contents. Additionally, it includes fields specific to the TPU context, such as payload size, transaction, requested and executed compute units, and flags. This structure is used to parse and display detailed information about Tango messages within the Wireshark network protocol analyzer.


---
### p\_fd\_txn
- **Type**: `Proto`
- **Members**:
    - `transaction_version`: Represents the version of the transaction.
    - `signature_cnt`: Indicates the number of signatures in the transaction.
    - `signature_off`: Specifies the offset for the signature.
    - `message_off`: Specifies the offset for the message.
    - `readonly_signed_cnt`: Counts the number of readonly signed accounts.
    - `readonly_unsigned_cnt`: Counts the number of readonly unsigned accounts.
    - `acct_addr_cnt`: Indicates the count of account addresses.
    - `acct_addr_off`: Specifies the offset for account addresses.
    - `recent_blockhash_off`: Specifies the offset for the recent blockhash.
    - `addr_table_lookup_cnt`: Counts the number of address table lookups.
    - `addr_table_adtl_writable_cnt`: Counts additional writable addresses in the table.
    - `addr_table_adtl_cnt`: Counts additional addresses in the table.
    - `instr_cnt`: Indicates the number of instructions in the transaction.
    - `instrs`: Represents the instructions in the transaction.
    - `instr`: Represents a single instruction in the transaction.
    - `program_id`: Index of the program ID for the instruction.
    - `acct_cnt`: Counts the number of accounts in the instruction.
    - `data_sz`: Specifies the size of the data in the instruction.
    - `acct_off`: Specifies the offset for accounts in the instruction.
    - `data_off`: Specifies the offset for data in the instruction.
    - `alts`: Represents the address tables in the transaction.
    - `alt`: Represents a single address table.
    - `addr_off`: Specifies the offset for addresses in the table.
    - `writable_cnt`: Counts the number of writable addresses in the table.
    - `readonly_cnt`: Counts the number of readonly addresses in the table.
    - `writable_off`: Specifies the offset for writable addresses in the table.
    - `readonly_off`: Specifies the offset for readonly addresses in the table.
- **Description**: The `p_fd_txn` data structure is a protocol definition for dissecting FD Transaction Structs in Wireshark. It includes fields for transaction metadata such as version, signature count, and offsets for various components like signatures, messages, and account addresses. The structure also defines fields for instructions and address tables, allowing detailed parsing of transaction data. This protocol is used to analyze and display transaction details in network packets, particularly for the Firedancer Tango messages.


---
### poh\_shred
- **Type**: `Proto`
- **Members**:
    - `f_parent_offset`: Represents the parent offset as a 64-bit unsigned integer.
    - `f_reference_tick`: Represents the reference tick as a 64-bit unsigned integer.
    - `f_block_complete`: Indicates if the block is complete as a 32-bit integer.
    - `f_hashcnt_delta`: Represents the hash count delta as a 64-bit unsigned integer.
    - `f_hash`: Stores the hash as a byte array.
    - `f_txn_cnt`: Represents the transaction count as a 64-bit unsigned integer.
    - `f_txns`: Holds the transactions as a non-specific field.
    - `f_slot_start_ns`: Represents the slot start time in nanoseconds as a 64-bit integer.
    - `f_bank_ptr`: Represents the bank pointer as a 64-bit unsigned integer in hexadecimal format.
- **Description**: The `poh_shred` data structure is a protocol definition for handling FD PoH to Shred messages within a network protocol analyzer like Wireshark. It defines several fields that capture various aspects of the message, such as parent offset, reference tick, block completion status, hash count delta, and transaction details. The structure is used to dissect and interpret the contents of a buffer, extracting relevant information for analysis. It is part of a larger set of protocols designed to handle different message types in the Firedancer Tango system.


---
### fd\_shred34
- **Type**: `Protocol`
- **Members**:
    - `f_shred_cnt`: Represents the count of shreds.
    - `f_est_txn_cnt`: Indicates the estimated transaction count.
    - `f_stride`: Defines the stride value for processing shreds.
    - `f_offset`: Specifies the offset value for shreds.
    - `f_shred_sz`: Denotes the size of each shred.
    - `f_shred_payload`: Contains the payload data of the shred.
- **Description**: The `fd_shred34` is a protocol data structure used in the context of Firedancer's Wireshark plugin to handle and dissect 'Shred to Store' messages. It defines fields related to the processing of shreds, including their count, estimated transaction count, stride, offset, and size. The protocol is designed to facilitate the analysis of network traffic by breaking down the shred payloads and processing them using a specified dissector, which in this case is the 'solana.shreds' dissector. This structure is crucial for understanding the data flow and transactions within the Solana network as captured by the Wireshark plugin.


---
### fd\_became\_leader
- **Type**: `Proto`
- **Members**:
    - `f_slot_start`: Represents the start time of the slot in UTC.
    - `f_slot_end`: Represents the end time of the slot in UTC.
    - `f_bank_ptr`: A pointer to the bank associated with the slot.
    - `f_max_microblocks_in_slot`: Indicates the maximum number of microblocks allowed in a slot.
    - `f_ticks_per_slot`: Specifies the number of ticks per slot.
- **Description**: The `fd_became_leader` data structure is a protocol definition for handling messages related to the transition of a node becoming a leader in a distributed system. It includes fields for tracking the start and end times of a slot, a bank pointer, and parameters for microblock and tick management within the slot. This structure is used in network packet dissection to interpret and display relevant information about leadership transitions in the Firedancer protocol.


# Functions

---
### tango\.dissector
The `tango.dissector` function is a Wireshark Lua dissector for parsing and displaying Firedancer Tango protocol messages.
- **Inputs**:
    - `tvb`: A Tvb object representing the buffer of packet data to be dissected.
    - `pinfo`: A Pinfo object containing information about the packet being dissected.
    - `tree`: A TreeItem object representing the root of the protocol tree to which dissected fields should be added.
- **Control Flow**:
    - The function begins by adding a subtree to the protocol tree for the Tango protocol.
    - It checks the length of the packet and returns immediately if the packet length is zero.
    - The function extracts the link hash from the last 4 bytes of the packet and determines the link name using a predefined hash-to-name mapping.
    - It adds the link hash and name to the subtree and proceeds to add various fields such as sequence number, signature, chunk, size, control, origin timestamp, and publish timestamp to the subtree.
    - The function extracts the dcache contents from the packet and adds it to the subtree.
    - Based on the link name, it selects an appropriate dissector to further dissect the dcache contents and calls the dissector with the relevant data.
- **Output**: The function does not return a value; instead, it populates the protocol tree with dissected fields and potentially calls other dissectors to handle specific parts of the packet data.


---
### p\_fd\_txn\.dissector
The `p_fd_txn.dissector` function is a Wireshark dissector for parsing and displaying the fields of an FD Transaction Struct from a given buffer.
- **Inputs**:
    - `buffer`: A Tvb object representing the packet buffer to be dissected.
    - `pinfo`: A Pinfo object containing information about the packet being dissected.
    - `tree`: A TreeItem object representing the root of the protocol tree to which this dissector will add its information.
- **Control Flow**:
    - Set the protocol column in the packet info to the name of the protocol being dissected.
    - Create a subtree for the FD Transaction Protocol in the provided tree.
    - Initialize an offset variable to track the current position in the buffer.
    - Add various fields to the subtree by reading from the buffer at the current offset and incrementing the offset accordingly.
    - If there are instructions, add them to a separate subtree and parse each instruction using the `parse_instr` function.
    - If there are address tables, add them to a separate subtree and parse each table using the `parse_alt` function.
- **Output**: The function does not return a value; it modifies the provided tree to include the parsed protocol fields.


---
### parse\_instr
The `parse_instr` function extracts and adds instruction-related fields from a buffer to a given instruction tree in a Wireshark dissector.
- **Inputs**:
    - `buffer`: A buffer containing the raw data from which instruction fields are extracted.
    - `instr_tree`: A tree structure to which the parsed instruction fields are added.
- **Control Flow**:
    - Initialize an offset variable to zero.
    - Add the 'program_id' field from the buffer to the instruction tree and increment the offset by 2 (including padding).
    - Add the 'acct_cnt' field from the buffer to the instruction tree and increment the offset by 2.
    - Add the 'data_sz' field from the buffer to the instruction tree and increment the offset by 2.
    - Add the 'acct_off' field from the buffer to the instruction tree and increment the offset by 2.
    - Add the 'data_off' field from the buffer to the instruction tree and increment the offset by 2.
- **Output**: The function does not return a value; it modifies the instruction tree by adding parsed fields from the buffer.


---
### parse\_alt
The `parse_alt` function parses a buffer containing address table information and adds the parsed data to a given tree structure.
- **Inputs**:
    - `buffer`: A buffer containing the address table data to be parsed.
    - `alt_tree`: A tree structure to which the parsed address table data will be added.
- **Control Flow**:
    - Initialize an offset variable to zero.
    - Add the address offset field to the tree using the buffer data and increment the offset by 2.
    - Add the writable count field to the tree using the buffer data and increment the offset by 1.
    - Add the readonly count field to the tree using the buffer data and increment the offset by 1.
    - Add the writable offset field to the tree using the buffer data and increment the offset by 2.
    - Add the readonly offset field to the tree using the buffer data and increment the offset by 2.
- **Output**: The function does not return a value; it modifies the `alt_tree` by adding parsed fields from the `buffer`.


---
### poh\_shred\.dissector
The `poh_shred.dissector` function is a Wireshark dissector for parsing and displaying fields of FD PoH to Shred messages in network packets.
- **Inputs**:
    - `buffer`: A Tvb object representing the buffer containing the packet data to be dissected.
    - `pinfo`: A Pinfo object containing information about the packet being dissected.
    - `tree`: A TreeItem object representing the root of the protocol tree to which dissected fields should be added.
- **Control Flow**:
    - Check if the buffer length is less than 64 bytes; if so, interpret the packet as a 'Became Leader' message and add relevant fields to the tree.
    - If the buffer length is 64 bytes or more, parse the packet as a regular FD PoH to Shred message.
    - Extract and add fields such as parent offset, reference tick, block complete, hash count delta, hash, and transaction count to the protocol tree.
    - If there are transactions, iterate over them, calling the 'solana.tpu.udp' dissector for each transaction and adding them to the tree.
- **Output**: The function adds parsed fields and subtrees to the provided protocol tree, allowing Wireshark to display the dissected packet data.


---
### fd\_shred34\.dissector
The `fd_shred34.dissector` function is a Wireshark Lua dissector for parsing and displaying Firedancer Shred to Store messages.
- **Inputs**:
    - `buffer`: A Tvb object representing the packet buffer to be dissected.
    - `pinfo`: A Pinfo object containing information about the packet being dissected.
    - `tree`: A TreeItem object representing the root of the protocol tree to which this dissector will add its information.
- **Control Flow**:
    - Create a subtree for the `fd_shred34` protocol in the provided tree.
    - Extract fields such as shred count, estimated transaction count, stride, offset, and shred size from the buffer.
    - Add these extracted fields to the subtree for display in Wireshark.
    - Retrieve the dissector for 'solana.shreds' and iterate over each shred in the buffer based on the extracted stride and offset.
    - For each shred, create a Tvb object and call the 'solana.shreds' dissector to process it.
- **Output**: The function does not return a value; it modifies the protocol tree to include parsed information from the buffer.


---
### fd\_became\_leader\.dissector
The `fd_became_leader.dissector` function is a Wireshark dissector for parsing and displaying the 'FD PoH to Pack Became Leader Message' protocol data.
- **Inputs**:
    - `buffer`: A Tvb object representing the packet buffer to be dissected.
    - `pinfo`: A Pinfo object containing information about the packet being dissected.
    - `tree`: A TreeItem object representing the root of the protocol tree to which dissected fields are added.
- **Control Flow**:
    - Create a subtree for the 'fd_became_leader_t' protocol in the provided tree.
    - Extract the slot start and end times from the buffer and convert them to NSTime objects.
    - Add the slot start and end times to the subtree with the appropriate field names and values.
    - Extract and add the bank pointer, maximum microblocks in slot, and ticks per slot fields to the subtree.
- **Output**: The function adds the parsed protocol fields to the provided protocol tree, allowing Wireshark to display the dissected data.


