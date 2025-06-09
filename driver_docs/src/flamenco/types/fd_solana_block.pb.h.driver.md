# Purpose
This C header file is an automatically generated component of the nanopb library, specifically designed for handling protocol buffers in the context of Solana blockchain transactions. The file defines a series of data structures and enumerations that represent various components of a Solana confirmed block, such as transactions, instructions, token balances, and rewards. These structures are used to serialize and deserialize data related to Solana blockchain transactions, enabling efficient data exchange and storage. The file includes definitions for enums like `fd_solblock_RewardType`, which categorizes different types of rewards, and complex structures like `fd_solblock_Transaction` and `fd_solblock_ConfirmedTransaction`, which encapsulate the details of a transaction and its associated metadata.

The header file is intended to be included in other C source files that require access to Solana transaction data in a structured format. It provides a public API for interacting with Solana blockchain data, allowing developers to encode and decode transaction-related information using nanopb's protocol buffer capabilities. The file also includes initializer macros for each structure, ensuring that developers can easily create and initialize instances of these data structures. Additionally, the file contains field tags and encoding specifications, which are crucial for the manual encoding and decoding processes. This header is a critical component for applications that need to process or analyze Solana blockchain data, providing a standardized way to handle complex transaction information.
# Imports and Dependencies

---
- `../../ballet/nanopb/pb_firedancer.h`


# Data Structures

---
### fd\_solblock\_RewardType
- **Type**: `enum`
- **Members**:
    - `fd_solblock_RewardType_Unspecified`: Represents an unspecified reward type with a value of 0.
    - `fd_solblock_RewardType_Fee`: Represents a fee reward type with a value of 1.
    - `fd_solblock_RewardType_Rent`: Represents a rent reward type with a value of 2.
    - `fd_solblock_RewardType_Staking`: Represents a staking reward type with a value of 3.
    - `fd_solblock_RewardType_Voting`: Represents a voting reward type with a value of 4.
- **Description**: The `fd_solblock_RewardType` is an enumeration that defines various types of rewards that can be associated with a Solana block. It includes specific reward types such as Fee, Rent, Staking, and Voting, each represented by a unique integer value. This enum is used to categorize the nature of rewards in the context of Solana blockchain transactions.


---
### fd\_solblock\_MessageHeader
- **Type**: `struct`
- **Members**:
    - `has_num_required_signatures`: Indicates if the number of required signatures is specified.
    - `num_required_signatures`: Stores the number of required signatures for the message.
    - `has_num_readonly_signed_accounts`: Indicates if the number of readonly signed accounts is specified.
    - `num_readonly_signed_accounts`: Stores the number of readonly signed accounts.
    - `has_num_readonly_unsigned_accounts`: Indicates if the number of readonly unsigned accounts is specified.
    - `num_readonly_unsigned_accounts`: Stores the number of readonly unsigned accounts.
- **Description**: The `fd_solblock_MessageHeader` structure is used to define the header of a message in the Solana blockchain context, containing metadata about the number of required signatures and the number of readonly signed and unsigned accounts. Each field is accompanied by a boolean flag indicating whether the corresponding count is specified, allowing for optional inclusion of these counts in the message header.


---
### fd\_solblock\_Instruction
- **Type**: `struct`
- **Members**:
    - `has_program_id_index`: Indicates if the program_id_index is present.
    - `program_id_index`: Stores the index of the program ID.
    - `accounts`: Pointer to a byte array representing accounts involved in the instruction.
    - `data`: Pointer to a byte array containing the instruction data.
- **Description**: The `fd_solblock_Instruction` structure is used to represent an instruction within a Solana block. It contains information about whether a program ID index is present, the index itself, and pointers to byte arrays for accounts and data associated with the instruction. This structure is part of a larger system for handling confirmed blocks in the Solana blockchain, facilitating the processing and storage of transaction instructions.


---
### fd\_solblock\_MessageAddressTableLookup
- **Type**: `struct`
- **Members**:
    - `has_account_key`: Indicates if the account_key is present.
    - `account_key`: A fixed-length byte array representing the account key.
    - `writable_indexes`: A callback structure for handling writable indexes.
    - `readonly_indexes`: A callback structure for handling readonly indexes.
- **Description**: The `fd_solblock_MessageAddressTableLookup` structure is used to manage address table lookups within a Solana block message. It contains information about whether an account key is present, the account key itself, and callback structures for managing writable and readonly indexes. This structure is part of the nanopb-generated code for handling protocol buffers in the Solana blockchain context.


---
### fd\_solblock\_Message
- **Type**: `struct`
- **Members**:
    - `has_header`: Indicates if the message has a header.
    - `header`: Contains the message header details.
    - `account_keys_count`: Number of account keys in the message.
    - `account_keys`: Array of account keys, each 32 bytes long.
    - `has_recent_blockhash`: Indicates if the message has a recent blockhash.
    - `recent_blockhash`: The recent blockhash, 32 bytes long.
    - `instructions_count`: Number of instructions in the message.
    - `instructions`: Pointer to an array of instructions.
    - `has_versioned`: Indicates if the message is versioned.
    - `versioned`: Boolean flag indicating the version status of the message.
    - `address_table_lookups_count`: Number of address table lookups in the message.
    - `address_table_lookups`: Pointer to an array of address table lookups.
- **Description**: The `fd_solblock_Message` structure represents a message in the Solana blockchain context, encapsulating various components such as a header, account keys, recent blockhash, instructions, and address table lookups. It includes flags to indicate the presence of certain elements like the header and recent blockhash, and supports versioning. This structure is crucial for defining the contents and metadata of a transaction message, enabling the processing and validation of transactions within the Solana network.


---
### fd\_solblock\_Transaction
- **Type**: `struct`
- **Members**:
    - `signatures_count`: Stores the number of signatures associated with the transaction.
    - `signatures`: An array of 32-byte signatures for the transaction.
    - `has_message`: Indicates whether the transaction contains a message.
    - `message`: Holds the message data associated with the transaction, encapsulated in a `fd_solblock_Message` structure.
- **Description**: The `fd_solblock_Transaction` structure represents a transaction in the Solana blockchain, encapsulating the necessary components such as signatures and message data. It includes a count of signatures, an array to store these signatures, a boolean flag to indicate the presence of a message, and a `fd_solblock_Message` structure to hold the transaction's message details. This structure is crucial for handling transaction data within the Solana blockchain's confirmed block storage system.


---
### fd\_solblock\_InnerInstruction
- **Type**: `struct`
- **Members**:
    - `has_program_id_index`: Indicates if the program_id_index is set.
    - `program_id_index`: Stores the index of the program ID.
    - `accounts`: Pointer to a byte array representing accounts involved in the instruction.
    - `data`: Pointer to a byte array containing the instruction data.
    - `has_stack_height`: Indicates if the stack_height is set.
    - `stack_height`: Represents the invocation stack height of the inner instruction.
- **Description**: The `fd_solblock_InnerInstruction` structure is used to represent an inner instruction within a Solana transaction, capturing details such as the program ID index, associated accounts, and instruction data. It also includes information about the invocation stack height, which is available from Solana version 1.14.6 onwards, providing context for the execution depth of the instruction.


---
### fd\_solblock\_InnerInstructions
- **Type**: `struct`
- **Members**:
    - `has_index`: Indicates if the index field is present.
    - `index`: Stores the index of the inner instruction.
    - `instructions_count`: Holds the number of inner instructions.
    - `instructions`: Pointer to an array of inner instructions.
- **Description**: The `fd_solblock_InnerInstructions` structure is designed to encapsulate a collection of inner instructions within a Solana transaction. It includes a boolean flag to indicate the presence of an index, the index itself, a count of how many inner instructions are present, and a pointer to the array of these inner instructions. This structure is crucial for managing and accessing the detailed execution steps of a transaction's inner workings.


---
### fd\_solblock\_TransactionError
- **Type**: `struct`
- **Members**:
    - `err`: A pointer to a pb_bytes_array_t structure that holds the error data related to a transaction.
- **Description**: The `fd_solblock_TransactionError` structure is designed to encapsulate error information associated with a transaction in the Solana blockchain context. It contains a single member, `err`, which is a pointer to a `pb_bytes_array_t` type, allowing it to store a variable-length array of bytes representing the error details. This structure is part of a larger set of data structures used to manage and interpret transaction data within the Solana blockchain's confirmed block storage system.


---
### fd\_solblock\_UiTokenAmount
- **Type**: `struct`
- **Members**:
    - `has_ui_amount`: Indicates if the `ui_amount` field is present.
    - `ui_amount`: Represents the token amount in a user-friendly format as a double.
    - `has_decimals`: Indicates if the `decimals` field is present.
    - `decimals`: Specifies the number of decimal places for the token amount.
    - `amount`: Stores the token amount as a string.
    - `ui_amount_string`: Stores the user-friendly token amount as a string.
- **Description**: The `fd_solblock_UiTokenAmount` structure is designed to represent a token amount in both raw and user-friendly formats. It includes fields to indicate the presence of user-friendly amount (`ui_amount`) and decimal precision (`decimals`), as well as the actual values for these fields. Additionally, it stores the token amount as a string (`amount`) and provides a string representation of the user-friendly amount (`ui_amount_string`). This structure is useful for applications that need to display token amounts in a format that is easy for users to understand, while also maintaining the precision required for accurate calculations.


---
### fd\_solblock\_TokenBalance
- **Type**: `struct`
- **Members**:
    - `has_account_index`: Indicates if the account_index field is present.
    - `account_index`: Stores the index of the account associated with the token balance.
    - `has_mint`: Indicates if the mint field is present.
    - `mint`: Holds the mint address of the token as a string.
    - `has_ui_token_amount`: Indicates if the ui_token_amount field is present.
    - `ui_token_amount`: Represents the user interface token amount details.
    - `has_owner`: Indicates if the owner field is present.
    - `owner`: Stores the owner's address of the token as a string.
    - `has_program_id`: Indicates if the program_id field is present.
    - `program_id`: Holds the program ID associated with the token as a string.
- **Description**: The `fd_solblock_TokenBalance` structure is designed to encapsulate information about a token balance within a Solana block. It includes fields to optionally store the account index, mint address, user interface token amount, owner address, and program ID, each accompanied by a boolean flag indicating the presence of the respective field. This structure is useful for managing and accessing token balance details in a structured manner, particularly in contexts where certain fields may or may not be present.


---
### fd\_solblock\_Reward
- **Type**: `struct`
- **Members**:
    - `has_pubkey`: Indicates if the public key is present.
    - `pubkey`: Stores the public key as a string of up to 45 characters.
    - `has_lamports`: Indicates if the lamports value is present.
    - `lamports`: Stores the number of lamports as a 64-bit integer.
    - `has_post_balance`: Indicates if the post-balance value is present.
    - `post_balance`: Stores the post-balance as a 64-bit unsigned integer.
    - `has_reward_type`: Indicates if the reward type is present.
    - `reward_type`: Stores the type of reward as an enum of type fd_solblock_RewardType.
    - `commission`: Stores the commission as a string pointer.
- **Description**: The `fd_solblock_Reward` structure is used to represent a reward in the Solana blockchain context, containing information about the public key, lamports, post-balance, reward type, and commission. Each field is accompanied by a boolean flag indicating its presence, allowing for optional inclusion of data. This structure is essential for handling reward-related data in confirmed block transactions.


---
### fd\_solblock\_ReturnData
- **Type**: `struct`
- **Members**:
    - `has_program_id`: Indicates if the program_id field is present.
    - `program_id`: A fixed-length byte array of 32 bytes representing the program ID.
    - `data`: A callback structure for handling byte data.
- **Description**: The `fd_solblock_ReturnData` structure is used to encapsulate return data from a Solana transaction, specifically indicating whether a program ID is present, storing the program ID itself, and managing associated data through a callback mechanism. This structure is part of a larger system for handling confirmed block data in the Solana blockchain, providing a way to manage and access return data efficiently.


---
### fd\_solblock\_TransactionStatusMeta
- **Type**: `struct`
- **Members**:
    - `has_err`: Indicates if there is an error in the transaction.
    - `err`: Stores the transaction error details.
    - `has_fee`: Indicates if a fee is associated with the transaction.
    - `fee`: Stores the transaction fee amount.
    - `pre_balances_count`: Number of pre-transaction balances.
    - `pre_balances`: Array of pre-transaction balances.
    - `post_balances_count`: Number of post-transaction balances.
    - `post_balances`: Array of post-transaction balances.
    - `inner_instructions_count`: Number of inner instructions in the transaction.
    - `inner_instructions`: Array of inner instructions.
    - `log_messages_count`: Number of log messages generated during the transaction.
    - `log_messages`: Array of log messages.
    - `pre_token_balances_count`: Number of pre-transaction token balances.
    - `pre_token_balances`: Array of pre-transaction token balances.
    - `post_token_balances_count`: Number of post-transaction token balances.
    - `post_token_balances`: Array of post-transaction token balances.
    - `rewards_count`: Number of rewards associated with the transaction.
    - `rewards`: Array of rewards.
    - `has_inner_instructions_none`: Indicates if there are no inner instructions.
    - `inner_instructions_none`: Flag for absence of inner instructions.
    - `has_log_messages_none`: Indicates if there are no log messages.
    - `log_messages_none`: Flag for absence of log messages.
    - `loaded_writable_addresses_count`: Number of loaded writable addresses.
    - `loaded_writable_addresses`: Array of loaded writable addresses.
    - `loaded_readonly_addresses_count`: Number of loaded readonly addresses.
    - `loaded_readonly_addresses`: Array of loaded readonly addresses.
    - `has_return_data`: Indicates if return data is present.
    - `return_data`: Stores the return data of the transaction.
    - `has_return_data_none`: Indicates if there is no return data.
    - `return_data_none`: Flag for absence of return data.
    - `has_compute_units_consumed`: Indicates if compute units consumed is available.
    - `compute_units_consumed`: Stores the total compute units consumed by the transaction.
- **Description**: The `fd_solblock_TransactionStatusMeta` structure encapsulates metadata about a Solana transaction, including error status, fees, balance changes, inner instructions, log messages, token balances, rewards, and compute units consumed. It provides a comprehensive view of the transaction's execution and its effects on account balances and token states, as well as any associated rewards or errors. This structure is crucial for understanding the outcome and impact of a transaction within the Solana blockchain.


---
### fd\_solblock\_ConfirmedTransaction
- **Type**: `struct`
- **Members**:
    - `has_transaction`: Indicates if the transaction field is present.
    - `transaction`: Holds the transaction data if present.
    - `has_meta`: Indicates if the meta field is present.
    - `meta`: Holds the transaction status metadata if present.
- **Description**: The `fd_solblock_ConfirmedTransaction` structure is used to represent a confirmed transaction in the Solana blockchain. It contains information about whether a transaction and its associated metadata are present, and if so, it holds the transaction details and the transaction status metadata. This structure is part of a larger system for handling confirmed blocks in Solana, providing a way to encapsulate both the transaction and its execution results.


