# Purpose
This Python script is designed to facilitate the creation and management of Solana blockchain transactions, specifically focusing on different types of token transfers. It serves as a comprehensive tool for setting up accounts, funding them, and executing transactions across the Solana network. The script is structured to handle various transaction types, including system transfers, token transfers, and nano-token transfers, utilizing the Solana and SPL token libraries. It also incorporates multiprocessing and threading to efficiently manage and send transactions to multiple Transaction Processing Units (TPUs) concurrently.

The script begins by parsing command-line arguments to configure the transaction parameters, such as the number of keys, transaction type, and account access distribution. It then initializes key components, including the Solana client, funder account, and network socket for UDP communication. The script defines several functions to create and fund accounts, generate transactions, and send them to the network. It also includes monitoring and fetching mechanisms to track transaction throughput and update recent blockhashes. The main function orchestrates these components, setting up the necessary accounts and launching worker processes to execute transactions in parallel, ensuring high throughput and efficient resource utilization.
# Imports and Dependencies

---
- `argparse`
- `logging`
- `json`
- `time`
- `random`
- `socket`
- `math`
- `multiprocessing`
- `threading`
- `requests`
- `functools.partial`
- `typing.List`
- `multiprocessing.sharedctypes.SynchronizedBase`
- `multiprocessing.Event`
- `multiprocessing.Value`
- `multiprocessing.Array`
- `base64`
- `numpy`
- `tqdm`
- `pqdm.processes.pqdm`
- `solana.transaction.Transaction`
- `solana.rpc.api.Client`
- `solders.hash.Hash`
- `solana.rpc.commitment.Commitment`
- `solders.keypair.Keypair`
- `solders.system_program.TransferParams`
- `solders.system_program.transfer`
- `solders.system_program.create_account`
- `solders.system_program.CreateAccountParams`
- `solders.compute_budget.set_compute_unit_limit`
- `solders.compute_budget.set_compute_unit_price`
- `solders.pubkey.Pubkey`
- `solders.instruction.AccountMeta`
- `solders.instruction.Instruction`
- `solders.system_program.ID`
- `spl.token.client.Token`
- `spl.token.constants.TOKEN_PROGRAM_ID`
- `spl.token._layouts.ACCOUNT_LAYOUT`
- `spl.token._layouts.MINT_LAYOUT`
- `spl.token._layouts.MULTISIG_LAYOUT`
- `spl.token.instructions.initialize_mint`
- `spl.token.instructions.get_associated_token_address`
- `spl.token.instructions.create_associated_token_account`
- `spl.token.instructions.InitializeMintParams`
- `spl.token.instructions.mint_to`
- `spl.token.instructions.MintToParams`
- `spl.token.instructions.transfer`
- `spl.token.instructions.TransferParams`
- `solders.rent.Rent`
- `solana.rpc.types.TxOpts`


# Global Variables

---
### TXN\_TYPE\_EMPTY
- **Type**: `int`
- **Description**: `TXN_TYPE_EMPTY` is a global integer variable that represents a transaction type with a value of 0. It is used to denote an empty transaction type in the context of the application.
- **Use**: This variable is used to identify and handle empty transactions within the transaction processing logic.


---
### TXN\_TYPE\_SYSTEM\_TRANSFER
- **Type**: `int`
- **Description**: `TXN_TYPE_SYSTEM_TRANSFER` is a global integer variable that represents a specific type of transaction, specifically a system transfer, within the application. It is assigned the value `1`, indicating its unique identifier among other transaction types.
- **Use**: This variable is used to identify and differentiate system transfer transactions from other types of transactions in the code.


---
### TXN\_TYPE\_TOKEN\_TRANSFER
- **Type**: `int`
- **Description**: `TXN_TYPE_TOKEN_TRANSFER` is a global integer variable that represents a specific type of transaction, specifically a token transfer transaction, within the system. It is assigned the value `2`, which is used as an identifier for this transaction type.
- **Use**: This variable is used to specify and identify token transfer transactions in the code, particularly when creating or processing transactions.


---
### TXN\_TYPE\_NANO\_TOKEN\_TRANSFER
- **Type**: `int`
- **Description**: `TXN_TYPE_NANO_TOKEN_TRANSFER` is a global integer variable set to the value 3. It is used as a constant to represent a specific type of transaction, namely a 'nano token transfer', within the codebase.
- **Use**: This variable is used to identify and handle nano token transfer transactions in the application logic.


---
### ACCT\_ACCESS\_DIST\_REGULAR
- **Type**: `int`
- **Description**: `ACCT_ACCESS_DIST_REGULAR` is a global integer variable set to 0. It is used to represent a specific type of account access distribution in the context of transaction processing.
- **Use**: This variable is used to determine the account access distribution strategy when sending transactions, specifically indicating a regular distribution.


---
### ACCT\_ACCESS\_DIST\_POWER
- **Type**: `int`
- **Description**: `ACCT_ACCESS_DIST_POWER` is a global integer variable set to the value 1. It is used to represent a specific account access distribution type in the context of transaction processing.
- **Use**: This variable is used to determine the account access distribution strategy, specifically the 'power' distribution, when sending transactions.


---
### NANO\_TOKEN\_ID
- **Type**: `Pubkey`
- **Description**: `NANO_TOKEN_ID` is a global variable that holds a `Pubkey` object, which is initialized using the `from_string` method with a specific string representing a public key. This public key is likely used to identify a specific token or account within the Solana blockchain ecosystem.
- **Use**: This variable is used as the owner or program ID in various transaction and account creation operations, particularly related to nano token transfers.


---
### NOOP\_ID
- **Type**: `Pubkey`
- **Description**: `NOOP_ID` is a global variable that holds a `Pubkey` object created from a specific string identifier, "NoopToken1111111111111111111111111111111111". This identifier is likely used as a placeholder or a default value in the context of Solana transactions or programs.
- **Use**: This variable is used to represent a public key for a 'No Operation' token, potentially serving as a default or placeholder in transaction operations.


---
### seed\_file
- **Type**: `file object`
- **Description**: The `seed_file` variable is a file object that is opened in read mode. It points to the file located at '../test-ledger/faucet-keypair.json'. This file is expected to contain JSON data that is used to initialize the `top_seed` variable.
- **Use**: This variable is used to read JSON data from a file, which is then converted into bytes and used for cryptographic operations.


---
### top\_seed
- **Type**: `bytes`
- **Description**: The `top_seed` variable is a byte sequence obtained by loading JSON data from a file named `seed_file`. This JSON data is then converted into bytes, which are used as a seed for cryptographic operations.
- **Use**: This variable is used to generate key pairs with specific derivation paths for cryptographic operations.


---
### fd\_mint
- **Type**: `Keypair`
- **Description**: The `fd_mint` variable is an instance of the `Keypair` class, created using a seed and a specific derivation path. It represents a cryptographic key pair used in the Solana blockchain, specifically for minting tokens.
- **Use**: This variable is used to generate and manage a public/private key pair for a token minting account in the Solana blockchain.


---
### config\_acc
- **Type**: `Keypair`
- **Description**: The `config_acc` variable is an instance of the `Keypair` class, created by loading a JSON file located at `../keygrinds/config.json` and converting its contents into bytes. This keypair is used to represent a cryptographic key pair, which includes a public and private key, for authentication and encryption purposes.
- **Use**: This variable is used to store and manage the cryptographic key pair for the configuration account, which is utilized in various functions for signing transactions and managing account operations.


---
### nano\_mint
- **Type**: `Keypair`
- **Description**: The `nano_mint` variable is an instance of the `Keypair` class, created using a seed and a specific derivation path. It represents a cryptographic key pair used in blockchain transactions, specifically for a minting operation in a Solana-based application.
- **Use**: This variable is used to generate and manage a public/private key pair for minting operations, allowing the application to interact with the blockchain securely.


# Functions

---
### get\_recent\_blockhash<!-- {{#callable:firedancer/contrib/tool/txn-gen.get_recent_blockhash}} -->
The `get_recent_blockhash` function retrieves the latest blockhash from a Solana RPC endpoint.
- **Inputs**:
    - `rpc`: A string representing the URL of the Solana RPC endpoint to query for the latest blockhash.
- **Control Flow**:
    - Constructs a JSON-RPC request payload as a string to call the 'getLatestBlockhash' method with 'processed' commitment.
    - Sends a POST request to the specified RPC endpoint with the constructed JSON-RPC payload and appropriate headers.
    - Parses the JSON response to extract the 'blockhash' value from the nested 'result' and 'value' fields.
    - Converts the extracted blockhash string into a Hash object using the `Hash.from_string` method.
- **Output**: Returns a `Hash` object representing the latest blockhash obtained from the RPC response.


---
### get\_balance<!-- {{#callable:firedancer/contrib/tool/txn-gen.get_balance}} -->
The `get_balance` function retrieves the balance of a given account from a specified RPC endpoint using a JSON-RPC request.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL to which the JSON-RPC request will be sent.
    - `acc`: A `Pubkey` object representing the public key of the account whose balance is to be retrieved.
- **Control Flow**:
    - Convert the `acc` (account public key) to a string format.
    - Construct a JSON-RPC request payload to call the `getBalance` method with the account public key and a commitment level of 'confirmed'.
    - Send a POST request to the specified `rpc` endpoint with the constructed JSON-RPC payload and appropriate headers.
    - Check if the response status code is not 200, and if so, return 0 indicating failure to retrieve balance.
    - If the response is successful, parse the JSON response to extract and return the balance value from the 'result' field.
    - If any exception occurs during the process, return 0 as a fallback.
- **Output**: An integer representing the balance of the specified account, or 0 if the balance could not be retrieved.


---
### get\_account\_info<!-- {{#callable:firedancer/contrib/tool/txn-gen.get_account_info}} -->
The `get_account_info` function retrieves and decodes account information from a specified RPC endpoint using a JSON-RPC request.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL to which the JSON-RPC request will be sent.
    - `acc`: A string representing the account identifier for which information is being requested.
- **Control Flow**:
    - Constructs a JSON-RPC request payload with the method `getAccountInfo` and the specified account and parameters.
    - Sends a POST request to the specified RPC endpoint with the constructed JSON-RPC payload.
    - Checks if the HTTP response status code is not 200, returning `None` if true.
    - Checks if the `value` field in the JSON response is `None`, returning `None` if true.
    - If the response is valid and contains data, decodes the base64-encoded account data and returns it.
- **Output**: The function returns the decoded account data as bytes if successful, or `None` if the request fails or the account data is not available.


---
### parse\_args<!-- {{#callable:firedancer/contrib/tool/txn-gen.parse_args}} -->
The `parse_args` function parses command-line arguments required for configuring and executing transactions in a Solana-based application.
- **Inputs**: None
- **Control Flow**:
    - An `ArgumentParser` object is created to handle command-line arguments.
    - Several arguments are added to the parser, each with specific options such as `required`, `type`, and `help` descriptions.
    - The arguments include `--tpus`, `--rpc`, `--nkeys`, `--seed`, `--funder`, `--workers`, `--txn-type`, and `--acct-access-distr`, all of which are required.
    - The `parse_args` method of the parser is called to parse the command-line arguments and store them in the `args` variable.
    - The parsed arguments are returned as an `argparse.Namespace` object.
- **Output**: The function returns an `argparse.Namespace` object containing the parsed command-line arguments.


---
### send\_round\_of\_txs<!-- {{#callable:firedancer/contrib/tool/txn-gen.send_round_of_txs}} -->
The `send_round_of_txs` function sends a batch of transactions to multiple TPU endpoints using a socket.
- **Inputs**:
    - `txs`: A list of `Transaction` objects to be sent.
    - `sock`: A socket object used to send the transactions.
    - `tpus`: A list of TPU (Transaction Processing Unit) endpoints to which the transactions will be sent.
- **Control Flow**:
    - Iterates over each transaction in the `txs` list using a progress bar provided by `tqdm`.
    - Converts each transaction to a byte format using the `to_solders` method.
    - For each TPU endpoint in the `tpus` list, sends the byte-formatted transaction using the `sock.sendto` method.
    - Pauses for 0.001 seconds after sending each transaction to all TPU endpoints.
- **Output**: The function does not return any value; it sends transactions over the network.


---
### fund\_config\_account<!-- {{#callable:firedancer/contrib/tool/txn-gen.fund_config_account}} -->
The `fund_config_account` function creates and signs a Solana transaction to fund a configuration account with a specified amount of lamports plus an additional range.
- **Inputs**:
    - `funder`: The account (Keypair) that will fund the transaction and sign it.
    - `lamports`: The base amount of lamports to transfer to the configuration account.
    - `recent_blockhash`: The recent blockhash to be used in the transaction for ensuring its validity.
    - `range`: An additional amount of lamports to add to the base amount for the transaction.
- **Control Flow**:
    - A new `Transaction` object is created using the provided `recent_blockhash`, the funder's public key, and compute unit settings.
    - The transaction is augmented by adding an instruction to create a new account with the specified lamports plus range, a space of 16 bytes, and ownership by `NANO_TOKEN_ID`.
    - The transaction is signed by the funder and the configuration account keypair.
    - The signed transaction is returned.
- **Output**: A signed `Transaction` object that can be submitted to the Solana network to fund the configuration account.


---
### fund\_config\_account2<!-- {{#callable:firedancer/contrib/tool/txn-gen.fund_config_account2}} -->
The `fund_config_account2` function creates and signs a Solana transaction to fund a configuration account with specific compute unit settings.
- **Inputs**:
    - `funder`: The account that will fund the transaction, represented as a Keypair object.
    - `lamports`: The amount of lamports to be transferred, though not directly used in this function.
    - `recent_blockhash`: The recent blockhash to be used in the transaction for ensuring its validity.
    - `range`: An additional parameter, though not directly used in this function.
- **Control Flow**:
    - A new Transaction object is created with the provided recent_blockhash, no fee payer, the funder's public key, and specific compute unit settings.
    - A zero value is converted to a byte array to serve as the instruction data, indicating a 0 discriminator.
    - A list of AccountMeta objects is created to specify the accounts involved in the transaction, including the configuration account, the system program ID, and the funder's public key.
    - An Instruction object is created using the accounts list, the NANO_TOKEN_ID as the program ID, and the zero byte array as data.
    - The instruction is added to the transaction.
    - The transaction is signed by the funder.
    - The signed transaction is returned.
- **Output**: The function returns a signed Transaction object ready to be sent to the Solana network.


---
### fund\_nano\_mint\_account2<!-- {{#callable:firedancer/contrib/tool/txn-gen.fund_nano_mint_account2}} -->
The `fund_nano_mint_account2` function creates and signs a Solana transaction to fund a nano mint account with a specified amount of lamports plus an additional range.
- **Inputs**:
    - `funder`: The account (Keypair) that will fund the transaction and sign it.
    - `lamports`: The number of lamports to transfer to the nano mint account.
    - `recent_blockhash`: The recent blockhash to be used for the transaction.
    - `range`: An additional amount to be added to the lamports for the transaction.
- **Control Flow**:
    - A new Transaction object is created with the provided recent_blockhash, no fee payer, the funder's public key, and two compute budget instructions to set the compute unit price and limit.
    - A create account instruction is added to the transaction to create an account with the funder's public key as the source, the nano mint's public key as the destination, the total lamports (lamports + range), a space of 64 bytes, and the NANO_TOKEN_ID as the owner.
    - The transaction is signed by the funder and the nano mint keypair.
    - The signed transaction is returned.
- **Output**: A signed Transaction object that can be sent to the Solana network to fund the nano mint account.


---
### fund\_nano\_mint\_account<!-- {{#callable:firedancer/contrib/tool/txn-gen.fund_nano_mint_account}} -->
The `fund_nano_mint_account` function creates and signs a Solana transaction to fund a nano mint account with specific instructions and account metadata.
- **Inputs**:
    - `funder`: The account (Keypair) that will fund the transaction and sign it.
    - `lamports`: The amount of lamports to be transferred, though not directly used in this function.
    - `recent_blockhash`: The recent blockhash to be used in the transaction for ensuring its validity.
    - `range`: An additional parameter, though not directly used in this function.
- **Control Flow**:
    - A new `Transaction` object is created with the provided `recent_blockhash`, the funder's public key, and compute unit settings.
    - Three data segments are created: a discriminator byte, the funder's public key, and a decimal value, which are concatenated to form the instruction data.
    - A list of `AccountMeta` objects is created, representing the accounts involved in the transaction, including the nano mint account, configuration account, system program ID, and the funder account.
    - An `Instruction` object is created using the account metadata, the NANO_TOKEN_ID as the program ID, and the concatenated data.
    - The instruction is added to the transaction.
    - The transaction is signed by the funder.
    - The signed transaction is returned.
- **Output**: The function returns a signed `Transaction` object ready to be sent to the Solana network.


---
### fund\_token\_account<!-- {{#callable:firedancer/contrib/tool/txn-gen.fund_token_account}} -->
The `fund_token_account` function creates and signs a Solana transaction to fund a token account with specified lamports and initialize a mint with given parameters.
- **Inputs**:
    - `funder`: The account (Keypair) that will fund the token account and sign the transaction.
    - `lamports`: The amount of lamports to be transferred to the new token account.
    - `recent_blockhash`: The recent blockhash to be used for the transaction.
    - `is_print`: A boolean flag, though not used in the function logic.
    - `range`: An additional amount to be added to the lamports for the transaction.
- **Control Flow**:
    - A new `Transaction` object is created with the provided `recent_blockhash`, the funder's public key, and compute unit settings.
    - A `create_account` instruction is added to the transaction to create a new account with the specified lamports plus the range, using the funder's public key as the source and the `fd_mint` public key as the destination.
    - An `InitializeMintParams` object is created with specific parameters including decimals, mint, mint authority, and program ID.
    - An `initialize_mint` instruction is added to the transaction using the `InitializeMintParams`.
    - The transaction is signed by the funder and the `fd_mint` keypair.
    - The transaction object is returned.
- **Output**: A `Transaction` object that represents the signed transaction to fund and initialize a token account.


---
### create\_accounts\_tx<!-- {{#callable:firedancer/contrib/tool/txn-gen.create_accounts_tx}} -->
The `create_accounts_tx` function constructs and returns a Solana transaction for transferring lamports and optionally setting up token accounts based on the transaction type.
- **Inputs**:
    - `funder`: The account that will fund the transactions and sign them.
    - `lamports`: The amount of lamports to transfer to each account.
    - `recent_blockhash`: The recent blockhash to use for the transaction.
    - `txn_type`: The type of transaction to create, which determines additional actions like token account setup.
    - `accs`: A list of accounts to which lamports will be transferred and potentially token accounts will be set up.
- **Control Flow**:
    - Initialize the compute unit limit to 200,000, but reduce it to 15,000 if the transaction type is `TXN_TYPE_NANO_TOKEN_TRANSFER`.
    - Create a new transaction with the given recent blockhash, funder's public key, and compute unit settings.
    - Iterate over each account in `accs` to add a lamport transfer instruction to the transaction.
    - If the transaction type is `TXN_TYPE_TOKEN_TRANSFER`, add instructions to create an associated token account and mint tokens to it.
    - If the transaction type is `TXN_TYPE_NANO_TOKEN_TRANSFER`, derive a nano token address, create an instruction to set up the nano token account, and add a mint instruction to the transaction.
    - Sign the transaction with the funder's key.
- **Output**: A signed `Transaction` object ready to be sent to the Solana network.


---
### get\_balance\_sufficient<!-- {{#callable:firedancer/contrib/tool/txn-gen.get_balance_sufficient}} -->
The `get_balance_sufficient` function checks if an account has a sufficient balance of lamports or a valid nano token account for a specific transaction type.
- **Inputs**:
    - `lamports`: The minimum balance required for the account.
    - `rpc`: The RPC endpoint URL as a string to interact with the Solana blockchain.
    - `txn_type`: The type of transaction, which determines the specific checks to perform.
    - `acc`: The account object whose balance is being checked.
- **Control Flow**:
    - If the transaction type is `TXN_TYPE_NANO_TOKEN_TRANSFER`, derive the associated token address (ATA) using the account's public key and a zero byte array as seeds.
    - Retrieve account information for the derived ATA using the [`get_account_info`](#get_account_info) function.
    - If the account information is not available or the first byte of the data is zero, return `None`.
    - Retrieve the balance of the account using the [`get_balance`](#get_balance) function.
    - If the balance is available, print the account's public key and balance.
    - If the balance is greater than or equal to the required lamports, return the account object.
    - If none of the conditions for sufficient balance are met, return `None`.
- **Output**: Returns the account object if the balance is sufficient or the nano token account is valid; otherwise, returns `None`.
- **Functions called**:
    - [`firedancer/contrib/tool/txn-gen.get_account_info`](#get_account_info)
    - [`firedancer/contrib/tool/txn-gen.get_balance`](#get_balance)


---
### create\_accounts<!-- {{#callable:firedancer/contrib/tool/txn-gen.create_accounts}} -->
The `create_accounts` function generates a specified number of accounts, funds them with lamports, and handles different transaction types for account creation and funding on the Solana blockchain.
- **Inputs**:
    - `funder`: The account that will fund the new accounts with lamports.
    - `rpc`: The RPC endpoint URL for interacting with the Solana blockchain.
    - `num_accs`: The number of accounts to create.
    - `lamports`: The amount of lamports to fund each account with.
    - `seed`: The seed used to derive the keypairs for the accounts.
    - `sock`: The socket used for sending transactions.
    - `tpus`: A list of TPU (Transaction Processing Unit) endpoints to send transactions to.
    - `txn_type`: The type of transaction to perform, which determines the account setup and funding logic.
- **Control Flow**:
    - Retrieve account information for the nano mint and fd mint accounts using the RPC endpoint.
    - Print the balance of a specific token account and the NANO_TOKEN_ID account.
    - Generate keypairs for the specified number of accounts using the provided seed and transaction type.
    - Divide the generated accounts into chunks for processing in parallel.
    - Check and create necessary configurations and mint accounts based on the transaction type (e.g., NANO_TOKEN_TRANSFER).
    - For each account, check if it has sufficient balance and remove it from the remaining accounts if it does.
    - If there are remaining accounts, create transactions to fund them and send these transactions to the TPU endpoints.
    - Repeat the funding process until all accounts have been funded or have sufficient balance.
    - Return the list of created accounts.
- **Output**: A list of created Keypair objects representing the new accounts.
- **Functions called**:
    - [`firedancer/contrib/tool/txn-gen.get_account_info`](#get_account_info)
    - [`firedancer/contrib/tool/txn-gen.get_balance`](#get_balance)
    - [`firedancer/contrib/tool/txn-gen.get_recent_blockhash`](#get_recent_blockhash)
    - [`firedancer/contrib/tool/txn-gen.fund_config_account`](#fund_config_account)
    - [`firedancer/contrib/tool/txn-gen.send_round_of_txs`](#send_round_of_txs)
    - [`firedancer/contrib/tool/txn-gen.fund_nano_mint_account`](#fund_nano_mint_account)


---
### gen\_tx\_empty<!-- {{#callable:firedancer/contrib/tool/txn-gen.gen_tx_empty}} -->
The `gen_tx_empty` function creates and signs a Solana transaction with specified compute unit price and limit, using a given recent blockhash, key, and account.
- **Inputs**:
    - `recent_blockhash`: A recent blockhash used to initialize the transaction, ensuring it is processed in a timely manner.
    - `key`: A keypair used to sign the transaction, providing the necessary authorization.
    - `acc`: The account associated with the transaction, which will be used as the fee payer.
    - `cu_price`: The compute unit price to be set for the transaction, determining the cost of compute resources.
- **Control Flow**:
    - A `Transaction` object is created using the provided `recent_blockhash`, `None` for the fee payer, the `acc` as the fee payer, and a list of instructions to set the compute unit price and limit.
    - The transaction is signed using the provided `key`, which authorizes the transaction.
    - The signed transaction is returned.
- **Output**: A signed `Transaction` object ready to be sent to the Solana network.


---
### gen\_tx\_system\_transfer<!-- {{#callable:firedancer/contrib/tool/txn-gen.gen_tx_system_transfer}} -->
The `gen_tx_system_transfer` function creates and signs a Solana transaction for a system transfer with specified compute unit price and limits.
- **Inputs**:
    - `recent_blockhash`: A recent blockhash used to ensure the transaction is processed in a timely manner.
    - `key`: A Keypair object used to sign the transaction.
    - `acc`: The public key of the account involved in the transaction, used as both the sender and receiver.
    - `cu_price`: The price per compute unit to be set for the transaction.
- **Control Flow**:
    - A Transaction object is created with the provided recent blockhash, account, and compute unit settings.
    - A transfer instruction is added to the transaction, transferring 1 lamport from the account to itself.
    - The transaction is signed using the provided keypair.
- **Output**: The function returns the signed Transaction object.


---
### gen\_tx\_token\_transfer<!-- {{#callable:firedancer/contrib/tool/txn-gen.gen_tx_token_transfer}} -->
The `gen_tx_token_transfer` function generates a Solana transaction for transferring a token from and to the same associated token account.
- **Inputs**:
    - `recent_blockhash`: A recent blockhash used to ensure the transaction is processed in a timely manner.
    - `key`: A Keypair object representing the account that will sign the transaction.
    - `acc`: The public key of the account initiating the transaction.
    - `cu_price`: The price of compute units to be set for the transaction.
- **Control Flow**:
    - A new Transaction object is created with the provided recent blockhash, account, and compute unit settings.
    - The associated token address (ATA) for the given key and a predefined mint is retrieved.
    - A SplTransferParams object is created to define the token transfer parameters, including the program ID, source and destination addresses, owner, and amount.
    - A SPL token transfer instruction is added to the transaction using the transfer parameters.
    - The transaction is signed using the provided key.
    - The signed transaction is returned.
- **Output**: A signed Transaction object ready to be sent to the Solana network for processing a token transfer.


---
### gen\_tx\_nano\_token\_transfer<!-- {{#callable:firedancer/contrib/tool/txn-gen.gen_tx_nano_token_transfer}} -->
The function `gen_tx_nano_token_transfer` generates a transaction for transferring a nano token between two accounts on the Solana blockchain.
- **Inputs**:
    - `recent_blockhash`: The recent blockhash to be used for the transaction, ensuring it is processed in the current block.
    - `src_key`: The keypair of the source account, used to sign the transaction.
    - `src_acc`: The public key of the source account from which the nano token will be transferred.
    - `src_nano_ata`: The associated token account (ATA) of the source account for the nano token.
    - `dst_nano_ata`: The associated token account (ATA) of the destination account for the nano token.
    - `cu_price`: The compute unit price to be set for the transaction.
- **Control Flow**:
    - A `Transaction` object is created with the provided `recent_blockhash`, source account, and compute unit settings.
    - The instruction data for the nano token transfer is constructed, including a transfer tag and amount.
    - Account metadata is set up for the source and destination nano token ATAs and the source account.
    - An `Instruction` object is created with the nano token program ID, account metadata, and instruction data.
    - The instruction is added to the transaction.
    - The transaction is signed using the source keypair.
- **Output**: The function returns a signed `Transaction` object ready to be sent to the Solana network for processing the nano token transfer.


---
### send\_txs<!-- {{#callable:firedancer/contrib/tool/txn-gen.send_txs}} -->
The `send_txs` function sends transactions to specified TPU endpoints using a list of keypairs and transaction types, while monitoring and adjusting compute unit prices based on recent blockhash changes.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL for blockchain interaction.
    - `tpus`: A list of strings representing the TPU UDP endpoints to send transactions to.
    - `keys`: A list of Keypair objects representing the accounts involved in the transactions.
    - `tx_idx`: A shared multiprocessing Value object used to track the number of transactions sent.
    - `mult`: An integer multiplier used in the transaction sending process (not directly used in the function).
    - `idx`: An integer index representing the worker's identifier.
    - `stop_event`: A multiprocessing Event object used to signal when to stop sending transactions.
    - `rbh`: A shared multiprocessing Array object containing the recent blockhash.
    - `txn_type`: An integer representing the type of transaction to send (e.g., empty, system transfer, token transfer, nano token transfer).
    - `acct_access_distr`: An integer representing the account access distribution type (e.g., regular, power).
- **Control Flow**:
    - A UDP socket is created for sending transactions.
    - Public keys are extracted from the provided keypairs and used to derive associated token addresses (nano_atas).
    - The function enters a loop that continues until the stop_event is set.
    - Within the loop, the recent blockhash is updated and compared to the previous blockhash to adjust the compute unit price (cu_price).
    - The number of iterations (niter) is determined based on the account access distribution and transaction type.
    - For each iteration, indices i and j are determined based on the account access distribution type.
    - A transaction is generated based on the transaction type and the current compute unit price.
    - The transaction is serialized and sent to each TPU endpoint using the UDP socket.
    - The transaction index (tx_idx) is incremented by the number of iterations (niter).
    - The loop continues until the stop_event is set, at which point the function prints a stopping message with the worker index.
- **Output**: The function does not return any value; it sends transactions to the specified TPU endpoints and updates the transaction index.
- **Functions called**:
    - [`firedancer/contrib/tool/txn-gen.gen_tx_empty`](#gen_tx_empty)
    - [`firedancer/contrib/tool/txn-gen.gen_tx_system_transfer`](#gen_tx_system_transfer)
    - [`firedancer/contrib/tool/txn-gen.gen_tx_token_transfer`](#gen_tx_token_transfer)
    - [`firedancer/contrib/tool/txn-gen.gen_tx_nano_token_transfer`](#gen_tx_nano_token_transfer)


---
### monitor\_send\_tps<!-- {{#callable:firedancer/contrib/tool/txn-gen.monitor_send_tps}} -->
The `monitor_send_tps` function monitors and prints the transactions per second (TPS) over a specified interval until a stop event is triggered or the interval reaches 10 seconds.
- **Inputs**:
    - `tx_idx`: A synchronized shared memory object that holds the current transaction index or count.
    - `stop_event`: A multiprocessing event object used to signal when the monitoring should stop.
    - `interval`: An optional integer specifying the time interval in seconds for monitoring TPS, defaulting to 1.
- **Control Flow**:
    - Initialize `prev_count` to 0 and `prev_time` to the current time.
    - Enter a while loop that continues as long as `interval` is less than 10 and `stop_event` is not set.
    - Sleep for the duration of `interval`.
    - Acquire a lock on `tx_idx` to safely read the current transaction count into `current_count`.
    - Calculate the current time and compute TPS as the difference in transaction count divided by `interval`.
    - Update `prev_count` to `current_count` and calculate the elapsed time since `prev_time`.
    - Print the calculated TPS and elapsed time.
    - If TPS is zero, increment the `interval` by 1.
    - Update `prev_time` to the current time.
- **Output**: The function does not return any value; it outputs TPS and elapsed time to the console.


---
### fetch\_recent\_blockhash<!-- {{#callable:firedancer/contrib/tool/txn-gen.fetch_recent_blockhash}} -->
The `fetch_recent_blockhash` function continuously updates a shared memory array with the latest blockhash from a Solana RPC endpoint until a stop event is triggered.
- **Inputs**:
    - `rbh`: A shared memory array that will be updated with the latest blockhash as bytes.
    - `rpc`: A string representing the RPC endpoint URL to fetch the recent blockhash from.
    - `stop_event`: A threading event used to signal when the function should stop executing.
- **Control Flow**:
    - Initialize `prev_recent_blockhash` with the current blockhash fetched from the RPC endpoint using [`get_recent_blockhash`](#get_recent_blockhash) function.
    - Enter a loop that continues until `stop_event` is set.
    - Inside the loop, sleep for 0.1 seconds to prevent excessive requests.
    - Try to fetch the latest blockhash from the RPC endpoint.
    - If the fetched blockhash is different from `prev_recent_blockhash`, update the `rbh` array with the new blockhash and set `prev_recent_blockhash` to this new value.
    - Print the new blockhash if it is different from the previous one.
    - If an exception occurs during fetching, print 'bad RBH'.
- **Output**: The function does not return any value; it updates the `rbh` array in place with the latest blockhash.
- **Functions called**:
    - [`firedancer/contrib/tool/txn-gen.get_recent_blockhash`](#get_recent_blockhash)


---
### main<!-- {{#callable:firedancer/contrib/tool/txn-gen.main}} -->
The `main` function initializes and manages the execution of a transaction sending process using multiple worker processes and threads to monitor and fetch recent blockhashes.
- **Inputs**: None
- **Control Flow**:
    - Parse command-line arguments using `parse_args()` to get necessary parameters like RPC endpoint, seed file, funder file, transaction type, and number of workers.
    - Initialize a `Client` object with the RPC endpoint and read the seed and funder key from the specified files.
    - Create a UDP socket and parse the TPU endpoints from the arguments.
    - Determine the transaction type and account access distribution based on the provided arguments, exiting with an error if unknown types are specified.
    - Call [`create_accounts`](#create_accounts) to generate accounts needed for transactions, using the funder, RPC, number of keys, seed, socket, TPU endpoints, and transaction type.
    - Divide the created accounts into chunks based on the number of workers specified.
    - Initialize shared memory structures for recent blockhash (`rbh`), a stop event, and a transaction index counter (`tx_idx`).
    - Start a monitoring thread to track transactions per second and a fetching thread to update the recent blockhash periodically.
    - Create and start multiple worker processes, each responsible for sending transactions using the `send_txs` function, passing necessary parameters including RPC, TPU endpoints, account chunks, and transaction type.
    - Enter a loop to keep the main process alive, sleeping briefly in each iteration.
    - Upon termination (e.g., via a signal), set the stop event to signal all threads and processes to stop, and join all worker processes to ensure clean shutdown.
- **Output**: The function does not return any value; it orchestrates the setup and execution of transaction sending processes and threads.
- **Functions called**:
    - [`firedancer/contrib/tool/txn-gen.parse_args`](#parse_args)
    - [`firedancer/contrib/tool/txn-gen.create_accounts`](#create_accounts)


