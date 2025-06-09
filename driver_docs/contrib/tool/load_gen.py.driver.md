# Purpose
This Python script is designed to facilitate high-throughput transaction processing on the Solana blockchain. It serves as a transaction generator and sender, capable of creating and dispatching various types of transactions, including empty transactions, system transfers, token transfers, and nano-token transfers. The script is structured as a command-line tool, utilizing the `argparse` module to parse input arguments that specify the transaction processing unit (TPU) endpoints, RPC endpoint, number of keys, seed file, funder file, number of worker processes, and transaction type. The script leverages multiprocessing and threading to handle concurrent transaction generation and sending, ensuring efficient use of system resources.

Key components of the script include functions for generating different types of transactions, managing account creation and funding, and monitoring transaction throughput. The script interacts with the Solana blockchain using the `solana` and `solders` libraries, and it employs the `requests` library for HTTP communication with Solana RPC nodes. The script also uses the `pqdm` library to parallelize tasks across multiple processes. The main function orchestrates the setup and execution of the transaction sending process, including initializing accounts, fetching recent blockhashes, and starting worker processes to send transactions continuously. The script is intended for use in environments where high transaction throughput is required, such as performance testing or stress testing of the Solana network.
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
- **Description**: `TXN_TYPE_EMPTY` is a global integer variable that represents a transaction type with a value of 0. It is used to denote an empty transaction type in the context of the transaction processing system.
- **Use**: This variable is used to identify and handle empty transactions within the transaction processing logic.


---
### TXN\_TYPE\_SYSTEM\_TRANSFER
- **Type**: `int`
- **Description**: `TXN_TYPE_SYSTEM_TRANSFER` is a global integer variable that represents a specific type of transaction, specifically a system transfer, within the application. It is assigned the value `1`, which is used as an identifier for this transaction type.
- **Use**: This variable is used to specify and identify system transfer transactions in the code logic.


---
### TXN\_TYPE\_TOKEN\_TRANSFER
- **Type**: `int`
- **Description**: `TXN_TYPE_TOKEN_TRANSFER` is a global integer variable that represents a specific type of transaction, specifically a token transfer, within the system. It is assigned the value `2`, which is used as an identifier for this transaction type.
- **Use**: This variable is used to specify and identify token transfer transactions in the code.


---
### TXN\_TYPE\_NANO\_TOKEN\_TRANSFER
- **Type**: `int`
- **Description**: `TXN_TYPE_NANO_TOKEN_TRANSFER` is a global integer variable set to the value 3. It is used as a constant to represent a specific type of transaction, namely a 'nano token transfer', within the codebase.
- **Use**: This variable is used to identify and handle nano token transfer transactions in the application.


---
### NANO\_TOKEN\_ID
- **Type**: `Pubkey`
- **Description**: `NANO_TOKEN_ID` is a global variable that holds a `Pubkey` object, which is initialized using the `from_string` method with a specific string representing a public key. This public key is likely used as an identifier for a specific token or program within the Solana blockchain ecosystem.
- **Use**: This variable is used as the owner or program ID in various transaction and account creation operations related to the NANO token.


---
### seed\_file
- **Type**: `file object`
- **Description**: `seed_file` is a global variable that holds a file object opened in read mode. It points to the file located at '../keygrinds/bench-tps.json'. This file is expected to contain JSON data that is subsequently loaded and used in the program.
- **Use**: This variable is used to read JSON data from a file, which is then converted into bytes and used to derive keypairs for cryptographic operations.


---
### top\_seed
- **Type**: `bytes`
- **Description**: The `top_seed` variable is a byte sequence obtained by loading JSON data from a file named `bench-tps.json` and converting it to bytes. This byte sequence is used as a seed for cryptographic operations.
- **Use**: This variable is used to generate key pairs with specific derivation paths for cryptographic operations.


---
### fd\_mint
- **Type**: `Keypair`
- **Description**: The `fd_mint` variable is an instance of the `Keypair` class, created using a seed and a specific derivation path. It represents a cryptographic key pair used in the Solana blockchain ecosystem, specifically for minting tokens.
- **Use**: This variable is used to generate and manage a public/private key pair for minting tokens in the Solana blockchain.


---
### config\_acc
- **Type**: `Keypair`
- **Description**: The `config_acc` variable is an instance of the `Keypair` class, created by loading a JSON configuration file located at `../keygrinds/config.json`. This file is read and its contents are converted into bytes, which are then used to initialize the `Keypair` object.
- **Use**: This variable is used to store a keypair that is likely used for signing transactions or accessing a specific account in the Solana blockchain.


---
### nano\_mint
- **Type**: `Keypair`
- **Description**: The `nano_mint` variable is an instance of the `Keypair` class, created using a seed and a specific derivation path. It represents a cryptographic key pair used in blockchain transactions, specifically for a nano token minting process.
- **Use**: This variable is used to generate and manage a public/private key pair for the nano token minting process, allowing for secure transactions and operations within the blockchain environment.


# Functions

---
### get\_recent\_blockhash<!-- {{#callable:firedancer/contrib/tool/load_gen.get_recent_blockhash}} -->
The `get_recent_blockhash` function retrieves the latest blockhash from a Solana RPC endpoint and returns it as a `Hash` object.
- **Inputs**:
    - `rpc`: A string representing the URL of the Solana RPC endpoint to query for the latest blockhash.
- **Control Flow**:
    - Constructs a JSON-RPC request payload as a string to call the `getLatestBlockhash` method with a `processed` commitment parameter.
    - Sends a POST request to the specified RPC endpoint with the constructed JSON-RPC payload and appropriate headers.
    - Prints the response text received from the RPC endpoint for debugging or logging purposes.
    - Parses the JSON response to extract the blockhash value from the nested result structure.
    - Converts the extracted blockhash string into a `Hash` object using the `Hash.from_string` method.
    - Returns the `Hash` object representing the latest blockhash.
- **Output**: A `Hash` object representing the latest blockhash obtained from the Solana RPC endpoint.


---
### get\_balance<!-- {{#callable:firedancer/contrib/tool/load_gen.get_balance}} -->
The `get_balance` function retrieves the balance of a given account from a specified RPC endpoint using a JSON-RPC request.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL to which the JSON-RPC request will be sent.
    - `acc`: A `Pubkey` object representing the public key of the account whose balance is to be retrieved.
- **Control Flow**:
    - Convert the `acc` parameter to a string to use in the JSON-RPC request.
    - Construct a JSON-RPC request payload to call the `getBalance` method with the account's public key and a commitment level of 'confirmed'.
    - Send a POST request to the specified `rpc` endpoint with the constructed JSON-RPC payload and appropriate headers.
    - Check if the response status code is not 200; if so, return 0 indicating failure to retrieve balance.
    - If the response is successful, parse the JSON response to extract and return the balance value from the 'result' field.
    - If any exception occurs during the process, return 0 as a fallback.
- **Output**: An integer representing the balance of the account, or 0 if the balance could not be retrieved.


---
### get\_account\_info<!-- {{#callable:firedancer/contrib/tool/load_gen.get_account_info}} -->
The `get_account_info` function retrieves account information from a specified RPC endpoint and returns a status code based on the response.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL to which the request is sent.
    - `acc`: A string representing the account identifier for which information is being requested.
- **Control Flow**:
    - Constructs a JSON-RPC request payload with the method `getAccountInfo` and the specified account and parameters.
    - Sends a POST request to the given RPC endpoint with the constructed JSON data and appropriate headers.
    - Checks if the HTTP response status code is not 200, returning 0 if true.
    - Checks if the `value` field in the JSON response is `None`, printing the response and returning 0 if true.
    - Prints the JSON response and returns 1 if the `value` field is not `None`.
- **Output**: Returns an integer status code: 0 if the request fails or the account information is not found, and 1 if the account information is successfully retrieved.


---
### parse\_args<!-- {{#callable:firedancer/contrib/tool/load_gen.parse_args}} -->
The `parse_args` function parses command-line arguments required for configuring and executing transactions on a Solana network.
- **Inputs**: None
- **Control Flow**:
    - An `ArgumentParser` object is created to handle command-line arguments.
    - Several arguments are added to the parser, each with specific flags, types, and requirements.
    - The arguments include TPU endpoints, RPC endpoint, number of keys, seed file, funder file, number of workers, and transaction type.
    - The `parse_args` method of the parser is called to parse the command-line arguments.
    - The parsed arguments are returned as a `Namespace` object.
- **Output**: The function returns an `argparse.Namespace` object containing the parsed command-line arguments.


---
### send\_round\_of\_txs<!-- {{#callable:firedancer/contrib/tool/load_gen.send_round_of_txs}} -->
The `send_round_of_txs` function sends a list of transactions to multiple TPU endpoints using a socket.
- **Inputs**:
    - `txs`: A list of `Transaction` objects that need to be sent.
    - `sock`: A socket object used to send the transactions over UDP.
    - `tpus`: A list of TPU (Transaction Processing Unit) endpoints to which the transactions will be sent.
- **Control Flow**:
    - Iterates over each transaction in the `txs` list using a progress bar provided by `tqdm`.
    - Converts each transaction to a byte format using the `to_solders` method.
    - Iterates over each TPU endpoint in the `tpus` list.
    - Sends the byte-formatted transaction to each TPU endpoint using the `sendto` method of the socket.
    - Pauses for 0.001 seconds after sending each transaction to all TPU endpoints.
- **Output**: The function does not return any value; it sends transactions to the specified TPU endpoints.


---
### fund\_config\_account<!-- {{#callable:firedancer/contrib/tool/load_gen.fund_config_account}} -->
The `fund_config_account` function creates and signs a Solana transaction to fund a configuration account with specified lamports and additional parameters.
- **Inputs**:
    - `funder`: The account (Keypair) that will fund the transaction and sign it.
    - `lamports`: The amount of lamports to be transferred to the configuration account.
    - `recent_blockhash`: The recent blockhash to be used for the transaction.
    - `range`: An additional amount to be added to the lamports for the transaction.
- **Control Flow**:
    - A new Transaction object is created with the recent blockhash, funder's public key, and compute unit settings.
    - The transaction is updated to include an instruction to create an account with the specified lamports plus range, space, and owner parameters.
    - A zero value is converted to bytes to be used as data for the instruction.
    - AccountMeta objects are created for the configuration account, system program ID, and funder, specifying their roles in the transaction.
    - An Instruction object is created with the account metadata, program ID, and data, and added to the transaction.
    - The transaction is signed by the funder and the configuration account.
    - The signed transaction is returned.
- **Output**: A signed Transaction object ready to be sent to the Solana network.


---
### fund\_nano\_mint\_account<!-- {{#callable:firedancer/contrib/tool/load_gen.fund_nano_mint_account}} -->
The `fund_nano_mint_account` function creates and signs a Solana transaction to fund a nano mint account with specified lamports and additional parameters.
- **Inputs**:
    - `funder`: The account (Keypair) that will fund the nano mint account.
    - `lamports`: The amount of lamports to transfer to the nano mint account.
    - `recent_blockhash`: The recent blockhash to be used for the transaction.
    - `range`: An additional amount to be added to the lamports for the transaction.
- **Control Flow**:
    - A new transaction is created with the given recent blockhash and funder's public key, setting compute unit price and limit.
    - An account creation instruction is added to the transaction to create the nano mint account with the specified lamports plus range, space, and owner.
    - Data for the instruction is prepared by converting integers to bytes and concatenating them with the funder's public key bytes.
    - AccountMeta objects are created for the nano mint, config account, system program, and funder, specifying their roles in the transaction.
    - An instruction is created with the prepared accounts and data, and added to the transaction.
    - The transaction is signed by the funder and the nano mint keypair.
    - The signed transaction is returned.
- **Output**: A signed `Transaction` object that funds the nano mint account.


---
### fund\_token\_account<!-- {{#callable:firedancer/contrib/tool/load_gen.fund_token_account}} -->
The `fund_token_account` function creates and signs a Solana transaction to fund a token account with specified lamports and initializes the mint for the token.
- **Inputs**:
    - `funder`: The `funder` is a Keypair object representing the account that will fund the token account and sign the transaction.
    - `lamports`: The `lamports` is an integer representing the amount of lamports to be transferred to the token account.
    - `recent_blockhash`: The `recent_blockhash` is a Hash object representing the recent blockhash to be used in the transaction.
    - `is_print`: The `is_print` is a boolean flag indicating whether to print additional information (not used in the function).
    - `range`: The `range` is an integer added to the lamports to determine the total amount to be transferred.
- **Control Flow**:
    - A new Transaction object is created with the recent blockhash, funder's public key, and compute unit settings.
    - A create_account instruction is added to the transaction to create a new account with the specified lamports plus range, using the funder's public key as the source and the fd_mint's public key as the destination.
    - An InitializeMintParams object is created with the mint's public key, funder's public key as the mint authority, and the TOKEN_PROGRAM_ID.
    - An initialize_mint instruction is added to the transaction using the InitializeMintParams object.
    - The transaction is signed by the funder and the fd_mint keypair.
- **Output**: The function returns the signed Transaction object.


---
### create\_accounts\_tx<!-- {{#callable:firedancer/contrib/tool/load_gen.create_accounts_tx}} -->
The `create_accounts_tx` function constructs and returns a Solana transaction for transferring lamports and optionally setting up token accounts based on the transaction type.
- **Inputs**:
    - `funder`: The keypair of the account funding the transaction.
    - `lamports`: The amount of lamports to transfer to each account.
    - `recent_blockhash`: The recent blockhash to use for the transaction.
    - `txn_type`: The type of transaction, which determines the setup of token accounts (e.g., system transfer, token transfer, nano token transfer).
    - `accs`: A list of accounts to which lamports will be transferred and token accounts may be set up.
- **Control Flow**:
    - Initialize the compute unit limit to 200,000, or 15,000 if the transaction type is NANO_TOKEN_TRANSFER.
    - Create a new transaction with the recent blockhash, funder's public key, and compute unit settings.
    - Iterate over each account in the `accs` list.
    - For each account, add a lamport transfer instruction to the transaction.
    - If the transaction type is TOKEN_TRANSFER, add instructions to create an associated token account and mint tokens to it.
    - If the transaction type is NANO_TOKEN_TRANSFER, derive the nano token address, create the account, and mint tokens to it using specific instructions.
    - Sign the transaction with the funder's keypair.
    - Return the constructed transaction.
- **Output**: A `Transaction` object representing the constructed transaction with all added instructions.


---
### get\_balance\_sufficient<!-- {{#callable:firedancer/contrib/tool/load_gen.get_balance_sufficient}} -->
The `get_balance_sufficient` function checks if an account's balance is sufficient to meet a specified lamport threshold and returns the account if it is, otherwise returns None.
- **Inputs**:
    - `lamports`: The minimum balance threshold in lamports that the account must have.
    - `rpc`: The RPC endpoint URL as a string to query the account balance.
    - `acc`: The account object whose balance is to be checked, which must have a `pubkey()` method.
- **Control Flow**:
    - Call [`get_balance`](#get_balance) with `rpc` and `acc.pubkey()` to retrieve the account's balance.
    - If the balance is non-zero, print a message indicating the account's public key and its balance.
    - Check if the retrieved balance is greater than or equal to the specified `lamports`.
    - If the balance is sufficient, return the account object `acc`.
    - If the balance is insufficient, return `None`.
- **Output**: Returns the account object `acc` if the balance is sufficient, otherwise returns `None`.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen.get_balance`](#get_balance)


---
### create\_accounts<!-- {{#callable:firedancer/contrib/tool/load_gen.create_accounts}} -->
The `create_accounts` function generates and funds a specified number of accounts on the Solana blockchain, handling different transaction types and ensuring accounts have sufficient balance.
- **Inputs**:
    - `funder`: The account that will fund the new accounts.
    - `rpc`: The RPC endpoint URL for interacting with the Solana blockchain.
    - `num_accs`: The number of accounts to create.
    - `lamports`: The amount of lamports to fund each account with.
    - `seed`: The seed used to derive the keypairs for the accounts.
    - `sock`: The socket used for sending transactions.
    - `tpus`: A list of TPU (Transaction Processing Unit) endpoints to send transactions to.
    - `txn_type`: The type of transaction to perform, which affects how accounts are funded and set up.
- **Control Flow**:
    - Retrieve account information for the funder's mint account and print its balance.
    - Generate keypairs for the specified number of accounts using the provided seed and store them in a list.
    - Divide the list of accounts into chunks for batch processing.
    - Retrieve the recent blockhash from the blockchain.
    - Create and send transactions to fund the accounts in parallel using the `pqdm` library.
    - Check if additional configuration or mint accounts need funding based on the transaction type and fund them if necessary.
    - Iteratively check the balance of each account to ensure they have been funded sufficiently, removing accounts from the list once they are confirmed funded.
    - Continue funding accounts in chunks until all accounts have sufficient balance.
    - Return the list of created accounts.
- **Output**: A list of created and funded account keypairs.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen.get_account_info`](#get_account_info)
    - [`firedancer/contrib/tool/load_gen.get_balance`](#get_balance)
    - [`firedancer/contrib/tool/load_gen.get_recent_blockhash`](#get_recent_blockhash)
    - [`firedancer/contrib/tool/load_gen.send_round_of_txs`](#send_round_of_txs)
    - [`firedancer/contrib/tool/load_gen.fund_config_account`](#fund_config_account)


---
### gen\_tx\_empty<!-- {{#callable:firedancer/contrib/tool/load_gen.gen_tx_empty}} -->
The `gen_tx_empty` function creates and signs a Solana transaction with a specified compute unit price and limit, using a given recent blockhash, key, and account.
- **Inputs**:
    - `recent_blockhash`: A recent blockhash used to initialize the transaction, ensuring it is processed in a timely manner.
    - `key`: A keypair used to sign the transaction, providing the necessary authorization.
    - `acc`: The account associated with the transaction, which will be used as the fee payer.
    - `cu_price`: The compute unit price to be set for the transaction, determining the cost of compute resources.
- **Control Flow**:
    - A new Transaction object is created using the provided recent blockhash, account, and a list of instructions to set the compute unit price and limit.
    - The transaction is signed using the provided keypair.
    - The signed transaction is returned.
- **Output**: A signed Transaction object ready to be sent to the Solana network.


---
### gen\_tx\_system\_transfer<!-- {{#callable:firedancer/contrib/tool/load_gen.gen_tx_system_transfer}} -->
The `gen_tx_system_transfer` function creates and signs a Solana transaction for a system transfer with specified compute unit price and limits.
- **Inputs**:
    - `recent_blockhash`: A recent blockhash used to initialize the transaction, ensuring it is processed in a timely manner.
    - `key`: A Keypair object used to sign the transaction, providing the necessary authorization.
    - `acc`: A public key (Pubkey) representing the account from which the transfer is initiated and to which it is sent.
    - `cu_price`: An integer representing the compute unit price to be set for the transaction.
- **Control Flow**:
    - A Transaction object is created using the provided recent blockhash, account, and compute unit settings.
    - A transfer instruction is added to the transaction, specifying a transfer of 1 lamport from the account to itself.
    - The transaction is signed using the provided keypair, authorizing the transaction.
    - The signed transaction is returned.
- **Output**: A signed Transaction object ready to be sent to the Solana network for processing.


---
### gen\_tx\_token\_transfer<!-- {{#callable:firedancer/contrib/tool/load_gen.gen_tx_token_transfer}} -->
The `gen_tx_token_transfer` function generates a Solana transaction for transferring a token using the SPL Token program.
- **Inputs**:
    - `recent_blockhash`: The recent blockhash to be used in the transaction, ensuring it is processed in a timely manner.
    - `key`: A Keypair object representing the signer of the transaction, which provides the public key and private key for signing.
    - `acc`: The public key of the account that will pay for the transaction fees.
    - `cu_price`: The price of compute units to be set for the transaction, affecting the transaction fee.
- **Control Flow**:
    - A new Transaction object is created with the provided recent blockhash, account, and compute unit settings.
    - The associated token address (ATA) for the given key and mint is retrieved using `get_associated_token_address`.
    - A `SplTransferParams` object is created to define the parameters for the token transfer, including the source and destination addresses, owner, and amount.
    - The SPL token transfer instruction is added to the transaction using `spl_transfer` with the defined parameters.
    - The transaction is signed using the provided keypair.
    - The signed transaction is returned.
- **Output**: The function returns a signed Transaction object ready to be sent to the Solana network for processing the token transfer.


---
### gen\_tx\_nano\_token\_transfer<!-- {{#callable:firedancer/contrib/tool/load_gen.gen_tx_nano_token_transfer}} -->
The `gen_tx_nano_token_transfer` function generates a transaction for transferring a nano token between two accounts on the Solana blockchain.
- **Inputs**:
    - `recent_blockhash`: The recent blockhash used to ensure the transaction is processed in a timely manner.
    - `src_key`: The keypair of the source account, used to sign the transaction.
    - `dst_key`: The keypair of the destination account, although not directly used in this function.
    - `src_acc`: The public key of the source account from which the nano token will be transferred.
    - `dst_acc`: The public key of the destination account to which the nano token will be transferred.
    - `cu_price`: The compute unit price, although not directly used in this function.
- **Control Flow**:
    - A new transaction is initialized with the recent blockhash, source account, and a compute unit limit of 198.
    - The nano token addresses for the source and destination accounts are derived using the mint id, nano token program id, and account public keys.
    - Instruction data is constructed with a transfer tag and amount, and account metadata is prepared for the source and destination nano token addresses and the source account.
    - An instruction is created with the nano token program id, the prepared accounts, and the constructed data, and added to the transaction.
    - The transaction is signed using the source keypair.
    - The transaction is returned.
- **Output**: A signed `Transaction` object representing the nano token transfer.


---
### send\_txs<!-- {{#callable:firedancer/contrib/tool/load_gen.send_txs}} -->
The `send_txs` function sends transactions to specified TPU endpoints using a list of keypairs and transaction types, while monitoring for changes in the recent blockhash and adjusting compute unit prices accordingly.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL for blockchain interaction.
    - `tpus`: A list of strings representing TPU UDP endpoints to send transactions to.
    - `keys`: A list of Keypair objects used to sign transactions.
    - `tx_idx`: A shared multiprocessing Value object used to track the index of transactions.
    - `mult`: An integer multiplier, though not used in the function body.
    - `idx`: An integer index used for identifying the worker process.
    - `stop_event`: A multiprocessing Event object used to signal when to stop sending transactions.
    - `rbh`: A shared multiprocessing Array object containing the recent blockhash.
    - `txn_type`: An integer representing the type of transaction to generate and send.
- **Control Flow**:
    - Initialize a UDP socket for sending transactions.
    - Convert the list of keypairs to a list of public keys.
    - Retrieve the initial recent blockhash from the shared array.
    - Enter a loop that continues until the stop_event is set.
    - Within the loop, update the recent blockhash and adjust the compute unit price if the blockhash has not changed.
    - Iterate over each keypair to generate a transaction based on the specified transaction type.
    - Convert the transaction to bytes and send it to each TPU endpoint.
    - Update the transaction index by the number of keys processed.
    - Print a stopping message when the loop exits.
- **Output**: The function does not return any value; it sends transactions over the network and updates the transaction index.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen.gen_tx_empty`](#gen_tx_empty)
    - [`firedancer/contrib/tool/load_gen.gen_tx_system_transfer`](#gen_tx_system_transfer)
    - [`firedancer/contrib/tool/load_gen.gen_tx_token_transfer`](#gen_tx_token_transfer)
    - [`firedancer/contrib/tool/load_gen.gen_tx_nano_token_transfer`](#gen_tx_nano_token_transfer)


---
### monitor\_send\_tps<!-- {{#callable:firedancer/contrib/tool/load_gen.monitor_send_tps}} -->
The `monitor_send_tps` function monitors and prints the transactions per second (TPS) over a specified interval, adjusting the interval if no transactions are detected.
- **Inputs**:
    - `tx_idx`: A shared multiprocessing.Value object that holds the current transaction count.
    - `stop_event`: A multiprocessing.Event object used to signal when the monitoring should stop.
    - `interval`: An optional integer specifying the time interval in seconds for monitoring TPS, defaulting to 1.
- **Control Flow**:
    - Initialize `prev_count` to 0 and `prev_time` to the current time.
    - Enter a while loop that continues as long as `interval` is less than 10 and `stop_event` is not set.
    - Sleep for the duration of `interval`.
    - Acquire a lock on `tx_idx` to safely read the current transaction count into `current_count`.
    - Calculate the current time and compute TPS as the difference in transaction count divided by `interval`.
    - Update `prev_count` to `current_count` and calculate the elapsed time since `prev_time`.
    - Print the TPS and elapsed time.
    - If TPS is zero, increment the `interval` by 1.
    - Update `prev_time` to the current time.
- **Output**: The function does not return any value; it outputs TPS and elapsed time to the console.


---
### fetch\_recent\_blockhash<!-- {{#callable:firedancer/contrib/tool/load_gen.fetch_recent_blockhash}} -->
The `fetch_recent_blockhash` function continuously updates a shared memory array with the latest blockhash from a Solana RPC endpoint until a stop event is triggered.
- **Inputs**:
    - `rbh`: A shared memory array that will be updated with the latest blockhash as bytes.
    - `rpc`: A string representing the RPC endpoint URL to fetch the recent blockhash from.
    - `stop_event`: A threading event used to signal when the function should stop executing.
- **Control Flow**:
    - Initialize `prev_recent_blockhash` with the current blockhash fetched from the RPC endpoint using [`get_recent_blockhash`](#get_recent_blockhash) function.
    - Enter a loop that continues until `stop_event` is set.
    - Within the loop, sleep for 0.1 seconds to avoid excessive requests.
    - Attempt to fetch the latest blockhash from the RPC endpoint.
    - If the fetched blockhash is different from `prev_recent_blockhash`, update `rbh` with the new blockhash and set `prev_recent_blockhash` to this new value.
    - Print the new blockhash if it is different from the previous one.
    - If an exception occurs during the fetch, print 'bad RBH'.
- **Output**: The function does not return any value; it updates the `rbh` shared memory array with the latest blockhash.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen.get_recent_blockhash`](#get_recent_blockhash)


---
### main<!-- {{#callable:firedancer/contrib/tool/load_gen.main}} -->
The `main` function initializes and orchestrates the process of creating accounts and sending transactions to specified TPU endpoints using multiprocessing and threading.
- **Inputs**: None
- **Control Flow**:
    - Parse command-line arguments using `parse_args()` to get necessary parameters like RPC endpoint, seed file, funder file, TPU endpoints, number of keys, number of workers, and transaction type.
    - Initialize a `Client` object with the RPC endpoint and read the seed and funder key from the specified files.
    - Create a UDP socket and parse the TPU endpoints into a list of tuples containing IP and port.
    - Determine the transaction type based on the `txn_type` argument and set the corresponding constant value.
    - Call [`create_accounts`](#create_accounts) to generate and fund the specified number of accounts using the funder key, seed, and other parameters.
    - Divide the created accounts into chunks based on the number of workers for parallel processing.
    - Initialize shared memory objects for recent blockhash (`rbh`), a stop event, and a transaction index counter (`tx_idx`).
    - Start a monitoring thread to track transactions per second and a fetching thread to update the recent blockhash periodically.
    - Create and start multiple worker processes to send transactions using the `send_txs` function, each handling a chunk of accounts.
    - Enter a try-finally block to continuously run the main loop, sleeping briefly in each iteration, and ensure all processes and threads are properly terminated when the program exits.
- **Output**: The function does not return any value; it orchestrates the execution of the transaction sending process and manages resources like threads and processes.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen.parse_args`](#parse_args)
    - [`firedancer/contrib/tool/load_gen.create_accounts`](#create_accounts)


