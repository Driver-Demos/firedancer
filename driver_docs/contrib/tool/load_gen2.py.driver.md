# Purpose
This Python script is designed to facilitate the creation and management of transactions on the Solana blockchain. It serves as a command-line tool that interacts with Solana's RPC (Remote Procedure Call) endpoints to perform various operations such as fetching recent block hashes, checking account balances, creating accounts, and sending transactions. The script is structured to handle different types of transactions, including empty transactions, system transfers, and token transfers, as indicated by the constants `TXN_TYPE_EMPTY`, `TXN_TYPE_SYSTEM_TRANSFER`, and `TXN_TYPE_TOKEN_TRANSFER`. It leverages multiprocessing and threading to efficiently manage and send transactions in parallel, ensuring high throughput and performance.

The script's main components include functions for parsing command-line arguments, creating and funding accounts, generating transactions, and monitoring transaction throughput. It uses external libraries such as `requests` for HTTP requests, `tqdm` for progress bars, and `pqdm` for parallel processing. The script defines a public API through its command-line interface, requiring users to specify parameters like TPU endpoints, RPC URL, number of keys, seed file, funder file, number of workers, and transaction type. The [`main`](#main) function orchestrates the overall workflow, setting up necessary resources and launching worker processes to handle transaction sending. This script is intended for users who need to automate and manage large-scale transaction operations on the Solana blockchain.
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
- `solana.rpc.types.TxOpts`
- `solders.keypair.Keypair`
- `solders.system_program.TransferParams`
- `solders.system_program.transfer`
- `solders.compute_budget.set_compute_unit_limit`
- `solders.compute_budget.set_compute_unit_price`
- `solders.pubkey.Pubkey`
- `solders.signature.Signature`
- `solders.message.Message`
- `solders.instruction.AccountMeta`
- `solders.instruction.Instruction`


# Global Variables

---
### TXN\_TYPE\_EMPTY
- **Type**: `int`
- **Description**: `TXN_TYPE_EMPTY` is a global integer variable that represents a transaction type with a value of 0. It is used to identify transactions that are considered 'empty', meaning they do not perform any significant operation.
- **Use**: This variable is used to specify the type of transaction when generating or sending transactions, particularly in the `send_txs` function.


---
### TXN\_TYPE\_SYSTEM\_TRANSFER
- **Type**: `int`
- **Description**: `TXN_TYPE_SYSTEM_TRANSFER` is a global integer variable that represents a specific type of transaction, specifically a system transfer, within the application. It is assigned the value of 1, distinguishing it from other transaction types such as empty transactions or token transfers.
- **Use**: This variable is used to identify and handle system transfer transactions within the code, particularly in functions that generate or send transactions.


---
### TXN\_TYPE\_TOKEN\_TRANSFER
- **Type**: `int`
- **Description**: `TXN_TYPE_TOKEN_TRANSFER` is a global integer variable that represents a specific type of transaction, specifically a token transfer, within the application. It is assigned the value `2`, which is used as an identifier for this transaction type.
- **Use**: This variable is used to determine the type of transaction to be executed, particularly when the transaction involves transferring tokens.


# Functions

---
### get\_recent\_blockhash<!-- {{#callable:firedancer/contrib/tool/load_gen2.get_recent_blockhash}} -->
The `get_recent_blockhash` function retrieves the latest blockhash from a Solana RPC endpoint and returns it as a `Hash` object.
- **Inputs**:
    - `rpc`: A string representing the URL of the Solana RPC endpoint to query for the latest blockhash.
- **Control Flow**:
    - Constructs a JSON-RPC request payload as a string to call the `getLatestBlockhash` method with no parameters.
    - Sends a POST request to the specified RPC endpoint with the constructed JSON-RPC payload and appropriate headers.
    - Parses the JSON response to extract the blockhash value from the nested dictionary structure.
    - Converts the extracted blockhash string into a `Hash` object using the `Hash.from_string` method.
    - Returns the `Hash` object representing the latest blockhash.
- **Output**: A `Hash` object representing the latest blockhash retrieved from the Solana RPC endpoint.


---
### get\_balance<!-- {{#callable:firedancer/contrib/tool/load_gen2.get_balance}} -->
The `get_balance` function retrieves the balance of a given Solana account using an RPC endpoint.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL to connect to the Solana network.
    - `acc`: A `Pubkey` object representing the public key of the Solana account whose balance is to be retrieved.
- **Control Flow**:
    - The function attempts to retrieve the account balance up to 10 times in a loop.
    - Within the loop, it converts the `acc` public key to a string and constructs a JSON-RPC request payload to get the balance with a 'confirmed' commitment.
    - It sends the request to the specified `rpc` endpoint using an HTTP POST request.
    - If the response status code is not 200, it returns 0, indicating failure to retrieve the balance.
    - If the response is successful, it extracts and returns the balance value from the JSON response.
    - If an exception occurs during the process, it waits for 0.1 seconds and retries the operation.
- **Output**: An integer representing the balance of the specified account, or 0 if the balance could not be retrieved.


---
### parse\_args<!-- {{#callable:firedancer/contrib/tool/load_gen2.parse_args}} -->
The `parse_args` function parses command-line arguments required for configuring and executing a transaction sending process.
- **Inputs**: None
- **Control Flow**:
    - An `ArgumentParser` object is created to handle command-line argument parsing.
    - Several arguments are added to the parser, each with specific flags, types, and requirements: `--tpus`, `--rpc`, `--nkeys`, `--seed`, `--funder`, `--workers`, and `--txn-type`.
    - The `parse_args` method of the parser is called to parse the command-line arguments and store them in the `args` variable.
    - The parsed arguments are returned as an `argparse.Namespace` object.
- **Output**: The function returns an `argparse.Namespace` object containing the parsed command-line arguments.


---
### send\_round\_of\_txs<!-- {{#callable:firedancer/contrib/tool/load_gen2.send_round_of_txs}} -->
The `send_round_of_txs` function sends a batch of transactions to multiple TPU endpoints using a UDP socket.
- **Inputs**:
    - `txs`: A list of transactions to be sent.
    - `sock`: A UDP socket object used to send the transactions.
    - `tpus`: A list of TPU (Transaction Processing Unit) endpoints to which the transactions will be sent.
    - `rpc`: A string representing the RPC endpoint used to initialize the Solana client.
    - `funder`: An unused parameter in the function, possibly intended for future use or for compatibility with other functions.
- **Control Flow**:
    - Initialize a Solana RPC client using the provided RPC endpoint.
    - Iterate over each transaction in the `txs` list, displaying a progress bar using `tqdm`.
    - Convert each transaction to a byte message using the `to_solders` method.
    - For each TPU endpoint in the `tpus` list, send the byte message using the UDP socket.
    - Pause for 0.001 seconds after sending each transaction to all TPU endpoints.
- **Output**: The function does not return any value; it sends transactions over the network to specified TPU endpoints.


---
### create\_accounts\_tx<!-- {{#callable:firedancer/contrib/tool/load_gen2.create_accounts_tx}} -->
The `create_accounts_tx` function constructs and signs a Solana transaction to transfer a specified amount of lamports from a funder to multiple accounts.
- **Inputs**:
    - `funder`: The account (Keypair) that will fund the transactions, providing the lamports to be transferred.
    - `lamports`: The amount of lamports to be transferred to each account.
    - `recent_blockhash`: The recent blockhash to be used for the transaction, ensuring it is processed in the current block.
    - `accs`: A list of accounts (Keypair) to which the lamports will be transferred.
- **Control Flow**:
    - A new Transaction object is created using the provided recent blockhash, with the funder's public key as the fee payer.
    - The transaction is initialized with a compute unit price set to 1.
    - For each account in the `accs` list, a transfer instruction is added to the transaction, specifying the funder's public key as the source and the account's public key as the destination, with the specified lamports amount.
    - The transaction is signed by the funder to authorize the transfer of lamports.
    - The signed transaction is returned.
- **Output**: A signed Transaction object ready to be sent to the Solana network for processing.


---
### get\_balance\_sufficient<!-- {{#callable:firedancer/contrib/tool/load_gen2.get_balance_sufficient}} -->
The `get_balance_sufficient` function checks if an account has a balance greater than or equal to a specified amount of lamports and returns the account if true, otherwise returns None.
- **Inputs**:
    - `lamports`: The minimum balance in lamports that the account should have.
    - `rpc`: The RPC endpoint URL as a string to query the balance.
    - `acc`: The account object whose balance is to be checked.
- **Control Flow**:
    - The function first attempts to return the account object `acc` immediately, which seems to be an error in the code as it bypasses the balance check.
    - It then calls the [`get_balance`](#get_balance) function with the `rpc` and the public key of `acc` to retrieve the current balance of the account.
    - If the retrieved balance is greater than or equal to the specified `lamports`, it returns the account `acc`.
    - If the balance is less than the specified `lamports`, it returns `None`.
- **Output**: The function returns the account object `acc` if its balance is sufficient, otherwise it returns `None`. However, due to the immediate return statement at the beginning, it currently always returns `acc`.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen2.get_balance`](#get_balance)


---
### create\_accounts<!-- {{#callable:firedancer/contrib/tool/load_gen2.create_accounts}} -->
The `create_accounts` function generates a specified number of Solana accounts, checks their balance, and funds them if necessary using parallel processing.
- **Inputs**:
    - `funder`: The Keypair object representing the account that will fund the new accounts.
    - `rpc`: A string representing the RPC endpoint to interact with the Solana blockchain.
    - `num_accs`: An integer specifying the number of accounts to create.
    - `lamports`: An integer representing the amount of lamports each account should have.
    - `seed`: A string used as a seed for generating account keypairs.
    - `sock`: A socket object used for sending transactions.
    - `tpus`: A list of TPU (Transaction Processing Unit) endpoints to send transactions to.
    - `txn_type`: An integer representing the type of transaction to be used.
- **Control Flow**:
    - Initialize an empty list `accs` to store the generated accounts.
    - Iterate over the range of `num_accs` to create keypairs using the provided seed and append them to `accs`.
    - Convert `accs` to a set `remaining_accs` to track accounts that need funding.
    - While there are accounts in `remaining_accs`, check their balance using `pqdm` for parallel processing.
    - Remove accounts from `remaining_accs` if they have sufficient balance.
    - If `remaining_accs` is empty, break the loop.
    - Divide `remaining_accs` into chunks of size 8 and get the recent blockhash from the RPC.
    - Create transactions to fund the accounts using `pqdm` for parallel processing.
    - Send the transactions using [`send_round_of_txs`](#send_round_of_txs).
- **Output**: Returns a list of Keypair objects representing the created accounts.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen2.get_recent_blockhash`](#get_recent_blockhash)
    - [`firedancer/contrib/tool/load_gen2.send_round_of_txs`](#send_round_of_txs)


---
### gen\_tx\_empty<!-- {{#callable:firedancer/contrib/tool/load_gen2.gen_tx_empty}} -->
The `gen_tx_empty` function generates and signs a Solana transaction with a specified compute unit price and a 'noop' instruction.
- **Inputs**:
    - `recent_blockhash`: The recent blockhash to be used in the transaction, ensuring it is processed in the correct block.
    - `key`: The keypair used to sign the transaction, providing authentication and authorization.
    - `acc`: The account public key that will be used as the fee payer for the transaction.
    - `cu_price`: An integer representing the compute unit price to be set in the transaction.
- **Control Flow**:
    - A `Transaction` object is created using the provided `recent_blockhash`, `acc`, and a list of instructions.
    - The list of instructions includes setting a compute unit limit of 152 and a 'noop' instruction with the compute unit price converted to bytes.
    - The transaction is signed using the provided `key`.
    - The signed transaction is returned.
- **Output**: A signed `Transaction` object ready to be sent to the Solana network.


---
### gen\_tx\_system\_transfer<!-- {{#callable:firedancer/contrib/tool/load_gen2.gen_tx_system_transfer}} -->
The `gen_tx_system_transfer` function generates a Solana transaction for a system transfer with specified compute unit price and limits.
- **Inputs**:
    - `recent_blockhash`: The recent blockhash to be used in the transaction.
    - `key`: The key used for signing the transaction.
    - `acc`: The account public key involved in the transfer.
    - `cu_price`: The compute unit price to be set for the transaction.
- **Control Flow**:
    - Creates a message with a compute unit price, compute unit limit, and a transfer instruction using the provided account and blockhash.
    - Populates a transaction with the created message and a random signature.
    - Returns the populated transaction.
- **Output**: A `Transaction` object representing the system transfer with the specified parameters.


---
### send\_txs<!-- {{#callable:firedancer/contrib/tool/load_gen2.send_txs}} -->
The `send_txs` function sends transactions to specified TPU endpoints using a list of keypairs and monitors for changes in the recent blockhash to adjust compute unit pricing.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL.
    - `tpus`: A list of strings representing the TPU UDP endpoints to send transactions to.
    - `keys`: A list of Keypair objects used to sign transactions.
    - `tx_idx`: A shared multiprocessing Value object used to track the number of transactions sent.
    - `mult`: An integer multiplier, though not used in the function body.
    - `idx`: An integer index used for identifying the worker process.
    - `stop_event`: A multiprocessing Event object used to signal when to stop sending transactions.
    - `rbh`: A shared multiprocessing Array containing the recent blockhash as bytes.
    - `txn_type`: An integer representing the type of transaction to send (e.g., empty, system transfer, token transfer).
- **Control Flow**:
    - A UDP socket is created for sending transactions.
    - The public keys are extracted from the provided keypairs.
    - The recent blockhash is initialized from the provided bytes array.
    - A loop runs until the stop_event is set, continuously checking for changes in the recent blockhash.
    - If the blockhash remains the same, the compute unit price is incremented; otherwise, it is reset to 1.
    - For each keypair, a transaction is generated based on the specified transaction type.
    - The transaction is serialized and sent to each TPU endpoint using the UDP socket.
    - The transaction index is incremented by the number of keys after sending all transactions.
    - The loop measures the time taken for sending transactions and prints a stopping message when the loop exits.
- **Output**: The function does not return any value; it sends transactions over the network and updates the transaction index.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen2.gen_tx_empty`](#gen_tx_empty)
    - [`firedancer/contrib/tool/load_gen2.gen_tx_system_transfer`](#gen_tx_system_transfer)


---
### monitor\_send\_tps<!-- {{#callable:firedancer/contrib/tool/load_gen2.monitor_send_tps}} -->
The `monitor_send_tps` function monitors and prints the transactions per second (TPS) at regular intervals, adjusting the interval if no transactions are detected.
- **Inputs**:
    - `tx_idx`: A synchronized shared integer value representing the transaction index, used to track the number of transactions.
    - `stop_event`: A multiprocessing event used to signal when the monitoring should stop.
    - `interval`: An optional integer specifying the time interval in seconds between TPS calculations, defaulting to 1.
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
### fetch\_recent\_blockhash<!-- {{#callable:firedancer/contrib/tool/load_gen2.fetch_recent_blockhash}} -->
The `fetch_recent_blockhash` function continuously fetches the latest blockhash from a Solana RPC endpoint and updates a shared memory array with the new blockhash if it changes.
- **Inputs**:
    - `rbh`: A shared memory array that will be updated with the latest blockhash as a byte sequence.
    - `rpc`: A string representing the RPC endpoint URL from which to fetch the latest blockhash.
    - `stop_event`: A threading event used to signal when the function should stop running.
- **Control Flow**:
    - Initialize `prev_recent_blockhash` with the current blockhash fetched from the RPC endpoint using [`get_recent_blockhash`](#get_recent_blockhash) function.
    - Enter a loop that continues until `stop_event` is set.
    - Within the loop, sleep for 0.1 seconds to prevent excessive requests to the RPC endpoint.
    - Attempt to fetch the latest blockhash from the RPC endpoint.
    - If the fetched blockhash is the same as `prev_recent_blockhash`, continue to the next iteration of the loop.
    - If the fetched blockhash is different, update the `rbh` array with the new blockhash and set `prev_recent_blockhash` to this new value.
    - Print the new blockhash to the console.
    - If an exception occurs during the blockhash fetch, print 'bad RBH' to the console.
- **Output**: The function does not return any value; it updates the `rbh` shared memory array with the latest blockhash when it changes.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen2.get_recent_blockhash`](#get_recent_blockhash)


---
### main<!-- {{#callable:firedancer/contrib/tool/load_gen2.main}} -->
The `main` function initializes and manages the process of creating accounts and sending transactions to specified TPU endpoints using multiprocessing and threading.
- **Inputs**: None
- **Control Flow**:
    - Parse command-line arguments using `parse_args()` to get necessary parameters like RPC endpoint, seed file, funder file, TPU endpoints, number of keys, number of workers, and transaction type.
    - Initialize a `Client` object with the RPC endpoint and read the seed and funder key from the specified files.
    - Create a UDP socket for communication and parse the TPU endpoints into a list of tuples containing host and port.
    - Determine the transaction type based on the `txn_type` argument and set the corresponding constant value.
    - Call [`create_accounts`](#create_accounts) to generate the required number of accounts using the funder, RPC endpoint, and other parameters.
    - Divide the created accounts into chunks based on the number of workers specified.
    - Initialize shared memory structures like `Array` for recent blockhash, `Event` for stopping processes, and `Value` for transaction index counter.
    - Start a monitoring thread to track transactions per second and a fetching thread to update the recent blockhash periodically.
    - Create and start multiple worker processes to send transactions using the `send_txs` function, each handling a chunk of accounts.
    - Enter a loop to keep the main process alive, periodically sleeping, and set the stop event when interrupted.
    - Join all worker processes to ensure they complete before the program exits.
- **Output**: The function does not return any value; it orchestrates the execution of transaction sending processes and threads.
- **Functions called**:
    - [`firedancer/contrib/tool/load_gen2.parse_args`](#parse_args)
    - [`firedancer/contrib/tool/load_gen2.create_accounts`](#create_accounts)


