# Purpose
This C source code file implements a command-line tool named `fd_blockstore_tool` that interacts with a RocksDB database to process and aggregate blockchain data. The tool provides three main functionalities: aggregating data into CSV files in either "microblock" or "batch" formats, and printing information about shred payload sizes. The code is structured to handle command-line arguments, initialize necessary resources, and perform operations based on the specified mode. It uses the RocksDB database to read and import data within specified slot ranges, and then processes this data to generate CSV outputs or display information.

The file includes several key components, such as functions for initializing the blockstore and RocksDB, aggregating entries, and writing data to CSV files. It defines data structures like `fd_batch_row_t` and `fd_entry_row_t` to represent rows in the CSV outputs. The code is designed to be executed as a standalone program, with a [`main`](#main) function that parses command-line arguments, sets up the environment, and calls the appropriate aggregation or investigation functions based on user input. The tool is intended for use in environments where blockchain data needs to be analyzed or exported, providing a focused set of functionalities for data aggregation and inspection.
# Imports and Dependencies

---
- `../../flamenco/runtime/fd_blockstore.h`
- `../../flamenco/runtime/fd_rocksdb.h`
- `unistd.h`
- `stdio.h`


# Data Structures

---
### fd\_batch\_row
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the batch row.
    - `ref_tick`: An integer representing a reference tick or timestamp for the batch row.
    - `sz`: The size of the batch row in bytes.
    - `shred_cnt`: The count of shreds in the batch row.
- **Description**: The `fd_batch_row` structure is used to represent a row of batch data, typically for aggregation into a CSV file. It contains information about a specific slot, including a reference tick, the size of the data in bytes, and the number of shreds associated with that slot. This structure is part of a larger system that processes and aggregates data from a blockstore, likely for analysis or reporting purposes.


---
### fd\_batch\_row\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the batch row.
    - `ref_tick`: An integer representing a reference tick for the batch.
    - `sz`: The size of the batch in bytes.
    - `shred_cnt`: The count of shreds in the batch.
- **Description**: The `fd_batch_row_t` structure is used to represent a row of batch data in a CSV file, specifically for aggregating data from a RocksDB database. It contains fields for the slot number, a reference tick, the size of the batch in bytes, and the count of shreds in the batch. This structure is utilized in functions that handle batch data aggregation and CSV file writing, providing a standardized format for batch data representation.


---
### fd\_entry\_row
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the entry.
    - `batch_idx`: Indicates the index of the batch within the slot.
    - `ref_tick`: Stores a reference tick value for timing or synchronization purposes.
    - `sz`: Holds the size in bytes of the entry.
    - `txn_cnt`: Counts the number of transactions in the entry.
    - `hashcnt_from_slot_start`: Tracks the cumulative hash count from the start of the slot.
- **Description**: The `fd_entry_row` structure is designed to encapsulate information about a specific entry within a blockstore system, particularly in the context of batch processing. It includes fields for identifying the slot and batch index, as well as metrics such as the size of the entry, the number of transactions, and a hash count from the start of the slot. This structure is used to organize and manage data entries for efficient processing and storage in a distributed ledger or database system.


---
### fd\_entry\_row\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the entry.
    - `batch_idx`: Indicates the index of the batch within the slot.
    - `ref_tick`: Stores a reference tick value for the entry.
    - `sz`: Holds the size of the entry in bytes.
    - `txn_cnt`: Counts the number of transactions in the entry.
    - `hashcnt_from_slot_start`: Tracks the number of hashes from the start of the slot.
- **Description**: The `fd_entry_row_t` structure is designed to represent a row of data entries within a blockstore system, specifically for microblock aggregation. It contains fields to store information about the slot, batch index, reference tick, size in bytes, transaction count, and the number of hashes from the start of the slot. This structure is used to organize and manage data entries for efficient processing and storage in a blockstore environment.


# Functions

---
### usage<!-- {{#callable:usage}} -->
The `usage` function prints the usage instructions for the `fd_blockstore_tool` command-line tool to the standard error stream.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fprintf` to print a detailed usage message to `stderr`.
    - The usage message includes the command format, description of operations, and options with their requirements.
    - The function then returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### entry\_write\_header<!-- {{#callable:entry_write_header}} -->
The `entry_write_header` function creates a new CSV file and writes a header line for entry data.
- **Inputs**:
    - `filename`: A constant character pointer representing the name of the file to be created and written to.
- **Control Flow**:
    - Attempt to open the file specified by `filename` in write mode.
    - Check if the file was successfully opened; if not, print an error message and return.
    - Write the header line 'slot,batch_idx,ref_tick,hash_count_from_start,sz,txn_cnt' to the file.
    - Close the file.
- **Output**: The function does not return any value; it performs file operations to create and write to a file.


---
### batch\_write\_header<!-- {{#callable:batch_write_header}} -->
The `batch_write_header` function opens a file for writing and writes a CSV header line specific to batch data.
- **Inputs**:
    - `filename`: A constant character pointer representing the name of the file to be opened and written to.
- **Control Flow**:
    - The function attempts to open the specified file in write mode using `fopen`.
    - It checks if the file was successfully opened; if not, it prints an error message using `perror` and returns immediately.
    - If the file is successfully opened, it writes the CSV header line 'slot,ref_tick,sz,shred_cnt\n' to the file using `fprintf`.
    - Finally, it closes the file using `fclose`.
- **Output**: The function does not return any value; it performs file operations and writes a header to the specified file.


---
### batch\_append\_csv<!-- {{#callable:batch_append_csv}} -->
The `batch_append_csv` function appends a row of batch data to a specified CSV file.
- **Inputs**:
    - `filename`: A constant character pointer representing the name of the CSV file to which the data will be appended.
    - `row`: A pointer to an `fd_batch_row_t` structure containing the batch data to be written to the CSV file, including slot, ref_tick, size, and shred count.
- **Control Flow**:
    - Open the specified file in append mode using `fopen` with the filename and "a" mode.
    - Check if the file was opened successfully; if not, print an error message using `perror` and return immediately.
    - Use `fprintf` to write the data from the `row` structure to the file in CSV format, with fields separated by commas.
    - Close the file using `fclose` to ensure all data is flushed and resources are released.
- **Output**: The function does not return any value; it performs file operations to append data to a CSV file.


---
### entry\_append\_csv<!-- {{#callable:entry_append_csv}} -->
The `entry_append_csv` function appends a row of data to a CSV file specified by the filename, using the data from a `fd_entry_row_t` structure.
- **Inputs**:
    - `filename`: A constant character pointer representing the name of the CSV file to which the data will be appended.
    - `row`: A pointer to an `fd_entry_row_t` structure containing the data to be written to the CSV file.
- **Control Flow**:
    - Open the file specified by `filename` in append mode using `fopen`.
    - Check if the file was successfully opened; if not, print an error message using `perror` and return immediately.
    - Use `fprintf` to write the data from the `row` structure to the file in CSV format, with fields separated by commas.
    - Close the file using `fclose`.
- **Output**: The function does not return any value; it performs file I/O operations to append data to a CSV file.


---
### get\_next\_batch\_shred\_off<!-- {{#callable:get_next_batch_shred_off}} -->
The function `get_next_batch_shred_off` iterates through an array of shreds to find the offset of the next shred batch that is marked as complete.
- **Inputs**:
    - `shreds`: A pointer to an array of `fd_block_shred_t` structures, representing the shreds to be processed.
    - `shreds_cnt`: The total number of shreds in the `shreds` array.
    - `curr_shred_idx`: A pointer to an `ulong` that indicates the current index in the `shreds` array from which to start searching; it is updated to the next index after a complete batch is found.
- **Control Flow**:
    - The function starts a loop from the index pointed to by `curr_shred_idx` and iterates up to `shreds_cnt`.
    - For each shred, it checks if the `FD_SHRED_DATA_FLAG_DATA_COMPLETE` flag is set in the `flags` field of the shred's header.
    - If a complete shred is found, it updates `curr_shred_idx` to the next index and checks if there is another shred after the current one.
    - If there is another shred, it returns the offset of the next shred; otherwise, it returns `ULONG_MAX`.
    - If no complete shred is found by the end of the loop, it returns `ULONG_MAX`.
- **Output**: The function returns the offset of the next shred after a complete batch, or `ULONG_MAX` if no such shred exists.


---
### initialize\_rocksdb<!-- {{#callable:initialize_rocksdb}} -->
The `initialize_rocksdb` function initializes a RocksDB instance and imports blocks from a specified range of slots into a blockstore, recording the slots that were successfully populated.
- **Inputs**:
    - `wksp`: A pointer to a workspace object used for memory allocation.
    - `blockstore`: A pointer to a blockstore object where blocks will be imported.
    - `folder`: A string representing the path to the RocksDB folder.
    - `st`: The starting slot number for the range of slots to be processed.
    - `end`: The ending slot number for the range of slots to be processed.
    - `populated_slots_out`: An array to store the slot numbers that were successfully populated.
- **Control Flow**:
    - Initialize a `fd_rocksdb_t` and `fd_rocksdb_root_iter_t` structure to zero.
    - Call `fd_rocksdb_init` to initialize the RocksDB instance with the given folder path.
    - If initialization fails, log an error and return -1.
    - Create a new RocksDB root iterator using `fd_rocksdb_root_iter_new`.
    - Allocate memory for a virtual allocator using `fd_wksp_alloc_laddr`, `fd_alloc_new`, and `fd_alloc_join`.
    - Initialize a `fd_slot_meta_t` structure and a buffer `trash_hash_buf` filled with 0xFE.
    - Iterate over each slot from `st` to `end`.
    - For each slot, use `fd_rocksdb_root_iter_seek` to seek the slot in the RocksDB instance.
    - If the seek is successful, import the block into the blockstore using `fd_rocksdb_import_block_blockstore`.
    - If the import is successful, record the slot number in `populated_slots_out`.
    - Return the number of slots that were successfully populated.
- **Output**: Returns the number of slots that were successfully populated in the `populated_slots_out` array, or -1 if initialization of RocksDB fails.


---
### aggregate\_entries<!-- {{#callable:aggregate_entries}} -->
The `aggregate_entries` function processes blockchain data from a specified range of slots, aggregates it into structured entries, and appends these entries to a CSV file.
- **Inputs**:
    - `wksp`: A pointer to a workspace object used for memory allocation and management.
    - `folder`: A string representing the path to the folder containing the RocksDB database.
    - `csv`: A string representing the path to the output CSV file where aggregated entries will be appended.
    - `st`: An unsigned long integer representing the start slot number for data aggregation.
    - `end`: An unsigned long integer representing the end slot number for data aggregation.
- **Control Flow**:
    - Initialize a blockstore using the `INITIALIZE_BLOCKSTORE` macro and verify its initialization.
    - Allocate and initialize an array `populated_slots` to store slot numbers that have data.
    - Call [`initialize_rocksdb`](#initialize_rocksdb) to populate `populated_slots` with valid slots from the RocksDB database between `st` and `end`.
    - Iterate over each slot in `populated_slots` and query the blockstore for the corresponding block data.
    - If a block is found, retrieve its shreds, micros, and data using fast local address functions.
    - Initialize batch processing variables and iterate over microblocks within the block.
    - For each microblock, check if it starts a new batch and update batch-related variables accordingly.
    - Parse transactions within each microblock to calculate the total payload size and update the entry row structure.
    - Append the constructed entry row to the CSV file using [`entry_append_csv`](#entry_append_csv).
    - Log debug information about each processed entry.
- **Output**: The function does not return a value; it outputs aggregated entry data to the specified CSV file.
- **Functions called**:
    - [`initialize_rocksdb`](#initialize_rocksdb)
    - [`get_next_batch_shred_off`](#get_next_batch_shred_off)
    - [`entry_append_csv`](#entry_append_csv)


---
### aggregate\_batch\_entries<!-- {{#callable:aggregate_batch_entries}} -->
The `aggregate_batch_entries` function processes block data from a specified range of slots, aggregates it into batches, and appends the results to a CSV file.
- **Inputs**:
    - `wksp`: A pointer to the workspace (fd_wksp_t) used for memory allocation and management.
    - `folder`: A string representing the path to the folder containing the RocksDB database.
    - `csv`: A string representing the path to the output CSV file where the aggregated data will be appended.
    - `st`: An unsigned long integer representing the starting slot number for processing.
    - `end`: An unsigned long integer representing the ending slot number for processing.
- **Control Flow**:
    - Initialize the blockstore using the `INITIALIZE_BLOCKSTORE` macro.
    - Initialize the blockstore with `fd_blockstore_init` and check for success using `FD_TEST`.
    - Create an array `populated_slots` to store the slots that have data and initialize it to -1.
    - Call [`initialize_rocksdb`](#initialize_rocksdb) to populate the `populated_slots` array with valid slots between `st` and `end`.
    - Iterate over each slot in `populated_slots` and query the block data using `fd_blockstore_block_query`.
    - If a block is incomplete (i.e., not found), log a warning and continue to the next slot.
    - For each block, iterate over its shreds to calculate the batch size and determine when a batch is complete based on the `FD_SHRED_DATA_FLAG_DATA_COMPLETE` flag.
    - When a batch is complete, update the `fd_batch_row_t` structure with the batch details and append it to the CSV using [`batch_append_csv`](#batch_append_csv).
    - Log debug information about each completed batch.
- **Output**: The function does not return a value; it outputs the aggregated batch data to the specified CSV file.
- **Functions called**:
    - [`initialize_rocksdb`](#initialize_rocksdb)
    - [`batch_append_csv`](#batch_append_csv)


---
### investigate\_shred<!-- {{#callable:investigate_shred}} -->
The `investigate_shred` function analyzes and prints information about shreds and micros in a specified range of slots from a blockstore.
- **Inputs**:
    - `wksp`: A pointer to the workspace (fd_wksp_t) used for memory allocation and management.
    - `folder`: A string representing the path to the folder containing the RocksDB database.
    - `st`: An unsigned long integer representing the start slot number to investigate.
    - `end`: An unsigned long integer representing the end slot number to investigate.
- **Control Flow**:
    - Initialize the blockstore using the `INITIALIZE_BLOCKSTORE` macro.
    - Call `fd_blockstore_init` to initialize the blockstore with a file descriptor and minimum archive size.
    - Create an array `populated_slots` to store the slots that are populated between `st` and `end`, initializing it with -1.
    - Call [`initialize_rocksdb`](#initialize_rocksdb) to populate the `populated_slots` array with slots that exist in the RocksDB database.
    - Iterate over each populated slot, querying the blockstore for the block associated with each slot.
    - For each block, retrieve the shreds and micros using `fd_wksp_laddr_fast`.
    - Iterate over each shred in the block, printing the payload size and checking if the shred is the last in its batch.
    - Iterate over each micro in the block, logging the offset of each micro.
    - Print a message indicating the completion of processing for each slot.
- **Output**: The function does not return a value; it outputs information to the console about shred payload sizes, batch completion, and micro offsets for each slot.
- **Functions called**:
    - [`initialize_rocksdb`](#initialize_rocksdb)


---
### prepare\_csv<!-- {{#callable:prepare_csv}} -->
The `prepare_csv` function processes command-line arguments to determine the output CSV file path, opens the file for read/write access, truncates it to zero length, and returns the file path.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - The function calls `fd_env_strip_cmdline_cstr` to extract the CSV file path from the command-line arguments using the `--out` flag.
    - It opens the specified CSV file with read/write permissions, creating it if it does not exist, using the `open` function with `O_RDWR | O_CREAT` flags and permissions set to `0666`.
    - The function checks if the file descriptor `csv_fd` is valid (greater than 0) using `FD_TEST`.
    - It truncates the file to zero length using `ftruncate` and checks for success using `FD_TEST`.
    - Finally, the function returns the CSV file path.
- **Output**: The function returns a constant character pointer to the CSV file path extracted from the command-line arguments.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, processes command-line arguments, and performs data aggregation or investigation based on specified options.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Set default values for `page_cnt`, `_page_sz`, and `numa_idx`.
    - Log the creation of a workspace with specified parameters.
    - Create a new anonymous workspace using `fd_wksp_new_anonymous`.
    - Check if the `--help` flag is present in the command-line arguments; if so, call `usage()` and exit.
    - Retrieve the `--rocksdb-path` from command-line arguments and open the directory specified by it.
    - Retrieve the start and end slot numbers from command-line arguments using `fd_env_strip_cmdline_ulong`.
    - Check for the presence of `microblock`, `batch`, or `info` in the command-line arguments and execute the corresponding function ([`aggregate_entries`](#aggregate_entries), [`aggregate_batch_entries`](#aggregate_batch_entries), or [`investigate_shred`](#investigate_shred)).
    - If none of the expected options are specified, log a warning message.
    - Call `fd_halt` to clean up and exit the program.
- **Output**: The function returns an integer value `0` to indicate successful execution.
- **Functions called**:
    - [`usage`](#usage)
    - [`prepare_csv`](#prepare_csv)
    - [`entry_write_header`](#entry_write_header)
    - [`aggregate_entries`](#aggregate_entries)
    - [`batch_write_header`](#batch_write_header)
    - [`aggregate_batch_entries`](#aggregate_batch_entries)
    - [`investigate_shred`](#investigate_shred)


