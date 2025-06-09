# Purpose
This C source code file is designed to perform performance benchmarking and validation of various transaction processing functions, specifically focusing on sorting, hashing, and AVX (Advanced Vector Extensions) operations. The file includes several key components: it imports binary transaction data, defines sorting and hashing mechanisms for transaction account addresses, and implements functions to validate these operations. The main function orchestrates the execution of these validation functions over a large number of iterations to measure their performance, logging the average time taken for each operation. The code utilizes SIMD (Single Instruction, Multiple Data) operations for efficient data processing and includes custom hash map implementations to manage transaction account addresses.

The file is structured to be an executable C program, as indicated by the presence of a [`main`](#main) function. It does not define public APIs or external interfaces but rather focuses on internal validation and performance testing. The code leverages several utility headers and templates for sorting and hashing, indicating a modular design where specific functionalities are abstracted into reusable components. The use of macros and templates for sorting and hashing suggests a focus on flexibility and efficiency, allowing the code to handle different data types and operations with minimal overhead.
# Imports and Dependencies

---
- `../fd_ballet.h`
- `fd_pack.h`
- `fd_compute_budget_program.h`
- `../txn/fd_txn.h`
- `../../util/simd/fd_avx.h`
- `../../util/tmpl/fd_sort.c`
- `../../util/tmpl/fd_map.c`


# Global Variables

---
### \_txn
- **Type**: `uchar array`
- **Description**: The `_txn` variable is a global array of unsigned characters with a size defined by `FD_TXN_MAX_SZ`. It is used to store transaction data that is parsed and processed by various functions in the code.
- **Use**: This variable is used to hold transaction data after parsing, allowing functions to access and manipulate the transaction details.


---
### scratch1
- **Type**: `fd_acct_addr_t[]`
- **Description**: The variable `scratch1` is a global array of type `fd_acct_addr_t` with a size defined by `FD_TXN_ACCT_ADDR_MAX`. It is aligned to a 32-byte boundary for performance optimization, likely to take advantage of SIMD operations or cache line alignment.
- **Use**: `scratch1` is used as a temporary storage buffer for account addresses during transaction processing, particularly in sorting operations.


---
### scratch2
- **Type**: `fd_acct_addr_t array`
- **Description**: The variable `scratch2` is a global array of type `fd_acct_addr_t` with a size defined by `FD_TXN_ACCT_ADDR_MAX`. It is aligned to a 32-byte boundary for performance optimization, likely to take advantage of SIMD operations or cache line alignment.
- **Use**: `scratch2` is used as a temporary buffer to store account addresses during transaction processing, particularly in sorting operations.


---
### null\_addr
- **Type**: ``fd_acct_addr_t``
- **Description**: The `null_addr` is a static constant of type `fd_acct_addr_t`, initialized with a specific value of `{{ 1, 0 }}`. This structure likely represents an account address with a predefined null or invalid state.
- **Use**: It is used as a sentinel value in hash map operations to represent a null or invalid key.


---
### \_map
- **Type**: `uchar array`
- **Description**: The `_map` variable is a global array of unsigned characters (`uchar`) with a size determined by the product of the size of `fd_pack_addr_use_t` and `2^9` (512). It is aligned to a 32-byte boundary for optimized memory access.
- **Use**: This variable is used as a memory buffer for hash map operations involving account addresses, facilitating efficient storage and retrieval of address usage records.


# Data Structures

---
### fd\_pack\_private\_addr\_use\_record
- **Type**: `struct`
- **Members**:
    - `key`: Holds the account address as a key.
- **Description**: The `fd_pack_private_addr_use_record` structure is a simple data structure designed to store an account address, encapsulated in the `fd_acct_addr_t` type, as its key. This structure is used to represent a record of address usage within a larger system, likely for tracking or mapping purposes. It is typedef'd to `fd_pack_addr_use_t` for ease of use in the codebase.


---
### fd\_pack\_addr\_use\_t
- **Type**: `struct`
- **Members**:
    - `key`: Represents an account address.
- **Description**: The `fd_pack_addr_use_t` is a structure that encapsulates a single field, `key`, which is of type `fd_acct_addr_t`. This structure is used to represent an account address within the context of a hash map, as indicated by its use in the `hash_pubkeys` map. The structure is designed to facilitate operations on account addresses, such as insertion, removal, and querying within a hash map, which is part of a larger system for processing transactions.


---
### wrap\_ul
- **Type**: `struct`
- **Members**:
    - `key`: An unsigned long integer used as the key in the data structure.
- **Description**: The `wrap_ul` structure is a simple data structure that encapsulates a single unsigned long integer, `key`, which is used as a key in various operations, such as hashing or mapping. This structure is typically used in contexts where a single numeric key is needed to represent or identify an entity or object within a larger system, such as a hash map or a sorting algorithm.


---
### wrap\_ul\_t
- **Type**: `struct`
- **Members**:
    - `key`: A field of type 'ulong' used as a key in the data structure.
- **Description**: The `wrap_ul_t` is a simple data structure defined as a struct with a single member, `key`, which is of type `ulong`. This structure is likely used to encapsulate a key value for operations such as hashing or mapping, as indicated by its usage in the `hash_ul` map implementation. The simplicity of the structure suggests it is designed for efficient storage and retrieval of a single key value.


# Functions

---
### check\_sort<!-- {{#callable:check_sort}} -->
The `check_sort` function verifies if the account addresses extracted from a transaction payload are sorted uniquely in a stable manner.
- **Inputs**:
    - `payload`: A pointer to the transaction payload data, represented as an array of unsigned characters.
    - `sz`: The size of the transaction payload in bytes, represented as an unsigned long integer.
- **Control Flow**:
    - The function begins by parsing the transaction payload using `fd_txn_parse` and stores the result in a global buffer `_txn`.
    - It retrieves the transaction object from the parsed data and calculates the number of account addresses using `fd_txn_account_cnt`.
    - The account addresses are copied from the transaction into a scratch buffer `scratch1` using `memcpy`.
    - The addresses in `scratch1` are then sorted using `sort_pubkeys_stable_fast`, with the sorted result stored in `scratch2`.
    - A loop iterates over the sorted addresses to check for duplicates by comparing each address with the previous one using `memcmp`.
    - If any duplicate addresses are found, the function returns 0, indicating the addresses are not uniquely sorted.
    - If no duplicates are found, the function returns 1, indicating the addresses are uniquely sorted.
- **Output**: The function returns an integer: 1 if the account addresses are uniquely sorted, and 0 if there are duplicates.


---
### check\_hash<!-- {{#callable:check_hash}} -->
The `check_hash` function verifies if any account addresses in a transaction payload have been previously encountered by using a hash map to track them.
- **Inputs**:
    - `payload`: A pointer to an unsigned character array representing the transaction payload to be parsed and checked.
    - `sz`: An unsigned long integer representing the size of the payload.
- **Control Flow**:
    - Parse the transaction from the payload using `fd_txn_parse` and store it in `_txn`.
    - Retrieve the transaction object from `_txn` and determine the number of immediate account addresses using `fd_txn_account_cnt`.
    - Get the list of account addresses from the transaction using `fd_txn_get_acct_addrs`.
    - Join the hash map using `hash_pubkeys_join` to prepare for querying and inserting addresses.
    - Initialize `retval` to 1, indicating no duplicate addresses found initially.
    - Iterate over each account address and check if it already exists in the hash map using `hash_pubkeys_query`; if found, set `retval` to 0 and break the loop.
    - If not found, insert the address into the hash map using `hash_pubkeys_insert`.
    - After checking all addresses, iterate again to remove each address from the hash map using `hash_pubkeys_remove`.
    - Return `retval`, which indicates whether any duplicate addresses were found.
- **Output**: An integer value, where 1 indicates no duplicate account addresses were found, and 0 indicates at least one duplicate was detected.


---
### dummy<!-- {{#callable:dummy}} -->
The `dummy` function parses a transaction payload, retrieves account addresses, and accesses the first byte of each address in a loop, returning a constant value.
- **Inputs**:
    - `payload`: A pointer to an array of unsigned characters representing the transaction payload.
    - `sz`: An unsigned long integer representing the size of the payload.
- **Control Flow**:
    - The function begins by parsing the transaction payload using `fd_txn_parse`, storing the result in a global transaction buffer `_txn`.
    - It casts the global buffer `_txn` to a `fd_txn_t` pointer named `txn`.
    - The function retrieves the count of immediate category accounts in the transaction using `fd_txn_account_cnt`.
    - It obtains the account addresses from the transaction using `fd_txn_get_acct_addrs`.
    - A loop iterates over each account address, accessing the first byte of each address and storing it in a volatile variable `d`.
    - The function concludes by returning the constant integer value `1`.
- **Output**: The function returns a constant integer value `1`, indicating successful execution.


---
### check\_hash64<!-- {{#callable:check_hash64}} -->
The `check_hash64` function verifies that no duplicate 64-bit hash keys, derived from transaction account addresses, exist within a given payload.
- **Inputs**:
    - `payload`: A pointer to an array of unsigned characters representing the transaction data to be parsed and checked.
    - `sz`: An unsigned long integer representing the size of the payload in bytes.
- **Control Flow**:
    - The function begins by parsing the transaction data from the payload using `fd_txn_parse` and stores it in a global buffer `_txn`.
    - It retrieves the transaction object and the count of immediate category accounts using `fd_txn_account_cnt`.
    - The function obtains the account addresses from the transaction using `fd_txn_get_acct_addrs`.
    - A hash map is joined using `hash_ul_join` to manage the 64-bit keys derived from the account addresses.
    - The function initializes a return value `retval` to 1, indicating no duplicates found initially.
    - It iterates over each account address, computes a 64-bit key by loading 8 bytes from the address and adding 1, and checks if this key already exists in the hash map using `hash_ul_query`.
    - If a duplicate key is found, `retval` is set to 0, and the loop breaks.
    - If no duplicate is found, the key is inserted into the hash map using `hash_ul_insert`.
    - After checking all addresses, the function iterates again to remove all keys from the hash map using `hash_ul_remove`.
    - Finally, the function returns `retval`, indicating whether duplicates were found.
- **Output**: The function returns an integer value, 1 if no duplicate keys were found, and 0 if any duplicates were detected.


---
### check\_avx<!-- {{#callable:check_avx}} -->
The `check_avx` function verifies if a transaction's account addresses are unique by using AVX vector operations to check for duplicate bits in specific byte positions.
- **Inputs**:
    - `payload`: A pointer to the transaction data to be parsed and checked.
    - `sz`: The size of the transaction data in bytes.
- **Control Flow**:
    - Parse the transaction from the payload using `fd_txn_parse` and store it in a global buffer `_txn`.
    - Retrieve the transaction object and count the number of immediate accounts using `fd_txn_account_cnt`.
    - Get the account addresses from the transaction using `fd_txn_get_acct_addrs`.
    - Initialize several bit vector variables (`bv8`, `bv9`, `bv14`, `bv17`, `bv21`, `bv26`, `bv28`, `bv31`) to zero, which will be used to track unique bits for specific byte positions.
    - Define a `shift_mask` vector to assist in bit manipulation for different byte positions.
    - Iterate over each account address, and for each address, perform the `CHECK_AND_UPDATE` macro for specific byte positions (8, 9, 14, 17, 21, 26, 28, 31).
    - In the `CHECK_AND_UPDATE` macro, broadcast the byte at the specified position, subtract the `shift_mask`, create a bitmask, and check for intersections with the corresponding bit vector.
    - Update the bit vector with the new bitmask and check if the intersection is zero, indicating no duplicate bits.
    - Sum the results of the `CHECK_AND_UPDATE` operations and check if the sum equals -24, which indicates a duplicate was found, returning 0 in this case.
    - If no duplicates are found after checking all addresses, return 1.
- **Output**: Returns 1 if all account addresses are unique, otherwise returns 0 if a duplicate is detected.


---
### main<!-- {{#callable:main}} -->
The `main` function benchmarks various transaction validation methods by measuring the time taken to process a million iterations of different validation functions on sample transactions.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Declare and initialize a variable `sum` to 0 and `dummyt` to the negative value of the current wall clock time.
    - Run a loop 1,000,000 times calling the [`dummy`](#dummy) function on four different transaction samples, summing their results, and updating `sum`.
    - Calculate the elapsed time for the dummy operations and log the mean time per validation.
    - Run another loop 1,000,000 times calling the [`check_sort`](#check_sort) function on the same four transaction samples, summing their results, and updating `sum`.
    - Calculate the elapsed time for the sort operations, excluding overhead, and log the mean time per validation.
    - Initialize a hash map using `hash_pubkeys_new`.
    - Run a loop 1,000,000 times calling the [`check_hash`](#check_hash) function on the transaction samples, summing their results, and updating `sum`.
    - Calculate the elapsed time for the hash operations, excluding overhead, and log the mean time per validation.
    - Delete the hash map using `hash_pubkeys_delete`.
    - Run a loop 1,000,000 times calling the [`check_avx`](#check_avx) function on the transaction samples, summing their results, and updating `sum`.
    - Calculate the elapsed time for the AVX operations, excluding overhead, and log the mean time per validation.
    - Initialize another hash map using `hash_ul_new`.
    - Run a loop 1,000,000 times calling the [`check_hash64`](#check_hash64) function on the transaction samples, summing their results, and updating `sum`.
    - Calculate the elapsed time for the hash64 operations, excluding overhead, and log the mean time per validation.
    - Delete the hash map using `hash_ul_delete`.
    - Terminate the environment using `fd_halt` and return 0.
- **Output**: The function returns 0, indicating successful execution.
- **Functions called**:
    - [`dummy`](#dummy)
    - [`check_sort`](#check_sort)
    - [`check_hash`](#check_hash)
    - [`check_avx`](#check_avx)
    - [`check_hash64`](#check_hash64)


