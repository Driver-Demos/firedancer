# Purpose
The provided C header file, `fd_funk_base.h`, defines the foundational components and operations for managing a data structure referred to as a "funk instance." This instance is designed to store records as key-value pairs, where keys have a fixed length and values are variable-sized binary data. The file outlines the structure and behavior of transactions that describe changes to these records, supporting a history of transactions through parent-child relationships. The header file provides definitions for key data types, such as `fd_funk_rec_key_t` for record keys and `fd_funk_txn_xid_t` for transaction identifiers, along with their associated operations like hashing, equality checks, and copying.

The file also defines a set of error codes and constants to facilitate error handling and memory alignment. It includes functions for hashing and comparing keys and transaction IDs, which are crucial for managing the records and transactions efficiently. The header file is intended to be included in other C source files, providing a public API for interacting with funk instances. It does not contain executable code but rather serves as a library of definitions and inline functions that can be used to build applications requiring transactional record management. The file emphasizes the importance of transaction integrity and history, allowing for complex operations like parallel transaction histories and transaction cancellation.
# Imports and Dependencies

---
- `../util/fd_util.h`
- `../util/valloc/fd_valloc.h`


# Global Variables

---
### fd\_funk\_strerror
- **Type**: ``FD_FN_CONST char const *``
- **Description**: The `fd_funk_strerror` function is a global function that converts error codes related to the funk system into human-readable strings. It takes an integer error code as input and returns a constant character pointer to a string that describes the error. The returned string is always non-NULL and has an infinite lifetime.
- **Use**: This function is used to provide descriptive error messages for error codes returned by various funk APIs.


# Data Structures

---
### fd\_funk\_rec\_key
- **Type**: `union`
- **Members**:
    - `uc`: An array of unsigned characters with a size defined by FD_FUNK_REC_KEY_FOOTPRINT.
    - `ui`: An array of 10 unsigned integers.
    - `ul`: An array of 5 unsigned long integers.
- **Description**: The `fd_funk_rec_key` is a union data structure used to represent a fixed-length key for a funk record. It provides three different views of the key's binary data: as an array of unsigned characters, as an array of unsigned integers, and as an array of unsigned long integers. This flexibility allows the key to be manipulated in different ways depending on the requirements of the application, such as hashing or comparison operations. The union is aligned according to `FD_FUNK_REC_KEY_ALIGN` and has a footprint defined by `FD_FUNK_REC_KEY_FOOTPRINT`, ensuring efficient memory usage and access.


---
### fd\_funk\_rec\_key\_t
- **Type**: `union`
- **Members**:
    - `uc`: An array of unsigned characters with a size equal to FD_FUNK_REC_KEY_FOOTPRINT.
    - `ui`: An array of unsigned integers with a size of 10.
    - `ul`: An array of unsigned long integers with a size of 5.
- **Description**: The `fd_funk_rec_key_t` is a union data structure used to represent a fixed-length key for a funk record. It provides multiple views of the key data, allowing it to be accessed as an array of unsigned characters, unsigned integers, or unsigned long integers. This flexibility facilitates different operations on the key, such as hashing or comparison, while maintaining a compact binary format. The key is aligned to an 8-byte boundary and has a footprint of 40 bytes, which includes a 32-byte hash and 8 bytes of metadata.


---
### fd\_funk\_txn\_xid
- **Type**: `union`
- **Members**:
    - `uc`: An array of unsigned characters with a size defined by FD_FUNK_TXN_XID_FOOTPRINT.
    - `ul`: An array of unsigned long integers with a size defined by FD_FUNK_TXN_XID_FOOTPRINT divided by the size of an unsigned long.
- **Description**: The `fd_funk_txn_xid` is a union data structure used to represent a transaction identifier in the funk system, which is a part of a larger transactional record management system. It provides two views of the transaction ID: as a byte array (`uc`) and as an array of unsigned long integers (`ul`). This allows for flexible manipulation and storage of transaction IDs, which are crucial for identifying and managing transactions in preparation within the funk system. The union is aligned according to `FD_FUNK_TXN_XID_ALIGN` to ensure efficient memory access and is designed to fit within a footprint defined by `FD_FUNK_TXN_XID_FOOTPRINT`.


---
### fd\_funk\_txn\_xid\_t
- **Type**: `union`
- **Members**:
    - `uc`: An array of unsigned characters with a size defined by FD_FUNK_TXN_XID_FOOTPRINT.
    - `ul`: An array of unsigned long integers with a size defined by FD_FUNK_TXN_XID_FOOTPRINT divided by the size of an unsigned long.
- **Description**: The `fd_funk_txn_xid_t` is a union data structure used to identify a funk transaction currently in preparation. It provides a compact binary identifier for transactions, with the option to use a C-style string (cstr) as long as it fits within the defined footprint. The union allows for different representations of the transaction ID, either as an array of unsigned characters or as an array of unsigned long integers, facilitating flexible usage depending on the application needs.


---
### fd\_funk\_xid\_key\_pair
- **Type**: `struct`
- **Members**:
    - `xid`: An array of one fd_funk_txn_xid_t, representing the transaction identifier.
    - `key`: An array of one fd_funk_rec_key_t, representing the record key.
- **Description**: The `fd_funk_xid_key_pair` structure is a compound data type that encapsulates a transaction identifier (`xid`) and a record key (`key`) into a single entity. This structure is used to uniquely identify a record within a funk instance, where each record is associated with a specific transaction. The `xid` is used to track the transaction context, while the `key` is used to index the record within the funk system. This pairing allows for efficient management and querying of records in relation to their transactions.


---
### fd\_funk\_xid\_key\_pair\_t
- **Type**: `struct`
- **Members**:
    - `xid`: An array containing a single element of type `fd_funk_txn_xid_t`, representing the transaction identifier.
    - `key`: An array containing a single element of type `fd_funk_rec_key_t`, representing the record key.
- **Description**: The `fd_funk_xid_key_pair_t` structure is a compound data type that encapsulates a pair consisting of a transaction identifier (`xid`) and a record key (`key`). This structure is used to uniquely identify a funk record by combining the transaction context with the specific record key, allowing for efficient management and querying of records within a transactional system. The structure is aligned to 8 bytes and has a footprint of 56 bytes, ensuring efficient memory usage and access.


---
### fd\_funk\_shmem\_t
- **Type**: `struct`
- **Members**:
    - `fd_funk_shmem_private`: A private structure used internally to represent the top part of a funk object in shared memory.
- **Description**: The `fd_funk_shmem_t` is a typedef for a private structure `fd_funk_shmem_private`, which is used to represent the top part of a funk object in shared memory. This structure is part of a larger system that manages records and transactions in a shared memory context, allowing for efficient data storage and retrieval. The details of the structure are encapsulated and not exposed, indicating that it is intended for internal use within the funk system.


---
### fd\_funk\_t
- **Type**: `struct`
- **Members**:
    - `fd_funk_private`: A private structure representing a local join handle to a funk instance.
- **Description**: The `fd_funk_t` is a typedef for a private structure `fd_funk_private`, which serves as a local join handle to a funk instance. This structure is part of a system that manages records as key-value pairs, with transactions describing changes to these records. The `fd_funk_t` is used to interact with the funk instance, allowing operations such as querying and updating records within the context of transactions.


# Functions

---
### fd\_xxh3\_mul128\_fold64<!-- {{#callable:fd_xxh3_mul128_fold64}} -->
The `fd_xxh3_mul128_fold64` function multiplies two unsigned long integers and folds the 128-bit product into a 64-bit result using XOR.
- **Inputs**:
    - `lhs`: The left-hand side operand, an unsigned long integer.
    - `rhs`: The right-hand side operand, an unsigned long integer.
- **Control Flow**:
    - The function casts both input operands, `lhs` and `rhs`, to 128-bit integers and multiplies them, resulting in a 128-bit product.
    - The 128-bit product is split into two 64-bit parts: the lower 64 bits and the upper 64 bits (obtained by right-shifting the product by 64 bits).
    - The function returns the result of XORing the lower 64 bits with the upper 64 bits.
- **Output**: A 64-bit unsigned long integer that is the result of folding the 128-bit product of the inputs using XOR.


---
### fd\_xxh3\_mix16b<!-- {{#callable:fd_xxh3_mix16b}} -->
The `fd_xxh3_mix16b` function combines two 64-bit integers with two salt values and a seed, then applies a 128-bit multiplication and folding operation to produce a 64-bit result.
- **Inputs**:
    - `i0`: The first 64-bit integer input to be mixed.
    - `i1`: The second 64-bit integer input to be mixed.
    - `s0`: The first 64-bit salt value used in the mixing process.
    - `s1`: The second 64-bit salt value used in the mixing process.
    - `seed`: A 64-bit seed value used to influence the mixing process.
- **Control Flow**:
    - The function takes five 64-bit unsigned long integers as input: i0, i1, s0, s1, and seed.
    - It computes the XOR of i0 with the sum of s0 and seed, and the XOR of i1 with the difference of s1 and seed.
    - These two results are passed to the [`fd_xxh3_mul128_fold64`](#fd_xxh3_mul128_fold64) function, which performs a 128-bit multiplication and folding operation.
    - The result of the [`fd_xxh3_mul128_fold64`](#fd_xxh3_mul128_fold64) function is returned as the output of `fd_xxh3_mix16b`.
- **Output**: A 64-bit unsigned long integer that is the result of the mixing and folding operation.
- **Functions called**:
    - [`fd_xxh3_mul128_fold64`](#fd_xxh3_mul128_fold64)


---
### fd\_funk\_rec\_key\_hash<!-- {{#callable:fd_funk_rec_key_hash}} -->
The `fd_funk_rec_key_hash` function computes a quasi-random 64-bit hash for a given record key using a seed value.
- **Inputs**:
    - `k`: A pointer to a `fd_funk_rec_key_t` structure, which represents the record key to be hashed.
    - `seed`: An unsigned long integer used as a seed to select the specific hash function variant.
- **Control Flow**:
    - The function begins by XORing the seed with the fifth element of the key's `ul` array (`k->ul[4]`).
    - It then computes four separate hash values using `fd_ulong_hash`, each with a different combination of the seed, a shifted constant, and elements from the key's `ul` array (`k->ul[0]` to `k->ul[3]`).
    - The function XORs these four hash values together to produce the final hash result.
- **Output**: The function returns a 64-bit unsigned long integer representing the hash of the record key.


---
### fd\_funk\_rec\_key\_eq<!-- {{#callable:fd_funk_rec_key_eq}} -->
The `fd_funk_rec_key_eq` function checks if two `fd_funk_rec_key_t` keys are equal by comparing their underlying `ulong` arrays.
- **Inputs**:
    - `ka`: A pointer to the first `fd_funk_rec_key_t` key to be compared.
    - `kb`: A pointer to the second `fd_funk_rec_key_t` key to be compared.
- **Control Flow**:
    - Extract the `ulong` arrays from both `ka` and `kb` keys.
    - Perform bitwise XOR operations between corresponding elements of the two arrays.
    - Combine the results using bitwise OR operations to check if any differences exist.
    - Return the negation of the combined result, which is 1 if all elements are equal and 0 otherwise.
- **Output**: Returns 1 if the keys are equal and 0 if they are not.


---
### fd\_funk\_rec\_key\_copy<!-- {{#callable:fd_funk_rec_key_copy}} -->
The `fd_funk_rec_key_copy` function copies the contents of one `fd_funk_rec_key_t` structure to another and returns the destination pointer.
- **Inputs**:
    - `kd`: A pointer to the destination `fd_funk_rec_key_t` structure where the key will be copied to.
    - `ks`: A pointer to the source `fd_funk_rec_key_t` structure from which the key will be copied.
- **Control Flow**:
    - Extracts the `ul` array from the destination `fd_funk_rec_key_t` pointer `kd` and assigns it to `d`.
    - Extracts the `ul` array from the source `fd_funk_rec_key_t` pointer `ks` and assigns it to `s`.
    - Copies each of the five `ulong` elements from the source array `s` to the destination array `d`.
    - Returns the destination pointer `kd`.
- **Output**: The function returns the pointer to the destination `fd_funk_rec_key_t` structure, `kd`, after copying the key.


---
### fd\_funk\_txn\_xid\_hash<!-- {{#callable:fd_funk_txn_xid_hash}} -->
The `fd_funk_txn_xid_hash` function computes a quasi-random 64-bit hash for a given transaction ID using a seed value.
- **Inputs**:
    - `x`: A pointer to a `fd_funk_txn_xid_t` structure representing the transaction ID to be hashed.
    - `seed`: An unsigned long integer used as the seed for the hash function.
- **Control Flow**:
    - The function takes a transaction ID and a seed as inputs.
    - It computes the hash by XORing the seed with shifted constants and elements of the transaction ID.
    - The function applies `fd_ulong_hash` to these XORed values and combines the results using XOR to produce the final hash.
- **Output**: The function returns a 64-bit unsigned long integer representing the hash of the transaction ID.


---
### fd\_funk\_txn\_xid\_eq<!-- {{#callable:fd_funk_txn_xid_eq}} -->
The `fd_funk_txn_xid_eq` function checks if two transaction IDs are equal by comparing their underlying data.
- **Inputs**:
    - `xa`: A pointer to the first transaction ID (`fd_funk_txn_xid_t`) to be compared.
    - `xb`: A pointer to the second transaction ID (`fd_funk_txn_xid_t`) to be compared.
- **Control Flow**:
    - Retrieve the underlying `ulong` arrays from both transaction ID pointers `xa` and `xb`.
    - Perform a bitwise XOR operation between corresponding elements of the two arrays.
    - Combine the results of the XOR operations using a bitwise OR operation.
    - Return the negation of the combined result, which will be 1 if all elements are equal (i.e., the XOR results are all zero) and 0 otherwise.
- **Output**: Returns an integer value: 1 if the transaction IDs are equal, and 0 if they are not.


---
### fd\_funk\_txn\_xid\_copy<!-- {{#callable:fd_funk_txn_xid_copy}} -->
The `fd_funk_txn_xid_copy` function copies a transaction ID from one `fd_funk_txn_xid_t` structure to another.
- **Inputs**:
    - `xd`: A pointer to the destination `fd_funk_txn_xid_t` structure where the transaction ID will be copied to.
    - `xs`: A pointer to the source `fd_funk_txn_xid_t` structure from which the transaction ID will be copied.
- **Control Flow**:
    - The function begins by creating a pointer `d` to the `ul` array of the destination `fd_funk_txn_xid_t` structure `xd`.
    - It also creates a pointer `s` to the `ul` array of the source `fd_funk_txn_xid_t` structure `xs`.
    - The function then copies the first two elements of the `ul` array from `xs` to `xd`.
    - Finally, the function returns the pointer to the destination `fd_funk_txn_xid_t` structure `xd`.
- **Output**: The function returns a pointer to the destination `fd_funk_txn_xid_t` structure `xd` after copying the transaction ID.


---
### fd\_funk\_txn\_xid\_eq\_root<!-- {{#callable:fd_funk_txn_xid_eq_root}} -->
The function `fd_funk_txn_xid_eq_root` checks if a given transaction ID is the root transaction.
- **Inputs**:
    - `x`: A pointer to a `fd_funk_txn_xid_t` structure representing the transaction ID to be checked.
- **Control Flow**:
    - Retrieve the `ul` array from the transaction ID structure pointed to by `x`.
    - Check if both elements of the `ul` array are zero using a bitwise OR operation.
    - Return 1 if both elements are zero (indicating the root transaction), otherwise return 0.
- **Output**: An integer value, 1 if the transaction ID is the root transaction, otherwise 0.


---
### fd\_funk\_txn\_xid\_set\_root<!-- {{#callable:fd_funk_txn_xid_set_root}} -->
The function `fd_funk_txn_xid_set_root` sets the transaction ID pointed to by `x` to the root transaction by zeroing its components.
- **Inputs**:
    - `x`: A pointer to a `fd_funk_txn_xid_t` structure, which represents a transaction ID.
- **Control Flow**:
    - The function takes a pointer `x` to a `fd_funk_txn_xid_t` structure.
    - It accesses the `ul` array within the structure, which is an array of `ulong` values.
    - The function sets both elements of the `ul` array to `0UL`, effectively marking the transaction ID as the root transaction.
    - The function returns the modified pointer `x`.
- **Output**: The function returns the pointer `x` after setting its transaction ID to the root transaction.


---
### fd\_funk\_xid\_key\_pair\_hash<!-- {{#callable:fd_funk_xid_key_pair_hash}} -->
The `fd_funk_xid_key_pair_hash` function computes a 64-bit hash for a given `fd_funk_xid_key_pair_t` structure, focusing only on the record key part and ignoring the transaction ID.
- **Inputs**:
    - `p`: A pointer to a `fd_funk_xid_key_pair_t` structure, which contains a transaction ID and a record key.
    - `seed`: An unsigned long integer used as a seed for the hash function to ensure variability in the hash output.
- **Control Flow**:
    - The function takes a pointer to a `fd_funk_xid_key_pair_t` structure and a seed as inputs.
    - It calls the [`fd_funk_rec_key_hash`](#fd_funk_rec_key_hash) function, passing the record key part of the `fd_funk_xid_key_pair_t` and the seed.
    - The function returns the hash value computed by [`fd_funk_rec_key_hash`](#fd_funk_rec_key_hash), effectively ignoring the transaction ID part of the input structure.
- **Output**: The function returns a 64-bit unsigned long integer representing the hash of the record key part of the input `fd_funk_xid_key_pair_t` structure.
- **Functions called**:
    - [`fd_funk_rec_key_hash`](#fd_funk_rec_key_hash)


---
### fd\_funk\_xid\_key\_pair\_eq<!-- {{#callable:fd_funk_xid_key_pair_eq}} -->
The function `fd_funk_xid_key_pair_eq` checks if two `fd_funk_xid_key_pair_t` structures are equal by comparing their transaction IDs and record keys.
- **Inputs**:
    - `pa`: A pointer to the first `fd_funk_xid_key_pair_t` structure to compare.
    - `pb`: A pointer to the second `fd_funk_xid_key_pair_t` structure to compare.
- **Control Flow**:
    - The function calls [`fd_funk_txn_xid_eq`](#fd_funk_txn_xid_eq) to compare the transaction IDs (`xid`) of `pa` and `pb`.
    - It then calls [`fd_funk_rec_key_eq`](#fd_funk_rec_key_eq) to compare the record keys (`key`) of `pa` and `pb`.
    - The results of the two comparisons are combined using a bitwise AND operation.
    - The function returns the result of the AND operation, which is 1 if both the transaction IDs and record keys are equal, and 0 otherwise.
- **Output**: The function returns an integer, 1 if both the transaction ID and record key of the two structures are equal, and 0 otherwise.
- **Functions called**:
    - [`fd_funk_txn_xid_eq`](#fd_funk_txn_xid_eq)
    - [`fd_funk_rec_key_eq`](#fd_funk_rec_key_eq)


---
### fd\_funk\_xid\_key\_pair\_copy<!-- {{#callable:fd_funk_xid_key_pair_copy}} -->
The `fd_funk_xid_key_pair_copy` function copies the transaction ID and record key from one `fd_funk_xid_key_pair_t` structure to another.
- **Inputs**:
    - `pd`: A pointer to the destination `fd_funk_xid_key_pair_t` structure where the transaction ID and record key will be copied to.
    - `ps`: A pointer to the source `fd_funk_xid_key_pair_t` structure from which the transaction ID and record key will be copied.
- **Control Flow**:
    - The function calls [`fd_funk_txn_xid_copy`](#fd_funk_txn_xid_copy) to copy the transaction ID from `ps->xid` to `pd->xid`.
    - The function calls [`fd_funk_rec_key_copy`](#fd_funk_rec_key_copy) to copy the record key from `ps->key` to `pd->key`.
    - The function returns the pointer `pd` after copying is complete.
- **Output**: The function returns a pointer to the destination `fd_funk_xid_key_pair_t` structure (`pd`).
- **Functions called**:
    - [`fd_funk_txn_xid_copy`](#fd_funk_txn_xid_copy)
    - [`fd_funk_rec_key_copy`](#fd_funk_rec_key_copy)


---
### fd\_funk\_xid\_key\_pair\_init<!-- {{#callable:fd_funk_xid_key_pair_init}} -->
The function `fd_funk_xid_key_pair_init` initializes a `fd_funk_xid_key_pair_t` structure with a given transaction ID and record key.
- **Inputs**:
    - `p`: A pointer to a `fd_funk_xid_key_pair_t` structure that will be initialized.
    - `x`: A constant pointer to a `fd_funk_txn_xid_t` structure representing the transaction ID to be copied into `p`.
    - `k`: A constant pointer to a `fd_funk_rec_key_t` structure representing the record key to be copied into `p`.
- **Control Flow**:
    - The function begins by copying the transaction ID from `x` into the `xid` field of the `fd_funk_xid_key_pair_t` structure pointed to by `p` using [`fd_funk_txn_xid_copy`](#fd_funk_txn_xid_copy).
    - Next, it copies the record key from `k` into the `key` field of the `fd_funk_xid_key_pair_t` structure pointed to by `p` using [`fd_funk_rec_key_copy`](#fd_funk_rec_key_copy).
    - Finally, the function returns the pointer `p`.
- **Output**: The function returns the pointer `p`, which now contains the initialized `fd_funk_xid_key_pair_t` structure.
- **Functions called**:
    - [`fd_funk_txn_xid_copy`](#fd_funk_txn_xid_copy)
    - [`fd_funk_rec_key_copy`](#fd_funk_rec_key_copy)


# Function Declarations (Public API)

---
### fd\_funk\_strerror<!-- {{#callable_declaration:fd_funk_strerror}} -->
Convert an error code to a human-readable string.
- **Description**: Use this function to obtain a human-readable description of an error code returned by other fd_funk APIs. This is useful for logging or displaying error messages to users. The function maps known error codes to specific strings and returns "unknown" for any unrecognized error code. The returned string is a constant and should not be modified or freed by the caller.
- **Inputs**:
    - `err`: An integer representing an error code, which can be one of FD_FUNK_SUCCESS or FD_FUNK_ERR_* constants. The function handles both valid and invalid error codes, returning "unknown" for any code not explicitly recognized.
- **Output**: A constant string describing the error code. The string is always non-NULL and has an infinite lifetime.
- **See also**: [`fd_funk_strerror`](fd_funk_base.c.driver.md#fd_funk_strerror)  (Implementation)


