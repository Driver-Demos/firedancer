# Purpose
The provided C++ code defines a simulation framework for managing transactions and records, likely intended for testing or prototyping a transactional system. The code is structured around three main classes: [`fake_rec`](#fake_recfake_rec), [`fake_txn`](#fake_txnfake_txn), and [`fake_funk`](#fake_funkfake_funk). The [`fake_rec`](#fake_recfake_rec) class represents a record with a unique key and data, and it includes mechanisms for creating random records and managing their lifecycle. The [`fake_txn`](#fake_txnfake_txn) class models a transaction, holding a collection of records and potentially having child transactions, thus forming a transaction hierarchy. The [`fake_funk`](#fake_funkfake_funk) class acts as the main orchestrator, managing a workspace and a collection of transactions, and providing methods to perform random operations such as inserting, removing, publishing, and canceling transactions.

The code is not a standalone executable but rather a component that could be part of a larger system, possibly for testing purposes. It includes functionality to simulate transaction operations and verify the integrity of the transaction and record states. The use of macros like `FD_TEST`, `FD_LOG_NOTICE`, and `FD_FUNK_SUCCESS` suggests integration with a specific framework or library, likely related to the `fd_funk` system, which appears to be a transactional framework. The code also includes conditional compilation sections for testing with file-based transactions, indicating its flexibility in testing different transaction storage mechanisms. Overall, the code provides a comprehensive simulation environment for testing transaction management logic, focusing on operations like insertion, removal, and publication of records within a transactional context.
# Imports and Dependencies

---
- `fd_funk.h`
- `map`
- `vector`
- `set`
- `algorithm`
- `stdlib.h`
- `assert.h`
- `unistd.h`


# Global Variables

---
### ROOT\_KEY
- **Type**: `long`
- **Description**: `ROOT_KEY` is a global constant variable of type `long` initialized to 0. It serves as a unique identifier for the root transaction in the `fake_funk` structure.
- **Use**: `ROOT_KEY` is used to identify and manage the root transaction within the `fake_funk` class, ensuring that certain operations are correctly associated with the root transaction.


---
### MAX\_TXNS
- **Type**: `ulong`
- **Description**: `MAX_TXNS` is a global constant of type `ulong` that is set to the value 100. It represents the maximum number of transactions that can be handled or stored in the system at any given time.
- **Use**: `MAX_TXNS` is used to limit the number of transactions that can be managed, ensuring that operations such as transaction creation and management do not exceed this predefined limit.


---
### MAX\_CHILDREN
- **Type**: `ulong`
- **Description**: `MAX_CHILDREN` is a global constant of type `ulong` that is set to the value 100. It is used to define the maximum number of child transactions or records that can be associated with a parent transaction in the context of the `fake_funk` system.
- **Use**: This variable is used to limit the number of child transactions or records that can be managed within a transaction, ensuring that operations such as insertion and removal do not exceed this predefined limit.


---
### MAX\_PARTS
- **Type**: ``uint``
- **Description**: `MAX_PARTS` is a global constant variable of type `uint` that is set to the value 8. It is defined as a static constant, meaning its value is fixed and cannot be changed during the execution of the program.
- **Use**: This variable is used to define a constant limit or maximum number of parts, likely for use in operations or data structures that require a fixed number of elements.


# Data Structures

---
### fake\_rec<!-- {{#data_structure:fake_rec}} -->
- **Type**: `struct`
- **Members**:
    - `_key`: An unsigned long integer representing the unique key of the record.
    - `_data`: A vector of long integers storing the data associated with the record.
    - `_erased`: A boolean flag indicating whether the record has been marked as erased.
    - `_touched`: A boolean flag indicating whether the record has been accessed or modified.
    - `_all`: A static set of pointers to all instances of fake_rec, used for tracking and managing all created records.
- **Description**: The `fake_rec` struct is a data structure designed to represent a record with a unique key and associated data. It includes mechanisms for tracking its existence and state, such as whether it has been erased or touched. The struct maintains a static set of all instances to ensure proper management and prevent duplicates. The constructor and destructor manage the inclusion and removal of instances from this set, ensuring that each instance is uniquely tracked. The struct also provides methods for generating random records, calculating the size of the data, and accessing the data in a specific format.
- **Member Functions**:
    - [`fake_rec::fake_rec`](#fake_recfake_rec)
    - [`fake_rec::fake_rec`](#fake_recfake_rec)
    - [`fake_rec::~fake_rec`](#fake_recfake_rec)
    - [`fake_rec::make_random`](#fake_recmake_random)
    - [`fake_rec::real_id`](#fake_recreal_id)
    - [`fake_rec::size`](#fake_recsize)
    - [`fake_rec::data`](#fake_recdata)

**Methods**

---
#### fake\_rec::fake\_rec<!-- {{#callable:fake_rec::fake_rec}} -->
The `fake_rec` constructor initializes a `fake_rec` object with a given key and ensures the object is unique within a static set of all `fake_rec` instances.
- **Inputs**:
    - `key`: An unsigned long integer representing the unique key for the `fake_rec` instance.
- **Control Flow**:
    - The constructor is deleted for the default case, meaning `fake_rec` cannot be instantiated without a key.
    - The constructor initializes the `_key` member with the provided `key` argument.
    - An assertion checks that the current instance is not already in the `_all` set, ensuring uniqueness.
    - The current instance is inserted into the static `_all` set of `fake_rec` pointers.
- **Output**: The constructor does not return a value as it is a constructor for the `fake_rec` struct.
- **See also**: [`fake_rec`](#fake_rec)  (Data Structure)


---
#### fake\_rec::fake\_rec<!-- {{#callable:fake_rec::fake_rec}} -->
The `fake_rec` constructor initializes a `fake_rec` object with a given key and ensures the object is unique in the static set of all `fake_rec` instances.
- **Inputs**:
    - `key`: An unsigned long integer (`ulong`) representing the key to initialize the `fake_rec` object with.
- **Control Flow**:
    - The constructor initializes the `_key` member with the provided `key` argument.
    - It asserts that the current object (`this`) is not already present in the static set `_all`.
    - The current object is then inserted into the `_all` set to track all instances of `fake_rec`.
- **Output**: The constructor does not return a value as it is used to initialize an object of the `fake_rec` class.
- **See also**: [`fake_rec`](#fake_rec)  (Data Structure)


---
#### fake\_rec::\~fake\_rec<!-- {{#callable:fake_rec::~fake_rec}} -->
The destructor `~fake_rec` ensures that the current `fake_rec` instance is removed from the static set `_all` upon its destruction.
- **Inputs**: None
- **Control Flow**:
    - The destructor asserts that the current instance (`this`) is present in the `_all` set exactly once.
    - It then removes the current instance from the `_all` set.
- **Output**: The function does not return any value as it is a destructor.
- **See also**: [`fake_rec`](#fake_rec)  (Data Structure)


---
#### fake\_rec::make\_random<!-- {{#callable:fake_rec::make_random}} -->
The `make_random` function creates and returns a new `fake_rec` object with a random key and a randomly sized data vector filled with random values.
- **Inputs**: None
- **Control Flow**:
    - A new `fake_rec` object is created with a random key generated by `lrand48()` modulo `MAX_CHILDREN`.
    - The length of the `_data` vector is determined by another random value from `lrand48()` modulo 8.
    - The `_data` vector is resized to the determined length.
    - A loop iterates over the length of the `_data` vector, filling each element with a random value from `lrand48()`.
    - The newly created `fake_rec` object is returned.
- **Output**: A pointer to a newly created `fake_rec` object with random key and data.
- **See also**: [`fake_rec`](#fake_rec)  (Data Structure)


---
#### fake\_rec::real\_id<!-- {{#callable:fake_rec::real_id}} -->
The `real_id` function returns a `fd_funk_rec_key_t` structure with its first element set to the `_key` of the `fake_rec` instance.
- **Inputs**: None
- **Control Flow**:
    - Declare a variable `i` of type `fd_funk_rec_key_t`.
    - Initialize all bytes of `i` to zero using `memset`.
    - Set the first element of `i.ul` to the `_key` of the `fake_rec` instance.
    - Return the `fd_funk_rec_key_t` structure `i`.
- **Output**: A `fd_funk_rec_key_t` structure with its first element set to the `_key` of the `fake_rec` instance.
- **See also**: [`fake_rec`](#fake_rec)  (Data Structure)


---
#### fake\_rec::size<!-- {{#callable:fake_rec::size}} -->
The `size` function calculates the total memory size in bytes occupied by the `_data` vector of a `fake_rec` instance.
- **Inputs**: None
- **Control Flow**:
    - The function accesses the `_data` member, which is a `std::vector<long>`, of the `fake_rec` instance.
    - It calculates the size of the vector using `_data.size()`, which returns the number of elements in the vector.
    - It multiplies the number of elements by `sizeof(long)` to get the total memory size in bytes occupied by the vector.
    - The function returns this calculated size.
- **Output**: The function returns an `ulong` representing the total memory size in bytes occupied by the `_data` vector.
- **See also**: [`fake_rec`](#fake_rec)  (Data Structure)


---
#### fake\_rec::data<!-- {{#callable:fake_rec::data}} -->
The `data` function returns a pointer to the underlying data of the `_data` vector in the `fake_rec` structure, cast to a `const uchar*` type.
- **Inputs**: None
- **Control Flow**:
    - The function accesses the `_data` member of the `fake_rec` structure, which is a `std::vector<long>`.
    - It calls the `data()` method on the `_data` vector to get a pointer to its underlying array.
    - The pointer is then cast to a `const uchar*` type before being returned.
- **Output**: A pointer to the underlying data of the `_data` vector, cast to a `const uchar*` type.
- **See also**: [`fake_rec`](#fake_rec)  (Data Structure)



---
### fake\_txn<!-- {{#data_structure:fake_txn}} -->
- **Type**: `struct`
- **Members**:
    - `_key`: A unique identifier for the transaction.
    - `_recs`: A vector of pointers to fake_rec objects associated with the transaction.
    - `_children`: A map of child transactions keyed by their unique identifiers.
    - `_parent`: A pointer to the parent transaction, or NULL if there is no parent.
    - `_touched`: A boolean flag indicating whether the transaction has been modified.
- **Description**: The `fake_txn` struct represents a transaction in a simulated transaction system. It maintains a unique key, a collection of records (`fake_rec` objects), and a hierarchical relationship with other transactions through parent and child pointers. The struct provides functionality to insert records, manage child transactions, and track whether the transaction has been modified. It is designed to simulate transaction operations in a larger system, interacting with other components to manage and verify transaction states.
- **Member Functions**:
    - [`fake_txn::fake_txn`](#fake_txnfake_txn)
    - [`fake_txn::~fake_txn`](#fake_txnfake_txn)
    - [`fake_txn::real_id`](#fake_txnreal_id)
    - [`fake_txn::insert`](#fake_txninsert)

**Methods**

---
#### fake\_txn::fake\_txn<!-- {{#callable:fake_txn::fake_txn}} -->
The `fake_txn` constructor initializes a transaction object with a given key, and the destructor cleans up by deleting all associated records.
- **Inputs**:
    - `key`: An unsigned long integer representing the unique identifier for the transaction.
- **Control Flow**:
    - The constructor `fake_txn(ulong key)` initializes the `_key` member with the provided key value.
    - The destructor `~fake_txn()` iterates over the `_recs` vector, deleting each `fake_rec` pointer to free memory.
- **Output**: The constructor does not return a value, and the destructor does not return a value but ensures memory cleanup of records.
- **See also**: [`fake_txn`](#fake_txn)  (Data Structure)


---
#### fake\_txn::\~fake\_txn<!-- {{#callable:fake_txn::~fake_txn}} -->
The destructor `~fake_txn` deletes all `fake_rec` pointers stored in the `_recs` vector of a `fake_txn` object.
- **Inputs**: None
- **Control Flow**:
    - Iterates over each element in the `_recs` vector of the `fake_txn` object.
    - Deletes each `fake_rec` pointer in the vector to free memory.
- **Output**: The function does not return any value as it is a destructor.
- **See also**: [`fake_txn`](#fake_txn)  (Data Structure)


---
#### fake\_txn::real\_id<!-- {{#callable:fake_txn::real_id}} -->
The `real_id` function constructs and returns a `fd_funk_txn_xid_t` object with its first element set to the transaction's key.
- **Inputs**: None
- **Control Flow**:
    - Declare a variable `i` of type `fd_funk_txn_xid_t`.
    - Initialize all bytes of `i` to zero using `memset`.
    - Set the first element of `i.ul` to the transaction's `_key`.
    - Return the `fd_funk_txn_xid_t` object `i`.
- **Output**: A `fd_funk_txn_xid_t` object with its first element set to the transaction's key.
- **See also**: [`fake_txn`](#fake_txn)  (Data Structure)


---
#### fake\_txn::insert<!-- {{#callable:fake_txn::insert}} -->
The `insert` function attempts to add a `fake_rec` record to the `_recs` vector of a `fake_txn` object, ensuring no duplicate keys exist.
- **Inputs**:
    - `rec`: A pointer to a `fake_rec` object that is to be inserted into the `_recs` vector of the `fake_txn`.
- **Control Flow**:
    - Iterate over the `_recs` vector to check if any existing record has the same key as the input `rec`.
    - If a duplicate key is found, delete the input `rec` and return `false`.
    - If no duplicate is found, resize the `_recs` vector to accommodate the new record.
    - Insert the `rec` at the end of the `_recs` vector.
    - Return `true` to indicate successful insertion.
- **Output**: A boolean value indicating whether the insertion was successful (`true`) or failed due to a duplicate key (`false`).
- **See also**: [`fake_txn`](#fake_txn)  (Data Structure)



---
### fake\_funk<!-- {{#data_structure:fake_funk}} -->
- **Type**: `struct`
- **Members**:
    - `_wksp`: A pointer to a workspace of type fd_wksp_t.
    - `_real`: An array of fd_funk_t with a single element.
    - `_txns`: A map associating unsigned long keys with pointers to fake_txn objects.
    - `_lastxid`: An unsigned long representing the last transaction ID used.
    - `close_args`: A structure for file closing arguments, used conditionally with TEST_FUNK_FILE.
- **Description**: The `fake_funk` struct is a complex data structure designed to manage a collection of fake transactions (`fake_txn`) and their associated records (`fake_rec`). It integrates with a workspace (`fd_wksp_t`) and a real transaction system (`fd_funk_t`) to simulate transaction operations such as insertion, removal, and publication of records. The struct maintains a map of transactions, each identified by a unique key, and provides mechanisms to handle transaction hierarchies, including parent-child relationships and transaction cancellation. The struct also includes conditional compilation for file operations, allowing it to open, close, and manage transaction files when the `TEST_FUNK_FILE` macro is defined.
- **Member Functions**:
    - [`fake_funk::fake_funk`](#fake_funkfake_funk)
    - [`fake_funk::~fake_funk`](#fake_funkfake_funk)
    - [`fake_funk::reopen_file`](#fake_funkreopen_file)
    - [`fake_funk::pick_unfrozen_txn`](#fake_funkpick_unfrozen_txn)
    - [`fake_funk::get_real_txn`](#fake_funkget_real_txn)
    - [`fake_funk::random_insert`](#fake_funkrandom_insert)
    - [`fake_funk::random_remove`](#fake_funkrandom_remove)
    - [`fake_funk::random_new_txn`](#fake_funkrandom_new_txn)
    - [`fake_funk::fake_cancel_family`](#fake_funkfake_cancel_family)
    - [`fake_funk::fake_publish_to_parent`](#fake_funkfake_publish_to_parent)
    - [`fake_funk::fake_publish`](#fake_funkfake_publish)
    - [`fake_funk::random_publish`](#fake_funkrandom_publish)
    - [`fake_funk::random_publish_into_parent`](#fake_funkrandom_publish_into_parent)
    - [`fake_funk::random_cancel`](#fake_funkrandom_cancel)
    - [`fake_funk::verify`](#fake_funkverify)

**Methods**

---
#### fake\_funk::fake\_funk<!-- {{#callable:fake_funk::fake_funk}} -->
The `fake_funk` constructor initializes a transactional workspace and sets up a root transaction for managing fake transactions and records.
- **Inputs**:
    - `argc`: A pointer to an integer representing the number of command-line arguments.
    - `argv`: A pointer to an array of character strings representing the command-line arguments.
- **Control Flow**:
    - The function begins by calling `fd_boot` with `argc` and `argv` to initialize the environment.
    - It sets `txn_max` to 128 and `rec_max` to 65536 (1<<16).
    - If `TEST_FUNK_FILE` is defined, it opens a file-backed funk instance using `fd_funk_open_file` and assigns the workspace pointer using [`fd_funk_wksp`](fd_funk.h.driver.md#fd_funk_wksp).
    - If `TEST_FUNK_FILE` is not defined, it creates an anonymous workspace using `fd_wksp_new_anonymous` and allocates memory for a new funk instance using `fd_wksp_alloc_laddr`.
    - It then joins the funk instance using [`fd_funk_join`](fd_funk.c.driver.md#fd_funk_join).
    - Finally, it initializes the root transaction by creating a new `fake_txn` with `ROOT_KEY` and stores it in the `_txns` map.
- **Output**: The function does not return any value; it initializes the `fake_funk` object.
- **Functions called**:
    - [`fd_funk_wksp`](fd_funk.h.driver.md#fd_funk_wksp)
    - [`fd_funk_align`](fd_funk.c.driver.md#fd_funk_align)
    - [`fd_funk_footprint`](fd_funk.c.driver.md#fd_funk_footprint)
    - [`fd_funk_join`](fd_funk.c.driver.md#fd_funk_join)
    - [`fd_funk_new`](fd_funk.c.driver.md#fd_funk_new)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::\~fake\_funk<!-- {{#callable:fake_funk::~fake_funk}} -->
The destructor `~fake_funk` cleans up resources by deleting all transactions, closing a test file if applicable, and logging any leaked records.
- **Inputs**: None
- **Control Flow**:
    - Iterates over the `_txns` map and deletes each transaction object pointed to by the map's values.
    - If `TEST_FUNK_FILE` is defined, it calls `fd_funk_close_file` to close the file and unlinks the test file named `funk_test_file`.
    - Iterates over the static set `fake_rec::_all` and logs a notice for each leaked record.
- **Output**: This destructor does not return any value; it performs cleanup operations.
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::reopen\_file<!-- {{#callable:fake_funk::reopen_file}} -->
The `reopen_file` function closes and then reopens a file associated with the `fake_funk` object, updating the workspace pointer.
- **Inputs**: None
- **Control Flow**:
    - The function first calls `fd_funk_close_file` with `close_args` to close the currently open file.
    - It then calls `fd_funk_open_file` with parameters including `_real`, the file name "funk_test_file", and `close_args` to reopen the file in read-write mode.
    - The function updates the `_wksp` pointer by calling [`fd_funk_wksp`](fd_funk.h.driver.md#fd_funk_wksp) with `_real`.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`fd_funk_wksp`](fd_funk.h.driver.md#fd_funk_wksp)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::pick\_unfrozen\_txn<!-- {{#callable:fake_funk::pick_unfrozen_txn}} -->
The `pick_unfrozen_txn` function selects and returns a random transaction from a list of transactions that have no children.
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `list` to store pointers to `fake_txn` objects and a counter `listlen` to zero.
    - Iterate over all transactions in the `_txns` map.
    - For each transaction, check if it has no children by evaluating if `_children.size()` is zero.
    - If the transaction has no children, add it to the `list` array and increment `listlen`.
    - Select a random index using `lrand48()` modulo `listlen` and return the transaction at that index from the `list`.
- **Output**: A pointer to a randomly selected `fake_txn` object that has no children.
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::get\_real\_txn<!-- {{#callable:fake_funk::get_real_txn}} -->
The `get_real_txn` function retrieves the real transaction object corresponding to a given fake transaction, unless the transaction is the root transaction.
- **Inputs**:
    - `txn`: A pointer to a `fake_txn` object representing the fake transaction for which the real transaction is to be retrieved.
- **Control Flow**:
    - Check if the transaction's key is equal to `ROOT_KEY`; if so, return `NULL` as there is no real transaction for the root.
    - Retrieve the transaction map using `fd_funk_txn_map` with the `_real` member of the `fake_funk` structure.
    - Obtain the real transaction ID by calling `real_id()` on the `fake_txn` object.
    - Query the transaction map for the real transaction using `fd_funk_txn_query` with the real transaction ID and return the result.
- **Output**: A pointer to an `fd_funk_txn_t` object representing the real transaction, or `NULL` if the input transaction is the root transaction.
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::random\_insert<!-- {{#callable:fake_funk::random_insert}} -->
The `random_insert` function selects a random unfrozen transaction and inserts a new unique record into it, then prepares and publishes this record in the real transaction system.
- **Inputs**: None
- **Control Flow**:
    - Select a random unfrozen transaction using `pick_unfrozen_txn()`.
    - Check if the transaction has reached the maximum number of children; if so, exit the function.
    - Create a new random record using `fake_rec::make_random()` and attempt to insert it into the transaction, ensuring no duplicate keys are inserted.
    - Retrieve the real transaction corresponding to the selected fake transaction using `get_real_txn()`.
    - Prepare the record for insertion into the real transaction system using `fd_funk_rec_prepare()`.
    - Allocate memory for the record's value and copy the data from the fake record to the real record using `fd_funk_val_truncate()` and `memcpy()`.
    - Publish the prepared record using `fd_funk_rec_publish()`.
    - Assert that the size of the value in the real record matches the size of the fake record.
- **Output**: The function does not return any value; it performs operations on the transaction and record data structures.
- **Functions called**:
    - [`fake_funk::pick_unfrozen_txn`](#fake_funkpick_unfrozen_txn)
    - [`fake_funk::get_real_txn`](#fake_funkget_real_txn)
    - [`fd_funk_rec_prepare`](fd_funk_rec.c.driver.md#fd_funk_rec_prepare)
    - [`fd_funk_val_truncate`](fd_funk_val.c.driver.md#fd_funk_val_truncate)
    - [`fd_funk_alloc`](fd_funk.h.driver.md#fd_funk_alloc)
    - [`fd_funk_rec_publish`](fd_funk_rec.c.driver.md#fd_funk_rec_publish)
    - [`fd_funk_val_sz`](fd_funk_val.h.driver.md#fd_funk_val_sz)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::random\_remove<!-- {{#callable:fake_funk::random_remove}} -->
The `random_remove` function selects a random non-erased record from a randomly chosen unfrozen transaction and removes it from the real transaction system, marking it as erased.
- **Inputs**: None
- **Control Flow**:
    - Select a random unfrozen transaction using `pick_unfrozen_txn()`.
    - Iterate over the records in the selected transaction to build a list of non-erased records.
    - If there are no non-erased records, exit the function.
    - Select a random record from the list of non-erased records.
    - Retrieve the real transaction corresponding to the selected fake transaction using `get_real_txn()`.
    - Remove the selected record from the real transaction system using `fd_funk_rec_remove()`.
    - Mark the record as erased and clear its data.
- **Output**: The function does not return any value; it modifies the state of the selected record and transaction.
- **Functions called**:
    - [`fake_funk::pick_unfrozen_txn`](#fake_funkpick_unfrozen_txn)
    - [`fake_funk::get_real_txn`](#fake_funkget_real_txn)
    - [`fd_funk_rec_remove`](fd_funk_rec.c.driver.md#fd_funk_rec_remove)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::random\_new\_txn<!-- {{#callable:fake_funk::random_new_txn}} -->
The `random_new_txn` function creates a new transaction in the `fake_funk` system, assigns it a parent transaction, and prepares it for execution.
- **Inputs**: None
- **Control Flow**:
    - Check if the maximum number of transactions (`MAX_TXNS`) has been reached; if so, return immediately.
    - Create an array `list` to hold pointers to existing transactions and populate it with current transactions from `_txns`.
    - Select a random parent transaction from the `list` using a random index generated by `lrand48()`.
    - Increment `_lastxid` to generate a new unique transaction key and create a new `fake_txn` with this key.
    - Assign the selected parent transaction to the new transaction's `_parent` field and add the new transaction to the parent's `_children` map.
    - Retrieve the real transaction object for the parent using [`get_real_txn`](#fake_funkget_real_txn) and prepare the new transaction using [`fd_funk_txn_prepare`](fd_funk_txn.c.driver.md#fd_funk_txn_prepare).
- **Output**: The function does not return any value; it modifies the state of the `fake_funk` object by adding a new transaction to its `_txns` map.
- **Functions called**:
    - [`fake_funk::get_real_txn`](#fake_funkget_real_txn)
    - [`fd_funk_txn_prepare`](fd_funk_txn.c.driver.md#fd_funk_txn_prepare)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::fake\_cancel\_family<!-- {{#callable:fake_funk::fake_cancel_family}} -->
The `fake_cancel_family` function recursively cancels a transaction and all its descendant transactions, removing them from their parent's child list and deleting them from memory.
- **Inputs**:
    - `txn`: A pointer to a `fake_txn` object representing the transaction to be canceled.
- **Control Flow**:
    - Assert that the transaction's key is not the ROOT_KEY, ensuring it is not the root transaction.
    - While the transaction has children, recursively call `fake_cancel_family` on the first child, effectively canceling all descendant transactions.
    - Remove the transaction from its parent's child list using its key.
    - Erase the transaction from the `_txns` map using its key.
    - Delete the transaction object to free memory.
- **Output**: The function does not return any value; it performs operations to cancel and delete transactions.
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::fake\_publish\_to\_parent<!-- {{#callable:fake_funk::fake_publish_to_parent}} -->
The `fake_publish_to_parent` function moves records from a child transaction to its parent, cancels sibling transactions, and reassigns child transactions to the parent before deleting the child transaction.
- **Inputs**:
    - `txn`: A pointer to a `fake_txn` object representing the transaction whose records are to be published to its parent.
- **Control Flow**:
    - Retrieve the parent transaction of the given transaction `txn`.
    - Iterate over each record in `txn`'s records and attempt to insert them into the parent's records, removing any existing records in the parent with the same key.
    - Clear the records of `txn` after moving them to the parent.
    - Enter a loop to cancel all sibling transactions of `txn` by calling [`fake_cancel_family`](#fake_funkfake_cancel_family) on each sibling, repeating until no siblings remain.
    - Assert that `txn` is the only child of its parent after canceling siblings.
    - Clear the parent's children map and reassign all children of `txn` to the parent, updating their parent pointers.
    - Remove `txn` from the global transaction map `_txns` and delete it.
- **Output**: The function does not return any value; it modifies the parent transaction and the global transaction map by moving records and reassigning children.
- **Functions called**:
    - [`fake_funk::fake_cancel_family`](#fake_funkfake_cancel_family)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::fake\_publish<!-- {{#callable:fake_funk::fake_publish}} -->
The `fake_publish` function recursively publishes a transaction and its ancestors to the root transaction, ensuring all records are moved to the parent transaction and siblings are canceled.
- **Inputs**:
    - `txn`: A pointer to a `fake_txn` object representing the transaction to be published.
- **Control Flow**:
    - Assert that the transaction's key is not the ROOT_KEY, ensuring it is not the root transaction.
    - If the transaction's parent is not the root, recursively call `fake_publish` on the parent transaction.
    - Assert that the transaction's parent is now the root transaction, ensuring the transaction is ready to be published to the root.
    - Call [`fake_publish_to_parent`](#fake_funkfake_publish_to_parent) to move the transaction's records to its parent and handle sibling cancellation.
- **Output**: The function does not return a value; it modifies the transaction hierarchy and records in place.
- **Functions called**:
    - [`fake_funk::fake_publish_to_parent`](#fake_funkfake_publish_to_parent)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::random\_publish<!-- {{#callable:fake_funk::random_publish}} -->
The `random_publish` function selects a random transaction from a list of non-root transactions and publishes it using the [`fd_funk_txn_publish`](fd_funk_txn.c.driver.md#fd_funk_txn_publish) function, then simulates the publication with [`fake_publish`](#fake_funkfake_publish).
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `list` to store pointers to `fake_txn` objects and a counter `listlen` to track the number of transactions added to the list.
    - Iterate over the `_txns` map to populate `list` with transactions whose keys are not `ROOT_KEY`.
    - If `listlen` is zero, return immediately as there are no transactions to publish.
    - Select a random transaction from `list` using `lrand48()` and store it in `txn`.
    - Retrieve the real transaction object `txn2` corresponding to `txn` using [`get_real_txn`](#fake_funkget_real_txn).
    - Assert that the [`fd_funk_txn_publish`](fd_funk_txn.c.driver.md#fd_funk_txn_publish) function call on `_real` and `txn2` is successful.
    - Call [`fake_publish`](#fake_funkfake_publish) to simulate the publication of the transaction.
- **Output**: The function does not return any value; it performs operations on transactions and asserts successful publication.
- **Functions called**:
    - [`fake_funk::get_real_txn`](#fake_funkget_real_txn)
    - [`fd_funk_txn_publish`](fd_funk_txn.c.driver.md#fd_funk_txn_publish)
    - [`fake_funk::fake_publish`](#fake_funkfake_publish)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::random\_publish\_into\_parent<!-- {{#callable:fake_funk::random_publish_into_parent}} -->
The `random_publish_into_parent` function selects a random transaction from a list of non-root transactions and publishes it into its parent transaction, simulating the publication process.
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `list` to store pointers to `fake_txn` objects and a counter `listlen` to track the number of transactions added to the list.
    - Iterate over the `_txns` map to populate `list` with transactions whose keys are not equal to `ROOT_KEY`.
    - If `listlen` is zero, indicating no eligible transactions, return immediately.
    - Select a random transaction `txn` from the `list` using `lrand48()` to generate a random index.
    - Retrieve the real transaction object `txn2` corresponding to `txn` using [`get_real_txn`](#fake_funkget_real_txn).
    - Assert that publishing `txn2` into its parent is successful using [`fd_funk_txn_publish_into_parent`](fd_funk_txn.c.driver.md#fd_funk_txn_publish_into_parent).
    - Simulate the publication by calling [`fake_publish_to_parent`](#fake_funkfake_publish_to_parent) with `txn`.
- **Output**: The function does not return any value; it performs operations on the transactions and asserts successful publication.
- **Functions called**:
    - [`fake_funk::get_real_txn`](#fake_funkget_real_txn)
    - [`fd_funk_txn_publish_into_parent`](fd_funk_txn.c.driver.md#fd_funk_txn_publish_into_parent)
    - [`fake_funk::fake_publish_to_parent`](#fake_funkfake_publish_to_parent)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::random\_cancel<!-- {{#callable:fake_funk::random_cancel}} -->
The `random_cancel` function randomly selects a non-root transaction from a list and cancels it, simulating the cancellation process.
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `list` to store pointers to `fake_txn` objects and a counter `listlen` to track the number of transactions added to the list.
    - Iterate over the `_txns` map, adding each transaction to `list` if its key is not `ROOT_KEY`.
    - If `listlen` is zero, indicating no non-root transactions, return immediately.
    - Select a random transaction from `list` using `lrand48()` and store it in `txn`.
    - Retrieve the real transaction object `txn2` corresponding to `txn` using [`get_real_txn`](#fake_funkget_real_txn).
    - Assert that the cancellation of `txn2` in the real transaction system is successful using [`fd_funk_txn_cancel`](fd_funk_txn.c.driver.md#fd_funk_txn_cancel).
    - Simulate the cancellation of the transaction family by calling [`fake_cancel_family`](#fake_funkfake_cancel_family) on `txn`.
- **Output**: The function does not return any value; it performs operations on the transaction system and modifies the state of the `fake_funk` object.
- **Functions called**:
    - [`fake_funk::get_real_txn`](#fake_funkget_real_txn)
    - [`fd_funk_txn_cancel`](fd_funk_txn.c.driver.md#fd_funk_txn_cancel)
    - [`fake_funk::fake_cancel_family`](#fake_funkfake_cancel_family)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)


---
#### fake\_funk::verify<!-- {{#callable:fake_funk::verify}} -->
The `verify` function checks the consistency and integrity of transactions and records within a `fake_funk` object, ensuring that all records and transactions are correctly linked and marked.
- **Inputs**: None
- **Control Flow**:
    - If `FD_FUNK_HANDHOLDING` is defined, assert that `fd_funk_verify(_real)` returns `FD_FUNK_SUCCESS`.
    - Iterate over all transactions in `_txns`, asserting that each transaction's key matches its map key and setting all records' `_touched` flags to false.
    - Initialize an iterator for all records in `_real` and iterate through them, checking that each record's transaction exists in `_txns`, and that the record is correctly linked and not erased unless marked as such.
    - For each record, verify that it matches a corresponding record in `_txns` by comparing keys and data, and mark the record as touched.
    - Iterate over all transactions again, asserting that each record is either touched or erased.
    - Iterate over all transactions to verify parent-child relationships, ensuring the root transaction has no parent and other transactions are correctly linked to their parents.
    - Verify the root transaction's records by iterating over them and ensuring each record exists in the root transaction's records.
    - Initialize a transaction iterator for all transactions in `_real` and iterate through them, verifying that each transaction exists in `_txns`, is not touched, and is correctly linked to its parent.
    - Finally, iterate over all transactions to assert that each transaction is marked as touched.
- **Output**: The function does not return any value; it uses assertions to ensure the integrity and consistency of the data structures.
- **Functions called**:
    - [`fd_funk_verify`](fd_funk.c.driver.md#fd_funk_verify)
    - [`fd_funk_all_iter_new`](fd_funk_rec.c.driver.md#fd_funk_all_iter_new)
    - [`fd_funk_all_iter_done`](fd_funk_rec.c.driver.md#fd_funk_all_iter_done)
    - [`fd_funk_all_iter_next`](fd_funk_rec.c.driver.md#fd_funk_all_iter_next)
    - [`fd_funk_all_iter_ele_const`](fd_funk_rec.c.driver.md#fd_funk_all_iter_ele_const)
    - [`fd_funk_rec_xid`](fd_funk_rec.h.driver.md#fd_funk_rec_xid)
    - [`fd_funk_rec_key`](fd_funk_rec.h.driver.md#fd_funk_rec_key)
    - [`fd_funk_val_sz`](fd_funk_val.h.driver.md#fd_funk_val_sz)
    - [`fd_funk_val`](fd_funk_val.h.driver.md#fd_funk_val)
    - [`fd_funk_rec_query_try_global`](fd_funk_rec.c.driver.md#fd_funk_rec_query_try_global)
    - [`fd_funk_rec_query_test`](fd_funk_rec.c.driver.md#fd_funk_rec_query_test)
    - [`fd_funk_txn_first_rec`](fd_funk_txn.c.driver.md#fd_funk_txn_first_rec)
    - [`fd_funk_txn_next_rec`](fd_funk_txn.c.driver.md#fd_funk_txn_next_rec)
    - [`fd_funk_txn_all_iter_new`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_new)
    - [`fd_funk_txn_all_iter_done`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_done)
    - [`fd_funk_txn_all_iter_next`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_next)
    - [`fd_funk_txn_all_iter_ele_const`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_ele_const)
- **See also**: [`fake_funk`](#fake_funk)  (Data Structure)



