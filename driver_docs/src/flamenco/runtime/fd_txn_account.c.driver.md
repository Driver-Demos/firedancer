# Purpose
The provided C code is a comprehensive implementation for managing transaction accounts, specifically designed to handle both mutable and read-only states. It is part of a larger system, likely dealing with financial transactions or blockchain-like operations, where accounts need to be initialized, modified, and queried. The code defines a set of functions to initialize accounts, set up account metadata, and manage account data in both mutable and read-only contexts. It includes mechanisms for safely acquiring and releasing write access to accounts, ensuring that operations on accounts are thread-safe and consistent.

Key components of the code include functions for initializing accounts from metadata and data, setting up accounts with default values, and managing account states (mutable or read-only). The code also provides a set of vtable definitions that abstract the operations on accounts, allowing for flexible handling of account data depending on its state. The functions are designed to interact with a larger framework, as indicated by the use of external types and functions like `fd_funk_t`, `fd_wksp_t`, and logging macros. This code is intended to be part of a library or module that provides account management functionality, with a focus on ensuring data integrity and consistency across different states and operations.
# Imports and Dependencies

---
- `fd_txn_account.h`
- `fd_runtime.h`


# Global Variables

---
### fd\_txn\_account\_set\_meta\_mutable\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_meta_mutable_readonly` function is designed to handle an error condition where an attempt is made to set metadata as mutable on a readonly account. It logs an error message indicating that this operation is not allowed.
- **Use**: This function is used to enforce immutability constraints on readonly accounts by preventing changes to their metadata.


---
### fd\_txn\_account\_set\_executable\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_executable_readonly` function is designed to handle attempts to set the executable flag on a transaction account that is marked as read-only. It logs an error message indicating that this operation is not allowed.
- **Use**: This function is used to enforce the immutability of read-only transaction accounts by preventing changes to their executable status.


---
### fd\_txn\_account\_set\_owner\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_owner_readonly` function is designed to handle attempts to set the owner of a transaction account that is marked as readonly. It logs an error message indicating that the owner cannot be set in a readonly account.
- **Use**: This function is used to enforce the immutability of readonly transaction accounts by preventing changes to the account owner.


---
### fd\_txn\_account\_set\_lamports\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_lamports_readonly` function is a part of the transaction account management system. It is designed to handle attempts to set the lamports (a unit of currency) for an account that is marked as readonly.
- **Use**: This function logs an error message when there is an attempt to modify the lamports of a readonly account, enforcing the immutability of such accounts.


---
### fd\_txn\_account\_checked\_add\_lamports\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_checked_add_lamports_readonly` function is designed to handle attempts to add lamports to a readonly account. It logs an error message indicating that this operation is not allowed and returns a success code, indicating that the operation is effectively a no-op in this context.
- **Use**: This function is used to prevent modifications to the lamports of a readonly account by logging an error and returning a success code.


---
### fd\_txn\_account\_checked\_sub\_lamports\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_checked_sub_lamports_readonly` function is a global function that attempts to perform a checked subtraction of lamports from a readonly account. It logs an error message indicating that this operation is not allowed on readonly accounts.
- **Use**: This function is used to handle attempts to subtract lamports from readonly accounts, ensuring that such operations are not performed and logging an error if attempted.


---
### fd\_txn\_account\_set\_rent\_epoch\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_rent_epoch_readonly` function is a global function that attempts to set the rent epoch for a transaction account that is marked as read-only. It logs an error message indicating that this operation is not allowed.
- **Use**: This function is used to enforce immutability by preventing changes to the rent epoch of a read-only account.


---
### fd\_txn\_account\_set\_data\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_data_readonly` function is a global function that attempts to set data in a transaction account that is marked as readonly. It logs an error message indicating that data cannot be set in a readonly account.
- **Use**: This function is used to enforce the immutability of data in readonly transaction accounts by preventing any modifications.


---
### fd\_txn\_account\_set\_data\_len\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_data_len_readonly` function is a global function that logs an error message when an attempt is made to set the data length of a readonly account. It is part of a set of functions that manage transaction accounts, specifically handling operations that are not allowed on readonly accounts.
- **Use**: This function is used to enforce immutability by preventing changes to the data length of readonly transaction accounts, ensuring data integrity.


---
### fd\_txn\_account\_set\_slot\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_slot_readonly` function is a global function that attempts to set a slot in a transaction account that is marked as readonly. It logs an error message indicating that this operation is not allowed.
- **Use**: This function is used to enforce the immutability of readonly transaction accounts by preventing any modifications to their slot values.


---
### fd\_txn\_account\_set\_hash\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_hash_readonly` function is a global function that attempts to set a hash value for a transaction account that is marked as readonly. However, it logs an error message indicating that this operation is not allowed.
- **Use**: This function is used to enforce the immutability of readonly transaction accounts by preventing hash modifications.


---
### fd\_txn\_account\_clear\_owner\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_clear_owner_readonly` function is designed to handle attempts to clear the owner of a transaction account that is marked as readonly. It logs an error message indicating that the operation cannot be performed on a readonly account.
- **Use**: This function is used to prevent modifications to the owner field of a readonly transaction account, ensuring data integrity and consistency.


---
### fd\_txn\_account\_set\_meta\_info\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_set_meta_info_readonly` function is a global function that attempts to set metadata information on a transaction account that is marked as readonly. It logs an error message indicating that this operation is not allowed.
- **Use**: This function is used to enforce the immutability of readonly transaction accounts by preventing any modifications to their metadata.


---
### fd\_txn\_account\_resize\_readonly
- **Type**: `function`
- **Description**: The `fd_txn_account_resize_readonly` function is a global function that attempts to resize a transaction account marked as readonly. It logs an error message indicating that resizing a readonly account is not allowed.
- **Use**: This function is used to handle attempts to resize readonly transaction accounts by logging an error.


# Functions

---
### fd\_txn\_account\_init<!-- {{#callable:fd_txn_account_init}} -->
Initializes a transaction account structure with default values and checks for pointer validity.
- **Inputs**:
    - `ptr`: A pointer to a memory location where the `fd_txn_account_t` structure will be initialized.
- **Control Flow**:
    - Checks if the input pointer `ptr` is NULL; if so, logs a warning and returns NULL.
    - Checks if the pointer `ptr` is aligned to the required boundary for `fd_txn_account_t`; if not, logs a warning and returns NULL.
    - Clears the memory at the location pointed to by `ptr` using `memset`.
    - Initializes various fields of the `fd_txn_account_t` structure to default values.
    - Sets the virtual table pointer to the writable vtable.
    - Sets a magic number to validate the structure later.
    - Returns a pointer to the initialized `fd_txn_account_t` structure.
- **Output**: Returns a pointer to the initialized `fd_txn_account_t` structure, or NULL if the input pointer was invalid.


---
### fd\_txn\_account\_setup\_common<!-- {{#callable:fd_txn_account_setup_common}} -->
Sets up common initial values for a transaction account based on its metadata.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be set up.
- **Control Flow**:
    - The function retrieves the account metadata from either `const_meta` or `meta` fields of the `acct` structure.
    - It checks if `starting_dlen` is equal to `ULONG_MAX`, and if so, assigns it the value of `dlen` from the metadata.
    - It checks if `starting_lamports` is equal to `ULONG_MAX`, and if so, assigns it the value of `lamports` from the metadata.
- **Output**: The function does not return a value; it modifies the `acct` structure directly to set its `starting_dlen` and `starting_lamports` based on the metadata.


---
### fd\_txn\_account\_init\_from\_meta\_and\_data\_mutable<!-- {{#callable:fd_txn_account_init_from_meta_and_data_mutable}} -->
Initializes a mutable transaction account from provided metadata and data.
- **Inputs**:
    - `acct`: A pointer to an `fd_txn_account_t` structure representing the transaction account to be initialized.
    - `meta`: A pointer to an `fd_account_meta_t` structure containing metadata associated with the transaction account.
    - `data`: A pointer to a byte array (`uchar *`) that holds the data for the transaction account.
- **Control Flow**:
    - The function assigns the provided `data` and `meta` pointers to the corresponding fields in the `acct->private_state` structure.
    - It sets the `vt` (vtable) pointer of the account to point to the writable vtable, indicating that the account is mutable.
- **Output**: The function does not return a value; it modifies the state of the `acct` structure directly.


---
### fd\_txn\_account\_init\_from\_meta\_and\_data\_readonly<!-- {{#callable:fd_txn_account_init_from_meta_and_data_readonly}} -->
Initializes a transaction account in a read-only state using provided metadata and data.
- **Inputs**:
    - `acct`: A pointer to an `fd_txn_account_t` structure that represents the transaction account to be initialized.
    - `meta`: A constant pointer to an `fd_account_meta_t` structure containing metadata for the account.
    - `data`: A constant pointer to a byte array (`uchar`) that represents the data associated with the account.
- **Control Flow**:
    - The function assigns the `data` pointer to the `const_data` field of the `private_state` member of the `acct` structure.
    - It assigns the `meta` pointer to the `const_meta` field of the `private_state` member of the `acct` structure.
    - The function sets the virtual table pointer `vt` of the `acct` structure to point to the read-only vtable.
- **Output**: The function does not return a value; it modifies the state of the `acct` structure to reflect the read-only initialization.


---
### fd\_txn\_account\_setup\_sentinel\_meta\_readonly<!-- {{#callable:fd_txn_account_setup_sentinel_meta_readonly}} -->
Sets up a read-only sentinel metadata structure for a transaction account.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure representing the transaction account to be set up.
    - `spad`: A pointer to the `fd_spad_t` structure used for memory allocation.
    - `spad_wksp`: A pointer to the `fd_wksp_t` structure representing the workspace for the allocated memory.
- **Control Flow**:
    - Allocates memory for a `fd_account_meta_t` structure using `fd_spad_alloc`.
    - Initializes the allocated memory to zero using `fd_memset`.
    - Sets the `magic` field of the sentinel to `FD_ACCOUNT_META_MAGIC`.
    - Sets the `rent_epoch` field of the sentinel to `ULONG_MAX`.
    - Assigns the sentinel to the `const_meta` field of the account's private state.
    - Initializes the `starting_lamports` and `starting_dlen` fields of the account to zero.
    - Calculates and assigns the global address of the sentinel in the workspace to `meta_gaddr`.
- **Output**: The function does not return a value; it modifies the state of the provided transaction account by setting up its metadata.


---
### fd\_txn\_account\_setup\_meta\_mutable<!-- {{#callable:fd_txn_account_setup_meta_mutable}} -->
Sets up mutable metadata and data for a transaction account.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure representing the transaction account to be set up.
    - `spad`: A pointer to the `fd_spad_t` structure used for memory allocation.
    - `sz`: An unsigned long integer representing the size of additional data to be allocated.
- **Control Flow**:
    - Allocates memory for `fd_account_meta_t` and additional data using `fd_spad_alloc`.
    - Calculates the pointer to the additional data by offsetting from the `fd_account_meta_t` structure.
    - Sets the `const_meta` and `meta` fields of the account's private state to the allocated metadata.
    - Sets the `const_data` and `data` fields of the account's private state to the allocated additional data.
    - Assigns the writable vtable to the account's vtable pointer.
- **Output**: The function does not return a value; it modifies the state of the provided transaction account.


---
### fd\_txn\_account\_setup\_readonly<!-- {{#callable:fd_txn_account_setup_readonly}} -->
Sets up a transaction account in a read-only state using a public key and account metadata.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure that represents the transaction account to be set up.
    - `pubkey`: A pointer to a `fd_pubkey_t` structure containing the public key associated with the account.
    - `meta`: A pointer to a constant `fd_account_meta_t` structure that holds metadata for the account.
- **Control Flow**:
    - Copies the public key from the `pubkey` argument into the `acct->pubkey` field.
    - Assigns the `meta` pointer to `acct->private_state.const_meta` without copying the metadata, assuming read locks are held.
    - Calculates the address of the constant data by adding the length of the metadata header to the `meta` pointer and assigns it to `acct->private_state.const_data`.
    - Sets the virtual table pointer `acct->vt` to point to the read-only vtable.
    - Calls the [`fd_txn_account_setup_common`](#fd_txn_account_setup_common) function to initialize common fields of the account.
- **Output**: The function does not return a value; it modifies the `acct` structure in place to set it up as a read-only transaction account.
- **Functions called**:
    - [`fd_txn_account_setup_common`](#fd_txn_account_setup_common)


---
### fd\_txn\_account\_setup\_mutable<!-- {{#callable:fd_txn_account_setup_mutable}} -->
Sets up a mutable transaction account with the provided public key and metadata.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure representing the transaction account to be set up.
    - `pubkey`: A pointer to a `fd_pubkey_t` structure containing the public key associated with the account.
    - `meta`: A pointer to a `fd_account_meta_t` structure containing metadata for the account.
- **Control Flow**:
    - Copies the public key from the `pubkey` argument into the `acct->pubkey` field.
    - Sets the `const_rec` field of the account's private state to the current record.
    - Assigns the `meta` argument to both `const_meta` and `meta` fields of the account's private state.
    - Calculates the address for the account's data by adding the header length (`hlen`) of the metadata to the metadata pointer and assigns it to both `const_data` and `data` fields.
    - Sets the virtual table pointer (`vt`) to point to the writable vtable for transaction accounts.
    - Calls the [`fd_txn_account_setup_common`](#fd_txn_account_setup_common) function to perform additional common setup tasks.
- **Output**: The function does not return a value; it modifies the provided `acct` structure in place to set it up as a mutable transaction account.
- **Functions called**:
    - [`fd_txn_account_setup_common`](#fd_txn_account_setup_common)


---
### fd\_txn\_account\_init\_data<!-- {{#callable:fd_txn_account_init_data}} -->
Initializes account data for a transaction account, either by copying existing metadata or setting up new metadata.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account whose data is to be initialized.
    - `buf`: A pointer to a buffer where the account data will be initialized; it is assumed to point to sufficient memory for the account data.
- **Control Flow**:
    - The function first casts the `buf` pointer to a `uchar*` type to work with raw byte data.
    - It checks if the `const_meta` field of the `acct` structure is not NULL to determine if the account already has existing metadata.
    - If `const_meta` is not NULL, it copies the metadata and associated data length from `const_meta` to the `new_raw_data` buffer using `fd_memcpy`.
    - If `const_meta` is NULL, it indicates that the account did not exist, and the function calls [`fd_account_meta_init`](fd_acc_mgr.h.driver.md#fd_account_meta_init) to initialize the metadata in the `new_raw_data` buffer.
- **Output**: Returns a pointer to the initialized account data in the buffer.
- **Functions called**:
    - [`fd_account_meta_init`](fd_acc_mgr.h.driver.md#fd_account_meta_init)


---
### fd\_txn\_account\_make\_mutable<!-- {{#callable:fd_txn_account_make_mutable}} -->
The `fd_txn_account_make_mutable` function converts a transaction account to a mutable state, initializing its data and metadata.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure representing the transaction account to be made mutable.
    - `buf`: A pointer to a buffer that will be used to store the mutable account's data.
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for managing global addresses of the account's metadata and data.
- **Control Flow**:
    - The function first checks if the account's data is already mutable; if so, it logs an error.
    - It retrieves the length of the data from the account's metadata if available.
    - It initializes the account's data using the provided buffer by calling [`fd_txn_account_init_data`](#fd_txn_account_init_data).
    - The account's metadata and data pointers are updated to point to the newly initialized data.
    - Global addresses for the metadata and data are updated using the workspace.
    - Finally, the account's virtual table is set to the writable vtable.
- **Output**: The function returns a pointer to the updated `fd_txn_account_t` structure, now in a mutable state.
- **Functions called**:
    - [`fd_txn_account_init_data`](#fd_txn_account_init_data)


---
### fd\_txn\_account\_init\_from\_funk\_readonly<!-- {{#callable:fd_txn_account_init_from_funk_readonly}} -->
Initializes a transaction account in read-only mode using metadata from a specified funk.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure that represents the transaction account to be initialized.
    - `pubkey`: A pointer to a `fd_pubkey_t` structure that contains the public key associated with the account.
    - `funk`: A pointer to a `fd_funk_t` structure that represents the funk from which to read account metadata.
    - `funk_txn`: A pointer to a `fd_funk_txn_t` structure that represents the transaction context within the funk.
- **Control Flow**:
    - Calls [`fd_txn_account_init`](#fd_txn_account_init) to initialize the account structure.
    - Retrieves account metadata using [`fd_funk_get_acc_meta_readonly`](fd_acc_mgr.c.driver.md#fd_funk_get_acc_meta_readonly), checking for errors.
    - If an error occurs during metadata retrieval, it returns the error code.
    - Checks if the retrieved metadata exists; if not, returns an unknown account error.
    - Validates the magic number of the account to ensure it is correctly initialized.
    - Sets up global addresses for metadata and data for execution and replay sharing.
    - Calls [`fd_txn_account_setup_readonly`](#fd_txn_account_setup_readonly) to finalize the setup of the account in read-only mode.
    - Returns success if all operations complete without errors.
- **Output**: Returns `FD_ACC_MGR_SUCCESS` on successful initialization, or an error code indicating the type of failure.
- **Functions called**:
    - [`fd_txn_account_init`](#fd_txn_account_init)
    - [`fd_funk_get_acc_meta_readonly`](fd_acc_mgr.c.driver.md#fd_funk_get_acc_meta_readonly)
    - [`fd_account_meta_exists`](fd_acc_mgr.h.driver.md#fd_account_meta_exists)
    - [`fd_txn_account_setup_readonly`](#fd_txn_account_setup_readonly)


---
### fd\_txn\_account\_init\_from\_funk\_mutable<!-- {{#callable:fd_txn_account_init_from_funk_mutable}} -->
Initializes a mutable transaction account from a funk and its associated transaction.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure that will be initialized.
    - `pubkey`: A pointer to the public key (`fd_pubkey_t`) associated with the account.
    - `funk`: A pointer to the `fd_funk_t` structure representing the funk context.
    - `funk_txn`: A pointer to the `fd_funk_txn_t` structure representing the transaction context.
    - `do_create`: An integer flag indicating whether to create a new account if it does not exist.
    - `min_data_sz`: An unsigned long specifying the minimum size of data to allocate for the account.
- **Control Flow**:
    - Calls [`fd_txn_account_init`](#fd_txn_account_init) to initialize the account structure.
    - Prepares a `fd_funk_rec_prepare_t` structure for record preparation.
    - Retrieves the account metadata using [`fd_funk_get_acc_meta_mutable`](fd_acc_mgr.c.driver.md#fd_funk_get_acc_meta_mutable), passing in the funk, transaction, public key, creation flag, and minimum data size.
    - Checks if the metadata retrieval was successful; if not, returns the error code.
    - Validates the magic number of the retrieved metadata to ensure it is correct; if not, returns an error code.
    - Populates the `prepared_rec` field of the account with the prepared record.
    - Calls [`fd_txn_account_setup_mutable`](#fd_txn_account_setup_mutable) to set up the account with the public key and metadata.
    - Triggers a segmentation fault if the function is called from an execution tile, ensuring that the data is not accessed inappropriately.
- **Output**: Returns `FD_ACC_MGR_SUCCESS` on successful initialization, or an error code if any checks fail.
- **Functions called**:
    - [`fd_txn_account_init`](#fd_txn_account_init)
    - [`fd_funk_get_acc_meta_mutable`](fd_acc_mgr.c.driver.md#fd_funk_get_acc_meta_mutable)
    - [`fd_txn_account_setup_mutable`](#fd_txn_account_setup_mutable)


---
### fd\_txn\_account\_save\_internal<!-- {{#callable:fd_txn_account_save_internal}} -->
The `fd_txn_account_save_internal` function saves the internal state of a transaction account to a specified workspace.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be saved.
    - `funk`: A pointer to a `fd_funk_t` structure representing the workspace where the account's state will be saved.
- **Control Flow**:
    - The function first checks if the `rec` field of the `private_state` in the `acct` is NULL, returning an error code if it is.
    - It retrieves the workspace associated with the `funk` parameter.
    - The function calculates the length of the record to be saved, which includes the size of the account metadata and the length of the account's data.
    - It retrieves a pointer to the raw memory location where the account's state will be saved.
    - The function then copies the account's metadata into the specified memory location.
    - Finally, it returns a success code.
- **Output**: The function returns an integer indicating the success or failure of the save operation, with `FD_ACC_MGR_SUCCESS` indicating success and `FD_ACC_MGR_ERR_WRITE_FAILED` indicating failure.


---
### fd\_txn\_account\_save<!-- {{#callable:fd_txn_account_save}} -->
The `fd_txn_account_save` function saves the state of a transaction account to a specified workspace, ensuring that the account is writable and managing the associated records in a transaction.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be saved.
    - `funk`: A pointer to a `fd_funk_t` structure representing the transaction context in which the account is being saved.
    - `txn`: A pointer to a `fd_funk_txn_t` structure representing the specific transaction that is being processed.
    - `acc_data_wksp`: A pointer to a `fd_wksp_t` structure representing the workspace where account data is stored.
- **Control Flow**:
    - The function retrieves the addresses of the account's metadata and data from the workspace using `fd_wksp_laddr`.
    - If the metadata pointer is NULL, it logs a debug message and returns an error indicating that the account is not writable.
    - The function prepares a record key for the account using [`fd_funk_acc_key`](fd_acc_mgr.h.driver.md#fd_funk_rec_key_tfd_funk_acc_key) and removes any previous record associated with that key from the transaction.
    - It then prepares a new record for the account in the transaction and checks for errors during this process.
    - The function attempts to truncate the record to the appropriate size and logs an error if this fails.
    - Finally, it calls [`fd_txn_account_save_internal`](#fd_txn_account_save_internal) to save the account's internal state and publishes the prepared record.
- **Output**: The function returns an integer indicating the success or failure of the save operation, with specific error codes for different failure conditions.
- **Functions called**:
    - [`fd_funk_rec_key_t::fd_funk_acc_key`](fd_acc_mgr.h.driver.md#fd_funk_rec_key_tfd_funk_acc_key)
    - [`fd_txn_account_save_internal`](#fd_txn_account_save_internal)


---
### fd\_txn\_account\_mutable\_fini<!-- {{#callable:fd_txn_account_mutable_fini}} -->
Finalizes the mutable transaction account by validating and potentially publishing the prepared record.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure representing the transaction account to be finalized.
    - `funk`: A pointer to the `fd_funk_t` structure representing the funk context in which the transaction is being processed.
    - `txn`: A pointer to the `fd_funk_txn_t` structure representing the current transaction context.
- **Control Flow**:
    - The function begins by creating a query structure and generating a key from the account's public key.
    - It attempts to retrieve an existing record from the funk context using the generated key.
    - If a prepared record exists, it checks for its validity, ensuring it is not null and that its key matches the expected key.
    - If a record already exists in the funk context and a prepared record is also present, an error is logged.
    - If no existing record is found and a prepared record exists, the prepared record is published to the funk context.
- **Output**: The function does not return a value; it performs operations that may log errors or publish a record based on the state of the transaction account.
- **Functions called**:
    - [`fd_funk_rec_key_t::fd_funk_acc_key`](fd_acc_mgr.h.driver.md#fd_funk_rec_key_tfd_funk_acc_key)


---
### fd\_txn\_account\_acquire\_write\_is\_safe<!-- {{#callable:fd_txn_account_acquire_write_is_safe}} -->
Checks if it is safe to acquire write access to a transaction account.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account to check.
- **Control Flow**:
    - The function evaluates the `refcnt_excl` field of the `private_state` member of the `acct` structure.
    - It returns 1 (true) if `refcnt_excl` is zero, indicating that it is safe to acquire write access, otherwise it returns 0 (false).
- **Output**: Returns an integer value: 1 if it is safe to acquire write access, or 0 if it is not.


---
### fd\_txn\_account\_acquire\_write<!-- {{#callable:fd_txn_account_acquire_write}} -->
Acquires exclusive write access to a transaction account if it is safe to do so.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to acquire write access for.
- **Control Flow**:
    - The function first checks if acquiring write access is safe by calling [`fd_txn_account_acquire_write_is_safe`](#fd_txn_account_acquire_write_is_safe) with the provided account.
    - If the check fails (i.e., it is not safe to acquire write access), the function returns 0.
    - If the check passes, it sets the `refcnt_excl` field of the account's private state to 1, indicating that write access has been successfully acquired.
    - Finally, the function returns 1 to indicate success.
- **Output**: Returns 1 if write access was successfully acquired, or 0 if it was not safe to acquire write access.
- **Functions called**:
    - [`fd_txn_account_acquire_write_is_safe`](#fd_txn_account_acquire_write_is_safe)


---
### fd\_txn\_account\_release\_write<!-- {{#callable:fd_txn_account_release_write}} -->
Releases exclusive write access to a transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account whose write access is being released.
- **Control Flow**:
    - The function first checks that the exclusive reference count (`refcnt_excl`) of the account is exactly 1 using `FD_TEST`, ensuring that it is safe to release the write access.
    - If the check passes, it sets the `refcnt_excl` to 0, effectively releasing the write access.
- **Output**: The function does not return a value; it modifies the state of the `acct` by resetting its exclusive reference count.


---
### fd\_txn\_account\_release\_write\_private<!-- {{#callable:fd_txn_account_release_write_private}} -->
Releases the write access of a transaction account if it is currently acquired.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account whose write access is to be released.
- **Control Flow**:
    - The function first checks if the write access is currently safe to release by calling [`fd_txn_account_acquire_write_is_safe`](#fd_txn_account_acquire_write_is_safe).
    - If the write access is not safe (i.e., it is currently acquired), it calls [`fd_txn_account_release_write`](#fd_txn_account_release_write) to release the write access.
- **Output**: This function does not return a value; it modifies the state of the transaction account by releasing its write access if it was previously acquired.
- **Functions called**:
    - [`fd_txn_account_acquire_write_is_safe`](#fd_txn_account_acquire_write_is_safe)
    - [`fd_txn_account_release_write`](#fd_txn_account_release_write)


---
### fd\_txn\_account\_get\_acc\_meta<!-- {{#callable:fd_txn_account_get_acc_meta}} -->
Returns the constant account metadata associated with a transaction account.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which to retrieve the metadata.
- **Control Flow**:
    - The function directly accesses the `private_state` member of the `acct` structure.
    - It retrieves the `const_meta` pointer from the `private_state` of the account.
- **Output**: Returns a pointer to a constant `fd_account_meta_t` structure containing the metadata of the account, or NULL if the account does not have associated metadata.


---
### fd\_txn\_account\_get\_acc\_data<!-- {{#callable:fd_txn_account_get_acc_data}} -->
Returns a pointer to the constant account data from a transaction account.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which to retrieve the data.
- **Control Flow**:
    - The function directly accesses the `private_state` member of the `acct` structure.
    - It retrieves the `const_data` pointer from the `private_state` of the account.
- **Output**: Returns a pointer to a constant `uchar` array representing the account's data.


---
### fd\_txn\_account\_get\_acc\_rec<!-- {{#callable:fd_txn_account_get_acc_rec}} -->
Retrieves the constant account record from a transaction account.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which the record is to be retrieved.
- **Control Flow**:
    - The function directly accesses the `private_state` member of the `acct` structure.
    - It retrieves the `const_rec` field from the `private_state` structure of the account.
- **Output**: Returns a pointer to a constant `fd_funk_rec_t` structure, which represents the account record associated with the transaction account.


---
### fd\_txn\_account\_get\_acc\_data\_mut\_writable<!-- {{#callable:fd_txn_account_get_acc_data_mut_writable}} -->
Returns a pointer to the mutable writable account data of a transaction account.
- **Inputs**:
    - `acct`: A constant pointer to a `fd_txn_account_t` structure representing the transaction account from which to retrieve the mutable writable data.
- **Control Flow**:
    - The function directly accesses the `data` member of the `private_state` structure within the `acct` parameter.
    - It returns the value of `acct->private_state.data`, which is expected to be a pointer to the mutable writable data.
- **Output**: Returns a pointer of type `uchar*` that points to the mutable writable data associated with the transaction account.


---
### fd\_txn\_account\_set\_meta\_readonly<!-- {{#callable:fd_txn_account_set_meta_readonly}} -->
Sets the `const_meta` field of a transaction account to a read-only account metadata.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be modified.
    - `meta`: A pointer to a constant `fd_account_meta_t` structure containing the metadata to be set as read-only.
- **Control Flow**:
    - The function directly assigns the `meta` pointer to the `const_meta` field of the `acct` structure.
    - No conditional checks or loops are present, making the function straightforward and efficient.
- **Output**: The function does not return a value; it modifies the state of the `acct` structure in place.


---
### fd\_txn\_account\_set\_meta\_mutable\_writable<!-- {{#callable:fd_txn_account_set_meta_mutable_writable}} -->
Sets the mutable writable metadata for a transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be modified.
    - `meta`: A pointer to a `fd_account_meta_t` structure containing the metadata to be set for the transaction account.
- **Control Flow**:
    - The function directly assigns the `meta` pointer to both `acct->private_state.const_meta` and `acct->private_state.meta`.
    - This operation effectively updates the metadata for the transaction account to the new value provided.
- **Output**: The function does not return a value; it modifies the state of the `acct` structure directly.


---
### fd\_txn\_account\_get\_data\_len<!-- {{#callable:fd_txn_account_get_data_len}} -->
Retrieves the length of the data associated with a transaction account.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account.
- **Control Flow**:
    - Checks if the `const_meta` field of the `private_state` in the `acct` is NULL, indicating that the account is not properly set up.
    - If `const_meta` is NULL, logs an error message indicating that the account is not set up.
    - Returns the `dlen` field from the `const_meta`, which represents the length of the data associated with the account.
- **Output**: Returns the length of the data associated with the transaction account, or triggers an error log if the account is not set up.


---
### fd\_txn\_account\_is\_executable<!-- {{#callable:fd_txn_account_is_executable}} -->
Checks if a transaction account is executable based on its metadata.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account to be checked.
- **Control Flow**:
    - The function first checks if the `const_meta` field of the `private_state` of the account is NULL, indicating that the account is not properly set up.
    - If `const_meta` is NULL, an error message is logged using `FD_LOG_ERR`.
    - The function then returns the value of the `executable` field from the `info` structure within `const_meta`, converting it to an integer (0 or 1) using the double negation operator (!!).
- **Output**: Returns 1 if the account is executable, 0 otherwise.


---
### fd\_txn\_account\_get\_owner<!-- {{#callable:fd_txn_account_get_owner}} -->
Retrieves the owner public key of a transaction account.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which the owner public key is to be retrieved.
- **Control Flow**:
    - The function first checks if the `const_meta` field of the `private_state` of the `acct` is NULL, indicating that the account is not properly set up.
    - If the account is not set up, it logs an error message using `FD_LOG_ERR`.
    - If the account is set up, it retrieves the owner public key from the `info` field of the `const_meta` structure and returns it.
- **Output**: Returns a pointer to the `fd_pubkey_t` structure representing the owner of the transaction account, or NULL if the account is not set up.


---
### fd\_txn\_account\_get\_lamports<!-- {{#callable:fd_txn_account_get_lamports}} -->
Retrieves the number of lamports from a transaction account.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which to retrieve the lamports.
- **Control Flow**:
    - The function first checks if the `const_meta` field of the `acct` structure is NULL, indicating an internal error; if it is NULL, the function returns 0.
    - If `const_meta` is valid, the function accesses the `info` field of `const_meta` to retrieve the `lamports` value and returns it.
- **Output**: Returns the number of lamports as an unsigned long integer, or 0 if the account's metadata is not set.


---
### fd\_txn\_account\_get\_rent\_epoch<!-- {{#callable:fd_txn_account_get_rent_epoch}} -->
Retrieves the rent epoch from a transaction account's metadata.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which the rent epoch is to be retrieved.
- **Control Flow**:
    - The function first checks if the `const_meta` field of the `private_state` of the account is NULL, indicating that the account is not properly set up.
    - If `const_meta` is NULL, an error is logged indicating that the account is not set up.
    - If the account is set up correctly, the function accesses the `rent_epoch` field from the `info` structure within `const_meta` and returns its value.
- **Output**: Returns the rent epoch as an unsigned long integer, which represents the epoch in which the account's rent is due.


---
### fd\_txn\_account\_get\_hash<!-- {{#callable:fd_txn_account_get_hash}} -->
Retrieves the hash associated with a transaction account.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which the hash is to be retrieved.
- **Control Flow**:
    - Checks if the `const_meta` field of the `private_state` of the account is NULL, indicating that the account is not properly set up.
    - If the account is not set up, logs an error message.
    - Returns the hash from the `const_meta` structure of the account.
- **Output**: Returns a pointer to a constant `fd_hash_t` structure containing the hash of the transaction account, or NULL if the account is not set up.


---
### fd\_txn\_account\_get\_info<!-- {{#callable:fd_txn_account_get_info}} -->
Retrieves the account metadata information from a transaction account structure.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which to retrieve metadata.
- **Control Flow**:
    - Checks if the `const_meta` field of the `private_state` in the `acct` is NULL, indicating that the account is not properly set up.
    - If `const_meta` is NULL, logs an error message indicating that the account is not set up.
    - Returns a pointer to the `info` field of the `const_meta` structure, which contains the account metadata.
- **Output**: Returns a pointer to a constant `fd_solana_account_meta_t` structure containing the metadata information of the transaction account.


---
### fd\_txn\_account\_set\_executable\_writable<!-- {{#callable:fd_txn_account_set_executable_writable}} -->
Sets the 'executable' property of a transaction account to a specified boolean value.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account.
    - `is_executable`: An integer that indicates whether the account should be set as executable (non-zero value) or not (zero value).
- **Control Flow**:
    - Checks if the `meta` field of the `private_state` in the account structure is NULL, indicating that the account is not mutable.
    - If the account is not mutable, logs an error message.
    - Sets the `executable` field in the `info` structure of the account's `meta` to the boolean value of `is_executable`.
- **Output**: The function does not return a value; it modifies the state of the account directly.


---
### fd\_txn\_account\_set\_owner\_writable<!-- {{#callable:fd_txn_account_set_owner_writable}} -->
Sets the owner of a transaction account to a writable state.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account whose owner is to be set.
    - `owner`: A pointer to a `fd_pubkey_t` structure containing the public key of the new owner.
- **Control Flow**:
    - Checks if the `meta` field of the `acct` is NULL, indicating that the account is not mutable; if so, logs an error.
    - Copies the `owner` public key into the `info.owner` field of the `acct->private_state.meta` structure.
- **Output**: The function does not return a value; it modifies the owner field of the account's metadata directly.


---
### fd\_txn\_account\_set\_lamports\_writable<!-- {{#callable:fd_txn_account_set_lamports_writable}} -->
Sets the `lamports` value of a mutable transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be modified.
    - `lamports`: An unsigned long integer representing the new value of lamports to be set for the account.
- **Control Flow**:
    - Checks if the `meta` field of the account's private state is NULL, indicating that the account is not mutable.
    - If the account is not mutable, logs an error message.
    - If the account is mutable, updates the `lamports` field in the account's metadata with the provided value.
- **Output**: The function does not return a value; it modifies the `lamports` field of the account's metadata directly.


---
### fd\_txn\_account\_checked\_add\_lamports\_writable<!-- {{#callable:fd_txn_account_checked_add_lamports_writable}} -->
This function adds a specified number of lamports to a writable transaction account after checking for arithmetic overflow.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to which lamports will be added.
    - `lamports`: An unsigned long integer representing the number of lamports to add to the account's balance.
- **Control Flow**:
    - The function initializes a variable `balance_post` to zero.
    - It calls [`fd_ulong_checked_add`](program/fd_program_util.h.driver.md#fd_ulong_checked_add) to attempt to add the current lamports in the account (retrieved via `acct->vt->get_lamports(acct)`) to the specified `lamports`, storing the result in `balance_post`.
    - If [`fd_ulong_checked_add`](program/fd_program_util.h.driver.md#fd_ulong_checked_add) returns an error (indicating an arithmetic overflow), the function returns an error code `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW`.
    - If the addition is successful, it updates the account's lamports by calling `acct->vt->set_lamports(acct, balance_post)`.
    - Finally, the function returns `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful completion.
- **Output**: The function returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` on successful addition of lamports, or `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW` if an overflow occurred during the addition.
- **Functions called**:
    - [`fd_ulong_checked_add`](program/fd_program_util.h.driver.md#fd_ulong_checked_add)


---
### fd\_txn\_account\_checked\_sub\_lamports\_writable<!-- {{#callable:fd_txn_account_checked_sub_lamports_writable}} -->
This function subtracts a specified number of lamports from a transaction account's balance, ensuring that the operation does not result in an arithmetic overflow.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account from which lamports will be subtracted.
    - `lamports`: An unsigned long integer representing the number of lamports to subtract from the account's balance.
- **Control Flow**:
    - The function first retrieves the current balance of lamports in the account using `acct->vt->get_lamports(acct)`.
    - It then calls [`fd_ulong_checked_sub`](program/fd_program_util.h.driver.md#FD_FN_UNUSEDfd_ulong_checked_sub) to perform a checked subtraction of the specified `lamports` from the current balance.
    - If the subtraction results in an error (indicating an arithmetic overflow), the function returns an error code `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW`.
    - If the subtraction is successful, it updates the account's balance by calling `acct->vt->set_lamports(acct, balance_post)`.
    - Finally, the function returns `FD_EXECUTOR_INSTR_SUCCESS` to indicate that the operation was completed successfully.
- **Output**: The function returns an integer status code: `FD_EXECUTOR_INSTR_SUCCESS` if the operation was successful, or `FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW` if there was an arithmetic overflow during the subtraction.
- **Functions called**:
    - [`FD_FN_UNUSED::fd_ulong_checked_sub`](program/fd_program_util.h.driver.md#FD_FN_UNUSEDfd_ulong_checked_sub)


---
### fd\_txn\_account\_set\_rent\_epoch\_writable<!-- {{#callable:fd_txn_account_set_rent_epoch_writable}} -->
Sets the rent epoch of a transaction account to a specified value if the account is mutable.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account whose rent epoch is to be set.
    - `rent_epoch`: An unsigned long integer representing the new rent epoch value to be set for the account.
- **Control Flow**:
    - The function first checks if the `meta` field of the `private_state` in the `acct` is NULL, indicating that the account is not mutable.
    - If the account is not mutable, an error is logged using `FD_LOG_ERR`.
    - If the account is mutable, the `rent_epoch` field of the `info` structure within `meta` is updated to the new value provided.
- **Output**: The function does not return a value; it modifies the state of the account directly.


---
### fd\_txn\_account\_set\_data\_writable<!-- {{#callable:fd_txn_account_set_data_writable}} -->
Sets the data of a transaction account to be writable and updates its length.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure representing the transaction account to be modified.
    - `data`: A pointer to the data that will be copied into the account's writable data area.
    - `data_sz`: An unsigned long integer representing the size of the data to be copied.
- **Control Flow**:
    - Checks if the `meta` field of the account is NULL, indicating that the account is not mutable; if so, logs an error.
    - Updates the `dlen` field of the account's `meta` to the size of the new data.
    - Copies the provided data into the account's writable data area using `fd_memcpy`.
- **Output**: The function does not return a value; it modifies the state of the `fd_txn_account_t` structure directly.


---
### fd\_txn\_account\_set\_data\_len\_writable<!-- {{#callable:fd_txn_account_set_data_len_writable}} -->
Sets the data length of a writable transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account whose data length is to be set.
    - `data_len`: An unsigned long integer representing the new length of the data to be set for the transaction account.
- **Control Flow**:
    - Checks if the `meta` field of the `private_state` of the account is NULL, indicating that the account is not mutable.
    - If the account is not mutable, logs an error message.
    - If the account is mutable, sets the `dlen` field of the `meta` structure to the provided `data_len`.
- **Output**: The function does not return a value; it modifies the `dlen` field of the account's metadata directly.


---
### fd\_txn\_account\_set\_slot\_writable<!-- {{#callable:fd_txn_account_set_slot_writable}} -->
Sets the writable slot of a transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be modified.
    - `slot`: An unsigned long integer representing the new slot value to be set for the account.
- **Control Flow**:
    - Checks if the `meta` field of the `acct` is NULL, indicating that the account is not mutable.
    - If the account is not mutable, logs an error message.
    - If the account is mutable, sets the `slot` field of the `meta` structure to the provided `slot` value.
- **Output**: The function does not return a value; it modifies the `slot` field of the account's metadata directly.


---
### fd\_txn\_account\_set\_hash\_writable<!-- {{#callable:fd_txn_account_set_hash_writable}} -->
Sets the hash of a writable transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be modified.
    - `hash`: A pointer to a `fd_hash_t` structure containing the new hash value to be set for the account.
- **Control Flow**:
    - Checks if the `meta` field of the `acct` is NULL, indicating that the account is not mutable; if so, logs an error.
    - Copies the hash value from the `hash` parameter into the `hash` field of the `meta` structure of the `acct`.
- **Output**: The function does not return a value; it modifies the state of the `acct` by setting its hash.


---
### fd\_txn\_account\_clear\_owner\_writable<!-- {{#callable:fd_txn_account_clear_owner_writable}} -->
Clears the owner field of a writable transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account whose owner is to be cleared.
- **Control Flow**:
    - Checks if the `meta` field of the account's private state is NULL, indicating that the account is not mutable.
    - If the account is not mutable, logs an error message.
    - If the account is mutable, sets the owner field in the `info` structure of the account's `meta` to zero using `fd_memset`.
- **Output**: The function does not return a value; it modifies the state of the account by clearing the owner field.


---
### fd\_txn\_account\_set\_meta\_info\_writable<!-- {{#callable:fd_txn_account_set_meta_info_writable}} -->
Sets the metadata information of a writable transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account whose metadata is to be set.
    - `info`: A constant pointer to a `fd_solana_account_meta_t` structure containing the new metadata information to be assigned to the account.
- **Control Flow**:
    - Checks if the `meta` field of the `acct` structure is NULL, indicating that the account is not mutable.
    - If the account is not mutable, logs an error message.
    - If the account is mutable, copies the contents of the `info` structure into the `info` field of the account's `meta`.
- **Output**: The function does not return a value; it modifies the metadata of the specified transaction account directly.


---
### fd\_txn\_account\_resize\_writable<!-- {{#callable:fd_txn_account_resize_writable}} -->
Resizes the writable transaction account by updating its data length and zeroing out any newly allocated space.
- **Inputs**:
    - `acct`: A pointer to the `fd_txn_account_t` structure representing the transaction account to be resized.
    - `dlen`: An unsigned long integer representing the new desired length of the account's data.
- **Control Flow**:
    - Checks if the account's metadata is NULL, indicating that the account is not mutable, and logs an error if so.
    - Stores the current data length of the account in `old_sz` and the new desired length in `new_sz`.
    - Calculates the size of memory to be zeroed out using `fd_ulong_sat_sub` to ensure it does not underflow.
    - Uses `fd_memset` to zero out the newly allocated space in the account's data buffer.
    - Updates the account's metadata to reflect the new data length.
- **Output**: The function does not return a value; it modifies the state of the `fd_txn_account_t` structure directly.


---
### fd\_txn\_account\_get\_acc\_data\_mut\_readonly<!-- {{#callable:fd_txn_account_get_acc_data_mut_readonly}} -->
This function logs an error indicating that the account is not mutable and returns NULL.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account.
- **Control Flow**:
    - The function begins by logging an error message indicating that the account is not mutable.
    - It then returns NULL, indicating that no mutable data can be accessed.
- **Output**: The function returns NULL, indicating that the requested mutable account data is not available due to the account's read-only status.


---
### fd\_txn\_account\_is\_borrowed<!-- {{#callable:fd_txn_account_is_borrowed}} -->
The `fd_txn_account_is_borrowed` function checks if a transaction account is currently borrowed by examining its exclusive reference count.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account to be checked.
- **Control Flow**:
    - The function accesses the `private_state.refcnt_excl` member of the `acct` structure.
    - It uses the logical NOT operator to convert the value of `refcnt_excl` into a boolean representation (0 or 1).
    - The result is returned as a `ushort` value, indicating whether the account is borrowed (1) or not (0).
- **Output**: Returns a non-zero value if the account is borrowed (i.e., `refcnt_excl` is greater than zero), otherwise returns zero.


---
### fd\_txn\_account\_is\_mutable<!-- {{#callable:fd_txn_account_is_mutable}} -->
Determines if a transaction account is mutable based on the presence of its metadata.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account to be checked.
- **Control Flow**:
    - The function checks if the `meta` field of the `private_state` structure within the `acct` is not NULL.
    - If `meta` is not NULL, the function returns 1, indicating the account is mutable.
    - If `meta` is NULL, the function returns 0, indicating the account is not mutable.
- **Output**: Returns an integer value: 1 if the account is mutable, 0 if it is not.


---
### fd\_txn\_account\_is\_readonly<!-- {{#callable:fd_txn_account_is_readonly}} -->
Determines if a transaction account is read-only based on its metadata.
- **Inputs**:
    - `acct`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account to be checked.
- **Control Flow**:
    - The function checks if the `const_meta` field of the `acct` is not NULL.
    - It also checks if the `meta` field of the `acct` is NULL.
    - If both conditions are satisfied, the function returns 1 (true), indicating the account is read-only; otherwise, it returns 0 (false).
- **Output**: Returns an integer value: 1 if the account is read-only, and 0 if it is not.


---
### fd\_txn\_account\_try\_borrow\_mut<!-- {{#callable:fd_txn_account_try_borrow_mut}} -->
Attempts to acquire write access for a transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account for which write access is being requested.
- **Control Flow**:
    - Calls the [`fd_txn_account_acquire_write`](#fd_txn_account_acquire_write) function with the provided account pointer.
    - Returns the result of the [`fd_txn_account_acquire_write`](#fd_txn_account_acquire_write) function, which indicates whether the write access was successfully acquired.
- **Output**: Returns an integer value: 1 if write access was successfully acquired, or 0 if the attempt failed.
- **Functions called**:
    - [`fd_txn_account_acquire_write`](#fd_txn_account_acquire_write)


---
### fd\_txn\_account\_drop<!-- {{#callable:fd_txn_account_drop}} -->
Releases the write access of a transaction account.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be released.
- **Control Flow**:
    - Calls [`fd_txn_account_release_write_private`](#fd_txn_account_release_write_private) with the provided account pointer.
    - The [`fd_txn_account_release_write_private`](#fd_txn_account_release_write_private) function checks if the account is currently in a writable state and releases it if necessary.
- **Output**: The function does not return a value; it performs an action to release the write access of the account.
- **Functions called**:
    - [`fd_txn_account_release_write_private`](#fd_txn_account_release_write_private)


---
### fd\_txn\_account\_set\_readonly<!-- {{#callable:fd_txn_account_set_readonly}} -->
Sets the `fd_txn_account_t` structure to a read-only state.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure that represents the transaction account to be set to read-only.
- **Control Flow**:
    - The function sets the `meta`, `data`, and `rec` fields of the `acct` structure to NULL, effectively clearing any mutable state.
    - It assigns the `vt` field of the `acct` structure to point to the `fd_txn_account_readonly_vtable`, indicating that the account is now in a read-only state.
- **Output**: The function does not return a value; it modifies the state of the `fd_txn_account_t` structure in place.


---
### fd\_txn\_account\_set\_mutable<!-- {{#callable:fd_txn_account_set_mutable}} -->
Sets the mutable state of a transaction account by updating its private state pointers and vtable.
- **Inputs**:
    - `acct`: A pointer to a `fd_txn_account_t` structure representing the transaction account to be set as mutable.
- **Control Flow**:
    - The function directly assigns the `const_meta`, `const_data`, and `const_rec` pointers from the `acct` structure to the mutable state pointers in the `private_state` of the account.
    - It updates the virtual table pointer (`vt`) of the account to point to the writable vtable, indicating that the account is now in a mutable state.
- **Output**: The function does not return a value; it modifies the state of the provided transaction account in place.


