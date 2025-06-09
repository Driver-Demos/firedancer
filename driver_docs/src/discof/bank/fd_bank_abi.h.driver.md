# Purpose
This C header file, `fd_bank_abi.h`, defines a set of constants, function prototypes, and macros related to the bank application binary interface (ABI) within a larger software system. The file provides narrow functionality focused on managing and interacting with bank-related transactions and accounts. It includes error codes for transaction initialization, which indicate various failure conditions such as account not found, invalid account owner, and uninitialized account. These error codes are crucial for handling transaction-related errors in a consistent manner across the system.

The file also declares several function prototypes that facilitate operations such as resolving address lookup tables for transactions, managing bank resources, setting administrative identities, loading account data, and handling proof-of-history (PoH) events like tick registration and leader change signaling. These functions are likely intended to be used by other parts of the software that need to interact with the bank's transaction and account management system. The inclusion of `fd_pack.h` suggests that this header file is part of a larger modular system, where `fd_pack.h` might provide additional utilities or definitions needed for the bank ABI operations. Overall, this header file serves as an interface for bank-related functionalities, providing essential tools for transaction processing and account management within the system.
# Imports and Dependencies

---
- `../../disco/pack/fd_pack.h`


# Function Declarations (Public API)

---
### fd\_ext\_bank\_release<!-- {{#callable_declaration:fd_ext_bank_release}} -->
Releases resources associated with a bank.
- **Description**: This function is intended to release any resources or perform cleanup associated with a bank object. It should be called when the bank is no longer needed to ensure proper resource management. The function does not perform any operations in its current implementation, but it is provided as part of the API for future extensibility or platform-specific implementations. It is safe to call this function with a null or invalid bank pointer, as the parameter is marked as unused.
- **Inputs**:
    - `bank`: A pointer to a bank object. The parameter is marked as unused, indicating that the function does not currently utilize this input. It is safe to pass a null or invalid pointer.
- **Output**: None
- **See also**: [`fd_ext_bank_release`](fd_bank_abi.c.driver.md#fd_ext_bank_release)  (Implementation)


---
### fd\_ext\_admin\_rpc\_set\_identity<!-- {{#callable_declaration:fd_ext_admin_rpc_set_identity}} -->
Sets the identity for the admin RPC interface.
- **Description**: This function is used to set the identity keypair for the admin RPC interface, which may be required for authentication or identification purposes. It is important to ensure that the identity keypair provided is valid and correctly formatted. The function also takes a parameter to specify whether a tower is required, which may affect the behavior of the RPC interface. This function does not perform any operations and always returns a success code, indicating that it is not yet implemented or is a placeholder.
- **Inputs**:
    - `identity_keypair`: A pointer to an unsigned character array representing the identity keypair. The keypair must be valid and correctly formatted. The parameter is marked as unused, indicating it is not currently utilized by the function.
    - `require_tower`: An integer indicating whether a tower is required. The parameter is marked as unused, indicating it is not currently utilized by the function.
- **Output**: The function always returns 0, indicating success, but does not perform any actual operations.
- **See also**: [`fd_ext_admin_rpc_set_identity`](fd_bank_abi.c.driver.md#fd_ext_admin_rpc_set_identity)  (Implementation)


---
### fd\_ext\_bank\_acquire<!-- {{#callable_declaration:fd_ext_bank_acquire}} -->
Acquires a reference to an external bank.
- **Description**: This function is intended to acquire a reference to an external bank, which is typically used in scenarios where multiple operations need to be performed on the bank. It is expected to be called before any operations that require a bank reference. However, in its current form, the function logs an error and does not perform any acquisition. This suggests that the function is either not implemented or is intended to be overridden. Users should ensure that the bank reference is valid and that any necessary initialization has been performed before calling this function.
- **Inputs**:
    - `bank`: A pointer to the bank object that is intended to be acquired. The parameter is marked as unused, indicating that it is not currently utilized in the function. The caller retains ownership of the bank object, and it must not be null.
- **Output**: None
- **See also**: [`fd_ext_bank_acquire`](fd_bank_abi.c.driver.md#fd_ext_bank_acquire)  (Implementation)


---
### fd\_ext\_bank\_load\_account<!-- {{#callable_declaration:fd_ext_bank_load_account}} -->
Loads account information from the bank using the specified address.
- **Description**: This function is used to retrieve account information from a bank using a specified address. It is intended to be called when account details such as the owner and data need to be accessed. The function requires valid pointers for the address, owner, data, and data size parameters. It returns a status code indicating success or the type of error encountered, such as account not found or invalid account data. Ensure that the bank is properly initialized before calling this function.
- **Inputs**:
    - `bank`: A pointer to the bank from which the account information is to be loaded. The caller retains ownership and it must not be null.
    - `fixed_root`: An integer parameter that may influence the lookup process. The specific valid range is not detailed, but it should be a valid integer.
    - `addr`: A pointer to the address of the account to be loaded. It must not be null and should point to a valid address.
    - `owner`: A pointer to a buffer where the account owner information will be stored. It must not be null and should have sufficient space to store the owner data.
    - `data`: A pointer to a buffer where the account data will be stored. It must not be null and should have sufficient space to store the account data.
    - `data_sz`: A pointer to a variable where the size of the account data will be stored. It must not be null and should be able to store an unsigned long value.
- **Output**: Returns an integer status code: FD_BANK_ABI_TXN_INIT_SUCCESS on success, or an error code such as FD_BANK_ABI_TXN_INIT_ERR_ACCOUNT_NOT_FOUND on failure.
- **See also**: [`fd_ext_bank_load_account`](fd_bank_abi.c.driver.md#fd_ext_bank_load_account)  (Implementation)


---
### fd\_ext\_poh\_register\_tick<!-- {{#callable_declaration:fd_ext_poh_register_tick}} -->
Registers a tick with the Proof of History (PoH) service.
- **Description**: This function is intended to register a tick with the Proof of History (PoH) service, which is a component of the system that helps maintain a historical record of events. However, the current implementation does not perform any operations and logs an error message instead. This function should be called when a new tick needs to be recorded in the PoH service, but users should be aware that it currently does not fulfill its intended purpose.
- **Inputs**:
    - `bank`: A pointer to a bank object. The parameter is marked as unused, indicating it is not currently utilized by the function. The caller retains ownership and it must not be null.
    - `hash`: A pointer to a hash value representing the tick. The parameter is marked as unused, indicating it is not currently utilized by the function. The caller retains ownership and it must not be null.
- **Output**: None
- **See also**: [`fd_ext_poh_register_tick`](fd_bank_abi.c.driver.md#fd_ext_poh_register_tick)  (Implementation)


---
### fd\_ext\_poh\_signal\_leader\_change<!-- {{#callable_declaration:fd_ext_poh_signal_leader_change}} -->
Signals a leader change event.
- **Description**: This function is used to signal a change in leadership within the system. It is typically called when a new leader is elected or when there is a transition in leadership roles. The function does not perform any operations with the provided sender parameter, and it is expected to be used in contexts where leader change notifications are required. There are no side effects or return values from this function, and it is primarily used for signaling purposes.
- **Inputs**:
    - `sender`: A pointer to the sender of the signal. This parameter is not used within the function, and its value is ignored. The caller retains ownership of the pointer, and it can be null or any arbitrary value.
- **Output**: None
- **See also**: [`fd_ext_poh_signal_leader_change`](fd_bank_abi.c.driver.md#fd_ext_poh_signal_leader_change)  (Implementation)


