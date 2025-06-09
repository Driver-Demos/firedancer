# Purpose
This C header file defines a set of function prototypes related to managing and interacting with a "rent" system variable within a software framework, likely related to a blockchain or financial application. The file includes necessary dependencies and declares functions for initializing, writing, and reading the rent system variable, as well as calculating the minimum balance required for an account to be exempt from rent. The functions operate on data structures such as `fd_exec_slot_ctx_t`, `fd_rent_t`, and `fd_funk_t`, which are presumably defined elsewhere in the codebase. The header ensures that these functions can be used across different parts of the program, facilitating the management of rent-related operations within the system.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`
- `../../../funk/fd_funk.h`


# Global Variables

---
### fd\_sysvar\_rent\_read
- **Type**: `function pointer`
- **Description**: The `fd_sysvar_rent_read` is a function that reads the current value of the rent system variable from a data structure called `funk`. It returns a pointer to a constant `fd_rent_t` structure, which contains the rent parameters. If the account does not exist in `funk` or has zero lamports, the function returns NULL.
- **Use**: This function is used to retrieve the current rent parameters from the `funk` data structure for further processing or decision-making.


# Function Declarations (Public API)

---
### fd\_sysvar\_rent\_init<!-- {{#callable_declaration:fd_sysvar_rent_init}} -->
Copy the cached rent sysvar to the corresponding account in the database.
- **Description**: This function is used to update the rent sysvar for a specific execution slot context by copying the cached rent sysvar from the provided execution slot context to the corresponding account in the database. It is important to note that this function does not initialize the global bank's rent variable. This function should be called when the rent sysvar needs to be synchronized with the database for the given execution context.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This parameter must not be null, as it is used to access the cached rent sysvar and the epoch context.
- **Output**: None
- **See also**: [`fd_sysvar_rent_init`](fd_sysvar_rent.c.driver.md#fd_sysvar_rent_init)  (Implementation)


---
### fd\_sysvar\_rent\_write<!-- {{#callable_declaration:fd_sysvar_rent_write}} -->
Writes the current rent sysvar value to the database.
- **Description**: This function is used to update the rent sysvar value in the database using the provided execution slot context and rent parameters. It should be called when the current rent parameters need to be persisted to the database. The function assumes that the rent parameters are valid and encodable. It does not perform any initialization of global rent parameters, and it is expected that the slot context and rent parameters are properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. It must be properly initialized and not null, as it is used to identify the target database slot for the rent sysvar.
    - `rent`: A pointer to an fd_rent_t structure containing the current rent parameters. It must be valid and not null, as it is used to encode the rent sysvar value for storage.
- **Output**: None
- **See also**: [`fd_sysvar_rent_write`](fd_sysvar_rent.c.driver.md#fd_sysvar_rent_write)  (Implementation)


---
### fd\_rent\_exempt\_minimum\_balance<!-- {{#callable_declaration:fd_rent_exempt_minimum_balance}} -->
Calculate the minimum balance required for rent exemption based on account data length.
- **Description**: Use this function to determine the minimum balance required for an account to be exempt from rent, given the length of the account's data. This is useful when managing account balances to ensure they meet the necessary criteria for rent exemption. The function requires the current rent parameters to perform the calculation, which includes factors like the cost per byte per year and the exemption threshold. Ensure that the rent parameter is valid and points to the current rent settings before calling this function.
- **Inputs**:
    - `rent`: A pointer to an fd_rent_t structure containing the current rent parameters. Must not be null and should be properly initialized with valid rent settings.
    - `data_len`: The length of the account data in bytes. Must be a non-negative integer representing the size of the data for which the rent exemption balance is being calculated.
- **Output**: Returns the minimum balance in lamports required for the account to be rent exempt, based on the provided data length and rent parameters.
- **See also**: [`fd_rent_exempt_minimum_balance`](fd_sysvar_rent1.c.driver.md#fd_rent_exempt_minimum_balance)  (Implementation)


---
### fd\_sysvar\_rent\_read<!-- {{#callable_declaration:fd_sysvar_rent_read}} -->
Reads the current value of the rent sysvar from funk.
- **Description**: Use this function to obtain the current rent sysvar value from the specified funk context. It should be called when you need to access the rent parameters stored in the funk database. The function will return NULL if the rent sysvar account does not exist in the funk or if it exists but has zero lamports, indicating a non-existent account in practical terms. Ensure that the funk and funk_txn parameters are properly initialized before calling this function.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk context from which the rent sysvar is to be read. Must be properly initialized and not null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the transaction context within the funk. Must be properly initialized and not null.
    - `spad`: A pointer to an fd_spad_t structure used for decoding the rent sysvar. Must be properly initialized and not null.
- **Output**: Returns a pointer to an fd_rent_t structure containing the rent sysvar if successful, or NULL if the account does not exist or has zero lamports.
- **See also**: [`fd_sysvar_rent_read`](fd_sysvar_rent.c.driver.md#fd_sysvar_rent_read)  (Implementation)


