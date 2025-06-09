# Purpose
This C header file defines constants and function prototypes for managing an address lookup table within a runtime program, likely part of a larger system. It includes status definitions for the address lookup table, indicating whether it is activated, deactivating, or deactivated, and specifies a metadata size constant. The file provides function prototypes for executing the address lookup table program and for retrieving the length of active addresses, which suggests its role in managing and querying address states within a given execution context. The inclusion of another header file, `fd_exec_instr_ctx.h`, indicates that these functions operate within a specific execution instruction context, hinting at a modular design where this header facilitates interaction with address lookup functionalities.
# Imports and Dependencies

---
- `../context/fd_exec_instr_ctx.h`


# Function Declarations (Public API)

---
### fd\_address\_lookup\_table\_program\_execute<!-- {{#callable_declaration:fd_address_lookup_table_program_execute}} -->
Executes an address lookup table program instruction.
- **Description**: This function executes an instruction for the address lookup table program based on the context provided. It should be called with a valid execution instruction context, which includes the transaction context and instruction data. The function checks for unsupported program IDs and invalid instruction data, returning specific error codes in such cases. It processes the instruction by decoding it and executing the corresponding operation, such as creating, freezing, extending, deactivating, or closing a lookup table. The function must be called with a properly initialized context, and it handles various instruction types by returning appropriate success or error codes.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure that contains the execution context, including transaction context and instruction data. Must not be null. The function will return an error if the instruction data is invalid or if the program ID is unsupported.
- **Output**: Returns an integer status code indicating success or the type of error encountered, such as unsupported program ID or invalid instruction data.
- **See also**: [`fd_address_lookup_table_program_execute`](fd_address_lookup_table_program.c.driver.md#fd_address_lookup_table_program_execute)  (Implementation)


---
### fd\_get\_active\_addresses\_len<!-- {{#callable_declaration:fd_get_active_addresses_len}} -->
Determine the number of active addresses in the lookup table.
- **Description**: Use this function to calculate the number of active addresses in a given address lookup table at a specific slot. It is essential to ensure that the lookup table is active for the specified slot; otherwise, the function will return an error code. The function updates the provided pointer with the length of active addresses, which is determined based on the current slot and the table's metadata. This function should be called when you need to know how many addresses are currently active in the table for processing or validation purposes.
- **Inputs**:
    - `self`: A pointer to an `fd_address_lookup_table_t` structure representing the address lookup table. Must not be null.
    - `current_slot`: An unsigned long integer representing the current slot for which active addresses are being queried.
    - `slot_hashes`: A pointer to a constant `fd_slot_hash_t` structure containing slot hash information. Must not be null.
    - `addresses_len`: An unsigned long integer representing the total number of addresses in the lookup table.
    - `active_addresses_len`: A pointer to an unsigned long where the function will store the number of active addresses. Must not be null.
- **Output**: Returns an integer status code: `FD_RUNTIME_EXECUTE_SUCCESS` on success, or `FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND` if the lookup table is not active for the given slot.
- **See also**: [`fd_get_active_addresses_len`](fd_address_lookup_table_program.c.driver.md#fd_get_active_addresses_len)  (Implementation)


