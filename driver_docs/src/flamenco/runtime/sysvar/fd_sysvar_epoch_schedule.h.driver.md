# Purpose
This C header file, `epoch_schedule.h`, is part of a larger system related to the Solana blockchain runtime, specifically dealing with the concept of epochs. It provides a set of functions and constants to manage and calculate epoch numbers, which are integral to the Solana protocol. An epoch in Solana is a sequence of slots, and this file defines how these epochs are structured, including the warmup period where epoch lengths increase exponentially and the constant period where epoch lengths remain fixed. The file includes definitions for minimum and maximum epoch lengths, ensuring that operations remain within safe bounds to prevent overflow.

The file defines several functions for initializing, reading, writing, and deriving epoch schedules, as well as utility functions to calculate the number of slots in an epoch, the starting slot of an epoch, and the epoch number for a given slot. These functions are crucial for maintaining the integrity of the epoch schedule within the Solana runtime, allowing for accurate tracking and management of epochs. The header file is designed to be included in other parts of the system, providing a public API for interacting with epoch schedules, and it is structured to ensure that epoch-related calculations are consistent and reliable across the system.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../context/fd_exec_slot_ctx.h`


# Global Variables

---
### fd\_sysvar\_epoch\_schedule\_read
- **Type**: `fd_epoch_schedule_t *`
- **Description**: The `fd_sysvar_epoch_schedule_read` is a function that returns a pointer to an `fd_epoch_schedule_t` structure. This function reads the current value of the epoch schedule sysvar from a data structure referred to as 'funk'. If the account does not exist in 'funk' or has zero lamports, the function returns NULL.
- **Use**: This function is used to access the current epoch schedule configuration from a specified data source, allowing for epoch-related calculations and operations.


---
### fd\_epoch\_schedule\_derive
- **Type**: `fd_epoch_schedule_t *`
- **Description**: The `fd_epoch_schedule_derive` function is designed to initialize and derive an epoch schedule configuration based on the provided parameters. It returns a pointer to an `fd_epoch_schedule_t` structure, which represents the epoch schedule configuration.
- **Use**: This function is used to create new epoch schedule configurations by setting parameters such as epoch length, leader schedule slot offset, and whether a warmup period is enabled.


# Function Declarations (Public API)

---
### fd\_sysvar\_epoch\_schedule\_init<!-- {{#callable_declaration:fd_sysvar_epoch_schedule_init}} -->
Initialize the epoch schedule sysvar account.
- **Description**: This function sets up the epoch schedule sysvar account using the provided slot context. It should be called to initialize the epoch schedule before any operations that depend on the epoch schedule are performed. This function does not return a value and does not handle invalid input explicitly, so ensure that the provided slot context is valid and properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the slot context. This parameter must not be null and should be properly initialized before calling the function. The caller retains ownership of this pointer.
- **Output**: None
- **See also**: [`fd_sysvar_epoch_schedule_init`](fd_sysvar_epoch_schedule.c.driver.md#fd_sysvar_epoch_schedule_init)  (Implementation)


---
### fd\_sysvar\_epoch\_schedule\_read<!-- {{#callable_declaration:fd_sysvar_epoch_schedule_read}} -->
Reads the current epoch schedule sysvar from the specified funk.
- **Description**: This function retrieves the current epoch schedule sysvar from the provided funk and transaction context. It should be used when you need to access the epoch scheduling constants for epoch-related calculations. The function returns NULL if the sysvar account does not exist in the funk or if it has zero lamports, indicating a non-existent account in this context. Ensure that the funk and transaction context are properly initialized before calling this function.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk from which the epoch schedule sysvar is to be read. Must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the transaction context within the funk. Must not be null.
    - `spad`: A pointer to an fd_spad_t structure used for decoding the epoch schedule. Must not be null.
- **Output**: Returns a pointer to an fd_epoch_schedule_t structure containing the epoch schedule if successful, or NULL if the account does not exist or has zero lamports.
- **See also**: [`fd_sysvar_epoch_schedule_read`](fd_sysvar_epoch_schedule.c.driver.md#fd_sysvar_epoch_schedule_read)  (Implementation)


---
### fd\_sysvar\_epoch\_schedule\_write<!-- {{#callable_declaration:fd_sysvar_epoch_schedule_write}} -->
Writes the current epoch schedule to the sysvar.
- **Description**: This function is used to update the epoch schedule sysvar with the current epoch schedule data. It should be called when there is a need to persist the current epoch schedule configuration to the sysvar, typically after modifications or initial setup. The function requires a valid execution slot context and a properly initialized epoch schedule. It logs the size of the epoch schedule being written and handles encoding errors by logging an error message. Ensure that the provided epoch schedule is valid and that the slot context is correctly set up before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized before calling this function. The caller retains ownership.
    - `epoch_schedule`: A pointer to an fd_epoch_schedule_t structure containing the epoch schedule to be written. Must not be null and should be properly initialized. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_sysvar_epoch_schedule_write`](fd_sysvar_epoch_schedule.c.driver.md#fd_sysvar_epoch_schedule_write)  (Implementation)


---
### fd\_epoch\_schedule\_derive<!-- {{#callable_declaration:fd_epoch_schedule_derive}} -->
Derives an epoch schedule configuration from specified parameters.
- **Description**: Use this function to create a new epoch schedule configuration based on the provided parameters. It initializes the given schedule structure with the specified epoch length, leader schedule slot offset, and warmup period settings. The function must be called with a valid schedule pointer and an epoch length greater than or equal to FD_EPOCH_LEN_MIN. If the epoch length is too small, the function returns NULL and logs a warning. This function is essential for setting up epoch scheduling in systems that follow the Solana runtime model.
- **Inputs**:
    - `schedule`: A pointer to an fd_epoch_schedule_t structure that will be initialized. Must not be null.
    - `epoch_len`: The desired number of slots per epoch. Must be greater than or equal to FD_EPOCH_LEN_MIN. If less, the function returns NULL.
    - `leader_schedule_slot_offset`: The number of slots before the start of an epoch when the leader schedule should be generated. Must be a valid ulong value.
    - `warmup`: An integer indicating whether a warmup period is enabled (1) or disabled (0). Any non-zero value is treated as enabled.
- **Output**: Returns a pointer to the initialized fd_epoch_schedule_t structure on success, or NULL if the epoch length is invalid.
- **See also**: [`fd_epoch_schedule_derive`](fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_schedule_derive)  (Implementation)


---
### fd\_epoch\_slot\_cnt<!-- {{#callable_declaration:fd_epoch_slot_cnt}} -->
Returns the number of slots in a specified epoch.
- **Description**: Use this function to determine the number of slots in a given epoch based on the provided epoch schedule configuration. It is particularly useful for understanding the structure of epochs during both the warmup and constant periods. The function must be called with a valid epoch schedule and a non-negative epoch number. It handles epochs in the warmup period by calculating the slot count using an exponential growth model, while epochs in the constant period return a fixed slot count as defined in the schedule.
- **Inputs**:
    - `schedule`: A pointer to a constant fd_epoch_schedule_t structure that defines the epoch schedule configuration. Must not be null.
    - `epoch`: An unsigned long integer representing the epoch number for which the slot count is requested. Must be non-negative.
- **Output**: Returns the number of slots in the specified epoch as an unsigned long integer. The value is greater than zero.
- **See also**: [`fd_epoch_slot_cnt`](fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot_cnt)  (Implementation)


---
### fd\_epoch\_slot0<!-- {{#callable_declaration:fd_epoch_slot0}} -->
Returns the absolute slot number of the first slot in a specified epoch.
- **Description**: Use this function to determine the starting slot number of a given epoch based on the provided epoch schedule. This is useful for understanding the slot boundaries within an epoch, especially when dealing with epoch transitions. The function requires a valid epoch schedule and an epoch number as inputs. It handles both the warmup and constant periods of the epoch schedule, ensuring accurate slot calculations across different epoch configurations.
- **Inputs**:
    - `schedule`: A pointer to a constant fd_epoch_schedule_t structure that defines the epoch schedule. Must not be null, and should be properly initialized before calling this function.
    - `epoch`: An unsigned long integer representing the epoch number for which the first slot number is to be calculated. It should be a valid epoch number within the context of the provided schedule.
- **Output**: Returns the unsigned long integer representing the absolute slot number of the first slot in the specified epoch.
- **See also**: [`fd_epoch_slot0`](fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot0)  (Implementation)


---
### fd\_slot\_to\_epoch<!-- {{#callable_declaration:fd_slot_to_epoch}} -->
Returns the epoch number for a given slot.
- **Description**: This function determines the epoch number that contains the specified slot number based on the provided epoch schedule. It is useful for mapping slot numbers to their corresponding epochs in the Solana runtime. The function can also optionally provide the offset of the slot within its epoch if a non-null pointer is supplied for the offset parameter. It is important to ensure that the schedule's slots_per_epoch is non-zero before calling this function, as a zero value will result in undefined behavior.
- **Inputs**:
    - `schedule`: A pointer to a constant fd_epoch_schedule_t structure that defines the epoch schedule. Must not be null and must have a non-zero slots_per_epoch.
    - `slot`: An unsigned long integer representing the slot number for which the epoch number is to be determined. There are no specific constraints on the value, but it should be within the valid range of slots defined by the schedule.
    - `out_offset_opt`: An optional pointer to an unsigned long where the function will store the offset of the slot within its epoch. If null, the offset is not returned.
- **Output**: Returns the epoch number as an unsigned long. If out_offset_opt is non-null, it also writes the slot's offset within the epoch to the location pointed to by out_offset_opt.
- **See also**: [`fd_slot_to_epoch`](fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)  (Implementation)


---
### fd\_slot\_to\_leader\_schedule\_epoch<!-- {{#callable_declaration:fd_slot_to_leader_schedule_epoch}} -->
Calculates the leader schedule epoch for a given slot.
- **Description**: Use this function to determine the leader schedule epoch associated with a specific slot number within the context of a given epoch schedule. This is particularly useful when you need to align operations or decisions with the leader schedule epoch rather than the general epoch. The function requires a valid epoch schedule and a slot number, and it handles both normal and pre-normal slots appropriately.
- **Inputs**:
    - `schedule`: A pointer to a constant fd_epoch_schedule_t structure representing the epoch schedule. Must not be null.
    - `slot`: An unsigned long integer representing the slot number for which the leader schedule epoch is to be determined. Must be within the valid range of slots as defined by the schedule.
- **Output**: Returns the leader schedule epoch number as an unsigned long integer for the specified slot.
- **See also**: [`fd_slot_to_leader_schedule_epoch`](fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_leader_schedule_epoch)  (Implementation)


