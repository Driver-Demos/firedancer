# Purpose
This C source code file is designed to test the functionality of epoch scheduling, specifically focusing on the `fd_epoch_schedule_t` structure. The file includes a series of static assertions to ensure the correct memory layout of the `fd_epoch_schedule_t` structure, which is crucial for maintaining data integrity and alignment. The primary functionality revolves around testing the derivation and validation of epoch schedules using predefined test vectors. These test vectors are arrays of `fd_epoch_schedule_t` structures, each initialized with specific values for slots per epoch, first normal epoch, and first normal slot. The code includes two main testing functions: [`test_epoch_schedule_derive`](#test_epoch_schedule_derive) and [`test_epoch_schedule`](#test_epoch_schedule), which verify the correctness of the epoch schedule derivation and the mapping of slots to epochs, respectively.

The file serves as an executable test suite, as indicated by the presence of a [`main`](#main) function, which initializes the testing environment, iterates over the test vectors, and invokes the testing functions. The [`main`](#main) function also handles the setup and teardown of the testing environment using `fd_boot` and `fd_halt` functions. The tests ensure that the epoch schedule derivation correctly handles both warmup and non-warmup scenarios, and that the slot-to-epoch mapping is accurate and consistent. The file does not define public APIs or external interfaces but rather focuses on internal validation of epoch scheduling logic, making it a critical component for ensuring the reliability of systems that depend on precise epoch scheduling.
# Imports and Dependencies

---
- `fd_sysvar_epoch_schedule.h`
- `stddef.h`


# Global Variables

---
### fd\_epoch\_schedule\_test\_vectors
- **Type**: ``fd_epoch_schedule_t const[]``
- **Description**: The `fd_epoch_schedule_test_vectors` is a static constant array of `fd_epoch_schedule_t` structures, each representing a test vector for epoch scheduling. Each element in the array specifies the number of slots per epoch, the first normal epoch, and the first normal slot, which are used to test the epoch scheduling logic. The array is terminated with a zero-initialized structure to indicate the end of the test vectors.
- **Use**: This variable is used to provide predefined test vectors for validating the epoch scheduling logic in the `test_epoch_schedule_derive` and `test_epoch_schedule` functions.


# Functions

---
### test\_epoch\_schedule\_derive<!-- {{#callable:test_epoch_schedule_derive}} -->
The function `test_epoch_schedule_derive` tests the derivation of epoch schedules with and without warmup for a given epoch schedule configuration.
- **Inputs**:
    - `t`: A pointer to a constant `fd_epoch_schedule_t` structure, representing the epoch schedule configuration to be tested.
- **Control Flow**:
    - Initialize `epoch_len` with the number of slots per epoch from the first element of the input schedule `t`.
    - Enter a loop that continues as long as `epoch_len` is less than the number of slots per epoch in the second element of `t`.
    - Within the loop, create a local `fd_epoch_schedule_t` structure named `schedule`.
    - Call [`fd_epoch_schedule_derive`](fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_schedule_derive) to derive a schedule with warmup, using `epoch_len`, `epoch_len / 2` as the leader schedule offset, and `1` for warmup.
    - Use `FD_TEST` assertions to verify that the derived schedule matches expected values for slots per epoch, leader schedule slot offset, first normal epoch, first normal slot, and warmup flag.
    - Call [`fd_epoch_schedule_derive`](fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_schedule_derive) again to derive a schedule without warmup, using the same parameters but with `0` for warmup.
    - Use `FD_TEST` assertions to verify that the derived schedule matches expected values for slots per epoch, leader schedule slot offset, first normal epoch, first normal slot, and warmup flag when warmup is not applied.
    - Increment `epoch_len` and repeat the loop.
- **Output**: The function does not return a value; it performs assertions to validate the correctness of derived epoch schedules.
- **Functions called**:
    - [`fd_epoch_schedule_derive`](fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_schedule_derive)


---
### test\_epoch\_schedule<!-- {{#callable:test_epoch_schedule}} -->
The function `test_epoch_schedule` verifies the correctness of epoch and slot calculations for a given epoch schedule configuration.
- **Inputs**:
    - `t`: A pointer to a constant `fd_epoch_schedule_t` structure containing the epoch schedule configuration to be tested.
- **Control Flow**:
    - Initialize `last_epoch` to 0 and `last_slot_idx` to `ULONG_MAX` to track the last processed epoch and slot index.
    - Iterate over each slot from 0 to `t->first_normal_slot - 1`.
    - For each slot, calculate the current epoch and slot index using [`fd_slot_to_epoch`](fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch).
    - Verify that the epoch number is monotonically increasing and does not increase by more than one using `FD_TEST`.
    - Check that the slot index increments correctly within the same epoch or resets when a new epoch starts.
    - If a new epoch is detected, verify the first slot of the epoch and the epoch length using `FD_TEST`.
    - Update `last_epoch` and `last_slot_idx` for the next iteration.
- **Output**: The function does not return a value; it performs assertions to validate the epoch schedule logic.
- **Functions called**:
    - [`fd_slot_to_epoch`](fd_sysvar_epoch_schedule.c.driver.md#fd_slot_to_epoch)
    - [`fd_epoch_slot0`](fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot0)
    - [`fd_epoch_slot_cnt`](fd_sysvar_epoch_schedule.c.driver.md#fd_epoch_slot_cnt)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the system, iterates over a set of test vectors to validate epoch scheduling logic, logs a success message, and then halts the system.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the system with command-line arguments.
    - Iterate over `fd_epoch_schedule_test_vectors` until a vector with `slots_per_epoch` of zero is encountered.
    - For each vector, call [`test_epoch_schedule_derive`](#test_epoch_schedule_derive) to test the derivation of epoch schedules with and without warmup.
    - For each vector, call [`test_epoch_schedule`](#test_epoch_schedule) to validate the epoch and slot calculations.
    - Log a notice message indicating the tests passed using `FD_LOG_NOTICE`.
    - Call `fd_halt` to halt the system.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_epoch_schedule_derive`](#test_epoch_schedule_derive)
    - [`test_epoch_schedule`](#test_epoch_schedule)


