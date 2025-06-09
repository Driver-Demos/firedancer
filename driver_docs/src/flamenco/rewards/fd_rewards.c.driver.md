# Purpose
The provided C code is part of a larger system that manages the calculation and distribution of rewards in a blockchain environment, specifically focusing on stake and vote accounts. This code is designed to handle the complex logic of calculating rewards based on various parameters such as inflation rates, stake history, and epoch schedules. It includes functions for calculating total rewards, validator and foundation rewards, and distributing these rewards across multiple accounts in a partitioned manner. The code also manages the state of reward distribution, ensuring that rewards are distributed correctly and efficiently across different epochs.

Key components of this code include functions for calculating inflation rates, determining the number of slots in an epoch, and managing the distribution of rewards to stake accounts. The code uses a combination of mathematical calculations and data structures to efficiently manage and distribute rewards. It also includes mechanisms for logging and error handling to ensure robustness. The code is structured to be part of a larger system, with functions that are likely called by other parts of the system to initiate reward calculations and distributions. The use of external libraries and data structures, such as hash functions and maps, indicates a focus on performance and scalability, which are critical in a blockchain environment.
# Imports and Dependencies

---
- `fd_rewards.h`
- `math.h`
- `../../ballet/siphash13/fd_siphash13.h`
- `../runtime/fd_executor_err.h`
- `../runtime/fd_system_ids.h`
- `../runtime/fd_runtime.h`
- `../runtime/context/fd_exec_slot_ctx.h`
- `../runtime/program/fd_program_util.h`
- `../runtime/sysvar/fd_sysvar_stake_history.h`


# Functions

---
### total<!-- {{#callable:total}} -->
The `total` function calculates the inflation-adjusted value for a given year, considering an initial inflation rate, a taper rate, and a terminal value.
- **Inputs**:
    - `inflation`: A pointer to a constant `fd_inflation_t` structure containing the initial inflation rate, taper rate, and terminal value.
    - `year`: A double representing the year for which the inflation-adjusted value is to be calculated.
- **Control Flow**:
    - Check if the year is 0.0 and log an error if true, as this is an unlikely and erroneous condition.
    - Calculate the tapered inflation value using the formula: `inflation->initial * pow((1.0 - inflation->taper), year)`.
    - Return the greater of the calculated tapered value and the terminal value from the inflation structure.
- **Output**: A double representing the inflation-adjusted value for the given year, ensuring it does not fall below the terminal value.


---
### foundation<!-- {{#callable:foundation}} -->
The `foundation` function calculates the foundation rate for a given year based on inflation parameters, returning a product of the foundation rate and total inflation if the year is within the foundation term, otherwise returning 0.0.
- **Inputs**:
    - `inflation`: A pointer to a constant `fd_inflation_t` structure containing inflation parameters such as foundation, foundation_term, initial, taper, and terminal.
    - `year`: A double representing the year for which the foundation rate is being calculated.
- **Control Flow**:
    - Check if the given year is less than the foundation term specified in the inflation structure.
    - If true, calculate the foundation rate by multiplying the foundation value with the result of the [`total`](#total) function for the given year.
    - If false, return 0.0.
- **Output**: A double representing the calculated foundation rate for the given year, or 0.0 if the year is beyond the foundation term.
- **Functions called**:
    - [`total`](#total)


---
### validator<!-- {{#callable:validator}} -->
The `validator` function calculates the validator inflation rate by subtracting the foundation rate from the total inflation rate for a given year.
- **Inputs**:
    - `inflation`: A pointer to an `fd_inflation_t` structure containing inflation parameters such as initial, taper, terminal, and foundation rates.
    - `year`: A double representing the year for which the inflation rates are being calculated.
- **Control Flow**:
    - Log the debug information including the year, total inflation rate, foundation rate, taper, and initial inflation rate.
    - Calculate the total inflation rate for the given year using the [`total`](#total) function.
    - Calculate the foundation rate for the given year using the [`foundation`](#foundation) function.
    - Return the difference between the total inflation rate and the foundation rate.
- **Output**: A double representing the validator inflation rate for the specified year.
- **Functions called**:
    - [`total`](#total)
    - [`foundation`](#foundation)


---
### get\_inflation\_start\_slot<!-- {{#callable:get_inflation_start_slot}} -->
The `get_inflation_start_slot` function calculates the starting slot for inflation based on the activation of certain features in the given execution slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains the context of the current execution slot, including slot bank and epoch context with feature activations.
- **Control Flow**:
    - Initialize `devnet_and_testnet` to the activation slot of the `devnet_and_testnet` feature or `ULONG_MAX` if not active.
    - Initialize `enable` to `ULONG_MAX`.
    - Check if both `full_inflation_vote` and `full_inflation_enable` features are active; if so, set `enable` to the activation slot of `full_inflation_enable`.
    - Calculate `min_slot` as the minimum of `enable` and `devnet_and_testnet`.
    - If `min_slot` is `ULONG_MAX`, check if `pico_inflation` is active; if so, set `min_slot` to its activation slot, otherwise set it to 0.
    - Return `min_slot` as the starting slot for inflation.
- **Output**: The function returns an `ulong` representing the starting slot for inflation, determined by the earliest activation slot of relevant features or 0 if none are active.


---
### get\_inflation\_num\_slots<!-- {{#callable:get_inflation_num_slots}} -->
The `get_inflation_num_slots` function calculates the number of slots that have passed since the start of inflation for a given slot in an epoch schedule.
- **Inputs**:
    - `slot_ctx`: A pointer to a `fd_exec_slot_ctx_t` structure, which contains context information about the execution slot.
    - `epoch_schedule`: A pointer to a `fd_epoch_schedule_t` structure, which defines the schedule of epochs and slots.
    - `slot`: An unsigned long integer representing the current slot for which the number of inflation slots is being calculated.
- **Control Flow**:
    - Retrieve the inflation activation slot using [`get_inflation_start_slot`](#get_inflation_start_slot) with `slot_ctx` as input.
    - Calculate the inflation start slot by determining the epoch of the inflation activation slot, subtracting one, and finding the starting slot of that epoch using `fd_epoch_slot0`.
    - Determine the epoch of the given `slot` using `fd_slot_to_epoch`.
    - Calculate the number of slots since the inflation start slot by subtracting the inflation start slot from the starting slot of the current epoch.
- **Output**: Returns an unsigned long integer representing the number of slots since the start of inflation for the given slot.
- **Functions called**:
    - [`get_inflation_start_slot`](#get_inflation_start_slot)


---
### slot\_in\_year\_for\_inflation<!-- {{#callable:slot_in_year_for_inflation}} -->
The function `slot_in_year_for_inflation` calculates the fraction of the year that has passed based on the number of slots since inflation started.
- **Inputs**:
    - `slot_ctx`: A pointer to a `fd_exec_slot_ctx_t` structure, which contains context information about the current execution slot, including epoch and slot bank details.
- **Control Flow**:
    - Retrieve the epoch bank from the slot context's epoch context using `fd_exec_epoch_ctx_epoch_bank` function.
    - Calculate the number of slots since inflation started by calling [`get_inflation_num_slots`](#get_inflation_num_slots) with the slot context, epoch schedule, and current slot.
    - Divide the number of slots since inflation started by the total number of slots per year to get the fraction of the year that has passed.
- **Output**: Returns a `double` representing the fraction of the year that has passed based on the number of slots since inflation started.
- **Functions called**:
    - [`get_inflation_num_slots`](#get_inflation_num_slots)


---
### calculate\_stake\_points\_and\_credits<!-- {{#callable:calculate_stake_points_and_credits}} -->
The function `calculate_stake_points_and_credits` computes the stake points and updates the credits observed for a given stake and vote state.
- **Inputs**:
    - `stake_history`: A constant pointer to `fd_stake_history_t`, representing the history of stake activations and deactivations.
    - `stake`: A constant pointer to `fd_stake_t`, representing the current stake information including credits observed.
    - `vote_state_versioned`: A pointer to `fd_vote_state_versioned_t`, representing the versioned state of the vote account.
    - `new_rate_activation_epoch`: A pointer to `ulong`, which may be updated with the new rate activation epoch.
    - `result`: A pointer to `fd_calculated_stake_points_t`, where the calculated stake points and updated credits will be stored.
- **Control Flow**:
    - Initialize `credits_in_stake` with the credits observed from the stake.
    - Determine the `epoch_credits` based on the discriminant of `vote_state_versioned`.
    - Calculate `credits_in_vote` from the tail of `epoch_credits` if it is not empty.
    - If `credits_in_vote` is less than `credits_in_stake`, set result points to 0, update `new_credits_observed`, and set `force_credits_update_with_skipped_reward` to 1, then return.
    - If `credits_in_vote` equals `credits_in_stake`, set result points to 0, update `new_credits_observed`, and set `force_credits_update_with_skipped_reward` to 0, then return.
    - Iterate over `epoch_credits` to calculate earned credits and update `new_credits_observed`.
    - For each epoch credit, calculate the effective stake amount and accumulate the points.
    - Store the calculated points, updated credits, and set `force_credits_update_with_skipped_reward` to 0 in the result.
- **Output**: The function outputs the calculated stake points, updated credits observed, and a flag indicating if a forced credits update with skipped reward is needed, stored in `fd_calculated_stake_points_t`.


---
### calculate\_stake\_rewards<!-- {{#callable:calculate_stake_rewards}} -->
The `calculate_stake_rewards` function computes the rewards for a given stake based on its history, vote state, and point values, and updates the result with the calculated rewards and credits observed.
- **Inputs**:
    - `stake_history`: A constant pointer to `fd_stake_history_t`, representing the history of stake changes.
    - `stake`: A constant pointer to `fd_stake_t`, representing the current stake information.
    - `vote_state_versioned`: A pointer to `fd_vote_state_versioned_t`, representing the versioned state of the vote account.
    - `rewarded_epoch`: An unsigned long integer representing the epoch for which rewards are being calculated.
    - `point_value`: A pointer to `fd_point_value_t`, representing the point value used in reward calculation.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer where the new rate activation epoch will be stored.
    - `result`: A pointer to `fd_calculated_stake_rewards_t`, where the calculated rewards and credits observed will be stored.
- **Control Flow**:
    - Initialize `fd_calculated_stake_points_t` structure to zero.
    - Call [`calculate_stake_points_and_credits`](#calculate_stake_points_and_credits) to compute stake points and credits observed.
    - Check if rewards are disabled or if this is the stake's activation epoch, and update `force_credits_update_with_skipped_reward` accordingly.
    - If `force_credits_update_with_skipped_reward` is set, set staker and voter rewards to zero, update `new_credits_observed`, and return 0.
    - If either `stake_points_result.points` or `point_value->points` is zero, return 1.
    - Calculate rewards using the formula `stake_points_result.points * point_value->rewards / point_value->points`.
    - If calculated rewards are zero, return 1.
    - Call `fd_vote_commission_split` to split rewards between staker and voter.
    - If the split is invalid (either portion is zero), return 1.
    - Update the result with calculated staker and voter rewards, and `new_credits_observed`, then return 0.
- **Output**: The function returns an integer status code: 0 on success, or 1 if an error occurs during reward calculation.
- **Functions called**:
    - [`calculate_stake_points_and_credits`](#calculate_stake_points_and_credits)


---
### redeem\_rewards<!-- {{#callable:redeem_rewards}} -->
The `redeem_rewards` function calculates and redeems stake rewards for a given stake and vote state, returning a success code if successful.
- **Inputs**:
    - `stake_history`: A constant pointer to `fd_stake_history_t`, representing the history of stake changes.
    - `stake`: A constant pointer to `fd_stake_t`, representing the current stake information.
    - `vote_state_versioned`: A pointer to `fd_vote_state_versioned_t`, representing the versioned state of the vote account.
    - `rewarded_epoch`: An unsigned long integer representing the epoch for which rewards are being calculated.
    - `point_value`: A pointer to `fd_point_value_t`, representing the point value used in reward calculations.
    - `new_rate_activation_epoch`: A pointer to an unsigned long integer where the new rate activation epoch will be stored.
    - `calculated_stake_rewards`: A pointer to `fd_calculated_stake_rewards_t`, where the calculated stake rewards will be stored.
- **Control Flow**:
    - Call [`calculate_stake_rewards`](#calculate_stake_rewards) with the provided inputs to compute the stake rewards.
    - Check if the return code from [`calculate_stake_rewards`](#calculate_stake_rewards) is non-zero, indicating an error.
    - If an error occurred, return the error code.
    - If successful, return `FD_EXECUTOR_INSTR_SUCCESS`.
- **Output**: Returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success or an error code if [`calculate_stake_rewards`](#calculate_stake_rewards) fails.
- **Functions called**:
    - [`calculate_stake_rewards`](#calculate_stake_rewards)


---
### calculate\_points<!-- {{#callable:calculate_points}} -->
The `calculate_points` function computes the number of points earned by a stake based on its credits and updates the result with these points.
- **Inputs**:
    - `stake`: A constant pointer to an `fd_stake_t` structure representing the stake account.
    - `vote_state_versioned`: A pointer to an `fd_vote_state_versioned_t` structure representing the vote state versioned account.
    - `stake_history`: A constant pointer to an `fd_stake_history_t` structure representing the stake history.
    - `new_rate_activation_epoch`: A pointer to an `ulong` where the new rate activation epoch will be stored.
    - `result`: A pointer to a `uint128` where the calculated points will be stored.
- **Control Flow**:
    - Declare a variable `stake_point_result` of type `fd_calculated_stake_points_t` to store the result of the stake points calculation.
    - Call the function [`calculate_stake_points_and_credits`](#calculate_stake_points_and_credits) with the provided inputs and `stake_point_result` to calculate the stake points and credits.
    - Assign the `points` from `stake_point_result` to the `result` pointer.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful execution.
- **Output**: The function returns an integer status code `FD_EXECUTOR_INSTR_SUCCESS` indicating successful execution, and updates the `result` pointer with the calculated points.
- **Functions called**:
    - [`calculate_stake_points_and_credits`](#calculate_stake_points_and_credits)


---
### get\_slots\_in\_epoch<!-- {{#callable:get_slots_in_epoch}} -->
The `get_slots_in_epoch` function calculates the number of slots in a given epoch based on the epoch's position relative to the first normal epoch in the epoch schedule.
- **Inputs**:
    - `epoch`: An unsigned long integer representing the epoch number for which the number of slots is to be determined.
    - `epoch_bank`: A pointer to a constant `fd_epoch_bank_t` structure that contains the epoch schedule and other related information.
- **Control Flow**:
    - Check if the given epoch is less than the first normal epoch in the epoch schedule.
    - If true, calculate the number of slots as `1UL << fd_ulong_sat_add(epoch, FD_EPOCH_LEN_MIN_TRAILING_ZERO)`.
    - If false, return the `slots_per_epoch` value from the epoch schedule.
- **Output**: Returns an unsigned long integer representing the number of slots in the specified epoch.


---
### epoch\_duration\_in\_years<!-- {{#callable:epoch_duration_in_years}} -->
The function `epoch_duration_in_years` calculates the duration of a given epoch in years based on the number of slots in the epoch and the slots per year defined in the epoch bank.
- **Inputs**:
    - `epoch_bank`: A pointer to a constant `fd_epoch_bank_t` structure that contains information about the epoch schedule and slots per year.
    - `prev_epoch`: An unsigned long integer representing the previous epoch for which the duration is to be calculated.
- **Control Flow**:
    - Call the function [`get_slots_in_epoch`](#get_slots_in_epoch) with `prev_epoch` and `epoch_bank` to determine the number of slots in the specified epoch.
    - Convert the number of slots in the epoch to a double and divide it by the slots per year from the `epoch_bank` to calculate the duration in years.
    - Return the calculated duration as a double.
- **Output**: The function returns a double representing the duration of the specified epoch in years.
- **Functions called**:
    - [`get_slots_in_epoch`](#get_slots_in_epoch)


---
### calculate\_previous\_epoch\_inflation\_rewards<!-- {{#callable:calculate_previous_epoch_inflation_rewards}} -->
The function `calculate_previous_epoch_inflation_rewards` calculates the inflation rewards for the previous epoch based on the given slot context, previous epoch capitalization, and epoch data, and stores the results in a rewards structure.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure, which contains the execution context for the current slot, including epoch context and slot bank information.
    - `prev_epoch_capitalization`: An unsigned long integer representing the capitalization of the previous epoch.
    - `prev_epoch`: An unsigned long integer representing the previous epoch number.
    - `rewards`: A pointer to the `fd_prev_epoch_inflation_rewards_t` structure where the calculated rewards will be stored.
- **Control Flow**:
    - Calculate the slot's position in the year using [`slot_in_year_for_inflation`](#slot_in_year_for_inflation) function with `slot_ctx` as input.
    - Retrieve the epoch bank from the epoch context within `slot_ctx`.
    - Calculate the validator rate using the [`validator`](#validator) function with the epoch bank's inflation data and the slot's position in the year.
    - Calculate the foundation rate using the [`foundation`](#foundation) function with the epoch bank's inflation data and the slot's position in the year.
    - Calculate the duration of the previous epoch in years using [`epoch_duration_in_years`](#epoch_duration_in_years) function with the epoch bank and `prev_epoch` as inputs.
    - Calculate the validator rewards by multiplying the validator rate, previous epoch capitalization, and the previous epoch duration in years, and cast the result to an unsigned long integer.
    - Log the calculated rewards, rate, duration, capitalization, and slot in year for debugging purposes.
- **Output**: The function does not return a value but populates the `rewards` structure with the calculated validator rate, foundation rate, previous epoch duration in years, and validator rewards.
- **Functions called**:
    - [`slot_in_year_for_inflation`](#slot_in_year_for_inflation)
    - [`validator`](#validator)
    - [`foundation`](#foundation)
    - [`epoch_duration_in_years`](#epoch_duration_in_years)


---
### get\_minimum\_stake\_delegation<!-- {{#callable:get_minimum_stake_delegation}} -->
The `get_minimum_stake_delegation` function determines the minimum stake delegation required for rewards based on the active features in the current slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains the current slot and epoch context, including active features.
- **Control Flow**:
    - Check if the feature `stake_minimum_delegation_for_rewards` is active for the current slot; if not, return 0.
    - If the feature `stake_raise_minimum_delegation_to_1_sol` is active, return the constant `LAMPORTS_PER_SOL`.
    - If neither condition is met, return 1.
- **Output**: Returns an `ulong` representing the minimum stake delegation required, which can be 0, `LAMPORTS_PER_SOL`, or 1, depending on the active features.


---
### calculate\_points\_range<!-- {{#callable:calculate_points_range}} -->
The `calculate_points_range` function calculates the total reward points for a range of stake accounts based on their delegation and vote state information.
- **Inputs**:
    - `stake_infos`: A pointer to an array of `fd_epoch_info_pair_t` structures containing information about stake accounts.
    - `task_args`: A pointer to a `fd_calculate_points_task_args_t` structure containing task-specific arguments such as stake history, minimum stake delegation, and pointers to vote state information.
    - `start_idx`: An unsigned long integer representing the starting index of the range of stake accounts to process.
    - `end_idx`: An unsigned long integer representing the ending index of the range of stake accounts to process.
- **Control Flow**:
    - Initialize local variables for stake history, new warmup cooldown rate epoch, and minimum stake delegation from `task_args`.
    - Initialize `total_points` to zero to accumulate points for the range of stake accounts.
    - Iterate over the stake accounts from `start_idx` to `end_idx`.
    - For each stake account, check if its delegation stake is below the minimum stake delegation; if so, skip to the next account.
    - Create a query key for the vote account using the stake's voter public key and attempt to find the vote state information in the cache.
    - If the vote state information is not found, log a debug message and skip to the next account.
    - Call [`calculate_points`](#calculate_points) to compute the points for the current stake account using its vote state and stake history.
    - If [`calculate_points`](#calculate_points) returns an error, log a debug message and skip to the next account.
    - Add the calculated account points to `total_points`.
    - After processing all accounts in the range, atomically add `total_points` to the total points in `task_args`.
- **Output**: The function does not return a value but updates the total points in `task_args` by adding the calculated points for the specified range of stake accounts.
- **Functions called**:
    - [`calculate_points`](#calculate_points)


---
### calculate\_points\_tpool\_task<!-- {{#callable:calculate_points_tpool_task}} -->
The `calculate_points_tpool_task` function is a task function for a thread pool that calculates reward points for a range of stake accounts using the [`calculate_points_range`](#calculate_points_range) function.
- **Inputs**:
    - `tpool`: A pointer to the thread pool, which is cast to a pointer to an array of `fd_epoch_info_pair_t` structures representing stake information.
    - `t0`: Unused parameter, typically used for task partitioning.
    - `t1`: Unused parameter, typically used for task partitioning.
    - `args`: A pointer to a `fd_calculate_points_task_args_t` structure containing arguments needed for the task, such as stake history and total points.
    - `reduce`: Unused parameter, typically used for reduction operations in parallel tasks.
    - `stride`: Unused parameter, typically used for task partitioning.
    - `l0`: Unused parameter, typically used for task partitioning.
    - `l1`: Unused parameter, typically used for task partitioning.
    - `m0`: The starting index of the range of stake accounts to process.
    - `m1`: The ending index of the range of stake accounts to process.
    - `n0`: Unused parameter, typically used for task partitioning.
    - `n1`: Unused parameter, typically used for task partitioning.
- **Control Flow**:
    - The function casts the `tpool` pointer to a `fd_epoch_info_pair_t` pointer to access stake information.
    - The `args` pointer is cast to a `fd_calculate_points_task_args_t` pointer to access task-specific arguments.
    - The [`calculate_points_range`](#calculate_points_range) function is called with the stake information, task arguments, and the range indices `m0` and `m1`.
- **Output**: The function does not return a value; it performs calculations and updates the total points in the task arguments.
- **Functions called**:
    - [`calculate_points_range`](#calculate_points_range)


---
### calculate\_reward\_points\_partitioned<!-- {{#callable:calculate_reward_points_partitioned}} -->
The `calculate_reward_points_partitioned` function calculates the reward points for stake delegations in a partitioned manner, potentially using a thread pool for parallel execution, and updates the result with the calculated points and rewards.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and epoch.
    - `stake_history`: A constant pointer to the stake history, which provides historical data about stake delegations.
    - `rewards`: An unsigned long integer representing the total rewards to be distributed.
    - `result`: A pointer to a `fd_point_value_t` structure where the calculated points and rewards will be stored.
    - `tpool`: A pointer to a thread pool, which may be used for parallel execution of tasks.
    - `temp_info`: A pointer to temporary epoch information, which includes data about vote states and stake information.
    - `runtime_spad`: A pointer to a runtime scratchpad, used for temporary storage and calculations.
- **Control Flow**:
    - Initialize `points` to zero and determine the `minimum_stake_delegation` using [`get_minimum_stake_delegation`](#get_minimum_stake_delegation) function.
    - Attempt to calculate a new warmup cooldown rate epoch using `fd_new_warmup_cooldown_rate_epoch`; if unsuccessful, set it to NULL.
    - Prepare task arguments for point calculation, including stake history, new warmup cooldown rate epoch, minimum stake delegation, and vote states.
    - Check if a thread pool (`tpool`) is provided; if so, execute tasks in parallel using `fd_tpool_exec_all_batch`, otherwise, calculate points sequentially using [`calculate_points_range`](#calculate_points_range).
    - If calculated `points` is greater than zero, update the `result` structure with the calculated points and the provided rewards.
- **Output**: The function does not return a value but updates the `result` structure with the calculated points and rewards if points are greater than zero.
- **Functions called**:
    - [`get_minimum_stake_delegation`](#get_minimum_stake_delegation)
    - [`calculate_points_range`](#calculate_points_range)


---
### calculate\_stake\_vote\_rewards\_account<!-- {{#callable:calculate_stake_vote_rewards_account}} -->
The `calculate_stake_vote_rewards_account` function calculates and updates the rewards for stake and vote accounts over a specified range of indices, considering various conditions and updating the results accordingly.
- **Inputs**:
    - `temp_info`: A pointer to a constant `fd_epoch_info_t` structure containing information about the current epoch, including stake and vote state information.
    - `task_args`: A pointer to a constant `fd_calculate_stake_vote_rewards_task_args_t` structure containing arguments needed for the reward calculation, such as slot context, stake history, rewarded epoch, point value, and result storage.
    - `start_idx`: An unsigned long integer representing the starting index of the stake accounts to process.
    - `end_idx`: An unsigned long integer representing the ending index of the stake accounts to process.
- **Control Flow**:
    - Initialize local variables for minimum stake delegation, total stake rewards, and additional count for the dlist.
    - Allocate and initialize a local vote reward map using the provided SPAD (Scratchpad) memory.
    - Iterate over the range from `start_idx` to `end_idx`, processing each stake account.
    - For each stake account, check if it meets the minimum delegation requirement for rewards; if not, skip it.
    - Find the corresponding vote state entry for the stake account's voter public key; if not found, skip it.
    - Attempt to redeem rewards for the stake account using the [`redeem_rewards`](#redeem_rewards) function; if it fails, log a debug message and skip it.
    - Determine the commission for the vote account based on its versioned state.
    - Find or create a vote reward node in the local map and update its rewards and commission.
    - Add the calculated stake reward to the result's stake reward list, ensuring thread-safe updates.
    - Update the total stake rewards and the additional count for the dlist.
    - After processing all accounts, merge the local vote rewards into the result's vote reward map, using atomic operations to ensure thread safety.
    - Update the result's total stake rewards and stake rewards length using atomic operations.
- **Output**: The function does not return a value but updates the `result` structure within `task_args` with calculated stake and vote rewards, including total stake rewards and vote reward map updates.
- **Functions called**:
    - [`get_minimum_stake_delegation`](#get_minimum_stake_delegation)
    - [`redeem_rewards`](#redeem_rewards)


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:calculate_stake_vote_rewards_account::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function calculates and updates stake and vote rewards for a range of stake accounts, ensuring that rewards are distributed correctly and efficiently.
- **Inputs**:
    - `spad`: A pointer to a shared memory allocation descriptor used for temporary storage during the function's execution.
- **Control Flow**:
    - Initialize variables for minimum stake delegation, total stake rewards, and additional count for the dlist.
    - Create a local vote reward map using the provided spad for memory allocation.
    - Iterate over the range of stake accounts from start_idx to end_idx.
    - For each stake account, check if it meets the minimum delegation requirement and find the corresponding vote state entry.
    - Calculate stake rewards using the redeem_rewards function and handle any errors.
    - Determine the commission for the vote account based on its versioned state.
    - Find or create a vote reward node in the local map and update its rewards and commission.
    - Add the calculated stake reward to the list of all stake rewards, ensuring thread safety.
    - Update the total stake rewards and the additional count for the dlist.
    - Merge the local vote rewards with the result's vote reward map, updating commission and rewards atomically.
    - Update the result's total stake rewards and stake rewards length atomically.
- **Output**: The function does not return a value but updates the result structure with calculated stake and vote rewards.
- **Functions called**:
    - [`get_minimum_stake_delegation`](#get_minimum_stake_delegation)
    - [`redeem_rewards`](#redeem_rewards)


---
### calculate\_stake\_vote\_rewards\_account\_tpool\_task<!-- {{#callable:calculate_stake_vote_rewards_account_tpool_task}} -->
The function `calculate_stake_vote_rewards_account_tpool_task` calculates the stake and vote rewards for a specific range of accounts using a thread pool task.
- **Inputs**:
    - `tpool`: A pointer to the thread pool, which is used to execute tasks concurrently.
    - `t0`: Unused parameter, typically used for task scheduling.
    - `t1`: Unused parameter, typically used for task scheduling.
    - `args`: A pointer to the arguments for the task, specifically of type `fd_calculate_stake_vote_rewards_task_args_t`.
    - `reduce`: Unused parameter, typically used for reduction operations in parallel tasks.
    - `stride`: Unused parameter, typically used for task scheduling.
    - `l0`: Unused parameter, typically used for task scheduling.
    - `l1`: Unused parameter, typically used for task scheduling.
    - `m0`: The starting index of the range of accounts to process.
    - `m1`: The ending index of the range of accounts to process.
    - `n0`: Unused parameter, typically used for task scheduling.
    - `n1`: Unused parameter, typically used for task scheduling.
- **Control Flow**:
    - The function begins by casting the `tpool` pointer to a `fd_epoch_info_t` pointer, which contains information about the current epoch.
    - It also casts the `args` pointer to a `fd_calculate_stake_vote_rewards_task_args_t` pointer, which contains the task-specific arguments.
    - The function then calls [`calculate_stake_vote_rewards_account`](#calculate_stake_vote_rewards_account), passing the epoch information, task arguments, and the range of accounts to process (from `m0` to `m1`).
- **Output**: The function does not return a value; it performs its operations as a side effect, updating the rewards for the specified range of accounts.
- **Functions called**:
    - [`calculate_stake_vote_rewards_account`](#calculate_stake_vote_rewards_account)


---
### calculate\_stake\_vote\_rewards<!-- {{#callable:calculate_stake_vote_rewards}} -->
The `calculate_stake_vote_rewards` function calculates and distributes rewards for stake and vote accounts for a given epoch, using a pool and dlist structure to manage memory efficiently.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and epoch.
    - `stake_history`: A constant pointer to the stake history, which provides historical data on stake accounts.
    - `rewarded_epoch`: An unsigned long integer representing the epoch for which rewards are being calculated.
    - `point_value`: A pointer to a structure that holds the point value used in reward calculations.
    - `result`: A pointer to a structure where the results of the reward calculations will be stored.
    - `temp_info`: A pointer to temporary epoch information used during calculations.
    - `tpool`: A pointer to a thread pool used for parallel execution of tasks.
    - `exec_spads`: A pointer to an array of execution scratchpad pointers used for temporary storage during execution.
    - `exec_spad_cnt`: An unsigned long integer representing the count of execution scratchpads.
    - `runtime_spad`: A pointer to a runtime scratchpad used for temporary allocations during execution.
- **Control Flow**:
    - Initialize a new warmup cooldown rate epoch value and check if it is valid.
    - Create a stake rewards pool and a dlist for managing stake rewards, which will be destroyed after distribution.
    - Create a vote rewards map pool for managing vote rewards, which will also be destroyed after distribution.
    - Pre-fill the vote rewards map with public keys from the vote states pool.
    - Pre-allocate dlist elements for stake rewards and check for allocation errors.
    - Prepare task arguments for calculating stake and vote rewards.
    - Execute the reward calculation tasks using a thread pool if available, otherwise execute sequentially.
- **Output**: The function outputs the calculated stake and vote rewards, stored in the provided result structure, and updates the total stake rewards in lamports.
- **Functions called**:
    - [`calculate_stake_vote_rewards_account`](#calculate_stake_vote_rewards_account)


---
### calculate\_validator\_rewards<!-- {{#callable:calculate_validator_rewards}} -->
The `calculate_validator_rewards` function calculates the rewards for validators by determining epoch reward points and distributing stake and vote rewards for each account.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment.
    - `rewarded_epoch`: An unsigned long integer representing the epoch for which rewards are being calculated.
    - `rewards`: An unsigned long integer representing the total rewards to be distributed.
    - `result`: A pointer to a structure where the calculated rewards results will be stored.
    - `temp_info`: A pointer to temporary epoch information used during the calculation.
    - `tpool`: A pointer to a thread pool used for parallel execution of tasks.
    - `exec_spads`: A pointer to an array of execution scratchpad memory areas used for temporary storage during execution.
    - `exec_spad_cnt`: An unsigned long integer representing the count of execution scratchpad memory areas.
    - `runtime_spad`: A pointer to a runtime scratchpad memory area used for temporary storage during execution.
- **Control Flow**:
    - Read the stake history sysvar using the provided slot context and runtime scratchpad.
    - Check if the stake history was successfully read; if not, log an error and exit.
    - Call [`calculate_reward_points_partitioned`](#calculate_reward_points_partitioned) to compute the epoch reward points from stake and vote accounts.
    - Call [`calculate_stake_vote_rewards`](#calculate_stake_vote_rewards) to compute and distribute the stake and vote rewards for each account.
- **Output**: The function does not return a value but populates the `result` structure with the calculated rewards data.
- **Functions called**:
    - [`calculate_reward_points_partitioned`](#calculate_reward_points_partitioned)
    - [`calculate_stake_vote_rewards`](#calculate_stake_vote_rewards)


---
### get\_reward\_distribution\_num\_blocks<!-- {{#callable:get_reward_distribution_num_blocks}} -->
The function `get_reward_distribution_num_blocks` calculates the number of blocks required to distribute rewards to all stake accounts based on the epoch schedule, current slot, and total number of stake accounts.
- **Inputs**:
    - `epoch_schedule`: A pointer to a constant `fd_epoch_schedule_t` structure that contains information about the epoch schedule, including whether warmup is enabled and the first normal epoch.
    - `slot`: An unsigned long integer representing the current slot number.
    - `total_stake_accounts`: An unsigned long integer representing the total number of stake accounts.
- **Control Flow**:
    - Check if the epoch schedule is in warmup mode and if the current slot's epoch is before the first normal epoch; if so, return 1 block.
    - Calculate the number of chunks needed by dividing the total stake accounts by the number of stake accounts that can be stored per block, adjusting for any remainder.
    - Ensure the number of chunks is at least 1 using `fd_ulong_max`.
    - Limit the number of chunks to a maximum value based on the slots per epoch divided by a predefined maximum factor, using `fd_ulong_min`.
    - Return the calculated number of chunks.
- **Output**: The function returns an unsigned long integer representing the number of blocks required for reward distribution.


---
### hash\_rewards\_into\_partitions<!-- {{#callable:hash_rewards_into_partitions}} -->
The `hash_rewards_into_partitions` function distributes stake rewards into specified partitions based on a hash derived from the parent blockhash and stake public key.
- **Inputs**:
    - `stake_reward_calculation`: A pointer to a structure containing the stake reward calculation data, including a pool of stake rewards.
    - `parent_blockhash`: A constant pointer to a hash structure representing the parent block's hash.
    - `num_partitions`: An unsigned long integer representing the number of partitions to distribute the rewards into.
    - `result`: A pointer to a structure where the partitioned stake rewards will be stored.
    - `runtime_spad`: A pointer to a shared pool of dynamic memory used for runtime allocations.
- **Control Flow**:
    - Initialize a dlist for each partition using the same pool from the stake reward calculation.
    - Allocate memory for the partitions using the runtime_spad.
    - Iterate over all stake rewards in the stake_reward_calculation, moving valid rewards into the appropriate partition based on a hash value.
    - For each valid stake reward, initialize a SipHash hasher, append the parent blockhash and stake public key to the hasher, and finalize the hash to get a 64-bit hash value.
    - Calculate the partition index by scaling the hash value to the number of partitions.
    - Move the stake reward to the calculated partition's dlist and increment the partition's length.
- **Output**: The function does not return a value but modifies the 'result' structure to contain the partitioned stake rewards.


---
### calculate\_rewards\_for\_partitioning<!-- {{#callable:calculate_rewards_for_partitioning}} -->
The `calculate_rewards_for_partitioning` function calculates and partitions rewards for a given epoch based on previous epoch's inflation rewards and validator rewards, preparing them for distribution.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and epoch.
    - `prev_epoch`: An unsigned long integer representing the previous epoch number.
    - `parent_blockhash`: A pointer to the hash of the parent block, used for partitioning rewards.
    - `result`: A pointer to a structure where the calculated partitioned rewards will be stored.
    - `temp_info`: A pointer to temporary epoch information used during calculations.
    - `tpool`: A pointer to a thread pool used for parallel processing.
    - `exec_spads`: A pointer to an array of shared memory areas used for execution.
    - `exec_spad_cnt`: An unsigned long integer representing the count of execution shared memory areas.
    - `runtime_spad`: A pointer to a shared memory area used during runtime for temporary storage.
- **Control Flow**:
    - Initialize a structure to hold previous epoch inflation rewards.
    - Call [`calculate_previous_epoch_inflation_rewards`](#calculate_previous_epoch_inflation_rewards) to compute inflation rewards for the previous epoch.
    - Retrieve the slot bank from the slot context.
    - Initialize a structure to hold validator rewards results.
    - Call [`calculate_validator_rewards`](#calculate_validator_rewards) to compute validator rewards based on the previous epoch and inflation rewards.
    - Determine the number of partitions needed for reward distribution using [`get_reward_distribution_num_blocks`](#get_reward_distribution_num_blocks).
    - Call [`hash_rewards_into_partitions`](#hash_rewards_into_partitions) to distribute stake rewards into partitions based on the parent block hash.
    - Update the result structure with calculated rewards, rates, and other relevant information.
- **Output**: The function outputs the calculated partitioned rewards and related information in the `result` structure.
- **Functions called**:
    - [`calculate_previous_epoch_inflation_rewards`](#calculate_previous_epoch_inflation_rewards)
    - [`calculate_validator_rewards`](#calculate_validator_rewards)
    - [`get_reward_distribution_num_blocks`](#get_reward_distribution_num_blocks)
    - [`hash_rewards_into_partitions`](#hash_rewards_into_partitions)


---
### calculate\_rewards\_and\_distribute\_vote\_rewards<!-- {{#callable:calculate_rewards_and_distribute_vote_rewards}} -->
The function `calculate_rewards_and_distribute_vote_rewards` calculates rewards for a given epoch and distributes vote rewards to the appropriate accounts.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and epoch.
    - `prev_epoch`: The previous epoch number for which rewards are being calculated.
    - `parent_blockhash`: A pointer to the hash of the parent block, used in reward calculations.
    - `result`: A pointer to a structure where the results of the reward calculation and distribution will be stored.
    - `temp_info`: A pointer to temporary epoch information used during calculations.
    - `tpool`: A pointer to a thread pool used for parallel processing.
    - `exec_spads`: An array of pointers to execution scratchpads used for temporary storage during execution.
    - `exec_spad_cnt`: The count of execution scratchpads available.
    - `runtime_spad`: A pointer to a runtime scratchpad used for temporary storage during execution.
- **Control Flow**:
    - Initialize a rewards calculation result structure.
    - Call [`calculate_rewards_for_partitioning`](#calculate_rewards_for_partitioning) to compute rewards for partitioning based on the previous epoch and parent blockhash.
    - Iterate over all vote reward nodes in the calculated rewards map.
    - For each node that needs to be stored, initialize a transaction account for the vote public key.
    - Set the slot for the vote record and add the calculated vote rewards to the account, checking for overflow.
    - Finalize the transaction account and update the distributed rewards in the result structure.
    - Verify that the total distributed rewards do not exceed the expected validator rewards.
    - Update the slot context's capitalization with the distributed rewards.
    - Copy the stake rewards by partition and point value from the calculation result to the output result.
- **Output**: The function outputs the total distributed rewards and updates the slot context's capitalization and the result structure with the calculated rewards and point value.
- **Functions called**:
    - [`calculate_rewards_for_partitioning`](#calculate_rewards_for_partitioning)


---
### distribute\_epoch\_reward\_to\_stake\_acc<!-- {{#callable:distribute_epoch_reward_to_stake_acc}} -->
The function `distribute_epoch_reward_to_stake_acc` distributes a specified reward to a stake account, updating its state and credits observed.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and transaction context.
    - `stake_pubkey`: A pointer to the public key of the stake account to which the reward is to be distributed.
    - `reward_lamports`: The amount of reward, in lamports, to be added to the stake account.
    - `new_credits_observed`: The new value for credits observed to be set in the stake account's state.
- **Control Flow**:
    - Initialize a mutable transaction account record for the stake account using the provided public key and slot context.
    - Set the slot of the stake account record to the current slot from the slot context.
    - Retrieve the current state of the stake account into a local variable `stake_state`.
    - Check if the account is a valid stake account; if not, log a debug message and return an error code.
    - Attempt to add the reward lamports to the stake account; if this fails, log a debug message and return an error code.
    - Update the `credits_observed` and `delegation.stake` fields in the stake account's state with the new values.
    - Write the updated stake state back to the account; if this fails, log an error message.
    - Finalize the mutable transaction account record.
- **Output**: Returns 0 on success, or 1 if any error occurs during the process.


---
### set\_epoch\_reward\_status\_inactive<!-- {{#callable:set_epoch_reward_status_inactive}} -->
The function `set_epoch_reward_status_inactive` sets the epoch reward status to inactive and cleans up any associated state if the status was previously active.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context, which contains information about the current slot and epoch reward status.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for managing runtime state and memory allocation.
- **Control Flow**:
    - Check if the current epoch reward status is active by comparing the discriminant with `fd_epoch_reward_status_enum_Active`.
    - If the status is active, log a notice indicating that partitioning rewards for the current epoch is done.
    - Call `fd_spad_pop` to clean up or release any state associated with the active status in `runtime_spad`.
    - Set the epoch reward status discriminant to `fd_epoch_reward_status_enum_Inactive` to mark it as inactive.
- **Output**: This function does not return any value; it modifies the state of `slot_ctx` and potentially `runtime_spad`.


---
### set\_epoch\_reward\_status\_active<!-- {{#callable:set_epoch_reward_status_active}} -->
The function `set_epoch_reward_status_active` sets the epoch reward status to active and initializes the distribution starting block height and partitioned stake rewards in the slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to the `fd_exec_slot_ctx_t` structure, which contains the execution context for the current slot, including the slot bank and epoch reward status.
    - `distribution_starting_block_height`: An unsigned long integer representing the block height at which the distribution of rewards should start.
    - `partitioned_rewards`: A pointer to the `fd_partitioned_stake_rewards_t` structure, which contains the partitioned stake rewards to be set as active.
- **Control Flow**:
    - Log a notice indicating that the epoch reward status is being set to active.
    - Set the `discriminant` of `epoch_reward_status` in `slot_ctx->slot_bank` to `fd_epoch_reward_status_enum_Active`.
    - Set the `distribution_starting_block_height` in the `inner.Active` structure of `epoch_reward_status` to the provided `distribution_starting_block_height`.
    - Copy the `partitioned_rewards` structure into the `inner.Active.partitioned_stake_rewards` of `epoch_reward_status`.
- **Output**: The function does not return a value; it modifies the `slot_ctx` structure to set the epoch reward status as active.


---
### distribute\_epoch\_rewards\_in\_partition<!-- {{#callable:distribute_epoch_rewards_in_partition}} -->
The function `distribute_epoch_rewards_in_partition` processes and distributes rewards for a specific partition of stake accounts, updating the system's reward records and total capitalization.
- **Inputs**:
    - `partition`: A pointer to a `fd_partitioned_stake_rewards_dlist_t` structure representing the partition of stake rewards to be processed.
    - `pool`: A pointer to a `fd_stake_reward_t` structure representing the pool of stake rewards.
    - `slot_ctx`: A pointer to a `fd_exec_slot_ctx_t` structure representing the execution context for the current slot.
    - `runtime_spad`: A pointer to a `fd_spad_t` structure used for runtime memory allocation and management.
- **Control Flow**:
    - Initialize `lamports_distributed` and `lamports_burned` to zero.
    - Iterate over each stake reward in the partition using a forward iterator.
    - For each stake reward, attempt to distribute the reward to the corresponding stake account using [`distribute_epoch_reward_to_stake_acc`](#distribute_epoch_reward_to_stake_acc).
    - If the distribution is successful, add the reward amount to `lamports_distributed`; otherwise, add it to `lamports_burned`.
    - Check if certain features are active in the slot context to determine if the epoch rewards sysvar should be updated.
    - If the features are active, update the epoch rewards sysvar with the total amount of lamports distributed and burned.
    - Log the amounts of lamports burned and distributed.
    - Update the slot context's capitalization with the total lamports distributed.
- **Output**: The function does not return a value; it updates the system's reward records and the slot context's capitalization.
- **Functions called**:
    - [`distribute_epoch_reward_to_stake_acc`](#distribute_epoch_reward_to_stake_acc)


---
### fd\_distribute\_partitioned\_epoch\_rewards<!-- {{#callable:fd_distribute_partitioned_epoch_rewards}} -->
The function `fd_distribute_partitioned_epoch_rewards` manages the distribution of partitioned epoch rewards to stake accounts based on the current block height and epoch reward status.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and epoch.
    - `tpool`: A pointer to a thread pool, which is not used in this function.
    - `exec_spads`: An array of pointers to execution scratchpad areas, which is not used in this function.
    - `exec_spad_cnt`: The count of execution scratchpad areas, which is not used in this function.
    - `runtime_spad`: A pointer to a runtime scratchpad area used for temporary data storage.
- **Control Flow**:
    - Check if the epoch reward status is inactive; if so, return immediately.
    - Retrieve the active epoch reward status and calculate the distribution end block height.
    - Determine the current epoch and verify that the number of slots in the epoch is greater than the number of partitions; log an error if not.
    - If the current block height is within the distribution range, calculate the partition index and distribute rewards for that partition.
    - Check if the distribution is complete by comparing the incremented block height with the distribution end; if complete, set the reward status to inactive.
- **Output**: The function does not return a value; it performs operations to distribute rewards and update the epoch reward status.
- **Functions called**:
    - [`get_slots_in_epoch`](#get_slots_in_epoch)
    - [`distribute_epoch_rewards_in_partition`](#distribute_epoch_rewards_in_partition)
    - [`set_epoch_reward_status_inactive`](#set_epoch_reward_status_inactive)


---
### fd\_update\_rewards<!-- {{#callable:fd_update_rewards}} -->
The `fd_update_rewards` function calculates and distributes epoch rewards for stake and vote accounts in a non-partitioned manner.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and epoch.
    - `parent_blockhash`: A constant pointer to the hash of the parent block, used for reward calculations.
    - `parent_epoch`: An unsigned long representing the parent epoch number.
    - `temp_info`: A pointer to temporary epoch information used during reward calculations.
    - `tpool`: A pointer to a thread pool used for parallel processing.
    - `exec_spads`: A pointer to an array of execution scratchpad pointers, used for temporary storage during execution.
    - `exec_spad_cnt`: An unsigned long representing the count of execution scratchpads.
    - `runtime_spad`: A pointer to a runtime scratchpad used for temporary storage during execution.
- **Control Flow**:
    - Initialize a result structure for rewards calculation and distribution.
    - Call [`calculate_rewards_and_distribute_vote_rewards`](#calculate_rewards_and_distribute_vote_rewards) to compute rewards and distribute vote rewards based on the provided context and parameters.
    - Iterate over each partition in the calculated rewards and call [`distribute_epoch_rewards_in_partition`](#distribute_epoch_rewards_in_partition) to distribute the rewards to stake accounts.
- **Output**: The function does not return a value; it performs operations to update the rewards in the system state.
- **Functions called**:
    - [`calculate_rewards_and_distribute_vote_rewards`](#calculate_rewards_and_distribute_vote_rewards)
    - [`distribute_epoch_rewards_in_partition`](#distribute_epoch_rewards_in_partition)


---
### fd\_begin\_partitioned\_rewards<!-- {{#callable:fd_begin_partitioned_rewards}} -->
The `fd_begin_partitioned_rewards` function initiates the process of calculating and distributing partitioned rewards for a given epoch in a blockchain system.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current slot and epoch.
    - `parent_blockhash`: A pointer to the hash of the parent block, used for reward calculations.
    - `parent_epoch`: The epoch number of the parent block.
    - `temp_info`: A pointer to temporary epoch information used during reward calculations.
    - `tpool`: A pointer to a thread pool used for parallel processing.
    - `exec_spads`: An array of pointers to execution scratchpad areas used for temporary storage during calculations.
    - `exec_spad_cnt`: The count of execution scratchpad areas available.
    - `runtime_spad`: A pointer to a runtime scratchpad area used for temporary storage during calculations.
- **Control Flow**:
    - Initialize a result structure for rewards calculation and distribution.
    - Call [`calculate_rewards_and_distribute_vote_rewards`](#calculate_rewards_and_distribute_vote_rewards) to compute rewards and distribute vote rewards based on the provided context and parameters.
    - Determine the starting block height for reward distribution by adding a predefined number of blocks to the current block height.
    - Activate the epoch reward status by calling [`set_epoch_reward_status_active`](#set_epoch_reward_status_active), passing the calculated starting block height and partitioned stake rewards.
    - Initialize the epoch rewards system variable using `fd_sysvar_epoch_rewards_init` with the calculated rewards and distribution parameters.
- **Output**: The function does not return a value; it modifies the state of the slot context and initializes reward distribution processes.
- **Functions called**:
    - [`calculate_rewards_and_distribute_vote_rewards`](#calculate_rewards_and_distribute_vote_rewards)
    - [`set_epoch_reward_status_active`](#set_epoch_reward_status_active)


---
### fd\_rewards\_recalculate\_partitioned\_rewards<!-- {{#callable:fd_rewards_recalculate_partitioned_rewards}} -->
The function `fd_rewards_recalculate_partitioned_rewards` recalculates partitioned stake rewards for a given execution context and updates the epoch reward status accordingly.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution environment and state.
    - `tpool`: A pointer to a thread pool used for parallel execution of tasks.
    - `exec_spads`: An array of pointers to execution scratchpad areas used for temporary data storage during execution.
    - `exec_spad_cnt`: The count of execution scratchpad areas available.
    - `runtime_spad`: A pointer to the runtime scratchpad area used for temporary data storage during execution.
- **Control Flow**:
    - Read the epoch rewards sysvar using the provided slot context and runtime scratchpad.
    - If the epoch rewards sysvar is not available, log a notice and set the epoch reward status to inactive, then return.
    - Log a notice indicating the start of recalculating partitioned rewards.
    - Check if the epoch rewards are active; if not, set the epoch reward status to inactive and return.
    - Push a new frame onto the runtime scratchpad stack to prepare for calculations.
    - Determine the current epoch and the rewarded epoch (the previous epoch).
    - Allocate memory for the new warmup cooldown rate epoch and calculate it using the slot context and runtime scratchpad.
    - Read the stake history sysvar; if unavailable, log an error and exit.
    - Initialize a point value structure with total points and rewards from the epoch rewards sysvar.
    - Initialize epoch information and accumulate stake information using the slot context, stake history, and runtime scratchpad.
    - Populate vote accounts using the slot context, stake history, and runtime scratchpad.
    - Calculate stake vote rewards using the accumulated epoch information and runtime scratchpad.
    - Hash the calculated stake rewards into partitions using the parent blockhash and number of partitions from the epoch rewards sysvar.
    - Update the epoch reward status to active with the newly calculated partitioned stake rewards.
- **Output**: The function does not return a value; it updates the epoch reward status in the slot context with recalculated partitioned rewards.
- **Functions called**:
    - [`set_epoch_reward_status_inactive`](#set_epoch_reward_status_inactive)
    - [`calculate_stake_vote_rewards`](#calculate_stake_vote_rewards)
    - [`hash_rewards_into_partitions`](#hash_rewards_into_partitions)
    - [`set_epoch_reward_status_active`](#set_epoch_reward_status_active)


