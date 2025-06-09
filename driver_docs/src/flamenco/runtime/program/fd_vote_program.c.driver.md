# Purpose
The provided C code is part of a voting program implementation, likely for a blockchain or distributed ledger system. This code is designed to manage and process voting-related operations, including vote state updates, vote authorization, and account management. The file includes a variety of functions that handle different aspects of the voting process, such as initializing vote accounts, processing votes, updating vote states, and managing authorized voters. The code is structured to interact with various system variables and accounts, ensuring that voting operations are executed correctly and securely.

Key components of the code include functions for handling vote state transitions, managing authorized voters, and processing different types of voting instructions. The code also includes mechanisms for verifying signatures and ensuring that vote operations comply with system rules and constraints. Additionally, the code is designed to be integrated into a larger system, as indicated by the inclusion of various header files and the use of system-specific data structures and functions. Overall, this code provides a comprehensive framework for managing voting operations within a distributed system, ensuring that votes are processed accurately and securely.
# Imports and Dependencies

---
- `fd_vote_program.h`
- `../../types/fd_types_yaml.h`
- `../fd_borrowed_account.h`
- `../fd_executor.h`
- `../fd_pubkey_utils.h`
- `../sysvar/fd_sysvar_epoch_schedule.h`
- `../sysvar/fd_sysvar_rent.h`
- `../sysvar/fd_sysvar_clock.h`
- `../sysvar/fd_sysvar_slot_hashes.h`
- `limits.h`
- `math.h`
- `stdio.h`
- `string.h`


# Global Variables

---
### last\_voted\_slot
- **Type**: `function pointer`
- **Description**: `last_voted_slot` is a function pointer that returns a pointer to an unsigned long integer (`ulong`). It takes a single argument, which is a pointer to a `fd_vote_state_t` structure.
- **Use**: This function is used to retrieve the slot number of the last vote cast in the voting state represented by the `fd_vote_state_t` structure.


# Functions

---
### size\_of\_versioned<!-- {{#callable:size_of_versioned}} -->
The `size_of_versioned` function returns the size of a versioned vote state based on whether it is the current version or an older version.
- **Inputs**:
    - `is_current`: An integer flag indicating whether the version requested is the current version (1 for current, 0 for previous).
- **Control Flow**:
    - The function uses the `fd_ulong_if` macro to conditionally return the size based on the value of `is_current`.
    - If `is_current` is true (non-zero), it returns `FD_VOTE_STATE_V3_SZ`, otherwise it returns `FD_VOTE_STATE_V2_SZ`.
- **Output**: The function outputs an unsigned long integer representing the size of the vote state for the specified version.


---
### lockout<!-- {{#callable:lockout}} -->
The `lockout` function calculates the lockout duration based on the confirmation count of a voting lockout.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_lockout_t` structure that contains the current confirmation count.
- **Control Flow**:
    - The function retrieves the `confirmation_count` from the `self` structure.
    - It ensures that the `confirmation_count` does not exceed `MAX_LOCKOUT_HISTORY` using the `fd_ulong_min` function.
    - The function then calculates the lockout duration by shifting 1 left by the value of `confirmation_count`.
- **Output**: Returns the calculated lockout duration as an unsigned long integer, which is 2 raised to the power of the confirmation count.


---
### last\_locked\_out\_slot<!-- {{#callable:last_locked_out_slot}} -->
The `last_locked_out_slot` function calculates the last slot that a vote lockout applies to by adding the current slot to the lockout duration.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_lockout_t` structure that contains the current slot and confirmation count.
- **Control Flow**:
    - The function calls `lockout(self)` to determine the lockout duration based on the confirmation count.
    - It then adds the current slot (from `self->slot`) to the lockout duration using `fd_ulong_sat_add` to ensure that the result does not overflow.
- **Output**: Returns the last slot that the vote is locked out from, which is the sum of the current slot and the calculated lockout duration.
- **Functions called**:
    - [`lockout`](#lockout)


---
### is\_locked\_out\_at\_slot<!-- {{#callable:is_locked_out_at_slot}} -->
The `is_locked_out_at_slot` function checks if a vote lockout is active at a specified slot.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_lockout_t` structure that contains information about the vote lockout.
    - `slot`: An unsigned long integer representing the slot number to check against the lockout.
- **Control Flow**:
    - Calls the [`last_locked_out_slot`](#last_locked_out_slot) function to retrieve the last slot at which a lockout occurred.
    - Compares the result of [`last_locked_out_slot`](#last_locked_out_slot) with the provided `slot` argument.
    - Returns a boolean indicating whether the last locked out slot is greater than or equal to the specified slot.
- **Output**: Returns a boolean value (as an unsigned long) indicating whether the lockout is active at the specified slot.
- **Functions called**:
    - [`last_locked_out_slot`](#last_locked_out_slot)


---
### increase\_confirmation\_count<!-- {{#callable:increase_confirmation_count}} -->
The `increase_confirmation_count` function increments the `confirmation_count` of a `fd_vote_lockout_t` structure by a specified amount, ensuring that the result does not exceed a predefined maximum.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_lockout_t` structure that contains the current confirmation count.
    - `by`: An unsigned integer representing the amount by which to increase the confirmation count.
- **Control Flow**:
    - The function calls `fd_uint_sat_add` to safely add the current `confirmation_count` to the value of `by`.
    - The result of the addition is stored back in the `confirmation_count` field of the `fd_vote_lockout_t` structure.
- **Output**: The function does not return a value; it modifies the `confirmation_count` field of the provided `fd_vote_lockout_t` structure in place.


---
### from\_vote\_state\_1\_14\_11<!-- {{#callable:from_vote_state_1_14_11}} -->
The `from_vote_state_1_14_11` function converts a current vote state object into an older version (v1.14.11) while transferring relevant data and cleaning up the original state.
- **Inputs**:
    - `vote_state`: A pointer to the current vote state object (`fd_vote_state_t`) that contains the data to be converted.
    - `vote_state_1_14_11`: A pointer to the output vote state object (`fd_vote_state_1_14_11_t`) that will hold the converted data.
    - `spad`: A pointer to a memory allocator (`fd_spad_t`) used for allocating memory during the conversion process.
- **Control Flow**:
    - The function begins by copying basic fields from `vote_state` to `vote_state_1_14_11`.
    - If the `votes` field in `vote_state` is not NULL, it allocates memory for the votes in the new structure and iterates through the votes in the current state, transferring each lockout to the new state.
    - The function then copies additional fields from `vote_state` to `vote_state_1_14_11`, including moving ownership of certain structures.
    - Finally, it clears the moved objects in the original `vote_state` to prevent dangling pointers.
- **Output**: The function does not return a value but modifies the `vote_state_1_14_11` object to contain the converted data from the current vote state, effectively transforming it into an older version.


---
### get\_state<!-- {{#callable:get_state}} -->
The `get_state` function retrieves and decodes the vote state from a transaction account.
- **Inputs**:
    - `self`: A pointer to a constant `fd_txn_account_t` structure representing the transaction account from which the vote state is to be retrieved.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation during the decoding process.
    - `err`: A pointer to an integer where the function will store the error code if any decoding error occurs.
- **Control Flow**:
    - The function initializes a variable `decode_err` to track decoding errors.
    - It calls the `fd_bincode_decode_spad` function to decode the vote state from the provided `spad` using the data from the transaction account.
    - If decoding fails (indicated by a non-zero `decode_err`), it sets the error code pointed to by `err` to `FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA` and returns NULL.
    - If decoding is successful, it sets the error code pointed to by `err` to `FD_EXECUTOR_INSTR_SUCCESS` and returns the decoded vote state.
- **Output**: The function returns a pointer to a `fd_vote_state_versioned_t` structure representing the decoded vote state, or NULL if an error occurred.


---
### set\_state<!-- {{#callable:set_state}} -->
The `set_state` function updates the state of a borrowed account with a serialized vote state.
- **Inputs**:
    - `self`: A pointer to a `fd_borrowed_account_t` structure representing the account whose state is to be set.
    - `state`: A pointer to a `fd_vote_state_versioned_t` structure containing the new state to be serialized and set.
- **Control Flow**:
    - The function begins by declaring variables for data and its length, initializing them to NULL and 0 respectively.
    - It calls `fd_borrowed_account_get_data_mut` to retrieve mutable access to the account's data and its length, checking for errors.
    - Next, it calculates the serialized size of the new state using `fd_vote_state_versioned_size` and checks if it fits in the available data length.
    - If the serialized size exceeds the available length, it returns an error indicating the account data is too small.
    - An encoding context is set up with the retrieved data and its end pointer.
    - The function then encodes the new state into the account's data using `fd_vote_state_versioned_encode`, logging any errors that occur during encoding.
    - Finally, it returns a success status code.
- **Output**: The function returns an integer status code indicating success or an error code if an error occurred during the process.


---
### authorized\_voters\_new<!-- {{#callable:authorized_voters_new}} -->
The `authorized_voters_new` function initializes a new authorized voters structure with memory allocation and populates it with the provided epoch and public key.
- **Inputs**:
    - `epoch`: An unsigned long integer representing the epoch for which the authorized voter is being created.
    - `pubkey`: A pointer to a `fd_pubkey_t` structure containing the public key of the authorized voter.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation.
    - `authorized_voters`: A pointer to a `fd_vote_authorized_voters_t` structure that will be populated with the new authorized voters data.
- **Control Flow**:
    - Memory for the authorized voters pool is allocated using `fd_spad_alloc` with alignment and footprint calculated based on the minimum required size.
    - The allocated memory is then used to create a new pool for authorized voters using `fd_vote_authorized_voters_pool_new`.
    - A similar process is followed to allocate memory for a treap structure that will manage the authorized voters.
    - The function checks if the pool is empty after allocation and logs an error if it is.
    - An element is acquired from the pool, and its epoch and public key are set based on the input parameters.
    - Finally, the new authorized voter element is inserted into the treap structure.
- **Output**: The function does not return a value but populates the `authorized_voters` structure with the newly created authorized voter data, including its pool and treap.


---
### authorized\_voters\_is\_empty<!-- {{#callable:authorized_voters_is_empty}} -->
The `authorized_voters_is_empty` function checks if the authorized voters treap is empty.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_authorized_voters_t` structure that contains the treap of authorized voters.
- **Control Flow**:
    - The function calls `fd_vote_authorized_voters_treap_ele_cnt` with the treap from the `self` structure to get the count of elements.
    - It compares the count to zero and returns the result of this comparison.
- **Output**: Returns 1 if the treap is empty (i.e., contains no authorized voters), otherwise returns 0.


---
### authorized\_voters\_contains<!-- {{#callable:authorized_voters_contains}} -->
The `authorized_voters_contains` function checks if a specific epoch is present in the authorized voters treap.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_authorized_voters_t` structure that contains the treap and pool of authorized voters.
    - `epoch`: An unsigned long integer representing the epoch to check for presence in the authorized voters.
- **Control Flow**:
    - The function calls `fd_vote_authorized_voters_treap_ele_query` with the treap from `self`, the specified `epoch`, and the pool from `self`.
    - The result of the query is converted to a boolean value using the double negation operator (!!) to determine if the epoch exists in the treap.
- **Output**: Returns an integer value: 1 if the epoch is found in the authorized voters, and 0 otherwise.


---
### authorized\_voters\_last<!-- {{#callable:authorized_voters_last}} -->
The `authorized_voters_last` function retrieves the last authorized voter from a treap structure.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_authorized_voters_t` structure that contains the treap of authorized voters.
- **Control Flow**:
    - Initializes a reverse iterator for the treap contained in the `self` structure.
    - Calls the `fd_vote_authorized_voters_treap_rev_iter_ele` function with the iterator and the pool to retrieve the last authorized voter.
- **Output**: Returns a pointer to the last `fd_vote_authorized_voter_t` structure from the treap, or NULL if the treap is empty.


---
### authorized\_voters\_purge\_authorized\_voters<!-- {{#callable:authorized_voters_purge_authorized_voters}} -->
The `authorized_voters_purge_authorized_voters` function purges expired authorized voters from a treap based on the current epoch.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_authorized_voters_t` structure representing the current authorized voters.
    - `current_epoch`: An unsigned long integer representing the current epoch to compare against the epochs of authorized voters.
    - `ctx`: A constant pointer to an `fd_exec_instr_ctx_t` structure that provides execution context, including a stack allocator.
- **Control Flow**:
    - The function begins by allocating memory for an array to hold expired keys using the stack allocator from the execution context.
    - It initializes a forward iterator to traverse the treap of authorized voters and checks each voter's epoch against the current epoch.
    - If a voter's epoch is less than the current epoch, it adds the voter's epoch to the expired keys array.
    - After collecting all expired keys, it iterates over the expired keys to remove each corresponding voter from the treap and release their memory.
    - Finally, it asserts that the authorized voters structure is not empty after the purge operation.
- **Output**: The function does not return a value; it modifies the state of the `self` structure by removing expired voters.
- **Functions called**:
    - [`authorized_voters_is_empty`](#authorized_voters_is_empty)


---
### authorized\_voters\_get\_or\_calculate\_authorized\_voter\_for\_epoch<!-- {{#callable:authorized_voters_get_or_calculate_authorized_voter_for_epoch}} -->
The function retrieves or calculates the authorized voter for a specified epoch.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_authorized_voters_t` structure that contains the authorized voters.
    - `epoch`: An unsigned long representing the epoch for which the authorized voter is being queried.
    - `existed`: A pointer to an integer that will be set to indicate whether the authorized voter already exists.
- **Control Flow**:
    - The function initializes the `existed` flag to 0 and sets `latest_epoch` to 0.
    - It attempts to query the authorized voter for the specified `epoch` from a treap structure.
    - If the voter does not exist, it iterates through the treap to find the most recent authorized voter from previous epochs.
    - If a valid voter is found, it updates the `latest_epoch` and sets the result to this voter.
    - If the voter exists, it sets the `existed` flag to 1 and returns the found voter.
- **Output**: Returns a pointer to the `fd_vote_authorized_voter_t` structure representing the authorized voter for the specified epoch, or NULL if no voter is found.


---
### authorized\_voters\_get\_and\_cache\_authorized\_voter\_for\_epoch<!-- {{#callable:authorized_voters_get_and_cache_authorized_voter_for_epoch}} -->
The function retrieves and caches an authorized voter for a specific epoch.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_authorized_voters_t` structure that contains the pool and treap of authorized voters.
    - `epoch`: An unsigned long integer representing the epoch for which the authorized voter is being retrieved.
- **Control Flow**:
    - The function initializes an integer `existed` to track if the voter already exists.
    - It calls [`authorized_voters_get_or_calculate_authorized_voter_for_epoch`](#authorized_voters_get_or_calculate_authorized_voter_for_epoch) to attempt to retrieve the authorized voter for the specified epoch.
    - If the voter does not exist, it checks if the pool of authorized voters is empty and logs an error if so.
    - If the voter was newly created, it allocates a new `fd_vote_authorized_voter_t` element from the pool, sets its properties, and inserts it into the treap.
- **Output**: Returns a pointer to the `fd_vote_authorized_voter_t` structure representing the authorized voter for the specified epoch, or NULL if no voter exists.
- **Functions called**:
    - [`authorized_voters_get_or_calculate_authorized_voter_for_epoch`](#authorized_voters_get_or_calculate_authorized_voter_for_epoch)


---
### landed\_votes\_from\_lockouts<!-- {{#callable:landed_votes_from_lockouts}} -->
The `landed_votes_from_lockouts` function generates a list of landed votes based on provided lockouts.
- **Inputs**:
    - `lockouts`: A pointer to a `fd_vote_lockout_t` structure that contains the lockout information.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation.
- **Control Flow**:
    - The function first checks if the `lockouts` pointer is NULL and returns NULL if it is.
    - It calculates the count of lockouts and ensures it is at least `MAX_LOCKOUT_HISTORY`.
    - Memory is allocated for the landed votes using the `fd_spad_alloc` function.
    - A new deque of landed votes is created and initialized.
    - The function iterates over each lockout in the `lockouts` structure.
    - For each lockout, a new landed vote is created and initialized with default values.
    - The slot and confirmation count from the lockout are assigned to the corresponding fields in the landed vote.
    - Finally, the function returns the populated list of landed votes.
- **Output**: Returns a pointer to a `fd_landed_vote_t` structure containing the generated landed votes.


---
### is\_uninitialized<!-- {{#callable:is_uninitialized}} -->
The `is_uninitialized` function checks if a given vote state is uninitialized based on its version.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_versioned_t` structure representing the vote state to be checked.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` field of the `self` structure to determine the version of the vote state.
    - For version `fd_vote_state_versioned_enum_v0_23_5`, it compares the `authorized_voter` field with a default public key initialized to zero.
    - For version `fd_vote_state_versioned_enum_v1_14_11`, it calls the [`authorized_voters_is_empty`](#authorized_voters_is_empty) function to check if the authorized voters list is empty.
    - For the current version, it also checks if the authorized voters list is empty using the same function.
    - If the `discriminant` does not match any known version, it logs an error indicating an invalid vote state version.
- **Output**: The function returns an integer: 1 if the vote state is uninitialized, 0 otherwise, and logs an error for invalid versions.
- **Functions called**:
    - [`authorized_voters_is_empty`](#authorized_voters_is_empty)


---
### convert\_to\_current<!-- {{#callable:convert_to_current}} -->
Converts a versioned vote state to the current version.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_versioned_t` structure representing the vote state to be converted.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation during the conversion process.
- **Control Flow**:
    - The function begins by checking the `discriminant` field of the `self` structure to determine the version of the vote state.
    - If the version is `fd_vote_state_versioned_enum_v0_23_5`, it extracts the relevant fields from the `v0_23_5` structure, creates a new `fd_vote_state_t` structure, and populates it with the current values.
    - It then sets the `discriminant` of `self` to `fd_vote_state_versioned_enum_current` and assigns the newly created `fd_vote_state_t` to the `inner.current` field.
    - If the version is `fd_vote_state_versioned_enum_v1_14_11`, it follows a similar process but uses the `v1_14_11` structure instead.
    - If the version is already `fd_vote_state_versioned_enum_current`, no action is taken.
    - If the version is unsupported, an error is logged.
- **Output**: The function does not return a value, but it modifies the `self` structure to reflect the current vote state.
- **Functions called**:
    - [`authorized_voters_new`](#authorized_voters_new)
    - [`landed_votes_from_lockouts`](#landed_votes_from_lockouts)


---
### vote\_state\_new<!-- {{#callable:vote_state_new}} -->
The `vote_state_new` function initializes a new voting state based on the provided initialization parameters.
- **Inputs**:
    - `vote_init`: A pointer to a `fd_vote_init_t` structure containing initialization data for the vote state.
    - `clock`: A pointer to a constant `fd_sol_sysvar_clock_t` structure that provides the current epoch information.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation.
    - `vote_state`: A pointer to a `fd_vote_state_t` structure that will be populated with the new vote state.
- **Control Flow**:
    - The function begins by copying the public key from the `vote_init` structure to the `vote_state` structure.
    - It then calls the [`authorized_voters_new`](#authorized_voters_new) function to initialize the authorized voters for the current epoch using the public key from `vote_init`.
    - Next, it sets the authorized withdrawer and commission values in the `vote_state` structure from the `vote_init` structure.
    - Finally, it initializes the prior voters index to 31 and marks the prior voters as empty.
- **Output**: The function does not return a value but populates the `vote_state` structure with the initialized voting state.
- **Functions called**:
    - [`authorized_voters_new`](#authorized_voters_new)


---
### verify\_authorized\_signer<!-- {{#callable:verify_authorized_signer}} -->
The `verify_authorized_signer` function checks if a specified public key is present in a list of signers.
- **Inputs**:
    - `authorized`: A pointer to the `fd_pubkey_t` structure representing the authorized public key that needs to be verified.
    - `signers`: An array of pointers to `fd_pubkey_t` structures representing the list of signers.
- **Control Flow**:
    - The function calls `fd_signers_contains` with the `signers` array and the `authorized` public key.
    - If `fd_signers_contains` returns true, the function returns `FD_EXECUTOR_INSTR_SUCCESS`.
    - If `fd_signers_contains` returns false, the function returns `FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE`.
- **Output**: The function returns an integer indicating success or an error code based on whether the authorized signer is found in the list of signers.


---
### verify<!-- {{#callable:verify}} -->
The `verify` function checks if a signer is authorized based on the provided conditions.
- **Inputs**:
    - `epoch_authorized_voter`: A pointer to the public key of the authorized voter for the current epoch.
    - `authorized_withdrawer_signer`: An integer flag indicating whether the authorized withdrawer is a signer.
    - `signers`: An array of pointers to public keys representing the signers of the transaction.
- **Control Flow**:
    - The function first checks if the `authorized_withdrawer_signer` is true.
    - If true, it returns 0, indicating no error.
    - If false, it calls the [`verify_authorized_signer`](#verify_authorized_signer) function with the `epoch_authorized_voter` and `signers` as arguments.
- **Output**: The function returns 0 if the authorized withdrawer is a signer; otherwise, it returns the result of the [`verify_authorized_signer`](#verify_authorized_signer) function.
- **Functions called**:
    - [`verify_authorized_signer`](#verify_authorized_signer)


---
### pop\_expired\_votes<!-- {{#callable:pop_expired_votes}} -->
The `pop_expired_votes` function removes votes from the tail of a queue if they are not locked out at a specified slot.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_t` structure representing the current state of the vote, which contains a queue of votes.
    - `next_vote_slot`: An unsigned long integer representing the slot number to check against the lockout of each vote.
- **Control Flow**:
    - The function enters a while loop that continues as long as the queue of votes is not empty.
    - Within the loop, it retrieves the vote at the tail of the queue.
    - It checks if the vote is locked out at the specified `next_vote_slot` using the [`is_locked_out_at_slot`](#is_locked_out_at_slot) function.
    - If the vote is not locked out, it is removed from the queue; otherwise, the loop breaks.
- **Output**: The function does not return a value; it modifies the state of the `self` structure by removing expired votes.
- **Functions called**:
    - [`is_locked_out_at_slot`](#is_locked_out_at_slot)


---
### double\_lockouts<!-- {{#callable:double_lockouts}} -->
The `double_lockouts` function increments the confirmation count of landed votes in a voting state if certain conditions regarding stack depth and confirmation count are met.
- **Inputs**:
    - `fd_vote_state_t * self`: A pointer to the current voting state which contains the votes to be processed.
- **Control Flow**:
    - Retrieve the count of landed votes from the `self->votes` deque.
    - Initialize an index variable `i` to track the current iteration.
    - Iterate over each landed vote in the `self->votes` deque using an iterator.
    - For each vote, check if the current stack depth exceeds the sum of the index and the vote's confirmation count.
    - If the condition is met, increment the confirmation count of the vote by 1.
    - Increment the index variable `i` after processing each vote.
- **Output**: The function does not return a value; it modifies the confirmation counts of the votes in place within the provided voting state.
- **Functions called**:
    - [`increase_confirmation_count`](#increase_confirmation_count)


---
### compute\_vote\_latency<!-- {{#callable:compute_vote_latency}} -->
The `compute_vote_latency` function calculates the latency of a vote based on the slots voted for and the current slot.
- **Inputs**:
    - `voted_for_slot`: An unsigned long integer representing the slot number for which the vote was cast.
    - `current_slot`: An unsigned long integer representing the current slot number.
- **Control Flow**:
    - The function first computes the difference between `current_slot` and `voted_for_slot` using `fd_ulong_sat_sub`, which safely handles underflow.
    - It then applies `fd_ulong_min` to ensure that the result does not exceed `UCHAR_MAX`, effectively capping the latency value.
    - Finally, the result is cast to an unsigned char and returned.
- **Output**: The function returns an unsigned char representing the computed vote latency, which is the difference between the current slot and the voted for slot, capped at 255.


---
### credits\_for\_vote\_at\_index<!-- {{#callable:credits_for_vote_at_index}} -->
Calculates the credits awarded for a vote at a specific index based on latency and other parameters.
- **Inputs**:
    - `self`: A pointer to the `fd_vote_state_t` structure representing the current vote state.
    - `index`: An unsigned long integer representing the index of the vote in the votes deque.
    - `timely_vote_credits`: An integer indicating whether timely vote credits should be awarded.
    - `deprecate_unused_legacy_vote_plumbing`: An integer indicating whether to use the new maximum credits value.
- **Control Flow**:
    - The function retrieves the landed vote at the specified index from the votes deque.
    - It checks the latency of the landed vote; if it is NULL, it defaults to 0.
    - Based on the `deprecate_unused_legacy_vote_plumbing` flag, it sets the maximum credits to either the new or old maximum value.
    - If the latency is 0 or if legacy vote plumbing is deprecated and timely vote credits are not awarded, it returns 1 credit.
    - It calculates the difference between the latency and a grace period, returning the maximum credits if the difference is non-positive.
    - It calculates the credits based on the maximum credits and the difference, returning 1 if the credits are non-positive.
- **Output**: Returns an unsigned long integer representing the number of credits awarded for the vote at the specified index.


---
### increment\_credits<!-- {{#callable:increment_credits}} -->
The `increment_credits` function updates the credit count for a specific epoch in a voting state.
- **Inputs**:
    - `self`: A pointer to the `fd_vote_state_t` structure representing the current voting state.
    - `epoch`: An unsigned long integer representing the epoch for which credits are being incremented.
    - `credits`: An unsigned long integer representing the number of credits to be added.
- **Control Flow**:
    - The function first checks if the `epoch_credits` deque is empty; if so, it initializes it with the current epoch and zero credits.
    - If the deque is not empty, it checks if the provided epoch is different from the last epoch in the deque.
    - If the epoch is different, it retrieves the last credits and previous credits, and checks if they are different.
    - If the credits are different, it checks if the deque has reached its maximum capacity; if so, it removes the oldest entry.
    - Then, it adds a new entry for the current epoch with the updated credits.
    - If the epoch is the same as the last one, it simply updates the epoch value.
    - Finally, it increments the credits for the current epoch using a saturated addition function.
- **Output**: The function does not return a value; it modifies the state of the `fd_vote_state_t` structure by updating the credits for the specified epoch.


---
### process\_next\_vote\_slot<!-- {{#callable:process_next_vote_slot}} -->
Processes the next vote slot for a given voting state.
- **Inputs**:
    - `self`: A pointer to the `fd_vote_state_t` structure representing the current voting state.
    - `next_vote_slot`: The slot number for the next vote to be processed.
    - `epoch`: The current epoch number.
    - `current_slot`: The current slot number.
    - `timely_vote_credits`: An integer indicating whether timely vote credits should be awarded.
    - `deprecate_unused_legacy_vote_plumbing`: An integer indicating whether to deprecate unused legacy vote plumbing.
- **Control Flow**:
    - Check if the last voted slot is greater than or equal to the next vote slot; if so, return early.
    - Call [`pop_expired_votes`](#pop_expired_votes) to remove any expired votes from the voting state.
    - Compute the latency for the new vote based on the current slot and whether timely vote credits are applicable.
    - Check if the number of landed votes has reached the maximum lockout history; if so, increment credits and update the root slot.
    - Push the new landed vote to the tail of the votes deque.
    - Call [`double_lockouts`](#double_lockouts) to update the confirmation counts of the landed votes.
- **Output**: The function does not return a value; it modifies the state of the `fd_vote_state_t` structure directly.
- **Functions called**:
    - [`last_voted_slot`](#last_voted_slot)
    - [`pop_expired_votes`](#pop_expired_votes)
    - [`compute_vote_latency`](#compute_vote_latency)
    - [`credits_for_vote_at_index`](#credits_for_vote_at_index)
    - [`increment_credits`](#increment_credits)
    - [`double_lockouts`](#double_lockouts)


---
### get\_and\_update\_authorized\_voter<!-- {{#callable:get_and_update_authorized_voter}} -->
The `get_and_update_authorized_voter` function retrieves and updates the authorized voter for a given epoch.
- **Inputs**:
    - `self`: A pointer to the `fd_vote_state_t` structure representing the current vote state.
    - `current_epoch`: An unsigned long integer representing the current epoch for which the authorized voter is being retrieved.
    - `pubkey`: A pointer to a pointer of `fd_pubkey_t` where the public key of the authorized voter will be stored.
    - `ctx`: A constant pointer to the execution instruction context, which provides the context for the operation.
- **Control Flow**:
    - The function calls [`authorized_voters_get_and_cache_authorized_voter_for_epoch`](#authorized_voters_get_and_cache_authorized_voter_for_epoch) to retrieve the authorized voter for the specified epoch.
    - If the retrieved authorized voter is NULL, the function returns an error code indicating invalid account data.
    - The public key of the authorized voter is assigned to the output parameter `pubkey`.
    - The function then calls [`authorized_voters_purge_authorized_voters`](#authorized_voters_purge_authorized_voters) to remove any expired authorized voters for the current epoch.
    - Finally, the function returns a success code.
- **Output**: The function returns an integer indicating the success or failure of the operation, with specific error codes for different failure conditions.
- **Functions called**:
    - [`authorized_voters_get_and_cache_authorized_voter_for_epoch`](#authorized_voters_get_and_cache_authorized_voter_for_epoch)
    - [`authorized_voters_purge_authorized_voters`](#authorized_voters_purge_authorized_voters)


---
### set\_new\_authorized\_voter<!-- {{#callable:set_new_authorized_voter}} -->
The `set_new_authorized_voter` function updates the authorized voter for a voting account in a specified epoch.
- **Inputs**:
    - `self`: A pointer to the current vote state structure (`fd_vote_state_t`) that holds the voting account's state.
    - `authorized_pubkey`: A pointer to the public key of the new authorized voter (`fd_pubkey_t`) that is being set.
    - `current_epoch`: The current epoch number (`ulong`) during which the authorization is being set.
    - `target_epoch`: The target epoch number (`ulong`) for which the new authorization is intended.
    - `authorized_withdrawer_signer`: An integer indicating whether the authorized withdrawer is a signer (1 for true, 0 for false).
    - `signers`: An array of public keys (`fd_pubkey_t`) representing the signers for the transaction.
    - `ctx`: A pointer to the execution context (`fd_exec_instr_ctx_t`) that provides the context for the instruction execution.
- **Control Flow**:
    - The function first retrieves and updates the current authorized voter for the given `current_epoch`.
    - It verifies if the current authorized voter matches the provided `authorized_withdrawer_signer` and the signers.
    - It checks if the `target_epoch` already has an authorized voter; if so, it sets a custom error indicating it's too soon to reauthorize.
    - It retrieves the latest authorized voter and checks if the new `authorized_pubkey` differs from the latest one.
    - If the new authorized voter is different, it updates the prior voters' history and ensures the `target_epoch` is valid.
    - Finally, it acquires a new entry from the authorized voters pool, sets its epoch and public key, and inserts it into the authorized voters structure.
- **Output**: Returns 0 on success, or an error code indicating the type of failure encountered during the operation.
- **Functions called**:
    - [`get_and_update_authorized_voter`](#get_and_update_authorized_voter)
    - [`verify`](#verify)
    - [`authorized_voters_contains`](#authorized_voters_contains)
    - [`authorized_voters_last`](#authorized_voters_last)


---
### process\_timestamp<!-- {{#callable:process_timestamp}} -->
The `process_timestamp` function updates the last recorded timestamp and slot in a voting state if the provided timestamp and slot are valid.
- **Inputs**:
    - `self`: A pointer to the `fd_vote_state_t` structure representing the current voting state.
    - `slot`: An unsigned long integer representing the slot number associated with the timestamp.
    - `timestamp`: A long integer representing the timestamp to be processed.
    - `ctx`: A constant pointer to the execution instruction context, which contains transaction context and error handling.
- **Control Flow**:
    - The function first checks if the provided `slot` and `timestamp` are valid compared to the last recorded values in `self->last_timestamp`.
    - If the new `slot` or `timestamp` is older than the last recorded values, it sets a custom error in the context and returns an error code.
    - If the values are valid, it updates `self->last_timestamp.slot` and `self->last_timestamp.timestamp` with the new values.
    - Finally, it returns 0 to indicate success.
- **Output**: Returns 0 on success, or an error code if the provided timestamp is too old.


---
### set\_vote\_account\_state<!-- {{#callable:set_vote_account_state}} -->
The `set_vote_account_state` function updates the state of a vote account based on the provided vote state and execution context.
- **Inputs**:
    - `vote_account`: A pointer to a `fd_borrowed_account_t` structure representing the vote account to be updated.
    - `vote_state`: A pointer to a `fd_vote_state_t` structure containing the new state information for the vote account.
    - `ctx`: A constant pointer to an `fd_exec_instr_ctx_t` structure that contains execution context and feature set information.
- **Control Flow**:
    - The function first checks if the feature `vote_state_add_vote_latency` is active in the execution context.
    - If the feature is active, it calculates the required size for the new vote state and checks if the current account data length is sufficient.
    - If resizing is needed and the account has enough lamports to cover the rent exemption, it attempts to resize the account data.
    - If resizing fails or is not possible, it converts the current vote state to an older version and sets it as the new state.
    - If the feature is not active, it directly converts the current vote state to an older version and sets it as the new state.
- **Output**: The function returns an integer indicating the success or failure of the operation, with a success value of `FD_EXECUTOR_INSTR_SUCCESS` on successful state update.
- **Functions called**:
    - [`size_of_versioned`](#size_of_versioned)
    - [`from_vote_state_1_14_11`](#from_vote_state_1_14_11)
    - [`set_state`](#set_state)


---
### last\_lockout<!-- {{#callable:last_lockout}} -->
The `last_lockout` function retrieves the lockout information of the most recent vote in a given vote state.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_t` structure representing the current state of the vote.
- **Control Flow**:
    - The function first checks if the `votes` deque in the `fd_vote_state_t` structure is empty using `deq_fd_landed_vote_t_empty`.
    - If the `votes` deque is empty, the function returns `NULL`.
    - If there are votes, it retrieves the last vote using `deq_fd_landed_vote_t_peek_tail`.
    - Finally, it returns a pointer to the `lockout` field of the last vote.
- **Output**: The function returns a pointer to the `fd_vote_lockout_t` structure associated with the last vote, or `NULL` if there are no votes.


---
### last\_voted\_slot<!-- {{#callable:last_voted_slot}} -->
The `last_voted_slot` function retrieves the slot number of the last vote recorded in the given vote state.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_t` structure representing the current state of the vote.
- **Control Flow**:
    - Calls the [`last_lockout`](#last_lockout) function to get the last lockout associated with the vote state.
    - Checks if the last lockout is NULL; if it is, the function returns NULL.
    - If the last lockout is valid, it returns a pointer to the `slot` field of the last lockout.
- **Output**: Returns a pointer to the slot number of the last vote, or NULL if there is no last lockout.
- **Functions called**:
    - [`last_lockout`](#last_lockout)


---
### contains\_slot<!-- {{#callable:contains_slot}} -->
The `contains_slot` function checks if a specific slot exists within a sorted list of votes.
- **Inputs**:
    - `vote_state`: A pointer to a `fd_vote_state_t` structure that contains the current voting state, including a list of votes.
    - `slot`: An unsigned long integer representing the slot number to be checked for existence in the vote state.
- **Control Flow**:
    - The function first retrieves the count of votes in the `vote_state`.
    - If the count is zero, it returns 0, indicating that the slot does not exist.
    - It then enters a loop that performs a binary search to find the position of the slot.
    - The loop continues until the size of the search space is reduced to one or less.
    - Finally, it checks if the slot at the found index matches the input slot and returns 1 if it matches, otherwise returns 0.
- **Output**: Returns 1 if the specified slot exists in the vote state, otherwise returns 0.


---
### check\_and\_filter\_proposed\_vote\_state<!-- {{#callable:check_and_filter_proposed_vote_state}} -->
The `check_and_filter_proposed_vote_state` function validates and filters proposed vote states against existing vote states and slot hashes.
- **Inputs**:
    - `vote_state`: A pointer to the current vote state structure, which contains the existing votes and their lockouts.
    - `proposed_lockouts`: A pointer to the proposed lockouts that need to be validated.
    - `proposed_has_root`: A pointer to a boolean indicating if the proposed state has a root.
    - `proposed_root`: A pointer to the proposed root slot.
    - `proposed_hash`: A pointer to the hash associated with the proposed vote state.
    - `slot_hashes`: A pointer to the structure containing historical slot hashes.
    - `ctx`: A pointer to the execution context that holds transaction-related information.
- **Control Flow**:
    - The function first checks if the proposed lockouts are empty, returning an error if they are.
    - It retrieves the last vote from the current vote state if available.
    - It checks if the proposed lockouts are newer than the last vote's lockout; if not, it sets an error.
    - It verifies that the slot hashes are not empty and retrieves the earliest slot hash.
    - It checks if the proposed vote is too old compared to the earliest slot hash.
    - If a proposed root exists, it checks if it is valid against the historical data.
    - The function iterates through proposed lockouts and slot hashes to validate each proposed vote.
    - It filters out any proposed lockouts that do not match the historical data.
    - Finally, it checks if the proposed lockouts match the expected count and validates the hash.
- **Output**: The function returns an integer indicating success or an error code if validation fails.
- **Functions called**:
    - [`contains_slot`](#contains_slot)


---
### check\_slots\_are\_valid<!-- {{#callable:check_slots_are_valid}} -->
The `check_slots_are_valid` function validates a series of vote slots against the current vote state and slot hashes.
- **Inputs**:
    - `vote_state`: A pointer to the current vote state structure (`fd_vote_state_t`) that contains information about the voting process.
    - `vote_slots`: An array of vote slots (`ulong const *`) that need to be validated.
    - `vote_hash`: A pointer to a hash value (`fd_hash_t const *`) that represents the expected hash for the vote.
    - `slot_hashes`: A pointer to a structure (`fd_slot_hashes_t const *`) containing the historical slot hashes.
    - `ctx`: A pointer to the execution context (`fd_exec_instr_ctx_t const *`) that holds transaction-related information.
- **Control Flow**:
    - The function initializes indices `i` and `j` to track the current position in the `vote_slots` and `slot_hashes` respectively.
    - It enters a loop that continues as long as there are vote slots to check and valid slot hashes.
    - For each vote slot, it checks if it is greater than the last voted slot; if not, it increments `i` and continues.
    - It then checks if the current vote slot matches the corresponding slot hash; if not, it decrements `j` and continues.
    - If a mismatch is found between the expected hash and the provided hash, an error is set in the context and the function returns an error code.
    - Finally, if all checks pass, the function returns 0 indicating success.
- **Output**: The function returns 0 on success, or an error code indicating the type of validation failure, such as mismatched slots or hashes.
- **Functions called**:
    - [`last_voted_slot`](#last_voted_slot)


---
### process\_new\_vote\_state<!-- {{#callable:process_new_vote_state}} -->
Processes a new vote state by validating and updating the current vote state with new votes.
- **Inputs**:
    - `vote_state`: A pointer to the current vote state structure that will be updated.
    - `new_state`: A pointer to the new landed votes that are to be processed.
    - `has_new_root`: An integer indicating whether there is a new root slot.
    - `new_root`: The new root slot number.
    - `has_timestamp`: An integer indicating whether a timestamp is provided.
    - `timestamp`: The timestamp associated with the new vote state.
    - `epoch`: The current epoch number.
    - `current_slot`: The current slot number.
    - `ctx`: A pointer to the execution context containing feature set and transaction context.
- **Control Flow**:
    - The function begins by asserting that the new state is not empty.
    - It checks if the number of new votes exceeds the maximum allowed lockout history, returning an error if so.
    - It validates the new root slot against the current root slot, returning an error if a rollback is detected.
    - The function iterates through each vote in the new state, validating confirmation counts and ensuring proper ordering of slots.
    - It calculates credits earned from newly rooted slots based on whether timely vote credits are active.
    - The function updates the vote state with the new votes and their associated latencies.
    - Finally, it updates the last timestamp if provided and sets the new root slot in the vote state.
- **Output**: Returns FD_EXECUTOR_INSTR_SUCCESS on successful processing, or an error code if any validation fails.
- **Functions called**:
    - [`last_locked_out_slot`](#last_locked_out_slot)
    - [`credits_for_vote_at_index`](#credits_for_vote_at_index)
    - [`compute_vote_latency`](#compute_vote_latency)
    - [`increment_credits`](#increment_credits)
    - [`process_timestamp`](#process_timestamp)


---
### authorize<!-- {{#callable:authorize}} -->
The `authorize` function updates the authorized voter or withdrawer for a voting account based on the provided authorization type.
- **Inputs**:
    - `vote_account`: A pointer to the `fd_borrowed_account_t` structure representing the voting account to be authorized.
    - `authorized`: A pointer to the `fd_pubkey_t` structure containing the public key of the new authorized voter or withdrawer.
    - `vote_authorize`: An `fd_vote_authorize_t` structure indicating whether the authorization is for a voter or a withdrawer.
    - `signers`: An array of pointers to `fd_pubkey_t` structures representing the signers for the transaction.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current clock information.
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure containing the execution context.
- **Control Flow**:
    - The function begins by initializing a return code variable `rc` to 0.
    - It retrieves the current state of the voting account using [`get_state`](#get_state), checking for errors.
    - The state is converted to the current version using [`convert_to_current`](#convert_to_current).
    - A switch statement is used to determine the type of authorization (voter or withdrawer).
    - If the authorization is for a voter, it verifies if the signer is authorized to make this change.
    - It calculates the target epoch for the new authorization and calls [`set_new_authorized_voter`](#set_new_authorized_voter) to update the voter.
    - If the authorization is for a withdrawer, it verifies the signer and updates the authorized withdrawer directly.
    - Finally, it calls [`set_vote_account_state`](#set_vote_account_state) to persist the changes to the voting account.
- **Output**: The function returns an integer indicating the success or failure of the operation, with 0 indicating success.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`convert_to_current`](#convert_to_current)
    - [`verify_authorized_signer`](#verify_authorized_signer)
    - [`set_new_authorized_voter`](#set_new_authorized_voter)
    - [`set_vote_account_state`](#set_vote_account_state)


---
### update\_validator\_identity<!-- {{#callable:update_validator_identity}} -->
Updates the identity of a validator by changing its public key in the vote account.
- **Inputs**:
    - `vote_account`: A pointer to the `fd_borrowed_account_t` structure representing the vote account to be updated.
    - `node_pubkey`: A pointer to the `fd_pubkey_t` structure containing the new public key for the validator.
    - `signers`: An array of pointers to `fd_pubkey_t` structures representing the signers that authorize the update.
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure containing execution context and feature set.
- **Control Flow**:
    - The function initializes a return code variable `rc` to 0.
    - It retrieves the current state of the vote account using [`get_state`](#get_state), checking for errors.
    - If an error occurs, it returns the error code immediately.
    - The function converts the retrieved state to the current version using [`convert_to_current`](#convert_to_current).
    - It verifies if the signers are authorized to make the update by calling [`verify_authorized_signer`](#verify_authorized_signer) for both the withdrawer and the new node public key.
    - If any verification fails, it returns the corresponding error code.
    - The new node public key is assigned to the vote state.
    - Finally, it updates the vote account state by calling [`set_vote_account_state`](#set_vote_account_state) and returns the result.
- **Output**: Returns an integer indicating the success or failure of the operation, with 0 indicating success.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`convert_to_current`](#convert_to_current)
    - [`verify_authorized_signer`](#verify_authorized_signer)
    - [`set_vote_account_state`](#set_vote_account_state)


---
### is\_commission\_update\_allowed<!-- {{#callable:is_commission_update_allowed}} -->
The `is_commission_update_allowed` function checks if a commission update is permitted based on the current slot and epoch schedule.
- **Inputs**:
    - `slot`: The current slot number, which is used to determine the timing of the commission update.
    - `epoch_schedule`: A pointer to a `fd_epoch_schedule_t` structure that contains information about the epoch, including the first normal slot and the number of slots per epoch.
- **Control Flow**:
    - The function first checks if the number of slots per epoch is greater than zero using `FD_LIKELY` for optimization.
    - If the condition is true, it calculates the `relative_slot` by subtracting the `first_normal_slot` from the current `slot` and then takes the modulo with `slots_per_epoch`.
    - It then checks if twice the `relative_slot` is less than or equal to `slots_per_epoch` to determine if the commission update is allowed.
    - If the number of slots per epoch is not greater than zero, the function returns 1, indicating that the update is allowed.
- **Output**: The function returns an integer: 1 if the commission update is allowed, or 0 if it is not allowed.


---
### update\_commission<!-- {{#callable:update_commission}} -->
The `update_commission` function updates the commission rate of a voting account based on specific rules and conditions.
- **Inputs**:
    - `vote_account`: A pointer to the `fd_borrowed_account_t` structure representing the voting account whose commission is to be updated.
    - `commission`: An unsigned character representing the new commission rate to be set for the voting account.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the authorized signers for the transaction.
    - `epoch_schedule`: A pointer to the `fd_epoch_schedule_t` structure containing the epoch schedule information.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current clock information.
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure containing the execution context and feature set.
- **Control Flow**:
    - The function initializes a return code variable `rc` to 0 and declares pointers for the vote state.
    - It checks if the feature allowing commission decrease at any time is active; if so, it retrieves the current state of the vote account.
    - If the commission is being increased, it checks if the commission update is allowed only in the first half of the epoch.
    - If the vote state is not already retrieved, it fetches it again and converts it to the current version.
    - The function verifies if the signer is authorized to make the commission update.
    - If all checks pass, it updates the commission in the vote state and sets the new state back to the vote account.
- **Output**: The function returns an integer indicating the success or failure of the operation, with specific error codes for different failure conditions.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`convert_to_current`](#convert_to_current)
    - [`is_commission_update_allowed`](#is_commission_update_allowed)
    - [`verify_authorized_signer`](#verify_authorized_signer)
    - [`set_vote_account_state`](#set_vote_account_state)


---
### withdraw<!-- {{#callable:withdraw}} -->
The `withdraw` function processes a withdrawal from a vote account, ensuring sufficient funds and proper authorization.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which contains transaction-related information.
    - `vote_account`: A pointer to the borrowed account representing the vote account from which funds are being withdrawn.
    - `lamports`: The amount of lamports to withdraw from the vote account.
    - `to_account_index`: The index of the account to which the withdrawn lamports will be transferred.
    - `signers`: An array of public keys representing the signers authorized to perform the withdrawal.
    - `rent_sysvar`: A pointer to the rent system variable, used to check rent-exempt balance.
    - `clock`: A pointer to the system clock variable, used to obtain the current epoch.
- **Control Flow**:
    - The function begins by initializing a return code variable `rc` to 0.
    - It retrieves the current state of the vote account using [`get_state`](#get_state), checking for errors.
    - The function converts the vote state to the current version if necessary.
    - It verifies that the signer is authorized to withdraw funds from the vote account.
    - It checks if the requested withdrawal amount exceeds the available balance in the vote account.
    - If the remaining balance after withdrawal is zero, it checks if the account can be closed based on recent activity.
    - If the account cannot be closed, it sets a custom error and returns an error code.
    - If the remaining balance is below the minimum rent-exempt balance, it returns an insufficient funds error.
    - The function then subtracts the specified amount of lamports from the vote account.
    - Finally, it adds the withdrawn lamports to the specified account and returns success.
- **Output**: The function returns 0 on success, or an error code indicating the type of failure encountered during the withdrawal process.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`convert_to_current`](#convert_to_current)
    - [`verify_authorized_signer`](#verify_authorized_signer)
    - [`set_vote_account_state`](#set_vote_account_state)


---
### process\_vote\_unfiltered<!-- {{#callable:process_vote_unfiltered}} -->
Processes a set of vote slots by validating them and updating the vote state accordingly.
- **Inputs**:
    - `vote_state`: A pointer to the current state of the vote, represented by `fd_vote_state_t`.
    - `vote_slots`: An array of slots (ulong) that represent the votes being processed.
    - `vote`: A pointer to the vote structure containing the hash and other vote-related data.
    - `slot_hashes`: A pointer to the slot hashes structure that contains the hashes for the slots.
    - `epoch`: The current epoch number (ulong) in which the votes are being processed.
    - `current_slot`: The current slot number (ulong) at which the processing is occurring.
    - `timely_vote_credits`: An integer indicating whether timely vote credits should be awarded.
    - `deprecate_unused_legacy_vote_plumbing`: An integer flag indicating whether to deprecate legacy vote plumbing.
    - `ctx`: A pointer to the execution context (`fd_exec_instr_ctx_t`) for the instruction being processed.
- **Control Flow**:
    - The function first calls [`check_slots_are_valid`](#check_slots_are_valid) to validate the provided vote slots against the current vote state and slot hashes.
    - If the validation fails, the function returns an error code immediately.
    - Next, it iterates over each slot in `vote_slots` using a loop.
    - For each slot, it calls [`process_next_vote_slot`](#process_next_vote_slot), passing the current vote state and the slot along with other parameters.
    - After processing all slots, the function returns 0 indicating success.
- **Output**: Returns 0 on success or an error code if any validation or processing step fails.
- **Functions called**:
    - [`check_slots_are_valid`](#check_slots_are_valid)
    - [`process_next_vote_slot`](#process_next_vote_slot)


---
### process\_vote<!-- {{#callable:process_vote}} -->
The `process_vote` function processes a voting operation by validating and filtering vote slots before delegating the actual processing to another function.
- **Inputs**:
    - `vote_state`: A pointer to the current state of the voting process, represented as `fd_vote_state_t`.
    - `vote`: A pointer to the vote data structure, represented as `fd_vote_t`, containing the slots to be voted on.
    - `slot_hashes`: A pointer to the slot hashes data structure, represented as `fd_slot_hashes_t`, which contains historical slot hashes.
    - `epoch`: An unsigned long integer representing the current epoch in which the vote is being processed.
    - `current_slot`: An unsigned long integer representing the current slot number.
    - `timely_vote_credits`: An integer indicating whether timely vote credits are enabled.
    - `deprecate_unused_legacy_vote_plumbing`: An integer indicating whether to deprecate unused legacy vote plumbing.
    - `ctx`: A pointer to the execution context, represented as `fd_exec_instr_ctx_t`, which contains transaction context and other execution-related data.
- **Control Flow**:
    - The function first checks if the `vote->slots` is empty; if so, it sets a custom error and returns an error code.
    - It retrieves the earliest slot in history from `slot_hashes` if available.
    - It allocates memory for the vote slots and populates it with valid slots that are not older than the earliest slot in history.
    - If no valid vote slots remain after filtering, it sets a custom error and returns an error code.
    - Finally, it calls [`process_vote_unfiltered`](#process_vote_unfiltered) to handle the actual processing of the valid vote slots.
- **Output**: The function returns an integer indicating the success or failure of the vote processing operation, with specific error codes for different failure conditions.
- **Functions called**:
    - [`process_vote_unfiltered`](#process_vote_unfiltered)


---
### initialize\_account<!-- {{#callable:initialize_account}} -->
Initializes a voting account with specified parameters.
- **Inputs**:
    - `vote_account`: A pointer to the `fd_borrowed_account_t` structure representing the vote account to be initialized.
    - `vote_init`: A pointer to the `fd_vote_init_t` structure containing initialization parameters for the vote account.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the authorized signers for the transaction.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current clock information.
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure containing execution context and feature set.
- **Control Flow**:
    - The function retrieves the data length of the `vote_account` and checks if it matches the expected size for the current version.
    - If the data length is incorrect, it returns an error indicating invalid account data.
    - It retrieves the current state of the vote account and checks if it is uninitialized.
    - If the account is already initialized, it returns an error indicating the account is already initialized.
    - The function verifies if the provided signer is authorized to initialize the account.
    - If the signer verification fails, it returns an error.
    - The function resets the vote state object and initializes it with the provided parameters.
    - Finally, it sets the new state of the vote account and returns the result.
- **Output**: Returns an integer indicating the success or failure of the initialization process.
- **Functions called**:
    - [`size_of_versioned`](#size_of_versioned)
    - [`get_state`](#get_state)
    - [`is_uninitialized`](#is_uninitialized)
    - [`verify_authorized_signer`](#verify_authorized_signer)
    - [`vote_state_new`](#vote_state_new)
    - [`set_vote_account_state`](#set_vote_account_state)


---
### verify\_and\_get\_vote\_state<!-- {{#callable:verify_and_get_vote_state}} -->
The `verify_and_get_vote_state` function retrieves and verifies the current vote state of a given vote account.
- **Inputs**:
    - `vote_account`: A pointer to a `fd_borrowed_account_t` structure representing the vote account to be verified.
    - `clock`: A pointer to a `fd_sol_sysvar_clock_t` structure containing the current clock information.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the signers for the transaction.
    - `vote_state`: A pointer to a `fd_vote_state_t` structure where the current vote state will be stored (output parameter).
    - `ctx`: A pointer to a `fd_exec_instr_ctx_t` structure containing the execution context.
- **Control Flow**:
    - The function starts by initializing a return code variable `rc` to 0.
    - It calls [`get_state`](#get_state) to retrieve the current state of the vote account, checking for errors.
    - If the account is uninitialized, it returns an error code indicating the account is uninitialized.
    - The function then converts the retrieved state to the current version using [`convert_to_current`](#convert_to_current).
    - It retrieves the authorized voter for the current epoch using [`get_and_update_authorized_voter`](#get_and_update_authorized_voter), checking for errors.
    - Finally, it verifies that the authorized voter is among the provided signers using [`verify_authorized_signer`](#verify_authorized_signer).
- **Output**: The function returns an integer indicating success (FD_EXECUTOR_INSTR_SUCCESS) or an error code if any checks fail.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`is_uninitialized`](#is_uninitialized)
    - [`convert_to_current`](#convert_to_current)
    - [`get_and_update_authorized_voter`](#get_and_update_authorized_voter)
    - [`verify_authorized_signer`](#verify_authorized_signer)


---
### process\_vote\_with\_account<!-- {{#callable:process_vote_with_account}} -->
Processes a vote with the associated account, updating the vote state and handling timestamps.
- **Inputs**:
    - `vote_account`: A pointer to the `fd_borrowed_account_t` structure representing the account associated with the vote.
    - `slot_hashes`: A pointer to the `fd_slot_hashes_t` structure containing the hashes of the slots.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current clock information.
    - `vote`: A pointer to the `fd_vote_t` structure containing the vote details.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the signers of the transaction.
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure containing the execution context.
- **Control Flow**:
    - The function begins by verifying and retrieving the current vote state using [`verify_and_get_vote_state`](#verify_and_get_vote_state).
    - If the verification fails, it returns the error code immediately.
    - It checks for the activation of features related to timely vote credits and legacy vote plumbing.
    - The function processes the vote using [`process_vote`](#process_vote), which updates the vote state based on the provided vote details.
    - If the vote has a timestamp, it checks if the slots are empty and processes the timestamp accordingly.
    - Finally, it updates the vote account state with the new vote state using [`set_vote_account_state`](#set_vote_account_state).
- **Output**: Returns an integer indicating the success or failure of the operation, with error codes for various failure conditions.
- **Functions called**:
    - [`verify_and_get_vote_state`](#verify_and_get_vote_state)
    - [`process_vote`](#process_vote)
    - [`process_timestamp`](#process_timestamp)
    - [`set_vote_account_state`](#set_vote_account_state)


---
### do\_process\_vote\_state\_update<!-- {{#callable:do_process_vote_state_update}} -->
The `do_process_vote_state_update` function processes updates to the vote state by validating and applying proposed changes.
- **Inputs**:
    - `vote_state`: A pointer to the current vote state structure that is being updated.
    - `slot_hashes`: A pointer to a structure containing slot hashes used for validation.
    - `epoch`: The current epoch number, used to track the voting period.
    - `slot`: The current slot number, indicating the time of the vote.
    - `vote_state_update`: A pointer to a structure containing the proposed updates to the vote state.
    - `ctx`: A pointer to the execution context, which may include feature flags and transaction context.
- **Control Flow**:
    - The function first calls [`check_and_filter_proposed_vote_state`](#check_and_filter_proposed_vote_state) to validate the proposed updates against the current vote state and slot hashes.
    - If the validation fails, the function returns an error code immediately.
    - Memory is allocated for the new landed votes based on the number of lockouts in the proposed update.
    - The function iterates over the proposed lockouts, creating new landed votes and adding them to the allocated memory.
    - Finally, it calls [`process_new_vote_state`](#process_new_vote_state) to apply the validated updates to the current vote state.
- **Output**: The function returns an integer status code indicating success or failure of the operation.
- **Functions called**:
    - [`check_and_filter_proposed_vote_state`](#check_and_filter_proposed_vote_state)
    - [`process_new_vote_state`](#process_new_vote_state)


---
### fd\_query\_pubkey\_stake<!-- {{#callable:fd_query_pubkey_stake}} -->
The `fd_query_pubkey_stake` function retrieves the stake associated with a given public key from a set of vote accounts.
- **Inputs**:
    - `pubkey`: A pointer to a `fd_pubkey_t` structure representing the public key whose stake is to be queried.
    - `vote_accounts`: A pointer to a `fd_vote_accounts_t` structure containing the pool and root of vote accounts.
- **Control Flow**:
    - The function initializes a key structure with the provided public key.
    - It checks if both the vote accounts pool and root are null; if so, it returns 0, indicating no stake.
    - It calls `fd_vote_accounts_pair_t_map_find` to search for the vote account associated with the given public key.
    - If a corresponding vote node is found, it returns the stake; otherwise, it returns 0.
- **Output**: Returns the stake amount as an unsigned long integer, or 0 if the public key is not found in the vote accounts.


---
### process\_vote\_state\_update<!-- {{#callable:process_vote_state_update}} -->
The `process_vote_state_update` function updates the vote state of a given account based on the provided vote state update.
- **Inputs**:
    - `vote_account`: A pointer to the `fd_borrowed_account_t` structure representing the account whose vote state is being updated.
    - `slot_hashes`: A pointer to the `fd_slot_hashes_t` structure containing the hashes of slots.
    - `clock`: A pointer to the `fd_sol_sysvar_clock_t` structure providing the current clock information.
    - `vote_state_update`: A pointer to the `fd_vote_state_update_t` structure containing the new vote state information.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the signers of the transaction.
    - `ctx`: A pointer to the `fd_exec_instr_ctx_t` structure containing execution context and feature set.
- **Control Flow**:
    - The function first checks if the `lockouts` in the `vote_state_update` are not empty.
    - If there are lockouts, it retrieves the last lockout and updates the bank hash comparison structure with the new vote state hash.
    - Next, it verifies and retrieves the current vote state from the `vote_account` using the provided `clock` and `signers`.
    - If the verification is successful, it processes the vote state update by calling [`do_process_vote_state_update`](#do_process_vote_state_update).
    - Finally, it sets the updated vote state back to the `vote_account`.
- **Output**: The function returns an integer indicating the success or failure of the operation, with a non-zero value indicating an error.
- **Functions called**:
    - [`fd_query_pubkey_stake`](#fd_query_pubkey_stake)
    - [`verify_and_get_vote_state`](#verify_and_get_vote_state)
    - [`do_process_vote_state_update`](#do_process_vote_state_update)
    - [`set_vote_account_state`](#set_vote_account_state)


---
### do\_process\_tower\_sync<!-- {{#callable:do_process_tower_sync}} -->
The `do_process_tower_sync` function processes a synchronization request for a voting tower, updating the vote state based on proposed lockouts.
- **Inputs**:
    - `vote_state`: A pointer to the current state of the vote, which will be updated based on the synchronization.
    - `slot_hashes`: A pointer to the slot hashes that represent the history of slots.
    - `epoch`: The current epoch number, used to track the progression of time in the voting process.
    - `slot`: The current slot number, indicating the specific time frame in which the vote is being processed.
    - `tower_sync`: A pointer to the `fd_tower_sync_t` structure containing proposed lockouts and other synchronization data.
    - `ctx`: A pointer to the execution context, which contains information about the current execution environment.
- **Control Flow**:
    - The function first checks and filters the proposed vote state using [`check_and_filter_proposed_vote_state`](#check_and_filter_proposed_vote_state), which validates the proposed lockouts against the current vote state.
    - If the check fails, the function returns an error immediately.
    - If the check passes, it enters a frame for stack allocation using `FD_SPAD_FRAME_BEGIN`.
    - Within this frame, it processes the new vote state by calling [`process_new_vote_state`](#process_new_vote_state), which updates the vote state with the new lockouts and other parameters.
    - Finally, the function returns the result of the processing, which indicates success or failure.
- **Output**: The function returns an integer indicating the success or failure of the operation, with specific error codes for different failure conditions.
- **Functions called**:
    - [`check_and_filter_proposed_vote_state`](#check_and_filter_proposed_vote_state)
    - [`process_new_vote_state`](#process_new_vote_state)
    - [`landed_votes_from_lockouts`](#landed_votes_from_lockouts)


---
### process\_tower\_sync<!-- {{#callable:process_tower_sync}} -->
The `process_tower_sync` function processes synchronization updates for a voting account in a blockchain context.
- **Inputs**:
    - `vote_account`: A pointer to a `fd_borrowed_account_t` structure representing the voting account.
    - `slot_hashes`: A pointer to a constant `fd_slot_hashes_t` structure containing the hashes of slots.
    - `clock`: A pointer to a constant `fd_sol_sysvar_clock_t` structure representing the current clock state.
    - `tower_sync`: A pointer to a `fd_tower_sync_t` structure containing synchronization data.
    - `signers`: An array of pointers to `fd_pubkey_t` representing the signers for the transaction.
    - `ctx`: A pointer to a constant `fd_exec_instr_ctx_t` structure containing execution context.
- **Control Flow**:
    - The function first checks if the `lockouts` in the `tower_sync` structure are not empty.
    - If not empty, it retrieves the last lockout and compares it with the bank hash to ensure synchronization.
    - It then verifies and retrieves the current vote state from the `vote_account` using the provided clock and signers.
    - Next, it processes the synchronization updates by calling [`do_process_tower_sync`](#do_process_tower_sync) with the retrieved vote state.
    - Finally, it updates the vote account state with the new vote state.
- **Output**: Returns an integer indicating success or an error code.
- **Functions called**:
    - [`fd_query_pubkey_stake`](#fd_query_pubkey_stake)
    - [`verify_and_get_vote_state`](#verify_and_get_vote_state)
    - [`do_process_tower_sync`](#do_process_tower_sync)
    - [`set_vote_account_state`](#set_vote_account_state)


---
### fd\_vote\_decode\_compact\_update<!-- {{#callable:fd_vote_decode_compact_update}} -->
Decodes a compact vote state update and applies it to a vote state update structure.
- **Inputs**:
    - `compact_update`: Pointer to a `fd_compact_vote_state_update_t` structure containing the compact representation of the vote state update.
    - `vote_update`: Pointer to a `fd_vote_state_update_t` structure where the decoded vote state update will be stored.
    - `ctx`: Pointer to a `fd_exec_instr_ctx_t` structure representing the execution context.
- **Control Flow**:
    - Check if the `root` field in `compact_update` is not equal to `ULONG_MAX` to determine if a root exists.
    - If a root exists, set `vote_update->has_root` to 1 and assign `vote_update->root` to `compact_update->root`; otherwise, set `vote_update->has_root` to 0 and `vote_update->root` to `ULONG_MAX`.
    - Calculate the length of lockouts and determine the maximum number of lockouts to allocate memory for.
    - Allocate memory for the lockouts in `vote_update` using the provided execution context.
    - Iterate over the lockouts in `compact_update`, creating new lockout entries in `vote_update` and calculating their slots based on offsets.
    - Set the `hash`, `has_timestamp`, and `timestamp` fields in `vote_update` from `compact_update`.
- **Output**: Returns 1 on successful decoding and updating of the vote state; returns 0 if an overflow occurs during slot calculations.


---
### fd\_vote\_record\_timestamp\_vote\_with\_slot<!-- {{#callable:fd_vote_record_timestamp_vote_with_slot}} -->
Records a timestamp vote associated with a specific slot.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot.
    - `vote_acc`: A pointer to the public key of the vote account.
    - `timestamp`: The timestamp to be recorded for the vote.
    - `slot`: The slot number associated with the vote.
- **Control Flow**:
    - Acquire a write lock on the vote stake lock to ensure thread safety.
    - Check if the vote account pool is allocated; log an error if not.
    - Create a `timestamp_vote` structure to hold the vote details.
    - Attempt to find an existing node in the vote pool that matches the new vote.
    - If a matching node is found, update its element with the new vote details.
    - If no matching node is found, acquire a new node from the pool, insert the new vote, and update the root pointer.
    - Release the write lock on the vote stake lock.
- **Output**: The function does not return a value; it modifies the state of the vote account in the context.


---
### fd\_vote\_acc\_credits<!-- {{#callable:fd_vote_acc_credits}} -->
The `fd_vote_acc_credits` function retrieves the total credits accumulated by a specified vote account.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which contains transaction-related information.
    - `vote_acc_meta`: A pointer to metadata associated with the vote account.
    - `vote_acc_data`: A pointer to the raw data of the vote account.
    - `result`: A pointer to a variable where the result (total credits) will be stored.
- **Control Flow**:
    - The function begins by reading the current system clock using `fd_sysvar_clock_read`.
    - If the clock cannot be read, it returns an error indicating unsupported system variable.
    - Next, it initializes a vote account structure from the provided metadata and data.
    - The function then attempts to retrieve the current state of the vote account using [`get_state`](#get_state).
    - If an error occurs while retrieving the state, it returns the error code.
    - The state is converted to the current version using [`convert_to_current`](#convert_to_current).
    - The function checks if the `epoch_credits` deque in the state is empty.
    - If it is empty, it sets the result to 0; otherwise, it retrieves the credits from the last entry in the deque.
- **Output**: The function returns an integer indicating success or failure, and the total credits accumulated by the vote account is stored in the variable pointed to by `result`.
- **Functions called**:
    - [`get_state`](#get_state)
    - [`convert_to_current`](#convert_to_current)


---
### fd\_vote\_commission\_split<!-- {{#callable:fd_vote_commission_split}} -->
The `fd_vote_commission_split` function calculates the distribution of a commission between voters and stakers based on the current vote state.
- **Inputs**:
    - `vote_state_versioned`: A pointer to a `fd_vote_state_versioned_t` structure that contains the current state of the vote.
    - `on`: An unsigned long integer representing the total amount to be split between the voter and the staker.
    - `result`: A pointer to a `fd_commission_split_t` structure where the results of the split will be stored.
- **Control Flow**:
    - The function begins by determining the commission value based on the discriminant of the `vote_state_versioned` structure.
    - It uses a switch statement to access the appropriate commission value depending on the version of the vote state.
    - The commission value is dereferenced and capped at 100 using the `fd_uint_min` function.
    - The function checks if the commission split is 0 or 100 to determine the portions for the voter and staker.
    - If the commission split is neither 0 nor 100, it calculates the portions for the voter and staker based on the commission percentage.
- **Output**: The function outputs the split portions in the `result` structure, indicating whether the commission was split or not.


---
### process\_authorize\_with\_seed\_instruction<!-- {{#callable:process_authorize_with_seed_instruction}} -->
Processes an authorization instruction with a derived key seed for a vote account.
- **Inputs**:
    - `ctx`: A pointer to the execution context containing transaction and instruction details.
    - `vote_account`: A pointer to the account that is being voted on.
    - `new_authority`: A pointer to the public key of the new authority to be set.
    - `authorization_type`: An enumeration indicating the type of authorization (voter or withdrawer).
    - `current_authority_derived_key_owner`: A pointer to the public key of the current authority's derived key owner.
    - `current_authority_derived_key_seed`: A pointer to the seed used to derive the current authority's key.
    - `current_authority_derived_key_seed_len`: The length of the seed used for deriving the current authority's key.
- **Control Flow**:
    - Check if the required system variable account is present; return an error if not.
    - Read the current system clock from the context.
    - Check if the instruction has at least three accounts; return an error if not.
    - If the third account is a signer, retrieve its public key.
    - Create a new public key using the provided seed and base public key.
    - Call the [`authorize`](#authorize) function to update the vote account with the new authority.
- **Output**: Returns an integer indicating the success or failure of the operation.
- **Functions called**:
    - [`authorize`](#authorize)


---
### fd\_vote\_program\_execute<!-- {{#callable:fd_vote_program_execute}} -->
The `fd_vote_program_execute` function processes voting instructions for a Solana-based voting program.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`) which contains information about the current transaction and its associated accounts.
- **Control Flow**:
    - Initializes the compute units for the execution context.
    - Checks if there are enough account keys provided in the instruction context.
    - Attempts to borrow the first account and checks for errors.
    - Validates that the owner of the borrowed account matches the expected program ID.
    - Marks the transaction context's vote account as dirty to indicate changes.
    - Retrieves the signers from the instruction context.
    - Decodes the instruction data into a vote instruction structure.
    - Processes the decoded instruction based on its type using a switch-case structure, handling various vote-related operations such as account initialization, authorization, voting, and state updates.
    - Returns the result code indicating success or failure of the operation.
- **Output**: Returns an integer status code indicating the success or failure of the execution, with specific error codes for various failure conditions.
- **Functions called**:
    - [`initialize_account`](#initialize_account)
    - [`authorize`](#authorize)
    - [`process_authorize_with_seed_instruction`](#process_authorize_with_seed_instruction)
    - [`update_validator_identity`](#update_validator_identity)
    - [`update_commission`](#update_commission)
    - [`process_vote_with_account`](#process_vote_with_account)
    - [`process_vote_state_update`](#process_vote_state_update)
    - [`fd_vote_decode_compact_update`](#fd_vote_decode_compact_update)
    - [`process_tower_sync`](#process_tower_sync)
    - [`withdraw`](#withdraw)


---
### fd\_vote\_state\_versions\_is\_correct\_and\_initialized<!-- {{#callable:fd_vote_state_versions_is_correct_and_initialized}} -->
The `fd_vote_state_versions_is_correct_and_initialized` function checks if a vote account's state is correctly initialized and matches expected version sizes.
- **Inputs**:
    - `vote_account`: A pointer to a `fd_txn_account_t` structure representing the vote account to be checked.
- **Control Flow**:
    - The function first checks if the data length of the vote account matches the size of version 3 of the vote state.
    - It initializes a test data array with zeros and compares the relevant portion of the vote account's data to this test data.
    - If both the data length check and the data comparison indicate that the vote account is correctly initialized for version 3, it returns 1.
    - If not, it checks if the data length matches version 2 of the vote state and performs a similar comparison with a different test data array.
    - Finally, it returns the result of the checks for version 2.
- **Output**: The function returns 1 if the vote account is correctly initialized and matches the expected version size; otherwise, it returns 0.


---
### fd\_vote\_get\_state<!-- {{#callable:fd_vote_get_state}} -->
Retrieves the current state of a voting account.
- **Inputs**:
    - `self`: A pointer to a constant `fd_txn_account_t` structure representing the voting account whose state is to be retrieved.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation during the state retrieval process.
    - `versioned`: A double pointer to a `fd_vote_state_versioned_t` structure where the retrieved state will be stored.
- **Control Flow**:
    - An integer variable `err` is initialized to zero to track any errors during the state retrieval process.
    - The function [`get_state`](#get_state) is called with the provided `self`, `spad`, and a reference to `err` to retrieve the current state of the voting account.
    - The retrieved state is assigned to the `versioned` pointer.
    - The function returns the error code stored in `err`.
- **Output**: Returns an integer indicating the success or failure of the state retrieval operation, with a value of zero indicating success.
- **Functions called**:
    - [`get_state`](#get_state)


---
### fd\_vote\_convert\_to\_current<!-- {{#callable:fd_vote_convert_to_current}} -->
Converts a versioned vote state to the current version.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_versioned_t` structure representing the vote state to be converted.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation during the conversion process.
- **Control Flow**:
    - The function calls [`convert_to_current`](#convert_to_current), passing the `self` and `spad` parameters to perform the actual conversion.
    - The [`convert_to_current`](#convert_to_current) function handles the logic of converting the vote state based on its version.
- **Output**: This function does not return a value; it modifies the `self` parameter in place to represent the current version of the vote state.
- **Functions called**:
    - [`convert_to_current`](#convert_to_current)


---
### remove\_vote\_account<!-- {{#callable:remove_vote_account}} -->
The `remove_vote_account` function removes a specified vote account from the epoch's vote accounts and the slot bank's account keys.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, which contains information about the epoch and the slot bank.
    - `vote_account`: A pointer to the transaction account representing the vote account to be removed.
- **Control Flow**:
    - The function retrieves the epoch bank from the slot context.
    - It checks if the vote accounts pool exists; if not, it logs a debug message and returns.
    - It creates a key for the vote account and attempts to find the corresponding entry in the vote accounts pool.
    - If the entry is found, it removes the vote account from the pool.
    - Next, it checks if the account keys pool exists in the slot bank; if not, it logs a debug message and returns.
    - It creates a key for the account and attempts to find the corresponding entry in the account keys pool.
    - If the entry is found, it removes the account key from the pool.
- **Output**: The function does not return a value; it modifies the state of the vote accounts and account keys pools by removing the specified vote account and its associated key.


---
### upsert\_vote\_account<!-- {{#callable:upsert_vote_account}} -->
The `upsert_vote_account` function updates or inserts a vote account into the appropriate data structures.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, which contains information about the slot bank and epoch.
    - `vote_account`: A pointer to the transaction account representing the vote account to be upserted.
- **Control Flow**:
    - The function first checks if the vote account keys pool exists; if not, it logs a debug message and returns.
    - It retrieves the epoch bank from the execution context.
    - It checks if the vote account is correctly initialized and has the correct version.
    - If the vote account is valid, it creates a key for the account and checks for duplicates in the account keys pool and the epoch's vote accounts.
    - If no duplicates are found, it acquires a new node for the account keys pool and inserts the vote account into the pool.
    - If the vote account is not valid, it calls [`remove_vote_account`](#remove_vote_account) to remove it from the relevant data structures.
- **Output**: The function does not return a value; it modifies the state of the vote account data structures based on the input vote account.
- **Functions called**:
    - [`fd_vote_state_versions_is_correct_and_initialized`](#fd_vote_state_versions_is_correct_and_initialized)
    - [`remove_vote_account`](#remove_vote_account)


---
### fd\_vote\_store\_account<!-- {{#callable:fd_vote_store_account}} -->
Stores or removes a vote account based on its ownership and lamport balance.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution context for the current slot, which includes locks for managing concurrent access.
    - `vote_account`: A pointer to the transaction account representing the vote account to be stored or removed.
- **Control Flow**:
    - Retrieve the owner of the `vote_account` using the `get_owner` method.
    - Check if the owner matches the expected Solana vote program ID; if not, exit the function.
    - Acquire a write lock on the `vote_stake_lock` to ensure thread safety during modifications.
    - Check the lamport balance of the `vote_account` using the `get_lamports` method.
    - If the balance is zero, call [`remove_vote_account`](#remove_vote_account) to remove the account from the context.
    - If the balance is non-zero, call [`upsert_vote_account`](#upsert_vote_account) to update or insert the account into the context.
    - Release the write lock on the `vote_stake_lock`.
- **Output**: The function does not return a value; it modifies the state of the vote account in the provided execution context.
- **Functions called**:
    - [`remove_vote_account`](#remove_vote_account)
    - [`upsert_vote_account`](#upsert_vote_account)


# Function Declarations (Public API)

---
### last\_voted\_slot<!-- {{#callable_declaration:last_voted_slot}} -->
Retrieve the last voted slot from the vote state.
- **Description**: Use this function to obtain a pointer to the last slot that was voted on in the given vote state. This function is useful when you need to check or update the last voted slot in a voting process. It should be called with a valid vote state object. If there are no votes recorded, the function will return NULL, indicating that no slot has been voted on yet.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_t` structure representing the vote state. This parameter must not be null, and it should point to a properly initialized vote state object. If the vote state has no recorded votes, the function will return NULL.
- **Output**: Returns a pointer to the last voted slot as an `ulong`, or NULL if no votes are recorded.
- **See also**: [`last_voted_slot`](#last_voted_slot)  (Implementation)


