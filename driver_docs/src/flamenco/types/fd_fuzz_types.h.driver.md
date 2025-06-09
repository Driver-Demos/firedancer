# Purpose
This C source file is an auto-generated implementation that provides a comprehensive set of functions for generating various data structures related to a blockchain or distributed ledger system, likely inspired by Solana. The file includes a wide array of functions, each responsible for generating a specific type of data structure, such as transactions, accounts, votes, and various system states. These functions utilize random number generation to populate the fields of these structures, which suggests that the code is intended for use in fuzz testing or simulation environments where random data is needed to test the robustness and behavior of the system under various conditions.

The file is structured to include a series of functions that create and initialize different types of data structures, such as [`fd_flamenco_txn_generate`](#fd_flamenco_txn_generate), [`fd_hash_generate`](#fd_hash_generate), and [`fd_pubkey_generate`](#fd_pubkey_generate), among many others. Each function takes pointers to memory and allocation pointers, along with a random number generator, to fill the structures with random data. The code also includes several switch-case constructs to handle different variants of structures, indicating a polymorphic design where structures can have multiple forms. This file does not define public APIs or external interfaces directly but rather serves as a backend utility for generating test data, likely to be used in conjunction with other components of a larger system.
# Imports and Dependencies

---
- `fd_types.h`
- `fd_types_custom.h`


# Functions

---
### fd\_flamenco\_txn\_generate<!-- {{#callable:fd_flamenco_txn_generate}} -->
Generates a new `fd_flamenco_txn_t` transaction structure with randomized data.
- **Inputs**:
    - `mem`: A pointer to a memory location where the transaction structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_flamenco_txn_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_flamenco_txn_t` structure.
    - The `fd_flamenco_txn_new` function is called to initialize the transaction structure.
    - The [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) function is called to mutate the `txn_buf` field of the transaction with random data.
    - A random size for the `raw` field is generated using the `fd_rng_ulong` function, constrained by `FD_TXN_MTU`.
    - The [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) function is called again to mutate the `raw` field with the generated size.
- **Output**: Returns a pointer to the initialized `fd_flamenco_txn_t` structure.
- **Functions called**:
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_hash\_generate<!-- {{#callable:fd_hash_generate}} -->
Generates a new hash value and mutates the memory associated with it.
- **Inputs**:
    - `mem`: A pointer to the memory location where the hash will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the allocated memory for the hash.
    - `rng`: A pointer to a random number generator used for mutating the hash.
- **Control Flow**:
    - The function first updates the `alloc_mem` pointer to allocate space for a new `fd_hash_t` structure.
    - It then calls the [`fd_hash_new`](fd_types.h.driver.md#fd_hash_new) function to initialize the hash structure at the provided memory location.
    - Next, it uses the [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) function to mutate the memory of the hash structure, applying random changes to it.
    - Finally, the function returns the pointer to the memory where the hash was generated.
- **Output**: Returns a pointer to the memory location containing the generated hash.
- **Functions called**:
    - [`fd_hash_new`](fd_types.h.driver.md#fd_hash_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_pubkey\_generate<!-- {{#callable:fd_pubkey_generate}} -->
Generates a public key by allocating memory and mutating it using a random number generator.
- **Inputs**:
    - `mem`: A pointer to the memory location where the public key will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the newly allocated memory for the public key.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function first updates the `alloc_mem` pointer to allocate enough space for a new `fd_pubkey_t` structure.
    - It then calls the `fd_pubkey_new` function to initialize the public key in the provided memory.
    - Next, it uses the [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) function to mutate the memory allocated for the public key, introducing randomness.
    - Finally, the function returns the pointer to the memory where the public key has been generated.
- **Output**: Returns a pointer to the memory location containing the generated public key.
- **Functions called**:
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_signature\_generate<!-- {{#callable:fd_signature_generate}} -->
Generates a new `fd_signature_t` structure and mutates its memory.
- **Inputs**:
    - `mem`: A pointer to the memory location where the new signature will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for mutating the signature.
- **Control Flow**:
    - The function first updates the `alloc_mem` pointer to allocate space for a new `fd_signature_t` structure.
    - It then calls the [`fd_signature_new`](fd_types.h.driver.md#fd_signature_new) function to initialize the signature structure at the provided memory location.
    - Next, it uses the [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) function to randomly mutate the contents of the memory allocated for the signature.
    - Finally, the function returns the pointer to the memory location containing the generated signature.
- **Output**: Returns a pointer to the memory location containing the generated and mutated `fd_signature_t` structure.
- **Functions called**:
    - [`fd_signature_new`](fd_types.h.driver.md#fd_signature_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_gossip\_ip4\_addr\_generate<!-- {{#callable:fd_gossip_ip4_addr_generate}} -->
Generates a new IPv4 address for gossip communication.
- **Inputs**:
    - `mem`: A pointer to the memory location where the new IPv4 address will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for mutating the generated address.
- **Control Flow**:
    - The function first updates the `alloc_mem` pointer to allocate space for a new `fd_gossip_ip4_addr_t` structure.
    - It then calls the [`fd_gossip_ip4_addr_new`](fd_types.h.driver.md#fd_gossip_ip4_addr_new) function to initialize the new IPv4 address in the provided memory.
    - Next, it uses the [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) function to mutate the memory containing the new IPv4 address, allowing for fuzz testing.
    - Finally, the function returns the pointer to the memory containing the generated IPv4 address.
- **Output**: Returns a pointer to the memory location containing the newly generated IPv4 address.
- **Functions called**:
    - [`fd_gossip_ip4_addr_new`](fd_types.h.driver.md#fd_gossip_ip4_addr_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_gossip\_ip6\_addr\_generate<!-- {{#callable:fd_gossip_ip6_addr_generate}} -->
Generates a new IPv6 gossip address and mutates its data.
- **Inputs**:
    - `mem`: A pointer to the memory location where the new IPv6 address will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for mutating the address data.
- **Control Flow**:
    - The function first updates the `alloc_mem` pointer to allocate space for a new `fd_gossip_ip6_addr_t` structure.
    - It then calls `fd_gossip_ip6_addr_new(mem)` to initialize the new IPv6 address in the provided memory.
    - Next, it uses [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) to randomly mutate the data of the newly created IPv6 address.
    - Finally, the function returns the pointer to the memory where the IPv6 address was generated.
- **Output**: Returns a pointer to the memory location containing the generated and mutated IPv6 gossip address.
- **Functions called**:
    - [`fd_gossip_ip6_addr_new`](fd_types.h.driver.md#fd_gossip_ip6_addr_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_feature\_generate<!-- {{#callable:fd_feature_generate}} -->
Generates a new `fd_feature_t` structure with randomized activation properties.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_feature_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_feature_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_feature_t` structure.
    - The [`fd_feature_new`](fd_types.c.driver.md#fd_feature_new) function is called to initialize the `fd_feature_t` structure.
    - A random value is generated to determine if `has_activated_at` is set to true or false.
    - If `has_activated_at` is true, the [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) function is called to mutate the `activated_at` field.
- **Output**: Returns a pointer to the initialized `fd_feature_t` structure.
- **Functions called**:
    - [`fd_feature_new`](fd_types.c.driver.md#fd_feature_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_fee\_calculator\_generate<!-- {{#callable:fd_fee_calculator_generate}} -->
Generates a new `fd_fee_calculator_t` structure and initializes its fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_fee_calculator_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_fee_calculator_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_fee_calculator_t` structure.
    - The function calls `fd_fee_calculator_new(mem)` to initialize the new fee calculator structure.
    - It generates a random value for `lamports_per_signature` using `fd_rng_ulong(rng)` and assigns it to `self->lamports_per_signature`.
- **Output**: Returns a pointer to the initialized `fd_fee_calculator_t` structure.
- **Functions called**:
    - [`fd_fee_calculator_new`](fd_types.h.driver.md#fd_fee_calculator_new)


---
### fd\_hash\_age\_generate<!-- {{#callable:fd_hash_age_generate}} -->
Generates a new `fd_hash_age_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_hash_age_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure's fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_hash_age_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_hash_age_t` structure.
    - It calls [`fd_hash_age_new`](fd_types.h.driver.md#fd_hash_age_new) to initialize the `fd_hash_age_t` structure.
    - It generates a new `fd_fee_calculator` for the `fee_calculator` field of the structure.
    - It assigns a random value to the `hash_index` field using `fd_rng_ulong`.
    - It assigns a random value to the `timestamp` field using `fd_rng_ulong`.
    - Finally, it returns the pointer to the initialized `fd_hash_age_t` structure.
- **Output**: Returns a pointer to the initialized `fd_hash_age_t` structure.
- **Functions called**:
    - [`fd_hash_age_new`](fd_types.h.driver.md#fd_hash_age_new)
    - [`fd_fee_calculator_generate`](#fd_fee_calculator_generate)


---
### fd\_hash\_hash\_age\_pair\_generate<!-- {{#callable:fd_hash_hash_age_pair_generate}} -->
Generates a new `fd_hash_hash_age_pair_t` structure with a key and value.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_hash_hash_age_pair_t` structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_hash_hash_age_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_hash_hash_age_pair_t` structure.
    - It calls [`fd_hash_hash_age_pair_new`](fd_types.h.driver.md#fd_hash_hash_age_pair_new) to initialize the new structure.
    - It generates a new hash for the `key` field of the structure by calling [`fd_hash_generate`](#fd_hash_generate).
    - It generates a new age for the `val` field of the structure by calling [`fd_hash_age_generate`](#fd_hash_age_generate).
    - Finally, it returns the pointer to the `fd_hash_hash_age_pair_t` structure.
- **Output**: Returns a pointer to the initialized `fd_hash_hash_age_pair_t` structure.
- **Functions called**:
    - [`fd_hash_hash_age_pair_new`](fd_types.h.driver.md#fd_hash_hash_age_pair_new)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_hash_age_generate`](#fd_hash_age_generate)


---
### fd\_block\_hash\_vec\_generate<!-- {{#callable:fd_block_hash_vec_generate}} -->
Generates a new `fd_block_hash_vec_t` structure, initializing its fields and allocating memory for its components based on random values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_block_hash_vec_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for initializing the fields.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_block_hash_vec_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_block_hash_vec_t` structure.
    - The [`fd_block_hash_vec_new`](fd_types.c.driver.md#fd_block_hash_vec_new) function is called to initialize the structure.
    - A random index for the last hash is generated using `fd_rng_ulong`.
    - A random value is generated to determine if the last hash should be null or allocated.
    - If not null, memory is allocated for the last hash and initialized using [`fd_hash_new`](fd_types.h.driver.md#fd_hash_new) and [`fd_hash_generate`](#fd_hash_generate).
    - A random length for the ages array is generated, and if greater than zero, memory is allocated for it.
    - A loop iterates over the length of ages, initializing each age using [`fd_hash_hash_age_pair_new`](fd_types.h.driver.md#fd_hash_hash_age_pair_new) and [`fd_hash_hash_age_pair_generate`](#fd_hash_hash_age_pair_generate).
    - Finally, a random maximum age is generated and assigned to the structure.
- **Output**: Returns a pointer to the initialized `fd_block_hash_vec_t` structure.
- **Functions called**:
    - [`fd_block_hash_vec_new`](fd_types.c.driver.md#fd_block_hash_vec_new)
    - [`fd_hash_new`](fd_types.h.driver.md#fd_hash_new)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_hash_hash_age_pair_new`](fd_types.h.driver.md#fd_hash_hash_age_pair_new)
    - [`fd_hash_hash_age_pair_generate`](#fd_hash_hash_age_pair_generate)


---
### fd\_block\_hash\_queue\_generate<!-- {{#callable:fd_block_hash_queue_generate}} -->
Generates a new `fd_block_hash_queue_t` structure with randomized properties.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_block_hash_queue_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_block_hash_queue_t` type and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_block_hash_queue_t` structure.
    - A new block hash queue is created using [`fd_block_hash_queue_new`](fd_types.c.driver.md#fd_block_hash_queue_new).
    - A random index for the last hash is generated using `fd_rng_ulong`.
    - A random value is generated to determine if the last hash should be null or allocated.
    - If the last hash is not null, memory is allocated for it, and a new hash is generated and populated.
    - A random length for the ages pool is generated, and a new ages pool is created.
    - For each age in the pool, a new node is acquired, generated, and inserted into the ages root.
    - Finally, a random maximum age is generated and assigned.
- **Output**: Returns a pointer to the initialized `fd_block_hash_queue_t` structure.
- **Functions called**:
    - [`fd_block_hash_queue_new`](fd_types.c.driver.md#fd_block_hash_queue_new)
    - [`fd_hash_new`](fd_types.h.driver.md#fd_hash_new)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_hash_hash_age_pair_t_map_join_new`](fd_types.h.driver.md#fd_hash_hash_age_pair_t_map_join_new)
    - [`fd_hash_hash_age_pair_generate`](#fd_hash_hash_age_pair_generate)


---
### fd\_fee\_rate\_governor\_generate<!-- {{#callable:fd_fee_rate_governor_generate}} -->
Generates a new `fd_fee_rate_governor_t` structure with randomized fee rate parameters.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_fee_rate_governor_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for the fee rate parameters.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_fee_rate_governor_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate enough space for a new `fd_fee_rate_governor_t` structure.
    - The function calls `fd_fee_rate_governor_new(mem)` to initialize the structure.
    - Random values are generated for `target_lamports_per_signature`, `target_signatures_per_slot`, `min_lamports_per_signature`, `max_lamports_per_signature`, and `burn_percent` using the `rng` pointer.
    - Finally, the function returns the pointer to the initialized `fd_fee_rate_governor_t` structure.
- **Output**: Returns a pointer to the initialized `fd_fee_rate_governor_t` structure.
- **Functions called**:
    - [`fd_fee_rate_governor_new`](fd_types.h.driver.md#fd_fee_rate_governor_new)


---
### fd\_slot\_pair\_generate<!-- {{#callable:fd_slot_pair_generate}} -->
Generates a new `fd_slot_pair_t` structure with random slot and value.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_slot_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the slot and value.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_slot_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_slot_pair_t` structure.
    - The function calls `fd_slot_pair_new(mem)` to initialize the new structure.
    - It generates a random value for `self->slot` using `fd_rng_ulong(rng)`.
    - It generates a random value for `self->val` using `fd_rng_ulong(rng)`.
    - Finally, it returns the pointer to the allocated memory.
- **Output**: Returns a pointer to the allocated `fd_slot_pair_t` structure with initialized slot and value.
- **Functions called**:
    - [`fd_slot_pair_new`](fd_types.h.driver.md#fd_slot_pair_new)


---
### fd\_hard\_forks\_generate<!-- {{#callable:fd_hard_forks_generate}} -->
Generates hard fork data structures and initializes them based on random values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_hard_forks_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_hard_forks_t` structure and initializes it.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_hard_forks_t` structure.
    - It calls [`fd_hard_forks_new`](fd_types.c.driver.md#fd_hard_forks_new) to initialize the hard forks structure.
    - It generates a random length for the hard forks (up to 7) using the random number generator.
    - If the generated length is greater than zero, it allocates memory for the hard forks array and updates `alloc_mem` accordingly.
    - A loop iterates over the number of hard forks, calling [`fd_slot_pair_new`](fd_types.h.driver.md#fd_slot_pair_new) and [`fd_slot_pair_generate`](#fd_slot_pair_generate) for each fork to initialize and populate them.
    - If the generated length is zero, it sets the hard forks pointer to NULL.
- **Output**: Returns a pointer to the initialized `fd_hard_forks_t` structure.
- **Functions called**:
    - [`fd_hard_forks_new`](fd_types.c.driver.md#fd_hard_forks_new)
    - [`fd_slot_pair_new`](fd_types.h.driver.md#fd_slot_pair_new)
    - [`fd_slot_pair_generate`](#fd_slot_pair_generate)


---
### fd\_inflation\_generate<!-- {{#callable:fd_inflation_generate}} -->
Generates a new `fd_inflation_t` structure with random values for its properties.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_inflation_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_inflation_t` type.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_inflation_t` structure.
    - The function calls `fd_inflation_new(mem)` to initialize the structure.
    - It generates random values for the `initial`, `terminal`, `taper`, `foundation`, `foundation_term`, and `unused` properties using the `fd_rng_double_o` function.
- **Output**: Returns a pointer to the initialized `fd_inflation_t` structure.
- **Functions called**:
    - [`fd_inflation_new`](fd_types.h.driver.md#fd_inflation_new)


---
### fd\_rent\_generate<!-- {{#callable:fd_rent_generate}} -->
Generates a `fd_rent_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_rent_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_rent_t` structure type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_rent_t` structure.
    - The function calls [`fd_rent_new`](fd_types.h.driver.md#fd_rent_new) to initialize the `fd_rent_t` structure.
    - Random values are generated for the `lamports_per_uint8_year`, `exemption_threshold`, and `burn_percent` fields using the provided random number generator.
- **Output**: Returns a pointer to the initialized `fd_rent_t` structure.
- **Functions called**:
    - [`fd_rent_new`](fd_types.h.driver.md#fd_rent_new)


---
### fd\_epoch\_schedule\_generate<!-- {{#callable:fd_epoch_schedule_generate}} -->
Generates a new `fd_epoch_schedule_t` structure with randomized parameters.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_epoch_schedule_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for the schedule parameters.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_epoch_schedule_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_epoch_schedule_t` structure.
    - The function calls [`fd_epoch_schedule_new`](fd_types.c.driver.md#fd_epoch_schedule_new) to initialize the structure.
    - Random values are generated for `slots_per_epoch`, `leader_schedule_slot_offset`, `warmup`, `first_normal_epoch`, and `first_normal_slot` using the provided random number generator.
- **Output**: Returns a pointer to the initialized `fd_epoch_schedule_t` structure.
- **Functions called**:
    - [`fd_epoch_schedule_new`](fd_types.c.driver.md#fd_epoch_schedule_new)


---
### fd\_rent\_collector\_generate<!-- {{#callable:fd_rent_collector_generate}} -->
Generates a new `fd_rent_collector_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_rent_collector_t` structure will be initialized.
    - `alloc_mem`: A double pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_rent_collector_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_rent_collector_t` structure.
    - The [`fd_rent_collector_new`](fd_types.c.driver.md#fd_rent_collector_new) function is called to initialize the `fd_rent_collector_t` structure.
    - A random epoch value is generated using `fd_rng_ulong` and assigned to `self->epoch`.
    - The [`fd_epoch_schedule_generate`](#fd_epoch_schedule_generate) function is called to initialize the epoch schedule, passing the updated `alloc_mem` and `rng`.
    - A random value for slots per year is generated and assigned to `self->slots_per_year`.
    - The [`fd_rent_generate`](#fd_rent_generate) function is called to initialize the rent structure, passing the updated `alloc_mem` and `rng`.
- **Output**: Returns a pointer to the initialized `fd_rent_collector_t` structure.
- **Functions called**:
    - [`fd_rent_collector_new`](fd_types.c.driver.md#fd_rent_collector_new)
    - [`fd_epoch_schedule_generate`](#fd_epoch_schedule_generate)
    - [`fd_rent_generate`](#fd_rent_generate)


---
### fd\_stake\_history\_entry\_generate<!-- {{#callable:fd_stake_history_entry_generate}} -->
Generates a new `fd_stake_history_entry_t` structure with random values for effective, activating, and deactivating fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_stake_history_entry_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_history_entry_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_history_entry_t` structure.
    - It calls `fd_stake_history_entry_new(mem)` to initialize the new stake history entry.
    - It generates random values for the `effective`, `activating`, and `deactivating` fields of the `self` structure using the `fd_rng_ulong(rng)` function.
    - Finally, it returns the pointer to the initialized `fd_stake_history_entry_t` structure.
- **Output**: Returns a pointer to the initialized `fd_stake_history_entry_t` structure.
- **Functions called**:
    - [`fd_stake_history_entry_new`](fd_types.h.driver.md#fd_stake_history_entry_new)


---
### fd\_epoch\_stake\_history\_entry\_pair\_generate<!-- {{#callable:fd_epoch_stake_history_entry_pair_generate}} -->
Generates a new `fd_epoch_stake_history_entry_pair_t` structure with a random epoch and a generated stake history entry.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_epoch_stake_history_entry_pair_t` structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_epoch_stake_history_entry_pair_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_epoch_stake_history_entry_pair_t` structure.
    - It calls [`fd_epoch_stake_history_entry_pair_new`](fd_types.h.driver.md#fd_epoch_stake_history_entry_pair_new) to initialize the new structure.
    - It generates a random epoch value using `fd_rng_ulong` and assigns it to the `epoch` field of the structure.
    - It calls [`fd_stake_history_entry_generate`](#fd_stake_history_entry_generate) to generate a new stake history entry and assigns it to the `entry` field.
- **Output**: Returns a pointer to the memory location containing the newly generated `fd_epoch_stake_history_entry_pair_t` structure.
- **Functions called**:
    - [`fd_epoch_stake_history_entry_pair_new`](fd_types.h.driver.md#fd_epoch_stake_history_entry_pair_new)
    - [`fd_stake_history_entry_generate`](#fd_stake_history_entry_generate)


---
### fd\_stake\_history\_generate<!-- {{#callable:fd_stake_history_generate}} -->
Generates a stake history structure with a random number of epoch stake history entries.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_history_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_history_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_stake_history_t` structure.
    - It calls [`fd_stake_history_new`](fd_types.c.driver.md#fd_stake_history_new) to initialize the stake history structure.
    - It generates a random length for the stake history entries (up to 7) using the random number generator.
    - It sets the size of the stake history to 512 and initializes the offset to 0.
    - It enters a loop to generate the specified number of epoch stake history entry pairs by calling [`fd_epoch_stake_history_entry_pair_generate`](#fd_epoch_stake_history_entry_pair_generate) for each entry.
- **Output**: Returns a pointer to the initialized `fd_stake_history_t` structure.
- **Functions called**:
    - [`fd_stake_history_new`](fd_types.c.driver.md#fd_stake_history_new)
    - [`fd_epoch_stake_history_entry_pair_generate`](#fd_epoch_stake_history_entry_pair_generate)


---
### fd\_solana\_account\_generate<!-- {{#callable:fd_solana_account_generate}} -->
Generates a new Solana account with random attributes.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_solana_account_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_solana_account_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_solana_account_t` structure.
    - It initializes the account using `fd_solana_account_new(mem)`.
    - It generates a random number of lamports for the account using `fd_rng_ulong(rng)`.
    - It generates a random data length (up to 7) and allocates memory for the data if the length is greater than zero.
    - If data length is greater than zero, it fills the data array with random values.
    - It generates a public key for the account owner using `fd_pubkey_generate(&self->owner, alloc_mem, rng)`.
    - It sets the executable flag and rent epoch using random values.
- **Output**: Returns a pointer to the initialized `fd_solana_account_t` structure.
- **Functions called**:
    - [`fd_solana_account_new`](fd_types.c.driver.md#fd_solana_account_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_vote\_accounts\_pair\_generate<!-- {{#callable:fd_vote_accounts_pair_generate}} -->
Generates a new `fd_vote_accounts_pair_t` structure with a public key and associated stake.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_accounts_pair_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_accounts_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_vote_accounts_pair_t` structure.
    - It calls `fd_vote_accounts_pair_new(mem)` to initialize the structure.
    - It generates a new public key for `self->key` by calling `fd_pubkey_generate()`.
    - It assigns a random stake value to `self->stake` using `fd_rng_ulong(rng)`.
    - It generates a new `fd_solana_account_t` for `self->value` by calling `fd_solana_account_generate()`.
    - Finally, it returns the pointer to the initialized `fd_vote_accounts_pair_t` structure.
- **Output**: Returns a pointer to the initialized `fd_vote_accounts_pair_t` structure.
- **Functions called**:
    - [`fd_vote_accounts_pair_new`](fd_types.c.driver.md#fd_vote_accounts_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_solana_account_generate`](#fd_solana_account_generate)


---
### fd\_vote\_accounts\_generate<!-- {{#callable:fd_vote_accounts_generate}} -->
Generates a set of vote accounts with random properties.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_accounts_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_accounts_t` structure and initializes it.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_vote_accounts_t` structure.
    - A random length for the vote accounts is generated, constrained to a maximum of 8.
    - A new vote accounts pool is created using [`fd_vote_accounts_pair_t_map_join_new`](fd_types.h.driver.md#fd_vote_accounts_pair_t_map_join_new) with a minimum size of 15000.
    - A loop iterates over the generated length of vote accounts, acquiring nodes from the pool and generating vote account pairs.
    - Each generated vote account pair is inserted into the vote accounts pool.
- **Output**: Returns a pointer to the initialized `fd_vote_accounts_t` structure.
- **Functions called**:
    - [`fd_vote_accounts_new`](fd_types.c.driver.md#fd_vote_accounts_new)
    - [`fd_vote_accounts_pair_t_map_join_new`](fd_types.h.driver.md#fd_vote_accounts_pair_t_map_join_new)
    - [`fd_vote_accounts_pair_generate`](#fd_vote_accounts_pair_generate)


---
### fd\_account\_keys\_pair\_generate<!-- {{#callable:fd_account_keys_pair_generate}} -->
Generates a new account keys pair with a public key and existence flag.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_account_keys_pair_t` structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_account_keys_pair_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_account_keys_pair_t` structure.
    - It calls [`fd_account_keys_pair_new`](fd_types.h.driver.md#fd_account_keys_pair_new) to initialize the new account keys pair.
    - It generates a public key using [`fd_pubkey_generate`](#fd_pubkey_generate) and assigns it to the `key` field of the structure.
    - It generates a random existence flag (0 or 1) using `fd_rng_uchar` and assigns it to the `exists` field.
- **Output**: Returns a pointer to the memory location containing the generated `fd_account_keys_pair_t` structure.
- **Functions called**:
    - [`fd_account_keys_pair_new`](fd_types.h.driver.md#fd_account_keys_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_account\_keys\_generate<!-- {{#callable:fd_account_keys_generate}} -->
Generates account keys for a given account.
- **Inputs**:
    - `mem`: A pointer to a memory location where the account keys structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for account keys.
- **Control Flow**:
    - The function casts the input memory pointer to an `fd_account_keys_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_account_keys_t` structure.
    - It initializes the account keys structure by calling [`fd_account_keys_new`](fd_types.c.driver.md#fd_account_keys_new).
    - It generates a random length for the account keys pool, ensuring it is at least 100000.
    - It creates a new account keys pool using [`fd_account_keys_pair_t_map_join_new`](fd_types.h.driver.md#fd_account_keys_pair_t_map_join_new).
    - It initializes the root of the account keys pool to NULL.
    - It enters a loop to generate a number of account keys based on the random length, acquiring nodes from the pool, generating account key pairs, and inserting them into the pool.
- **Output**: Returns a pointer to the initialized memory containing the account keys structure.
- **Functions called**:
    - [`fd_account_keys_new`](fd_types.c.driver.md#fd_account_keys_new)
    - [`fd_account_keys_pair_t_map_join_new`](fd_types.h.driver.md#fd_account_keys_pair_t_map_join_new)
    - [`fd_account_keys_pair_generate`](#fd_account_keys_pair_generate)


---
### fd\_stake\_weight\_generate<!-- {{#callable:fd_stake_weight_generate}} -->
Generates a new `fd_stake_weight_t` structure with a public key and a randomly assigned stake value.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_stake_weight_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_weight_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_weight_t` structure.
    - The function calls `fd_stake_weight_new(mem)` to initialize the `fd_stake_weight_t` structure.
    - It generates a new public key by calling `fd_pubkey_generate(&self->key, alloc_mem, rng)`.
    - A random stake value is assigned to `self->stake` using `fd_rng_ulong(rng)`.
- **Output**: Returns a pointer to the initialized `fd_stake_weight_t` structure.
- **Functions called**:
    - [`fd_stake_weight_new`](fd_types.h.driver.md#fd_stake_weight_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_stake\_weights\_generate<!-- {{#callable:fd_stake_weights_generate}} -->
Generates stake weights for a given memory allocation.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_weights_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for stake weights.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_stake_weights_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_weights_t` structure.
    - The [`fd_stake_weights_new`](fd_types.c.driver.md#fd_stake_weights_new) function is called to initialize the structure.
    - A random length for the stake weights is generated using the `fd_rng_ulong` function, limited to a maximum of 8.
    - A new stake weights pool is created using [`fd_stake_weight_t_map_join_new`](fd_types.h.driver.md#fd_stake_weight_t_map_join_new) with the generated length.
    - A loop iterates over the generated length, acquiring nodes from the stake weights pool and generating individual stake weights using [`fd_stake_weight_generate`](#fd_stake_weight_generate).
    - Each generated stake weight node is inserted into the stake weights pool.
- **Output**: Returns a pointer to the initialized `fd_stake_weights_t` structure.
- **Functions called**:
    - [`fd_stake_weights_new`](fd_types.c.driver.md#fd_stake_weights_new)
    - [`fd_stake_weight_t_map_join_new`](fd_types.h.driver.md#fd_stake_weight_t_map_join_new)
    - [`fd_stake_weight_generate`](#fd_stake_weight_generate)


---
### fd\_delegation\_generate<!-- {{#callable:fd_delegation_generate}} -->
Generates a new `fd_delegation_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_delegation_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_delegation_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_delegation_t` structure.
    - The function calls `fd_delegation_new(mem)` to initialize the `fd_delegation_t` structure.
    - It generates a new public key for the `voter_pubkey` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - Random values for `stake`, `activation_epoch`, `deactivation_epoch`, and `warmup_cooldown_rate` are generated using the random number generator.
- **Output**: Returns a pointer to the initialized `fd_delegation_t` structure.
- **Functions called**:
    - [`fd_delegation_new`](fd_types.h.driver.md#fd_delegation_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_delegation\_pair\_generate<!-- {{#callable:fd_delegation_pair_generate}} -->
Generates a new `fd_delegation_pair_t` structure with initialized account and delegation fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_delegation_pair_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_delegation_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_delegation_pair_t` structure.
    - It calls [`fd_delegation_pair_new`](fd_types.h.driver.md#fd_delegation_pair_new) to initialize the `fd_delegation_pair_t` structure.
    - It generates a public key for the `account` field of `self` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates a delegation structure for the `delegation` field of `self` using [`fd_delegation_generate`](#fd_delegation_generate).
    - Finally, it returns the pointer to the initialized `fd_delegation_pair_t` structure.
- **Output**: Returns a pointer to the initialized `fd_delegation_pair_t` structure.
- **Functions called**:
    - [`fd_delegation_pair_new`](fd_types.h.driver.md#fd_delegation_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_delegation_generate`](#fd_delegation_generate)


---
### fd\_stake\_generate<!-- {{#callable:fd_stake_generate}} -->
Generates a new `fd_stake_t` structure with initialized delegation and observed credits.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_t` structure.
    - It calls [`fd_stake_new`](fd_types.h.driver.md#fd_stake_new) to initialize the `fd_stake_t` structure.
    - It generates a new delegation for the stake by calling [`fd_delegation_generate`](#fd_delegation_generate).
    - It assigns a random value to `credits_observed` using `fd_rng_ulong`.
- **Output**: Returns a pointer to the initialized `fd_stake_t` structure.
- **Functions called**:
    - [`fd_stake_new`](fd_types.h.driver.md#fd_stake_new)
    - [`fd_delegation_generate`](#fd_delegation_generate)


---
### fd\_stake\_pair\_generate<!-- {{#callable:fd_stake_pair_generate}} -->
Generates a new `fd_stake_pair_t` structure with initialized account and stake.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_stake_pair_t` structure.
    - It calls `fd_stake_pair_new(mem)` to initialize the `fd_stake_pair_t` structure.
    - It generates a public key for the account by calling [`fd_pubkey_generate`](#fd_pubkey_generate) with the account field of `self`.
    - It generates a stake by calling [`fd_stake_generate`](#fd_stake_generate) with the stake field of `self`.
    - Finally, it returns the pointer to the `fd_stake_pair_t` structure.
- **Output**: Returns a pointer to the initialized `fd_stake_pair_t` structure.
- **Functions called**:
    - [`fd_stake_pair_new`](fd_types.h.driver.md#fd_stake_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_stake_generate`](#fd_stake_generate)


---
### fd\_stakes\_generate<!-- {{#callable:fd_stakes_generate}} -->
Generates a new `fd_stakes_t` structure with initialized vote accounts and stake delegations.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stakes_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stakes_t` structure and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stakes_t` structure.
    - It calls [`fd_vote_accounts_generate`](#fd_vote_accounts_generate) to initialize the `vote_accounts` field of the `fd_stakes_t` structure.
    - It generates a random length for the stake delegations and initializes the `stake_delegations_pool`.
    - A loop iterates over the number of stake delegations, generating each delegation and inserting it into the pool.
    - Random values are generated for the `unused` and `epoch` fields.
    - Finally, it calls [`fd_stake_history_generate`](#fd_stake_history_generate) to initialize the `stake_history` field.
- **Output**: Returns a pointer to the initialized `fd_stakes_t` structure.
- **Functions called**:
    - [`fd_stakes_new`](fd_types.c.driver.md#fd_stakes_new)
    - [`fd_vote_accounts_generate`](#fd_vote_accounts_generate)
    - [`fd_delegation_pair_t_map_join_new`](fd_types.h.driver.md#fd_delegation_pair_t_map_join_new)
    - [`fd_delegation_pair_generate`](#fd_delegation_pair_generate)
    - [`fd_stake_history_generate`](#fd_stake_history_generate)


---
### fd\_stakes\_stake\_generate<!-- {{#callable:fd_stakes_stake_generate}} -->
Generates a new `fd_stakes_stake_t` structure with associated vote accounts and stake delegations.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stakes_stake_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stakes_stake_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the new structure.
    - It calls [`fd_stakes_stake_new`](fd_types.c.driver.md#fd_stakes_stake_new) to initialize the new stake structure.
    - It generates vote accounts by calling [`fd_vote_accounts_generate`](#fd_vote_accounts_generate).
    - It generates a random number of stake delegations (up to 7) and allocates a pool for them.
    - For each delegation, it acquires a node from the pool, generates a stake pair, and inserts it into the delegation pool.
    - It generates random values for `unused` and `epoch` fields.
    - Finally, it generates the stake history by calling [`fd_stake_history_generate`](#fd_stake_history_generate).
- **Output**: Returns a pointer to the initialized `fd_stakes_stake_t` structure.
- **Functions called**:
    - [`fd_stakes_stake_new`](fd_types.c.driver.md#fd_stakes_stake_new)
    - [`fd_vote_accounts_generate`](#fd_vote_accounts_generate)
    - [`fd_stake_pair_t_map_join_new`](fd_types.h.driver.md#fd_stake_pair_t_map_join_new)
    - [`fd_stake_pair_generate`](#fd_stake_pair_generate)
    - [`fd_stake_history_generate`](#fd_stake_history_generate)


---
### fd\_bank\_incremental\_snapshot\_persistence\_generate<!-- {{#callable:fd_bank_incremental_snapshot_persistence_generate}} -->
Generates an incremental snapshot persistence structure for a bank.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_bank_incremental_snapshot_persistence_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_bank_incremental_snapshot_persistence_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_bank_incremental_snapshot_persistence_t` structure.
    - The function initializes the structure by calling [`fd_bank_incremental_snapshot_persistence_new`](fd_types.h.driver.md#fd_bank_incremental_snapshot_persistence_new).
    - It generates a random value for `full_slot` using `fd_rng_ulong`.
    - The function generates a hash for `full_hash` using [`fd_hash_generate`](#fd_hash_generate).
    - It generates a random value for `full_capitalization` using `fd_rng_ulong`.
    - The function generates a hash for `incremental_hash` using [`fd_hash_generate`](#fd_hash_generate).
    - It generates a random value for `incremental_capitalization` using `fd_rng_ulong`.
- **Output**: Returns a pointer to the initialized `fd_bank_incremental_snapshot_persistence_t` structure.
- **Functions called**:
    - [`fd_bank_incremental_snapshot_persistence_new`](fd_types.h.driver.md#fd_bank_incremental_snapshot_persistence_new)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_node\_vote\_accounts\_generate<!-- {{#callable:fd_node_vote_accounts_generate}} -->
Generates vote accounts for a node, initializing them with random values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_node_vote_accounts_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the vote accounts.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_node_vote_accounts_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_node_vote_accounts_t` structure.
    - The function initializes the structure by calling `fd_node_vote_accounts_new(mem)`.
    - It generates a random length for the vote accounts (up to 7) using `fd_rng_ulong(rng) % 8`.
    - If the generated length is greater than zero, it allocates memory for the vote accounts and initializes each account using a loop.
    - For each vote account, it calls `fd_pubkey_new` and [`fd_pubkey_generate`](#fd_pubkey_generate) to create and populate the account with random values.
    - Finally, it generates a random total stake value using `fd_rng_ulong(rng)`.
- **Output**: Returns the pointer to the initialized `fd_node_vote_accounts_t` structure.
- **Functions called**:
    - [`fd_node_vote_accounts_new`](fd_types.c.driver.md#fd_node_vote_accounts_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_pubkey\_node\_vote\_accounts\_pair\_generate<!-- {{#callable:fd_pubkey_node_vote_accounts_pair_generate}} -->
Generates a new `fd_pubkey_node_vote_accounts_pair_t` structure with a public key and associated vote accounts.
- **Inputs**:
    - `mem`: A pointer to a memory location where the generated structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_pubkey_node_vote_accounts_pair_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_pubkey_node_vote_accounts_pair_t` structure.
    - It calls [`fd_pubkey_node_vote_accounts_pair_new`](fd_types.c.driver.md#fd_pubkey_node_vote_accounts_pair_new) to initialize the structure.
    - It generates a new public key using [`fd_pubkey_generate`](#fd_pubkey_generate) and assigns it to the `key` field of the structure.
    - It generates vote accounts using [`fd_node_vote_accounts_generate`](#fd_node_vote_accounts_generate) and assigns it to the `value` field of the structure.
    - Finally, it returns the pointer to the memory location where the structure is stored.
- **Output**: Returns a pointer to the allocated and initialized `fd_pubkey_node_vote_accounts_pair_t` structure.
- **Functions called**:
    - [`fd_pubkey_node_vote_accounts_pair_new`](fd_types.c.driver.md#fd_pubkey_node_vote_accounts_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_node_vote_accounts_generate`](#fd_node_vote_accounts_generate)


---
### fd\_pubkey\_pubkey\_pair\_generate<!-- {{#callable:fd_pubkey_pubkey_pair_generate}} -->
Generates a public key pair consisting of a key and a value.
- **Inputs**:
    - `mem`: A pointer to the memory location where the public key pair will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating the public keys.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_pubkey_pubkey_pair_t` type to access the structure for the public key pair.
    - It updates the `alloc_mem` pointer to allocate enough space for the `fd_pubkey_pubkey_pair_t` structure.
    - The function calls [`fd_pubkey_pubkey_pair_new`](fd_types.h.driver.md#fd_pubkey_pubkey_pair_new) to initialize the public key pair structure.
    - It generates a new public key for the `key` field of the public key pair by calling [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates another public key for the `value` field of the public key pair by calling [`fd_pubkey_generate`](#fd_pubkey_generate) again.
- **Output**: Returns a pointer to the memory location where the public key pair has been generated.
- **Functions called**:
    - [`fd_pubkey_pubkey_pair_new`](fd_types.h.driver.md#fd_pubkey_pubkey_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_epoch\_stakes\_generate<!-- {{#callable:fd_epoch_stakes_generate}} -->
Generates epoch stakes data including stakes and associated voting accounts.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_epoch_stakes_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the stakes and accounts.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_epoch_stakes_t` structure and initializing it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_epoch_stakes_t` structure.
    - The function then calls [`fd_stakes_generate`](#fd_stakes_generate) to initialize the `stakes` field of the `fd_epoch_stakes_t` structure.
    - A random total stake value is generated and assigned to `self->total_stake`.
    - The length of the `node_id_to_vote_accounts` array is randomly determined, and if greater than zero, memory is allocated for it.
    - A loop iterates over the length of `node_id_to_vote_accounts`, initializing each entry and generating its data.
    - Similarly, the length of the `epoch_authorized_voters` array is determined, and if greater than zero, memory is allocated and initialized.
    - Finally, the function returns the pointer to the initialized `fd_epoch_stakes_t` structure.
- **Output**: Returns a pointer to the initialized `fd_epoch_stakes_t` structure.
- **Functions called**:
    - [`fd_epoch_stakes_new`](fd_types.c.driver.md#fd_epoch_stakes_new)
    - [`fd_stakes_generate`](#fd_stakes_generate)
    - [`fd_pubkey_node_vote_accounts_pair_new`](fd_types.c.driver.md#fd_pubkey_node_vote_accounts_pair_new)
    - [`fd_pubkey_node_vote_accounts_pair_generate`](#fd_pubkey_node_vote_accounts_pair_generate)
    - [`fd_pubkey_pubkey_pair_new`](fd_types.h.driver.md#fd_pubkey_pubkey_pair_new)
    - [`fd_pubkey_pubkey_pair_generate`](#fd_pubkey_pubkey_pair_generate)


---
### fd\_epoch\_epoch\_stakes\_pair\_generate<!-- {{#callable:fd_epoch_epoch_stakes_pair_generate}} -->
Generates a new `fd_epoch_epoch_stakes_pair_t` structure with a random key and associated stakes.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_epoch_epoch_stakes_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_epoch_epoch_stakes_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_epoch_epoch_stakes_pair_t` structure.
    - It calls `fd_epoch_epoch_stakes_pair_new(mem)` to initialize the new structure.
    - It generates a random key using `fd_rng_ulong(rng)` and assigns it to `self->key`.
    - It calls `fd_epoch_stakes_generate(&self->value, alloc_mem, rng)` to generate the associated stakes.
- **Output**: Returns a pointer to the allocated `fd_epoch_epoch_stakes_pair_t` structure.
- **Functions called**:
    - [`fd_epoch_epoch_stakes_pair_new`](fd_types.c.driver.md#fd_epoch_epoch_stakes_pair_new)
    - [`fd_epoch_stakes_generate`](#fd_epoch_stakes_generate)


---
### fd\_pubkey\_u64\_pair\_generate<!-- {{#callable:fd_pubkey_u64_pair_generate}} -->
Generates a new `fd_pubkey_u64_pair_t` structure containing a public key and an unsigned 64-bit integer.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_pubkey_u64_pair_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_pubkey_u64_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_pubkey_u64_pair_t` structure.
    - It calls the [`fd_pubkey_u64_pair_new`](fd_types.h.driver.md#fd_pubkey_u64_pair_new) function to initialize the new structure.
    - It generates a new public key by calling [`fd_pubkey_generate`](#fd_pubkey_generate) and assigns it to the first element of the pair.
    - It generates a random unsigned 64-bit integer using `fd_rng_ulong` and assigns it to the second element of the pair.
- **Output**: Returns a pointer to the initialized `fd_pubkey_u64_pair_t` structure.
- **Functions called**:
    - [`fd_pubkey_u64_pair_new`](fd_types.h.driver.md#fd_pubkey_u64_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_unused\_accounts\_generate<!-- {{#callable:fd_unused_accounts_generate}} -->
Generates unused account data including public keys and associated lengths.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_unused_accounts_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random lengths and values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_unused_accounts_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_unused_accounts_t` structure.
    - The function initializes the structure by calling `fd_unused_accounts_new(mem)`.
    - It generates a random length for `unused1` using `fd_rng_ulong(rng) % 8`.
    - If `unused1_len` is greater than zero, it allocates memory for `unused1` and generates public keys for each entry.
    - The same process is repeated for `unused2` and `unused3`, generating random lengths and allocating memory as needed.
    - Finally, the function returns the original `mem` pointer.
- **Output**: Returns a pointer to the initialized `fd_unused_accounts_t` structure.
- **Functions called**:
    - [`fd_unused_accounts_new`](fd_types.c.driver.md#fd_unused_accounts_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_pubkey_u64_pair_new`](fd_types.h.driver.md#fd_pubkey_u64_pair_new)
    - [`fd_pubkey_u64_pair_generate`](#fd_pubkey_u64_pair_generate)


---
### fd\_versioned\_bank\_generate<!-- {{#callable:fd_versioned_bank_generate}} -->
Generates a new `fd_versioned_bank_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_versioned_bank_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_versioned_bank_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_versioned_bank_t` structure.
    - The [`fd_versioned_bank_new`](fd_types.c.driver.md#fd_versioned_bank_new) function is called to initialize the structure.
    - The [`fd_block_hash_vec_generate`](#fd_block_hash_vec_generate) function is called to generate a block hash vector.
    - A random length for the `ancestors` array is generated, and if greater than zero, memory is allocated for it.
    - A loop iterates over the `ancestors` length to initialize and generate each `fd_slot_pair_t`.
    - Random values are generated for various fields of the `fd_versioned_bank_t` structure, including hashes, slots, and fees.
    - The function concludes by returning the pointer to the initialized `fd_versioned_bank_t` structure.
- **Output**: Returns a pointer to the initialized `fd_versioned_bank_t` structure.
- **Functions called**:
    - [`fd_versioned_bank_new`](fd_types.c.driver.md#fd_versioned_bank_new)
    - [`fd_block_hash_vec_generate`](#fd_block_hash_vec_generate)
    - [`fd_slot_pair_new`](fd_types.h.driver.md#fd_slot_pair_new)
    - [`fd_slot_pair_generate`](#fd_slot_pair_generate)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_hard_forks_generate`](#fd_hard_forks_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_fee_calculator_generate`](#fd_fee_calculator_generate)
    - [`fd_fee_rate_governor_generate`](#fd_fee_rate_governor_generate)
    - [`fd_rent_collector_generate`](#fd_rent_collector_generate)
    - [`fd_epoch_schedule_generate`](#fd_epoch_schedule_generate)
    - [`fd_inflation_generate`](#fd_inflation_generate)
    - [`fd_stakes_generate`](#fd_stakes_generate)
    - [`fd_unused_accounts_generate`](#fd_unused_accounts_generate)
    - [`fd_epoch_epoch_stakes_pair_new`](fd_types.c.driver.md#fd_epoch_epoch_stakes_pair_new)
    - [`fd_epoch_epoch_stakes_pair_generate`](#fd_epoch_epoch_stakes_pair_generate)


---
### fd\_bank\_hash\_stats\_generate<!-- {{#callable:fd_bank_hash_stats_generate}} -->
Generates statistics for bank hash including updated and removed accounts.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_bank_hash_stats_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the statistics.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_bank_hash_stats_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_bank_hash_stats_t` structure.
    - The function calls [`fd_bank_hash_stats_new`](fd_types.h.driver.md#fd_bank_hash_stats_new) to initialize the structure.
    - Random values are generated for `num_updated_accounts`, `num_removed_accounts`, `num_lamports_stored`, `total_data_len`, and `num_executable_accounts` using the provided random number generator.
- **Output**: Returns a pointer to the initialized `fd_bank_hash_stats_t` structure.
- **Functions called**:
    - [`fd_bank_hash_stats_new`](fd_types.h.driver.md#fd_bank_hash_stats_new)


---
### fd\_bank\_hash\_info\_generate<!-- {{#callable:fd_bank_hash_info_generate}} -->
Generates hash information for a bank including account hashes and statistics.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_bank_hash_info_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_bank_hash_info_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_bank_hash_info_t` structure.
    - It calls [`fd_bank_hash_info_new`](fd_types.h.driver.md#fd_bank_hash_info_new) to initialize the structure.
    - It generates a hash for `accounts_delta_hash` using [`fd_hash_generate`](#fd_hash_generate).
    - It generates a hash for `accounts_hash` using [`fd_hash_generate`](#fd_hash_generate).
    - It generates statistics for the bank using [`fd_bank_hash_stats_generate`](#fd_bank_hash_stats_generate).
- **Output**: Returns a pointer to the initialized `fd_bank_hash_info_t` structure.
- **Functions called**:
    - [`fd_bank_hash_info_new`](fd_types.h.driver.md#fd_bank_hash_info_new)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_bank_hash_stats_generate`](#fd_bank_hash_stats_generate)


---
### fd\_slot\_map\_pair\_generate<!-- {{#callable:fd_slot_map_pair_generate}} -->
Generates a new `fd_slot_map_pair_t` structure with a random slot and a hash.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_slot_map_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_slot_map_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_slot_map_pair_t` structure.
    - It calls `fd_slot_map_pair_new(mem)` to initialize the new structure.
    - It generates a random slot value using `fd_rng_ulong(rng)` and assigns it to `self->slot`.
    - It calls `fd_hash_generate(&self->hash, alloc_mem, rng)` to generate a hash and store it in `self->hash`.
- **Output**: Returns a pointer to the allocated `fd_slot_map_pair_t` structure.
- **Functions called**:
    - [`fd_slot_map_pair_new`](fd_types.h.driver.md#fd_slot_map_pair_new)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_snapshot\_acc\_vec\_generate<!-- {{#callable:fd_snapshot_acc_vec_generate}} -->
Generates a new snapshot account vector with random ID and file size.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_snapshot_acc_vec_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_snapshot_acc_vec_t` type to access its fields.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_snapshot_acc_vec_t` structure.
    - It calls [`fd_snapshot_acc_vec_new`](fd_types.h.driver.md#fd_snapshot_acc_vec_new) to initialize the snapshot account vector.
    - It generates a random unsigned long value for the `id` field using `fd_rng_ulong`.
    - It generates a random unsigned long value for the `file_sz` field using `fd_rng_ulong`.
- **Output**: Returns a pointer to the initialized `fd_snapshot_acc_vec_t` structure.
- **Functions called**:
    - [`fd_snapshot_acc_vec_new`](fd_types.h.driver.md#fd_snapshot_acc_vec_new)


---
### fd\_snapshot\_slot\_acc\_vecs\_generate<!-- {{#callable:fd_snapshot_slot_acc_vecs_generate}} -->
Generates a snapshot of account vectors for a given slot.
- **Inputs**:
    - `mem`: A pointer to the memory location where the snapshot data will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the snapshot.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type `fd_snapshot_slot_acc_vecs_t`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_snapshot_slot_acc_vecs_t` structure.
    - It initializes the structure by calling [`fd_snapshot_slot_acc_vecs_new`](fd_types.c.driver.md#fd_snapshot_slot_acc_vecs_new).
    - A random slot number is generated and assigned to the `slot` field of the structure.
    - A random length for account vectors is generated, constrained to a maximum of 8.
    - If the length of account vectors is greater than zero, memory is allocated for the account vectors.
    - A loop iterates over the length of account vectors, initializing each vector and generating its data using [`fd_snapshot_acc_vec_generate`](#fd_snapshot_acc_vec_generate).
    - If the length is zero, the account vectors pointer is set to NULL.
- **Output**: Returns a pointer to the updated memory location containing the snapshot data.
- **Functions called**:
    - [`fd_snapshot_slot_acc_vecs_new`](fd_types.c.driver.md#fd_snapshot_slot_acc_vecs_new)
    - [`fd_snapshot_acc_vec_new`](fd_types.h.driver.md#fd_snapshot_acc_vec_new)
    - [`fd_snapshot_acc_vec_generate`](#fd_snapshot_acc_vec_generate)


---
### fd\_reward\_type\_generate<!-- {{#callable:fd_reward_type_generate}} -->
Generates a new `fd_reward_type_t` structure and assigns a random discriminant value.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_reward_type_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_reward_type_t` type.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_reward_type_t` structure.
    - The function calls [`fd_reward_type_new`](fd_types.h.driver.md#fd_reward_type_new) to initialize the structure.
    - A random value is generated using the `fd_rng_uint` function and assigned to the `discriminant` field of the structure.
- **Output**: Returns a pointer to the initialized `fd_reward_type_t` structure.
- **Functions called**:
    - [`fd_reward_type_new`](fd_types.h.driver.md#fd_reward_type_new)


---
### fd\_solana\_accounts\_db\_fields\_generate<!-- {{#callable:fd_solana_accounts_db_fields_generate}} -->
Generates fields for Solana accounts database.
- **Inputs**:
    - `mem`: Pointer to memory where the `fd_solana_accounts_db_fields_t` structure will be initialized.
    - `alloc_mem`: Pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: Pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function starts by casting the `mem` pointer to a `fd_solana_accounts_db_fields_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_solana_accounts_db_fields_t` structure.
    - It initializes the structure by calling [`fd_solana_accounts_db_fields_new`](fd_types.c.driver.md#fd_solana_accounts_db_fields_new).
    - A random length for `storages` is generated, which can be between 0 and 7.
    - If `storages_len` is greater than 0, it allocates memory for `storages` and initializes each storage element using a loop.
    - The `version` and `slot` fields are assigned random values.
    - The function generates bank hash information by calling [`fd_bank_hash_info_generate`](#fd_bank_hash_info_generate).
    - A random length for `historical_roots` is generated, and if greater than 0, it allocates memory and mutates the historical roots.
    - Another random length for `historical_roots_with_hash` is generated, and if greater than 0, it allocates memory and initializes each historical root with hash.
- **Output**: Returns a pointer to the initialized `fd_solana_accounts_db_fields_t` structure.
- **Functions called**:
    - [`fd_solana_accounts_db_fields_new`](fd_types.c.driver.md#fd_solana_accounts_db_fields_new)
    - [`fd_snapshot_slot_acc_vecs_new`](fd_types.c.driver.md#fd_snapshot_slot_acc_vecs_new)
    - [`fd_snapshot_slot_acc_vecs_generate`](#fd_snapshot_slot_acc_vecs_generate)
    - [`fd_bank_hash_info_generate`](#fd_bank_hash_info_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_slot_map_pair_new`](fd_types.h.driver.md#fd_slot_map_pair_new)
    - [`fd_slot_map_pair_generate`](#fd_slot_map_pair_generate)


---
### fd\_versioned\_epoch\_stakes\_current\_generate<!-- {{#callable:fd_versioned_epoch_stakes_current_generate}} -->
Generates a `fd_versioned_epoch_stakes_current_t` structure with randomized values for its fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_versioned_epoch_stakes_current_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure's fields.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_versioned_epoch_stakes_current_t` type and assigning it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_versioned_epoch_stakes_current_t` structure.
    - The [`fd_versioned_epoch_stakes_current_new`](fd_types.c.driver.md#fd_versioned_epoch_stakes_current_new) function is called to initialize the structure.
    - The [`fd_stakes_stake_generate`](#fd_stakes_stake_generate) function is called to generate stakes for the `self->stakes` field.
    - A random value is assigned to `self->total_stake` using the random number generator.
    - The length of `node_id_to_vote_accounts` is randomly determined, and if greater than zero, memory is allocated for it.
    - A loop iterates over the length of `node_id_to_vote_accounts`, generating each entry using [`fd_pubkey_node_vote_accounts_pair_generate`](#fd_pubkey_node_vote_accounts_pair_generate).
    - Similarly, the length of `epoch_authorized_voters` is determined, and if greater than zero, memory is allocated and populated in a loop.
- **Output**: Returns a pointer to the initialized `fd_versioned_epoch_stakes_current_t` structure.
- **Functions called**:
    - [`fd_versioned_epoch_stakes_current_new`](fd_types.c.driver.md#fd_versioned_epoch_stakes_current_new)
    - [`fd_stakes_stake_generate`](#fd_stakes_stake_generate)
    - [`fd_pubkey_node_vote_accounts_pair_new`](fd_types.c.driver.md#fd_pubkey_node_vote_accounts_pair_new)
    - [`fd_pubkey_node_vote_accounts_pair_generate`](#fd_pubkey_node_vote_accounts_pair_generate)
    - [`fd_pubkey_pubkey_pair_new`](fd_types.h.driver.md#fd_pubkey_pubkey_pair_new)
    - [`fd_pubkey_pubkey_pair_generate`](#fd_pubkey_pubkey_pair_generate)


---
### fd\_versioned\_epoch\_stakes\_inner\_generate<!-- {{#callable:fd_versioned_epoch_stakes_inner_generate}} -->
Generates versioned epoch stakes based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_versioned_epoch_stakes_inner_t` where the generated data will be stored.
    - `alloc_mem`: A double pointer to memory allocation space for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which version of epoch stakes to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - If the `discriminant` is 0, it calls the [`fd_versioned_epoch_stakes_current_generate`](#fd_versioned_epoch_stakes_current_generate) function to generate the current epoch stakes.
    - The function then exits after the generation is complete.
- **Output**: The function does not return a value; it modifies the `self` structure to contain the generated epoch stakes.
- **Functions called**:
    - [`fd_versioned_epoch_stakes_current_generate`](#fd_versioned_epoch_stakes_current_generate)


---
### fd\_versioned\_epoch\_stakes\_generate<!-- {{#callable:fd_versioned_epoch_stakes_generate}} -->
Generates a versioned epoch stakes structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_versioned_epoch_stakes_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_versioned_epoch_stakes_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_versioned_epoch_stakes_t` structure.
    - The function initializes the `fd_versioned_epoch_stakes_t` structure by calling [`fd_versioned_epoch_stakes_new`](fd_types.c.driver.md#fd_versioned_epoch_stakes_new).
    - A random discriminant value is generated using the random number generator, which determines the type of inner structure to generate.
    - The function calls [`fd_versioned_epoch_stakes_inner_generate`](#fd_versioned_epoch_stakes_inner_generate) with the inner structure and the generated discriminant to initialize it.
- **Output**: Returns a pointer to the initialized `fd_versioned_epoch_stakes_t` structure.
- **Functions called**:
    - [`fd_versioned_epoch_stakes_new`](fd_types.c.driver.md#fd_versioned_epoch_stakes_new)
    - [`fd_versioned_epoch_stakes_inner_generate`](#fd_versioned_epoch_stakes_inner_generate)


---
### fd\_versioned\_epoch\_stakes\_pair\_generate<!-- {{#callable:fd_versioned_epoch_stakes_pair_generate}} -->
Generates a new `fd_versioned_epoch_stakes_pair_t` structure with a random epoch and associated stakes.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_versioned_epoch_stakes_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the epoch and stakes.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_versioned_epoch_stakes_pair_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_versioned_epoch_stakes_pair_t` structure.
    - It calls [`fd_versioned_epoch_stakes_pair_new`](fd_types.c.driver.md#fd_versioned_epoch_stakes_pair_new) to initialize the structure.
    - A random epoch value is generated using `fd_rng_ulong` and assigned to the `epoch` field of the structure.
    - The function then calls [`fd_versioned_epoch_stakes_generate`](#fd_versioned_epoch_stakes_generate) to generate the stakes associated with the epoch.
- **Output**: Returns a pointer to the allocated `fd_versioned_epoch_stakes_pair_t` structure.
- **Functions called**:
    - [`fd_versioned_epoch_stakes_pair_new`](fd_types.c.driver.md#fd_versioned_epoch_stakes_pair_new)
    - [`fd_versioned_epoch_stakes_generate`](#fd_versioned_epoch_stakes_generate)


---
### fd\_reward\_info\_generate<!-- {{#callable:fd_reward_info_generate}} -->
Generates a new `fd_reward_info_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_reward_info_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_reward_info_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_reward_info_t` structure.
    - It calls [`fd_reward_info_new`](fd_types.c.driver.md#fd_reward_info_new) to initialize the `fd_reward_info_t` structure.
    - It generates a new reward type by calling [`fd_reward_type_generate`](#fd_reward_type_generate).
    - It generates random values for `lamports`, `post_balance`, and `commission` using the random number generator.
- **Output**: Returns a pointer to the initialized `fd_reward_info_t` structure.
- **Functions called**:
    - [`fd_reward_info_new`](fd_types.c.driver.md#fd_reward_info_new)
    - [`fd_reward_type_generate`](#fd_reward_type_generate)


---
### fd\_slot\_lthash\_generate<!-- {{#callable:fd_slot_lthash_generate}} -->
Generates a new `fd_slot_lthash_t` structure and mutates its `lthash` field.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_slot_lthash_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for mutating the `lthash` field.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_slot_lthash_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_slot_lthash_t` structure.
    - The function calls `fd_slot_lthash_new(mem)` to initialize the `fd_slot_lthash_t` structure.
    - It then calls [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) to mutate the `lthash` field of the `fd_slot_lthash_t` structure.
- **Output**: Returns a pointer to the initialized `fd_slot_lthash_t` structure.
- **Functions called**:
    - [`fd_slot_lthash_new`](fd_types.h.driver.md#fd_slot_lthash_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_solana\_manifest\_generate<!-- {{#callable:fd_solana_manifest_generate}} -->
Generates a `fd_solana_manifest_t` structure with various fields initialized based on random values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_solana_manifest_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the fields.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_solana_manifest_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_solana_manifest_t` structure.
    - The [`fd_solana_manifest_new`](fd_types.c.driver.md#fd_solana_manifest_new) function is called to initialize the structure.
    - The [`fd_versioned_bank_generate`](#fd_versioned_bank_generate) function is called to initialize the `bank` field of the manifest.
    - The [`fd_solana_accounts_db_fields_generate`](#fd_solana_accounts_db_fields_generate) function is called to initialize the `accounts_db` field.
    - A random value is generated for `lamports_per_signature`.
    - A random decision is made to either allocate and initialize `bank_incremental_snapshot_persistence` or set it to NULL.
    - A similar random decision is made for `epoch_account_hash`.
    - The length of `versioned_epoch_stakes` is randomly determined, and if greater than zero, it allocates space and initializes each entry.
    - Another random decision is made for `lthash`, either allocating and initializing it or setting it to NULL.
- **Output**: Returns a pointer to the initialized `fd_solana_manifest_t` structure.
- **Functions called**:
    - [`fd_solana_manifest_new`](fd_types.c.driver.md#fd_solana_manifest_new)
    - [`fd_versioned_bank_generate`](#fd_versioned_bank_generate)
    - [`fd_solana_accounts_db_fields_generate`](#fd_solana_accounts_db_fields_generate)
    - [`fd_bank_incremental_snapshot_persistence_new`](fd_types.h.driver.md#fd_bank_incremental_snapshot_persistence_new)
    - [`fd_bank_incremental_snapshot_persistence_generate`](#fd_bank_incremental_snapshot_persistence_generate)
    - [`fd_hash_new`](fd_types.h.driver.md#fd_hash_new)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_versioned_epoch_stakes_pair_new`](fd_types.c.driver.md#fd_versioned_epoch_stakes_pair_new)
    - [`fd_versioned_epoch_stakes_pair_generate`](#fd_versioned_epoch_stakes_pair_generate)
    - [`fd_slot_lthash_new`](fd_types.h.driver.md#fd_slot_lthash_new)
    - [`fd_slot_lthash_generate`](#fd_slot_lthash_generate)


---
### fd\_rust\_duration\_generate<!-- {{#callable:fd_rust_duration_generate}} -->
Generates a new `fd_rust_duration_t` structure with random values for seconds and nanoseconds.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_rust_duration_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for seconds and nanoseconds.
- **Control Flow**:
    - The function starts by casting the `mem` pointer to a `fd_rust_duration_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_rust_duration_t` structure.
    - The function then calls [`fd_rust_duration_new`](fd_types.h.driver.md#fd_rust_duration_new) to initialize the structure.
    - Random values for seconds and nanoseconds are generated using `fd_rng_ulong` and `fd_rng_uint`, respectively.
    - Finally, the function returns the pointer to the initialized `fd_rust_duration_t` structure.
- **Output**: Returns a pointer to the initialized `fd_rust_duration_t` structure.
- **Functions called**:
    - [`fd_rust_duration_new`](fd_types.h.driver.md#fd_rust_duration_new)


---
### fd\_poh\_config\_generate<!-- {{#callable:fd_poh_config_generate}} -->
Generates a new `fd_poh_config_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_poh_config_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to `fd_poh_config_t` and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_poh_config_t` structure.
    - It calls [`fd_rust_duration_generate`](#fd_rust_duration_generate) to initialize the `target_tick_duration` field.
    - It generates a random value to determine if `target_tick_count` should be set to a pointer or NULL.
    - If `target_tick_count` is set, it allocates memory for it and mutates its value using [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate).
    - It generates a random value to determine if `has_hashes_per_tick` is true or false, and if true, mutates the `hashes_per_tick` field.
- **Output**: Returns a pointer to the initialized `fd_poh_config_t` structure.
- **Functions called**:
    - [`fd_poh_config_new`](fd_types.c.driver.md#fd_poh_config_new)
    - [`fd_rust_duration_generate`](#fd_rust_duration_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_string\_pubkey\_pair\_generate<!-- {{#callable:fd_string_pubkey_pair_generate}} -->
Generates a public key pair and an associated random string.
- **Inputs**:
    - `mem`: A pointer to a memory location where the generated public key pair will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_string_pubkey_pair_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_string_pubkey_pair_t` structure.
    - A new `fd_string_pubkey_pair_t` is initialized using [`fd_string_pubkey_pair_new`](fd_types.c.driver.md#fd_string_pubkey_pair_new).
    - A random length for the string is generated using `fd_rng_ulong` and stored in `self->string_len`.
    - If the generated string length is greater than zero, memory is allocated for the string and filled with random characters.
    - A public key is generated and stored in `self->pubkey` using the [`fd_pubkey_generate`](#fd_pubkey_generate) function.
    - Finally, the function returns the original `mem` pointer.
- **Output**: Returns a pointer to the memory location containing the generated public key pair.
- **Functions called**:
    - [`fd_string_pubkey_pair_new`](fd_types.c.driver.md#fd_string_pubkey_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_pubkey\_account\_pair\_generate<!-- {{#callable:fd_pubkey_account_pair_generate}} -->
Generates a public key and associated Solana account.
- **Inputs**:
    - `mem`: A pointer to a memory location where the generated public key account pair will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_pubkey_account_pair_t` type to access the structure fields.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_pubkey_account_pair_t` structure.
    - It calls [`fd_pubkey_account_pair_new`](fd_types.c.driver.md#fd_pubkey_account_pair_new) to initialize the new public key account pair.
    - It generates a new public key using [`fd_pubkey_generate`](#fd_pubkey_generate) and stores it in the `key` field of the structure.
    - It generates a new Solana account using [`fd_solana_account_generate`](#fd_solana_account_generate) and stores it in the `account` field of the structure.
- **Output**: Returns a pointer to the memory location containing the generated `fd_pubkey_account_pair_t` structure.
- **Functions called**:
    - [`fd_pubkey_account_pair_new`](fd_types.c.driver.md#fd_pubkey_account_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_solana_account_generate`](#fd_solana_account_generate)


---
### fd\_genesis\_solana\_generate<!-- {{#callable:fd_genesis_solana_generate}} -->
Generates a new `fd_genesis_solana_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_genesis_solana_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_genesis_solana_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_genesis_solana_t` structure.
    - The [`fd_genesis_solana_new`](fd_types.c.driver.md#fd_genesis_solana_new) function is called to initialize the structure.
    - Random values are generated for `creation_time`, `accounts_len`, `native_instruction_processors_len`, and `rewards_pools_len`.
    - If `accounts_len` is greater than zero, memory is allocated for `accounts`, and each account is initialized and generated.
    - If `native_instruction_processors_len` is greater than zero, memory is allocated for `native_instruction_processors`, and each processor is initialized and generated.
    - If `rewards_pools_len` is greater than zero, memory is allocated for `rewards_pools`, and each pool is initialized and generated.
    - Random values are generated for `ticks_per_slot`, `unused`, and various configurations like `poh_config`, `fee_rate_governor`, `rent`, `inflation`, and `epoch_schedule`.
    - Finally, the function returns the pointer to the initialized `fd_genesis_solana_t` structure.
- **Output**: Returns a pointer to the initialized `fd_genesis_solana_t` structure.
- **Functions called**:
    - [`fd_genesis_solana_new`](fd_types.c.driver.md#fd_genesis_solana_new)
    - [`fd_pubkey_account_pair_new`](fd_types.c.driver.md#fd_pubkey_account_pair_new)
    - [`fd_pubkey_account_pair_generate`](#fd_pubkey_account_pair_generate)
    - [`fd_string_pubkey_pair_new`](fd_types.c.driver.md#fd_string_pubkey_pair_new)
    - [`fd_string_pubkey_pair_generate`](#fd_string_pubkey_pair_generate)
    - [`fd_poh_config_generate`](#fd_poh_config_generate)
    - [`fd_fee_rate_governor_generate`](#fd_fee_rate_governor_generate)
    - [`fd_rent_generate`](#fd_rent_generate)
    - [`fd_inflation_generate`](#fd_inflation_generate)
    - [`fd_epoch_schedule_generate`](#fd_epoch_schedule_generate)


---
### fd\_sol\_sysvar\_clock\_generate<!-- {{#callable:fd_sol_sysvar_clock_generate}} -->
Generates a new `fd_sol_sysvar_clock_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_sol_sysvar_clock_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_sol_sysvar_clock_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_sol_sysvar_clock_t` structure.
    - The function calls [`fd_sol_sysvar_clock_new`](fd_types.h.driver.md#fd_sol_sysvar_clock_new) to initialize the structure.
    - Random values are generated for the `slot`, `epoch_start_timestamp`, `epoch`, `leader_schedule_epoch`, and `unix_timestamp` fields using the provided random number generator.
- **Output**: Returns a pointer to the initialized `fd_sol_sysvar_clock_t` structure.
- **Functions called**:
    - [`fd_sol_sysvar_clock_new`](fd_types.h.driver.md#fd_sol_sysvar_clock_new)


---
### fd\_sol\_sysvar\_last\_restart\_slot\_generate<!-- {{#callable:fd_sol_sysvar_last_restart_slot_generate}} -->
Generates a new `fd_sol_sysvar_last_restart_slot_t` structure with a random slot value.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_sol_sysvar_last_restart_slot_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_sol_sysvar_last_restart_slot_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_sol_sysvar_last_restart_slot_t` structure.
    - It calls [`fd_sol_sysvar_last_restart_slot_new`](fd_types.h.driver.md#fd_sol_sysvar_last_restart_slot_new) to initialize the structure.
    - It generates a random unsigned long value for the `slot` field using the `fd_rng_ulong` function.
- **Output**: Returns a pointer to the initialized `fd_sol_sysvar_last_restart_slot_t` structure.
- **Functions called**:
    - [`fd_sol_sysvar_last_restart_slot_new`](fd_types.h.driver.md#fd_sol_sysvar_last_restart_slot_new)


---
### fd\_vote\_lockout\_generate<!-- {{#callable:fd_vote_lockout_generate}} -->
Generates a new `fd_vote_lockout_t` structure with a random slot and confirmation count.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_lockout_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the slot and confirmation count.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_lockout_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_vote_lockout_t` structure.
    - The function calls `fd_vote_lockout_new(mem)` to initialize the `fd_vote_lockout_t` structure.
    - It generates a random value for `self->slot` using `fd_rng_ulong(rng)`.
    - It generates a random value for `self->confirmation_count` using `fd_rng_uint(rng)`.
    - Finally, it returns the pointer to the initialized `fd_vote_lockout_t` structure.
- **Output**: Returns a pointer to the initialized `fd_vote_lockout_t` structure.
- **Functions called**:
    - [`fd_vote_lockout_new`](fd_types.h.driver.md#fd_vote_lockout_new)


---
### fd\_lockout\_offset\_generate<!-- {{#callable:fd_lockout_offset_generate}} -->
Generates a lockout offset structure with random values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_lockout_offset_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_lockout_offset_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_lockout_offset_t` structure.
    - It calls [`fd_lockout_offset_new`](fd_types.c.driver.md#fd_lockout_offset_new) to initialize the structure.
    - It generates a random `offset` value using `fd_rng_ulong` and assigns it to the `offset` field of the structure.
    - It generates a random `confirmation_count` value using `fd_rng_uchar` and assigns it to the `confirmation_count` field of the structure.
    - Finally, it returns the pointer to the initialized structure.
- **Output**: Returns a pointer to the initialized `fd_lockout_offset_t` structure.
- **Functions called**:
    - [`fd_lockout_offset_new`](fd_types.c.driver.md#fd_lockout_offset_new)


---
### fd\_vote\_authorized\_voter\_generate<!-- {{#callable:fd_vote_authorized_voter_generate}} -->
Generates a new `fd_vote_authorized_voter_t` structure with randomized fields.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_vote_authorized_voter_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for the fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_authorized_voter_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_authorized_voter_t` structure.
    - It calls [`fd_vote_authorized_voter_new`](fd_types.h.driver.md#fd_vote_authorized_voter_new) to initialize the structure.
    - It generates a random `epoch` value using `fd_rng_ulong`.
    - It generates a random public key for the `pubkey` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates random values for the `parent`, `left`, `right`, and `prio` fields using `fd_rng_ulong`.
- **Output**: Returns a pointer to the initialized `fd_vote_authorized_voter_t` structure.
- **Functions called**:
    - [`fd_vote_authorized_voter_new`](fd_types.h.driver.md#fd_vote_authorized_voter_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_vote\_prior\_voter\_generate<!-- {{#callable:fd_vote_prior_voter_generate}} -->
Generates a new `fd_vote_prior_voter_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_prior_voter_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_prior_voter_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_vote_prior_voter_t` structure.
    - It calls `fd_vote_prior_voter_new(mem)` to initialize the new structure.
    - It generates a public key for the voter by calling `fd_pubkey_generate(&self->pubkey, alloc_mem, rng)`.
    - It assigns a random value to `self->epoch_start` using `fd_rng_ulong(rng)`.
    - It assigns a random value to `self->epoch_end` using `fd_rng_ulong(rng)`.
- **Output**: Returns a pointer to the initialized `fd_vote_prior_voter_t` structure.
- **Functions called**:
    - [`fd_vote_prior_voter_new`](fd_types.h.driver.md#fd_vote_prior_voter_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_vote\_prior\_voter\_0\_23\_5\_generate<!-- {{#callable:fd_vote_prior_voter_0_23_5_generate}} -->
Generates a new `fd_vote_prior_voter_0_23_5_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_prior_voter_0_23_5_t` structure will be initialized.
    - `alloc_mem`: A double pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_prior_voter_0_23_5_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_prior_voter_0_23_5_t` structure.
    - The function calls `fd_vote_prior_voter_0_23_5_new(mem)` to initialize the structure.
    - It generates a public key using [`fd_pubkey_generate`](#fd_pubkey_generate) and assigns it to `self->pubkey`.
    - Random values for `epoch_start`, `epoch_end`, and `slot` are generated using `fd_rng_ulong`.
- **Output**: Returns a pointer to the initialized `fd_vote_prior_voter_0_23_5_t` structure.
- **Functions called**:
    - [`fd_vote_prior_voter_0_23_5_new`](fd_types.h.driver.md#fd_vote_prior_voter_0_23_5_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_vote\_epoch\_credits\_generate<!-- {{#callable:fd_vote_epoch_credits_generate}} -->
Generates a new `fd_vote_epoch_credits_t` structure with random epoch and credit values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_vote_epoch_credits_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the epoch and credits.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_epoch_credits_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_epoch_credits_t` structure.
    - It calls [`fd_vote_epoch_credits_new`](fd_types.h.driver.md#fd_vote_epoch_credits_new) to initialize the structure.
    - It generates a random value for the `epoch` field using `fd_rng_ulong`.
    - It generates random values for the `credits` and `prev_credits` fields using `fd_rng_ulong`.
- **Output**: Returns a pointer to the initialized `fd_vote_epoch_credits_t` structure.
- **Functions called**:
    - [`fd_vote_epoch_credits_new`](fd_types.h.driver.md#fd_vote_epoch_credits_new)


---
### fd\_vote\_block\_timestamp\_generate<!-- {{#callable:fd_vote_block_timestamp_generate}} -->
Generates a new `fd_vote_block_timestamp_t` structure with a random slot and timestamp.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_vote_block_timestamp_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the slot and timestamp.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_block_timestamp_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_block_timestamp_t` structure.
    - It calls `fd_vote_block_timestamp_new(mem)` to initialize the structure.
    - It generates a random value for `self->slot` using `fd_rng_ulong(rng)`.
    - It generates a random value for `self->timestamp` using `fd_rng_long(rng)`.
    - Finally, it returns the pointer to the initialized `fd_vote_block_timestamp_t` structure.
- **Output**: Returns a pointer to the initialized `fd_vote_block_timestamp_t` structure.
- **Functions called**:
    - [`fd_vote_block_timestamp_new`](fd_types.h.driver.md#fd_vote_block_timestamp_new)


---
### fd\_vote\_prior\_voters\_generate<!-- {{#callable:fd_vote_prior_voters_generate}} -->
Generates a structure containing prior voters for a voting system.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_prior_voters_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_prior_voters_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_prior_voters_t` structure.
    - It calls [`fd_vote_prior_voters_new`](fd_types.c.driver.md#fd_vote_prior_voters_new) to initialize the structure.
    - A loop iterates 32 times, calling [`fd_vote_prior_voter_generate`](#fd_vote_prior_voter_generate) to populate each voter in the buffer.
    - It assigns a random index to `self->idx` using `fd_rng_ulong`.
    - It assigns a random value to `self->is_empty` using `fd_rng_uchar`.
- **Output**: Returns a pointer to the initialized `fd_vote_prior_voters_t` structure.
- **Functions called**:
    - [`fd_vote_prior_voters_new`](fd_types.c.driver.md#fd_vote_prior_voters_new)
    - [`fd_vote_prior_voter_generate`](#fd_vote_prior_voter_generate)


---
### fd\_vote\_prior\_voters\_0\_23\_5\_generate<!-- {{#callable:fd_vote_prior_voters_0_23_5_generate}} -->
Generates a structure for prior voters in a voting system.
- **Inputs**:
    - `mem`: A pointer to the memory location where the generated structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the structure being generated.
    - It calls [`fd_vote_prior_voters_0_23_5_new`](fd_types.h.driver.md#fd_vote_prior_voters_0_23_5_new) to initialize the structure.
    - A loop iterates 32 times, generating individual prior voters by calling [`fd_vote_prior_voter_0_23_5_generate`](#fd_vote_prior_voter_0_23_5_generate) for each entry in the buffer.
    - A random index is generated and assigned to the structure's index field.
- **Output**: Returns a pointer to the memory location containing the generated structure.
- **Functions called**:
    - [`fd_vote_prior_voters_0_23_5_new`](fd_types.h.driver.md#fd_vote_prior_voters_0_23_5_new)
    - [`fd_vote_prior_voter_0_23_5_generate`](#fd_vote_prior_voter_0_23_5_generate)


---
### fd\_landed\_vote\_generate<!-- {{#callable:fd_landed_vote_generate}} -->
Generates a new `fd_landed_vote_t` structure with a random latency and a generated lockout.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_landed_vote_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_landed_vote_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_landed_vote_t` structure.
    - It calls `fd_landed_vote_new(mem)` to initialize the new structure.
    - It generates a random `latency` value using `fd_rng_uchar(rng)` and assigns it to `self->latency`.
    - It calls `fd_vote_lockout_generate(&self->lockout, alloc_mem, rng)` to generate a new lockout structure.
- **Output**: Returns a pointer to the initialized `fd_landed_vote_t` structure.
- **Functions called**:
    - [`fd_landed_vote_new`](fd_types.h.driver.md#fd_landed_vote_new)
    - [`fd_vote_lockout_generate`](#fd_vote_lockout_generate)


---
### fd\_vote\_state\_0\_23\_5\_generate<!-- {{#callable:fd_vote_state_0_23_5_generate}} -->
Generates a new `fd_vote_state_0_23_5_t` structure with initialized fields based on random values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_state_0_23_5_t` structure will be initialized.
    - `alloc_mem`: A double pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_vote_state_0_23_5_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_state_0_23_5_t` structure.
    - The function initializes the structure by calling `fd_vote_state_0_23_5_new(mem)`.
    - It generates a public key for `node_pubkey` and `authorized_voter` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - The `authorized_voter_epoch` is assigned a random unsigned long value.
    - The function generates prior voters using [`fd_vote_prior_voters_0_23_5_generate`](#fd_vote_prior_voters_0_23_5_generate).
    - It generates a public key for `authorized_withdrawer`.
    - The `commission` is assigned a random unsigned char value.
    - The function determines the number of votes to generate (up to 8) and allocates space for them.
    - For each vote, it generates a `fd_vote_lockout_t` structure and populates it using [`fd_vote_lockout_generate`](#fd_vote_lockout_generate).
    - It randomly decides if the structure has a root slot and mutates the `root_slot` if true.
    - The function generates epoch credits (up to 8) and allocates space for them.
    - For each epoch credit, it generates a `fd_vote_epoch_credits_t` structure and populates it using [`fd_vote_epoch_credits_generate`](#fd_vote_epoch_credits_generate).
    - Finally, it generates a timestamp for the last block using [`fd_vote_block_timestamp_generate`](#fd_vote_block_timestamp_generate).
- **Output**: Returns a pointer to the initialized `fd_vote_state_0_23_5_t` structure.
- **Functions called**:
    - [`fd_vote_state_0_23_5_new`](fd_types.c.driver.md#fd_vote_state_0_23_5_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_vote_prior_voters_0_23_5_generate`](#fd_vote_prior_voters_0_23_5_generate)
    - [`deq_fd_vote_lockout_t_join_new`](fd_types.h.driver.md#deq_fd_vote_lockout_t_join_new)
    - [`fd_vote_lockout_generate`](#fd_vote_lockout_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`deq_fd_vote_epoch_credits_t_join_new`](fd_types.h.driver.md#deq_fd_vote_epoch_credits_t_join_new)
    - [`fd_vote_epoch_credits_generate`](#fd_vote_epoch_credits_generate)
    - [`fd_vote_block_timestamp_generate`](#fd_vote_block_timestamp_generate)


---
### fd\_vote\_authorized\_voters\_generate<!-- {{#callable:fd_vote_authorized_voters_generate}} -->
Generates a structure for authorized voters in a voting system.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_authorized_voters_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the voters.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_vote_authorized_voters_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_authorized_voters_t` structure.
    - A new `fd_vote_authorized_voters_t` structure is initialized using [`fd_vote_authorized_voters_new`](fd_types.c.driver.md#fd_vote_authorized_voters_new).
    - A random length for the treap of authorized voters is generated, constrained to a maximum of 8.
    - The maximum length for the treap is determined using `fd_ulong_max`, ensuring it is at least `FD_VOTE_AUTHORIZED_VOTERS_MIN`.
    - A new pool for authorized voters is created using [`fd_vote_authorized_voters_pool_join_new`](fd_types.h.driver.md#fd_vote_authorized_voters_pool_join_new).
    - A new treap for authorized voters is created using [`fd_vote_authorized_voters_treap_join_new`](fd_types.h.driver.md#fd_vote_authorized_voters_treap_join_new).
    - A loop iterates over the generated length, acquiring a new voter from the pool and generating its details.
    - If a voter with the same epoch already exists in the treap, it is removed to avoid duplication.
    - The new voter is then inserted into the treap.
- **Output**: Returns a pointer to the initialized `fd_vote_authorized_voters_t` structure.
- **Functions called**:
    - [`fd_vote_authorized_voters_new`](fd_types.c.driver.md#fd_vote_authorized_voters_new)
    - [`fd_vote_authorized_voters_pool_join_new`](fd_types.h.driver.md#fd_vote_authorized_voters_pool_join_new)
    - [`fd_vote_authorized_voters_treap_join_new`](fd_types.h.driver.md#fd_vote_authorized_voters_treap_join_new)
    - [`fd_vote_authorized_voter_generate`](#fd_vote_authorized_voter_generate)


---
### fd\_vote\_state\_1\_14\_11\_generate<!-- {{#callable:fd_vote_state_1_14_11_generate}} -->
Generates a new `fd_vote_state_1_14_11_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_state_1_14_11_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_state_1_14_11_t` type and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_state_1_14_11_t` structure.
    - Generates a new public key for `node_pubkey` and `authorized_withdrawer` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - Randomly assigns a commission value using `fd_rng_uchar`.
    - Determines the number of votes to generate (up to 8) and allocates space for them.
    - In a loop, it generates each vote lockout using [`fd_vote_lockout_generate`](#fd_vote_lockout_generate).
    - Randomly decides if the structure has a root slot and mutates its value if true.
    - Generates authorized voters and prior voters using their respective generation functions.
    - Determines the number of epoch credits to generate (up to 8) and allocates space for them.
    - In a loop, it generates each epoch credit using [`fd_vote_epoch_credits_generate`](#fd_vote_epoch_credits_generate).
    - Generates the last timestamp using [`fd_vote_block_timestamp_generate`](#fd_vote_block_timestamp_generate).
- **Output**: Returns a pointer to the initialized `fd_vote_state_1_14_11_t` structure.
- **Functions called**:
    - [`fd_vote_state_1_14_11_new`](fd_types.c.driver.md#fd_vote_state_1_14_11_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`deq_fd_vote_lockout_t_join_new`](fd_types.h.driver.md#deq_fd_vote_lockout_t_join_new)
    - [`fd_vote_lockout_generate`](#fd_vote_lockout_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_vote_authorized_voters_generate`](#fd_vote_authorized_voters_generate)
    - [`fd_vote_prior_voters_generate`](#fd_vote_prior_voters_generate)
    - [`deq_fd_vote_epoch_credits_t_join_new`](fd_types.h.driver.md#deq_fd_vote_epoch_credits_t_join_new)
    - [`fd_vote_epoch_credits_generate`](#fd_vote_epoch_credits_generate)
    - [`fd_vote_block_timestamp_generate`](#fd_vote_block_timestamp_generate)


---
### fd\_vote\_state\_generate<!-- {{#callable:fd_vote_state_generate}} -->
Generates a new `fd_vote_state_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_state_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_vote_state_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_state_t` structure.
    - The function initializes the `fd_vote_state_t` structure by calling `fd_vote_state_new(mem)`.
    - It generates a public key for `node_pubkey` and `authorized_withdrawer` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - A random commission value is assigned to the `commission` field.
    - The number of votes is randomly determined, and a maximum is calculated.
    - A new deque for votes is created and populated with randomly generated `fd_landed_vote_t` structures.
    - A random boolean value determines if the `root_slot` is set, and if so, it is mutated.
    - The function generates authorized voters and prior voters using their respective generation functions.
    - The function generates epoch credits and populates them similarly to votes.
    - Finally, it generates a timestamp for the last block and returns the initialized memory.
- **Output**: Returns a pointer to the initialized `fd_vote_state_t` structure.
- **Functions called**:
    - [`fd_vote_state_new`](fd_types.c.driver.md#fd_vote_state_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`deq_fd_landed_vote_t_join_new`](fd_types.h.driver.md#deq_fd_landed_vote_t_join_new)
    - [`fd_landed_vote_generate`](#fd_landed_vote_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_vote_authorized_voters_generate`](#fd_vote_authorized_voters_generate)
    - [`fd_vote_prior_voters_generate`](#fd_vote_prior_voters_generate)
    - [`deq_fd_vote_epoch_credits_t_join_new`](fd_types.h.driver.md#deq_fd_vote_epoch_credits_t_join_new)
    - [`fd_vote_epoch_credits_generate`](#fd_vote_epoch_credits_generate)
    - [`fd_vote_block_timestamp_generate`](#fd_vote_block_timestamp_generate)


---
### fd\_vote\_state\_versioned\_inner\_generate<!-- {{#callable:fd_vote_state_versioned_inner_generate}} -->
Generates a versioned vote state based on a discriminant value.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_versioned_inner_t` structure that will hold the generated vote state.
    - `alloc_mem`: A double pointer to memory allocation space for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which version of the vote state to generate.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value to determine which case to execute.
    - If `discriminant` is 0, it calls [`fd_vote_state_0_23_5_generate`](#fd_vote_state_0_23_5_generate) to generate the corresponding vote state.
    - If `discriminant` is 1, it calls [`fd_vote_state_1_14_11_generate`](#fd_vote_state_1_14_11_generate) for the second version.
    - If `discriminant` is 2, it calls [`fd_vote_state_generate`](#fd_vote_state_generate) for the current version.
- **Output**: The function does not return a value; it modifies the `self` structure to hold the generated vote state based on the specified version.
- **Functions called**:
    - [`fd_vote_state_0_23_5_generate`](#fd_vote_state_0_23_5_generate)
    - [`fd_vote_state_1_14_11_generate`](#fd_vote_state_1_14_11_generate)
    - [`fd_vote_state_generate`](#fd_vote_state_generate)


---
### fd\_vote\_state\_versioned\_generate<!-- {{#callable:fd_vote_state_versioned_generate}} -->
Generates a versioned vote state structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the vote state will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type `fd_vote_state_versioned_t`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_state_versioned_t` structure.
    - A new instance of `fd_vote_state_versioned_t` is initialized using [`fd_vote_state_versioned_new`](fd_types.c.driver.md#fd_vote_state_versioned_new).
    - A random discriminant value is generated using the random number generator, which determines the version of the vote state.
    - The inner generation function [`fd_vote_state_versioned_inner_generate`](#fd_vote_state_versioned_inner_generate) is called with the inner structure and the generated discriminant.
- **Output**: Returns a pointer to the memory location containing the generated versioned vote state.
- **Functions called**:
    - [`fd_vote_state_versioned_new`](fd_types.c.driver.md#fd_vote_state_versioned_new)
    - [`fd_vote_state_versioned_inner_generate`](#fd_vote_state_versioned_inner_generate)


---
### fd\_vote\_state\_update\_generate<!-- {{#callable:fd_vote_state_update_generate}} -->
Generates a new `fd_vote_state_update_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_vote_state_update_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_vote_state_update_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_state_update_t` structure.
    - A random length for lockouts is generated, constrained to a maximum of 8.
    - A new deque for lockouts is created with a maximum size determined by the generated length.
    - A loop iterates over the generated lockouts length, populating each lockout with a generated value.
    - A random boolean value is generated to determine if the root should be mutated.
    - If the root is to be mutated, a mutation is applied to the root value.
    - A hash is generated for the state update.
    - A random boolean value is generated to determine if a timestamp should be mutated.
    - If the timestamp is to be mutated, a mutation is applied to the timestamp value.
- **Output**: Returns a pointer to the initialized `fd_vote_state_update_t` structure.
- **Functions called**:
    - [`fd_vote_state_update_new`](fd_types.c.driver.md#fd_vote_state_update_new)
    - [`deq_fd_vote_lockout_t_join_new`](fd_types.h.driver.md#deq_fd_vote_lockout_t_join_new)
    - [`fd_vote_lockout_generate`](#fd_vote_lockout_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_compact\_vote\_state\_update\_generate<!-- {{#callable:fd_compact_vote_state_update_generate}} -->
Generates a compact vote state update structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_compact_vote_state_update_t` structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the fields of the structure.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_compact_vote_state_update_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_compact_vote_state_update_t` structure.
    - The [`fd_compact_vote_state_update_new`](fd_types.c.driver.md#fd_compact_vote_state_update_new) function is called to initialize the structure.
    - A random value is generated for the `root` field of the structure.
    - A random length for the `lockouts` array is generated, which can be between 0 and 7.
    - If `lockouts_len` is greater than 0, memory is allocated for the `lockouts` array, and each element is initialized and generated using [`fd_lockout_offset_generate`](#fd_lockout_offset_generate).
    - A hash is generated for the `hash` field using [`fd_hash_generate`](#fd_hash_generate).
    - A random value is generated for the `has_timestamp` field, and if true, the `timestamp` field is mutated.
- **Output**: Returns a pointer to the updated memory location containing the generated `fd_compact_vote_state_update_t` structure.
- **Functions called**:
    - [`fd_compact_vote_state_update_new`](fd_types.c.driver.md#fd_compact_vote_state_update_new)
    - [`fd_lockout_offset_new`](fd_types.c.driver.md#fd_lockout_offset_new)
    - [`fd_lockout_offset_generate`](#fd_lockout_offset_generate)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_compact\_vote\_state\_update\_switch\_generate<!-- {{#callable:fd_compact_vote_state_update_switch_generate}} -->
Generates a new `fd_compact_vote_state_update_switch` structure and populates it with a compact vote state update and a hash.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_compact_vote_state_update_switch` structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_compact_vote_state_update_switch_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_compact_vote_state_update_switch_t` structure.
    - It calls [`fd_compact_vote_state_update_generate`](#fd_compact_vote_state_update_generate) to populate the `compact_vote_state_update` field of the structure.
    - It calls [`fd_hash_generate`](#fd_hash_generate) to generate a hash for the structure.
- **Output**: Returns a pointer to the memory location containing the populated `fd_compact_vote_state_update_switch` structure.
- **Functions called**:
    - [`fd_compact_vote_state_update_switch_new`](fd_types.c.driver.md#fd_compact_vote_state_update_switch_new)
    - [`fd_compact_vote_state_update_generate`](#fd_compact_vote_state_update_generate)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_compact\_tower\_sync\_generate<!-- {{#callable:fd_compact_tower_sync_generate}} -->
Generates a new `fd_compact_tower_sync_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_compact_tower_sync_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_compact_tower_sync_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_compact_tower_sync_t` structure.
    - The [`fd_compact_tower_sync_new`](fd_types.c.driver.md#fd_compact_tower_sync_new) function is called to initialize the structure.
    - A random value is assigned to the `root` field of the structure.
    - A random length for lockout offsets is generated, and a maximum length is calculated.
    - A new deque for lockout offsets is created with the calculated maximum length.
    - A loop iterates over the generated length of lockout offsets, populating each with random values using [`fd_lockout_offset_generate`](#fd_lockout_offset_generate).
    - A hash is generated and assigned to the `hash` field of the structure.
    - A random boolean value determines if a timestamp is included, and if so, it is mutated.
    - A hash is generated for the `block_id` field.
- **Output**: Returns a pointer to the initialized `fd_compact_tower_sync_t` structure.
- **Functions called**:
    - [`fd_compact_tower_sync_new`](fd_types.c.driver.md#fd_compact_tower_sync_new)
    - [`deq_fd_lockout_offset_t_join_new`](fd_types.h.driver.md#deq_fd_lockout_offset_t_join_new)
    - [`fd_lockout_offset_generate`](#fd_lockout_offset_generate)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_tower\_sync\_switch\_generate<!-- {{#callable:fd_tower_sync_switch_generate}} -->
Generates a new `fd_tower_sync_switch_t` structure and populates its hash.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_tower_sync_switch_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_tower_sync_switch_t` type.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_tower_sync_switch_t` structure.
    - It calls the [`fd_tower_sync_switch_new`](fd_types.c.driver.md#fd_tower_sync_switch_new) function to initialize the structure.
    - It generates a hash for the `fd_tower_sync_switch_t` structure using the [`fd_hash_generate`](#fd_hash_generate) function.
    - Finally, it returns the pointer to the initialized `fd_tower_sync_switch_t` structure.
- **Output**: Returns a pointer to the initialized `fd_tower_sync_switch_t` structure.
- **Functions called**:
    - [`fd_tower_sync_switch_new`](fd_types.c.driver.md#fd_tower_sync_switch_new)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_slot\_history\_generate<!-- {{#callable:fd_slot_history_generate}} -->
Generates a `fd_slot_history_t` structure with random values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_slot_history_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_slot_history_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_slot_history_t` structure.
    - A new `fd_slot_history_t` instance is initialized using `fd_slot_history_new(mem)`.
    - A random value is generated to determine if the `has_bits` field is set (0 or 1).
    - If `has_bits` is set to 1, a random length for `bits_bitvec` is generated (0 to 7).
    - If `bits_bitvec_len` is greater than 0, memory is allocated for `bits_bitvec` and mutated using [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate).
    - The `bits_len` is set to `bits_bitvec_len` if `has_bits` is true, otherwise it is set to 0.
    - Finally, a random value is assigned to `next_slot`.
- **Output**: Returns a pointer to the initialized `fd_slot_history_t` structure.
- **Functions called**:
    - [`fd_slot_history_new`](fd_types.c.driver.md#fd_slot_history_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_slot\_hash\_generate<!-- {{#callable:fd_slot_hash_generate}} -->
Generates a new `fd_slot_hash_t` structure, initializing its slot and hash fields.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_slot_hash_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the slot and hash.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_slot_hash_t` type.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_slot_hash_t` structure.
    - The function calls [`fd_slot_hash_new`](fd_types.h.driver.md#fd_slot_hash_new) to initialize the `fd_slot_hash_t` structure.
    - It generates a random value for the `slot` field using `fd_rng_ulong`.
    - The function calls [`fd_hash_generate`](#fd_hash_generate) to initialize the `hash` field with a random value.
- **Output**: Returns a pointer to the initialized `fd_slot_hash_t` structure.
- **Functions called**:
    - [`fd_slot_hash_new`](fd_types.h.driver.md#fd_slot_hash_new)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_slot\_hashes\_generate<!-- {{#callable:fd_slot_hashes_generate}} -->
Generates slot hashes for a given memory structure.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_slot_hashes_t` structure is allocated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_slot_hashes_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_slot_hashes_t` structure.
    - It initializes the `fd_slot_hashes_t` structure by calling [`fd_slot_hashes_new`](fd_types.c.driver.md#fd_slot_hashes_new).
    - It generates a random length for the hashes (up to 7) using the random number generator.
    - It calculates the maximum number of hashes to be generated, ensuring it is at least 512.
    - It allocates a new deque for storing the hashes using [`deq_fd_slot_hash_t_join_new`](fd_types.h.driver.md#deq_fd_slot_hash_t_join_new).
    - A loop iterates over the number of hashes to be generated, creating each hash using [`fd_slot_hash_generate`](#fd_slot_hash_generate).
- **Output**: Returns a pointer to the updated memory location containing the generated slot hashes.
- **Functions called**:
    - [`fd_slot_hashes_new`](fd_types.c.driver.md#fd_slot_hashes_new)
    - [`deq_fd_slot_hash_t_join_new`](fd_types.h.driver.md#deq_fd_slot_hash_t_join_new)
    - [`fd_slot_hash_generate`](#fd_slot_hash_generate)


---
### fd\_block\_block\_hash\_entry\_generate<!-- {{#callable:fd_block_block_hash_entry_generate}} -->
Generates a new `fd_block_block_hash_entry_t` structure with a block hash and fee calculator.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_block_block_hash_entry_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_block_block_hash_entry_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_block_block_hash_entry_t` structure.
    - It calls [`fd_block_block_hash_entry_new`](fd_types.h.driver.md#fd_block_block_hash_entry_new) to initialize the new block hash entry.
    - It generates a block hash by calling [`fd_hash_generate`](#fd_hash_generate), passing the block hash field of `self`, `alloc_mem`, and `rng`.
    - It generates a fee calculator by calling [`fd_fee_calculator_generate`](#fd_fee_calculator_generate), passing the fee calculator field of `self`, `alloc_mem`, and `rng`.
- **Output**: Returns a pointer to the initialized `fd_block_block_hash_entry_t` structure.
- **Functions called**:
    - [`fd_block_block_hash_entry_new`](fd_types.h.driver.md#fd_block_block_hash_entry_new)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_fee_calculator_generate`](#fd_fee_calculator_generate)


---
### fd\_recent\_block\_hashes\_generate<!-- {{#callable:fd_recent_block_hashes_generate}} -->
Generates recent block hashes for a given memory structure.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_recent_block_hashes_t` structure is stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_recent_block_hashes_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_recent_block_hashes_t` structure.
    - It initializes the `fd_recent_block_hashes_t` structure by calling [`fd_recent_block_hashes_new`](fd_types.c.driver.md#fd_recent_block_hashes_new).
    - It generates a random length for the hashes (up to 7) and calculates the maximum number of hashes (at least 151).
    - It allocates a new deque for storing block hash entries using [`deq_fd_block_block_hash_entry_t_join_new`](fd_types.h.driver.md#deq_fd_block_block_hash_entry_t_join_new).
    - It enters a loop to generate each block hash entry, calling [`fd_block_block_hash_entry_generate`](#fd_block_block_hash_entry_generate) for each entry.
- **Output**: Returns a pointer to the updated memory location containing the generated recent block hashes.
- **Functions called**:
    - [`fd_recent_block_hashes_new`](fd_types.c.driver.md#fd_recent_block_hashes_new)
    - [`deq_fd_block_block_hash_entry_t_join_new`](fd_types.h.driver.md#deq_fd_block_block_hash_entry_t_join_new)
    - [`fd_block_block_hash_entry_generate`](#fd_block_block_hash_entry_generate)


---
### fd\_slot\_meta\_generate<!-- {{#callable:fd_slot_meta_generate}} -->
Generates metadata for a slot in a system, populating various fields with random values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_slot_meta_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the slot metadata.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_slot_meta_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_slot_meta_t` structure.
    - It initializes the `fd_slot_meta_t` structure by calling `fd_slot_meta_new(mem)`.
    - Random values are generated for various fields of the `fd_slot_meta_t` structure using the provided `rng`.
    - If `next_slot_len` is greater than zero, it allocates memory for `next_slot` and mutates it with random data.
    - If `entry_end_indexes_len` is greater than zero, it allocates memory for `entry_end_indexes` and mutates it with random data.
- **Output**: Returns the pointer to the initialized `fd_slot_meta_t` structure.
- **Functions called**:
    - [`fd_slot_meta_new`](fd_types.c.driver.md#fd_slot_meta_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_clock\_timestamp\_vote\_generate<!-- {{#callable:fd_clock_timestamp_vote_generate}} -->
Generates a new `fd_clock_timestamp_vote_t` structure with a public key, timestamp, and slot.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_clock_timestamp_vote_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the timestamp and slot.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_clock_timestamp_vote_t` type.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_clock_timestamp_vote_t` structure.
    - It calls [`fd_clock_timestamp_vote_new`](fd_types.h.driver.md#fd_clock_timestamp_vote_new) to initialize the new structure.
    - It generates a new public key using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates a random long value for the timestamp using `fd_rng_long`.
    - It generates a random unsigned long value for the slot using `fd_rng_ulong`.
- **Output**: Returns a pointer to the allocated and initialized `fd_clock_timestamp_vote_t` structure.
- **Functions called**:
    - [`fd_clock_timestamp_vote_new`](fd_types.h.driver.md#fd_clock_timestamp_vote_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_clock\_timestamp\_votes\_generate<!-- {{#callable:fd_clock_timestamp_votes_generate}} -->
Generates a set of clock timestamp votes based on random values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the generated votes will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the votes.
- **Control Flow**:
    - The function begins by casting the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the `fd_clock_timestamp_votes_t` structure.
    - A new `fd_clock_timestamp_votes_t` structure is initialized.
    - A random number of votes is generated, limited to a maximum of 8.
    - A loop iterates over the number of votes, generating each vote and inserting it into a pool.
    - Each generated vote is created using the [`fd_clock_timestamp_vote_generate`](#fd_clock_timestamp_vote_generate) function and inserted into a map.
- **Output**: Returns the original memory pointer passed to the function, now containing the generated clock timestamp votes.
- **Functions called**:
    - [`fd_clock_timestamp_votes_new`](fd_types.c.driver.md#fd_clock_timestamp_votes_new)
    - [`fd_clock_timestamp_vote_t_map_join_new`](fd_types.h.driver.md#fd_clock_timestamp_vote_t_map_join_new)
    - [`fd_clock_timestamp_vote_generate`](#fd_clock_timestamp_vote_generate)


---
### fd\_sysvar\_fees\_generate<!-- {{#callable:fd_sysvar_fees_generate}} -->
Generates a new `fd_sysvar_fees_t` structure and populates its `fee_calculator` field.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_sysvar_fees_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the fee calculator.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_sysvar_fees_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_sysvar_fees_t` structure.
    - It calls the [`fd_sysvar_fees_new`](fd_types.h.driver.md#fd_sysvar_fees_new) function to initialize the `fd_sysvar_fees_t` structure.
    - It calls the [`fd_fee_calculator_generate`](#fd_fee_calculator_generate) function to populate the `fee_calculator` field of the `fd_sysvar_fees_t` structure using the updated `alloc_mem` and `rng`.
- **Output**: Returns a pointer to the initialized `fd_sysvar_fees_t` structure.
- **Functions called**:
    - [`fd_sysvar_fees_new`](fd_types.h.driver.md#fd_sysvar_fees_new)
    - [`fd_fee_calculator_generate`](#fd_fee_calculator_generate)


---
### fd\_sysvar\_epoch\_rewards\_generate<!-- {{#callable:fd_sysvar_epoch_rewards_generate}} -->
Generates a new `fd_sysvar_epoch_rewards_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_sysvar_epoch_rewards_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure's fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_sysvar_epoch_rewards_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_sysvar_epoch_rewards_t` structure.
    - The function calls `fd_sysvar_epoch_rewards_new(mem)` to initialize the structure.
    - Random values are generated for various fields of the `self` structure using the provided `rng`.
    - The fields populated include `distribution_starting_block_height`, `num_partitions`, `parent_blockhash`, `total_points`, `total_rewards`, `distributed_rewards`, and `active`.
- **Output**: Returns a pointer to the initialized `fd_sysvar_epoch_rewards_t` structure.
- **Functions called**:
    - [`fd_sysvar_epoch_rewards_new`](fd_types.c.driver.md#fd_sysvar_epoch_rewards_new)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_config\_keys\_pair\_generate<!-- {{#callable:fd_config_keys_pair_generate}} -->
Generates a new `fd_config_keys_pair_t` structure with a public key and a signer.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_config_keys_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_config_keys_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_config_keys_pair_t` structure.
    - It calls `fd_config_keys_pair_new(mem)` to initialize the new structure.
    - It generates a public key using `fd_pubkey_generate(&self->key, alloc_mem, rng)`.
    - It assigns a random value to `self->signer` using `fd_rng_uchar(rng)`.
- **Output**: Returns a pointer to the allocated `fd_config_keys_pair_t` structure.
- **Functions called**:
    - [`fd_config_keys_pair_new`](fd_types.c.driver.md#fd_config_keys_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_stake\_config\_generate<!-- {{#callable:fd_stake_config_generate}} -->
Generates a new `fd_stake_config_t` structure with randomized configuration keys and parameters.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_config_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_config_t` structure and initializes it.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_stake_config_t` structure.
    - The length of the configuration keys is randomly determined (0 to 7).
    - If the length is greater than zero, memory is allocated for the configuration keys, and each key is initialized and generated using a loop.
    - The `warmup_cooldown_rate` and `slash_penalty` fields are assigned random values.
- **Output**: Returns a pointer to the initialized `fd_stake_config_t` structure.
- **Functions called**:
    - [`fd_stake_config_new`](fd_types.c.driver.md#fd_stake_config_new)
    - [`fd_config_keys_pair_new`](fd_types.c.driver.md#fd_config_keys_pair_new)
    - [`fd_config_keys_pair_generate`](#fd_config_keys_pair_generate)


---
### fd\_feature\_entry\_generate<!-- {{#callable:fd_feature_entry_generate}} -->
Generates a new `fd_feature_entry_t` structure with a public key and an optional description.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_feature_entry_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_feature_entry_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_feature_entry_t` structure.
    - It calls `fd_feature_entry_new(mem)` to initialize the new feature entry.
    - It generates a public key using [`fd_pubkey_generate`](#fd_pubkey_generate) and assigns it to `self->pubkey`.
    - It generates a random length for the description (0 to 7) using `fd_rng_ulong`.
    - If the description length is greater than 0, it allocates memory for the description and fills it with random values.
    - It assigns a random value to `self->since_slot` using `fd_rng_ulong`.
- **Output**: Returns a pointer to the initialized `fd_feature_entry_t` structure.
- **Functions called**:
    - [`fd_feature_entry_new`](fd_types.c.driver.md#fd_feature_entry_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_firedancer\_bank\_generate<!-- {{#callable:fd_firedancer_bank_generate}} -->
Generates a new `fd_firedancer_bank_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_firedancer_bank_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_firedancer_bank_t` type and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_firedancer_bank_t` structure.
    - Various sub-structures within `fd_firedancer_bank_t` are generated using dedicated functions, each of which also updates `alloc_mem`.
    - Random values are assigned to several fields of the `fd_firedancer_bank_t` structure using the random number generator.
- **Output**: Returns a pointer to the initialized `fd_firedancer_bank_t` structure.
- **Functions called**:
    - [`fd_firedancer_bank_new`](fd_types.c.driver.md#fd_firedancer_bank_new)
    - [`fd_stakes_generate`](#fd_stakes_generate)
    - [`fd_recent_block_hashes_generate`](#fd_recent_block_hashes_generate)
    - [`fd_clock_timestamp_votes_generate`](#fd_clock_timestamp_votes_generate)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_fee_rate_governor_generate`](#fd_fee_rate_governor_generate)
    - [`fd_inflation_generate`](#fd_inflation_generate)
    - [`fd_epoch_schedule_generate`](#fd_epoch_schedule_generate)
    - [`fd_rent_generate`](#fd_rent_generate)
    - [`fd_vote_accounts_generate`](#fd_vote_accounts_generate)
    - [`fd_sol_sysvar_last_restart_slot_generate`](#fd_sol_sysvar_last_restart_slot_generate)


---
### fd\_cluster\_type\_generate<!-- {{#callable:fd_cluster_type_generate}} -->
Generates a new `fd_cluster_type_t` structure and assigns a random discriminant value.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_cluster_type_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate the discriminant value.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_cluster_type_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_cluster_type_t` structure.
    - It calls [`fd_cluster_type_new`](fd_types.h.driver.md#fd_cluster_type_new) to initialize the structure.
    - It generates a random discriminant value using `fd_rng_uint` and assigns it to the `discriminant` field of the structure.
- **Output**: Returns a pointer to the initialized `fd_cluster_type_t` structure.
- **Functions called**:
    - [`fd_cluster_type_new`](fd_types.h.driver.md#fd_cluster_type_new)


---
### fd\_rent\_fresh\_account\_generate<!-- {{#callable:fd_rent_fresh_account_generate}} -->
Generates a fresh account for rent with a unique partition and public key.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_rent_fresh_account_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the account.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_rent_fresh_account_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_rent_fresh_account_t` structure.
    - The function calls [`fd_rent_fresh_account_new`](fd_types.h.driver.md#fd_rent_fresh_account_new) to initialize the account structure.
    - A random partition number is generated and assigned to the `partition` field of the account.
    - The function calls [`fd_pubkey_generate`](#fd_pubkey_generate) to generate a new public key for the account.
    - A random value is generated for the `present` field of the account.
- **Output**: Returns a pointer to the initialized `fd_rent_fresh_account_t` structure.
- **Functions called**:
    - [`fd_rent_fresh_account_new`](fd_types.h.driver.md#fd_rent_fresh_account_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_rent\_fresh\_accounts\_generate<!-- {{#callable:fd_rent_fresh_accounts_generate}} -->
Generates fresh rent accounts with randomized properties.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_rent_fresh_accounts_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the account properties.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_rent_fresh_accounts_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_rent_fresh_accounts_t` structure.
    - It initializes the `fd_rent_fresh_accounts_t` structure by calling `fd_rent_fresh_accounts_new(mem)`.
    - It generates a random total count of accounts using `fd_rng_ulong(rng)`.
    - It generates a random length for fresh accounts, ensuring it does not exceed 8.
    - If the length of fresh accounts is greater than zero, it allocates memory for the fresh accounts and initializes each account in a loop.
    - For each fresh account, it calls [`fd_rent_fresh_account_new`](fd_types.h.driver.md#fd_rent_fresh_account_new) and [`fd_rent_fresh_account_generate`](#fd_rent_fresh_account_generate) to initialize and populate the account data.
- **Output**: Returns a pointer to the initialized `fd_rent_fresh_accounts_t` structure.
- **Functions called**:
    - [`fd_rent_fresh_accounts_new`](fd_types.c.driver.md#fd_rent_fresh_accounts_new)
    - [`fd_rent_fresh_account_new`](fd_types.h.driver.md#fd_rent_fresh_account_new)
    - [`fd_rent_fresh_account_generate`](#fd_rent_fresh_account_generate)


---
### fd\_epoch\_bank\_generate<!-- {{#callable:fd_epoch_bank_generate}} -->
Generates a new `fd_epoch_bank_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_epoch_bank_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_epoch_bank_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_epoch_bank_t` structure.
    - It calls [`fd_epoch_bank_new`](fd_types.c.driver.md#fd_epoch_bank_new) to initialize the `fd_epoch_bank_t` structure.
    - It generates stakes using [`fd_stakes_generate`](#fd_stakes_generate).
    - Random values are generated for various fields of the `fd_epoch_bank_t` structure using the provided `rng`.
    - It generates inflation parameters using [`fd_inflation_generate`](#fd_inflation_generate).
    - It generates epoch schedule parameters using [`fd_epoch_schedule_generate`](#fd_epoch_schedule_generate).
    - It generates rent parameters using [`fd_rent_generate`](#fd_rent_generate).
    - It sets additional fields related to epoch and cluster type.
    - Finally, it generates vote accounts using [`fd_vote_accounts_generate`](#fd_vote_accounts_generate).
- **Output**: Returns a pointer to the initialized `fd_epoch_bank_t` structure.
- **Functions called**:
    - [`fd_epoch_bank_new`](fd_types.c.driver.md#fd_epoch_bank_new)
    - [`fd_stakes_generate`](#fd_stakes_generate)
    - [`fd_inflation_generate`](#fd_inflation_generate)
    - [`fd_epoch_schedule_generate`](#fd_epoch_schedule_generate)
    - [`fd_rent_generate`](#fd_rent_generate)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_vote_accounts_generate`](#fd_vote_accounts_generate)


---
### fd\_stake\_reward\_generate<!-- {{#callable:fd_stake_reward_generate}} -->
Generates a new `fd_stake_reward_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_stake_reward_t` structure will be initialized.
    - `alloc_mem`: A double pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_reward_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_reward_t` structure.
    - It calls [`fd_stake_reward_new`](fd_types.h.driver.md#fd_stake_reward_new) to initialize the structure.
    - Random values are generated for the `prev`, `next`, and `parent` fields using `fd_rng_ulong`.
    - A public key is generated for the `stake_pubkey` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - Random values are generated for the `credits_observed`, `lamports`, and `valid` fields.
- **Output**: Returns a pointer to the initialized `fd_stake_reward_t` structure.
- **Functions called**:
    - [`fd_stake_reward_new`](fd_types.h.driver.md#fd_stake_reward_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_vote\_reward\_generate<!-- {{#callable:fd_vote_reward_generate}} -->
Generates a new `fd_vote_reward_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_vote_reward_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_reward_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_reward_t` structure.
    - It calls [`fd_vote_reward_new`](fd_types.h.driver.md#fd_vote_reward_new) to initialize the structure.
    - It generates a new public key using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It assigns a random value to `vote_rewards` using `fd_rng_ulong`.
    - It assigns a random value to `commission` using `fd_rng_uchar`.
    - It assigns a random value to `needs_store` using `fd_rng_uchar`.
    - Finally, it returns the pointer to the initialized `fd_vote_reward_t` structure.
- **Output**: Returns a pointer to the initialized `fd_vote_reward_t` structure.
- **Functions called**:
    - [`fd_vote_reward_new`](fd_types.h.driver.md#fd_vote_reward_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_point\_value\_generate<!-- {{#callable:fd_point_value_generate}} -->
Generates a new `fd_point_value_t` structure with random rewards and points.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_point_value_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_point_value_t` type to access its fields.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_point_value_t` structure.
    - It calls `fd_point_value_new(mem)` to initialize the structure.
    - It generates a random value for `self->rewards` using `fd_rng_ulong(rng)`.
    - It generates a random value for `self->points` using `fd_rng_uint128(rng)`.
    - Finally, it returns the pointer to the initialized `fd_point_value_t` structure.
- **Output**: Returns a pointer to the initialized `fd_point_value_t` structure.
- **Functions called**:
    - [`fd_point_value_new`](fd_types.h.driver.md#fd_point_value_new)


---
### fd\_partitioned\_stake\_rewards\_generate<!-- {{#callable:fd_partitioned_stake_rewards_generate}} -->
Generates partitioned stake rewards based on random values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_partitioned_stake_rewards_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the stake rewards.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_partitioned_stake_rewards_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_partitioned_stake_rewards_t` structure.
    - The [`fd_partitioned_stake_rewards_new`](fd_types.c.driver.md#fd_partitioned_stake_rewards_new) function is called to initialize the structure.
    - A random number is generated to determine the number of partitions, which is limited to a maximum of 8.
    - A loop iterates 4096 times to generate random lengths for each partition and accumulates the total count of rewards.
    - The [`fd_partitioned_stake_rewards_pool_join_new`](fd_types.h.driver.md#fd_partitioned_stake_rewards_pool_join_new) function is called to create a new pool for the rewards based on the total count.
    - The [`fd_partitioned_stake_rewards_dlist_join_new`](fd_types.h.driver.md#fd_partitioned_stake_rewards_dlist_join_new) function is called to create a doubly linked list for the partitions.
    - Another loop iterates over the number of partitions, initializing each partition and generating the corresponding stake rewards.
    - For each partition, a nested loop generates the specified number of stake rewards and adds them to the corresponding partition.
- **Output**: Returns a pointer to the initialized `fd_partitioned_stake_rewards_t` structure.
- **Functions called**:
    - [`fd_partitioned_stake_rewards_new`](fd_types.c.driver.md#fd_partitioned_stake_rewards_new)
    - [`fd_partitioned_stake_rewards_pool_join_new`](fd_types.h.driver.md#fd_partitioned_stake_rewards_pool_join_new)
    - [`fd_partitioned_stake_rewards_dlist_join_new`](fd_types.h.driver.md#fd_partitioned_stake_rewards_dlist_join_new)
    - [`fd_stake_reward_new`](fd_types.h.driver.md#fd_stake_reward_new)
    - [`fd_stake_reward_generate`](#fd_stake_reward_generate)


---
### fd\_stake\_reward\_calculation\_partitioned\_generate<!-- {{#callable:fd_stake_reward_calculation_partitioned_generate}} -->
Generates a partitioned stake reward calculation structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_reward_calculation_partitioned_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_reward_calculation_partitioned_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_reward_calculation_partitioned_t` structure.
    - The function initializes the structure by calling [`fd_stake_reward_calculation_partitioned_new`](fd_types.c.driver.md#fd_stake_reward_calculation_partitioned_new).
    - It generates partitioned stake rewards by calling [`fd_partitioned_stake_rewards_generate`](#fd_partitioned_stake_rewards_generate) with the updated `alloc_mem` and `rng`.
    - Finally, it assigns a random value to `total_stake_rewards_lamports` using `fd_rng_ulong`.
- **Output**: Returns a pointer to the initialized `fd_stake_reward_calculation_partitioned_t` structure.
- **Functions called**:
    - [`fd_stake_reward_calculation_partitioned_new`](fd_types.c.driver.md#fd_stake_reward_calculation_partitioned_new)
    - [`fd_partitioned_stake_rewards_generate`](#fd_partitioned_stake_rewards_generate)


---
### fd\_stake\_reward\_calculation\_generate<!-- {{#callable:fd_stake_reward_calculation_generate}} -->
Generates a stake reward calculation structure with a specified number of stake rewards.
- **Inputs**:
    - `mem`: A pointer to a memory location where the stake reward calculation structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the stake rewards.
- **Control Flow**:
    - The function begins by casting the input memory pointer to a `fd_stake_reward_calculation_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_reward_calculation_t` structure.
    - The function initializes the new stake reward calculation structure using [`fd_stake_reward_calculation_new`](fd_types.c.driver.md#fd_stake_reward_calculation_new).
    - A random length for the stake rewards list is generated, limited to a maximum of 7.
    - A pool for the stake rewards is created using [`fd_stake_reward_calculation_pool_join_new`](fd_types.h.driver.md#fd_stake_reward_calculation_pool_join_new).
    - A doubly linked list for the stake rewards is created using [`fd_stake_reward_calculation_dlist_join_new`](fd_types.h.driver.md#fd_stake_reward_calculation_dlist_join_new).
    - A loop iterates over the number of stake rewards, generating each reward using [`fd_stake_reward_generate`](#fd_stake_reward_generate) and adding it to the list.
    - Finally, a total stake rewards value is generated and assigned to the structure.
- **Output**: Returns a pointer to the initialized memory containing the `fd_stake_reward_calculation_t` structure.
- **Functions called**:
    - [`fd_stake_reward_calculation_new`](fd_types.c.driver.md#fd_stake_reward_calculation_new)
    - [`fd_stake_reward_calculation_pool_join_new`](fd_types.h.driver.md#fd_stake_reward_calculation_pool_join_new)
    - [`fd_stake_reward_calculation_dlist_join_new`](fd_types.h.driver.md#fd_stake_reward_calculation_dlist_join_new)
    - [`fd_stake_reward_new`](fd_types.h.driver.md#fd_stake_reward_new)
    - [`fd_stake_reward_generate`](#fd_stake_reward_generate)


---
### fd\_calculate\_stake\_vote\_rewards\_result\_generate<!-- {{#callable:fd_calculate_stake_vote_rewards_result_generate}} -->
Generates a result structure for stake and vote rewards calculation.
- **Inputs**:
    - `mem`: A pointer to the memory location where the result structure will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the result structure.
    - It initializes the result structure by calling [`fd_calculate_stake_vote_rewards_result_new`](fd_types.c.driver.md#fd_calculate_stake_vote_rewards_result_new).
    - It generates stake reward calculations by calling [`fd_stake_reward_calculation_generate`](#fd_stake_reward_calculation_generate).
    - It generates a random length for the vote reward map and initializes a new map for vote rewards.
    - It iterates over the generated length to create and insert vote reward nodes into the map.
- **Output**: Returns a pointer to the memory location containing the generated stake vote rewards result structure.
- **Functions called**:
    - [`fd_calculate_stake_vote_rewards_result_new`](fd_types.c.driver.md#fd_calculate_stake_vote_rewards_result_new)
    - [`fd_stake_reward_calculation_generate`](#fd_stake_reward_calculation_generate)
    - [`fd_vote_reward_t_map_join_new`](fd_types.h.driver.md#fd_vote_reward_t_map_join_new)
    - [`fd_vote_reward_generate`](#fd_vote_reward_generate)


---
### fd\_calculate\_validator\_rewards\_result\_generate<!-- {{#callable:fd_calculate_validator_rewards_result_generate}} -->
Generates a new `fd_calculate_validator_rewards_result_t` structure with calculated rewards.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_calculate_validator_rewards_result_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_calculate_validator_rewards_result_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_calculate_validator_rewards_result_t` structure.
    - It calls [`fd_calculate_validator_rewards_result_new`](fd_types.c.driver.md#fd_calculate_validator_rewards_result_new) to initialize the structure pointed to by `self`.
    - It calls [`fd_calculate_stake_vote_rewards_result_generate`](#fd_calculate_stake_vote_rewards_result_generate) to generate the stake vote rewards result and store it in `self->calculate_stake_vote_rewards_result`.
    - It calls [`fd_point_value_generate`](#fd_point_value_generate) to generate a point value and store it in `self->point_value`.
- **Output**: Returns a pointer to the memory location of the generated `fd_calculate_validator_rewards_result_t` structure.
- **Functions called**:
    - [`fd_calculate_validator_rewards_result_new`](fd_types.c.driver.md#fd_calculate_validator_rewards_result_new)
    - [`fd_calculate_stake_vote_rewards_result_generate`](#fd_calculate_stake_vote_rewards_result_generate)
    - [`fd_point_value_generate`](#fd_point_value_generate)


---
### fd\_calculate\_rewards\_and\_distribute\_vote\_rewards\_result\_generate<!-- {{#callable:fd_calculate_rewards_and_distribute_vote_rewards_result_generate}} -->
Generates and distributes rewards for voting and staking.
- **Inputs**:
    - `mem`: A pointer to the memory location where the result structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type for rewards distribution.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_calculate_rewards_and_distribute_vote_rewards_result_t` structure.
    - The function initializes the structure by calling [`fd_calculate_rewards_and_distribute_vote_rewards_result_new`](fd_types.c.driver.md#fd_calculate_rewards_and_distribute_vote_rewards_result_new).
    - It generates random values for `total_rewards` and `distributed_rewards` using the provided random number generator.
    - The function generates a point value and a partitioned stake reward calculation, updating the `alloc_mem` pointer accordingly.
- **Output**: Returns a pointer to the updated memory location containing the rewards distribution result.
- **Functions called**:
    - [`fd_calculate_rewards_and_distribute_vote_rewards_result_new`](fd_types.c.driver.md#fd_calculate_rewards_and_distribute_vote_rewards_result_new)
    - [`fd_point_value_generate`](#fd_point_value_generate)
    - [`fd_stake_reward_calculation_partitioned_generate`](#fd_stake_reward_calculation_partitioned_generate)


---
### fd\_partitioned\_rewards\_calculation\_generate<!-- {{#callable:fd_partitioned_rewards_calculation_generate}} -->
Generates a partitioned rewards calculation structure.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_partitioned_rewards_calculation_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_partitioned_rewards_calculation_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_partitioned_rewards_calculation_t` structure.
    - The [`fd_partitioned_rewards_calculation_new`](fd_types.c.driver.md#fd_partitioned_rewards_calculation_new) function is called to initialize the structure.
    - A random length for the vote reward map is generated, constrained to a maximum of 8.
    - A new vote reward map pool is created using [`fd_vote_reward_t_map_join_new`](fd_types.h.driver.md#fd_vote_reward_t_map_join_new).
    - A loop iterates over the generated length, acquiring nodes from the vote reward map pool and generating vote rewards for each node.
    - The generated nodes are inserted into the vote reward map.
    - The [`fd_stake_reward_calculation_partitioned_generate`](#fd_stake_reward_calculation_partitioned_generate) function is called to generate stake rewards by partition.
    - Several random values are generated and assigned to the fields of the `fd_partitioned_rewards_calculation_t` structure.
    - Finally, the function returns the pointer to the initialized memory.
- **Output**: Returns a pointer to the initialized `fd_partitioned_rewards_calculation_t` structure.
- **Functions called**:
    - [`fd_partitioned_rewards_calculation_new`](fd_types.c.driver.md#fd_partitioned_rewards_calculation_new)
    - [`fd_vote_reward_t_map_join_new`](fd_types.h.driver.md#fd_vote_reward_t_map_join_new)
    - [`fd_vote_reward_generate`](#fd_vote_reward_generate)
    - [`fd_stake_reward_calculation_partitioned_generate`](#fd_stake_reward_calculation_partitioned_generate)
    - [`fd_point_value_generate`](#fd_point_value_generate)


---
### fd\_start\_block\_height\_and\_rewards\_generate<!-- {{#callable:fd_start_block_height_and_rewards_generate}} -->
Generates the starting block height and associated rewards for a staking system.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_start_block_height_and_rewards_t` structure will be initialized.
    - `alloc_mem`: A double pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the block height and rewards.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_start_block_height_and_rewards_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_start_block_height_and_rewards_t` structure.
    - The function calls [`fd_start_block_height_and_rewards_new`](fd_types.c.driver.md#fd_start_block_height_and_rewards_new) to initialize the structure.
    - A random block height is generated using `fd_rng_ulong` and assigned to `self->distribution_starting_block_height`.
    - The function then calls [`fd_partitioned_stake_rewards_generate`](#fd_partitioned_stake_rewards_generate) to generate the stake rewards associated with the block height.
- **Output**: Returns a pointer to the initialized `fd_start_block_height_and_rewards_t` structure.
- **Functions called**:
    - [`fd_start_block_height_and_rewards_new`](fd_types.c.driver.md#fd_start_block_height_and_rewards_new)
    - [`fd_partitioned_stake_rewards_generate`](#fd_partitioned_stake_rewards_generate)


---
### fd\_fd\_epoch\_reward\_status\_inner\_generate<!-- {{#callable:fd_fd_epoch_reward_status_inner_generate}} -->
Generates the inner state of epoch reward status, initializing memory and generating associated rewards.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_fd_epoch_reward_status_inner_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values during the initialization.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_fd_epoch_reward_status_inner_t` type to access its fields.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_fd_epoch_reward_status_inner_t` structure.
    - The function calls [`fd_fd_epoch_reward_status_inner_new`](fd_types.c.driver.md#fd_fd_epoch_reward_status_inner_new) to initialize the structure.
    - It then calls [`fd_start_block_height_and_rewards_generate`](#fd_start_block_height_and_rewards_generate) to generate the active rewards for the epoch.
- **Output**: Returns a pointer to the initialized `fd_fd_epoch_reward_status_inner_t` structure.
- **Functions called**:
    - [`fd_fd_epoch_reward_status_inner_new`](fd_types.c.driver.md#fd_fd_epoch_reward_status_inner_new)
    - [`fd_start_block_height_and_rewards_generate`](#fd_start_block_height_and_rewards_generate)


---
### fd\_epoch\_reward\_status\_inner\_generate<!-- {{#callable:fd_epoch_reward_status_inner_generate}} -->
Generates the inner state of epoch reward status based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_epoch_reward_status_inner_t` that will be populated.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which case to execute in the switch statement.
    - `rng`: A pointer to a random number generator of type `fd_rng_t` used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value using a switch statement.
    - If the `discriminant` is 0, it calls the function [`fd_start_block_height_and_rewards_generate`](#fd_start_block_height_and_rewards_generate) with the `Active` member of `self`, `alloc_mem`, and `rng` as arguments.
    - The function exits after executing the corresponding case.
- **Output**: The function does not return a value; it modifies the `self` structure directly based on the generated data.
- **Functions called**:
    - [`fd_start_block_height_and_rewards_generate`](#fd_start_block_height_and_rewards_generate)


---
### fd\_epoch\_reward\_status\_generate<!-- {{#callable:fd_epoch_reward_status_generate}} -->
Generates a new `fd_epoch_reward_status_t` structure and initializes its fields.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_epoch_reward_status_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure's fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_epoch_reward_status_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_epoch_reward_status_t` structure.
    - The function calls [`fd_epoch_reward_status_new`](fd_types.c.driver.md#fd_epoch_reward_status_new) to initialize the structure pointed to by `self`.
    - A random discriminant value is generated using the random number generator, which will determine the inner structure to be initialized.
    - The function calls [`fd_epoch_reward_status_inner_generate`](#fd_epoch_reward_status_inner_generate) with the inner structure and the generated discriminant to further initialize the inner fields.
- **Output**: Returns a pointer to the initialized `fd_epoch_reward_status_t` structure.
- **Functions called**:
    - [`fd_epoch_reward_status_new`](fd_types.c.driver.md#fd_epoch_reward_status_new)
    - [`fd_epoch_reward_status_inner_generate`](#fd_epoch_reward_status_inner_generate)


---
### fd\_slot\_bank\_generate<!-- {{#callable:fd_slot_bank_generate}} -->
Generates a new `fd_slot_bank_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_slot_bank_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_slot_bank_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_slot_bank_t` structure.
    - The function initializes the `fd_slot_bank_t` structure by calling `fd_slot_bank_new(mem)`.
    - It generates timestamp votes using [`fd_clock_timestamp_votes_generate`](#fd_clock_timestamp_votes_generate).
    - Random values are generated for various fields of the `fd_slot_bank_t` structure using the provided random number generator.
    - The function generates hashes and other necessary data for the bank's state.
    - Finally, it returns the pointer to the initialized `fd_slot_bank_t` structure.
- **Output**: Returns a pointer to the initialized `fd_slot_bank_t` structure.
- **Functions called**:
    - [`fd_slot_bank_new`](fd_types.c.driver.md#fd_slot_bank_new)
    - [`fd_clock_timestamp_votes_generate`](#fd_clock_timestamp_votes_generate)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_fee_rate_governor_generate`](#fd_fee_rate_governor_generate)
    - [`fd_vote_accounts_generate`](#fd_vote_accounts_generate)
    - [`fd_sol_sysvar_last_restart_slot_generate`](#fd_sol_sysvar_last_restart_slot_generate)
    - [`fd_account_keys_generate`](#fd_account_keys_generate)
    - [`fd_slot_lthash_generate`](#fd_slot_lthash_generate)
    - [`fd_block_hash_queue_generate`](#fd_block_hash_queue_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_hard_forks_generate`](#fd_hard_forks_generate)
    - [`fd_rent_fresh_accounts_generate`](#fd_rent_fresh_accounts_generate)
    - [`fd_epoch_reward_status_generate`](#fd_epoch_reward_status_generate)


---
### fd\_prev\_epoch\_inflation\_rewards\_generate<!-- {{#callable:fd_prev_epoch_inflation_rewards_generate}} -->
Generates inflation rewards for the previous epoch.
- **Inputs**:
    - `mem`: A pointer to a memory location where the inflation rewards structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the inflation rewards.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type for inflation rewards.
    - It updates the allocation memory pointer to account for the size of the inflation rewards structure.
    - The function initializes the inflation rewards structure by calling [`fd_prev_epoch_inflation_rewards_new`](fd_types.h.driver.md#fd_prev_epoch_inflation_rewards_new).
    - Random values for validator rewards, previous epoch duration, validator rate, and foundation rate are generated using the provided random number generator.
- **Output**: Returns a pointer to the initialized memory containing the inflation rewards structure.
- **Functions called**:
    - [`fd_prev_epoch_inflation_rewards_new`](fd_types.h.driver.md#fd_prev_epoch_inflation_rewards_new)


---
### fd\_vote\_generate<!-- {{#callable:fd_vote_generate}} -->
Generates a new `fd_vote_t` structure with randomized slots and a hash.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_vote_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_t` structure and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_t` structure.
    - A random number of slots (up to 7) is generated using the random number generator.
    - For each slot, a new slot value is pushed to the `slots` deque, and its value is mutated using [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate).
    - A hash for the vote is generated and stored in the `hash` field of the `fd_vote_t` structure.
    - A random decision is made to either assign a timestamp or set it to NULL, with the timestamp being mutated if assigned.
- **Output**: Returns a pointer to the initialized `fd_vote_t` structure.
- **Functions called**:
    - [`fd_vote_new`](fd_types.c.driver.md#fd_vote_new)
    - [`deq_ulong_join_new`](fd_types.h.driver.md#deq_ulong_join_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_vote\_init\_generate<!-- {{#callable:fd_vote_init_generate}} -->
Initializes a voting structure by generating public keys and setting a commission.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_vote_init_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_init_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_init_t` structure.
    - It calls [`fd_vote_init_new`](fd_types.h.driver.md#fd_vote_init_new) to initialize the `fd_vote_init_t` structure.
    - It generates a public key for `node_pubkey` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates a public key for `authorized_voter` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates a public key for `authorized_withdrawer` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It assigns a random commission value to the `commission` field using `fd_rng_uchar`.
- **Output**: Returns a pointer to the initialized `fd_vote_init_t` structure.
- **Functions called**:
    - [`fd_vote_init_new`](fd_types.h.driver.md#fd_vote_init_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_vote\_authorize\_generate<!-- {{#callable:fd_vote_authorize_generate}} -->
Generates a new `fd_vote_authorize_t` structure and initializes its `discriminant` field.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_authorize_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_authorize_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_vote_authorize_t` structure.
    - The function calls `fd_vote_authorize_new(mem)` to initialize the structure.
    - It generates a random `discriminant` value using the random number generator and assigns it to `self->discriminant`.
- **Output**: Returns a pointer to the initialized `fd_vote_authorize_t` structure.
- **Functions called**:
    - [`fd_vote_authorize_new`](fd_types.h.driver.md#fd_vote_authorize_new)


---
### fd\_vote\_authorize\_pubkey\_generate<!-- {{#callable:fd_vote_authorize_pubkey_generate}} -->
Generates a new `fd_vote_authorize_pubkey_t` structure with a public key and vote authorization.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_authorize_pubkey_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_authorize_pubkey_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_authorize_pubkey_t` structure.
    - It calls `fd_vote_authorize_pubkey_new(mem)` to initialize the structure.
    - It generates a public key by calling `fd_pubkey_generate(&self->pubkey, alloc_mem, rng)`.
    - It generates vote authorization data by calling `fd_vote_authorize_generate(&self->vote_authorize, alloc_mem, rng)`.
    - Finally, it returns the pointer to the initialized `fd_vote_authorize_pubkey_t` structure.
- **Output**: Returns a pointer to the initialized `fd_vote_authorize_pubkey_t` structure.
- **Functions called**:
    - [`fd_vote_authorize_pubkey_new`](fd_types.c.driver.md#fd_vote_authorize_pubkey_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_vote_authorize_generate`](#fd_vote_authorize_generate)


---
### fd\_vote\_switch\_generate<!-- {{#callable:fd_vote_switch_generate}} -->
Generates a new `fd_vote_switch_t` structure, populating it with a vote and a hash.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_switch_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_switch_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_vote_switch_t` structure.
    - It calls `fd_vote_switch_new(mem)` to initialize the `fd_vote_switch_t` structure.
    - It generates a vote by calling `fd_vote_generate(&self->vote, alloc_mem, rng)`.
    - It generates a hash by calling `fd_hash_generate(&self->hash, alloc_mem, rng)`.
- **Output**: Returns a pointer to the initialized `fd_vote_switch_t` structure.
- **Functions called**:
    - [`fd_vote_switch_new`](fd_types.c.driver.md#fd_vote_switch_new)
    - [`fd_vote_generate`](#fd_vote_generate)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_update\_vote\_state\_switch\_generate<!-- {{#callable:fd_update_vote_state_switch_generate}} -->
Generates a new `fd_update_vote_state_switch_t` structure and populates it with a vote state update and a hash.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_update_vote_state_switch_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_update_vote_state_switch_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_update_vote_state_switch_t` structure.
    - It calls [`fd_update_vote_state_switch_new`](fd_types.c.driver.md#fd_update_vote_state_switch_new) to initialize the `self` structure.
    - It generates a new vote state update by calling [`fd_vote_state_update_generate`](#fd_vote_state_update_generate) and passing the appropriate parameters.
    - It generates a hash for the `self` structure by calling [`fd_hash_generate`](#fd_hash_generate).
    - Finally, it returns the pointer to the initialized `fd_update_vote_state_switch_t` structure.
- **Output**: Returns a pointer to the initialized `fd_update_vote_state_switch_t` structure.
- **Functions called**:
    - [`fd_update_vote_state_switch_new`](fd_types.c.driver.md#fd_update_vote_state_switch_new)
    - [`fd_vote_state_update_generate`](#fd_vote_state_update_generate)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_vote\_authorize\_with\_seed\_args\_generate<!-- {{#callable:fd_vote_authorize_with_seed_args_generate}} -->
Generates a new `fd_vote_authorize_with_seed_args_t` structure with randomized values for its fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_vote_authorize_with_seed_args_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_vote_authorize_with_seed_args_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_vote_authorize_with_seed_args_t` structure.
    - It calls [`fd_vote_authorize_generate`](#fd_vote_authorize_generate) to initialize the `authorization_type` field.
    - It generates a public key for `current_authority_derived_key_owner`.
    - It randomly determines the length of `current_authority_derived_key_seed` and allocates memory for it if the length is greater than zero.
    - If the seed length is non-zero, it populates `current_authority_derived_key_seed` with random values.
    - Finally, it generates a public key for `new_authority`.
- **Output**: Returns a pointer to the initialized `fd_vote_authorize_with_seed_args_t` structure.
- **Functions called**:
    - [`fd_vote_authorize_with_seed_args_new`](fd_types.c.driver.md#fd_vote_authorize_with_seed_args_new)
    - [`fd_vote_authorize_generate`](#fd_vote_authorize_generate)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_vote\_authorize\_checked\_with\_seed\_args\_generate<!-- {{#callable:fd_vote_authorize_checked_with_seed_args_generate}} -->
Generates and initializes a `fd_vote_authorize_checked_with_seed_args_t` structure with various fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_authorize_checked_with_seed_args_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_authorize_checked_with_seed_args_t` structure.
    - It calls [`fd_vote_authorize_generate`](#fd_vote_authorize_generate) to initialize the `authorization_type` field.
    - It generates a public key for `current_authority_derived_key_owner`.
    - It generates a random length for `current_authority_derived_key_seed` and allocates memory for it if the length is greater than zero.
    - If the seed length is greater than zero, it populates `current_authority_derived_key_seed` with random values; otherwise, it sets it to NULL.
- **Output**: Returns a pointer to the initialized `fd_vote_authorize_checked_with_seed_args_t` structure.
- **Functions called**:
    - [`fd_vote_authorize_checked_with_seed_args_new`](fd_types.c.driver.md#fd_vote_authorize_checked_with_seed_args_new)
    - [`fd_vote_authorize_generate`](#fd_vote_authorize_generate)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_vote\_instruction\_inner\_generate<!-- {{#callable:fd_vote_instruction_inner_generate}} -->
Generates various components of a voting instruction based on a discriminant value.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_vote_instruction_inner_t` where the generated data will be stored.
    - `alloc_mem`: A double pointer to memory allocation space for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which specific voting instruction to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value to determine which case to execute.
    - For each case (0 to 15), it calls a specific generation function or assigns a random value to a member of the `self` structure.
    - If the `discriminant` is 0, it calls [`fd_vote_init_generate`](#fd_vote_init_generate) to initialize the account.
    - If the `discriminant` is 1, it calls [`fd_vote_authorize_pubkey_generate`](#fd_vote_authorize_pubkey_generate) to generate an authorization public key.
    - If the `discriminant` is 2, it calls [`fd_vote_generate`](#fd_vote_generate) to generate a vote.
    - For cases 3 and 5, it assigns random values to `withdraw` and `update_commission` respectively.
    - For cases 6 to 15, it calls various other generation functions to populate the `self` structure with appropriate data.
- **Output**: The function does not return a value; instead, it populates the `self` structure with generated data based on the specified `discriminant`.
- **Functions called**:
    - [`fd_vote_init_generate`](#fd_vote_init_generate)
    - [`fd_vote_authorize_pubkey_generate`](#fd_vote_authorize_pubkey_generate)
    - [`fd_vote_generate`](#fd_vote_generate)
    - [`fd_vote_switch_generate`](#fd_vote_switch_generate)
    - [`fd_vote_authorize_generate`](#fd_vote_authorize_generate)
    - [`fd_vote_state_update_generate`](#fd_vote_state_update_generate)
    - [`fd_update_vote_state_switch_generate`](#fd_update_vote_state_switch_generate)
    - [`fd_vote_authorize_with_seed_args_generate`](#fd_vote_authorize_with_seed_args_generate)
    - [`fd_vote_authorize_checked_with_seed_args_generate`](#fd_vote_authorize_checked_with_seed_args_generate)
    - [`fd_compact_vote_state_update_generate`](#fd_compact_vote_state_update_generate)
    - [`fd_compact_vote_state_update_switch_generate`](#fd_compact_vote_state_update_switch_generate)
    - [`fd_tower_sync_switch_generate`](#fd_tower_sync_switch_generate)


---
### fd\_vote\_instruction\_generate<!-- {{#callable:fd_vote_instruction_generate}} -->
Generates a new `fd_vote_instruction_t` structure with a random discriminant and initializes its inner components.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_vote_instruction_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_instruction_t` type and increments the `alloc_mem` pointer by the size of `fd_vote_instruction_t`.
    - It calls [`fd_vote_instruction_new`](fd_types.c.driver.md#fd_vote_instruction_new) to initialize the new instruction structure.
    - A random discriminant value is generated using the random number generator, which determines the type of vote instruction to create.
    - If the discriminant is 14 or 15, a new random value is generated until it falls within the valid range.
    - The function then calls [`fd_vote_instruction_inner_generate`](#fd_vote_instruction_inner_generate) to initialize the inner structure based on the discriminant.
- **Output**: Returns a pointer to the initialized `fd_vote_instruction_t` structure.
- **Functions called**:
    - [`fd_vote_instruction_new`](fd_types.c.driver.md#fd_vote_instruction_new)
    - [`fd_vote_instruction_inner_generate`](#fd_vote_instruction_inner_generate)


---
### fd\_system\_program\_instruction\_create\_account\_generate<!-- {{#callable:fd_system_program_instruction_create_account_generate}} -->
Generates a new account creation instruction for the system program.
- **Inputs**:
    - `mem`: A pointer to the memory location where the account creation instruction will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the instruction.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type for account creation.
    - It updates the allocation memory pointer to account for the size of the account creation structure.
    - It initializes the account creation structure by calling [`fd_system_program_instruction_create_account_new`](fd_types.h.driver.md#fd_system_program_instruction_create_account_new).
    - Random values for `lamports` and `space` are generated using the random number generator.
    - A public key for the account owner is generated by calling [`fd_pubkey_generate`](#fd_pubkey_generate).
- **Output**: Returns a pointer to the memory location containing the newly created account creation instruction.
- **Functions called**:
    - [`fd_system_program_instruction_create_account_new`](fd_types.h.driver.md#fd_system_program_instruction_create_account_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_system\_program\_instruction\_create\_account\_with\_seed\_generate<!-- {{#callable:fd_system_program_instruction_create_account_with_seed_generate}} -->
Generates a system program instruction to create an account with a seed.
- **Inputs**:
    - `mem`: A pointer to the memory location where the account structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type for account creation.
    - It updates the `alloc_mem` pointer to allocate space for the account structure.
    - It initializes the account structure by calling [`fd_system_program_instruction_create_account_with_seed_new`](fd_types.c.driver.md#fd_system_program_instruction_create_account_with_seed_new).
    - It generates a public key for the account base using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It randomly determines the length of the seed (up to 7) and allocates memory for it if necessary.
    - If the seed length is greater than zero, it fills the seed with random values.
    - It generates random values for `lamports` and `space` fields of the account.
    - Finally, it generates a public key for the account owner.
- **Output**: Returns a pointer to the memory location where the account structure has been created.
- **Functions called**:
    - [`fd_system_program_instruction_create_account_with_seed_new`](fd_types.c.driver.md#fd_system_program_instruction_create_account_with_seed_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_system\_program\_instruction\_allocate\_with\_seed\_generate<!-- {{#callable:fd_system_program_instruction_allocate_with_seed_generate}} -->
Allocates a `fd_system_program_instruction_allocate_with_seed` structure and generates a seed and public keys.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_system_program_instruction_allocate_with_seed` structure will be allocated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_system_program_instruction_allocate_with_seed_t` structure.
    - It updates the `alloc_mem` pointer to point to the next available memory after the size of the `fd_system_program_instruction_allocate_with_seed_t` structure.
    - It calls [`fd_system_program_instruction_allocate_with_seed_new`](fd_types.c.driver.md#fd_system_program_instruction_allocate_with_seed_new) to initialize the structure.
    - It generates a public key for the base using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates a random seed length between 0 and 7 using `fd_rng_ulong`.
    - If the seed length is greater than 0, it allocates memory for the seed and fills it with random values.
    - It generates a random space value using `fd_rng_ulong`.
    - Finally, it generates a public key for the owner using [`fd_pubkey_generate`](#fd_pubkey_generate).
- **Output**: Returns a pointer to the allocated memory containing the initialized `fd_system_program_instruction_allocate_with_seed` structure.
- **Functions called**:
    - [`fd_system_program_instruction_allocate_with_seed_new`](fd_types.c.driver.md#fd_system_program_instruction_allocate_with_seed_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_system\_program\_instruction\_assign\_with\_seed\_generate<!-- {{#callable:fd_system_program_instruction_assign_with_seed_generate}} -->
Generates a system program instruction for assigning a public key with a seed.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction data will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a specific structure type, `fd_system_program_instruction_assign_with_seed_t`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_system_program_instruction_assign_with_seed_t` structure.
    - The function then initializes the structure by calling `fd_system_program_instruction_assign_with_seed_new(mem)`.
    - A public key is generated and assigned to the `base` field of the structure using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - The length of the seed is randomly determined, and if it is non-zero, memory is allocated for the seed and filled with random values.
    - Another public key is generated for the `owner` field of the structure.
    - Finally, the function returns the original `mem` pointer.
- **Output**: Returns a pointer to the memory location containing the generated instruction data.
- **Functions called**:
    - [`fd_system_program_instruction_assign_with_seed_new`](fd_types.c.driver.md#fd_system_program_instruction_assign_with_seed_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_system\_program\_instruction\_transfer\_with\_seed\_generate<!-- {{#callable:fd_system_program_instruction_transfer_with_seed_generate}} -->
Generates a system program instruction for transferring lamports with a seed.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type for the system program instruction.
    - It updates the `alloc_mem` pointer to allocate space for the instruction structure.
    - It initializes the instruction structure using [`fd_system_program_instruction_transfer_with_seed_new`](fd_types.c.driver.md#fd_system_program_instruction_transfer_with_seed_new).
    - It generates a random value for `lamports` using `fd_rng_ulong`.
    - It generates a random length for `from_seed` using `fd_rng_ulong` and checks if it's non-zero.
    - If `from_seed_len` is non-zero, it allocates memory for `from_seed` and fills it with random values.
    - It generates a public key for `from_owner` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - Finally, it returns the original `mem` pointer.
- **Output**: Returns a pointer to the initialized memory for the system program instruction.
- **Functions called**:
    - [`fd_system_program_instruction_transfer_with_seed_new`](fd_types.c.driver.md#fd_system_program_instruction_transfer_with_seed_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_system\_program\_instruction\_inner\_generate<!-- {{#callable:fd_system_program_instruction_inner_generate}} -->
Generates a system program instruction based on a given discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_system_program_instruction_inner_t` where the generated instruction will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the allocated memory for the instruction.
    - `discriminant`: An unsigned integer that determines which type of system program instruction to generate.
    - `rng`: A pointer to a random number generator used to produce random values for the instruction.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which case to execute.
    - For each case, it calls the appropriate generation function for the specific instruction type.
    - The function handles multiple types of instructions, including creating accounts, transferring funds, and assigning accounts.
- **Output**: The function does not return a value; instead, it modifies the `self` structure to contain the generated instruction.
- **Functions called**:
    - [`fd_system_program_instruction_create_account_generate`](#fd_system_program_instruction_create_account_generate)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_system_program_instruction_create_account_with_seed_generate`](#fd_system_program_instruction_create_account_with_seed_generate)
    - [`fd_system_program_instruction_allocate_with_seed_generate`](#fd_system_program_instruction_allocate_with_seed_generate)
    - [`fd_system_program_instruction_assign_with_seed_generate`](#fd_system_program_instruction_assign_with_seed_generate)
    - [`fd_system_program_instruction_transfer_with_seed_generate`](#fd_system_program_instruction_transfer_with_seed_generate)


---
### fd\_system\_program\_instruction\_generate<!-- {{#callable:fd_system_program_instruction_generate}} -->
Generates a new `fd_system_program_instruction_t` structure with randomized fields.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_system_program_instruction_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the instruction.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_system_program_instruction_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_system_program_instruction_t` structure.
    - The function initializes the structure by calling `fd_system_program_instruction_new(mem)`.
    - A random `discriminant` value is generated to determine the type of instruction to create.
    - The function calls [`fd_system_program_instruction_inner_generate`](#fd_system_program_instruction_inner_generate) with the inner structure and the generated discriminant to populate the inner fields.
- **Output**: Returns a pointer to the allocated `fd_system_program_instruction_t` structure.
- **Functions called**:
    - [`fd_system_program_instruction_new`](fd_types.c.driver.md#fd_system_program_instruction_new)
    - [`fd_system_program_instruction_inner_generate`](#fd_system_program_instruction_inner_generate)


---
### fd\_system\_error\_generate<!-- {{#callable:fd_system_error_generate}} -->
Generates a new `fd_system_error_t` structure and assigns a random discriminant value.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_system_error_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_system_error_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_system_error_t` structure.
    - It calls the [`fd_system_error_new`](fd_types.h.driver.md#fd_system_error_new) function to initialize the new structure.
    - It assigns a random value to the `discriminant` field of the structure, which is generated using the `fd_rng_uint` function and constrained to a range of 0 to 8.
- **Output**: Returns a pointer to the allocated `fd_system_error_t` structure.
- **Functions called**:
    - [`fd_system_error_new`](fd_types.h.driver.md#fd_system_error_new)


---
### fd\_stake\_authorized\_generate<!-- {{#callable:fd_stake_authorized_generate}} -->
Generates a new `fd_stake_authorized_t` structure with initialized staker and withdrawer public keys.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_authorized_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating public keys.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_authorized_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_authorized_t` structure.
    - It calls [`fd_stake_authorized_new`](fd_types.h.driver.md#fd_stake_authorized_new) to initialize the `fd_stake_authorized_t` structure.
    - It generates a new public key for the staker by calling [`fd_pubkey_generate`](#fd_pubkey_generate) with the staker field of `self`.
    - It generates a new public key for the withdrawer by calling [`fd_pubkey_generate`](#fd_pubkey_generate) with the withdrawer field of `self`.
    - Finally, it returns the pointer to the `mem` location.
- **Output**: Returns a pointer to the initialized `fd_stake_authorized_t` structure.
- **Functions called**:
    - [`fd_stake_authorized_new`](fd_types.h.driver.md#fd_stake_authorized_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_stake\_lockup\_generate<!-- {{#callable:fd_stake_lockup_generate}} -->
Generates a new `fd_stake_lockup_t` structure with random values for its fields.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_lockup_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure's fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_lockup_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_stake_lockup_t` structure.
    - It calls `fd_stake_lockup_new(mem)` to initialize the structure.
    - It generates a random `unix_timestamp` using `fd_rng_long(rng)`.
    - It generates a random `epoch` using `fd_rng_ulong(rng)`.
    - It calls `fd_pubkey_generate(&self->custodian, alloc_mem, rng)` to generate a random public key for the custodian.
    - Finally, it returns the pointer to the `mem` location.
- **Output**: Returns a pointer to the initialized `fd_stake_lockup_t` structure.
- **Functions called**:
    - [`fd_stake_lockup_new`](fd_types.h.driver.md#fd_stake_lockup_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_stake\_instruction\_initialize\_generate<!-- {{#callable:fd_stake_instruction_initialize_generate}} -->
The `fd_stake_instruction_initialize_generate` function initializes a stake instruction structure and populates its fields.
- **Inputs**:
    - `mem`: A pointer to the memory location where the stake instruction structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_instruction_initialize_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_stake_instruction_initialize_t` structure.
    - The function calls [`fd_stake_instruction_initialize_new`](fd_types.h.driver.md#fd_stake_instruction_initialize_new) to initialize the structure.
    - It then calls [`fd_stake_authorized_generate`](#fd_stake_authorized_generate) to populate the `authorized` field of the structure.
    - Next, it calls [`fd_stake_lockup_generate`](#fd_stake_lockup_generate) to populate the `lockup` field of the structure.
    - Finally, it returns the pointer to the initialized structure.
- **Output**: The function returns a pointer to the initialized `fd_stake_instruction_initialize_t` structure.
- **Functions called**:
    - [`fd_stake_instruction_initialize_new`](fd_types.h.driver.md#fd_stake_instruction_initialize_new)
    - [`fd_stake_authorized_generate`](#fd_stake_authorized_generate)
    - [`fd_stake_lockup_generate`](#fd_stake_lockup_generate)


---
### fd\_stake\_lockup\_custodian\_args\_generate<!-- {{#callable:fd_stake_lockup_custodian_args_generate}} -->
Generates arguments for a stake lockup custodian.
- **Inputs**:
    - `mem`: A pointer to the memory location where the generated arguments will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the `fd_stake_lockup_custodian_args_t` structure.
    - It initializes the `lockup` field of the structure by calling [`fd_stake_lockup_generate`](#fd_stake_lockup_generate).
    - It initializes the `clock` field of the structure by calling [`fd_sol_sysvar_clock_generate`](#fd_sol_sysvar_clock_generate).
    - A random value is generated to determine if the `custodian` field should be assigned a new public key or set to NULL.
    - If the generated value indicates a non-null custodian, memory is allocated for the `custodian` field, and it is initialized and generated.
- **Output**: Returns a pointer to the memory location containing the generated `fd_stake_lockup_custodian_args_t` structure.
- **Functions called**:
    - [`fd_stake_lockup_custodian_args_new`](fd_types.c.driver.md#fd_stake_lockup_custodian_args_new)
    - [`fd_stake_lockup_generate`](#fd_stake_lockup_generate)
    - [`fd_sol_sysvar_clock_generate`](#fd_sol_sysvar_clock_generate)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_stake\_authorize\_generate<!-- {{#callable:fd_stake_authorize_generate}} -->
Generates a new `fd_stake_authorize_t` structure with a random discriminant.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_authorize_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_authorize_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_authorize_t` structure.
    - The function calls [`fd_stake_authorize_new`](fd_types.h.driver.md#fd_stake_authorize_new) to initialize the structure.
    - A random value is generated for the `discriminant` field of the structure using the random number generator.
- **Output**: Returns a pointer to the allocated `fd_stake_authorize_t` structure.
- **Functions called**:
    - [`fd_stake_authorize_new`](fd_types.h.driver.md#fd_stake_authorize_new)


---
### fd\_stake\_instruction\_authorize\_generate<!-- {{#callable:fd_stake_instruction_authorize_generate}} -->
Generates a new `fd_stake_instruction_authorize` structure with a public key and stake authorization.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_stake_instruction_authorize_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_instruction_authorize_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_instruction_authorize_t` structure.
    - The function calls [`fd_stake_instruction_authorize_new`](fd_types.c.driver.md#fd_stake_instruction_authorize_new) to initialize the structure.
    - It generates a public key using [`fd_pubkey_generate`](#fd_pubkey_generate) and updates the `alloc_mem` pointer.
    - It generates a stake authorization using [`fd_stake_authorize_generate`](#fd_stake_authorize_generate) and updates the `alloc_mem` pointer.
- **Output**: Returns a pointer to the initialized `fd_stake_instruction_authorize_t` structure.
- **Functions called**:
    - [`fd_stake_instruction_authorize_new`](fd_types.c.driver.md#fd_stake_instruction_authorize_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_stake_authorize_generate`](#fd_stake_authorize_generate)


---
### fd\_authorize\_with\_seed\_args\_generate<!-- {{#callable:fd_authorize_with_seed_args_generate}} -->
Generates arguments for authorizing a stake with a seed.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_vote_authorize_with_seed_args_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_vote_authorize_with_seed_args_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_authorize_with_seed_args_t` structure.
    - The function initializes the structure by calling `fd_vote_authorize_generate` to set the `authorization_type`.
    - It generates a new public key for `new_authorized_pubkey` using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - The length of the `authority_seed` is randomly determined, and if it is greater than zero, memory is allocated for it.
    - A loop fills the `authority_seed` with random values if its length is greater than zero.
    - Finally, it generates a new public key for `authority_owner`.
- **Output**: Returns a pointer to the initialized `fd_vote_authorize_with_seed_args_t` structure.
- **Functions called**:
    - [`fd_authorize_with_seed_args_new`](fd_types.c.driver.md#fd_authorize_with_seed_args_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_stake_authorize_generate`](#fd_stake_authorize_generate)


---
### fd\_authorize\_checked\_with\_seed\_args\_generate<!-- {{#callable:fd_authorize_checked_with_seed_args_generate}} -->
Generates and initializes a `fd_authorize_checked_with_seed_args_t` structure with authorization details and a seed.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_authorize_checked_with_seed_args_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_authorize_checked_with_seed_args_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the structure.
    - It calls `fd_vote_authorize_generate` to initialize the `stake_authorize` field of the structure.
    - It generates a random length for the `authority_seed` and allocates memory for it if the length is greater than zero.
    - If the `authority_seed_len` is non-zero, it populates the `authority_seed` with random values.
    - Finally, it generates a public key for the `authority_owner` field.
- **Output**: Returns a pointer to the initialized `fd_authorize_checked_with_seed_args_t` structure.
- **Functions called**:
    - [`fd_authorize_checked_with_seed_args_new`](fd_types.c.driver.md#fd_authorize_checked_with_seed_args_new)
    - [`fd_stake_authorize_generate`](#fd_stake_authorize_generate)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_lockup\_checked\_args\_generate<!-- {{#callable:fd_lockup_checked_args_generate}} -->
Generates checked arguments for a lockup structure, potentially allocating memory for timestamps.
- **Inputs**:
    - `mem`: Pointer to a memory location where the `fd_lockup_checked_args_t` structure will be initialized.
    - `alloc_mem`: Pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: Pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_lockup_checked_args_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_lockup_checked_args_t` structure.
    - The function initializes the structure by calling `fd_lockup_checked_args_new(mem)`.
    - It generates a random value to determine if the `unix_timestamp` should be allocated or set to NULL.
    - If allocated, it assigns a pointer to `unix_timestamp` and updates `alloc_mem` accordingly, mutating the value.
    - It repeats the same process for the `epoch` field, determining if it should be allocated or set to NULL.
- **Output**: Returns the original `mem` pointer, now containing the initialized `fd_lockup_checked_args_t` structure.
- **Functions called**:
    - [`fd_lockup_checked_args_new`](fd_types.c.driver.md#fd_lockup_checked_args_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_lockup\_args\_generate<!-- {{#callable:fd_lockup_args_generate}} -->
Generates and initializes a `fd_lockup_args_t` structure with random values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_lockup_args_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_lockup_args_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_lockup_args_t` structure.
    - It calls [`fd_lockup_args_new`](fd_types.c.driver.md#fd_lockup_args_new) to initialize the structure.
    - For each of the three fields (`unix_timestamp`, `epoch`, and `custodian`), it randomly decides whether to assign a value or set it to NULL.
    - If a value is assigned, it allocates memory for that field and uses [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) to modify the value.
- **Output**: Returns a pointer to the initialized `fd_lockup_args_t` structure.
- **Functions called**:
    - [`fd_lockup_args_new`](fd_types.c.driver.md#fd_lockup_args_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_stake\_instruction\_inner\_generate<!-- {{#callable:fd_stake_instruction_inner_generate}} -->
Generates a stake instruction based on a given discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_stake_instruction_inner_t` where the generated instruction will be stored.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which type of stake instruction to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which case to execute.
    - For each case, it calls the appropriate generation function or assigns a random value to a member of the `self` structure.
    - The cases include initializing, authorizing, splitting, withdrawing, setting lockup, and moving stake or lamports.
- **Output**: The function does not return a value; it modifies the `self` structure directly based on the discriminant.
- **Functions called**:
    - [`fd_stake_instruction_initialize_generate`](#fd_stake_instruction_initialize_generate)
    - [`fd_stake_instruction_authorize_generate`](#fd_stake_instruction_authorize_generate)
    - [`fd_lockup_args_generate`](#fd_lockup_args_generate)
    - [`fd_authorize_with_seed_args_generate`](#fd_authorize_with_seed_args_generate)
    - [`fd_stake_authorize_generate`](#fd_stake_authorize_generate)
    - [`fd_authorize_checked_with_seed_args_generate`](#fd_authorize_checked_with_seed_args_generate)
    - [`fd_lockup_checked_args_generate`](#fd_lockup_checked_args_generate)


---
### fd\_stake\_instruction\_generate<!-- {{#callable:fd_stake_instruction_generate}} -->
Generates a stake instruction with a random discriminant and initializes its inner structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the stake instruction will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the input memory pointer to a `fd_stake_instruction_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_instruction_t` structure.
    - The function calls [`fd_stake_instruction_new`](fd_types.c.driver.md#fd_stake_instruction_new) to initialize the stake instruction.
    - A random discriminant value is generated using the random number generator.
    - The function enters a loop to ensure the discriminant is not 14 or 15, which are invalid for this context.
    - It then calls [`fd_stake_instruction_inner_generate`](#fd_stake_instruction_inner_generate) to initialize the inner structure based on the discriminant.
- **Output**: Returns a pointer to the memory location containing the generated stake instruction.
- **Functions called**:
    - [`fd_stake_instruction_new`](fd_types.c.driver.md#fd_stake_instruction_new)
    - [`fd_stake_instruction_inner_generate`](#fd_stake_instruction_inner_generate)


---
### fd\_stake\_meta\_generate<!-- {{#callable:fd_stake_meta_generate}} -->
Generates metadata for a stake account.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_stake_meta_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the stake metadata.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_meta_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_meta_t` structure.
    - It calls [`fd_stake_meta_new`](fd_types.h.driver.md#fd_stake_meta_new) to initialize the stake metadata structure.
    - It generates a random value for `rent_exempt_reserve` using the provided random number generator.
    - It calls [`fd_stake_authorized_generate`](#fd_stake_authorized_generate) to initialize the `authorized` field of the stake metadata.
    - It calls [`fd_stake_lockup_generate`](#fd_stake_lockup_generate) to initialize the `lockup` field of the stake metadata.
- **Output**: Returns a pointer to the initialized `fd_stake_meta_t` structure.
- **Functions called**:
    - [`fd_stake_meta_new`](fd_types.h.driver.md#fd_stake_meta_new)
    - [`fd_stake_authorized_generate`](#fd_stake_authorized_generate)
    - [`fd_stake_lockup_generate`](#fd_stake_lockup_generate)


---
### fd\_stake\_flags\_generate<!-- {{#callable:fd_stake_flags_generate}} -->
Generates stake flags by initializing a `fd_stake_flags_t` structure and assigning a random value to its bits.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_stake_flags_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_flags_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_stake_flags_t` structure.
    - The function calls [`fd_stake_flags_new`](fd_types.h.driver.md#fd_stake_flags_new) to initialize the structure.
    - A random unsigned char value is generated using the `fd_rng_uchar` function and assigned to the `bits` field of the `fd_stake_flags_t` structure.
    - Finally, the function returns the pointer to the initialized `fd_stake_flags_t` structure.
- **Output**: Returns a pointer to the initialized `fd_stake_flags_t` structure.
- **Functions called**:
    - [`fd_stake_flags_new`](fd_types.h.driver.md#fd_stake_flags_new)


---
### fd\_stake\_state\_v2\_initialized\_generate<!-- {{#callable:fd_stake_state_v2_initialized_generate}} -->
Generates an initialized stake state for version 2.
- **Inputs**:
    - `mem`: A pointer to the memory location where the stake state will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type `fd_stake_state_v2_initialized_t`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_stake_state_v2_initialized_t` structure.
    - The function calls [`fd_stake_state_v2_initialized_new`](fd_types.h.driver.md#fd_stake_state_v2_initialized_new) to initialize the stake state structure.
    - It then calls [`fd_stake_meta_generate`](#fd_stake_meta_generate) to populate the `meta` field of the stake state with random values.
- **Output**: Returns a pointer to the initialized stake state structure.
- **Functions called**:
    - [`fd_stake_state_v2_initialized_new`](fd_types.h.driver.md#fd_stake_state_v2_initialized_new)
    - [`fd_stake_meta_generate`](#fd_stake_meta_generate)


---
### fd\_stake\_state\_v2\_stake\_generate<!-- {{#callable:fd_stake_state_v2_stake_generate}} -->
Generates a new stake state for version 2.
- **Inputs**:
    - `mem`: A pointer to the memory location where the stake state will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_state_v2_stake_t` type.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_stake_state_v2_stake_t` structure.
    - The function calls [`fd_stake_state_v2_stake_new`](fd_types.h.driver.md#fd_stake_state_v2_stake_new) to initialize the stake state.
    - It generates metadata for the stake using [`fd_stake_meta_generate`](#fd_stake_meta_generate).
    - It generates the stake using [`fd_stake_generate`](#fd_stake_generate).
    - It generates stake flags using [`fd_stake_flags_generate`](#fd_stake_flags_generate).
    - Finally, it returns the pointer to the memory location where the stake state was generated.
- **Output**: Returns a pointer to the memory location containing the newly generated stake state.
- **Functions called**:
    - [`fd_stake_state_v2_stake_new`](fd_types.h.driver.md#fd_stake_state_v2_stake_new)
    - [`fd_stake_meta_generate`](#fd_stake_meta_generate)
    - [`fd_stake_generate`](#fd_stake_generate)
    - [`fd_stake_flags_generate`](#fd_stake_flags_generate)


---
### fd\_stake\_state\_v2\_inner\_generate<!-- {{#callable:fd_stake_state_v2_inner_generate}} -->
Generates the inner state of a stake state version 2 based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_stake_state_v2_inner_t` where the generated state will be stored.
    - `alloc_mem`: A double pointer to memory allocation space for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which type of stake state to generate.
    - `rng`: A pointer to a random number generator instance used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which case to execute.
    - If `discriminant` is 1, it calls [`fd_stake_state_v2_initialized_generate`](#fd_stake_state_v2_initialized_generate) to generate the initialized state.
    - If `discriminant` is 2, it calls [`fd_stake_state_v2_stake_generate`](#fd_stake_state_v2_stake_generate) to generate the stake state.
- **Output**: The function does not return a value; it modifies the `self` structure directly based on the generated state.
- **Functions called**:
    - [`fd_stake_state_v2_initialized_generate`](#fd_stake_state_v2_initialized_generate)
    - [`fd_stake_state_v2_stake_generate`](#fd_stake_state_v2_stake_generate)


---
### fd\_stake\_state\_v2\_generate<!-- {{#callable:fd_stake_state_v2_generate}} -->
Generates a new `fd_stake_state_v2_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_stake_state_v2_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure's fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_stake_state_v2_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_stake_state_v2_t` structure.
    - The function calls `fd_stake_state_v2_new(mem)` to initialize the structure.
    - A random discriminant value is generated using the random number generator, which determines the type of inner structure to initialize.
    - The function calls [`fd_stake_state_v2_inner_generate`](#fd_stake_state_v2_inner_generate) with the inner structure and the generated discriminant to further initialize the inner fields.
- **Output**: Returns a pointer to the initialized `fd_stake_state_v2_t` structure.
- **Functions called**:
    - [`fd_stake_state_v2_new`](fd_types.c.driver.md#fd_stake_state_v2_new)
    - [`fd_stake_state_v2_inner_generate`](#fd_stake_state_v2_inner_generate)


---
### fd\_nonce\_data\_generate<!-- {{#callable:fd_nonce_data_generate}} -->
Generates nonce data including a public key, a durable nonce, and a fee calculator.
- **Inputs**:
    - `mem`: A pointer to the memory location where the nonce data will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_nonce_data_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_nonce_data_t` structure.
    - It calls [`fd_nonce_data_new`](fd_types.h.driver.md#fd_nonce_data_new) to initialize the nonce data structure.
    - It generates a public key for the authority using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates a durable nonce using [`fd_hash_generate`](#fd_hash_generate).
    - It generates a fee calculator using [`fd_fee_calculator_generate`](#fd_fee_calculator_generate).
- **Output**: Returns a pointer to the memory location containing the generated nonce data.
- **Functions called**:
    - [`fd_nonce_data_new`](fd_types.h.driver.md#fd_nonce_data_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_fee_calculator_generate`](#fd_fee_calculator_generate)


---
### fd\_nonce\_state\_inner\_generate<!-- {{#callable:fd_nonce_state_inner_generate}} -->
Generates a nonce state based on a given discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_nonce_state_inner_t` that will be populated.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which case to execute in the switch statement.
    - `rng`: A pointer to a random number generator of type `fd_rng_t` used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - If the `discriminant` is 1, it calls the [`fd_nonce_data_generate`](#fd_nonce_data_generate) function to populate the `initialized` field of the `self` structure.
    - The function exits after executing the appropriate case.
- **Output**: The function does not return a value; it modifies the `self` structure directly.
- **Functions called**:
    - [`fd_nonce_data_generate`](#fd_nonce_data_generate)


---
### fd\_nonce\_state\_generate<!-- {{#callable:fd_nonce_state_generate}} -->
Generates a new `fd_nonce_state_t` structure and initializes its fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_nonce_state_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_nonce_state_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_nonce_state_t` structure.
    - It calls [`fd_nonce_state_new`](fd_types.c.driver.md#fd_nonce_state_new) to initialize the `fd_nonce_state_t` structure.
    - It generates a random `discriminant` value (0 or 1) using the `fd_rng_uint` function.
    - It calls [`fd_nonce_state_inner_generate`](#fd_nonce_state_inner_generate) with the inner structure of `self`, the updated `alloc_mem`, the generated `discriminant`, and the `rng`.
- **Output**: Returns a pointer to the initialized `fd_nonce_state_t` structure.
- **Functions called**:
    - [`fd_nonce_state_new`](fd_types.c.driver.md#fd_nonce_state_new)
    - [`fd_nonce_state_inner_generate`](#fd_nonce_state_inner_generate)


---
### fd\_nonce\_state\_versions\_inner\_generate<!-- {{#callable:fd_nonce_state_versions_inner_generate}} -->
Generates nonce state versions based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_nonce_state_versions_inner_t` that holds the state versions.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which nonce state to generate (0 for legacy, 1 for current).
    - `rng`: A pointer to a random number generator of type `fd_rng_t` used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - If `discriminant` is 0, it calls [`fd_nonce_state_generate`](#fd_nonce_state_generate) to generate the legacy nonce state.
    - If `discriminant` is 1, it calls [`fd_nonce_state_generate`](#fd_nonce_state_generate) to generate the current nonce state.
- **Output**: The function does not return a value; it modifies the state of the `self` object based on the discriminant.
- **Functions called**:
    - [`fd_nonce_state_generate`](#fd_nonce_state_generate)


---
### fd\_nonce\_state\_versions\_generate<!-- {{#callable:fd_nonce_state_versions_generate}} -->
Generates a new `fd_nonce_state_versions_t` structure with a random discriminant and initializes its inner state.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_nonce_state_versions_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_nonce_state_versions_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_nonce_state_versions_t` structure.
    - It calls [`fd_nonce_state_versions_new`](fd_types.c.driver.md#fd_nonce_state_versions_new) to initialize the `self` structure.
    - It generates a random `discriminant` value using the random number generator and assigns it to `self->discriminant`.
    - It calls [`fd_nonce_state_versions_inner_generate`](#fd_nonce_state_versions_inner_generate) with the inner state of `self`, the updated `alloc_mem`, and the generated `discriminant`.
- **Output**: Returns a pointer to the initialized `fd_nonce_state_versions_t` structure.
- **Functions called**:
    - [`fd_nonce_state_versions_new`](fd_types.c.driver.md#fd_nonce_state_versions_new)
    - [`fd_nonce_state_versions_inner_generate`](#fd_nonce_state_versions_inner_generate)


---
### fd\_compute\_budget\_program\_instruction\_request\_units\_deprecated\_generate<!-- {{#callable:fd_compute_budget_program_instruction_request_units_deprecated_generate}} -->
Generates a request for computing budget program instruction units.
- **Inputs**:
    - `mem`: A pointer to the memory location where the generated structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the units and additional fee.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the structure being generated.
    - It calls a function to initialize the structure.
    - It generates random values for the 'units' and 'additional_fee' fields using the random number generator.
    - Finally, it returns the memory pointer.
- **Output**: Returns a pointer to the memory location containing the generated budget program instruction request units structure.
- **Functions called**:
    - [`fd_compute_budget_program_instruction_request_units_deprecated_new`](fd_types.h.driver.md#fd_compute_budget_program_instruction_request_units_deprecated_new)


---
### fd\_compute\_budget\_program\_instruction\_inner\_generate<!-- {{#callable:fd_compute_budget_program_instruction_inner_generate}} -->
Generates budget program instruction based on a discriminant value.
- **Inputs**:
    - `self`: Pointer to an instance of `fd_compute_budget_program_instruction_inner_t` that will be populated.
    - `alloc_mem`: Pointer to a memory allocation pointer that will be updated.
    - `discriminant`: An unsigned integer that determines which case to execute in the switch statement.
    - `rng`: Pointer to a random number generator instance used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value using a switch statement.
    - For each case (0 to 4), it performs different operations on the `self` structure.
    - Case 0 calls [`fd_compute_budget_program_instruction_request_units_deprecated_generate`](#fd_compute_budget_program_instruction_request_units_deprecated_generate) to populate the `request_units_deprecated` field.
    - Case 1 assigns a random value to `request_heap_frame` using `fd_rng_uint`.
    - Case 2 assigns a random value to `set_compute_unit_limit` using `fd_rng_uint`.
    - Case 3 assigns a random value to `set_compute_unit_price` using `fd_rng_ulong`.
    - Case 4 assigns a random value to `set_loaded_accounts_data_size_limit` using `fd_rng_uint`.
- **Output**: The function does not return a value but modifies the `self` structure based on the discriminant.
- **Functions called**:
    - [`fd_compute_budget_program_instruction_request_units_deprecated_generate`](#fd_compute_budget_program_instruction_request_units_deprecated_generate)


---
### fd\_compute\_budget\_program\_instruction\_generate<!-- {{#callable:fd_compute_budget_program_instruction_generate}} -->
Generates a budget program instruction for computing budget.
- **Inputs**:
    - `mem`: A pointer to the memory location where the budget program instruction will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the budget program instruction structure.
    - It initializes the budget program instruction structure using a helper function.
    - A random discriminant value is generated using the random number generator, which determines the type of instruction to generate.
    - The function then calls another helper function to generate the inner instruction based on the discriminant value.
    - Finally, it returns the pointer to the memory where the budget program instruction is stored.
- **Output**: Returns a pointer to the memory location containing the generated budget program instruction.
- **Functions called**:
    - [`fd_compute_budget_program_instruction_new`](fd_types.c.driver.md#fd_compute_budget_program_instruction_new)
    - [`fd_compute_budget_program_instruction_inner_generate`](#fd_compute_budget_program_instruction_inner_generate)


---
### fd\_config\_keys\_generate<!-- {{#callable:fd_config_keys_generate}} -->
Generates configuration keys for a given memory space using random values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_config_keys_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_config_keys_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_config_keys_t` structure.
    - It initializes the `fd_config_keys_t` structure by calling [`fd_config_keys_new`](fd_types.c.driver.md#fd_config_keys_new).
    - The length of the keys (`keys_len`) is determined by generating a random number between 0 and 7.
    - If `keys_len` is greater than 0, it allocates memory for the keys array and updates `alloc_mem` accordingly.
    - A loop iterates over the number of keys, initializing each key pair by calling [`fd_config_keys_pair_new`](fd_types.c.driver.md#fd_config_keys_pair_new) and generating its values using [`fd_config_keys_pair_generate`](#fd_config_keys_pair_generate).
    - If `keys_len` is 0, the keys pointer is set to NULL.
- **Output**: Returns a pointer to the initialized `fd_config_keys_t` structure.
- **Functions called**:
    - [`fd_config_keys_new`](fd_types.c.driver.md#fd_config_keys_new)
    - [`fd_config_keys_pair_new`](fd_types.c.driver.md#fd_config_keys_pair_new)
    - [`fd_config_keys_pair_generate`](#fd_config_keys_pair_generate)


---
### fd\_bpf\_loader\_program\_instruction\_write\_generate<!-- {{#callable:fd_bpf_loader_program_instruction_write_generate}} -->
Generates a BPF loader program instruction write operation.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction write structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_bpf_loader_program_instruction_write_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_bpf_loader_program_instruction_write_t` structure.
    - The function initializes the structure by calling [`fd_bpf_loader_program_instruction_write_new`](fd_types.c.driver.md#fd_bpf_loader_program_instruction_write_new).
    - It generates a random offset for the instruction using `fd_rng_uint`.
    - It generates a random length for the bytes to be written, ensuring it does not exceed 8.
    - If the generated length is greater than zero, it allocates memory for the bytes and fills it with random values using `fd_rng_uchar`.
    - If the length is zero, it sets the bytes pointer to NULL.
- **Output**: Returns a pointer to the initialized memory containing the instruction write structure.
- **Functions called**:
    - [`fd_bpf_loader_program_instruction_write_new`](fd_types.c.driver.md#fd_bpf_loader_program_instruction_write_new)


---
### fd\_bpf\_loader\_program\_instruction\_inner\_generate<!-- {{#callable:fd_bpf_loader_program_instruction_inner_generate}} -->
Generates a BPF loader program instruction based on a given discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_bpf_loader_program_instruction_inner_t` that will be populated.
    - `alloc_mem`: A double pointer to memory allocation space for the instruction.
    - `discriminant`: An unsigned integer that determines which type of instruction to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which instruction to generate.
    - If the `discriminant` is 0, it calls [`fd_bpf_loader_program_instruction_write_generate`](#fd_bpf_loader_program_instruction_write_generate) to generate a write instruction.
    - The function exits after generating the appropriate instruction.
- **Output**: The function does not return a value; it populates the `self` structure with the generated instruction data.
- **Functions called**:
    - [`fd_bpf_loader_program_instruction_write_generate`](#fd_bpf_loader_program_instruction_write_generate)


---
### fd\_bpf\_loader\_program\_instruction\_generate<!-- {{#callable:fd_bpf_loader_program_instruction_generate}} -->
Generates a BPF loader program instruction.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the instruction structure.
    - It initializes the instruction structure by calling [`fd_bpf_loader_program_instruction_new`](fd_types.c.driver.md#fd_bpf_loader_program_instruction_new).
    - A random discriminant value is generated using the random number generator.
    - The function then calls [`fd_bpf_loader_program_instruction_inner_generate`](#fd_bpf_loader_program_instruction_inner_generate) with the inner structure and the generated discriminant.
- **Output**: Returns a pointer to the memory location containing the generated BPF loader program instruction.
- **Functions called**:
    - [`fd_bpf_loader_program_instruction_new`](fd_types.c.driver.md#fd_bpf_loader_program_instruction_new)
    - [`fd_bpf_loader_program_instruction_inner_generate`](#fd_bpf_loader_program_instruction_inner_generate)


---
### fd\_loader\_v4\_program\_instruction\_write\_generate<!-- {{#callable:fd_loader_v4_program_instruction_write_generate}} -->
Generates a program instruction write for the loader version 4.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction write structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for the instruction.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a specific structure type for the loader version 4 program instruction write.
    - It updates the `alloc_mem` pointer to allocate space for the instruction write structure.
    - The function initializes the instruction write structure by calling [`fd_loader_v4_program_instruction_write_new`](fd_types.c.driver.md#fd_loader_v4_program_instruction_write_new).
    - It generates a random offset using `fd_rng_uint` and assigns it to the `offset` field of the structure.
    - It generates a random length for the bytes to be written, ensuring it does not exceed 8 bytes.
    - If the generated length is greater than zero, it allocates memory for the `bytes` field and fills it with random values using `fd_rng_uchar`.
    - Finally, the function returns the original `mem` pointer.
- **Output**: Returns a pointer to the initialized memory for the loader version 4 program instruction write.
- **Functions called**:
    - [`fd_loader_v4_program_instruction_write_new`](fd_types.c.driver.md#fd_loader_v4_program_instruction_write_new)


---
### fd\_loader\_v4\_program\_instruction\_copy\_generate<!-- {{#callable:fd_loader_v4_program_instruction_copy_generate}} -->
Generates a copy instruction for a loader program in version 4.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction data will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random offsets and lengths.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type `fd_loader_v4_program_instruction_copy_t`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_loader_v4_program_instruction_copy_t` structure.
    - The function initializes the instruction by calling [`fd_loader_v4_program_instruction_copy_new`](fd_types.h.driver.md#fd_loader_v4_program_instruction_copy_new).
    - It generates random values for `destination_offset`, `source_offset`, and `length` using the provided random number generator.
- **Output**: Returns a pointer to the memory location containing the generated instruction.
- **Functions called**:
    - [`fd_loader_v4_program_instruction_copy_new`](fd_types.h.driver.md#fd_loader_v4_program_instruction_copy_new)


---
### fd\_loader\_v4\_program\_instruction\_set\_program\_length\_generate<!-- {{#callable:fd_loader_v4_program_instruction_set_program_length_generate}} -->
Generates a program length setting instruction for the loader.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction data will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate the new program length.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type `fd_loader_v4_program_instruction_set_program_length_t`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_loader_v4_program_instruction_set_program_length_t` structure.
    - The function calls [`fd_loader_v4_program_instruction_set_program_length_new`](fd_types.h.driver.md#fd_loader_v4_program_instruction_set_program_length_new) to initialize the instruction structure.
    - It generates a new size for the program length using the `fd_rng_uint` function, which is stored in the `new_size` field of the structure.
    - Finally, the function returns the original `mem` pointer.
- **Output**: Returns a pointer to the memory location containing the initialized instruction structure.
- **Functions called**:
    - [`fd_loader_v4_program_instruction_set_program_length_new`](fd_types.h.driver.md#fd_loader_v4_program_instruction_set_program_length_new)


---
### fd\_loader\_v4\_program\_instruction\_inner\_generate<!-- {{#callable:fd_loader_v4_program_instruction_inner_generate}} -->
Generates a program instruction based on a specified discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_loader_v4_program_instruction_inner_t`, which holds the instruction data.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which type of instruction to generate.
    - `rng`: A pointer to a random number generator instance used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which case to execute.
    - If `discriminant` is 0, it calls [`fd_loader_v4_program_instruction_write_generate`](#fd_loader_v4_program_instruction_write_generate) to generate a write instruction.
    - If `discriminant` is 1, it calls [`fd_loader_v4_program_instruction_copy_generate`](#fd_loader_v4_program_instruction_copy_generate) to generate a copy instruction.
    - If `discriminant` is 2, it calls [`fd_loader_v4_program_instruction_set_program_length_generate`](#fd_loader_v4_program_instruction_set_program_length_generate) to set the program length.
- **Output**: The function does not return a value; it modifies the `self` structure based on the generated instruction.
- **Functions called**:
    - [`fd_loader_v4_program_instruction_write_generate`](#fd_loader_v4_program_instruction_write_generate)
    - [`fd_loader_v4_program_instruction_copy_generate`](#fd_loader_v4_program_instruction_copy_generate)
    - [`fd_loader_v4_program_instruction_set_program_length_generate`](#fd_loader_v4_program_instruction_set_program_length_generate)


---
### fd\_loader\_v4\_program\_instruction\_generate<!-- {{#callable:fd_loader_v4_program_instruction_generate}} -->
Generates a program instruction for the loader version 4.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type `fd_loader_v4_program_instruction_t`.
    - It updates the `alloc_mem` pointer to allocate space for the instruction structure.
    - It calls [`fd_loader_v4_program_instruction_new`](fd_types.c.driver.md#fd_loader_v4_program_instruction_new) to initialize the instruction structure.
    - A random discriminant value is generated using the random number generator, which determines the type of instruction to generate.
    - The function then calls [`fd_loader_v4_program_instruction_inner_generate`](#fd_loader_v4_program_instruction_inner_generate) with the inner structure and the generated discriminant to populate the instruction details.
- **Output**: Returns a pointer to the memory location containing the generated program instruction.
- **Functions called**:
    - [`fd_loader_v4_program_instruction_new`](fd_types.c.driver.md#fd_loader_v4_program_instruction_new)
    - [`fd_loader_v4_program_instruction_inner_generate`](#fd_loader_v4_program_instruction_inner_generate)


---
### fd\_bpf\_upgradeable\_loader\_program\_instruction\_write\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_program_instruction_write_generate}} -->
Generates a write instruction for the BPF upgradeable loader program.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction structure will be written.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type for the BPF upgradeable loader program instruction.
    - It updates the `alloc_mem` pointer to allocate space for the instruction structure.
    - The function generates a random `offset` value using the random number generator.
    - It generates a random length for the `bytes` field, which is constrained to a maximum of 8.
    - If the generated `bytes_len` is greater than zero, it allocates memory for the `bytes` field and fills it with random values.
    - If `bytes_len` is zero, it sets the `bytes` pointer to NULL.
- **Output**: Returns a pointer to the memory location where the instruction structure has been written.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_program_instruction_write_new`](fd_types.c.driver.md#fd_bpf_upgradeable_loader_program_instruction_write_new)


---
### fd\_bpf\_upgradeable\_loader\_program\_instruction\_deploy\_with\_max\_data\_len\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_generate}} -->
Generates a deploy instruction for a BPF upgradeable loader program with a maximum data length.
- **Inputs**:
    - `mem`: A pointer to the memory location where the program instruction structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the structure being initialized.
    - It calls a function to initialize a new instance of the program instruction structure.
    - It generates a random maximum data length using the random number generator.
    - Finally, it returns the memory pointer.
- **Output**: Returns a pointer to the initialized memory containing the program instruction with the maximum data length set.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new`](fd_types.h.driver.md#fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new)


---
### fd\_bpf\_upgradeable\_loader\_program\_instruction\_extend\_program\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_program_instruction_extend_program_generate}} -->
Generates an extended program for a BPF upgradeable loader.
- **Inputs**:
    - `mem`: A pointer to the memory location where the program instruction will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type for the BPF upgradeable loader program instruction.
    - It updates the `alloc_mem` pointer to allocate space for the new program instruction structure.
    - The function initializes a new program instruction using `fd_bpf_upgradeable_loader_program_instruction_new`.
    - It generates a random number of additional bytes using the random number generator and assigns it to the `additional_bytes` field of the structure.
    - Finally, it returns the pointer to the memory location where the program instruction was generated.
- **Output**: Returns a pointer to the memory location containing the generated BPF upgradeable loader program instruction.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_program_instruction_extend_program_new`](fd_types.h.driver.md#fd_bpf_upgradeable_loader_program_instruction_extend_program_new)


---
### fd\_bpf\_upgradeable\_loader\_program\_instruction\_inner\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_program_instruction_inner_generate}} -->
Generates a BPF upgradeable loader program instruction based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_bpf_upgradeable_loader_program_instruction_inner_t` that will be populated.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which type of instruction to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which case to execute.
    - If `discriminant` is 1, it calls [`fd_bpf_upgradeable_loader_program_instruction_write_generate`](#fd_bpf_upgradeable_loader_program_instruction_write_generate) to generate a write instruction.
    - If `discriminant` is 2, it calls [`fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_generate`](#fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_generate) to generate a deploy instruction.
    - If `discriminant` is 6, it calls [`fd_bpf_upgradeable_loader_program_instruction_extend_program_generate`](#fd_bpf_upgradeable_loader_program_instruction_extend_program_generate) to generate an extend program instruction.
- **Output**: The function does not return a value; it modifies the `self` structure based on the generated instruction.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_program_instruction_write_generate`](#fd_bpf_upgradeable_loader_program_instruction_write_generate)
    - [`fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_generate`](#fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_generate)
    - [`fd_bpf_upgradeable_loader_program_instruction_extend_program_generate`](#fd_bpf_upgradeable_loader_program_instruction_extend_program_generate)


---
### fd\_bpf\_upgradeable\_loader\_program\_instruction\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_program_instruction_generate}} -->
Generates a new `fd_bpf_upgradeable_loader_program_instruction_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_bpf_upgradeable_loader_program_instruction_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator context used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_bpf_upgradeable_loader_program_instruction_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_bpf_upgradeable_loader_program_instruction_t` structure.
    - It calls [`fd_bpf_upgradeable_loader_program_instruction_new`](fd_types.c.driver.md#fd_bpf_upgradeable_loader_program_instruction_new) to initialize the structure.
    - A random discriminant value is generated using the random number generator, which determines the type of instruction to generate.
    - The function then calls [`fd_bpf_upgradeable_loader_program_instruction_inner_generate`](#fd_bpf_upgradeable_loader_program_instruction_inner_generate) with the generated discriminant to populate the inner structure based on the discriminant value.
- **Output**: Returns a pointer to the initialized `fd_bpf_upgradeable_loader_program_instruction_t` structure.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_program_instruction_new`](fd_types.c.driver.md#fd_bpf_upgradeable_loader_program_instruction_new)
    - [`fd_bpf_upgradeable_loader_program_instruction_inner_generate`](#fd_bpf_upgradeable_loader_program_instruction_inner_generate)


---
### fd\_bpf\_upgradeable\_loader\_state\_buffer\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_state_buffer_generate}} -->
Generates a buffer for the `fd_bpf_upgradeable_loader_state` structure, potentially initializing an authority address.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_bpf_upgradeable_loader_state_buffer_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to determine if the authority address should be initialized.
- **Control Flow**:
    - The function first casts the `mem` pointer to a `fd_bpf_upgradeable_loader_state_buffer_t` type.
    - It increments the `alloc_mem` pointer by the size of `fd_bpf_upgradeable_loader_state_buffer_t`.
    - The function initializes the structure by calling [`fd_bpf_upgradeable_loader_state_buffer_new`](fd_types.c.driver.md#fd_bpf_upgradeable_loader_state_buffer_new).
    - A random value is generated to determine if the `authority_address` should be set to a new public key or to NULL.
    - If the generated value indicates to set the address, it allocates memory for the `authority_address`, initializes it, and generates a new public key.
- **Output**: Returns a pointer to the initialized `fd_bpf_upgradeable_loader_state_buffer_t` structure.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_state_buffer_new`](fd_types.c.driver.md#fd_bpf_upgradeable_loader_state_buffer_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_bpf\_upgradeable\_loader\_state\_program\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_state_program_generate}} -->
Generates a new `fd_bpf_upgradeable_loader_state_program_t` structure and initializes its fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_bpf_upgradeable_loader_state_program_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_bpf_upgradeable_loader_state_program_t` type.
    - It updates the `alloc_mem` pointer to allocate enough space for the `fd_bpf_upgradeable_loader_state_program_t` structure.
    - The function calls [`fd_bpf_upgradeable_loader_state_program_new`](fd_types.h.driver.md#fd_bpf_upgradeable_loader_state_program_new) to initialize the structure at the given memory location.
    - It generates a new public key for the `programdata_address` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - Finally, it returns the pointer to the initialized structure.
- **Output**: Returns a pointer to the initialized `fd_bpf_upgradeable_loader_state_program_t` structure.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_state_program_new`](fd_types.h.driver.md#fd_bpf_upgradeable_loader_state_program_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_bpf\_upgradeable\_loader\_state\_program\_data\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_state_program_data_generate}} -->
Generates program data for an upgradeable BPF loader state.
- **Inputs**:
    - `mem`: A pointer to the memory location where the program data structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the program data structure.
    - It initializes the program data structure by calling [`fd_bpf_upgradeable_loader_state_program_data_new`](fd_types.c.driver.md#fd_bpf_upgradeable_loader_state_program_data_new).
    - A random slot number is generated and assigned to the `slot` field of the structure.
    - A random value is generated to determine if the `upgrade_authority_address` should be set to a new address or remain NULL.
    - If not NULL, memory is allocated for the `upgrade_authority_address`, and it is initialized and generated using [`fd_pubkey_generate`](#fd_pubkey_generate).
- **Output**: Returns a pointer to the initialized program data structure.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_state_program_data_new`](fd_types.c.driver.md#fd_bpf_upgradeable_loader_state_program_data_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_bpf\_upgradeable\_loader\_state\_inner\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_state_inner_generate}} -->
Generates the inner state of a BPF upgradeable loader based on a discriminant.
- **Inputs**:
    - `self`: A pointer to the `fd_bpf_upgradeable_loader_state_inner_t` structure that will be populated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to allocated memory.
    - `discriminant`: An unsigned integer that determines which part of the state to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - Depending on the value of `discriminant`, it calls one of three functions to generate the corresponding state: [`fd_bpf_upgradeable_loader_state_buffer_generate`](#fd_bpf_upgradeable_loader_state_buffer_generate), [`fd_bpf_upgradeable_loader_state_program_generate`](#fd_bpf_upgradeable_loader_state_program_generate), or [`fd_bpf_upgradeable_loader_state_program_data_generate`](#fd_bpf_upgradeable_loader_state_program_data_generate).
    - Each of these functions populates a specific part of the `self` structure.
- **Output**: The function does not return a value; it modifies the `self` structure and updates the `alloc_mem` pointer to reflect any memory allocations made during the generation process.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_state_buffer_generate`](#fd_bpf_upgradeable_loader_state_buffer_generate)
    - [`fd_bpf_upgradeable_loader_state_program_generate`](#fd_bpf_upgradeable_loader_state_program_generate)
    - [`fd_bpf_upgradeable_loader_state_program_data_generate`](#fd_bpf_upgradeable_loader_state_program_data_generate)


---
### fd\_bpf\_upgradeable\_loader\_state\_generate<!-- {{#callable:fd_bpf_upgradeable_loader_state_generate}} -->
Generates a new `fd_bpf_upgradeable_loader_state_t` structure and initializes its fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_bpf_upgradeable_loader_state_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure's fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_bpf_upgradeable_loader_state_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to point to the next memory location after the size of `fd_bpf_upgradeable_loader_state_t`.
    - It calls `fd_bpf_upgradeable_loader_state_new(mem)` to initialize the structure.
    - It generates a random `discriminant` value between 0 and 3 using the random number generator.
    - It calls [`fd_bpf_upgradeable_loader_state_inner_generate`](#fd_bpf_upgradeable_loader_state_inner_generate) with the inner structure of `self`, the updated `alloc_mem`, the generated `discriminant`, and the random number generator.
- **Output**: Returns a pointer to the initialized `fd_bpf_upgradeable_loader_state_t` structure.
- **Functions called**:
    - [`fd_bpf_upgradeable_loader_state_new`](fd_types.c.driver.md#fd_bpf_upgradeable_loader_state_new)
    - [`fd_bpf_upgradeable_loader_state_inner_generate`](#fd_bpf_upgradeable_loader_state_inner_generate)


---
### fd\_loader\_v4\_state\_generate<!-- {{#callable:fd_loader_v4_state_generate}} -->
Generates a new state for the loader version 4.
- **Inputs**:
    - `mem`: A pointer to the memory location where the state will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific state type.
    - It updates the allocation memory pointer to account for the size of the state being generated.
    - It calls [`fd_loader_v4_state_new`](fd_types.h.driver.md#fd_loader_v4_state_new) to initialize the state.
    - It assigns a random value to the `slot` field using the random number generator.
    - It generates a public key for the `authority_address_or_next_version` field.
    - It assigns a random value to the `status` field.
- **Output**: Returns a pointer to the memory location where the new state has been generated.
- **Functions called**:
    - [`fd_loader_v4_state_new`](fd_types.h.driver.md#fd_loader_v4_state_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_frozen\_hash\_status\_generate<!-- {{#callable:fd_frozen_hash_status_generate}} -->
Generates a frozen hash status by initializing a new `fd_frozen_hash_status_t` structure and populating it with a hash and a duplicate confirmation.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_frozen_hash_status_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_frozen_hash_status_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_frozen_hash_status_t` structure.
    - It calls [`fd_frozen_hash_status_new`](fd_types.c.driver.md#fd_frozen_hash_status_new) to initialize the structure.
    - It generates a hash using [`fd_hash_generate`](#fd_hash_generate) and assigns it to the `frozen_hash` field of the structure.
    - It generates a random value for `is_duplicate_confirmed` using `fd_rng_uchar`.
- **Output**: Returns a pointer to the initialized `fd_frozen_hash_status_t` structure.
- **Functions called**:
    - [`fd_frozen_hash_status_new`](fd_types.c.driver.md#fd_frozen_hash_status_new)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_frozen\_hash\_versioned\_inner\_generate<!-- {{#callable:fd_frozen_hash_versioned_inner_generate}} -->
Generates a versioned frozen hash based on a discriminant.
- **Inputs**:
    - `self`: A pointer to a `fd_frozen_hash_versioned_inner_t` structure that will hold the generated hash.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to allocated memory.
    - `discriminant`: An unsigned integer that determines which case to execute in the switch statement.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value using a switch statement.
    - If the `discriminant` is 0, it calls the [`fd_frozen_hash_status_generate`](#fd_frozen_hash_status_generate) function to generate the current frozen hash status.
    - The function does not handle any other cases for the `discriminant`.
- **Output**: The function does not return a value; it modifies the `self` structure to contain the generated frozen hash status.
- **Functions called**:
    - [`fd_frozen_hash_status_generate`](#fd_frozen_hash_status_generate)


---
### fd\_frozen\_hash\_versioned\_generate<!-- {{#callable:fd_frozen_hash_versioned_generate}} -->
Generates a versioned frozen hash structure with a random discriminant and initializes its inner state.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_frozen_hash_versioned_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_frozen_hash_versioned_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_frozen_hash_versioned_t` structure.
    - It calls [`fd_frozen_hash_versioned_new`](fd_types.c.driver.md#fd_frozen_hash_versioned_new) to initialize the structure at the `mem` location.
    - A random discriminant value is generated using the random number generator and assigned to the `discriminant` field of the structure.
    - The function then calls [`fd_frozen_hash_versioned_inner_generate`](#fd_frozen_hash_versioned_inner_generate) to initialize the inner state of the structure based on the generated discriminant.
- **Output**: Returns a pointer to the initialized `fd_frozen_hash_versioned_t` structure.
- **Functions called**:
    - [`fd_frozen_hash_versioned_new`](fd_types.c.driver.md#fd_frozen_hash_versioned_new)
    - [`fd_frozen_hash_versioned_inner_generate`](#fd_frozen_hash_versioned_inner_generate)


---
### fd\_lookup\_table\_meta\_generate<!-- {{#callable:fd_lookup_table_meta_generate}} -->
Generates metadata for a lookup table, initializing various fields with random values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_lookup_table_meta_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for the fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_lookup_table_meta_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_lookup_table_meta_t` structure.
    - It calls [`fd_lookup_table_meta_new`](fd_types.c.driver.md#fd_lookup_table_meta_new) to initialize the structure.
    - Random values are generated for `deactivation_slot`, `last_extended_slot`, and `last_extended_slot_start_index` using the provided RNG.
    - A conditional check determines if the `has_authority` field should be set, and if so, it generates a public key.
    - Finally, it generates a random padding value.
- **Output**: Returns a pointer to the initialized `fd_lookup_table_meta_t` structure.
- **Functions called**:
    - [`fd_lookup_table_meta_new`](fd_types.c.driver.md#fd_lookup_table_meta_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_address\_lookup\_table\_generate<!-- {{#callable:fd_address_lookup_table_generate}} -->
Generates a new address lookup table and initializes its metadata.
- **Inputs**:
    - `mem`: A pointer to the memory location where the address lookup table will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_address_lookup_table_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the new address lookup table.
    - The function calls [`fd_address_lookup_table_new`](fd_types.c.driver.md#fd_address_lookup_table_new) to initialize the address lookup table.
    - It then calls [`fd_lookup_table_meta_generate`](#fd_lookup_table_meta_generate) to generate and initialize the metadata for the lookup table.
- **Output**: Returns a pointer to the initialized address lookup table.
- **Functions called**:
    - [`fd_address_lookup_table_new`](fd_types.c.driver.md#fd_address_lookup_table_new)
    - [`fd_lookup_table_meta_generate`](#fd_lookup_table_meta_generate)


---
### fd\_address\_lookup\_table\_state\_inner\_generate<!-- {{#callable:fd_address_lookup_table_state_inner_generate}} -->
Generates the inner state of an address lookup table based on a discriminant.
- **Inputs**:
    - `self`: A pointer to the `fd_address_lookup_table_state_inner_t` structure that will be populated.
    - `alloc_mem`: A pointer to a pointer that will be used for memory allocation.
    - `discriminant`: An unsigned integer that determines which case to execute in the switch statement.
    - `rng`: A pointer to a random number generator of type `fd_rng_t`.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value using a switch statement.
    - If the `discriminant` is 1, it calls the [`fd_address_lookup_table_generate`](#fd_address_lookup_table_generate) function to populate the `lookup_table` field of the `self` structure.
    - The function exits after executing the corresponding case.
- **Output**: The function does not return a value; it modifies the `self` structure directly.
- **Functions called**:
    - [`fd_address_lookup_table_generate`](#fd_address_lookup_table_generate)


---
### fd\_address\_lookup\_table\_state\_generate<!-- {{#callable:fd_address_lookup_table_state_generate}} -->
Generates a new state for the address lookup table.
- **Inputs**:
    - `mem`: A pointer to the memory location where the state will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the `fd_address_lookup_table_state_t` structure.
    - It initializes a new address lookup table state using [`fd_address_lookup_table_state_new`](fd_types.c.driver.md#fd_address_lookup_table_state_new).
    - A random discriminant value is generated using the random number generator.
    - The inner state of the address lookup table is generated based on the discriminant value.
- **Output**: Returns a pointer to the memory location where the address lookup table state has been generated.
- **Functions called**:
    - [`fd_address_lookup_table_state_new`](fd_types.c.driver.md#fd_address_lookup_table_state_new)
    - [`fd_address_lookup_table_state_inner_generate`](#fd_address_lookup_table_state_inner_generate)


---
### fd\_gossip\_ping\_generate<!-- {{#callable:fd_gossip_ping_generate}} -->
Generates a new `fd_gossip_ping_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_gossip_ping_t` structure will be initialized.
    - `alloc_mem`: A double pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_ping_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_ping_t` structure.
    - It calls [`fd_gossip_ping_new`](fd_types.h.driver.md#fd_gossip_ping_new) to initialize the `fd_gossip_ping_t` structure.
    - It generates a public key for the `from` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates a token using [`fd_hash_generate`](#fd_hash_generate).
    - It generates a signature using [`fd_signature_generate`](#fd_signature_generate).
- **Output**: Returns a pointer to the initialized `fd_gossip_ping_t` structure.
- **Functions called**:
    - [`fd_gossip_ping_new`](fd_types.h.driver.md#fd_gossip_ping_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_signature_generate`](#fd_signature_generate)


---
### fd\_gossip\_ip\_addr\_inner\_generate<!-- {{#callable:fd_gossip_ip_addr_inner_generate}} -->
Generates an IP address (IPv4 or IPv6) based on a discriminant.
- **Inputs**:
    - `self`: A pointer to a `fd_gossip_ip_addr_inner_t` structure where the generated IP address will be stored.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines whether to generate an IPv4 or IPv6 address.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - If `discriminant` is 0, it calls [`fd_gossip_ip4_addr_generate`](#fd_gossip_ip4_addr_generate) to generate an IPv4 address.
    - If `discriminant` is 1, it calls [`fd_gossip_ip6_addr_generate`](#fd_gossip_ip6_addr_generate) to generate an IPv6 address.
- **Output**: The function does not return a value; it modifies the `self` structure to contain the generated IP address.
- **Functions called**:
    - [`fd_gossip_ip4_addr_generate`](#fd_gossip_ip4_addr_generate)
    - [`fd_gossip_ip6_addr_generate`](#fd_gossip_ip6_addr_generate)


---
### fd\_gossip\_ip\_addr\_generate<!-- {{#callable:fd_gossip_ip_addr_generate}} -->
Generates a new gossip IP address structure with random values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the generated IP address structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_ip_addr_t` type to access its fields.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_ip_addr_t` structure.
    - The function calls [`fd_gossip_ip_addr_new`](fd_types.c.driver.md#fd_gossip_ip_addr_new) to initialize the structure.
    - A random discriminant value is generated using the random number generator, which determines the type of IP address (IPv4 or IPv6).
    - The function then calls [`fd_gossip_ip_addr_inner_generate`](#fd_gossip_ip_addr_inner_generate) with the inner structure and the generated discriminant to populate the inner IP address fields.
- **Output**: Returns a pointer to the memory location containing the generated `fd_gossip_ip_addr_t` structure.
- **Functions called**:
    - [`fd_gossip_ip_addr_new`](fd_types.c.driver.md#fd_gossip_ip_addr_new)
    - [`fd_gossip_ip_addr_inner_generate`](#fd_gossip_ip_addr_inner_generate)


---
### fd\_gossip\_prune\_data\_generate<!-- {{#callable:fd_gossip_prune_data_generate}} -->
Generates gossip prune data including public keys and signatures.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_prune_data_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_prune_data_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_prune_data_t` structure.
    - It generates a new public key for the `pubkey` field of the structure.
    - It randomly determines the length of the `prunes` array (up to 7).
    - If `prunes_len` is greater than 0, it allocates memory for the `prunes` array and generates public keys for each entry.
    - If `prunes_len` is 0, it sets the `prunes` pointer to NULL.
    - It generates a signature for the `signature` field.
    - It generates a public key for the `destination` field.
    - It assigns a random value to the `wallclock` field.
- **Output**: Returns a pointer to the initialized `fd_gossip_prune_data_t` structure.
- **Functions called**:
    - [`fd_gossip_prune_data_new`](fd_types.c.driver.md#fd_gossip_prune_data_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_signature_generate`](#fd_signature_generate)


---
### fd\_gossip\_prune\_sign\_data\_generate<!-- {{#callable:fd_gossip_prune_sign_data_generate}} -->
Generates a new `fd_gossip_prune_sign_data_t` structure with associated public keys and prunes.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_prune_sign_data_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to `fd_gossip_prune_sign_data_t` and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_prune_sign_data_t` structure.
    - Generates a public key for the `pubkey` field of the structure.
    - Determines the number of prunes (`prunes_len`) randomly, which can be between 0 and 7.
    - If `prunes_len` is greater than 0, it allocates memory for the `prunes` array and generates public keys for each prune.
    - Generates a public key for the `destination` field.
    - Sets a random wallclock value.
- **Output**: Returns a pointer to the initialized `fd_gossip_prune_sign_data_t` structure.
- **Functions called**:
    - [`fd_gossip_prune_sign_data_new`](fd_types.c.driver.md#fd_gossip_prune_sign_data_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_gossip\_prune\_sign\_data\_with\_prefix\_generate<!-- {{#callable:fd_gossip_prune_sign_data_with_prefix_generate}} -->
Generates a `fd_gossip_prune_sign_data_with_prefix_t` structure with a random prefix and associated data.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_prune_sign_data_with_prefix_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_prune_sign_data_with_prefix_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the structure.
    - It initializes the structure by calling [`fd_gossip_prune_sign_data_with_prefix_new`](fd_types.c.driver.md#fd_gossip_prune_sign_data_with_prefix_new).
    - A random prefix length is generated using `fd_rng_ulong` and stored in `self->prefix_len`.
    - If the prefix length is greater than zero, memory is allocated for the prefix and filled with random values.
    - The function then calls [`fd_gossip_prune_sign_data_generate`](#fd_gossip_prune_sign_data_generate) to generate the associated data.
    - Finally, it returns the original `mem` pointer.
- **Output**: Returns a pointer to the initialized `fd_gossip_prune_sign_data_with_prefix_t` structure.
- **Functions called**:
    - [`fd_gossip_prune_sign_data_with_prefix_new`](fd_types.c.driver.md#fd_gossip_prune_sign_data_with_prefix_new)
    - [`fd_gossip_prune_sign_data_generate`](#fd_gossip_prune_sign_data_generate)


---
### fd\_gossip\_socket\_addr\_old\_generate<!-- {{#callable:fd_gossip_socket_addr_old_generate}} -->
Generates a new `fd_gossip_socket_addr_old_t` structure with a random IP address and port.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_socket_addr_old_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_socket_addr_old_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_socket_addr_old_t` structure.
    - It calls [`fd_gossip_ip_addr_generate`](#fd_gossip_ip_addr_generate) to generate a random IP address and store it in the `addr` field of the structure.
    - It assigns a random port number to the `port` field using `fd_rng_ushort`.
- **Output**: Returns a pointer to the allocated `fd_gossip_socket_addr_old_t` structure.
- **Functions called**:
    - [`fd_gossip_socket_addr_old_new`](fd_types.c.driver.md#fd_gossip_socket_addr_old_new)
    - [`fd_gossip_ip_addr_generate`](#fd_gossip_ip_addr_generate)


---
### fd\_gossip\_socket\_addr\_ip4\_generate<!-- {{#callable:fd_gossip_socket_addr_ip4_generate}} -->
Generates a new IPv4 gossip socket address.
- **Inputs**:
    - `mem`: A pointer to the memory location where the generated address structure will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type `fd_gossip_socket_addr_ip4_t`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_socket_addr_ip4_t` structure.
    - The function calls [`fd_gossip_socket_addr_ip4_new`](fd_types.c.driver.md#fd_gossip_socket_addr_ip4_new) to initialize the structure.
    - It generates a random IPv4 address using [`fd_gossip_ip4_addr_generate`](#fd_gossip_ip4_addr_generate).
    - A random port number is generated using `fd_rng_ushort` and assigned to the `port` field of the structure.
    - Finally, the function returns the pointer to the memory location where the address structure is stored.
- **Output**: Returns a pointer to the memory location containing the generated `fd_gossip_socket_addr_ip4_t` structure.
- **Functions called**:
    - [`fd_gossip_socket_addr_ip4_new`](fd_types.c.driver.md#fd_gossip_socket_addr_ip4_new)
    - [`fd_gossip_ip4_addr_generate`](#fd_gossip_ip4_addr_generate)


---
### fd\_gossip\_socket\_addr\_ip6\_generate<!-- {{#callable:fd_gossip_socket_addr_ip6_generate}} -->
Generates an IPv6 gossip socket address structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_socket_addr_ip6_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_socket_addr_ip6_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_socket_addr_ip6_t` structure.
    - The function calls [`fd_gossip_socket_addr_ip6_new`](fd_types.c.driver.md#fd_gossip_socket_addr_ip6_new) to initialize the structure.
    - It generates a random IPv6 address using [`fd_gossip_ip6_addr_generate`](#fd_gossip_ip6_addr_generate).
    - The port, flowinfo, and scope_id fields are populated with random values using `fd_rng_ushort` and `fd_rng_uint`.
- **Output**: Returns a pointer to the initialized `fd_gossip_socket_addr_ip6_t` structure.
- **Functions called**:
    - [`fd_gossip_socket_addr_ip6_new`](fd_types.c.driver.md#fd_gossip_socket_addr_ip6_new)
    - [`fd_gossip_ip6_addr_generate`](#fd_gossip_ip6_addr_generate)


---
### fd\_gossip\_socket\_addr\_inner\_generate<!-- {{#callable:fd_gossip_socket_addr_inner_generate}} -->
Generates a socket address based on the provided discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_gossip_socket_addr_inner_t` where the generated address will be stored.
    - `alloc_mem`: A double pointer to memory allocation space for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which type of socket address to generate (IPv4 or IPv6).
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which type of socket address to generate.
    - If `discriminant` is 0, it calls [`fd_gossip_socket_addr_ip4_generate`](#fd_gossip_socket_addr_ip4_generate) to generate an IPv4 address.
    - If `discriminant` is 1, it calls [`fd_gossip_socket_addr_ip6_generate`](#fd_gossip_socket_addr_ip6_generate) to generate an IPv6 address.
- **Output**: The function does not return a value; instead, it populates the `self` structure with the generated socket address.
- **Functions called**:
    - [`fd_gossip_socket_addr_ip4_generate`](#fd_gossip_socket_addr_ip4_generate)
    - [`fd_gossip_socket_addr_ip6_generate`](#fd_gossip_socket_addr_ip6_generate)


---
### fd\_gossip\_socket\_addr\_generate<!-- {{#callable:fd_gossip_socket_addr_generate}} -->
Generates a new `fd_gossip_socket_addr_t` structure with a random address and port.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_gossip_socket_addr_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator state used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_socket_addr_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_socket_addr_t` structure.
    - It calls [`fd_gossip_socket_addr_new`](fd_types.c.driver.md#fd_gossip_socket_addr_new) to initialize the structure.
    - It generates a random `discriminant` value (0 or 1) using the random number generator.
    - It calls [`fd_gossip_socket_addr_inner_generate`](#fd_gossip_socket_addr_inner_generate) with the inner structure and the generated `discriminant` to initialize the inner address structure.
- **Output**: Returns a pointer to the initialized `fd_gossip_socket_addr_t` structure.
- **Functions called**:
    - [`fd_gossip_socket_addr_new`](fd_types.c.driver.md#fd_gossip_socket_addr_new)
    - [`fd_gossip_socket_addr_inner_generate`](#fd_gossip_socket_addr_inner_generate)


---
### fd\_gossip\_contact\_info\_v1\_generate<!-- {{#callable:fd_gossip_contact_info_v1_generate}} -->
Generates a new `fd_gossip_contact_info_v1_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_contact_info_v1_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_contact_info_v1_t` structure.
    - It updates the `alloc_mem` pointer to allocate enough space for the `fd_gossip_contact_info_v1_t` structure.
    - It calls [`fd_gossip_contact_info_v1_new`](fd_types.c.driver.md#fd_gossip_contact_info_v1_new) to initialize the structure.
    - It generates a public key for the `id` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates multiple socket addresses for various fields (gossip, tvu, tvu_fwd, repair, tpu, tpu_fwd, tpu_vote, rpc, rpc_pubsub, serve_repair) using [`fd_gossip_socket_addr_generate`](#fd_gossip_socket_addr_generate).
    - It assigns a random value to the `wallclock` field using `fd_rng_ulong`.
    - It assigns a random value to the `shred_version` field using `fd_rng_ushort`.
- **Output**: Returns a pointer to the initialized `fd_gossip_contact_info_v1_t` structure.
- **Functions called**:
    - [`fd_gossip_contact_info_v1_new`](fd_types.c.driver.md#fd_gossip_contact_info_v1_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_gossip_socket_addr_generate`](#fd_gossip_socket_addr_generate)


---
### fd\_gossip\_vote\_generate<!-- {{#callable:fd_gossip_vote_generate}} -->
Generates a new `fd_gossip_vote_t` structure with randomized fields.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_vote_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_vote_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_vote_t` structure.
    - The [`fd_gossip_vote_new`](fd_types.c.driver.md#fd_gossip_vote_new) function is called to initialize the structure.
    - A random index is assigned to the `index` field of the structure using the random number generator.
    - The [`fd_pubkey_generate`](#fd_pubkey_generate) function is called to generate a public key for the `from` field.
    - The [`fd_flamenco_txn_generate`](#fd_flamenco_txn_generate) function is called to generate a transaction for the `txn` field.
    - A random wallclock value is assigned to the `wallclock` field using the random number generator.
    - Finally, the function returns the pointer to the initialized `fd_gossip_vote_t` structure.
- **Output**: Returns a pointer to the initialized `fd_gossip_vote_t` structure.
- **Functions called**:
    - [`fd_gossip_vote_new`](fd_types.c.driver.md#fd_gossip_vote_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_flamenco_txn_generate`](#fd_flamenco_txn_generate)


---
### fd\_gossip\_lowest\_slot\_generate<!-- {{#callable:fd_gossip_lowest_slot_generate}} -->
Generates a new `fd_gossip_lowest_slot_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_gossip_lowest_slot_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_lowest_slot_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_lowest_slot_t` structure.
    - It calls [`fd_gossip_lowest_slot_new`](fd_types.c.driver.md#fd_gossip_lowest_slot_new) to initialize the structure.
    - Random values are generated for the `u8`, `from`, `root`, `lowest`, and `i_dont_know` fields using the provided RNG.
    - The `slots_len` field is set to a random value between 0 and 7, and if it's greater than 0, memory is allocated for the `slots` array.
    - If `slots_len` is greater than 0, the [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) function is called to mutate the allocated memory for `slots`.
- **Output**: Returns a pointer to the initialized `fd_gossip_lowest_slot_t` structure.
- **Functions called**:
    - [`fd_gossip_lowest_slot_new`](fd_types.c.driver.md#fd_gossip_lowest_slot_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_gossip\_slot\_hashes\_generate<!-- {{#callable:fd_gossip_slot_hashes_generate}} -->
Generates gossip slot hashes for a given memory context.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_gossip_slot_hashes_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_gossip_slot_hashes_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_slot_hashes_t` structure.
    - The [`fd_gossip_slot_hashes_new`](fd_types.c.driver.md#fd_gossip_slot_hashes_new) function is called to initialize the structure.
    - A public key is generated and stored in the `from` field of the structure using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - A random length for the hashes is generated, constrained to a maximum of 7.
    - If the generated length is greater than zero, memory is allocated for the hashes array, and each hash is initialized and generated in a loop.
    - If the length is zero, the hashes pointer is set to NULL.
    - Finally, a wallclock value is generated and stored in the `wallclock` field.
- **Output**: Returns a pointer to the initialized `fd_gossip_slot_hashes_t` structure.
- **Functions called**:
    - [`fd_gossip_slot_hashes_new`](fd_types.c.driver.md#fd_gossip_slot_hashes_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_slot_hash_new`](fd_types.h.driver.md#fd_slot_hash_new)
    - [`fd_slot_hash_generate`](#fd_slot_hash_generate)


---
### fd\_gossip\_slots\_generate<!-- {{#callable:fd_gossip_slots_generate}} -->
Generates a new `fd_gossip_slots_t` structure with randomized slot values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_slots_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_slots_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_gossip_slots_t` structure.
    - It initializes the `fd_gossip_slots_t` structure by calling `fd_gossip_slots_new(mem)`.
    - It generates a random value for `first_slot` using `fd_rng_ulong(rng)`.
    - It generates a random value for `num` using `fd_rng_ulong(rng)`.
    - It randomly determines if slots are present by generating a random byte and checking if it is odd.
    - If slots are present, it generates a random length for the `slots_bitvec` and allocates memory for it.
    - If the length is greater than zero, it fills the `slots_bitvec` with random values.
- **Output**: Returns a pointer to the initialized `fd_gossip_slots_t` structure.
- **Functions called**:
    - [`fd_gossip_slots_new`](fd_types.c.driver.md#fd_gossip_slots_new)


---
### fd\_gossip\_flate2\_slots\_generate<!-- {{#callable:fd_gossip_flate2_slots_generate}} -->
Generates a new `fd_gossip_flate2_slots_t` structure with random values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_flate2_slots_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_flate2_slots_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_flate2_slots_t` structure.
    - The function initializes the structure by calling `fd_gossip_flate2_slots_new(mem)`.
    - It generates a random value for `first_slot` using `fd_rng_ulong(rng)`.
    - It generates a random value for `num` using `fd_rng_ulong(rng)`.
    - It generates a random value for `compressed_len` using `fd_rng_ulong(rng) % 8`.
    - If `compressed_len` is greater than zero, it allocates memory for `compressed` and fills it with random values using a loop.
    - If `compressed_len` is zero, it sets `compressed` to NULL.
- **Output**: Returns a pointer to the initialized `fd_gossip_flate2_slots_t` structure.
- **Functions called**:
    - [`fd_gossip_flate2_slots_new`](fd_types.c.driver.md#fd_gossip_flate2_slots_new)


---
### fd\_gossip\_slots\_enum\_inner\_generate<!-- {{#callable:fd_gossip_slots_enum_inner_generate}} -->
Generates gossip slots based on a discriminant value.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_gossip_slots_enum_inner_t`, which holds the state for gossip slots.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which type of gossip slots to generate.
    - `rng`: A pointer to a random number generator of type `fd_rng_t` used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value to determine which case to execute.
    - If `discriminant` is 0, it calls [`fd_gossip_flate2_slots_generate`](#fd_gossip_flate2_slots_generate) to generate flate2 compressed slots.
    - If `discriminant` is 1, it calls [`fd_gossip_slots_generate`](#fd_gossip_slots_generate) to generate uncompressed slots.
- **Output**: The function does not return a value; it modifies the state of the `self` object based on the generated gossip slots.
- **Functions called**:
    - [`fd_gossip_flate2_slots_generate`](#fd_gossip_flate2_slots_generate)
    - [`fd_gossip_slots_generate`](#fd_gossip_slots_generate)


---
### fd\_gossip\_slots\_enum\_generate<!-- {{#callable:fd_gossip_slots_enum_generate}} -->
Generates a new `fd_gossip_slots_enum_t` structure with a random discriminant and initializes its inner structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_slots_enum_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to `fd_gossip_slots_enum_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_slots_enum_t` structure.
    - It calls [`fd_gossip_slots_enum_new`](fd_types.c.driver.md#fd_gossip_slots_enum_new) to initialize the structure.
    - It generates a random discriminant value (0 or 1) using the random number generator.
    - It calls [`fd_gossip_slots_enum_inner_generate`](#fd_gossip_slots_enum_inner_generate) with the inner structure and the generated discriminant to initialize it.
- **Output**: Returns a pointer to the initialized `fd_gossip_slots_enum_t` structure.
- **Functions called**:
    - [`fd_gossip_slots_enum_new`](fd_types.c.driver.md#fd_gossip_slots_enum_new)
    - [`fd_gossip_slots_enum_inner_generate`](#fd_gossip_slots_enum_inner_generate)


---
### fd\_gossip\_epoch\_slots\_generate<!-- {{#callable:fd_gossip_epoch_slots_generate}} -->
Generates a new `fd_gossip_epoch_slots_t` structure with random values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_epoch_slots_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to `fd_gossip_epoch_slots_t` and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_epoch_slots_t` structure.
    - It generates a random value for the `u8` field of the structure.
    - It generates a new public key for the `from` field using the provided random number generator.
    - It generates a random length for the `slots` array, which can be between 0 and 7.
    - If `slots_len` is greater than 0, it allocates memory for the `slots` array and initializes each slot using a loop.
    - Finally, it generates a random value for the `wallclock` field.
- **Output**: Returns a pointer to the initialized `fd_gossip_epoch_slots_t` structure.
- **Functions called**:
    - [`fd_gossip_epoch_slots_new`](fd_types.c.driver.md#fd_gossip_epoch_slots_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_gossip_slots_enum_new`](fd_types.c.driver.md#fd_gossip_slots_enum_new)
    - [`fd_gossip_slots_enum_generate`](#fd_gossip_slots_enum_generate)


---
### fd\_gossip\_version\_v1\_generate<!-- {{#callable:fd_gossip_version_v1_generate}} -->
Generates a new version of the gossip protocol with random attributes.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_version_v1_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_version_v1_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_version_v1_t` structure.
    - It calls [`fd_gossip_version_v1_new`](fd_types.c.driver.md#fd_gossip_version_v1_new) to initialize the structure.
    - It generates a public key for the `from` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It assigns random values to the `wallclock`, `major`, `minor`, and `patch` fields using the random number generator.
    - It randomly determines if the `has_commit` field is set and mutates the `commit` field if true.
- **Output**: Returns a pointer to the initialized `fd_gossip_version_v1_t` structure.
- **Functions called**:
    - [`fd_gossip_version_v1_new`](fd_types.c.driver.md#fd_gossip_version_v1_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_gossip\_version\_v2\_generate<!-- {{#callable:fd_gossip_version_v2_generate}} -->
Generates a new version 2 gossip message structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_version_v2_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for the fields of the gossip version.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_version_v2_t` structure type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_version_v2_t` structure.
    - The function initializes the `fd_gossip_version_v2_t` structure by calling `fd_gossip_version_v2_new(mem)`.
    - It generates a public key for the `from` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - The `wallclock`, `major`, `minor`, and `patch` fields are populated with random values generated by the `fd_rng` functions.
    - If the `has_commit` field is set to true (randomly determined), the `commit` field is mutated using [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate).
    - Finally, the function assigns a random value to the `feature_set` field.
- **Output**: Returns a pointer to the initialized `fd_gossip_version_v2_t` structure.
- **Functions called**:
    - [`fd_gossip_version_v2_new`](fd_types.c.driver.md#fd_gossip_version_v2_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_gossip\_version\_v3\_generate<!-- {{#callable:fd_gossip_version_v3_generate}} -->
Generates a new version 3 gossip structure with random versioning information.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_gossip_version_v3_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for the version fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_version_v3_t` structure type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_version_v3_t` structure.
    - It calls [`fd_gossip_version_v3_new`](fd_types.c.driver.md#fd_gossip_version_v3_new) to initialize the structure.
    - It generates random values for the `major`, `minor`, `patch`, `commit`, `feature_set`, and `client` fields using the provided random number generator.
- **Output**: Returns a pointer to the initialized `fd_gossip_version_v3_t` structure.
- **Functions called**:
    - [`fd_gossip_version_v3_new`](fd_types.c.driver.md#fd_gossip_version_v3_new)


---
### fd\_gossip\_node\_instance\_generate<!-- {{#callable:fd_gossip_node_instance_generate}} -->
Generates a new instance of a gossip node with random attributes.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_node_instance_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_node_instance_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_node_instance_t` structure.
    - It calls [`fd_gossip_node_instance_new`](fd_types.h.driver.md#fd_gossip_node_instance_new) to initialize the node instance.
    - It generates a public key for the `from` field of the node instance using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It assigns random values to the `wallclock`, `timestamp`, and `token` fields using the random number generator.
- **Output**: Returns a pointer to the initialized `fd_gossip_node_instance_t` structure.
- **Functions called**:
    - [`fd_gossip_node_instance_new`](fd_types.h.driver.md#fd_gossip_node_instance_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_gossip\_duplicate\_shred\_generate<!-- {{#callable:fd_gossip_duplicate_shred_generate}} -->
Generates a new `fd_gossip_duplicate_shred_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_gossip_duplicate_shred_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_duplicate_shred_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_duplicate_shred_t` structure.
    - It calls [`fd_gossip_duplicate_shred_new`](fd_types.c.driver.md#fd_gossip_duplicate_shred_new) to initialize the structure.
    - Random values are generated for various fields of the structure using the provided `rng`.
    - If `chunk_len` is greater than zero, it allocates memory for `chunk` and fills it with random values.
- **Output**: Returns a pointer to the initialized `fd_gossip_duplicate_shred_t` structure.
- **Functions called**:
    - [`fd_gossip_duplicate_shred_new`](fd_types.c.driver.md#fd_gossip_duplicate_shred_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_gossip\_incremental\_snapshot\_hashes\_generate<!-- {{#callable:fd_gossip_incremental_snapshot_hashes_generate}} -->
Generates incremental snapshot hashes for gossip protocol.
- **Inputs**:
    - `mem`: Pointer to memory where the `fd_gossip_incremental_snapshot_hashes_t` structure will be initialized.
    - `alloc_mem`: Pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: Pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_incremental_snapshot_hashes_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_incremental_snapshot_hashes_t` structure.
    - It initializes the structure by calling [`fd_gossip_incremental_snapshot_hashes_new`](fd_types.c.driver.md#fd_gossip_incremental_snapshot_hashes_new).
    - It generates a public key and a base hash using [`fd_pubkey_generate`](#fd_pubkey_generate) and [`fd_slot_hash_generate`](#fd_slot_hash_generate), respectively.
    - It randomly determines the length of the hashes array (up to 8) and allocates memory for it if the length is greater than zero.
    - If hashes are to be generated, it iterates through the length, initializing each hash using [`fd_slot_hash_new`](fd_types.h.driver.md#fd_slot_hash_new) and generating a hash for each using [`fd_slot_hash_generate`](#fd_slot_hash_generate).
    - Finally, it sets a wallclock value using `fd_rng_ulong` and returns the original `mem` pointer.
- **Output**: Returns a pointer to the initialized `fd_gossip_incremental_snapshot_hashes_t` structure.
- **Functions called**:
    - [`fd_gossip_incremental_snapshot_hashes_new`](fd_types.c.driver.md#fd_gossip_incremental_snapshot_hashes_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_slot_hash_generate`](#fd_slot_hash_generate)
    - [`fd_slot_hash_new`](fd_types.h.driver.md#fd_slot_hash_new)


---
### fd\_gossip\_socket\_entry\_generate<!-- {{#callable:fd_gossip_socket_entry_generate}} -->
Generates a new `fd_gossip_socket_entry_t` structure with random values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_socket_entry_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_socket_entry_t` type.
    - It updates the `alloc_mem` pointer to allocate space for a new `fd_gossip_socket_entry_t` structure.
    - It calls `fd_gossip_socket_entry_new(mem)` to initialize the structure.
    - It generates a random `key` using `fd_rng_uchar(rng)`.
    - It generates a random `index` using `fd_rng_uchar(rng)`.
    - It generates a random `offset` using `fd_rng_ushort(rng)`.
    - Finally, it returns the pointer to the initialized structure.
- **Output**: Returns a pointer to the allocated and initialized `fd_gossip_socket_entry_t` structure.
- **Functions called**:
    - [`fd_gossip_socket_entry_new`](fd_types.c.driver.md#fd_gossip_socket_entry_new)


---
### fd\_gossip\_contact\_info\_v2\_generate<!-- {{#callable:fd_gossip_contact_info_v2_generate}} -->
Generates a new `fd_gossip_contact_info_v2_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_contact_info_v2_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_gossip_contact_info_v2_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the new structure.
    - The [`fd_gossip_contact_info_v2_new`](fd_types.c.driver.md#fd_gossip_contact_info_v2_new) function is called to initialize the structure.
    - Random values are generated for the `from`, `wallclock`, `outset`, and `shred_version` fields.
    - The [`fd_gossip_version_v3_generate`](#fd_gossip_version_v3_generate) function is called to initialize the `version` field.
    - The length of the `addrs` array is determined randomly, and if greater than zero, memory is allocated for it and initialized.
    - For each address in the `addrs` array, the [`fd_gossip_ip_addr_generate`](#fd_gossip_ip_addr_generate) function is called to populate it with random data.
    - Similarly, the length of the `sockets` array is determined and initialized if greater than zero.
    - For each socket in the `sockets` array, the [`fd_gossip_socket_entry_generate`](#fd_gossip_socket_entry_generate) function is called to populate it with random data.
    - The length of the `extensions` array is determined and initialized if greater than zero, with random data generated for it.
- **Output**: Returns a pointer to the initialized `fd_gossip_contact_info_v2_t` structure.
- **Functions called**:
    - [`fd_gossip_contact_info_v2_new`](fd_types.c.driver.md#fd_gossip_contact_info_v2_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_gossip_version_v3_generate`](#fd_gossip_version_v3_generate)
    - [`fd_gossip_ip_addr_new`](fd_types.c.driver.md#fd_gossip_ip_addr_new)
    - [`fd_gossip_ip_addr_generate`](#fd_gossip_ip_addr_generate)
    - [`fd_gossip_socket_entry_new`](fd_types.c.driver.md#fd_gossip_socket_entry_new)
    - [`fd_gossip_socket_entry_generate`](#fd_gossip_socket_entry_generate)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_restart\_run\_length\_encoding\_inner\_generate<!-- {{#callable:fd_restart_run_length_encoding_inner_generate}} -->
Generates a new instance of `fd_restart_run_length_encoding_inner_t` with a random bit value.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_restart_run_length_encoding_inner_t` instance will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_restart_run_length_encoding_inner_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_restart_run_length_encoding_inner_t` instance.
    - It calls [`fd_restart_run_length_encoding_inner_new`](fd_types.c.driver.md#fd_restart_run_length_encoding_inner_new) to initialize the instance.
    - It generates a random ushort value using the `rng` and assigns it to the `bits` field of the instance.
- **Output**: Returns a pointer to the allocated and initialized `fd_restart_run_length_encoding_inner_t` instance.
- **Functions called**:
    - [`fd_restart_run_length_encoding_inner_new`](fd_types.c.driver.md#fd_restart_run_length_encoding_inner_new)


---
### fd\_restart\_run\_length\_encoding\_generate<!-- {{#callable:fd_restart_run_length_encoding_generate}} -->
Generates a run-length encoding structure with optional offsets.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_restart_run_length_encoding_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the offsets.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_restart_run_length_encoding_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_restart_run_length_encoding_t` structure.
    - It initializes the `fd_restart_run_length_encoding_t` structure by calling [`fd_restart_run_length_encoding_new`](fd_types.c.driver.md#fd_restart_run_length_encoding_new).
    - It generates a random length for the offsets (up to 7) using the random number generator.
    - If the generated length is greater than zero, it allocates memory for the offsets and initializes each offset using a loop.
    - For each offset, it calls [`fd_restart_run_length_encoding_inner_new`](fd_types.c.driver.md#fd_restart_run_length_encoding_inner_new) and [`fd_restart_run_length_encoding_inner_generate`](#fd_restart_run_length_encoding_inner_generate) to initialize and generate the inner structure.
- **Output**: Returns a pointer to the initialized `fd_restart_run_length_encoding_t` structure.
- **Functions called**:
    - [`fd_restart_run_length_encoding_new`](fd_types.c.driver.md#fd_restart_run_length_encoding_new)
    - [`fd_restart_run_length_encoding_inner_new`](fd_types.c.driver.md#fd_restart_run_length_encoding_inner_new)
    - [`fd_restart_run_length_encoding_inner_generate`](#fd_restart_run_length_encoding_inner_generate)


---
### fd\_restart\_raw\_offsets\_generate<!-- {{#callable:fd_restart_raw_offsets_generate}} -->
Generates raw offsets for a restart, potentially including a bit vector of offsets.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_restart_raw_offsets_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the offsets.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_restart_raw_offsets_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_restart_raw_offsets_t` structure.
    - The function initializes the structure by calling `fd_restart_raw_offsets_new(mem)`.
    - A random value is generated to determine if offsets will be included (0 or 1).
    - If offsets are included, another random value determines the length of the offsets bit vector (up to 8).
    - If the length is greater than zero, memory is allocated for the offsets bit vector, and random values are generated for each offset.
    - If no offsets are included, the length is set to zero.
- **Output**: Returns a pointer to the initialized `fd_restart_raw_offsets_t` structure.
- **Functions called**:
    - [`fd_restart_raw_offsets_new`](fd_types.c.driver.md#fd_restart_raw_offsets_new)


---
### fd\_restart\_slots\_offsets\_inner\_generate<!-- {{#callable:fd_restart_slots_offsets_inner_generate}} -->
Generates offsets for restart slots based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_restart_slots_offsets_inner_t` that holds the state for the offsets.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which type of offset generation to perform.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which case to execute.
    - If `discriminant` is 0, it calls [`fd_restart_run_length_encoding_generate`](#fd_restart_run_length_encoding_generate) to generate run length encoding offsets.
    - If `discriminant` is 1, it calls [`fd_restart_raw_offsets_generate`](#fd_restart_raw_offsets_generate) to generate raw offsets.
- **Output**: The function does not return a value; it modifies the `self` structure based on the generated offsets.
- **Functions called**:
    - [`fd_restart_run_length_encoding_generate`](#fd_restart_run_length_encoding_generate)
    - [`fd_restart_raw_offsets_generate`](#fd_restart_raw_offsets_generate)


---
### fd\_restart\_slots\_offsets\_generate<!-- {{#callable:fd_restart_slots_offsets_generate}} -->
Generates offsets for restart slots based on a random discriminant.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_restart_slots_offsets_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_restart_slots_offsets_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_restart_slots_offsets_t` structure.
    - It calls [`fd_restart_slots_offsets_new`](fd_types.c.driver.md#fd_restart_slots_offsets_new) to initialize the structure.
    - It generates a random `discriminant` value (0 or 1) using the random number generator.
    - Based on the `discriminant`, it calls [`fd_restart_slots_offsets_inner_generate`](#fd_restart_slots_offsets_inner_generate) to initialize the inner structure.
- **Output**: Returns a pointer to the initialized `fd_restart_slots_offsets_t` structure.
- **Functions called**:
    - [`fd_restart_slots_offsets_new`](fd_types.c.driver.md#fd_restart_slots_offsets_new)
    - [`fd_restart_slots_offsets_inner_generate`](#fd_restart_slots_offsets_inner_generate)


---
### fd\_gossip\_restart\_last\_voted\_fork\_slots\_generate<!-- {{#callable:fd_gossip_restart_last_voted_fork_slots_generate}} -->
Generates the last voted fork slots for gossip protocol.
- **Inputs**:
    - `mem`: A pointer to a memory location where the generated data will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a specific structure type.
    - It updates the allocation memory pointer to account for the size of the structure being generated.
    - It initializes the structure by calling [`fd_gossip_restart_last_voted_fork_slots_new`](fd_types.c.driver.md#fd_gossip_restart_last_voted_fork_slots_new).
    - It generates a public key and assigns it to the 'from' field of the structure.
    - It sets the wallclock field with a random unsigned long value.
    - It generates offsets for restart slots by calling [`fd_restart_slots_offsets_generate`](#fd_restart_slots_offsets_generate).
    - It assigns a random last voted slot value.
    - It generates a hash for the last voted slot and assigns it to the structure.
    - It sets the shred version with a random unsigned short value.
- **Output**: Returns a pointer to the memory location containing the generated `fd_gossip_restart_last_voted_fork_slots_t` structure.
- **Functions called**:
    - [`fd_gossip_restart_last_voted_fork_slots_new`](fd_types.c.driver.md#fd_gossip_restart_last_voted_fork_slots_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_restart_slots_offsets_generate`](#fd_restart_slots_offsets_generate)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_gossip\_restart\_heaviest\_fork\_generate<!-- {{#callable:fd_gossip_restart_heaviest_fork_generate}} -->
Generates a new `fd_gossip_restart_heaviest_fork_t` structure with randomized values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_gossip_restart_heaviest_fork_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_restart_heaviest_fork_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_restart_heaviest_fork_t` structure.
    - It calls [`fd_gossip_restart_heaviest_fork_new`](fd_types.h.driver.md#fd_gossip_restart_heaviest_fork_new) to initialize the structure.
    - It generates a public key for the `from` field using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It assigns random values to `wallclock`, `last_slot`, `observed_stake`, and `shred_version` using the random number generator.
    - It generates a hash for the `last_slot_hash` field using [`fd_hash_generate`](#fd_hash_generate).
- **Output**: Returns a pointer to the initialized `fd_gossip_restart_heaviest_fork_t` structure.
- **Functions called**:
    - [`fd_gossip_restart_heaviest_fork_new`](fd_types.h.driver.md#fd_gossip_restart_heaviest_fork_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_hash_generate`](#fd_hash_generate)


---
### fd\_crds\_data\_inner\_generate<!-- {{#callable:fd_crds_data_inner_generate}} -->
Generates inner data for `fd_crds_data_inner_t` based on a discriminant value.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_crds_data_inner_t` where the generated data will be stored.
    - `alloc_mem`: A pointer to a pointer that tracks the allocated memory for the generated data.
    - `discriminant`: An unsigned integer that determines which type of data to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value to determine which case to execute.
    - For each case (0 to 13), it calls a specific generation function corresponding to the type of data to be generated.
    - Each case generates a different type of gossip-related data and stores it in the appropriate field of the `self` structure.
- **Output**: The function does not return a value; instead, it populates the fields of the `self` structure with generated data based on the discriminant.
- **Functions called**:
    - [`fd_gossip_contact_info_v1_generate`](#fd_gossip_contact_info_v1_generate)
    - [`fd_gossip_vote_generate`](#fd_gossip_vote_generate)
    - [`fd_gossip_lowest_slot_generate`](#fd_gossip_lowest_slot_generate)
    - [`fd_gossip_slot_hashes_generate`](#fd_gossip_slot_hashes_generate)
    - [`fd_gossip_epoch_slots_generate`](#fd_gossip_epoch_slots_generate)
    - [`fd_gossip_version_v1_generate`](#fd_gossip_version_v1_generate)
    - [`fd_gossip_version_v2_generate`](#fd_gossip_version_v2_generate)
    - [`fd_gossip_node_instance_generate`](#fd_gossip_node_instance_generate)
    - [`fd_gossip_duplicate_shred_generate`](#fd_gossip_duplicate_shred_generate)
    - [`fd_gossip_incremental_snapshot_hashes_generate`](#fd_gossip_incremental_snapshot_hashes_generate)
    - [`fd_gossip_contact_info_v2_generate`](#fd_gossip_contact_info_v2_generate)
    - [`fd_gossip_restart_last_voted_fork_slots_generate`](#fd_gossip_restart_last_voted_fork_slots_generate)
    - [`fd_gossip_restart_heaviest_fork_generate`](#fd_gossip_restart_heaviest_fork_generate)


---
### fd\_crds\_data\_generate<!-- {{#callable:fd_crds_data_generate}} -->
Generates a new `fd_crds_data_t` structure with a random discriminant and initializes its inner data.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_crds_data_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_crds_data_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_crds_data_t` structure.
    - The function calls [`fd_crds_data_new`](fd_types.c.driver.md#fd_crds_data_new) to initialize the structure.
    - A random discriminant value is generated using the random number generator, which determines the type of inner data to be generated.
    - The function calls [`fd_crds_data_inner_generate`](#fd_crds_data_inner_generate) with the inner structure and the generated discriminant to populate the inner data.
- **Output**: Returns a pointer to the initialized `fd_crds_data_t` structure.
- **Functions called**:
    - [`fd_crds_data_new`](fd_types.c.driver.md#fd_crds_data_new)
    - [`fd_crds_data_inner_generate`](#fd_crds_data_inner_generate)


---
### fd\_crds\_bloom\_generate<!-- {{#callable:fd_crds_bloom_generate}} -->
Generates a new `fd_crds_bloom_t` structure with randomized keys and bits.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_crds_bloom_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the bloom filter.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_crds_bloom_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_crds_bloom_t` structure.
    - The [`fd_crds_bloom_new`](fd_types.c.driver.md#fd_crds_bloom_new) function is called to initialize the bloom filter structure.
    - A random length for the keys is generated, which can be between 0 and 7.
    - If the length of keys is greater than 0, memory is allocated for the keys and they are mutated with random values.
    - A random value is generated to determine if bits are present in the bloom filter.
    - If bits are present, a random length for the bits bit vector is generated, and memory is allocated and mutated accordingly.
    - Finally, a random number of bits set is generated.
- **Output**: Returns a pointer to the initialized `fd_crds_bloom_t` structure.
- **Functions called**:
    - [`fd_crds_bloom_new`](fd_types.c.driver.md#fd_crds_bloom_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_crds\_filter\_generate<!-- {{#callable:fd_crds_filter_generate}} -->
Generates a new `fd_crds_filter_t` structure and initializes its bloom filter and mask values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_crds_filter_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_crds_filter_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_crds_filter_t` structure.
    - The function calls [`fd_crds_bloom_generate`](#fd_crds_bloom_generate) to initialize the bloom filter within the `fd_crds_filter_t` structure.
    - It generates a random value for `self->mask` using `fd_rng_ulong`.
    - It generates a random value for `self->mask_bits` using `fd_rng_uint`.
    - Finally, it returns the pointer to the `fd_crds_filter_t` structure.
- **Output**: Returns a pointer to the initialized `fd_crds_filter_t` structure.
- **Functions called**:
    - [`fd_crds_filter_new`](fd_types.c.driver.md#fd_crds_filter_new)
    - [`fd_crds_bloom_generate`](#fd_crds_bloom_generate)


---
### fd\_crds\_value\_generate<!-- {{#callable:fd_crds_value_generate}} -->
Generates a new `fd_crds_value_t` structure with a signature and associated data.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_crds_value_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_crds_value_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_crds_value_t` structure.
    - It calls [`fd_signature_generate`](#fd_signature_generate) to generate a signature for the `fd_crds_value_t` structure.
    - It calls [`fd_crds_data_generate`](#fd_crds_data_generate) to generate the associated data for the `fd_crds_value_t` structure.
- **Output**: Returns a pointer to the allocated `fd_crds_value_t` structure.
- **Functions called**:
    - [`fd_crds_value_new`](fd_types.c.driver.md#fd_crds_value_new)
    - [`fd_signature_generate`](#fd_signature_generate)
    - [`fd_crds_data_generate`](#fd_crds_data_generate)


---
### fd\_gossip\_pull\_req\_generate<!-- {{#callable:fd_gossip_pull_req_generate}} -->
Generates a new `fd_gossip_pull_req_t` structure with a filter and value.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_pull_req_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_pull_req_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_pull_req_t` structure.
    - It calls [`fd_gossip_pull_req_new`](fd_types.c.driver.md#fd_gossip_pull_req_new) to initialize the `fd_gossip_pull_req_t` structure.
    - It generates a filter for the gossip pull request by calling [`fd_crds_filter_generate`](#fd_crds_filter_generate).
    - It generates a value for the gossip pull request by calling [`fd_crds_value_generate`](#fd_crds_value_generate).
    - Finally, it returns the pointer to the `fd_gossip_pull_req_t` structure.
- **Output**: Returns a pointer to the allocated and initialized `fd_gossip_pull_req_t` structure.
- **Functions called**:
    - [`fd_gossip_pull_req_new`](fd_types.c.driver.md#fd_gossip_pull_req_new)
    - [`fd_crds_filter_generate`](#fd_crds_filter_generate)
    - [`fd_crds_value_generate`](#fd_crds_value_generate)


---
### fd\_gossip\_pull\_resp\_generate<!-- {{#callable:fd_gossip_pull_resp_generate}} -->
Generates a response for a gossip pull request.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_pull_resp_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_pull_resp_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_pull_resp_t` structure.
    - It initializes the `fd_gossip_pull_resp_t` structure by calling `fd_gossip_pull_resp_new(mem)`.
    - It generates a public key for the response using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It randomly determines the length of the `crds` array (up to 8) using `fd_rng_ulong`.
    - If `crds_len` is greater than 0, it allocates memory for the `crds` array and initializes each element using [`fd_crds_value_generate`](#fd_crds_value_generate) in a loop.
    - If `crds_len` is 0, it sets the `crds` pointer to NULL.
- **Output**: Returns a pointer to the initialized `fd_gossip_pull_resp_t` structure.
- **Functions called**:
    - [`fd_gossip_pull_resp_new`](fd_types.c.driver.md#fd_gossip_pull_resp_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_crds_value_new`](fd_types.c.driver.md#fd_crds_value_new)
    - [`fd_crds_value_generate`](#fd_crds_value_generate)


---
### fd\_gossip\_push\_msg\_generate<!-- {{#callable:fd_gossip_push_msg_generate}} -->
Generates a new `fd_gossip_push_msg_t` message structure with a public key and optional CRDS values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_push_msg_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_push_msg_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_push_msg_t` structure.
    - It calls [`fd_pubkey_generate`](#fd_pubkey_generate) to generate a public key and store it in the `pubkey` field of the structure.
    - It generates a random length for the `crds` array, which can be up to 8.
    - If `crds_len` is greater than 0, it allocates memory for the `crds` array and populates it with `fd_crds_value_t` structures, each initialized with random values.
    - If `crds_len` is 0, it sets the `crds` pointer to NULL.
- **Output**: Returns a pointer to the initialized `fd_gossip_push_msg_t` structure.
- **Functions called**:
    - [`fd_gossip_push_msg_new`](fd_types.c.driver.md#fd_gossip_push_msg_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_crds_value_new`](fd_types.c.driver.md#fd_crds_value_new)
    - [`fd_crds_value_generate`](#fd_crds_value_generate)


---
### fd\_gossip\_prune\_msg\_generate<!-- {{#callable:fd_gossip_prune_msg_generate}} -->
Generates a new `fd_gossip_prune_msg_t` message with a public key and prune data.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_gossip_prune_msg_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_gossip_prune_msg_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_prune_msg_t` structure.
    - It calls [`fd_gossip_prune_msg_new`](fd_types.c.driver.md#fd_gossip_prune_msg_new) to initialize the `fd_gossip_prune_msg_t` structure.
    - It generates a public key for the `pubkey` field of the structure using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It generates prune data for the `data` field of the structure using [`fd_gossip_prune_data_generate`](#fd_gossip_prune_data_generate).
    - Finally, it returns the pointer to the initialized `fd_gossip_prune_msg_t` structure.
- **Output**: Returns a pointer to the initialized `fd_gossip_prune_msg_t` structure.
- **Functions called**:
    - [`fd_gossip_prune_msg_new`](fd_types.c.driver.md#fd_gossip_prune_msg_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_gossip_prune_data_generate`](#fd_gossip_prune_data_generate)


---
### fd\_gossip\_msg\_inner\_generate<!-- {{#callable:fd_gossip_msg_inner_generate}} -->
Generates a gossip message based on a discriminant value.
- **Inputs**:
    - `self`: A pointer to a `fd_gossip_msg_inner_t` structure that will hold the generated gossip message.
    - `alloc_mem`: A pointer to a pointer that will be used for memory allocation.
    - `discriminant`: An unsigned integer that determines which type of gossip message to generate.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value to determine which type of gossip message to generate.
    - Based on the value of `discriminant`, it calls the appropriate generation function for the specific message type.
    - The cases include generating pull requests, pull responses, push messages, prune messages, and ping messages.
- **Output**: The function does not return a value; instead, it populates the `self` structure with the generated gossip message.
- **Functions called**:
    - [`fd_gossip_pull_req_generate`](#fd_gossip_pull_req_generate)
    - [`fd_gossip_pull_resp_generate`](#fd_gossip_pull_resp_generate)
    - [`fd_gossip_push_msg_generate`](#fd_gossip_push_msg_generate)
    - [`fd_gossip_prune_msg_generate`](#fd_gossip_prune_msg_generate)
    - [`fd_gossip_ping_generate`](#fd_gossip_ping_generate)


---
### fd\_gossip\_msg\_generate<!-- {{#callable:fd_gossip_msg_generate}} -->
Generates a gossip message with a random discriminant and inner message.
- **Inputs**:
    - `mem`: Pointer to the memory location where the gossip message will be generated.
    - `alloc_mem`: Pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: Pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the input memory pointer to a `fd_gossip_msg_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_gossip_msg_t` structure.
    - The [`fd_gossip_msg_new`](fd_types.c.driver.md#fd_gossip_msg_new) function is called to initialize the gossip message.
    - A random discriminant value is generated using the random number generator, constrained to a range of 0 to 5.
    - A while loop ensures that the discriminant is not 0, 1, or 2, generating a new value if it is.
    - The [`fd_gossip_msg_inner_generate`](#fd_gossip_msg_inner_generate) function is called with the inner message structure, the updated `alloc_mem`, the generated discriminant, and the random number generator.
- **Output**: Returns a pointer to the memory location containing the generated gossip message.
- **Functions called**:
    - [`fd_gossip_msg_new`](fd_types.c.driver.md#fd_gossip_msg_new)
    - [`fd_gossip_msg_inner_generate`](#fd_gossip_msg_inner_generate)


---
### fd\_addrlut\_create\_generate<!-- {{#callable:fd_addrlut_create_generate}} -->
Generates a new address lookup table entry.
- **Inputs**:
    - `mem`: A pointer to the memory location where the address lookup table entry will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the entry.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type `fd_addrlut_create_t`.
    - It updates the `alloc_mem` pointer to allocate space for the new entry.
    - It calls [`fd_addrlut_create_new`](fd_types.h.driver.md#fd_addrlut_create_new) to initialize the new entry.
    - It generates a random value for `recent_slot` using `fd_rng_ulong`.
    - It generates a random value for `bump_seed` using `fd_rng_uchar`.
    - Finally, it returns the pointer to the newly created entry.
- **Output**: Returns a pointer to the memory location of the newly created address lookup table entry.
- **Functions called**:
    - [`fd_addrlut_create_new`](fd_types.h.driver.md#fd_addrlut_create_new)


---
### fd\_addrlut\_extend\_generate<!-- {{#callable:fd_addrlut_extend_generate}} -->
Generates an extended address lookup table by allocating new addresses based on a random length.
- **Inputs**:
    - `mem`: A pointer to the memory location where the address lookup table structure is stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_addrlut_extend_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the new addresses.
    - It initializes the new address lookup table by calling [`fd_addrlut_extend_new`](fd_types.c.driver.md#fd_addrlut_extend_new).
    - It generates a random length for new addresses, which is constrained to a maximum of 7.
    - If the generated length is greater than zero, it allocates memory for the new addresses and populates them using a loop that calls [`fd_pubkey_generate`](#fd_pubkey_generate) for each address.
    - If the generated length is zero, it sets the new addresses pointer to NULL.
- **Output**: Returns a pointer to the updated memory location containing the extended address lookup table.
- **Functions called**:
    - [`fd_addrlut_extend_new`](fd_types.c.driver.md#fd_addrlut_extend_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_addrlut\_instruction\_inner\_generate<!-- {{#callable:fd_addrlut_instruction_inner_generate}} -->
Generates address lookup table instructions based on a discriminant value.
- **Inputs**:
    - `self`: A pointer to an `fd_addrlut_instruction_inner_t` structure that will be populated.
    - `alloc_mem`: A pointer to a pointer that will be used to allocate memory for the generated structures.
    - `discriminant`: An unsigned integer that determines which type of address lookup instruction to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value to determine which case to execute.
    - If `discriminant` is 0, it calls [`fd_addrlut_create_generate`](#fd_addrlut_create_generate) to generate a create instruction.
    - If `discriminant` is 2, it calls [`fd_addrlut_extend_generate`](#fd_addrlut_extend_generate) to generate an extend instruction.
- **Output**: The function does not return a value; it modifies the `self` structure based on the generated instruction.
- **Functions called**:
    - [`fd_addrlut_create_generate`](#fd_addrlut_create_generate)
    - [`fd_addrlut_extend_generate`](#fd_addrlut_extend_generate)


---
### fd\_addrlut\_instruction\_generate<!-- {{#callable:fd_addrlut_instruction_generate}} -->
Generates an address lookup table instruction.
- **Inputs**:
    - `mem`: A pointer to the memory location where the instruction will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a specific structure type `fd_addrlut_instruction_t`.
    - It updates the `alloc_mem` pointer to allocate space for the instruction structure.
    - A random discriminant value is generated to determine which type of address lookup table instruction to create.
    - Based on the discriminant, the appropriate inner instruction generation function is called.
- **Output**: Returns a pointer to the generated address lookup table instruction.
- **Functions called**:
    - [`fd_addrlut_instruction_new`](fd_types.c.driver.md#fd_addrlut_instruction_new)
    - [`fd_addrlut_instruction_inner_generate`](#fd_addrlut_instruction_inner_generate)


---
### fd\_repair\_request\_header\_generate<!-- {{#callable:fd_repair_request_header_generate}} -->
Generates a repair request header with a signature, sender, recipient, timestamp, and nonce.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_repair_request_header_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_repair_request_header_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_repair_request_header_t` structure.
    - It calls [`fd_repair_request_header_new`](fd_types.h.driver.md#fd_repair_request_header_new) to initialize the header structure.
    - It generates a signature for the header using [`fd_signature_generate`](#fd_signature_generate).
    - It generates public keys for the sender and recipient using [`fd_pubkey_generate`](#fd_pubkey_generate).
    - It assigns a random timestamp and nonce using `fd_rng_ulong` and `fd_rng_uint` respectively.
- **Output**: Returns a pointer to the initialized `fd_repair_request_header_t` structure.
- **Functions called**:
    - [`fd_repair_request_header_new`](fd_types.h.driver.md#fd_repair_request_header_new)
    - [`fd_signature_generate`](#fd_signature_generate)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_repair\_window\_index\_generate<!-- {{#callable:fd_repair_window_index_generate}} -->
Generates a new `fd_repair_window_index_t` structure with a repair request header and random slot and shred index values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_repair_window_index_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_repair_window_index_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_repair_window_index_t` structure.
    - It calls [`fd_repair_request_header_generate`](#fd_repair_request_header_generate) to populate the `header` field of the `self` structure.
    - It generates a random `slot` value using `fd_rng_ulong`.
    - It generates a random `shred_index` value using `fd_rng_ulong`.
- **Output**: Returns a pointer to the allocated `fd_repair_window_index_t` structure.
- **Functions called**:
    - [`fd_repair_window_index_new`](fd_types.h.driver.md#fd_repair_window_index_new)
    - [`fd_repair_request_header_generate`](#fd_repair_request_header_generate)


---
### fd\_repair\_highest\_window\_index\_generate<!-- {{#callable:fd_repair_highest_window_index_generate}} -->
Generates a new `fd_repair_highest_window_index_t` structure with initialized fields.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_repair_highest_window_index_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure fields.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_repair_highest_window_index_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_repair_highest_window_index_t` structure.
    - It calls [`fd_repair_highest_window_index_new`](fd_types.h.driver.md#fd_repair_highest_window_index_new) to initialize the structure.
    - It generates a new repair request header by calling [`fd_repair_request_header_generate`](#fd_repair_request_header_generate).
    - It assigns random values to the `slot` and `shred_index` fields using the random number generator.
- **Output**: Returns a pointer to the initialized `fd_repair_highest_window_index_t` structure.
- **Functions called**:
    - [`fd_repair_highest_window_index_new`](fd_types.h.driver.md#fd_repair_highest_window_index_new)
    - [`fd_repair_request_header_generate`](#fd_repair_request_header_generate)


---
### fd\_repair\_orphan\_generate<!-- {{#callable:fd_repair_orphan_generate}} -->
Generates a new `fd_repair_orphan_t` structure and populates it with a repair request header and a random slot.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_repair_orphan_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_repair_orphan_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_repair_orphan_t` structure.
    - It calls [`fd_repair_request_header_generate`](#fd_repair_request_header_generate) to populate the header of the repair orphan.
    - It assigns a random slot value to the `slot` field of the `fd_repair_orphan_t` structure.
    - Finally, it returns the pointer to the `fd_repair_orphan_t` structure.
- **Output**: Returns a pointer to the allocated and initialized `fd_repair_orphan_t` structure.
- **Functions called**:
    - [`fd_repair_orphan_new`](fd_types.h.driver.md#fd_repair_orphan_new)
    - [`fd_repair_request_header_generate`](#fd_repair_request_header_generate)


---
### fd\_repair\_ancestor\_hashes\_generate<!-- {{#callable:fd_repair_ancestor_hashes_generate}} -->
Generates ancestor hashes for a repair request.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_repair_ancestor_hashes_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_repair_ancestor_hashes_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_repair_ancestor_hashes_t` structure.
    - The function calls [`fd_repair_ancestor_hashes_new`](fd_types.h.driver.md#fd_repair_ancestor_hashes_new) to initialize the structure.
    - It generates a new repair request header by calling [`fd_repair_request_header_generate`](#fd_repair_request_header_generate).
    - A random slot value is generated using `fd_rng_ulong` and assigned to the `slot` field of the structure.
- **Output**: Returns a pointer to the initialized `fd_repair_ancestor_hashes_t` structure.
- **Functions called**:
    - [`fd_repair_ancestor_hashes_new`](fd_types.h.driver.md#fd_repair_ancestor_hashes_new)
    - [`fd_repair_request_header_generate`](#fd_repair_request_header_generate)


---
### fd\_repair\_protocol\_inner\_generate<!-- {{#callable:fd_repair_protocol_inner_generate}} -->
Generates various components of a repair protocol based on a discriminant value.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_repair_protocol_inner_t` that will be populated.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which component to generate.
    - `rng`: A pointer to a random number generator instance used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - Based on the value of `discriminant`, it enters a switch-case structure.
    - For each case (7 to 11), it calls the corresponding generation function for the specific component.
    - Each case generates a different part of the repair protocol, such as a ping, window index, or ancestor hashes.
- **Output**: The function does not return a value but populates the `self` structure with generated data based on the discriminant.
- **Functions called**:
    - [`fd_gossip_ping_generate`](#fd_gossip_ping_generate)
    - [`fd_repair_window_index_generate`](#fd_repair_window_index_generate)
    - [`fd_repair_highest_window_index_generate`](#fd_repair_highest_window_index_generate)
    - [`fd_repair_orphan_generate`](#fd_repair_orphan_generate)
    - [`fd_repair_ancestor_hashes_generate`](#fd_repair_ancestor_hashes_generate)


---
### fd\_repair\_protocol\_generate<!-- {{#callable:fd_repair_protocol_generate}} -->
Generates a new `fd_repair_protocol_t` structure with a random discriminant and initializes its inner components.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_repair_protocol_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the protocol.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_repair_protocol_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_repair_protocol_t` structure.
    - The [`fd_repair_protocol_new`](fd_types.c.driver.md#fd_repair_protocol_new) function is called to initialize the protocol structure.
    - A random discriminant value is generated using the random number generator, which is constrained to a range of 0 to 11.
    - The [`fd_repair_protocol_inner_generate`](#fd_repair_protocol_inner_generate) function is called with the inner structure and the generated discriminant to initialize its components.
- **Output**: Returns a pointer to the initialized `fd_repair_protocol_t` structure.
- **Functions called**:
    - [`fd_repair_protocol_new`](fd_types.c.driver.md#fd_repair_protocol_new)
    - [`fd_repair_protocol_inner_generate`](#fd_repair_protocol_inner_generate)


---
### fd\_repair\_response\_inner\_generate<!-- {{#callable:fd_repair_response_inner_generate}} -->
Generates a response for a repair request based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_repair_response_inner_t` that will be populated.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines the type of response to generate.
    - `rng`: A pointer to a random number generator instance used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - If the `discriminant` is 0, it calls [`fd_gossip_ping_generate`](#fd_gossip_ping_generate) to generate a ping response and populate the `ping` field of `self`.
    - The function exits after processing the case.
- **Output**: The function does not return a value; it modifies the `self` structure directly.
- **Functions called**:
    - [`fd_gossip_ping_generate`](#fd_gossip_ping_generate)


---
### fd\_repair\_response\_generate<!-- {{#callable:fd_repair_response_generate}} -->
Generates a repair response structure with a random discriminant and associated inner data.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_repair_response_t` structure will be generated.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_repair_response_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_repair_response_t` structure.
    - It calls [`fd_repair_response_new`](fd_types.c.driver.md#fd_repair_response_new) to initialize the response structure.
    - It generates a random `discriminant` value using the random number generator.
    - It calls [`fd_repair_response_inner_generate`](#fd_repair_response_inner_generate) with the inner structure and the generated discriminant to populate it.
- **Output**: Returns a pointer to the memory location containing the generated `fd_repair_response_t` structure.
- **Functions called**:
    - [`fd_repair_response_new`](fd_types.c.driver.md#fd_repair_response_new)
    - [`fd_repair_response_inner_generate`](#fd_repair_response_inner_generate)


---
### fd\_instr\_error\_enum\_inner\_generate<!-- {{#callable:fd_instr_error_enum_inner_generate}} -->
Generates an error enumeration for instruction errors based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_instr_error_enum_inner_t` where the generated error will be stored.
    - `alloc_mem`: A pointer to a memory allocation pointer that will be updated with the allocated memory.
    - `discriminant`: An unsigned integer that determines which error case to generate.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which case to execute.
    - If the `discriminant` is 25, it generates a random unsigned integer and assigns it to the `custom` field of `self`.
    - If the `discriminant` is 44, it generates a random length for a string, allocates memory for it, and mutates the content of that memory to create a Borsh IO error string.
- **Output**: The function does not return a value but modifies the `self` structure to reflect the generated error based on the discriminant.
- **Functions called**:
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)


---
### fd\_instr\_error\_enum\_generate<!-- {{#callable:fd_instr_error_enum_generate}} -->
Generates a new `fd_instr_error_enum_t` structure with a random discriminant and populates its inner fields.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_instr_error_enum_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function first increments the `alloc_mem` pointer by the size of `fd_instr_error_enum_t` to allocate space for the new structure.
    - It then initializes the `fd_instr_error_enum_t` structure by calling `fd_instr_error_enum_new(mem)`.
    - A random discriminant value is generated using `fd_rng_uint(rng) % 54` and assigned to the `discriminant` field of the structure.
    - The function then calls [`fd_instr_error_enum_inner_generate`](#fd_instr_error_enum_inner_generate) to populate the inner fields of the structure based on the generated discriminant.
    - Finally, the function returns the pointer to the allocated memory.
- **Output**: Returns a pointer to the allocated `fd_instr_error_enum_t` structure.
- **Functions called**:
    - [`fd_instr_error_enum_new`](fd_types.c.driver.md#fd_instr_error_enum_new)
    - [`fd_instr_error_enum_inner_generate`](#fd_instr_error_enum_inner_generate)


---
### fd\_txn\_instr\_error\_generate<!-- {{#callable:fd_txn_instr_error_generate}} -->
Generates a new transaction instruction error structure.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_txn_instr_error_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_txn_instr_error_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_txn_instr_error_t` structure.
    - It calls [`fd_txn_instr_error_new`](fd_types.c.driver.md#fd_txn_instr_error_new) to initialize the structure.
    - It assigns a random instruction index to the `instr_idx` field of the structure using `fd_rng_uchar`.
    - It generates a random error enumeration and assigns it to the `error` field by calling [`fd_instr_error_enum_generate`](#fd_instr_error_enum_generate).
- **Output**: Returns a pointer to the initialized `fd_txn_instr_error_t` structure.
- **Functions called**:
    - [`fd_txn_instr_error_new`](fd_types.c.driver.md#fd_txn_instr_error_new)
    - [`fd_instr_error_enum_generate`](#fd_instr_error_enum_generate)


---
### fd\_txn\_error\_enum\_inner\_generate<!-- {{#callable:fd_txn_error_enum_inner_generate}} -->
Generates transaction error enumeration based on a given discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_txn_error_enum_inner_t` where the generated error information will be stored.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `discriminant`: An unsigned integer that determines which type of error to generate.
    - `rng`: A pointer to a random number generator instance used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` to determine which case to execute.
    - If `discriminant` is 8, it calls [`fd_txn_instr_error_generate`](#fd_txn_instr_error_generate) to generate an instruction error.
    - If `discriminant` is 30, it assigns a random value to `duplicate_instruction` using the random number generator.
    - If `discriminant` is 31, it assigns a random value to `insufficient_funds_for_rent`.
    - If `discriminant` is 35, it assigns a random value to `program_execution_temporarily_restricted`.
- **Output**: The function does not return a value; instead, it modifies the `self` structure to reflect the generated error state.
- **Functions called**:
    - [`fd_txn_instr_error_generate`](#fd_txn_instr_error_generate)


---
### fd\_txn\_error\_enum\_generate<!-- {{#callable:fd_txn_error_enum_generate}} -->
Generates a new `fd_txn_error_enum_t` structure with a random discriminant and initializes its inner components.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_txn_error_enum_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_txn_error_enum_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_txn_error_enum_t` structure.
    - The function calls `fd_txn_error_enum_new(mem)` to initialize the structure.
    - A random discriminant value is generated using `fd_rng_uint(rng) % 37` and assigned to `self->discriminant`.
    - The function calls `fd_txn_error_enum_inner_generate(&self->inner, alloc_mem, self->discriminant, rng)` to initialize the inner structure based on the discriminant.
- **Output**: Returns a pointer to the initialized `fd_txn_error_enum_t` structure.
- **Functions called**:
    - [`fd_txn_error_enum_new`](fd_types.c.driver.md#fd_txn_error_enum_new)
    - [`fd_txn_error_enum_inner_generate`](#fd_txn_error_enum_inner_generate)


---
### fd\_txn\_result\_inner\_generate<!-- {{#callable:fd_txn_result_inner_generate}} -->
Generates a transaction result based on a given discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_txn_result_inner_t` where the result will be stored.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines the type of transaction result to generate.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - If the `discriminant` is 1, it calls the [`fd_txn_error_enum_generate`](#fd_txn_error_enum_generate) function to generate an error result and assigns it to `self->error`.
- **Output**: The function does not return a value; it modifies the `self` structure to contain the generated transaction result.
- **Functions called**:
    - [`fd_txn_error_enum_generate`](#fd_txn_error_enum_generate)


---
### fd\_txn\_result\_generate<!-- {{#callable:fd_txn_result_generate}} -->
Generates a transaction result structure with a random discriminant and inner error state.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_txn_result_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_txn_result_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_txn_result_t` structure.
    - It calls [`fd_txn_result_new`](fd_types.c.driver.md#fd_txn_result_new) to initialize the transaction result structure.
    - It generates a random discriminant value (0 or 1) using the random number generator.
    - It calls [`fd_txn_result_inner_generate`](#fd_txn_result_inner_generate) with the inner structure and the generated discriminant to initialize the inner state.
- **Output**: Returns a pointer to the initialized `fd_txn_result_t` structure.
- **Functions called**:
    - [`fd_txn_result_new`](fd_types.c.driver.md#fd_txn_result_new)
    - [`fd_txn_result_inner_generate`](#fd_txn_result_inner_generate)


---
### fd\_cache\_status\_generate<!-- {{#callable:fd_cache_status_generate}} -->
Generates a new `fd_cache_status_t` structure and mutates its key slice.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_cache_status_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_cache_status_t` type.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_cache_status_t` structure.
    - It calls [`fd_cache_status_new`](fd_types.c.driver.md#fd_cache_status_new) to initialize the `fd_cache_status_t` structure.
    - It uses [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate) to randomly mutate the `key_slice` of the `fd_cache_status_t` structure.
    - It calls [`fd_txn_result_generate`](#fd_txn_result_generate) to generate a transaction result and store it in the `result` field of the `fd_cache_status_t` structure.
- **Output**: Returns a pointer to the initialized `fd_cache_status_t` structure.
- **Functions called**:
    - [`fd_cache_status_new`](fd_types.c.driver.md#fd_cache_status_new)
    - [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)
    - [`fd_txn_result_generate`](#fd_txn_result_generate)


---
### fd\_status\_value\_generate<!-- {{#callable:fd_status_value_generate}} -->
Generates a `fd_status_value_t` structure with a transaction index and an array of status values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_status_value_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the structure.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_status_value_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_status_value_t` structure.
    - It initializes the `fd_status_value_t` structure by calling `fd_status_value_new(mem)`.
    - It generates a random transaction index using `fd_rng_ulong(rng)`.
    - It generates a random length for the statuses array, which is constrained to a maximum of 8.
    - If the statuses length is greater than zero, it allocates memory for the statuses array and initializes each status by calling [`fd_cache_status_generate`](#fd_cache_status_generate) in a loop.
    - If the statuses length is zero, it sets the statuses pointer to NULL.
- **Output**: Returns a pointer to the initialized `fd_status_value_t` structure.
- **Functions called**:
    - [`fd_status_value_new`](fd_types.c.driver.md#fd_status_value_new)
    - [`fd_cache_status_new`](fd_types.c.driver.md#fd_cache_status_new)
    - [`fd_cache_status_generate`](#fd_cache_status_generate)


---
### fd\_status\_pair\_generate<!-- {{#callable:fd_status_pair_generate}} -->
Generates a new `fd_status_pair_t` structure with a hash and a status value.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_status_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_status_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_status_pair_t` structure.
    - It calls `fd_status_pair_new(mem)` to initialize the new status pair.
    - It generates a hash for the status pair by calling `fd_hash_generate(&self->hash, alloc_mem, rng)`.
    - It generates a status value by calling `fd_status_value_generate(&self->value, alloc_mem, rng)`.
    - Finally, it returns the pointer to the memory location where the `fd_status_pair_t` structure is stored.
- **Output**: Returns a pointer to the allocated `fd_status_pair_t` structure.
- **Functions called**:
    - [`fd_status_pair_new`](fd_types.c.driver.md#fd_status_pair_new)
    - [`fd_hash_generate`](#fd_hash_generate)
    - [`fd_status_value_generate`](#fd_status_value_generate)


---
### fd\_slot\_delta\_generate<!-- {{#callable:fd_slot_delta_generate}} -->
Generates a new `fd_slot_delta_t` structure with random values.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_slot_delta_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_slot_delta_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_slot_delta_t` structure.
    - It initializes the `fd_slot_delta_t` structure by calling `fd_slot_delta_new(mem)`.
    - It generates a random `slot` value using `fd_rng_ulong(rng)`.
    - It generates a random `is_root` value using `fd_rng_uchar(rng)`.
    - It generates a random length for `slot_delta_vec` using `fd_rng_ulong(rng) % 8`.
    - If `slot_delta_vec_len` is greater than zero, it allocates memory for `slot_delta_vec` and initializes each element using a loop.
    - For each element in `slot_delta_vec`, it calls [`fd_status_pair_new`](fd_types.c.driver.md#fd_status_pair_new) and [`fd_status_pair_generate`](#fd_status_pair_generate) to initialize them.
- **Output**: Returns a pointer to the initialized `fd_slot_delta_t` structure.
- **Functions called**:
    - [`fd_slot_delta_new`](fd_types.c.driver.md#fd_slot_delta_new)
    - [`fd_status_pair_new`](fd_types.c.driver.md#fd_status_pair_new)
    - [`fd_status_pair_generate`](#fd_status_pair_generate)


---
### fd\_bank\_slot\_deltas\_generate<!-- {{#callable:fd_bank_slot_deltas_generate}} -->
Generates slot deltas for a bank, including random slot delta lengths and their respective data.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_bank_slot_deltas_t` structure is to be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator used to generate random values for slot deltas.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_bank_slot_deltas_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_bank_slot_deltas_t` structure.
    - The function initializes the `fd_bank_slot_deltas_t` structure by calling `fd_bank_slot_deltas_new(mem)`.
    - It generates a random length for `slot_deltas_len` using the random number generator, constrained to a maximum of 7.
    - If `slot_deltas_len` is greater than 0, it allocates memory for `slot_deltas` and updates `alloc_mem` accordingly.
    - A loop iterates over the number of slot deltas, initializing each delta and generating its data using [`fd_slot_delta_generate`](#fd_slot_delta_generate).
- **Output**: Returns a pointer to the initialized `fd_bank_slot_deltas_t` structure.
- **Functions called**:
    - [`fd_bank_slot_deltas_new`](fd_types.c.driver.md#fd_bank_slot_deltas_new)
    - [`fd_slot_delta_new`](fd_types.c.driver.md#fd_slot_delta_new)
    - [`fd_slot_delta_generate`](#fd_slot_delta_generate)


---
### fd\_pubkey\_rewardinfo\_pair\_generate<!-- {{#callable:fd_pubkey_rewardinfo_pair_generate}} -->
Generates a new `fd_pubkey_rewardinfo_pair_t` structure with a public key and associated reward information.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_pubkey_rewardinfo_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_pubkey_rewardinfo_pair_t` type.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_pubkey_rewardinfo_pair_t` structure.
    - It calls [`fd_pubkey_generate`](#fd_pubkey_generate) to generate a public key and store it in the `pubkey` field of the structure.
    - It calls [`fd_reward_info_generate`](#fd_reward_info_generate) to generate reward information and store it in the `reward_info` field of the structure.
    - Finally, it returns the pointer to the `fd_pubkey_rewardinfo_pair_t` structure.
- **Output**: Returns a pointer to the allocated `fd_pubkey_rewardinfo_pair_t` structure containing the generated public key and reward information.
- **Functions called**:
    - [`fd_pubkey_rewardinfo_pair_new`](fd_types.c.driver.md#fd_pubkey_rewardinfo_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_reward_info_generate`](#fd_reward_info_generate)


---
### fd\_optional\_account\_generate<!-- {{#callable:fd_optional_account_generate}} -->
Generates an optional Solana account structure, potentially initializing it.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_optional_account_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that tracks the current allocation memory position for dynamic memory allocation.
    - `rng`: A pointer to a random number generator structure used to determine if the account should be null or initialized.
- **Control Flow**:
    - The function first casts the `mem` pointer to a `fd_optional_account_t` structure.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_optional_account_t` structure.
    - The function calls [`fd_optional_account_new`](fd_types.c.driver.md#fd_optional_account_new) to initialize the account structure.
    - A random number is generated to decide if the account should be null or initialized.
    - If the generated number indicates that the account should not be null, it allocates memory for a `fd_solana_account_t` structure, initializes it, and generates its details.
    - If the account is to be null, it sets the account pointer in the `fd_optional_account_t` structure to NULL.
- **Output**: Returns a pointer to the initialized `fd_optional_account_t` structure.
- **Functions called**:
    - [`fd_optional_account_new`](fd_types.c.driver.md#fd_optional_account_new)
    - [`fd_solana_account_new`](fd_types.c.driver.md#fd_solana_account_new)
    - [`fd_solana_account_generate`](#fd_solana_account_generate)


---
### fd\_calculated\_stake\_points\_generate<!-- {{#callable:fd_calculated_stake_points_generate}} -->
Generates calculated stake points for a given memory allocation.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_calculated_stake_points_t` structure will be initialized.
    - `alloc_mem`: A double pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the stake points.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_calculated_stake_points_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_calculated_stake_points_t` structure.
    - The function initializes the structure by calling `fd_calculated_stake_points_new(mem)`.
    - It generates a random 128-bit integer for `points` using `fd_rng_uint128(rng)`.
    - It generates a random unsigned long for `new_credits_observed` using `fd_rng_ulong(rng)`.
    - It generates a random unsigned char for `force_credits_update_with_skipped_reward` using `fd_rng_uchar(rng)`.
- **Output**: Returns a pointer to the initialized `fd_calculated_stake_points_t` structure.
- **Functions called**:
    - [`fd_calculated_stake_points_new`](fd_types.h.driver.md#fd_calculated_stake_points_new)


---
### fd\_calculated\_stake\_rewards\_generate<!-- {{#callable:fd_calculated_stake_rewards_generate}} -->
Generates calculated stake rewards for stakers and voters.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_calculated_stake_rewards_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for rewards.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_calculated_stake_rewards_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_calculated_stake_rewards_t` structure.
    - The function calls [`fd_calculated_stake_rewards_new`](fd_types.h.driver.md#fd_calculated_stake_rewards_new) to initialize the structure.
    - It generates random values for `staker_rewards`, `voter_rewards`, and `new_credits_observed` using the provided random number generator.
- **Output**: Returns a pointer to the initialized `fd_calculated_stake_rewards_t` structure.
- **Functions called**:
    - [`fd_calculated_stake_rewards_new`](fd_types.h.driver.md#fd_calculated_stake_rewards_new)


---
### fd\_duplicate\_slot\_proof\_generate<!-- {{#callable:fd_duplicate_slot_proof_generate}} -->
Generates a duplicate slot proof structure with random shreds.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_duplicate_slot_proof_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values for the shreds.
- **Control Flow**:
    - The function begins by casting the `mem` pointer to a `fd_duplicate_slot_proof_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_duplicate_slot_proof_t` structure.
    - The [`fd_duplicate_slot_proof_new`](fd_types.c.driver.md#fd_duplicate_slot_proof_new) function is called to initialize the structure.
    - A random length for the first shred (`shred1_len`) is generated, which can be between 0 and 7.
    - If `shred1_len` is greater than 0, memory is allocated for `shred1`, and random values are generated for each byte of `shred1`.
    - A similar process is repeated for the second shred (`shred2_len`), generating its length and values.
    - Finally, the function returns the pointer to the initialized `fd_duplicate_slot_proof_t` structure.
- **Output**: Returns a pointer to the initialized `fd_duplicate_slot_proof_t` structure.
- **Functions called**:
    - [`fd_duplicate_slot_proof_new`](fd_types.c.driver.md#fd_duplicate_slot_proof_new)


---
### fd\_epoch\_info\_pair\_generate<!-- {{#callable:fd_epoch_info_pair_generate}} -->
Generates a new `fd_epoch_info_pair_t` structure with an account public key and a stake.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_epoch_info_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_epoch_info_pair_t` type to access its fields.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_epoch_info_pair_t` structure.
    - It calls [`fd_pubkey_generate`](#fd_pubkey_generate) to generate a new public key for the account field of the structure.
    - It calls [`fd_stake_generate`](#fd_stake_generate) to generate a new stake for the stake field of the structure.
- **Output**: Returns a pointer to the allocated `fd_epoch_info_pair_t` structure.
- **Functions called**:
    - [`fd_epoch_info_pair_new`](fd_types.h.driver.md#fd_epoch_info_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_stake_generate`](#fd_stake_generate)


---
### fd\_vote\_info\_pair\_generate<!-- {{#callable:fd_vote_info_pair_generate}} -->
Generates a new `fd_vote_info_pair_t` structure with a public key and a versioned vote state.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_vote_info_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_vote_info_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_vote_info_pair_t` structure.
    - It calls `fd_vote_info_pair_new(mem)` to initialize the new vote info pair.
    - It generates a public key for the account using `fd_pubkey_generate(&self->account, alloc_mem, rng)`.
    - It generates a versioned vote state using `fd_vote_state_versioned_generate(&self->state, alloc_mem, rng)`.
    - Finally, it returns the pointer to the `mem` location.
- **Output**: Returns a pointer to the allocated `fd_vote_info_pair_t` structure.
- **Functions called**:
    - [`fd_vote_info_pair_new`](fd_types.c.driver.md#fd_vote_info_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)
    - [`fd_vote_state_versioned_generate`](#fd_vote_state_versioned_generate)


---
### fd\_epoch\_info\_generate<!-- {{#callable:fd_epoch_info_generate}} -->
Generates epoch information including stake and vote states.
- **Inputs**:
    - `mem`: Pointer to the memory location where the `fd_epoch_info_t` structure will be initialized.
    - `alloc_mem`: Pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: Pointer to a random number generator structure used for generating random values.
- **Control Flow**:
    - The function casts the `mem` pointer to `fd_epoch_info_t` and initializes it.
    - It updates the `alloc_mem` pointer to allocate space for `fd_epoch_info_t`.
    - A random length for `stake_infos` is generated, and if it's greater than zero, memory is allocated for `stake_infos`.
    - For each stake info, a new `fd_epoch_info_pair_t` is created and initialized.
    - A random length for `vote_states` is generated, and a new pool for vote states is created.
    - For each vote state, a new `fd_vote_info_pair_t` is generated and inserted into the vote states pool.
    - The function returns the pointer to the initialized `fd_epoch_info_t` structure.
- **Output**: Returns a pointer to the initialized `fd_epoch_info_t` structure.
- **Functions called**:
    - [`fd_epoch_info_new`](fd_types.c.driver.md#fd_epoch_info_new)
    - [`fd_epoch_info_pair_new`](fd_types.h.driver.md#fd_epoch_info_pair_new)
    - [`fd_epoch_info_pair_generate`](#fd_epoch_info_pair_generate)
    - [`fd_vote_info_pair_t_map_join_new`](fd_types.h.driver.md#fd_vote_info_pair_t_map_join_new)
    - [`fd_vote_info_pair_generate`](#fd_vote_info_pair_generate)


---
### fd\_usage\_cost\_details\_generate<!-- {{#callable:fd_usage_cost_details_generate}} -->
Generates usage cost details for a transaction.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_usage_cost_details_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random costs.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_usage_cost_details_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_usage_cost_details_t` structure.
    - The function calls [`fd_usage_cost_details_new`](fd_types.h.driver.md#fd_usage_cost_details_new) to initialize the structure.
    - It generates random values for various cost attributes using the `fd_rng_ulong` function.
    - Finally, it returns the pointer to the initialized structure.
- **Output**: Returns a pointer to the initialized `fd_usage_cost_details_t` structure.
- **Functions called**:
    - [`fd_usage_cost_details_new`](fd_types.h.driver.md#fd_usage_cost_details_new)


---
### fd\_transaction\_cost\_inner\_generate<!-- {{#callable:fd_transaction_cost_inner_generate}} -->
Generates transaction cost details based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_transaction_cost_inner_t` where the generated cost details will be stored.
    - `alloc_mem`: A double pointer to memory allocation for dynamic memory management.
    - `discriminant`: An unsigned integer that determines which type of cost details to generate.
    - `rng`: A pointer to a random number generator instance used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - If the `discriminant` is 1, it calls the [`fd_usage_cost_details_generate`](#fd_usage_cost_details_generate) function to populate the `transaction` field of `self` with generated cost details.
    - The function exits after executing the appropriate case.
- **Output**: The function does not return a value; it modifies the `self` structure in place with generated cost details.
- **Functions called**:
    - [`fd_usage_cost_details_generate`](#fd_usage_cost_details_generate)


---
### fd\_transaction\_cost\_generate<!-- {{#callable:fd_transaction_cost_generate}} -->
Generates a new `fd_transaction_cost_t` structure with random values.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_transaction_cost_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_transaction_cost_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_transaction_cost_t` structure.
    - It calls [`fd_transaction_cost_new`](fd_types.c.driver.md#fd_transaction_cost_new) to initialize the `fd_transaction_cost_t` structure.
    - It generates a random `discriminant` value using the random number generator.
    - It calls [`fd_transaction_cost_inner_generate`](#fd_transaction_cost_inner_generate) with the inner structure of `self`, the `alloc_mem`, and the generated `discriminant`.
- **Output**: Returns a pointer to the initialized `fd_transaction_cost_t` structure.
- **Functions called**:
    - [`fd_transaction_cost_new`](fd_types.c.driver.md#fd_transaction_cost_new)
    - [`fd_transaction_cost_inner_generate`](#fd_transaction_cost_inner_generate)


---
### fd\_account\_costs\_pair\_generate<!-- {{#callable:fd_account_costs_pair_generate}} -->
Generates a new `fd_account_costs_pair_t` structure with a public key and a randomly assigned cost.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_account_costs_pair_t` structure will be created.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_account_costs_pair_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_account_costs_pair_t` structure.
    - It calls `fd_account_costs_pair_new(mem)` to initialize the new structure.
    - It generates a new public key using [`fd_pubkey_generate`](#fd_pubkey_generate) and assigns it to `self->key`.
    - It assigns a random cost to `self->cost` using `fd_rng_ulong`.
- **Output**: Returns a pointer to the allocated `fd_account_costs_pair_t` structure.
- **Functions called**:
    - [`fd_account_costs_pair_new`](fd_types.h.driver.md#fd_account_costs_pair_new)
    - [`fd_pubkey_generate`](#fd_pubkey_generate)


---
### fd\_account\_costs\_generate<!-- {{#callable:fd_account_costs_generate}} -->
Generates account costs for a given memory allocation and random number generator.
- **Inputs**:
    - `mem`: Pointer to the memory location where the `fd_account_costs_t` structure will be initialized.
    - `alloc_mem`: Pointer to a pointer that will be updated to point to the next available memory location for allocation.
    - `rng`: Pointer to a random number generator used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_account_costs_t` structure.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_account_costs_t` structure.
    - It initializes the `fd_account_costs_t` structure by calling [`fd_account_costs_new`](fd_types.c.driver.md#fd_account_costs_new).
    - It generates a random length for account costs using the random number generator, constrained to a maximum of 8.
    - It allocates a new pool for account costs using [`fd_account_costs_pair_t_map_join_new`](fd_types.h.driver.md#fd_account_costs_pair_t_map_join_new).
    - It iterates over the generated length, acquiring nodes from the pool and generating account costs for each node.
    - Each generated account cost is inserted into the account costs pool.
- **Output**: Returns a pointer to the initialized `fd_account_costs_t` structure.
- **Functions called**:
    - [`fd_account_costs_new`](fd_types.c.driver.md#fd_account_costs_new)
    - [`fd_account_costs_pair_t_map_join_new`](fd_types.h.driver.md#fd_account_costs_pair_t_map_join_new)
    - [`fd_account_costs_pair_generate`](#fd_account_costs_pair_generate)


---
### fd\_cost\_tracker\_generate<!-- {{#callable:fd_cost_tracker_generate}} -->
Generates a new `fd_cost_tracker_t` structure with randomized cost limits and account costs.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_cost_tracker_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_cost_tracker_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to account for the size of the `fd_cost_tracker_t` structure.
    - It initializes the `fd_cost_tracker_t` structure by calling `fd_cost_tracker_new(mem)`.
    - Random values are generated for `account_cost_limit`, `block_cost_limit`, and `vote_cost_limit` using `fd_rng_ulong(rng)`.
    - The function generates account costs by calling [`fd_account_costs_generate`](#fd_account_costs_generate) with the appropriate parameters.
    - Additional random values are generated for various cost-related fields in the `fd_cost_tracker_t` structure.
- **Output**: Returns a pointer to the initialized `fd_cost_tracker_t` structure.
- **Functions called**:
    - [`fd_cost_tracker_new`](fd_types.c.driver.md#fd_cost_tracker_new)
    - [`fd_account_costs_generate`](#fd_account_costs_generate)


---
### fd\_rent\_paying\_generate<!-- {{#callable:fd_rent_paying_generate}} -->
Generates a new `fd_rent_paying_t` structure with randomized values for `lamports` and `data_size`.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_rent_paying_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator structure used to generate random values.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_rent_paying_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to point to the next memory location after the size of `fd_rent_paying_t`.
    - It calls `fd_rent_paying_new(mem)` to initialize the `fd_rent_paying_t` structure.
    - It generates a random value for `self->lamports` using `fd_rng_ulong(rng)`.
    - It generates a random value for `self->data_size` using `fd_rng_ulong(rng)`.
    - Finally, it returns the pointer to the initialized `fd_rent_paying_t` structure.
- **Output**: Returns a pointer to the initialized `fd_rent_paying_t` structure.
- **Functions called**:
    - [`fd_rent_paying_new`](fd_types.h.driver.md#fd_rent_paying_new)


---
### fd\_rent\_state\_inner\_generate<!-- {{#callable:fd_rent_state_inner_generate}} -->
Generates the inner state of a rent state based on a discriminant.
- **Inputs**:
    - `self`: A pointer to an instance of `fd_rent_state_inner_t` that will be populated.
    - `alloc_mem`: A double pointer to memory allocation for dynamic structures.
    - `discriminant`: An unsigned integer that determines which case to execute in the switch statement.
    - `rng`: A pointer to a random number generator used for generating random values.
- **Control Flow**:
    - The function begins by evaluating the `discriminant` value.
    - If `discriminant` is 1, it calls [`fd_rent_paying_generate`](#fd_rent_paying_generate) to populate the `rent_paying` field of the `self` structure.
- **Output**: The function does not return a value; it modifies the `self` structure directly.
- **Functions called**:
    - [`fd_rent_paying_generate`](#fd_rent_paying_generate)


---
### fd\_rent\_state\_generate<!-- {{#callable:fd_rent_state_generate}} -->
Generates a new `fd_rent_state_t` structure with initialized values.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_rent_state_t` structure will be initialized.
    - `alloc_mem`: A pointer to a pointer that will be updated to point to the next available memory location after allocation.
    - `rng`: A pointer to a random number generator used to generate random values for the state.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_rent_state_t` type and assigns it to `self`.
    - It updates the `alloc_mem` pointer to allocate space for the `fd_rent_state_t` structure.
    - The [`fd_rent_state_new`](fd_types.c.driver.md#fd_rent_state_new) function is called to initialize the `fd_rent_state_t` structure.
    - A random discriminant value is generated using the `fd_rng_uint` function, which will determine the type of rent state to generate.
    - The [`fd_rent_state_inner_generate`](#fd_rent_state_inner_generate) function is called with the inner state structure, the generated discriminant, and the random number generator.
- **Output**: Returns a pointer to the initialized `fd_rent_state_t` structure.
- **Functions called**:
    - [`fd_rent_state_new`](fd_types.c.driver.md#fd_rent_state_new)
    - [`fd_rent_state_inner_generate`](#fd_rent_state_inner_generate)


# Function Declarations (Public API)

---
### LLVMFuzzerMutate<!-- {{#callable_declaration:LLVMFuzzerMutate}} -->
Mutates a given data buffer for fuzz testing.
- **Description**: Use this function to apply mutations to a data buffer, which is useful in fuzz testing scenarios to generate variations of input data. The function takes a buffer and its current size, and attempts to mutate it without exceeding a specified maximum size. It is expected that the buffer is pre-allocated with enough space to accommodate the maximum size. The function should be called with valid pointers and sizes, as it does not perform any operations if the parameters are invalid.
- **Inputs**:
    - `data`: A pointer to the buffer that will be mutated. The buffer must be pre-allocated and must not be null.
    - `size`: The current size of the data in the buffer. It must be less than or equal to max_size.
    - `max_size`: The maximum size the buffer can grow to during mutation. It must be greater than or equal to size.
- **Output**: Returns the new size of the data in the buffer after mutation, or 0 if no mutation is performed.
- **See also**: [`LLVMFuzzerMutate`](../../util/sanitize/fd_fuzz_stub.c.driver.md#LLVMFuzzerMutate)  (Implementation)


