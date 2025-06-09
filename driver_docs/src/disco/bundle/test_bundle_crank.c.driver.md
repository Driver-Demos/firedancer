# Purpose
The provided C source code file is designed to test and validate the functionality of a system related to transaction generation and processing, specifically within a context that involves "cranking" operations, which likely pertain to some form of blockchain or distributed ledger technology. The file includes several test functions that verify the correctness of transaction generation, duplication checking, and transaction count management. The code imports several headers and binary data, which suggests it is part of a larger system, possibly a library or application that deals with financial transactions or smart contracts.

Key components of the code include the use of static assertions to ensure data structure sizes and offsets are as expected, which is crucial for maintaining data integrity and compatibility. The code defines and manipulates several account addresses and configurations, indicating its role in handling transaction-related data. The functions [`test_repro_onchain`](#test_repro_onchain), [`test_no_duplicates`](#test_no_duplicates), and [`test_crank_cnt`](#test_crank_cnt) are central to the file, each performing specific tests to ensure the system's reliability and correctness. The file is structured as an executable, with a [`main`](#main) function that initializes the system, runs the tests, and logs the results. This code is not intended to define public APIs or external interfaces but rather to serve as an internal testing mechanism to validate the functionality of the transaction processing components.
# Imports and Dependencies

---
- `fd_bundle_crank.h`
- `../pack/fd_chkdup.h`
- `../../ballet/base64/fd_base64.h`
- `stddef.h`


# Global Variables

---
### \_3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in cryptographic applications.
- **Use**: This variable is used to store a specific account address or public key, likely for cryptographic operations or identity verification within the application.


---
### \_4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in cryptographic applications.
- **Use**: This variable is used as an account address in various functions, such as `fd_bundle_crank_gen_init`, to initialize or verify cryptographic operations.


---
### \_96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in cryptographic applications.
- **Use**: This variable is used to store a specific account address or public key, likely for cryptographic operations or identity verification within the application.


---
### \_DNVZMSqeRH18Xa4MCTrb1MndNf3Npg4MEwqswo23eWkf
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_DNVZMSqeRH18Xa4MCTrb1MndNf3Npg4MEwqswo23eWkf` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in cryptographic and blockchain applications.
- **Use**: This variable is used to store a specific account address or public key, likely for use in cryptographic operations or blockchain transactions.


---
### \_feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_feeywn2ffX8DivmRvBJ9i9YZnss7WBouTmujfQcEdeY` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or identifier, which is likely used in financial or blockchain-related operations.
- **Use**: This variable is used as a block builder address in various functions related to transaction generation and validation.


---
### \_G8RaABmvrvNCcGu41NV5oKjCfHeBv1zNn58dFcZzyRRw
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_G8RaABmvrvNCcGu41NV5oKjCfHeBv1zNn58dFcZzyRRw` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in blockchain or cryptographic applications.
- **Use**: This variable is used to store a specific account address that is referenced in various functions, such as `fd_bundle_crank_get_addresses` and `fd_bundle_crank_generate`, to verify or generate transactions.


---
### \_GiLHMES95axFbFX7ogCTwL6QQ1uqspajz9SHMpt5dCGh
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_GiLHMES95axFbFX7ogCTwL6QQ1uqspajz9SHMpt5dCGh` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in cryptographic and blockchain applications.
- **Use**: This variable is used to store a specific account address, likely for use in cryptographic operations or blockchain transactions.


---
### \_GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in cryptographic and blockchain applications.
- **Use**: This variable is used as an account address in various functions related to transaction generation and validation.


---
### \_GZctHpWXmsZC1YHACTGGcHhYxjdRqQvTpYkb9LMvxDib
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_GZctHpWXmsZC1YHACTGGcHhYxjdRqQvTpYkb9LMvxDib` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or identifier, which is likely used in the context of financial transactions or account management within the software.
- **Use**: This variable is used to store a specific account address for operations involving account management or transaction processing.


---
### \_HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in cryptographic applications.
- **Use**: This variable is used to store a specific account address or public key for cryptographic operations or transactions.


---
### \_HgzT81VF1xZ3FT9Eq1pHhea7Wcfq2bv4tWTP3VvJ8Y9D
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_HgzT81VF1xZ3FT9Eq1pHhea7Wcfq2bv4tWTP3VvJ8Y9D` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or similar identifier, stored in the `.b` field of the `fd_acct_addr_t` structure.
- **Use**: This variable is used in the `test_repro_onchain` function to verify account address equality in transaction tests.


---
### \_T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt
- **Type**: `fd_acct_addr_t`
- **Description**: The variable `_T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt` is a global array of type `fd_acct_addr_t` with a single element. It is initialized with a 32-byte array representing an account address or public key, which is a common structure in cryptographic and blockchain applications.
- **Use**: This variable is used as an account address in various functions, such as `fd_bundle_crank_gen_init`, to initialize or verify account-related operations.


# Functions

---
### test\_repro\_onchain<!-- {{#callable:test_repro_onchain}} -->
The `test_repro_onchain` function tests the generation and validation of blockchain transactions using a specific configuration and compares them to a known reference.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `fd_bundle_crank_gen_t` object `g` with specific account addresses and a zero value.
    - Retrieve tip payment configuration and receiver addresses using [`fd_bundle_crank_get_addresses`](fd_bundle_crank.c.driver.md#fd_bundle_crank_get_addresses) and verify them against known values using `FD_TEST`.
    - Define an old tip payment configuration with specific parameters including a discriminator, tip receiver, block builder, commission percentage, and bumps.
    - Prepare payload and transaction buffers for generating and parsing transactions.
    - Generate a transaction using [`fd_bundle_crank_generate`](fd_bundle_crank.c.driver.md#fd_bundle_crank_generate) and verify its size against a known structure size.
    - Parse a reference transaction from a binary payload and verify its size.
    - Compare the instruction count of the generated transaction and the reference transaction, ensuring the generated one has one more instruction.
    - Retrieve account addresses from both transactions and compare them using a macro `ASSERT_PUBKEY_EQ` to ensure they match in terms of public key, writability, and signer status.
    - Iterate over instructions in the reference transaction, comparing program IDs, account counts, data sizes, and account addresses with the generated transaction.
    - Parse the generated transaction again and verify it matches the original transaction buffer.
    - Encode the transaction payload in base64 and log it as a sample transaction.
- **Output**: The function does not return any value; it performs tests and logs results, ensuring the transactions are generated and validated correctly.
- **Functions called**:
    - [`fd_bundle_crank_gen_init`](fd_bundle_crank.c.driver.md#fd_bundle_crank_gen_init)
    - [`fd_bundle_crank_get_addresses`](fd_bundle_crank.c.driver.md#fd_bundle_crank_get_addresses)
    - [`fd_bundle_crank_generate`](fd_bundle_crank.c.driver.md#fd_bundle_crank_generate)


---
### check\_duplicates<!-- {{#callable:check_duplicates}} -->
The `check_duplicates` function verifies if a generated transaction contains duplicate account addresses compared to given old tip receiver and block builder addresses.
- **Inputs**:
    - `g`: A pointer to an `fd_bundle_crank_gen_t` structure used for generating transactions.
    - `rng`: A pointer to an `fd_rng_t` structure used for random number generation.
    - `old_tip_receiver`: A constant pointer to an `fd_acct_addr_t` structure representing the old tip receiver's account address.
    - `old_block_builder`: A constant pointer to an `fd_acct_addr_t` structure representing the old block builder's account address.
- **Control Flow**:
    - Initialize an `fd_bundle_crank_tip_payment_config_t` structure with the old tip receiver and block builder addresses, a fixed commission percentage, and a predefined bumps array.
    - Allocate memory for transaction payload and transaction structure.
    - Generate a transaction using [`fd_bundle_crank_generate`](fd_bundle_crank.c.driver.md#fd_bundle_crank_generate) with the provided generator, configuration, and other parameters.
    - Verify the size of the generated transaction matches the expected size of `fd_bundle_crank_2_t`.
    - Retrieve account addresses from the transaction using `fd_txn_get_acct_addrs`.
    - Check if the transaction's account addresses match the old tip receiver and block builder addresses at specific offsets; return 0 if any mismatch is found.
    - Initialize a `fd_chkdup_t` structure for duplicate checking using the provided random number generator.
    - Check for duplicate account addresses in the transaction using `fd_chkdup_check` and return the negation of its result.
- **Output**: Returns an integer, 1 if no duplicates are found, and 0 if duplicates are detected or if any address mismatches occur.
- **Functions called**:
    - [`fd_bundle_crank_generate`](fd_bundle_crank.c.driver.md#fd_bundle_crank_generate)


---
### test\_no\_duplicates<!-- {{#callable:test_no_duplicates}} -->
The `test_no_duplicates` function initializes a random number generator and a bundle crank generator, then tests for duplicate account addresses in generated transactions using the [`check_duplicates`](#check_duplicates) function.
- **Inputs**: None
- **Control Flow**:
    - Initialize a random number generator `rng` using `fd_rng_new` and `fd_rng_join`.
    - Initialize a bundle crank generator `g` with specific account addresses using [`fd_bundle_crank_gen_init`](fd_bundle_crank.c.driver.md#fd_bundle_crank_gen_init).
    - Call [`check_duplicates`](#check_duplicates) multiple times with different pairs of account addresses to verify that no duplicates exist in the generated transactions.
    - Delete the random number generator using `fd_rng_leave` and `fd_rng_delete`.
- **Output**: The function does not return any value; it performs tests and relies on assertions to validate conditions.
- **Functions called**:
    - [`fd_bundle_crank_gen_init`](fd_bundle_crank.c.driver.md#fd_bundle_crank_gen_init)
    - [`check_duplicates`](#check_duplicates)


---
### test\_crank\_cnt<!-- {{#callable:test_crank_cnt}} -->
The `test_crank_cnt` function tests the generation of transaction bundles with various configurations and validates their sizes and properties.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `fd_bundle_crank_gen_t` object `g` with specific account addresses and a crank count of 1.
    - Configure a `fd_bundle_crank_tip_payment_config_t` object with a specific discriminator, tip receiver, block builder, commission percentage, and bumps.
    - Declare and initialize arrays for payload and transaction data.
    - Generate a transaction bundle using [`fd_bundle_crank_generate`](fd_bundle_crank.c.driver.md#fd_bundle_crank_generate) and verify its size against `fd_bundle_crank_3_t`.
    - Generate another transaction bundle with a different configuration and verify its size is zero.
    - Increment the commission percentage in the configuration and generate a transaction bundle, verifying its size against `fd_bundle_crank_2_t`, then revert the commission percentage.
    - Modify the tip receiver's address slightly, generate a transaction bundle, verify its size, and revert the address change.
    - Modify the block builder's address slightly, generate a transaction bundle, verify its size, and revert the address change.
    - Generate a final transaction bundle with the original configuration and verify its size is zero.
- **Output**: The function does not return any value; it performs tests and uses assertions to validate conditions.
- **Functions called**:
    - [`fd_bundle_crank_gen_init`](fd_bundle_crank.c.driver.md#fd_bundle_crank_gen_init)
    - [`fd_bundle_crank_generate`](fd_bundle_crank.c.driver.md#fd_bundle_crank_generate)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests, logs a success message, and then halts the program.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Execute [`test_repro_onchain`](#test_repro_onchain) to test on-chain reproduction functionality.
    - Execute [`test_no_duplicates`](#test_no_duplicates) to ensure no duplicate transactions are generated.
    - Execute [`test_crank_cnt`](#test_crank_cnt) to verify the crank count functionality.
    - Log a notice message indicating the tests passed using `FD_LOG_NOTICE`.
    - Call `fd_halt` to clean up and halt the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_repro_onchain`](#test_repro_onchain)
    - [`test_no_duplicates`](#test_no_duplicates)
    - [`test_crank_cnt`](#test_crank_cnt)


