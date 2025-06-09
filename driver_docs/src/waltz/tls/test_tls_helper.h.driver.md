# Purpose
This C header file, `tls_helper.h`, is designed to support unit testing for a TLS (Transport Layer Security) implementation. It provides utility functions and structures that facilitate the testing of TLS functionalities, such as random number generation, digital signing, and message handling. The file includes functions to create a deterministic random number generator ([`fd_tls_test_rand`](#fd_tls_rand_tfd_tls_test_rand)) and a signing context ([`fd_tls_test_sign_ctx`](#fd_tls_test_sign_ctx)) using the Ed25519 algorithm, which are both crucial for simulating cryptographic operations in a controlled test environment. The use of deterministic RNG is intentional for reproducibility in tests, despite being insecure for production use.

Additionally, the file defines structures and functions for handling TLS records in a test context. The `test_record_buf` structure manages a buffer of TLS records, allowing for the simulation of sending and receiving messages. Functions like [`test_record_send`](#test_record_send), `test_record_recv`, and [`test_record_log`](#test_record_log) facilitate the manipulation and logging of these records, enabling detailed inspection of message flows during testing. The file is not intended to be an executable but rather a utility library to be included in test suites, providing a focused set of tools for testing TLS protocol implementations.
# Imports and Dependencies

---
- `fd_tls.h`
- `fd_tls_proto.h`
- `../../ballet/sha512/fd_sha512.h`
- `../../ballet/ed25519/fd_ed25519.h`


# Data Structures

---
### fd\_tls\_test\_sign\_ctx
- **Type**: `struct`
- **Members**:
    - `sha512`: An array of one fd_sha512_t structure used for SHA-512 hashing operations.
    - `public_key`: A 32-byte array representing the public key used in the signing process.
    - `private_key`: A 32-byte array representing the private key used in the signing process.
- **Description**: The `fd_tls_test_sign_ctx` structure is designed to facilitate the signing process in TLS unit tests. It contains a SHA-512 hashing context and a pair of public and private keys, which are essential for generating digital signatures using the Ed25519 algorithm. This structure is used in conjunction with functions that perform cryptographic signing operations, ensuring secure and verifiable message integrity.


---
### fd\_tls\_test\_sign\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `sha512`: An array of one fd_sha512_t structure used for SHA-512 hashing operations.
    - `public_key`: A 32-byte array storing the public key for signing operations.
    - `private_key`: A 32-byte array storing the private key for signing operations.
- **Description**: The `fd_tls_test_sign_ctx_t` structure is used in the context of TLS testing to manage cryptographic signing operations. It contains a SHA-512 hashing context, a public key, and a private key, which are essential for generating digital signatures using the Ed25519 algorithm. This structure is part of a test suite designed to verify the functionality of TLS implementations by providing a controlled environment for cryptographic operations.


---
### test\_record
- **Type**: `struct`
- **Members**:
    - `level`: An unsigned integer representing the level of the test record.
    - `buf`: An array of unsigned characters with a size defined by TEST_RECORD_BUFSZ, used to store the data of the test record.
    - `cur`: An unsigned long integer indicating the current size or position within the buffer.
- **Description**: The 'test_record' structure is designed to encapsulate a single test record, which includes a level indicator, a buffer to hold the record's data, and a current position or size marker within the buffer. This structure is used in the context of test record transport, where it facilitates the storage and management of individual records within a larger buffer system.


---
### test\_record\_t
- **Type**: `struct`
- **Members**:
    - `level`: An unsigned integer representing the level of the test record.
    - `buf`: A buffer of fixed size (4096 bytes) to store the test record data.
    - `cur`: An unsigned long integer indicating the current size of the data in the buffer.
- **Description**: The `test_record_t` structure is designed to encapsulate a test record with a specific level and a buffer to hold the record's data. It includes a `level` to categorize or prioritize the record, a `buf` array to store the actual data up to a predefined size, and a `cur` field to track the current size of the data stored in the buffer. This structure is used in conjunction with a buffer management system to handle multiple test records efficiently.


---
### test\_record\_buf
- **Type**: `struct`
- **Members**:
    - `records`: An array of test_record_t structures, each representing a record in the buffer.
    - `recv`: A counter indicating the number of records received.
    - `send`: A counter indicating the number of records sent.
- **Description**: The `test_record_buf` structure is designed to manage a buffer of test records, facilitating the storage and retrieval of records in a testing environment. It contains an array of `test_record_t` structures, which hold individual records, and two counters, `recv` and `send`, which track the number of records received and sent, respectively. This structure is useful for simulating and testing record transport mechanisms, ensuring that records can be efficiently managed and processed in a controlled manner.


---
### test\_record\_buf\_t
- **Type**: `struct`
- **Members**:
    - `records`: An array of test_record_t structures, each representing a record with a fixed buffer size.
    - `recv`: An unsigned long integer indicating the index of the next record to be received.
    - `send`: An unsigned long integer indicating the index of the next record to be sent.
- **Description**: The `test_record_buf_t` structure is designed to manage a circular buffer of test records, each with a fixed size buffer for storing data. It maintains indices for sending and receiving records, allowing for efficient handling of multiple records in a test environment. The structure is particularly useful in scenarios where a sequence of records needs to be processed in a controlled manner, such as in testing transport layers or communication protocols.


# Functions

---
### fd\_tls\_test\_rand\_read<!-- {{#callable:fd_tls_test_rand_read}} -->
The `fd_tls_test_rand_read` function fills a buffer with random bytes generated by a deterministic random number generator (RNG) for testing purposes.
- **Inputs**:
    - `ctx`: A pointer to the context, which should be a `fd_rng_t` type representing the random number generator.
    - `buf`: A pointer to the buffer where random bytes will be written.
    - `bufsz`: The size of the buffer, indicating how many random bytes to generate.
- **Control Flow**:
    - Check if the `ctx` is NULL using `FD_UNLIKELY`; if it is, return NULL immediately.
    - Cast the `ctx` to a `fd_rng_t` pointer and `buf` to a `uchar` pointer for further operations.
    - Iterate over the buffer size (`bufsz`) and fill each byte of the buffer with a random byte generated by `fd_rng_uchar` using the RNG context.
    - Return the buffer pointer after it has been filled with random bytes.
- **Output**: Returns the pointer to the buffer filled with random bytes, or NULL if the context is invalid.


---
### fd\_tls\_test\_rand<!-- {{#callable:fd_tls_rand_t::fd_tls_test_rand}} -->
The `fd_tls_test_rand` function initializes and returns a deterministic random number generator context for testing purposes.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which is used as the context for the random number generator.
- **Control Flow**:
    - The function takes a single input, `rng`, which is a pointer to an `fd_rng_t` structure.
    - It returns an `fd_tls_rand_t` structure initialized with the `rng` as its context and `fd_tls_test_rand_read` as its random function.
- **Output**: An `fd_tls_rand_t` structure with the provided `rng` as its context and `fd_tls_test_rand_read` as its random function.
- **See also**: [`fd_tls_rand_t`](fd_tls.h.driver.md#fd_tls_rand_t)  (Data Structure)


---
### fd\_tls\_test\_sign\_sign<!-- {{#callable:fd_tls_test_sign_sign}} -->
The `fd_tls_test_sign_sign` function generates an Ed25519 signature for a given payload using a provided context containing the necessary cryptographic keys and hash function.
- **Inputs**:
    - `_ctx`: A pointer to a `fd_tls_test_sign_ctx_t` structure containing the public key, private key, and SHA-512 context used for signing.
    - `signature`: A pointer to a buffer where the generated signature will be stored.
    - `payload`: A pointer to the data that needs to be signed.
- **Control Flow**:
    - Cast the `_ctx` parameter to a `fd_tls_test_sign_ctx_t` pointer to access the cryptographic context.
    - Call the `fd_ed25519_sign` function with the signature buffer, payload, payload length (130 bytes), public key, private key, and SHA-512 context to generate the signature.
- **Output**: The function does not return a value; it outputs the generated signature directly into the provided `signature` buffer.


---
### fd\_tls\_test\_sign\_ctx<!-- {{#callable:fd_tls_test_sign_ctx}} -->
The `fd_tls_test_sign_ctx` function initializes a signing context by setting up a SHA-512 hash and generating a public-private key pair using a random number generator.
- **Inputs**:
    - `ctx`: A pointer to an `fd_tls_test_sign_ctx_t` structure that will be initialized with a SHA-512 context and a public-private key pair.
    - `rng`: A pointer to an `fd_rng_t` random number generator used to generate the private key.
- **Control Flow**:
    - The function begins by initializing a SHA-512 context within the `ctx` structure using `fd_sha512_new` and `fd_sha512_join` to ensure the SHA-512 context is properly set up.
    - A loop iterates 32 times to fill the `private_key` array in the `ctx` structure with random bytes generated by `fd_rng_uchar` using the provided `rng`.
    - The function then calls `fd_ed25519_public_from_private` to generate the corresponding public key from the private key and SHA-512 context, storing it in the `public_key` array of the `ctx` structure.
- **Output**: The function does not return a value; it initializes the provided `fd_tls_test_sign_ctx_t` structure with a SHA-512 context and a public-private key pair.


---
### fd\_tls\_test\_sign<!-- {{#callable:fd_tls_sign_t::fd_tls_test_sign}} -->
The `fd_tls_test_sign` function initializes and returns a `fd_tls_sign_t` structure with a given context and a predefined signing function.
- **Inputs**:
    - `ctx`: A pointer to a context that will be used by the signing function.
- **Control Flow**:
    - The function takes a single input parameter `ctx`.
    - It returns a `fd_tls_sign_t` structure.
    - The structure is initialized with the provided `ctx` and the `sign_fn` set to `fd_tls_test_sign_sign`.
- **Output**: A `fd_tls_sign_t` structure initialized with the provided context and a predefined signing function.
- **See also**: [`fd_tls_sign_t`](fd_tls.h.driver.md#fd_tls_sign_t)  (Data Structure)


---
### test\_record\_reset<!-- {{#callable:test_record_reset}} -->
The `test_record_reset` function resets the send and receive counters of a `test_record_buf_t` structure to zero.
- **Inputs**:
    - `buf`: A pointer to a `test_record_buf_t` structure whose send and receive counters are to be reset.
- **Control Flow**:
    - The function directly sets the `recv` and `send` fields of the `test_record_buf_t` structure pointed to by `buf` to 0UL.
- **Output**: This function does not return any value; it modifies the `test_record_buf_t` structure in place.


---
### test\_record\_send<!-- {{#callable:test_record_send}} -->
The `test_record_send` function stores a record with a specified level and size into a circular buffer for test records.
- **Inputs**:
    - `buf`: A pointer to a `test_record_buf_t` structure, which contains the circular buffer of test records.
    - `level`: An unsigned integer representing the level of the record being sent.
    - `record`: A pointer to an array of unsigned characters representing the record data to be stored.
    - `record_sz`: An unsigned long integer representing the size of the record data.
- **Control Flow**:
    - Calculate the index in the circular buffer where the new record will be stored using the current send index modulo the buffer count.
    - Increment the send index for the buffer.
    - Set the level of the record at the calculated index to the provided level.
    - Set the current size of the record at the calculated index to the provided record size.
    - Assert that the record size does not exceed the maximum buffer size using `FD_TEST`.
    - Copy the record data into the buffer at the calculated index using `fd_memcpy`.
- **Output**: The function does not return a value; it modifies the state of the `test_record_buf_t` structure by storing the record data in the buffer.


---
### test\_record\_log<!-- {{#callable:test_record_log}} -->
The `test_record_log` function logs a TLS record's type and source (server or client) along with a hexdump of the record data.
- **Inputs**:
    - `record`: A pointer to the TLS record data to be logged.
    - `record_sz`: The size of the TLS record data in bytes.
    - `from_server`: An integer flag indicating whether the record is from the server (non-zero) or client (zero).
- **Control Flow**:
    - The function begins by asserting that the record size is at least 4 bytes using `FD_TEST`.
    - A buffer `buf` of 512 bytes is initialized, and a string `str` is initialized to point to this buffer using `fd_cstr_init`.
    - The function determines the prefix ('server' or 'client') based on the `from_server` flag and appends it to `str`.
    - The function checks the first byte of the record to determine the TLS message type and assigns a corresponding string to `type`.
    - If the message type is unknown, an error is logged using `FD_LOG_ERR`.
    - The determined message type is appended to `str`.
    - The string is finalized using `fd_cstr_fini`.
    - Finally, a hexdump of the record is logged using `FD_LOG_HEXDUMP_INFO`, including the constructed string and the record data.
- **Output**: The function does not return a value; it logs information about the TLS record.


