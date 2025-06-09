# Purpose
This C source code file is a comprehensive test suite for AES (Advanced Encryption Standard) cryptographic operations, specifically focusing on key expansion, ECB (Electronic Codebook) mode, and GCM (Galois/Counter Mode) encryption and decryption. The file includes tests for AES-128 key expansion, using a predefined set of zero keys to verify the correctness of the key expansion process. It also contains a series of known-answer tests for AES-128-ECB, using test vectors from NIST to ensure the implementation produces the expected ciphertext for given plaintext and keys. Additionally, the file tests AES-128-GCM encryption and decryption, including boundary tests to detect out-of-bounds memory accesses and tests for the integrity of the encryption by checking for malleability.

The code is structured to be executed as a standalone program, with a [`main`](#main) function that initializes a random number generator and runs the various test functions. It uses conditional compilation to include platform-specific headers and to configure the AES implementation based on the available hardware capabilities, such as AES-NI and AVX2. The file imports external binary data for testing purposes and logs the results of each test, providing detailed feedback on the success or failure of the cryptographic operations. This test suite is crucial for validating the correctness and security of AES implementations in different modes and configurations.
# Imports and Dependencies

---
- `sys/mman.h`
- `fd_aes_base.h`
- `fd_aes_gcm.h`


# Global Variables

---
### fixture\_key\_expansion\_128\_zeros
- **Type**: `uchar const`
- **Description**: The `fixture_key_expansion_128_zeros` is a statically defined constant array of unsigned characters (bytes) with a size of 176 elements. It is aligned to a 16-byte boundary for optimal memory access performance.
- **Use**: This array is used as a test fixture for AES key expansion tests, specifically for a 128-bit key initialized with zeros.


---
### fd\_aes\_128\_ecb\_test\_vec
- **Type**: `fd_aes_128_ecb_fixture_t const[]`
- **Description**: The `fd_aes_128_ecb_test_vec` is an array of `fd_aes_128_ecb_fixture_t` structures, each containing a 128-bit AES key (`k`), a plaintext block (`p`), and the corresponding ciphertext block (`c`). These vectors are used for testing the AES-128 encryption and decryption in ECB mode, ensuring that the implementation produces the expected results for known inputs.
- **Use**: This variable is used to provide test vectors for validating the correctness of AES-128 encryption and decryption in ECB mode.


# Data Structures

---
### fd\_aes\_128\_ecb\_fixture
- **Type**: `struct`
- **Members**:
    - `k`: A 16-byte array representing the AES encryption key.
    - `p`: A 16-byte array representing the plaintext input for encryption.
    - `c`: A 16-byte array representing the ciphertext output from encryption.
- **Description**: The `fd_aes_128_ecb_fixture` structure is used to store test vectors for AES-128 encryption in ECB mode. It contains three 16-byte arrays: `k` for the encryption key, `p` for the plaintext, and `c` for the expected ciphertext. This structure is utilized in testing the correctness of AES-128 encryption and decryption operations by comparing the computed ciphertext with the expected ciphertext stored in `c`.


---
### fd\_aes\_128\_ecb\_fixture\_t
- **Type**: `struct`
- **Members**:
    - `k`: A 16-byte array representing the AES encryption key.
    - `p`: A 16-byte array representing the plaintext input for encryption.
    - `c`: A 16-byte array representing the ciphertext output from encryption.
- **Description**: The `fd_aes_128_ecb_fixture_t` structure is used to store test vectors for AES-128 encryption in ECB mode. It contains three 16-byte arrays: `k` for the encryption key, `p` for the plaintext, and `c` for the resulting ciphertext. This structure is primarily used for testing and validating the correctness of AES-128 encryption and decryption operations by comparing expected and actual results.


# Functions

---
### test\_key\_expansion\_zeros<!-- {{#callable:test_key_expansion_zeros}} -->
The function `test_key_expansion_zeros` tests the AES key expansion process for a zeroed key against expected results for a given bit count.
- **Inputs**:
    - `bit_cnt`: The bit count of the AES key, which determines the size of the key expansion.
    - `expected`: A pointer to the expected expanded key data for comparison.
    - `expected_round_cnt`: The expected number of rounds in the key expansion process.
- **Control Flow**:
    - Calculate the size of the expanded key based on the bit count.
    - Initialize a static zeroed key array of 32 bytes.
    - Declare an `fd_aes_key_t` structure to hold the expanded key.
    - Zero out the `expanded` key structure using `fd_memset`.
    - Set the encryption key using [`fd_aes_ref_set_encrypt_key`](fd_aes_base_ref.c.driver.md#fd_aes_ref_set_encrypt_key) with the zeroed key and bit count.
    - Compare the expanded key with the expected key using `memcmp` and assert they are equal.
    - Check that the number of rounds in the expanded key matches the expected round count.
    - Log a success message if all tests pass.
- **Output**: The function does not return a value but logs a success message if the key expansion matches the expected results.
- **Functions called**:
    - [`fd_aes_ref_set_encrypt_key`](fd_aes_base_ref.c.driver.md#fd_aes_ref_set_encrypt_key)


---
### test\_aes\_128\_ecb\_<!-- {{#callable:test_aes_128_ecb_}} -->
The function `test_aes_128_ecb_` tests the encryption and decryption of a 128-bit AES key in ECB mode using a given test vector.
- **Inputs**:
    - `ecb`: A pointer to a constant `fd_aes_128_ecb_fixture_t` structure containing the AES key (`k`), plaintext (`p`), and expected ciphertext (`c`).
- **Control Flow**:
    - Initialize an AES key structure `key` and two 16-byte arrays `c` and `p` for ciphertext and plaintext, respectively.
    - Set the encryption key using [`fd_aes_ref_set_encrypt_key`](fd_aes_base_ref.c.driver.md#fd_aes_ref_set_encrypt_key) with the key from the `ecb` structure and a key size of 128 bits.
    - Encrypt the plaintext from the `ecb` structure into the `c` array using [`fd_aes_ref_encrypt_core`](fd_aes_base_ref.c.driver.md#fd_aes_ref_encrypt_core).
    - Verify that the encrypted `c` matches the expected ciphertext in the `ecb` structure using `FD_TEST` and `memcmp`.
    - Set the decryption key using [`fd_aes_ref_set_decrypt_key`](fd_aes_base_ref.c.driver.md#fd_aes_ref_set_decrypt_key) with the key from the `ecb` structure and a key size of 128 bits.
    - Decrypt the ciphertext from the `ecb` structure into the `p` array using [`fd_aes_ref_decrypt_core`](fd_aes_base_ref.c.driver.md#fd_aes_ref_decrypt_core).
    - Verify that the decrypted `p` matches the original plaintext in the `ecb` structure using `FD_TEST` and `memcmp`.
- **Output**: The function does not return a value; it performs tests and asserts correctness using `FD_TEST`.
- **Functions called**:
    - [`fd_aes_ref_set_encrypt_key`](fd_aes_base_ref.c.driver.md#fd_aes_ref_set_encrypt_key)
    - [`fd_aes_ref_encrypt_core`](fd_aes_base_ref.c.driver.md#fd_aes_ref_encrypt_core)
    - [`fd_aes_ref_set_decrypt_key`](fd_aes_base_ref.c.driver.md#fd_aes_ref_set_decrypt_key)
    - [`fd_aes_ref_decrypt_core`](fd_aes_base_ref.c.driver.md#fd_aes_ref_decrypt_core)


---
### test\_aes\_128\_ecb<!-- {{#callable:test_aes_128_ecb}} -->
The `test_aes_128_ecb` function iterates over a set of AES-128-ECB test vectors, performing encryption and decryption tests on each vector to verify the correctness of the AES-128-ECB implementation.
- **Inputs**: None
- **Control Flow**:
    - Initialize a pointer `v` to the start of the `fd_aes_128_ecb_test_vec` array, which contains test vectors for AES-128-ECB.
    - Calculate the end pointer `v1` by adding the size of the test vector array divided by the size of a single test vector to `v`.
    - Enter a while loop that continues as long as `v` is less than `v1`.
    - In each iteration of the loop, call the [`test_aes_128_ecb_`](#test_aes_128_ecb_) function with the current test vector pointed to by `v`, and then increment `v`.
    - After the loop completes, log a message indicating that the AES-128-ECB encryption and decryption tests have passed.
- **Output**: The function does not return any value; it logs a message indicating the success of the AES-128-ECB tests.
- **Functions called**:
    - [`test_aes_128_ecb_`](#test_aes_128_ecb_)


---
### test\_aes\_128\_gcm\_bounds<!-- {{#callable:test_aes_128_gcm_bounds}} -->
The function `test_aes_128_gcm_bounds` tests AES-128-GCM encryption and decryption operations for out-of-bounds memory access by executing them near unmapped memory regions.
- **Inputs**:
    - `rng`: A pointer to a random number generator object (`fd_rng_t`) used to generate random data for memory initialization.
- **Control Flow**:
    - Check if the code is running on a Linux system using a preprocessor directive.
    - Allocate three large memory regions using `mmap` for plaintext, ciphertext, and state memory, and ensure they are successfully mapped.
    - Unmap most of each region, leaving only a small page-sized area mapped, to create a boundary for testing out-of-bounds access.
    - Initialize the remaining mapped memory regions to zero using `fd_memset`.
    - Set up an AES-GCM state object at the end of the state memory region, ensuring proper alignment.
    - Define zeroed AES key and IV for encryption and decryption operations.
    - Iterate over sizes from 0 to the page size, performing encryption and decryption operations on decreasing sizes of data near the boundary.
    - For each size, initialize the AES-GCM state, encrypt the data, and then decrypt it, checking for successful decryption.
    - Verify that the original plaintext region remains zeroed after operations, indicating no out-of-bounds writes.
    - Unmap the remaining mapped memory regions to clean up.
- **Output**: The function does not return any value; it performs tests and asserts conditions to ensure correct behavior of AES-GCM operations near memory boundaries.


---
### test\_aes\_128\_gcm<!-- {{#callable:test_aes_128_gcm}} -->
The `test_aes_128_gcm` function tests the AES-128-GCM encryption and decryption process, including verifying the integrity and authenticity of the data using predefined test vectors.
- **Inputs**: None
- **Control Flow**:
    - Initialize static arrays for expected IV, key, AAD, plaintext, tag, and ciphertext values.
    - Initialize arrays for actual ciphertext and tag to store encryption results.
    - Initialize an AES-GCM context with the given key and IV.
    - Encrypt the plaintext using AES-GCM, storing the result in the actual ciphertext and tag arrays.
    - Verify that the actual ciphertext and tag match the expected values using `FD_TEST` assertions.
    - Log a success message for encryption if the assertions pass.
    - Initialize an array for actual plaintext to store decryption results.
    - Reinitialize the AES-GCM context and decrypt the actual ciphertext, storing the result in the actual plaintext array.
    - Verify that the decryption was successful and that the actual plaintext matches the expected plaintext using `FD_TEST` assertions.
    - Log a success message for decryption if the assertions pass.
    - Test AEAD malleability by flipping bits in the tag, ciphertext, and AAD, and verify that decryption fails for each corruption using `FD_TEST` assertions.
    - Log a success message for AEAD authentication if the assertions pass.
- **Output**: The function does not return any value; it logs success messages and uses assertions to verify the correctness of the AES-128-GCM operations.


---
### test\_aes\_128\_gcm\_unroll<!-- {{#callable:test_aes_128_gcm_unroll}} -->
The function `test_aes_128_gcm_unroll` tests the AES-128-GCM encryption and decryption process using unrolled loops to ensure correctness and detect buffer overruns.
- **Inputs**: None
- **Control Flow**:
    - Initialize static key, IV, plaintext, and AAD arrays with predefined values.
    - Set a canary value to detect buffer overruns.
    - Iterate over the plaintext size from 1 to 2047 bytes.
    - For each iteration, initialize a result buffer and a tag buffer.
    - Store the canary value in the result buffer at the current index to check for buffer overruns.
    - Initialize the AES-GCM context with the key and IV.
    - Encrypt the plaintext of current size using AES-GCM and store the result in the result buffer and the tag in the tag buffer.
    - Check if the canary value is intact to detect buffer overruns after encryption.
    - Compare the encrypted result with a fixture to verify encryption correctness.
    - Reinitialize the AES-GCM context with the key and IV for decryption.
    - Decrypt the fixture ciphertext using AES-GCM and store the result in the result buffer.
    - Check if the canary value is intact to detect buffer overruns after decryption.
    - Verify the decryption result matches the original plaintext and check the decryption success flag.
- **Output**: The function does not return any value but logs errors if buffer overruns or encryption/decryption mismatches are detected.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, sets up a random number generator, selects AES implementations, runs a series of AES encryption and decryption tests, and then cleans up resources before exiting.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Create and join a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Log the AES implementation being used based on preprocessor directives.
    - Run [`test_key_expansion_zeros`](#test_key_expansion_zeros) to test AES key expansion with a 128-bit key.
    - Execute [`test_aes_128_ecb`](#test_aes_128_ecb) to test AES-128 ECB encryption and decryption.
    - Run [`test_aes_128_gcm_bounds`](#test_aes_128_gcm_bounds) to test AES-128 GCM encryption and decryption with boundary checks using the random number generator.
    - Execute [`test_aes_128_gcm`](#test_aes_128_gcm) to test AES-128 GCM encryption and decryption.
    - Run [`test_aes_128_gcm_unroll`](#test_aes_128_gcm_unroll) to test AES-128 GCM encryption and decryption with unrolling optimizations.
    - Delete the random number generator using `fd_rng_delete` and `fd_rng_leave`.
    - Log a success message and call `fd_halt` to clean up before exiting.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer, 0, indicating successful execution.
- **Functions called**:
    - [`test_key_expansion_zeros`](#test_key_expansion_zeros)
    - [`test_aes_128_ecb`](#test_aes_128_ecb)
    - [`test_aes_128_gcm_bounds`](#test_aes_128_gcm_bounds)
    - [`test_aes_128_gcm`](#test_aes_128_gcm)
    - [`test_aes_128_gcm_unroll`](#test_aes_128_gcm_unroll)


