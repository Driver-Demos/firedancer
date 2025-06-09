# Purpose
This C source code file is part of an implementation of a Reed-Solomon error correction algorithm, specifically designed to recover data from a set of shreds, which are fragments of data that include both original data and parity information. The function [`fd_reedsol_private_recover_var_128`](#fd_reedsol_private_recover_var_128) is the primary component of this file, and it is responsible for reconstructing missing or corrupted data shreds using the Reed-Solomon algorithm. The function takes in parameters such as the size of each shred, pointers to the shreds themselves, the count of data and parity shreds, and an array indicating which shreds are erased. It uses these inputs to determine which shreds need to be regenerated and performs operations in the Galois Field (GF) to achieve this.

The code is highly specialized and optimized for performance, as indicated by the use of macros and manual loop unrolling to handle up to 128 shreds at a time. It employs techniques such as Fast Fourier Transforms (FFT) and inverse FFTs (IFFT) to efficiently process the data. The function checks for data integrity by comparing regenerated shreds with existing ones and returns specific error codes if it detects partial data or corruption. This file is likely part of a larger library or system that deals with data redundancy and recovery, and it does not define public APIs or external interfaces directly, as it is marked as a private function. The inclusion of headers like "fd_reedsol_ppt.h" and "fd_reedsol_fderiv.h" suggests that it relies on other components of the Reed-Solomon implementation for its operations.
# Imports and Dependencies

---
- `fd_reedsol_ppt.h`
- `fd_reedsol_fderiv.h`


# Functions

---
### fd\_reedsol\_private\_recover\_var\_128<!-- {{#callable:fd_reedsol_private_recover_var_128}} -->
The function `fd_reedsol_private_recover_var_128` attempts to recover data from a set of shreds using Reed-Solomon error correction, handling up to 128 shreds at a time.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes.
    - `shred`: An array of pointers to the shreds, where each pointer points to a shred of data.
    - `data_shred_cnt`: The number of data shreds available.
    - `parity_shred_cnt`: The number of parity shreds available.
    - `erased`: An array indicating which shreds are erased (1 if erased, 0 if not).
- **Control Flow**:
    - Initialize arrays `_erased` and `pi` to track erased shreds and permutation indices respectively.
    - Calculate the total number of shreds (`shred_cnt`) and initialize `loaded_cnt` to count loaded data shreds.
    - Iterate over 128 possible shreds, marking those that can be loaded and updating `_erased` and `loaded_cnt`.
    - If the number of loaded data shreds is less than `data_shred_cnt`, return an error indicating partial data.
    - Generate permutation indices using [`fd_reedsol_private_gen_pi_128`](fd_reedsol_pi.c.driver.md#fd_reedsol_private_gen_pi_128).
    - Initialize `diff` to track differences between regenerated and original shreds.
    - Iterate over the shred size, loading data into vectors, filling erased vectors with zeros, and multiplying by permutation indices.
    - Perform inverse FFT, derivative generation, and FFT on the vectors.
    - Multiply the vectors by permutation indices again, focusing on erased shreds.
    - Use a switch-case to handle storing, comparing, and reloading shreds based on their erased status.
    - If any differences are detected, return an error indicating corruption.
    - Advance the shred position manually, ensuring it does not exceed the shred size.
    - Return success if all operations complete without errors.
- **Output**: Returns an integer status code: `FD_REEDSOL_SUCCESS` on successful recovery, `FD_REEDSOL_ERR_PARTIAL` if not enough data shreds are loaded, or `FD_REEDSOL_ERR_CORRUPT` if a corruption is detected.
- **Functions called**:
    - [`fd_reedsol_private_gen_pi_128`](fd_reedsol_pi.c.driver.md#fd_reedsol_private_gen_pi_128)
    - [`gf_ldu`](fd_reedsol_arith_none.h.driver.md#gf_ldu)
    - [`fd_reedsol_ifft_128_0`](wrapped_impl/fd_reedsol_fft_impl_128_0.c.driver.md#fd_reedsol_ifft_128_0)
    - [`fd_reedsol_fft_128_0`](wrapped_impl/fd_reedsol_fft_impl_128_0.c.driver.md#fd_reedsol_fft_128_0)


