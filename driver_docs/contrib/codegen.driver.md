
## Files
- **[cavp_generate.py](codegen/cavp_generate.py.driver.md)**: The `cavp_generate.py` file in the `firedancer` codebase generates C include files containing NIST CAVP test vectors for verifying cryptographic hash function implementations.
- **[gen_map_perfect.py](codegen/gen_map_perfect.py.driver.md)**: The `gen_map_perfect.py` file in the `firedancer` codebase is responsible for generating perfect hash functions for various tables of public keys and program identifiers by finding suitable constants for hash calculations.
- **[gen_wycheproofs.py](codegen/gen_wycheproofs.py.driver.md)**: The `gen_wycheproofs.py` file in the `firedancer` codebase downloads the latest Wycheproof test vectors and generates corresponding C test code for EDDSA and XDH algorithms.
- **[generate_filters.py](codegen/generate_filters.py.driver.md)**: The `generate_filters.py` file in the `firedancer` codebase is a script that compiles symbolic expressions into C header files containing cBPF code, specifically for generating seccomp filters, and includes functionality for handling conditional and unconditional jumps, as well as evaluating expressions.
