# Purpose
The provided Verilog code defines a module named `sha512_round`, which implements a single round of the SHA-512 cryptographic hash function. This module is a specialized component designed to perform the complex bitwise operations and arithmetic required in one iteration of the SHA-512 algorithm. The module takes as inputs a 512-bit hash value (`i_hash`), a 64-bit word (`i_word`), and a 64-bit constant value (`i_cval`). It outputs a 512-bit hash value (`o_hash`) after processing these inputs through the SHA-512 round operations. The module is clocked and resettable, with `clk` and `rst` as its clock and reset signals, respectively.

Key technical components of this module include the use of bitwise operations to compute intermediate values such as `ma`, `ch`, `ea`, and `ee`, which are essential for the SHA-512 round function. The module also utilizes a `shift_adder_6` instance to perform a series of additions and shifts, which are integral to the hash computation process. The final output hash is constructed by combining these intermediate results. The module enforces specific parameter values for `HASH_W` and `WORD_W` through assertions, ensuring that the module operates with the correct bit-widths for SHA-512. This code is a focused implementation of a cryptographic algorithm component, intended to be used as part of a larger system that performs SHA-512 hashing.
# Modules

---
### sha512\_round
The `sha512_round` module implements a single round of the SHA-512 hashing algorithm. It processes input hash values and constants to produce an updated hash output.
- **Constants**:
    - `HASH_W`: Defines the width of the hash, set to 512 bits.
    - `WORD_W`: Defines the width of a word, set to 64 bits.
    - `CYCLES_ROUND`: A local parameter set to 1, indicating the number of cycles per round.
- **Ports**:
    - `i_hash`: Input port for the current hash value, 512 bits wide.
    - `i_word`: Input port for the current word, 64 bits wide.
    - `i_cval`: Input port for the current constant value, 64 bits wide.
    - `o_hash`: Output port for the updated hash value, 512 bits wide.
    - `clk`: Clock input signal.
    - `rst`: Reset input signal.
- **Logic And Control Flow**:
    - The module begins with assertions to ensure that the `HASH_W` and `WORD_W` parameters are set to 512 and 64, respectively.
    - Local logic variables are declared to hold intermediate values for the hash computation.
    - An `always_comb` block is used to compute intermediate values such as `ma`, `ch`, `ea`, `ee`, `s0`, `s1`, and `s2` based on the input hash and word values.
    - The `shift_adder_6` module is instantiated to perform a series of additions, with its output `s6` used in further calculations.
    - An `always_ff` block updates the output hash `o_hash` on the rising edge of the clock, combining the computed values into the new hash.


