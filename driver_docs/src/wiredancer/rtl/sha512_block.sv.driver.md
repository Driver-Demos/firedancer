# Purpose
The provided Verilog code defines a module named `sha512_block`, which implements a hardware block for processing a single block of data using the SHA-512 cryptographic hash function. This module is a specialized component designed to perform the SHA-512 hashing algorithm, which is part of the SHA-2 family of cryptographic hash functions. The module is parameterized to handle specific data widths and control signals, and it processes 1024-bit data blocks to produce a 512-bit hash output. The code includes several local parameters and assertions to ensure that the module is configured correctly, adhering to the specifications of the SHA-512 algorithm as described in RFC 6234.

The module is composed of several key components, including initialization vectors, constants for the SHA-512 rounds, and a series of pipeline stages to manage the data flow and control signals. It uses a combination of combinational and sequential logic to implement the hashing process, with a focus on maintaining the big-endian data convention specified in the SHA-512 standard. The module also includes a dual-port RAM for storing intermediate hash values and a FIFO for managing message data. The design is structured to support 80 rounds of the SHA-512 compression function, with each round implemented by an instance of the `sha512_round` submodule. This module is intended to be used as a building block in larger cryptographic systems, providing the core functionality needed to compute SHA-512 hashes efficiently in hardware.
# Modules

---
### sha512\_block
The `sha512_block` module implements a SHA-512 hashing block, processing 1024-bit data blocks to produce a 512-bit hash output. It uses a series of constants and initial vectors defined by the SHA-512 standard and processes data through multiple rounds of hashing operations.
- **Constants**:
    - `DATA_W`: Defines the data width, set to 1024 bits, for the input data block.
    - `CTRL_W`: Defines the control width, set to 3 bits, for control signals.
    - `MSGI_W`: Defines the message input width, set to 64 bits.
    - `HASH_W`: Defines the hash width, set to 512 bits, for the output hash.
    - `WORD_W`: Defines the word width, set to 64 bits, for processing words.
    - `H_WD_N`: Calculated as HASH_W / WORD_W, representing the number of words in the hash, which is 8.
    - `N_ROUNDS`: Defines the number of rounds in the SHA-512 process, set to 80.
    - `CYCLES_OHEAD`: Defines the overhead cycles, set to 3.
    - `CYCLES_ROUND`: Defines the cycles per round, set to 1.
    - `CYCLES_ADDER`: Defines the cycles for the adder, set to 1.
    - `CYCLES_BLOCK`: Total cycles for processing a block, calculated as CYCLES_OHEAD + N_ROUNDS * CYCLES_ROUND + CYCLES_ADDER.
    - `M_FIFO_DEPTH`: Defines the depth of the message FIFO, calculated as 1<<$clog2(CYCLES_BLOCK + 2).
    - `M_FIFO_WIDTH`: Defines the width of the message FIFO, set to MSGI_W.
    - `CTRL_BIT_FIRST`: Defines the bit position for the first control bit, set to 2.
    - `CTRL_BIT_MIDD`: Defines the bit position for the middle control bit, set to 1.
    - `CTRL_BIT_LAST`: Defines the bit position for the last control bit, set to 0.
    - `RCOUNT_N`: Calculated as CYCLES_OHEAD + N_ROUNDS * CYCLES_ROUND, representing the number of rounds plus overhead.
    - `RCOUNT_D`: Defines a constant for round count adjustment, set to 6.
    - `RCOUNT_W`: Calculated as $clog2(RCOUNT_N + RCOUNT_D), representing the width of the round count.
    - `H_RAM_ADDR_W`: Defines the address width for the hash RAM, calculated as $clog2(RCOUNT_N).
    - `H_RAM_DATA_W`: Defines the data width for the hash RAM, set to HASH_W.
- **Ports**:
    - `i_valid`: Input signal indicating the validity of the input data.
    - `i_data`: 1024-bit input data block to be hashed.
    - `i_ctrl`: 3-bit input control signal for processing control.
    - `i_msgi`: 64-bit input message index or identifier.
    - `o_valid`: Output signal indicating the validity of the output hash.
    - `o_msgi`: 64-bit output message index or identifier.
    - `o_hash`: 512-bit output hash result.
    - `clk`: Clock input signal for synchronous operations.
    - `rst`: Reset input signal to initialize or reset the module.
- **Logic And Control Flow**:
    - The module uses assertions to ensure that the parameters DATA_W, CTRL_W, HASH_W, and WORD_W are set to their expected values, and it checks the derived parameter H_WD_N.
    - Local parameters define various constants used in the SHA-512 process, including the number of rounds, cycle overhead, and FIFO configurations.
    - The module initializes the SHA-512 initial hash values and constants as per the SHA-512 standard using big-endian convention.
    - The `always_ff` block at the positive edge of the clock updates the timestamp and processes the input data through a series of pipeline stages, managing control signals and hash calculations.
    - The `always_comb` block initializes the input vectors and manages the control flow for the message FIFO and hash RAM operations.
    - The module instantiates a `sha512_msgseq` submodule to handle message sequencing and a `sha512_round` submodule for each of the 80 rounds of the SHA-512 process.
    - A dual-port RAM is used to store intermediate hash values, and a FIFO is used for message handling, ensuring data is processed in the correct sequence.


