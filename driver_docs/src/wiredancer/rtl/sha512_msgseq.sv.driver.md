# Purpose
The provided Verilog code defines two modules, `aux_round_msgseq` and `sha512_msgseq`, which are integral components of a SHA-512 message scheduling process. The `aux_round_msgseq` module is responsible for processing a 1024-bit input data block and generating a 64-bit word output for each round of the SHA-512 algorithm. It includes assertions to ensure that the parameters such as `INST_I`, `DATA_W`, and `WORD_W` are within valid ranges, and it uses a combination of bitwise operations and a `shift_adder_6` instance to compute the necessary transformations on the input data. The module is designed to handle different rounds of the SHA-512 algorithm, with specific logic for rounds less than 16 and a more complex computation for rounds 16 and above.

The `sha512_msgseq` module orchestrates the message scheduling for the entire SHA-512 process, iterating over 80 rounds as specified by the SHA-512 standard. It initializes the input data in a big-endian format, as per RFC6234, and uses a generate block to instantiate 80 instances of the `aux_round_msgseq` module, each corresponding to a specific round. This module ensures that the input data is correctly parsed and processed through each round, producing a sequence of 64-bit words that are used in the SHA-512 compression function. The code is structured to adhere to the SHA-512 specification, ensuring that the message schedule is correctly generated for cryptographic operations.
# Modules

---
### aux\_round\_msgseq
The `aux_round_msgseq` module is a Verilog module designed to process a 1024-bit input data stream and produce a 64-bit word output, with the processing logic dependent on the `INST_I` parameter. It includes assertions to ensure parameter constraints and uses a combination of combinational and sequential logic to manipulate data based on the SHA-512 message schedule.
- **Constants**:
    - `DATA_W`: Defines the width of the data input and output, set to 1024 bits.
    - `WORD_W`: Defines the width of the word output, set to 64 bits.
    - `INST_I`: An instance index parameter that determines the processing logic path, constrained to be between 0 and 79.
- **Ports**:
    - `i_data`: 1024-bit input data stream.
    - `o_data`: 1024-bit output data stream.
    - `o_word`: 64-bit output word derived from the input data.
    - `clk`: Clock signal for synchronous operations.
    - `rst`: Reset signal to initialize or reset the module state.
- **Logic And Control Flow**:
    - The module uses assertions to ensure that `INST_I` is within the range [0, 80) and that `DATA_W` and `WORD_W` are set to 1024 and 64, respectively.
    - A `generate` block is used to conditionally assign the `word` based on the value of `INST_I`. If `INST_I` is less than 16, `word` is directly assigned from the `data` array.
    - For `INST_I` values 16 and above, a combinational block calculates intermediate values `a`, `b`, `c`, and `d` using bitwise operations and shifts on selected `data` elements.
    - The `shift_adder_6` module is instantiated to perform additional processing on the calculated values, producing the final `word` output.
    - An `always_ff` block updates `o_word` and `o_data` on the rising edge of `clk`, with `o_data` being conditionally assigned based on `INST_I`.


---
### sha512\_msgseq
The `sha512_msgseq` module is responsible for processing a 1024-bit input data block into a sequence of 64-bit words over 80 rounds, following the SHA-512 message schedule as defined in RFC6234. It uses a big-endian convention and generates intermediate data for each round using the `aux_round_msgseq` module.
- **Constants**:
    - `DATA_W`: Defines the width of the input data, set to 1024 bits.
    - `WORD_W`: Defines the width of each word, set to 64 bits.
    - `ROUNDS`: Defines the number of rounds, set to 80.
    - `D_WD_N`: Calculated as DATA_W divided by WORD_W, resulting in 16.
    - `CYCLES_MSGSEQ`: Defines the number of cycles for the message sequence, set to 1.
- **Ports**:
    - `i_data`: 1024-bit input data block.
    - `o_word`: Array of 80 64-bit output words, one for each round.
    - `clk`: Clock input signal.
    - `rst`: Reset input signal.
- **Logic And Control Flow**:
    - The module asserts that DATA_W, WORD_W, and ROUNDS are set to 1024, 64, and 80 respectively, and checks that D_WD_N equals 16.
    - An `always_comb` block is used to rearrange the input data into a big-endian format, storing it in `t_data[0]`.
    - A `generate` block iterates over 80 rounds, instantiating the `aux_round_msgseq` module for each round to process the data and produce the output words.


