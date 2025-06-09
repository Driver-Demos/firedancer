# Purpose
This Python file is a comprehensive testbench script designed for use with the Cocotb framework, which is a coroutine-based co-simulation library for testing VHDL and Verilog designs. The script is primarily focused on simulating and verifying the functionality of a digital design that involves cryptographic operations, specifically those related to the Ed25519 digital signature algorithm and SHA-512 hashing. The file imports several libraries, including Cocotb, and defines a variety of asynchronous functions (coroutines) that simulate different aspects of the hardware design, such as data transactions over PCIe, signature verification, and hash computation.

The script includes functions for generating test data, performing bit manipulations, and simulating hardware behavior. It defines several coroutines that monitor and verify the outputs of the design under test (DUT) against expected values, ensuring that the design behaves correctly under various conditions. The coroutines handle tasks such as toggling reset signals, generating random data, and verifying the results of cryptographic operations. The file also includes utility functions for converting data between different formats, such as bytes to integers, and for performing mathematical operations like modular arithmetic. Overall, this script serves as a detailed and automated testing environment for validating the correctness and performance of a hardware design implementing cryptographic functions.
# Imports and Dependencies

---
- `random`
- `hashlib`
- `cocotb`
- `cocotb.clock.Clock`
- `cocotb.triggers.Timer`
- `cocotb.triggers.RisingEdge`
- `cocotb.triggers.ReadOnly`
- `cocotb.binary.BinaryValue`
- `cocotb.utils.get_sim_time`
- `ed25519_lib`
- `ref_ed25519`
- `sigverify`


# Global Variables

---
### PCIE\_MAGIC
- **Type**: `int`
- **Description**: `PCIE_MAGIC` is a global integer variable that holds a specific hexadecimal value, `0xACE0FBAC`. This value is likely used as a magic number, which is a constant used to identify a file format or protocol and ensure data integrity.
- **Use**: This variable is used in the `build_pcie_tr_i` function to construct a block of data for PCIe transactions, serving as an identifier or marker.


---
### PCIE\_ADDR\_W
- **Type**: `int`
- **Description**: `PCIE_ADDR_W` is a global integer variable set to the value 20. This variable likely represents the width of a PCIe address in bits, which is a common parameter in hardware design and simulation contexts.
- **Use**: This variable is used to define the bit-width of PCIe addresses in the simulation environment.


---
### meta0
- **Type**: `list`
- **Description**: The variable `meta0` is a list containing two integer elements: 16 and 64. It is defined at the top level of the code, making it a global variable.
- **Use**: `meta0` is used as a base list to construct other lists like `meta1`, `meta6`, and `meta7` by appending additional elements to it.


---
### meta1
- **Type**: `list`
- **Description**: The variable `meta1` is a list that is constructed by appending three integer values, 256, 256, and 256, to the list `meta0`. The list `meta0` is defined earlier in the code as `[16, 64]`, so `meta1` becomes `[16, 64, 256, 256, 256]`. This list likely represents a set of parameters or configuration values used in the program.
- **Use**: `meta1` is used as a base list to define other meta variables like `meta2`, `meta3`, and `meta4` by further appending additional values to it.


---
### meta2
- **Type**: `list`
- **Description**: The variable `meta2` is a list that is constructed by appending the elements `[16, 6, 1, 512]` to the list `meta1`. The list `meta1` itself is derived from `meta0` by adding the elements `[256, 256, 256]` to it, where `meta0` is `[16, 64]`. Therefore, `meta2` is a list containing the elements `[16, 64, 256, 256, 256, 16, 6, 1, 512]`.
- **Use**: This variable is used to define a specific metadata structure, likely for configuration or data processing purposes in the code.


---
### meta3
- **Type**: `list`
- **Description**: The variable `meta3` is a list that is constructed by appending the elements `[1, 4, 1024]` to the list `meta1`. The list `meta1` itself is derived from `meta0` by adding three `256` values, making `meta1` equal to `[16, 64, 256, 256, 256]`. Therefore, `meta3` becomes `[16, 64, 256, 256, 256, 1, 4, 1024]`.
- **Use**: This variable is used to define a specific metadata structure, likely for configuration or data processing purposes in the code.


---
### meta4
- **Type**: `list`
- **Description**: The variable `meta4` is a list that is created by appending the integer 256 to the list `meta1`. The list `meta1` itself is derived from `meta0` by adding three 256 values to it, making `meta1` equal to `[16, 64, 256, 256, 256]`. Therefore, `meta4` becomes `[16, 64, 256, 256, 256, 256]`.
- **Use**: This variable is used to define a specific configuration or set of parameters, likely related to data processing or hardware configuration, as part of a series of similar lists (`meta0` to `meta7`).


---
### meta5
- **Type**: `list`
- **Description**: The variable `meta5` is a list that is constructed by appending eight 256 values to the list `meta4`. The list `meta4` itself is derived from `meta1` by adding a single 256 value, where `meta1` is an extension of `meta0` with three 256 values. `meta0` is initially defined as a list containing the integers 16 and 64.
- **Use**: This variable is used to define a specific metadata configuration, likely for use in data processing or transmission operations within the code.


---
### meta6
- **Type**: `list`
- **Description**: The variable `meta6` is a list that is constructed by concatenating the list `meta0` with a list of five 256 values and a single 1 at the end. `meta0` itself is a list containing the integers 16 and 64.
- **Use**: This variable is used to define a specific metadata structure, likely for configuration or data processing purposes in the context of the code.


---
### meta7
- **Type**: `list`
- **Description**: The variable `meta7` is a list that is created by appending the integer 1 to the list `meta0`. The list `meta0` is defined as `[16, 64]`, so `meta7` becomes `[16, 64, 1]`. This list is likely used to define a specific set of parameters or configuration values for a particular operation or function in the code.
- **Use**: `meta7` is used to extract metadata in the `extr_meta` function, which processes metadata based on the structure defined by `meta7`.


# Functions

---
### get\_cycle<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.get_cycle}} -->
The `get_cycle` function returns the current simulation time in nanoseconds.
- **Inputs**: None
- **Control Flow**:
    - The function calls `get_sim_time` with the argument `'ns'` to retrieve the current simulation time in nanoseconds.
    - It directly returns the result of the `get_sim_time` function call.
- **Output**: The output is the current simulation time in nanoseconds, as returned by the `get_sim_time` function.


---
### f1\_write\_32x16<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.f1_write_32x16}} -->
The `f1_write_32x16` function writes a 512-bit data value to a PCIe interface in a 32x16 configuration, either in a single or split transaction, based on a predefined split condition.
- **Inputs**:
    - `dut`: The device under test (DUT) object representing the hardware interface.
    - `clk`: The clock signal used to synchronize the write operation.
    - `addr`: The address to which the data is to be written on the PCIe interface.
    - `data`: The 512-bit data value to be written to the PCIe interface.
- **Control Flow**:
    - Initialize a `BinaryValue` object `b` with 512 bits and set its value to the input `data`.
    - Check the `split` variable, which is set to 0, indicating no split transaction.
    - If `split` is 0, set `dut.pcie_v` to 0x3, assign `addr` to `dut.pcie_a`, and split `b` into two 256-bit segments assigned to `dut.pcie_d[0]` and `dut.pcie_d[1]`.
    - Await a rising edge on the `clk` signal, then set `dut.pcie_v` to 0x0 to complete the transaction.
    - If `split` were 1 (though it is not in this code), the function would perform a split transaction, writing the first 256 bits, awaiting a clock edge, then writing the second 256 bits to an incremented address.
- **Output**: The function does not return any value; it performs a write operation on the DUT's PCIe interface.


---
### sha512\_modq\_from\_bytes<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.sha512_modq_from_bytes}} -->
The function `sha512_modq_from_bytes` computes the SHA-512 hash of a byte string, converts it to a little-endian integer, and returns the result modulo a predefined constant `q` from the `ref_ed25519` module.
- **Inputs**:
    - `s`: A byte string input for which the SHA-512 hash will be computed.
- **Control Flow**:
    - Compute the SHA-512 hash of the input byte string `s` and store the result in `h`.
    - Define a constant `q` as `2**252 + 27742317777372353535851937790883648493`.
    - Convert the hash `h` from bytes to a little-endian integer using the [`bytes_to_little`](#bytes_to_little) function.
    - Return the result of the little-endian integer modulo `ref_ed25519.q`.
- **Output**: An integer which is the SHA-512 hash of the input byte string, converted to a little-endian integer, and then taken modulo `ref_ed25519.q`.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.bytes_to_little`](#bytes_to_little)


---
### sha512\_modq\_from\_ints<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.sha512_modq_from_ints}} -->
The function `sha512_modq_from_ints` converts a list of integers to a byte array and computes the SHA-512 hash modulo a large prime number q.
- **Inputs**:
    - `s`: A list of integers that will be converted to a byte array for hashing.
- **Control Flow**:
    - The function takes a list of integers `s` as input.
    - It converts the list of integers into a `bytearray`.
    - It calls the function [`sha512_modq_from_bytes`](#sha512_modq_from_bytes) with the `bytearray` as an argument.
    - The result from [`sha512_modq_from_bytes`](#sha512_modq_from_bytes) is returned.
- **Output**: The output is the result of the SHA-512 hash of the input integers (converted to bytes) modulo a large prime number q.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.sha512_modq_from_bytes`](#sha512_modq_from_bytes)


---
### bytes\_to\_little<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.bytes_to_little}} -->
The `bytes_to_little` function converts a byte sequence into a little-endian integer.
- **Inputs**:
    - `s`: A sequence of bytes (e.g., a bytes object) to be converted into a little-endian integer.
- **Control Flow**:
    - Initialize an integer variable `n` to 0 to accumulate the result.
    - Iterate over each byte in the input sequence `s` using its index `i`.
    - For each byte, shift it left by `i*8` bits and add the result to `n`.
    - Continue this process for all bytes in the sequence to build the little-endian integer.
    - Return the accumulated integer `n`.
- **Output**: An integer representing the little-endian conversion of the input byte sequence.


---
### str\_to\_little<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.str_to_little}} -->
The `str_to_little` function converts a string into a little-endian integer representation.
- **Inputs**:
    - `s`: A string input that will be converted to a little-endian integer.
- **Control Flow**:
    - Initialize an integer variable `n` to 0.
    - Iterate over each character in the string `s` using its index `i`.
    - For each character, convert it to its ASCII value using `ord()` and shift it left by `i*8` bits.
    - Add the shifted value to `n`.
    - Return the final value of `n`.
- **Output**: An integer representing the little-endian conversion of the input string.


---
### little\_to\_str<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.little_to_str}} -->
The `little_to_str` function converts a given integer into a string by extracting bytes and converting them to characters.
- **Inputs**:
    - `n`: An integer representing the number to be converted into a string.
    - `bs`: An integer representing the number of bytes to process from the integer.
- **Control Flow**:
    - Initialize an empty string `s` to accumulate characters.
    - Iterate over a range of `bs`, which represents the number of bytes to process.
    - In each iteration, extract an 8-bit segment from `n` starting at the bit position `i*8` using the [`bits`](#bits) function.
    - Convert the extracted byte to a character using `chr` and append it to the string `s`.
    - Return the accumulated string `s`.
- **Output**: A string composed of characters derived from the bytes of the input integer `n`.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)


---
### little\_to\_ints<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.little_to_ints}} -->
The function `little_to_ints` converts a given integer into a list of integers, each representing a byte of the original integer in little-endian order.
- **Inputs**:
    - `n`: The integer to be converted into a list of byte-sized integers.
    - `bs`: The number of bytes to extract from the integer.
- **Control Flow**:
    - The function uses a list comprehension to iterate over a range of size `bs`.
    - For each iteration, it calls the [`bits`](#bits) function to extract an 8-bit segment from the integer `n`, starting at the bit position `i*8`.
    - The extracted 8-bit segments are collected into a list.
- **Output**: A list of integers, each representing an 8-bit segment of the input integer `n`, extracted in little-endian order.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)


---
### lfsr\_32<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.lfsr_32}} -->
The `lfsr_32` function performs a linear feedback shift register (LFSR) operation on a 32-bit integer.
- **Inputs**:
    - `lfsr`: A 32-bit integer representing the current state of the LFSR.
- **Control Flow**:
    - Calculate the feedback bit `fb` by XORing specific bits (0, 1, 21, and 31) of the input `lfsr`.
    - Shift the `lfsr` left by one bit and append the feedback bit `fb` to the least significant bit position.
    - Return the new LFSR state as a 32-bit integer.
- **Output**: A 32-bit integer representing the updated state of the LFSR after the shift and feedback operation.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)


---
### log2<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.log2}} -->
The `log2` function calculates the base-2 logarithm of a given number and returns it as an integer.
- **Inputs**:
    - `n`: The number for which the base-2 logarithm is to be calculated.
- **Control Flow**:
    - The function uses the `math.log` function to compute the natural logarithm of the input `n`.
    - It then divides the result by the natural logarithm of 2 to convert it to a base-2 logarithm.
    - The result is converted to an integer using the `int` function before being returned.
- **Output**: An integer representing the base-2 logarithm of the input number `n`.


---
### bits<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.bits}} -->
The `bits` function extracts a specified number of bits from an integer starting at a given bit position.
- **Inputs**:
    - `n`: The integer from which bits are to be extracted.
    - `b`: The number of bits to extract.
    - `s`: The starting bit position from which to begin extraction.
- **Control Flow**:
    - The function shifts the integer `n` to the right by `s` positions to align the desired bits with the least significant bit.
    - It then creates a mask by shifting 1 left by `b` positions and subtracting 1, which results in a binary number with `b` least significant bits set to 1.
    - The function performs a bitwise AND operation between the shifted integer and the mask to extract the desired bits.
- **Output**: The function returns an integer representing the extracted bits.


---
### random\_int<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.random_int}} -->
The `random_int` function generates a random integer with a specified number of bits.
- **Inputs**:
    - `b`: An integer specifying the number of bits for the random integer, defaulting to 32.
- **Control Flow**:
    - Initialize a variable `n` to 0 to store the resulting random integer.
    - Iterate `b` times, where `b` is the number of bits specified.
    - In each iteration, left-shift `n` by 1 bit to make room for the next random bit.
    - Use `random.randint(0, 1)` to generate a random bit (0 or 1) and bitwise OR it with `n` to add the random bit to the least significant position of `n`.
- **Output**: Returns an integer `n` that is a random number with `b` bits.


---
### gen\_blocks\_from\_msg\_str<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.gen_blocks_from_msg_str}} -->
The function `gen_blocks_from_msg_str` converts a string message into a list of integer blocks, each representing a 1024-bit block of the message after padding and length encoding.
- **Inputs**:
    - `m_str`: A string message where each character is 1 byte.
- **Control Flow**:
    - Convert each character in the input string to its hexadecimal representation and concatenate them to form a hex string.
    - Calculate the length of the hex string and append '80' to it for padding.
    - Determine the necessary padding length to make the total length a multiple of 1024 bits, considering the space needed for the length encoding.
    - Append the calculated number of '0's to the hex string for padding.
    - Append the original message length in bits, encoded as a 16-byte (32 hex characters) string, to the hex string.
    - Ensure the final hex string length is a multiple of 1024 bits, raising an assertion error if not.
    - Divide the hex string into 1024-bit blocks, convert each block from hex to an integer, and store them in a list.
    - Return the list of integer blocks.
- **Output**: A list of integers, each representing a 1024-bit block of the padded and length-encoded message.


---
### random\_tr<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.random_tr}} -->
The `random_tr` function generates a random transaction dictionary with various fields, including message, signature, and verification data, based on provided or default random inputs.
- **Inputs**:
    - `src`: The source identifier for the transaction, defaulting to 0.
    - `sha_pre_meta`: Optional pre-computed SHA pre-meta data, defaulting to None.
    - `sha_modq_meta`: Optional pre-computed SHA modq meta data, defaulting to None.
    - `tid`: Optional transaction ID, defaulting to None.
    - `mlen`: Optional message length, defaulting to None, which results in a random length between 0 and 1280.
    - `sig`: Optional signature data, defaulting to None.
    - `pub`: Optional public key data, defaulting to None.
    - `msg`: Optional message data, defaulting to None, which results in a random byte array of length `mlen`.
- **Control Flow**:
    - If `mlen` is None, it is set to a random integer between 0 and 1280.
    - If `msg` is None, it is set to a list of random integers between 0 and 255, with length `mlen`.
    - A dictionary `tr` is initialized to store transaction data.
    - Various fields in `tr` are populated with random values or derived from input parameters, including `dma_addr`, `dma_seq`, `dma_ctrl`, `dma_size`, `dma_chunk`, `time_0` to `time_3`, `err`, `src`, `tid`, `sig_l`, `sig_h`, `pub`, `msg_sz`, `msg_s`, `sha_msg`, `sha_modq`, `sha_pre_meta`, `sha_modq_meta`, `pcie_tr`, and `sigverify`.
    - The `sha_msg` field is constructed by concatenating the little-endian integer representations of `sig_l`, `pub`, and `msg_s`.
    - The `sha_modq` field is computed using the [`sha512_modq_from_ints`](#sha512_modq_from_ints) function on `sha_msg`.
    - The `sha_pre_meta` and `sha_modq_meta` fields are set to the provided values or computed using [`build_sha_pre_meta`](#build_sha_pre_meta) and [`build_sha_modq_meta`](#build_sha_modq_meta) functions, respectively.
    - The `pcie_tr` field is constructed using the [`build_pcie_tr_i`](#build_pcie_tr_i) function.
    - The `sigverify` field is computed by verifying the signature using the `ref_ed25519.verify` function.
    - The transaction dictionary `tr` is printed with the `sigverify` result and returned.
- **Output**: A dictionary `tr` containing the transaction data with fields such as `dma_addr`, `dma_seq`, `dma_ctrl`, `dma_size`, `dma_chunk`, `time_0` to `time_3`, `err`, `src`, `tid`, `sig_l`, `sig_h`, `pub`, `msg_sz`, `msg_s`, `sha_msg`, `sha_modq`, `sha_pre_meta`, `sha_modq_meta`, `pcie_tr`, and `sigverify`.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.random_int`](#random_int)
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)
    - [`firedancer/src/wiredancer/py/wd_cocotil.little_to_ints`](#little_to_ints)
    - [`firedancer/src/wiredancer/py/wd_cocotil.sha512_modq_from_ints`](#sha512_modq_from_ints)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_sha_pre_meta`](#build_sha_pre_meta)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_sha_modq_meta`](#build_sha_modq_meta)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_pcie_tr_i`](#build_pcie_tr_i)


---
### toggle\_reset<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.toggle_reset}} -->
The `toggle_reset` function asynchronously toggles a reset signal after a specified number of clock cycles.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `clk`: The clock signal to synchronize the reset toggling.
    - `reset`: The reset signal object whose value will be toggled.
    - `n`: The number of clock cycles to wait before toggling the reset signal.
    - `active_high`: A boolean indicating if the reset is active high (default is True).
- **Control Flow**:
    - Set the reset signal to the active state based on the `active_high` parameter.
    - Wait for `n` rising edges of the clock signal.
    - Set the reset signal to the inactive state by negating the `active_high` parameter.
    - Wait for another `n` rising edges of the clock signal.
- **Output**: The function does not return any value; it modifies the `reset` signal in place.


---
### random\_toggle<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.random_toggle}} -->
The `random_toggle` function asynchronously toggles the value of a signal based on a random probability at each rising edge of a clock signal.
- **Inputs**:
    - `clk`: The clock signal that triggers the toggle operation on its rising edge.
    - `s`: The signal whose value is to be toggled.
    - `p`: The probability (as an integer percentage) that the signal will be set to 1.
- **Control Flow**:
    - The function enters an infinite loop, continuously awaiting the next rising edge of the clock signal.
    - Upon each rising edge, it generates a random integer between 0 and 99.
    - It compares this random integer to the probability `p` to decide whether to set the signal `s` to 1 or 0.
- **Output**: The function does not return a value; it modifies the signal `s` in place.


---
### build\_meta0<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_meta0}} -->
The `build_meta0` function constructs a 64-bit integer by combining the 'src' and 'tid' fields from the input dictionary `tr`.
- **Inputs**:
    - `tr`: A dictionary containing at least the keys 'src' and 'tid', which are expected to be integers.
- **Control Flow**:
    - Initialize a variable `m` to 0.
    - Shift the 'src' value from the dictionary `tr` by 0 bits and OR it with `m`.
    - Shift the 'tid' value from the dictionary `tr` by 32 bits and OR it with `m`.
    - Return the resulting integer `m`.
- **Output**: A 64-bit integer that combines the 'src' and 'tid' fields from the input dictionary `tr`.


---
### extr\_meta<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.extr_meta}} -->
The `extr_meta` function extracts specific bit segments from a given integer based on a list of bit lengths and returns them as a tuple.
- **Inputs**:
    - `m`: A list of integers representing the number of bits to extract from the integer `n`.
    - `n`: An integer from which bit segments are extracted based on the bit lengths specified in `m`.
- **Control Flow**:
    - Initialize a variable `s` to 0 and an empty list `l`.
    - Iterate over each bit length `b` in the list `m`.
    - For each `b`, extract `b` bits from `n` starting at position `s` using the [`bits`](#bits) function and append the result to the list `l`.
    - Increment `s` by `b` to update the starting position for the next extraction.
    - After processing all bit lengths, convert the list `l` to a tuple and return it.
- **Output**: A tuple containing the extracted bit segments from the integer `n`, as specified by the bit lengths in `m`.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)


---
### random\_byte\_error<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.random_byte_error}} -->
The `random_byte_error` function introduces a random bit error into a given byte sequence.
- **Inputs**:
    - `bs`: A sequence of bytes (e.g., a bytearray or bytes object) to which a random bit error will be applied.
- **Control Flow**:
    - Convert the input byte sequence `bs` into a list `l` to allow mutation.
    - Select a random index `i` within the range of the byte sequence length.
    - Select a random bit position `j` within the range of 0 to 7 (inclusive).
    - Check if the bit at position `j` in the byte at index `i` is set (i.e., is 1).
    - If the bit is set, clear it by subtracting `1 << j` from the byte at index `i`.
    - If the bit is not set, set it by adding `1 << j` to the byte at index `i`.
    - Return the modified list `l` with the random bit error introduced.
- **Output**: A list of bytes with one random bit error introduced.


---
### build\_pcie\_tr\_i<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_pcie_tr_i}} -->
The function `build_pcie_tr_i` constructs a list of integer blocks representing a PCIe transaction from a given transaction dictionary.
- **Inputs**:
    - `tr`: A dictionary containing transaction details such as source, message size, DMA parameters, signature, and public key.
- **Control Flow**:
    - Initialize an empty list `blks` to store the blocks.
    - Create the first block `blk` by combining various fields from the transaction dictionary `tr` using bitwise operations and append it to `blks`.
    - Create the second block `blk` using the high part of the signature and the public key, then append it to `blks`.
    - Iterate over the message string `msg_s` from `tr`, constructing blocks of up to 512 bits, appending each completed block to `blks`.
    - If there is any remaining data in the last block, append it to `blks`.
- **Output**: A list of integer blocks representing the PCIe transaction.


---
### build\_pcie\_tr\_o<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_pcie_tr_o}} -->
The function `build_pcie_tr_o` constructs a list of 512-bit blocks from a transaction dictionary for PCIe output.
- **Inputs**:
    - `tr`: A dictionary containing transaction data with keys 'sig_l', 'pub', and 'msg_s'.
- **Control Flow**:
    - Initialize an empty list `blks` to store the blocks.
    - Create a 512-bit block `blk` and set its lower 256 bits to `tr['sig_l']` and upper 256 bits to `tr['pub']`, then append it to `blks`.
    - Initialize another 512-bit block `blk` and a byte index `bi`.
    - Iterate over the bytes in `tr['msg_s']`, shifting each byte into `blk` at the position determined by `bi`.
    - Increment `bi` after each byte and append `blk` to `blks` when `bi` reaches 64 (indicating a full 512-bit block), then reset `blk` and `bi`.
    - If there are remaining bytes after the loop, append the partially filled `blk` to `blks`.
- **Output**: A list of 512-bit integer blocks representing the transaction data.


---
### mon\_pcie\_tr\_ext<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.mon_pcie_tr_ext}} -->
The `mon_pcie_tr_ext` function monitors and verifies PCIe transactions by comparing expected and actual data on input and output queues.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The device under test (DUT) object used for logging.
    - `dut`: The device under test (DUT) object representing the hardware module being tested.
    - `clk`: The clock signal used to synchronize the monitoring process.
    - `q_i`: An optional input queue containing expected PCIe input transactions.
    - `q_o`: An optional output queue containing expected PCIe output transactions.
    - `do_log`: A boolean flag indicating whether to log detailed information about the transactions.
- **Control Flow**:
    - Initialize empty lists `refs_i` and `refs_o` to store expected input and output transaction data.
    - Enter an infinite loop to continuously monitor PCIe transactions.
    - Wait for a rising edge on the clock signal `clk`.
    - Check if there is an expected input transaction (`q_i` is not None) and the PCIe input valid signal (`dut.pcie_v`) is asserted.
    - If `refs_i` is empty, pop a transaction from `q_i` and build expected input transaction data using [`build_pcie_tr_i`](#build_pcie_tr_i).
    - Compare the actual input data (`dut.pcie_d`) with the expected data (`refs_i`) and log the comparison if `do_log` is True.
    - Assert that the PCIe input flow control signal (`dut.pcie_f`) is not asserted and that the expected and actual input data match.
    - Check if the PCIe output valid and ready signals (`dut.o_v` and `dut.o_r`) are asserted and there is an expected output transaction (`q_o` is not None).
    - If `refs_o` is empty, pop a transaction from `q_o`, build expected output transaction data using [`build_pcie_tr_o`](#build_pcie_tr_o), and append it to `refs_o`.
    - Extract metadata from the actual output data (`dut.o_m0`) and compare it with the expected output data (`refs_o`).
    - Log the comparison of expected and actual output data if `do_log` is True.
    - Assert that all fields of the expected and actual output data match.
- **Output**: The function does not return any value; it performs assertions and logging to verify PCIe transactions.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_pcie_tr_i`](#build_pcie_tr_i)
    - [`firedancer/src/wiredancer/py/wd_cocotil.extr_meta`](#extr_meta)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_pcie_tr_o`](#build_pcie_tr_o)
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)


---
### build\_sha\_pre\_meta<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_sha_pre_meta}} -->
The function `build_sha_pre_meta` constructs a metadata integer by bit-shifting and combining several fields from a transaction dictionary.
- **Inputs**:
    - `tr`: A dictionary representing a transaction, containing keys 'src', 'tid', 'sig_h', 'sig_l', and 'pub'.
- **Control Flow**:
    - Initialize an integer `m` to 0.
    - Bitwise OR the `src` field of `tr` shifted by 0 bits into `m`.
    - Bitwise OR the `tid` field of `tr` shifted by 32 bits into `m`.
    - Bitwise OR the `sig_h` field of `tr` shifted by 96 bits into `m`.
    - Bitwise OR the `sig_l` field of `tr` shifted by 352 bits into `m`.
    - Bitwise OR the `pub` field of `tr` shifted by 608 bits into `m`.
    - Return the constructed integer `m`.
- **Output**: An integer `m` representing the combined metadata from the transaction fields.


---
### build\_sha\_pre\_o<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_sha_pre_o}} -->
The function `build_sha_pre_o` generates a list of tuples containing transaction metadata and SHA pre-processing blocks from a given transaction dictionary.
- **Inputs**:
    - `tr`: A dictionary representing a transaction, containing keys such as 'src', 'tid', 'sig_l', 'sig_h', 'pub', and 'sha_msg'.
- **Control Flow**:
    - The function calls [`gen_blocks_from_msg_str`](#gen_blocks_from_msg_str) with the 'sha_msg' from the transaction dictionary to generate SHA pre-processing blocks.
    - It iterates over the generated blocks, creating a tuple for each block that includes transaction metadata and block-specific information.
    - Each tuple contains the source, transaction ID, signature parts, public key, flags indicating the first and last block, the total number of blocks, and the current block.
    - The function returns a list of these tuples.
- **Output**: A list of tuples, each containing transaction metadata and a SHA pre-processing block.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.gen_blocks_from_msg_str`](#gen_blocks_from_msg_str)


---
### mon\_sha\_pre<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.mon_sha_pre}} -->
The `mon_sha_pre` function is an asynchronous coroutine that monitors and verifies SHA pre-processing outputs against expected values in a hardware simulation environment.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The device under test (DUT) object, used for logging and interaction with the simulation.
    - `dut`: The actual DUT instance being monitored.
    - `clk`: The clock signal used to synchronize the coroutine's operations.
    - `q_i`: An optional input queue for expected input transactions, defaulting to None.
    - `q_o`: An optional output queue for expected output transactions, defaulting to None.
    - `do_log`: A boolean flag indicating whether to log detailed information about the transactions, defaulting to False.
- **Control Flow**:
    - Initialize an empty list `q_bo` to store expected output transactions.
    - Enter an infinite loop to continuously monitor the DUT.
    - Wait for a rising edge on the clock signal `clk`.
    - Check if the output valid signal `dut.o_v` is asserted (i.e., equals '1').
    - If `q_o` is not None and `q_bo` is empty, pop the first transaction from `q_o`, record the current cycle time, and extend `q_bo` with the expected output transactions built from the popped transaction.
    - Extract the output metadata from the DUT using [`extr_meta`](#extr_meta) and compare it with the expected values from `q_bo`.
    - If `do_log` is True, log detailed information about the comparison of expected and actual values.
    - Assert that all extracted metadata values match the expected values, raising an error if any do not.
- **Output**: The function does not return any value; it operates as a coroutine to monitor and verify the DUT's behavior in real-time.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.get_cycle`](#get_cycle)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_sha_pre_o`](#build_sha_pre_o)
    - [`firedancer/src/wiredancer/py/wd_cocotil.extr_meta`](#extr_meta)


---
### build\_sha\_modq\_o<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_sha_modq_o}} -->
The function `build_sha_modq_o` extracts and returns specific fields from a transaction dictionary.
- **Inputs**:
    - `tr`: A dictionary representing a transaction, containing fields such as 'src', 'tid', 'sig_l', 'sig_h', 'pub', and 'sha_modq'.
- **Control Flow**:
    - The function directly accesses the specified keys in the input dictionary 'tr'.
    - It returns a tuple containing the values associated with the keys 'src', 'tid', 'sig_l', 'sig_h', 'pub', and 'sha_modq'.
- **Output**: A tuple containing the values of 'src', 'tid', 'sig_l', 'sig_h', 'pub', and 'sha_modq' from the input dictionary.


---
### build\_sha\_modq\_meta<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_sha_modq_meta}} -->
The function `build_sha_modq_meta` constructs a metadata integer by bit-shifting and combining several fields from a transaction dictionary.
- **Inputs**:
    - `tr`: A dictionary representing a transaction, containing keys 'src', 'tid', 'sig_h', 'sig_l', and 'pub'.
- **Control Flow**:
    - Initialize an integer `m` to 0.
    - Bitwise OR the value of `tr['src']` shifted by 0 bits into `m`.
    - Bitwise OR the value of `tr['tid']` shifted by 32 bits into `m`.
    - Bitwise OR the value of `tr['sig_h']` shifted by 96 bits into `m`.
    - Bitwise OR the value of `tr['sig_l']` shifted by 352 bits into `m`.
    - Bitwise OR the value of `tr['pub']` shifted by 608 bits into `m`.
    - Return the constructed integer `m`.
- **Output**: An integer `m` representing the combined metadata from the transaction dictionary.


---
### build\_sha\_modq\_meta\_i<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_sha_modq_meta_i}} -->
The function `build_sha_modq_meta_i` generates metadata tuples for each block of a SHA message, indicating the block's position and associated transaction data.
- **Inputs**:
    - `tr`: A dictionary containing transaction data, including the SHA message string ('sha_msg'), transaction ID ('tid'), and SHA modq metadata ('sha_modq_meta').
- **Control Flow**:
    - Generate blocks from the SHA message string using the [`gen_blocks_from_msg_str`](#gen_blocks_from_msg_str) function.
    - Iterate over each block index to create a tuple for each block.
    - For each block, determine if it is the first or last block, and include this information in the tuple.
    - Include the total number of blocks, transaction ID, SHA modq metadata, and the block data in the tuple.
    - Return a list of tuples, each representing metadata for a block.
- **Output**: A list of tuples, each containing metadata for a block of the SHA message, including flags for first and last block, total block count, transaction ID, SHA modq metadata, and the block data.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.gen_blocks_from_msg_str`](#gen_blocks_from_msg_str)


---
### mon\_sha\_modq\_meta<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.mon_sha_modq_meta}} -->
The `mon_sha_modq_meta` function is an asynchronous coroutine that monitors and verifies the SHA-512 modular Q metadata transactions in a digital circuit simulation.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The device under test (DUT) object, used for logging and interaction with the simulation.
    - `dut`: The actual DUT object representing the hardware module being tested.
    - `clk`: The clock signal used to synchronize the operations within the coroutine.
    - `q_i`: An optional input queue containing expected input transactions for verification.
    - `q_o`: An optional output queue containing expected output transactions for verification.
    - `do_log`: A boolean flag indicating whether to log detailed information during the verification process.
- **Control Flow**:
    - Initialize a counter `i_cnt` to zero and an empty list `q_bi` to store intermediate data.
    - Enter an infinite loop to continuously monitor the clock signal using `await RisingEdge(clk)`.
    - Assert that there are no gaps in input transactions by checking `i_cnt` and `dut.i_v`.
    - If both `dut.i_v` and `dut.i_r` are asserted, extract metadata from `dut.i_m` and update `i_cnt` based on the extracted flag `i_f`.
    - If `q_i` is not None, verify the input transaction against expected values from `q_i` and log the comparison if `do_log` is True.
    - If `dut.o_v` is asserted, extract metadata from `dut.o_m` and verify the output transaction against expected values from `q_o`, logging the comparison if `do_log` is True.
- **Output**: The function does not return any value; it performs verification and logging as side effects.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.extr_meta`](#extr_meta)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_sha_modq_meta_i`](#build_sha_modq_meta_i)
    - [`firedancer/src/wiredancer/py/wd_cocotil.get_cycle`](#get_cycle)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_sha_modq_o`](#build_sha_modq_o)


---
### mon\_ed25519\_sigverify\_dsdp\_mul<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.mon_ed25519_sigverify_dsdp_mul}} -->
The function `mon_ed25519_sigverify_dsdp_mul` is a coroutine that monitors and verifies Ed25519 signature verification operations by comparing expected and actual values from a digital unit test (DUT) in a simulation environment.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `dut`: The device under test (DUT) object representing the hardware module being tested.
    - `clk`: The clock signal used to synchronize the coroutine with the simulation.
    - `q_i`: An optional input queue containing expected input transactions for verification.
    - `q_o`: An optional output queue containing expected output transactions for verification.
    - `do_print`: A boolean flag indicating whether to print debug information during execution.
    - `self_test`: A boolean flag indicating whether to perform self-testing.
- **Control Flow**:
    - The function enters an infinite loop, yielding to the rising edge of the clock signal to synchronize with the simulation.
    - It checks if the input valid (`i_v`) and ready (`i_r`) signals of the DUT are both '1', indicating valid input data is available.
    - If `q_i` is not None, it retrieves and removes the expected transaction from `q_i` using the index `i_m` from the DUT.
    - It calls [`build_ed25519_sigverify_0_o`](#build_ed25519_sigverify_0_o) to generate expected values for signature verification and compares them with the actual values from the DUT.
    - If `do_print` is True, it prints the expected and actual values for debugging purposes.
    - It asserts that the expected and actual values match for various parameters like `i_Ax`, `i_Ay`, `i_Az`, `i_At`, `i_ApGx`, `i_ApGy`, `i_ApGz`, `i_ApGt`, `i_As`, and `i_Gs`.
    - It checks if the output valid (`o_v`) signal of the DUT is '1', indicating valid output data is available.
    - If `q_o` is not None, it retrieves and removes the expected output transaction from `q_o` using the index `o_m` from the DUT.
    - It compares the expected and actual output values for `o_Cx`, `o_Cy`, `o_Cz`, and `o_Ct` and asserts their equality.
    - It verifies the mathematical relationship `t = (x*y)/z` using modular arithmetic and asserts its correctness.
- **Output**: The function does not return any value; it performs assertions to verify the correctness of the DUT's behavior during the simulation.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_ed25519_sigverify_0_o`](#build_ed25519_sigverify_0_o)
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)


---
### build\_ed25519\_sigverify\_0\_o<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_ed25519_sigverify_0_o}} -->
The function `build_ed25519_sigverify_0_o` processes a transaction dictionary to perform an Ed25519 signature verification operation and returns a tuple containing transaction details and evaluated signature verification results.
- **Inputs**:
    - `tr`: A dictionary representing a transaction, containing keys such as 'pub', 'sig_l', 'sig_h', 'src', 'tid', and 'sha_modq'.
- **Control Flow**:
    - The function calls `sigverify.ksigverify_split0` with expressions derived from the transaction's public key, signature parts, and reference Ed25519 constants to perform a signature verification operation.
    - The result of the signature verification operation is a tuple of expressions, which are then evaluated to obtain their actual values.
    - The function returns a tuple containing the transaction's source, transaction ID, signature parts, public key, SHA-512 mod q value, and the evaluated signature verification results.
- **Output**: A tuple containing the transaction's source, transaction ID, signature parts, public key, SHA-512 mod q value, and the evaluated signature verification results.


---
### mon\_ed25519\_sigverify\_0<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.mon_ed25519_sigverify_0}} -->
The `mon_ed25519_sigverify_0` function monitors and verifies the output of an Ed25519 signature verification process in a hardware simulation environment.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The design under test (DUT) object, which is the device being simulated.
    - `dut`: The specific instance of the DUT being monitored.
    - `clk`: The clock signal used to synchronize the simulation.
    - `q_i`: An optional input queue for transactions, defaulting to None.
    - `q_o`: An optional output queue for transactions, defaulting to None.
    - `do_log`: A boolean flag indicating whether to log detailed information, defaulting to False.
- **Control Flow**:
    - The function enters an infinite loop, waiting for a rising edge of the clock signal using `await RisingEdge(clk)`.
    - It checks if the input signals `i_v` and `i_r` of the DUT are both '1', logging an informational message if true.
    - If the output signal `o_v` of the DUT is '1', it extracts metadata from the DUT's output using the [`extr_meta`](#extr_meta) function.
    - If `q_o` is not None, it retrieves and removes a transaction from `q_o` using the transaction ID `o_tid`.
    - The function logs the transaction details and calculates the expected output using [`build_ed25519_sigverify_0_o`](#build_ed25519_sigverify_0_o).
    - If `do_log` is true, it logs detailed comparisons between expected and actual output values.
    - The function asserts that all expected values match the actual output values from the DUT.
- **Output**: The function does not return any value; it performs logging and assertions to verify the correctness of the DUT's output.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.extr_meta`](#extr_meta)
    - [`firedancer/src/wiredancer/py/wd_cocotil.get_cycle`](#get_cycle)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_ed25519_sigverify_0_o`](#build_ed25519_sigverify_0_o)


---
### build\_ed25519\_sigverify\_1\_o<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.build_ed25519_sigverify_1_o}} -->
The function `build_ed25519_sigverify_1_o` constructs and returns a tuple of values related to the Ed25519 signature verification process, using a specific multiplication operation.
- **Inputs**:
    - `tr`: A dictionary containing transaction data, including fields like 'src', 'tid', 'sig_l', 'sig_h', 'pub', and 'sha_modq'.
    - `DSDP_WS`: An integer representing the workspace size for the Ed25519 DSDP multiplication, defaulting to 256.
- **Control Flow**:
    - The function first calls [`build_ed25519_sigverify_0_o`](#build_ed25519_sigverify_0_o) with the transaction data `tr` to obtain initial values for signature verification.
    - It constructs a tuple `A` using the values `i_Ax`, the lower 255 bits of `i_pub`, a constant 1, and `i_At`.
    - The function assigns `i_h` to `As` and `i_sig_h` to `Gs`.
    - It performs a DSDP multiplication using `ed25519_lib.ed25519_dsdp_mul` with `A`, `As`, `Gs`, and the workspace size `DSDP_WS`, storing the result in `Z`.
    - Finally, it returns a tuple containing specific fields from `tr` and elements from `Z`.
- **Output**: A tuple containing the source, transaction ID, lower signature, and results from the DSDP multiplication, along with `i_Rx` and `i_res`.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_ed25519_sigverify_0_o`](#build_ed25519_sigverify_0_o)
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)


---
### mon\_ed25519\_sigverify\_1<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.mon_ed25519_sigverify_1}} -->
The `mon_ed25519_sigverify_1` function monitors and verifies Ed25519 signature operations in a hardware simulation environment, logging and asserting the correctness of the operations.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The device under test (DUT) object for logging and interaction.
    - `dut`: The actual device under test, representing the hardware module being simulated.
    - `clk`: The clock signal used to synchronize operations.
    - `q_i`: An optional queue for input transactions, defaulting to None.
    - `q_o`: An optional queue for output transactions, defaulting to None.
    - `do_log`: A boolean flag indicating whether to log detailed information, defaulting to False.
    - `self_test`: A boolean flag indicating whether to perform self-testing, defaulting to False.
- **Control Flow**:
    - Initialize an empty list `q_self` and retrieve the `DSDP_WS` parameter from the DUT.
    - Enter an infinite loop, awaiting a rising edge of the clock signal `clk`.
    - Check if both `i_v` and `i_r` signals of the DUT are '1', indicating valid input data.
    - Log the input event if `self_test` is enabled, and extract various input signals from the DUT.
    - Perform Ed25519 DSDP multiplication using the extracted inputs and append the result to `q_self`.
    - Check if the `o_v` signal of the DUT is '1', indicating valid output data.
    - Extract output metadata and compare it with expected values from `q_o` if available.
    - Log the output event and assert that the extracted output matches the expected values.
- **Output**: The function does not return a value but logs information and performs assertions to verify the correctness of Ed25519 signature operations.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)
    - [`firedancer/src/wiredancer/py/wd_cocotil.extr_meta`](#extr_meta)
    - [`firedancer/src/wiredancer/py/wd_cocotil.get_cycle`](#get_cycle)
    - [`firedancer/src/wiredancer/py/wd_cocotil.build_ed25519_sigverify_1_o`](#build_ed25519_sigverify_1_o)


---
### mon\_ed25519\_sigverify\_2<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.mon_ed25519_sigverify_2}} -->
The `mon_ed25519_sigverify_2` function is an asynchronous coroutine that monitors the output of a digital unit under test (DUT) for Ed25519 signature verification results and logs or asserts the correctness of the results against expected values.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The design under test (DUT) object, used for logging and interaction.
    - `dut`: The specific DUT instance being monitored.
    - `clk`: The clock signal to synchronize the monitoring process.
    - `q_i`: An optional input queue for incoming transactions, default is None.
    - `q_o`: An optional output queue for outgoing transactions, default is None.
    - `do_log`: A boolean flag indicating whether to log detailed information, default is False.
    - `self_test`: A boolean flag indicating whether to perform self-testing, default is False.
- **Control Flow**:
    - The function enters an infinite loop, continuously awaiting a rising edge of the clock signal `clk`.
    - Upon detecting a rising edge, it checks if the DUT's output valid signal `o_v` is '1', indicating a valid output is available.
    - If `q_o` is not None, it retrieves the transaction from the output queue `q_o` using the transaction ID `o_tid` extracted from the DUT's output metadata `o_m`.
    - The function logs the transaction details and timestamps if `do_log` is True.
    - It asserts that the expected source, transaction ID, and result match the actual values extracted from the DUT's output metadata.
- **Output**: The function does not return any value; it performs logging and assertions to verify the correctness of the DUT's output.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.extr_meta`](#extr_meta)
    - [`firedancer/src/wiredancer/py/wd_cocotil.get_cycle`](#get_cycle)


---
### mon\_dma<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.mon_dma}} -->
The `mon_dma` function is an asynchronous coroutine that monitors and verifies DMA transactions by comparing expected and actual values of DMA address, control, and data signals.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The design under test (DUT) object, used for logging and interaction with the test environment.
    - `dut`: The device under test, representing the hardware module being tested.
    - `clk`: The clock signal used to synchronize the monitoring process.
    - `q_o`: An optional queue of expected transaction records to verify against the actual transactions.
    - `do_log`: A boolean flag indicating whether to log detailed information about the transactions.
- **Control Flow**:
    - The function enters an infinite loop, continuously monitoring the DMA signals.
    - It waits for a rising edge on the clock signal using `await RisingEdge(clk)`.
    - If both `dut.dma_v` and `dut.dma_r` are asserted (indicating a valid transaction), it logs the event if logging is enabled.
    - If `q_o` is not None, it pops the first transaction record from the queue to verify against the current transaction.
    - It extracts the actual DMA address, control, and data values from the DUT.
    - It calculates the expected values for DMA address, control, and data based on the transaction record.
    - If logging is enabled, it logs the comparison between expected and actual values.
    - It asserts that the expected and actual values for DMA address, control, and data are equal, raising an exception if they are not.
- **Output**: The function does not return any value; it performs assertions to verify the correctness of DMA transactions.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.bits`](#bits)


---
### model\_schl\_cpu<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.model_schl_cpu}} -->
The `model_schl_cpu` function simulates a CPU model that processes input hash data and generates output hash data based on certain conditions and computations.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The device under test (DUT) object for logging and interaction.
    - `dut`: The device under test (DUT) object representing the hardware model.
    - `clk`: The clock signal used to synchronize operations.
    - `do_log`: A boolean flag indicating whether to log information during execution.
- **Control Flow**:
    - Initialize constants D, W_HASH, W_T, W_IN_MEM, and MAX_INFLIGHT from the DUT properties.
    - Start a coroutine to randomly toggle the 'in_hash_ready' signal of the DUT.
    - Initialize empty lists 'ins' and 'outs' to store input data and output data respectively.
    - Set the 'out_hash_valid' signal of the DUT to 0.
    - Enter an infinite loop that waits for a rising edge of the clock signal.
    - Check if both 'in_hash_valid' and 'in_hash_ready' signals of the DUT are '1'.
    - If true, read 'in_hash_ref' and 'in_hash_data' from the DUT, log the input data, and append 'in_hash_data' to the 'ins' list.
    - If the 'ins' list contains three elements, perform a signature verification split using 'sigverify.ksigverify_split0' and append the result to the 'outs' list with a delay of D cycles.
    - Set the 'out_hash_valid' signal of the DUT to 0.
    - Iterate over the 'outs' list to check if any output is ready to be processed based on the current cycle count.
    - If an output is ready, remove it from the 'outs' list, log the output data, and set the 'out_hash_valid', 'out_hash_data', 'out_ref', and 'out_d_addr' signals of the DUT with the processed data.
    - Increment the output address index 'oa' and check if there are more outputs to process; if so, re-append the output to the 'outs' list with an updated cycle count.
    - Break the loop to wait for the next clock cycle.
- **Output**: The function does not return a value but modifies the DUT's output signals based on the processed input data.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.random_toggle`](#random_toggle)
    - [`firedancer/src/wiredancer/py/wd_cocotil.get_cycle`](#get_cycle)


---
### model\_dsdp<!-- {{#callable:firedancer/src/wiredancer/py/wd_cocotil.model_dsdp}} -->
The `model_dsdp` function simulates a digital signal processing operation using the Ed25519 algorithm, processing input signals and producing output signals based on a clock edge.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `ddut`: The device under test (DUT) for logging and debugging purposes.
    - `dut`: The actual device under test, representing the hardware model being simulated.
    - `clk`: The clock signal used to synchronize the simulation.
    - `do_log`: A boolean flag indicating whether to log debug information.
- **Control Flow**:
    - Initialize parameters N_TH, W_M, and W_S from the DUT's attributes.
    - Start a coroutine to randomly toggle the `i_r` signal of the DUT.
    - Enter an infinite loop, waiting for a rising edge of the clock signal.
    - Check if both `i_v` and `i_r` signals of the DUT are high, indicating valid input data.
    - Extract input data `i_m`, `A`, `As`, and `Gs` from the DUT.
    - Perform a multiplication operation using the `ed25519_dsdp_mul` function from the `ed25519_lib` library.
    - Append the result to the `outs` list with a calculated cycle delay.
    - Set the `o_v` signal of the DUT to 0, indicating no valid output initially.
    - Iterate over the `outs` list to check if any output is ready based on the current cycle count.
    - If an output is ready, remove it from the list and convert the results to binary values.
    - Set the DUT's output signals (`o_v`, `o_m`, `o_Cx`, `o_Cy`, `o_Cz`, `o_Ct`) with the processed data.
    - Break the loop to wait for the next clock cycle.
- **Output**: The function does not return a value but sets the output signals of the DUT based on processed input data.
- **Functions called**:
    - [`firedancer/src/wiredancer/py/wd_cocotil.random_toggle`](#random_toggle)
    - [`firedancer/src/wiredancer/py/wd_cocotil.get_cycle`](#get_cycle)


