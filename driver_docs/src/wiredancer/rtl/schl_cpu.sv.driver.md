# Purpose
The provided Verilog code implements a specialized processor architecture designed to schedule and execute the Solana SigVerify algorithm as part of the Firedancer consensus node, specifically targeting the Xilinx Virtex UltraScale+ (VU9P) FPGA. This implementation is a simplified N-thread RISC CPU architecture that utilizes a fixed 256-bit pipeline ALU to perform mathematical operations required by the SigVerify algorithm. The design is optimized for hardware-software co-design, allowing for a balance between hardware footprint, mathematical complexity, and runtime latency/throughput. The processor operates with a fixed instruction stream and assumes a fixed-duration (21 cycles) for ALU operations, which is crucial for maintaining a consistent pipeline flow and preventing stalls.

The architecture is non-traditional, employing a set of parallel state machines to manage instruction pipelines virtually, rather than using a fixed set of stages. This design choice allows for scalability in the number of threads based on the FPGA's physical limitations. The processor uses a virtual address scheme for instruction generation, with independent physical scratchpad memory spaces for storing temporary values. The code includes a detailed memory mapping scheme, with specific address ranges for input data, constant data, and scratch memory. The processor's pipeline consists of three stages: FETCH, EXEC, and BLOCK, with a focus on maximizing ALU utilization and minimizing stalls. The design also includes mechanisms for instruction pre-fetching and memory management, ensuring efficient execution of the SigVerify algorithm. The code is part of a larger system, with additional components like the ALU logic found in a separate file (`ed25519_sigverify_ecc.sv`) and a corresponding testbench for simulation.
# Modules

---
### schl
The `schl` module is a top-level Verilog module designed to handle hash input and output operations, interfacing with a CPU module for processing. It includes a FIFO buffer to manage input data flow and a counter to track input references.
- **Constants**:
    - `W_HASH`: This constant defines the width of the hash input and output, set to 256 bits.
- **Ports**:
    - `clk`: Clock input signal for synchronizing operations.
    - `rst`: Reset input signal to initialize or reset the module.
    - `i_hash`: 256-bit input hash data.
    - `i_valid`: Input signal indicating the validity of the input hash data.
    - `i_ready`: Output signal indicating the module is ready to accept new input data.
    - `o_hash`: 256-bit output hash data.
    - `o_valid`: Output signal indicating the validity of the output hash data.
    - `o_correct`: Output signal, currently always set to '0', indicating correctness of the output.
- **Logic And Control Flow**:
    - The module uses a FIFO buffer (`showahead_fifo`) to manage input data flow, ensuring that input data is ready for processing by the CPU module.
    - An `always_ff` block is used to increment a 16-bit reference counter (`ref_cnt`) on each clock cycle, which is reset when the `rst` signal is high.
    - The `shcl_cpu` instance (`cpu0`) processes the input hash data, using the reference counter and input validity signals to manage data flow and produce output hash data.
    - The `i_ready` signal is assigned based on the `full` signal from the FIFO, indicating when the module can accept new input data.


---
### shcl\_cpu
The `shcl_cpu` module is a simplified N-thread RISC CPU architecture designed to schedule the runtime of the Solana SigVerify algorithm. It manages multiple logical threads using a fixed 256-bit pipeline ALU and supports parallel state machines for instruction execution.
- **Constants**:
    - `MUL_T`: A constant parameter set to 32'h007F_CCC2, used for multiplication operations.
    - `MUL_D`: A constant parameter set to 15, used to define the depth of the multiplication pipeline.
    - `W_HASH`: A constant parameter set to 256, representing the width of hash data.
    - `W_IN_MEM`: A constant parameter set to 6, representing the width of input memory addresses.
    - `W_T`: A constant parameter set to 16, representing the width of the reference tag.
    - `MAX_INFLIGHT`: A constant parameter calculated as (MUL_D+1)+6, representing the maximum number of inflight operations.
    - `NUM_PRIMS`: A local parameter set to 12, representing the number of primitives (11 math operations and 1 ternary operation).
    - `W_PRIMS`: A local parameter calculated as $clog2(NUM_PRIMS), representing the width of the primitives.
    - `NUM_TAGS`: A local parameter set to 32, representing the number of transaction handles or tags.
    - `W_TAGS`: A local parameter calculated as $clog2(NUM_TAGS), representing the width of the tags.
    - `NUM_OPS`: A local parameter set to 16, representing the maximum number of supported operations.
    - `W_OPS`: A local parameter calculated as $clog2(NUM_OPS), representing the width of the operations.
    - `SZ_MEM`: A local parameter set to 1024, representing the size of the memory.
    - `W_MEM`: A local parameter calculated as $clog2(SZ_MEM), representing the width of the memory addresses.
    - `NUM_CONSTS`: A local parameter set to 12, representing the number of constants in the constant memory.
    - `CONST_MEM`: A parameter array containing 12 256-bit constants used for various operations.
    - `ROM_WIDTH`: A local parameter calculated as 1 + W_OPS + 4*W_IN_MEM, representing the width of the instruction ROM.
    - `ROM_DEPTH`: A local parameter set to 2048, representing the depth of the instruction ROM.
    - `W_ROM_DEPTH`: A local parameter calculated as $clog2(ROM_DEPTH), representing the width of the ROM depth.
    - `OP_JMP`: A local parameter set to 4'hF, representing the jump operation code.
    - `MEM_CNT`: A local parameter set to 2, representing the number of identical memories for parallel reads.
    - `SCRATCH_TAG_OFFSET`: A parameter array defining the physical offset addresses for each tag's scratch memory.
- **Ports**:
    - `clk`: Clock input signal for the module.
    - `rst`: Reset input signal for the module.
    - `in_hash_data`: Input port for hash data with a width of W_HASH.
    - `in_hash_valid`: Input port indicating the validity of the hash data.
    - `in_hash_ref`: Input port for the reference tag with a width of W_T.
    - `in_hash_ready`: Output port indicating readiness to accept new hash data.
    - `out_hash_data`: Output port for hash data with a width of W_HASH.
    - `out_ref`: Output port for the reference tag with a width of W_T.
    - `out_d_addr`: Output port for the data address with a width of W_IN_MEM.
    - `out_hash_valid`: Output port indicating the validity of the output hash data.
- **Logic And Control Flow**:
    - The module uses a parameterized instruction ROM to fetch and execute instructions for multiple tags in parallel.
    - It employs a state machine for each tag to manage the instruction fetch, execution, and completion stages.
    - The module supports a fixed 256-bit pipeline ALU for executing mathematical operations, with a fixed duration of 21 cycles per instruction.
    - Memory operations are managed through dual-port RAMs for parallel reads and writes, with separate memory spaces for each tag.
    - The module includes logic to handle instruction pre-fetching and memory address translation for virtual to physical address mapping.
    - It uses combinatorial logic to determine the next instruction to fetch and execute, ensuring fairness across tags.
    - The module integrates an ALU for executing operations and manages the input and output connectivity for the ALU.
    - State management is handled through a set of parallel state machines, each representing a logical thread or tag.


