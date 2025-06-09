# Purpose
The provided Verilog code defines two modules, `showahead_fifo` and `showahead_fifo_nx1`, which implement FIFO (First-In-First-Out) memory structures with specific features. The `showahead_fifo` module is a parameterized FIFO that supports synchronous read and write operations, with configurable data width and depth. It includes features such as programmable full and empty thresholds, and it uses the Xilinx Parameterized Macro (XPM) for FIFO implementation, which allows for efficient resource utilization and advanced features like error correction. The module provides signals to indicate the status of the FIFO, such as full, empty, and data count, and it supports asynchronous clear functionality.

The `showahead_fifo_nx1` module extends the functionality of the `showahead_fifo` by creating an array of `N` FIFOs, each with a width of 1 bit. This module is designed to handle multiple data streams simultaneously, allowing for parallel data processing. It includes logic to manage read and write operations across the array of FIFOs, with the ability to read all data streams at once or sequentially. The module uses a generate block to instantiate multiple `showahead_fifo` instances, each handling a separate data stream, and it manages the read index and control signals to coordinate operations across the FIFOs. This design is suitable for applications requiring high throughput and parallel data handling.
# Modules

---
### showahead\_fifo
The `showahead_fifo` module is a parameterized FIFO (First-In-First-Out) buffer that supports synchronous read and write operations with separate clocks. It uses an XPM_FIFO instantiation to manage data flow and provides signals for full, empty, and data count status.
- **Constants**:
    - `WIDTH`: Defines the width of the data bus for both read and write operations, defaulting to 32 bits.
    - `DEPTH`: Specifies the depth of the FIFO, defaulting to 32 entries.
    - `D_L`: Calculates the number of bits required to address the depth of the FIFO using the logarithm base 2 of DEPTH.
    - `FULL_THRESH`: Sets the threshold for the FIFO to be considered full, defaulting to DEPTH minus 6.
- **Ports**:
    - `wr_clk`: Input clock signal for write operations.
    - `wr_req`: Input signal to request a write operation.
    - `wr_data`: Input data bus for writing data into the FIFO.
    - `wr_full`: Output signal indicating the FIFO is full.
    - `wr_full_b`: Output signal indicating the FIFO is not full (complement of wr_full).
    - `wr_count`: Output bus indicating the number of words written into the FIFO.
    - `rd_clk`: Input clock signal for read operations.
    - `rd_req`: Input signal to request a read operation.
    - `rd_data`: Output data bus for reading data from the FIFO.
    - `rd_empty`: Output signal indicating the FIFO is empty.
    - `rd_not_empty`: Output signal indicating the FIFO is not empty (complement of rd_empty).
    - `rd_count`: Output bus indicating the number of words read from the FIFO.
    - `aclr`: Input signal for asynchronous clear, resetting the FIFO.
- **Logic And Control Flow**:
    - The module assigns `wr_full_b` as the complement of `wr_full`, indicating when the FIFO is not full.
    - Similarly, `rd_not_empty` is assigned as the complement of `rd_empty`, indicating when the FIFO is not empty.
    - The module instantiates an `xpm_fifo_sync` component, which is a Xilinx Parameterized Macro for synchronous FIFO configurations, with various parameters set for FIFO behavior.
    - The `xpm_fifo_sync` instance connects the input and output ports to manage data flow, including handling of full, empty, and data count signals.


---
### showahead\_fifo\_nx1
The `showahead_fifo_nx1` module is a parameterized FIFO (First-In-First-Out) buffer that supports multiple data widths and depths, allowing for efficient data storage and retrieval. It utilizes a generate block to instantiate multiple `showahead_fifo` modules, each handling a portion of the data, and manages read and write operations with control signals for full and empty states.
- **Constants**:
    - `N`: The number of parallel FIFO instances, defaulting to 8.
    - `N_L`: The bit width required to index the number of FIFO instances, calculated as $clog2(N).
    - `WIDTH`: The width of the data in each FIFO instance, defaulting to 1.
    - `DEPTH`: The depth of each FIFO instance, defaulting to 512.
    - `D_L`: The bit width required to index the depth of the FIFO, calculated as $clog2(DEPTH).
    - `FULL_THRESH`: The threshold for considering the FIFO full, set to DEPTH-6.
- **Ports**:
    - `wr_clk`: Clock signal for write operations.
    - `wr_req`: Write request signal.
    - `wr_data`: Data input for write operations, with a width of N x WIDTH.
    - `wr_full`: Output signal indicating if the FIFO is full.
    - `wr_full_b`: Output signal indicating if the FIFO is not full.
    - `wr_count`: Output signal indicating the number of words written into the FIFO.
    - `rd_clk`: Clock signal for read operations.
    - `rd_req`: Read request signal.
    - `rd_all`: Signal to read all data from the FIFO.
    - `rd_data`: Data output for read operations, with a width of WIDTH.
    - `rd_data_all`: Data output for reading all data, with a width of N x WIDTH.
    - `rd_empty`: Output signal indicating if the FIFO is empty.
    - `rd_not_empty`: Output signal indicating if the FIFO is not empty.
    - `rd_count`: Output signal indicating the number of words read from the FIFO.
    - `aclr`: Asynchronous clear signal to reset the FIFO.
- **Logic And Control Flow**:
    - The module uses a generate block to instantiate N instances of the `showahead_fifo` module, each handling a portion of the data.
    - The `always_ff` block updates the read index `i` based on the read request and the `rd_all` signal, resetting it if `aclr` is asserted.
    - The `assign` statements manage the full and empty status signals, as well as the data outputs, based on the internal logic arrays `full`, `out_vs`, and `out_ds`.


