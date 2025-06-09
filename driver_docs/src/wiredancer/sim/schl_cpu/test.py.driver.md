# Purpose
This Python file is a testbench script designed for use with the Cocotb framework, which is a coroutine-based co-simulation library for testing digital designs. The script is specifically tailored to test a digital design that involves cryptographic operations, likely related to the Ed25519 elliptic curve, as indicated by the imports from `ref_ed25519` and `ed25519_lib`. The script includes several utility functions for bit manipulation and memory address calculations, which are used to simulate and verify the behavior of the digital design under test. The core components of the script include the `MathMonitor` and `OutMonitor` classes, which are responsible for monitoring and verifying the internal state and outputs of the design, respectively. The `MathMonitor` class handles the setup and checking of memory operations, while the `OutMonitor` class tracks the completion of the test and logs the results.

The script defines a Cocotb test, [`run_test`](#run_test), which orchestrates the simulation by initializing the clock, resetting the design, and sending random input data to the design under test. The testbench uses the [`send_rand_input`](#send_rand_input) coroutine to generate and send input data, while the monitors ensure that the design's outputs are correct and that the internal operations are performed as expected. The testbench is designed to handle multiple input sets and verify the results against expected values, making it a comprehensive tool for validating the functionality of the digital design. The use of Cocotb allows for a high level of abstraction and flexibility in testing, enabling the integration of Python's rich ecosystem for test automation and data analysis.
# Imports and Dependencies

---
- `cocotb`
- `os`
- `copy`
- `sys`
- `struct`
- `hashlib`
- `random`
- `cocotb.clock.Clock`
- `cocotb.triggers.Timer`
- `cocotb.triggers.RisingEdge`
- `cocotb.triggers.ReadOnly`
- `cocotb.regression.TestFactory`
- `cocotb.binary.BinaryValue`
- `ref_ed25519`
- `ref_ed25519.point_decompress`
- `ed25519_lib.Expr`
- `ref_ed25519.p`


# Global Variables

---
### sent\_in
- **Type**: `list`
- **Description**: The `sent_in` variable is a global list that is initially empty. It is used to store tuples of input values that are sent to the device under test (DUT) during the execution of the test.
- **Use**: This variable is used to keep track of the input values that have been sent to the DUT for verification purposes.


# Classes

---
### MathMonitor<!-- {{#class:firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor}} -->
- **Members**:
    - `dut`: Reference to the device under test (DUT) object.
    - `total_tags`: Total number of tags available in the DUT's CPU.
    - `mem`: Dictionary to store memory addresses and their values.
    - `verbose`: Flag to control the verbosity of logging output.
- **Description**: The MathMonitor class is designed to monitor and manage memory operations for a device under test (DUT) in a simulation environment. It initializes memory with constant values, checks the correctness of operations by comparing expected and observed results, and logs memory read and write operations. The class also includes an asynchronous run method that continuously processes input data and verifies computation results against expected outcomes, ensuring the DUT's operations are performed correctly.
- **Methods**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.__init__`](#MathMonitor__init__)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.check`](#MathMonitorcheck)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.setIn`](#MathMonitorsetIn)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.setMem`](#MathMonitorsetMem)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getPhyAddr`](#MathMonitorgetPhyAddr)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getMem`](#MathMonitorgetMem)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.run`](#MathMonitorrun)

**Methods**

---
#### MathMonitor\.\_\_init\_\_<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.__init__}} -->
The `__init__` method initializes a `MathMonitor` object by setting up its attributes and preloading memory with constant values.
- **Inputs**:
    - `dut`: A device under test (DUT) object that provides access to the hardware simulation environment.
- **Control Flow**:
    - Assigns the provided `dut` to the instance variable `self.dut`.
    - Retrieves the number of tags from `dut.cpu0.NUM_TAGS` and assigns it to `self.total_tags`.
    - Initializes an empty dictionary `self.mem` to store memory values.
    - Sets the `self.verbose` flag to `True` for logging purposes.
    - Fills the `self.mem` dictionary with zero values for addresses ranging from 0 to 0x3FE.
    - Preloads the first 12 memory addresses starting from 0x04 with constant values obtained from the [`get_const`](#get_const) function.
- **Output**: This method does not return any value; it initializes the state of the `MathMonitor` instance.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.setMem`](#MathMonitorsetMem)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.get_const`](#get_const)
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor`](#MathMonitor)  (Base Class)


---
#### MathMonitor\.check<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.check}} -->
The `check` method verifies if the expected value matches the observed value and logs a failure message if they do not match.
- **Inputs**:
    - `tag`: An identifier used for logging purposes to indicate the context or source of the check.
    - `errstr`: A string describing the error or context of the check, used in logging.
    - `expected`: The expected integer value that the observed value is compared against.
    - `observed`: The actual integer value that is being checked against the expected value.
- **Control Flow**:
    - Convert both `expected` and `observed` to integers and compare them.
    - If they are equal, the function returns immediately, indicating success.
    - If they are not equal, log a failure message with the tag, error string, expected, and observed values.
    - Call the [`FAIL`](#FAIL) function to assert failure.
- **Output**: The method does not return any value; it either logs a failure and asserts or returns silently on success.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.FAIL`](#FAIL)
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor`](#MathMonitor)  (Base Class)


---
#### MathMonitor\.setIn<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.setIn}} -->
The `setIn` method writes a value to a specific memory address calculated from a tag and address, and logs the operation if verbose mode is enabled.
- **Inputs**:
    - `tag`: An integer representing the tag used to calculate the physical memory address.
    - `addr`: An integer representing the address used to calculate the physical memory address.
    - `val`: The value to be written to the calculated memory address.
- **Control Flow**:
    - Calculate the physical memory address using the [`getPhyAddr`](#MathMonitorgetPhyAddr) method with the provided `tag` and `addr`.
    - Assign the provided `val` to the calculated memory address in the `mem` dictionary.
    - If `verbose` is set to `True`, log the operation using the `dut._log.info` method.
- **Output**: The method does not return any value; it performs a side effect by modifying the `mem` dictionary and potentially logging the operation.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getPhyAddr`](#MathMonitorgetPhyAddr)
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor`](#MathMonitor)  (Base Class)


---
#### MathMonitor\.setMem<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.setMem}} -->
The `setMem` method writes a given value to a specific memory address calculated from a tag and address, and logs the operation if verbose mode is enabled.
- **Inputs**:
    - `tag`: An integer representing a tag used to calculate the physical memory address.
    - `addr`: An integer representing the address used to calculate the physical memory address.
    - `val`: The value to be written to the calculated memory address, which is converted to an integer.
- **Control Flow**:
    - Calculate the physical memory address using the [`getPhyAddr`](#MathMonitorgetPhyAddr) method with the provided `tag` and `addr`.
    - Convert the `val` to an integer and store it in the `mem` dictionary at the calculated address.
    - If `verbose` is set to `True`, log the memory write operation with details including the tag, address, and value.
- **Output**: The method does not return any value; it performs a side effect by modifying the `mem` dictionary and potentially logging information.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getPhyAddr`](#MathMonitorgetPhyAddr)
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor`](#MathMonitor)  (Base Class)


---
#### MathMonitor\.getPhyAddr<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getPhyAddr}} -->
The `getPhyAddr` method calculates a physical memory address based on a given tag and address.
- **Inputs**:
    - `tag`: An integer representing the tag used in the address calculation.
    - `addr`: An integer representing the address offset to be used in the calculation.
- **Control Flow**:
    - Checks if the address is 0x00 and returns the tag plus 0x000 if true.
    - Checks if the address is 0x01 and returns the tag plus 0x020 if true.
    - Checks if the address is 0x02 and returns the tag plus 0x040 if true.
    - Checks if the address is 0x03 and returns the tag plus 0x060 if true.
    - Checks if the address is between 0x04 and 0x23 inclusive, and returns 0x080 plus the address minus 0x04 if true.
    - For any other address, returns 0x0A0 plus the result of `scratch_offset(tag)` plus the address minus 0x24.
- **Output**: Returns an integer representing the calculated physical memory address.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.scratch_offset`](#scratch_offset)
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor`](#MathMonitor)  (Base Class)


---
#### MathMonitor\.getMem<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getMem}} -->
The `getMem` method retrieves a value from a memory address calculated based on a given tag and address, and logs the operation if verbose mode is enabled.
- **Inputs**:
    - `tag`: An integer representing the tag used to calculate the physical memory address.
    - `addr`: An integer representing the address used to calculate the physical memory address.
- **Control Flow**:
    - Calculate the physical memory address by calling [`getPhyAddr`](#MathMonitorgetPhyAddr) with the provided `tag` and `addr`.
    - Retrieve the value stored at the calculated memory address from the `mem` dictionary.
    - If `verbose` is set to `True`, log the read operation with details including the tag, address, and retrieved value.
    - Return the retrieved value.
- **Output**: The method returns the value stored at the calculated memory address.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getPhyAddr`](#MathMonitorgetPhyAddr)
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor`](#MathMonitor)  (Base Class)


---
#### MathMonitor\.run<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.run}} -->
The `run` method in the `MathMonitor` class continuously monitors and processes CPU states, performing memory operations and evaluations based on CPU instructions and states.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**: None
- **Control Flow**:
    - Initialize variables and lists to store instruction data, addresses, values, expected results, and result check flags for each tag.
    - Enter an infinite loop that waits for a rising edge of the clock signal from the DUT (Device Under Test).
    - Iterate over each tag, checking the CPU state and performing operations based on the current state and conditions.
    - If the CPU state is 1 and certain conditions are met, insert input data into memory and update the `init_vals` and `next_tag` counters.
    - If the CPU state is 3, retrieve and calculate expected results based on the current instruction and memory values, logging the expected results if verbose mode is enabled.
    - If the CPU state is 5 and certain conditions are met, check the results against expected values, update memory, and mark the result as checked.
- **Output**: The method does not return any value; it performs operations and updates internal state and memory based on CPU instructions and states.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.setIn`](#MathMonitorsetIn)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.getMemAAddr`](#getMemAAddr)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.getMemBAddr`](#getMemBAddr)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.getMemTAddr`](#getMemTAddr)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.getMemOAddr`](#getMemOAddr)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getMem`](#MathMonitorgetMem)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.evalOp`](#evalOp)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.getOP`](#getOP)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.check`](#MathMonitorcheck)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.getPhyAddr`](#MathMonitorgetPhyAddr)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.setMem`](#MathMonitorsetMem)
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor`](#MathMonitor)  (Base Class)



---
### OutMonitor<!-- {{#class:firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor}} -->
- **Members**:
    - `dut`: The device under test (DUT) that the monitor interacts with.
    - `done`: A boolean flag indicating whether the monitoring process is complete.
    - `in_vals`: A list to store input values received from the DUT.
    - `out_vals`: A list to store output values received from the DUT.
    - `expected`: A list to store expected output values for comparison.
    - `inout_match`: A dictionary to map input values to their corresponding output values.
- **Description**: The OutMonitor class is designed to monitor the output of a device under test (DUT) in a hardware simulation environment. It tracks input and output values, logs the results, and determines when the monitoring process is complete. The class uses asynchronous methods to wait for specific conditions on the DUT's clock signal, ensuring that it captures the correct timing of input and output events. The class also maintains a mapping of input to output values and logs detailed information about the timing and results of the monitored operations.
- **Methods**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor.__init__`](#OutMonitor__init__)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor.is_done`](#OutMonitoris_done)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor.run`](#OutMonitorrun)

**Methods**

---
#### OutMonitor\.\_\_init\_\_<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor.__init__}} -->
The `__init__` method initializes an instance of the `OutMonitor` class by setting up the device under test (DUT) and a completion flag.
- **Inputs**:
    - `dut`: The device under test (DUT) that the `OutMonitor` instance will monitor.
- **Control Flow**:
    - Assigns the provided `dut` argument to the instance variable `self.dut`.
    - Initializes the `self.done` flag to `False`, indicating that the monitoring process is not yet complete.
- **Output**: There is no return value as this is a constructor method for initializing an instance of the `OutMonitor` class.
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor`](#OutMonitor)  (Base Class)


---
#### OutMonitor\.is\_done<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor.is_done}} -->
The `is_done` method asynchronously waits for the `done` attribute of the `OutMonitor` class to become `True`, indicating the completion of a process.
- **Inputs**: None
- **Control Flow**:
    - The method enters a while loop that continues as long as the `done` attribute is `False`.
    - Within the loop, it awaits a `RisingEdge` event on the `dut.clk`, effectively pausing execution until the clock signal rises.
- **Output**: The method does not return any value; it simply exits when the `done` attribute becomes `True`.
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor`](#OutMonitor)  (Base Class)


---
#### OutMonitor\.run<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor.run}} -->
The `run` method in the `OutMonitor` class asynchronously monitors input and output signals, logging results and timing information until a specified number of outputs are collected.
- **Decorators**: `@cocotb.coroutine`
- **Inputs**:
    - `self`: The instance of the `OutMonitor` class.
    - `total`: An integer specifying the total number of input sets to process, defaulting to 3.
- **Control Flow**:
    - Initialize variables `tic`, `start`, `in_vals`, `out_vals`, `expected`, `inout_match`, and `i_cnt`.
    - Enter an infinite loop that waits for a rising edge on the `dut.clk` signal.
    - Increment the `tic` counter on each clock cycle.
    - Check if `i_valid` is high; if so, capture the input hash value and append it to `in_vals` and `start` if `i_cnt` is 0.
    - Increment `i_cnt` and reset it to 0 after reaching 2.
    - Check if `o_valid` is high; if so, capture the output hash value, log the result, and calculate elapsed time.
    - Break the loop when the number of collected outputs reaches `total * 8`.
    - Set `self.done` to `True` to indicate completion.
- **Output**: The method does not return a value but updates the `in_vals`, `out_vals`, and `done` attributes of the `OutMonitor` instance.
- **See also**: [`firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor`](#OutMonitor)  (Base Class)



# Functions

---
### FAIL<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.FAIL}} -->
The FAIL function is a simple assertion that always fails by raising an AssertionError.
- **Inputs**: None
- **Control Flow**:
    - The function contains a single statement, which is an assertion that evaluates to False.
    - Since the assertion is always False, the function will raise an AssertionError whenever it is called.
- **Output**: The function does not return any value; instead, it raises an AssertionError.


---
### clamp<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.clamp}} -->
The `clamp` function ensures that a given value is constrained within a 256-bit range by applying a bitwise AND operation with a 256-bit mask.
- **Inputs**:
    - `val`: The input value to be clamped, which is expected to be convertible to an integer.
- **Control Flow**:
    - Convert the input `val` to an integer.
    - Apply a bitwise AND operation between the integer value and a 256-bit mask, which is `(1<<256)-1`.
    - Return the result of the bitwise operation, effectively clamping the value to a 256-bit range.
- **Output**: An integer that is the result of clamping the input value to a 256-bit range.


---
### getTern<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.getTern}} -->
The `getTern` function extracts the top 4 bits of a 32-bit integer by right-shifting the input value by 28 bits.
- **Inputs**:
    - `val`: An integer value from which the top 4 bits are to be extracted.
- **Control Flow**:
    - The function takes an integer input `val`.
    - It performs a right bitwise shift operation on `val` by 28 bits.
    - The result of the shift operation is converted to an integer and returned.
- **Output**: An integer representing the top 4 bits of the input value after right-shifting by 28 bits.


---
### getOP<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.getOP}} -->
The `getOP` function extracts a 4-bit operation code from a 32-bit integer by right-shifting the integer by 24 bits and applying a bitwise AND with 0xF.
- **Inputs**:
    - `val`: A 32-bit integer from which the operation code is to be extracted.
- **Control Flow**:
    - The function takes a 32-bit integer input `val`.
    - It right-shifts `val` by 24 bits to isolate the bits that represent the operation code.
    - It applies a bitwise AND operation with 0xF to extract the 4 least significant bits of the shifted value.
    - The result is converted to an integer and returned.
- **Output**: An integer representing the 4-bit operation code extracted from the input.


---
### getMemAAddr<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.getMemAAddr}} -->
The `getMemAAddr` function extracts a 6-bit memory address from a given integer by right-shifting the integer by 18 bits and applying a bitwise AND operation with 0x3F.
- **Inputs**:
    - `val`: An integer value from which a 6-bit memory address is to be extracted.
- **Control Flow**:
    - The function takes an integer input `val`.
    - It right-shifts `val` by 18 bits to isolate the relevant bits for the memory address.
    - It applies a bitwise AND operation with 0x3F to extract the 6-bit memory address.
    - The resulting integer is returned as the memory address.
- **Output**: The function returns an integer representing a 6-bit memory address extracted from the input value.


---
### getMemBAddr<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.getMemBAddr}} -->
The `getMemBAddr` function extracts and returns a 6-bit memory address from a given integer by right-shifting the integer by 12 bits and applying a bitwise AND with 0x3F.
- **Inputs**:
    - `val`: An integer from which a 6-bit memory address is to be extracted.
- **Control Flow**:
    - The function takes an integer input `val`.
    - It right-shifts `val` by 12 bits to discard the lower 12 bits.
    - It applies a bitwise AND operation with 0x3F to extract the next 6 bits.
    - The result of the bitwise operation is converted to an integer and returned.
- **Output**: An integer representing the 6-bit memory address extracted from the input value.


---
### getMemTAddr<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.getMemTAddr}} -->
The `getMemTAddr` function extracts a 6-bit memory address from a given integer by right-shifting the integer by 6 bits and applying a bitwise AND operation with 0x3F.
- **Inputs**:
    - `val`: An integer from which a 6-bit memory address is to be extracted.
- **Control Flow**:
    - The function takes an integer input `val`.
    - It right-shifts `val` by 6 bits to discard the lower 6 bits.
    - It applies a bitwise AND operation with 0x3F to extract the next 6 bits as the memory address.
    - The result is converted to an integer and returned.
- **Output**: An integer representing the extracted 6-bit memory address.


---
### getMemOAddr<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.getMemOAddr}} -->
The `getMemOAddr` function extracts the memory output address from a given integer value by applying a bitwise AND operation with 0x3F.
- **Inputs**:
    - `val`: An integer value from which the memory output address is to be extracted.
- **Control Flow**:
    - The function takes an integer input `val`.
    - It performs a bitwise AND operation between `val` and 0x3F.
    - The result of the bitwise operation is converted to an integer and returned.
- **Output**: An integer representing the memory output address extracted from the input value.


---
### scratch\_offset<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.scratch_offset}} -->
The `scratch_offset` function returns a specific offset value from a predefined list based on the provided tag index.
- **Inputs**:
    - `tag`: An integer index used to access a specific offset value from the predefined list.
- **Control Flow**:
    - A list of predefined offset values is initialized.
    - The function returns the offset value at the index specified by the input `tag`.
- **Output**: The function returns an integer representing the offset value corresponding to the input `tag` from the predefined list.


---
### get\_const<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.get_const}} -->
The `get_const` function retrieves a constant value from a predefined list based on the provided index.
- **Inputs**:
    - `addr`: An integer index used to access a specific constant from the predefined list.
- **Control Flow**:
    - A list of constant hexadecimal values is defined within the function.
    - The function returns the constant value at the index specified by the input `addr`.
- **Output**: The function returns a constant value from the list corresponding to the input index `addr`.


---
### evalOp<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.evalOp}} -->
The `evalOp` function performs a specified operation on two input values, `valA` and `valB`, and optionally a third value `valT`, based on the operation code `op`, and returns the result after clamping it to a 256-bit integer.
- **Inputs**:
    - `op`: An integer representing the operation code to be performed on the input values.
    - `valA`: The first integer value to be used in the operation.
    - `valB`: The second integer value to be used in the operation.
    - `valT`: An optional integer value used in certain operations, specifically when `op` is 11.
- **Control Flow**:
    - Check if `op` is 0, perform bitwise AND on `valA` and `valB`, and return the clamped result.
    - Check if `op` is 1, compare `valA` and `valB` for equality, and return the clamped result.
    - Check if `op` is 2, compare `valA` and `valB` for inequality, and return the clamped result.
    - Check if `op` is 3, check if `valA` is greater than or equal to `valB`, and return the clamped result.
    - Check if `op` is 4, left shift `valA` by 1, and return the clamped result.
    - Check if `op` is 5, right shift `valA` by 255, perform bitwise AND with 0x1, and return the clamped result.
    - Check if `op` is 6, add `valA` and `valB`, and return the clamped result.
    - Check if `op` is 7, subtract `valB` from `valA`, and return the clamped result.
    - Check if `op` is 8, add `valA` and `valB`, take modulo with `ref_ed25519.p`, and return the clamped result.
    - Check if `op` is 9, subtract `valB` from `valA`, take modulo with `ref_ed25519.p`, and return the clamped result.
    - Check if `op` is 10, multiply `valA` and `valB`, take modulo with `ref_ed25519.p`, and return the clamped result.
    - Check if `op` is 11, return `valA` if `valT` is true, otherwise return `valB`.
    - Check if `op` is 12, return 0.
    - If none of the above conditions are met, return 0.
- **Output**: The function returns an integer result of the operation specified by `op`, clamped to a 256-bit integer.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.clamp`](#clamp)


---
### send\_rand\_input<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.send_rand_input}} -->
The `send_rand_input` function asynchronously sends a sequence of predefined input values to a device under test (DUT) when it is ready, and appends these values to a global list.
- **Decorators**: `@cocotb.test`
- **Inputs**:
    - `dut`: The device under test (DUT) to which the input values are sent.
    - `i`: An optional integer index, defaulting to 0, used to track the number of inputs sent.
- **Control Flow**:
    - Import the constant `p` from the `ref_ed25519` module.
    - Define a list `in_tmp` with three predefined hexadecimal values.
    - Assign the first three values of `in_tmp` to a tuple `in_vals`.
    - Initialize a variable `total` to 3 and reset `i` to 0.
    - Enter a while loop that runs while `i` is less than `total`.
    - Check if `dut.i_ready` is 1; if true, set `dut.i_hash.value` to `in_vals[i]` and `dut.i_valid.value` to 1, then increment `i`.
    - If `dut.i_ready` is not 1, set `dut.i_hash.value` and `dut.i_valid.value` to 0.
    - Await a rising edge on `dut.clk`.
    - After the loop, set `dut.i_hash.value` and `dut.i_valid.value` to 0.
    - Append `in_vals` to the global list `sent_in`.
- **Output**: The function does not return a value, but it modifies the DUT's input signals and appends the sent input values to the global list `sent_in`.


---
### run\_test<!-- {{#callable:firedancer/src/wiredancer/sim/schl_cpu/test.run_test}} -->
The `run_test` function is an asynchronous test function that initializes and runs a simulation of a digital circuit using cocotb, sending random inputs and monitoring outputs.
- **Decorators**: `@cocotb.test`
- **Inputs**:
    - `dut`: The device under test (DUT) object representing the digital circuit to be simulated.
- **Control Flow**:
    - Initialize counters `num_sent` and `num_inputs` to 0 and 64, respectively.
    - Create instances of [`OutMonitor`](#OutMonitor) and [`MathMonitor`](#MathMonitor) for monitoring outputs and mathematical operations.
    - Start the clock for the DUT with a period of 4000 time units.
    - Start the [`OutMonitor`](#OutMonitor) and [`MathMonitor`](#MathMonitor) to run concurrently with the test.
    - Set initial values of `i_hash` and `i_valid` to 0 and reset the DUT by setting `rst` to 1 and then back to 0 after a few clock cycles.
    - Wait for the DUT to be ready by checking `i_ready` before proceeding.
    - Allow the DSPs to warm up by waiting for 2048 clock cycles.
    - In a loop, send random inputs to the DUT while `num_sent` is less than `num_inputs`, incrementing `num_sent` after each input is sent.
    - After sending all inputs, reset `i_hash` and `i_valid` to 0 and wait for 100 clock cycles.
    - Wait for the [`OutMonitor`](#OutMonitor) to signal that it is done processing outputs.
- **Output**: The function does not return a value but performs a series of operations to test the DUT, sending inputs and monitoring outputs.
- **Functions called**:
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor`](#OutMonitor)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor`](#MathMonitor)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.MathMonitor.run`](#MathMonitorrun)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.send_rand_input`](#send_rand_input)
    - [`firedancer/src/wiredancer/sim/schl_cpu/test.OutMonitor.is_done`](#OutMonitoris_done)


