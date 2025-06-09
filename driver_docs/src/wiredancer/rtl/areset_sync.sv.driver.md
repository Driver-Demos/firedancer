# Purpose
This Verilog source code defines a module named `areset_sync` that implements an asynchronous reset synchronizer using the Xilinx Parameterized Macro (XPM) for clock domain crossing. The module takes an asynchronous reset signal (`areset`) and a destination clock (`dclk`) as inputs and produces a synchronized reset signal (`dreset`) as output. The XPM instantiation, `xpm_cdc_async_rst`, is configured with parameters such as `DEST_SYNC_FF`, which determines the number of synchronization stages, `INIT_SYNC_FF` for simulation initialization, and `RST_ACTIVE_HIGH` to define the reset signal's polarity. This setup ensures that the reset signal is asserted asynchronously and deasserted synchronously with the destination clock, providing a reliable reset mechanism across different clock domains.
# Modules

---
### areset\_sync
The `areset_sync` module is designed to synchronize an asynchronous reset signal to a destination clock domain using the Xilinx Parameterized Macro (XPM) for asynchronous reset synchronization. It ensures that the reset signal is asserted asynchronously and deasserted synchronously, with a minimum width determined by the number of synchronization stages.
- **Constants**:
    - `DEST_SYNC_FF`: An integer parameter that specifies the number of register stages used to synchronize the signal in the destination clock domain, with a range of 2 to 10 and a default value of 4.
    - `INIT_SYNC_FF`: An integer parameter that enables (1) or disables (0) behavioral simulation initialization values on synchronization registers, with a default value of 0.
    - `RST_ACTIVE_HIGH`: An integer parameter that defines the polarity of the asynchronous reset signal, where 0 indicates active low and 1 indicates active high, with a default value of 0.
- **Ports**:
    - `areset`: Input wire for the source asynchronous reset signal.
    - `dclk`: Input wire for the destination clock signal.
    - `dreset`: Output wire for the synchronized asynchronous reset signal in the destination clock domain.
- **Logic And Control Flow**:
    - The module instantiates the `xpm_cdc_async_rst` component, which is a Xilinx Parameterized Macro for asynchronous reset synchronization.
    - The `xpm_cdc_async_rst` instance is configured with parameters `DEST_SYNC_FF`, `INIT_SYNC_FF`, and `RST_ACTIVE_HIGH` to control synchronization stages, initialization behavior, and reset signal polarity, respectively.
    - The `xpm_cdc_async_rst` component synchronizes the `areset` signal to the `dclk` domain, producing the `dreset` output, which asserts asynchronously and deasserts synchronously.


