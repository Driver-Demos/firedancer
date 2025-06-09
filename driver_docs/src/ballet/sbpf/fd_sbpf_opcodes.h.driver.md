# Purpose
This C header file, `fd_sbpf_opcodes.h`, defines a comprehensive set of macros and constants for working with eBPF (extended Berkeley Packet Filter) opcodes. The file provides a structured way to define and use opcodes for various operations in eBPF programs, which are used for packet filtering and other kernel-level tasks. The file includes definitions for register shortcuts, opcode classes, source modes, size modes, ALU operation modes, jump operation modes, and address modes. These definitions are crucial for constructing and interpreting eBPF instructions, which are used to perform operations such as arithmetic, logic, memory access, and control flow.

The file is organized into several sections, each focusing on a specific aspect of opcode construction. It includes macros for defining normal and memory access instruction opcodes, which are then used to create a set of static constants representing specific eBPF operations. These constants are used to facilitate the creation and manipulation of eBPF bytecode, making it easier for developers to write and maintain eBPF programs. The header file is intended to be included in other C source files that require eBPF opcode definitions, providing a standardized interface for eBPF instruction handling.
# Imports and Dependencies

---
- `../../util/fd_util.h`


# Global Variables

---
### FD\_SBPF\_OP\_ADD\_IMM
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_ADD_IMM` is a constant that represents a specific instruction opcode for adding an immediate value in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for arithmetic operations, the operation mode for addition, and the source mode indicating that the value is an immediate constant.
- **Use**: This variable is used to specify the opcode for the addition of an immediate value in BPF programs.


---
### FD\_SBPF\_OP\_ADD\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_ADD_REG` is a constant that represents an instruction opcode for adding two values using a register in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single byte value.
- **Use**: This variable is used to specify the opcode for the addition operation in BPF programs.


---
### FD\_SBPF\_OP\_SUB\_IMM
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_SUB_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for arithmetic operations (ALU), the operation mode for subtraction (SUB), and the source mode for immediate values (IMM). This opcode is used to perform subtraction operations with immediate values in BPF programs.
- **Use**: This variable is used to specify the opcode for subtracting an immediate value in BPF instructions.


---
### FD\_SBPF\_OP\_SUB\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_SUB_REG` is a constant variable that represents a specific BPF (Berkeley Packet Filter) instruction opcode for the subtraction operation using a register as a source operand. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines various opcode components such as the opcode class, operation mode, and source mode into a single byte value.
- **Use**: This variable is used to specify the opcode for a subtraction operation in BPF programs.


---
### FD\_SBPF\_OP\_MUL\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_MUL_IMM` is a constant that represents a specific instruction opcode for the SBPF (Simple BPF) architecture, specifically for the multiplication operation using an immediate value. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single byte value.
- **Use**: This variable is used to identify the multiplication operation with an immediate value in the SBPF instruction set.


---
### FD\_SBPF\_OP\_MUL\_REG
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_MUL_REG` is a constant that represents the opcode for the multiplication operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for arithmetic logic unit (ALU) operations, the specific operation mode for multiplication, and the source mode indicating that the operation uses a register.
- **Use**: This variable is used to specify the multiplication operation when constructing BPF instructions.


---
### FD\_SBPF\_OP\_DIV\_IMM
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_DIV_IMM` is a constant that represents a specific instruction opcode for the SBPF (Simple BPF) architecture, specifically for the division operation using an immediate value. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode into a single value.
- **Use**: This variable is used to identify the division operation with an immediate operand in the SBPF instruction set.


---
### FD\_SBPF\_OP\_DIV\_REG
- **Type**: `string`
- **Description**: `FD_SBPF_OP_DIV_REG` is a constant of type `uchar` that represents the opcode for the division operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for arithmetic operations, the specific operation mode for division, and the source mode indicating that the operation uses a register.
- **Use**: This variable is used to specify the division operation when constructing BPF instructions.


---
### FD\_SBPF\_OP\_OR\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_OR_IMM` is a constant of type `uchar` that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines the opcode class for arithmetic operations, the operation mode for logical OR, and the source mode for immediate values.
- **Use**: This variable is used to specify the opcode for performing a logical OR operation with an immediate value in BPF instructions.


---
### FD\_SBPF\_OP\_OR\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_OR_REG` is a constant that represents a specific BPF (Berkeley Packet Filter) opcode for the OR operation using a register as a source operand. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines opcode class, operation mode, and source mode into a single instruction format.
- **Use**: This variable is used to specify the OR operation in BPF instructions that involve register operands.


---
### FD\_SBPF\_OP\_AND\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_AND_IMM` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines opcode class, operation mode, and source mode to create a unique instruction identifier for the 'AND' operation with an immediate value.
- **Use**: This variable is used to specify the 'AND' operation in BPF instructions when the source operand is an immediate value.


---
### FD\_SBPF\_OP\_AND\_REG
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_AND_REG` is a constant that represents a specific BPF (Berkeley Packet Filter) instruction opcode for performing a bitwise AND operation between two registers. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value. This opcode is part of the ALU (Arithmetic Logic Unit) instruction set for BPF.
- **Use**: This variable is used to specify the AND operation in BPF instructions when manipulating data in registers.


---
### FD\_SBPF\_OP\_LSH\_IMM
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_LSH_IMM` is a constant that represents a left shift immediate operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines opcode class, operation mode, and source mode to create a unique instruction code.
- **Use**: This variable is used to specify the left shift immediate operation when constructing BPF instructions.


---
### FD\_SBPF\_OP\_LSH\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_LSH_REG` is a constant that represents a left shift operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines opcode class, operation mode, and source mode into a single instruction code.
- **Use**: This variable is used to specify the left shift operation when constructing BPF instructions.


---
### FD\_SBPF\_OP\_RSH\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_RSH_IMM` is a constant that represents a right shift immediate operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines opcode class, operation mode, and source mode to create a unique instruction code.
- **Use**: This variable is used to specify the opcode for performing a right shift operation with an immediate value in BPF programs.


---
### FD\_SBPF\_OP\_RSH\_REG
- **Type**: `string`
- **Description**: `FD_SBPF_OP_RSH_REG` is a constant of type `uchar` that represents a specific instruction opcode for the right shift operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value. This particular opcode is used for performing a right shift operation on a register.
- **Use**: This variable is used to define the right shift operation in BPF instructions, allowing the execution of right shift operations on register values.


---
### FD\_SBPF\_OP\_NEG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_NEG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines opcode class, operation mode, and source mode to create a unique instruction identifier for the negation operation in the arithmetic logic unit (ALU). This opcode is used in the context of BPF programs to perform negation on a register value.
- **Use**: This variable is used to specify the negation operation in BPF instruction sets.


---
### FD\_SBPF\_OP\_MOD\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_MOD_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the modulo operation with an immediate value.
- **Use**: This variable is used to specify the opcode for performing a modulo operation in BPF instructions.


---
### FD\_SBPF\_OP\_MOD\_REG
- **Type**: `string`
- **Description**: `FD_SBPF_OP_MOD_REG` is a constant of type `uchar` that represents a specific instruction opcode for the SBPF (Simple BPF) architecture. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines opcode class, operation mode, and source mode to create a unique instruction identifier for the modulo operation using a register as the source.
- **Use**: This variable is used to specify the opcode for the modulo operation in SBPF instructions.


---
### FD\_SBPF\_OP\_XOR\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_XOR_IMM` is a constant that represents the XOR operation in the BPF instruction set, specifically for immediate values. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for arithmetic operations, the XOR operation mode, and the immediate source mode.
- **Use**: This variable is used to specify the XOR immediate operation in BPF programs.


---
### FD\_SBPF\_OP\_XOR\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_XOR_REG` is a constant that represents the XOR operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for arithmetic logic operations (ALU), the specific operation mode for XOR, and the source mode indicating that the operation uses a register.
- **Use**: This variable is used to specify the XOR operation when constructing BPF instructions.


---
### FD\_SBPF\_OP\_MOV\_IMM
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_MOV_IMM` is a constant that represents a specific instruction opcode for moving an immediate value in the context of the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the opcode for the move immediate operation in BPF instructions.


---
### FD\_SBPF\_OP\_MOV\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_MOV_REG` is a constant variable that represents a specific instruction opcode for moving data between registers in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode into a single value.
- **Use**: This variable is used to specify the move register operation in BPF instructions.


---
### FD\_SBPF\_OP\_ARSH\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_ARSH_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the arithmetic right shift operation with an immediate value.
- **Use**: This variable is used to specify the opcode for the arithmetic right shift operation in BPF programs.


---
### FD\_SBPF\_OP\_ARSH\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_ARSH_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the arithmetic right shift operation on a register.
- **Use**: This variable is used to specify the opcode for the arithmetic right shift operation in BPF instruction sets.


---
### FD\_SBPF\_OP\_END\_LE
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_END_LE` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components to create a normalized instruction for the ALU (Arithmetic Logic Unit) class, specifically for the end operation in little-endian format.
- **Use**: This variable is used to define an opcode for the BPF instruction set, allowing the execution of an end operation in little-endian byte order.


---
### FD\_SBPF\_OP\_END\_BE
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_END_BE` is a constant variable that represents a specific BPF (Berkeley Packet Filter) opcode for an ALU operation that signifies the end of a sequence, specifically in a big-endian format. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components into a single instruction value.
- **Use**: This variable is used to define the end operation in BPF instructions, particularly when the endianness is set to big-endian.


---
### FD\_SBPF\_OP\_ADD64\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_ADD64_IMM` is a constant that represents a specific instruction opcode for adding a 64-bit immediate value in the context of the eBPF (extended Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the opcode for the addition operation with a 64-bit immediate value in eBPF programs.


---
### FD\_SBPF\_OP\_ADD64\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_ADD64_REG` is a constant variable that represents a specific instruction opcode for adding two 64-bit registers in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode into a single value.
- **Use**: This variable is used to identify the opcode for the addition operation between two 64-bit registers in BPF programs.


---
### FD\_SBPF\_OP\_SUB64\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_SUB64_IMM` is a constant that represents a specific instruction opcode for a 64-bit subtraction operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the opcode for a 64-bit immediate subtraction operation in BPF programs.


---
### FD\_SBPF\_OP\_SUB64\_REG
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_SUB64_REG` is a constant that represents a specific instruction opcode for a 64-bit subtraction operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value. This particular opcode is used for performing subtraction between two registers in a 64-bit context.
- **Use**: This variable is used to specify the opcode for a 64-bit subtraction operation in BPF programs.


---
### FD\_SBPF\_OP\_MUL64\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_MUL64_IMM` is a constant that represents a specific instruction opcode for a 64-bit multiplication operation using an immediate value in the context of the eBPF (Extended Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode into a single value.
- **Use**: This variable is used to specify the opcode for a 64-bit multiplication operation with an immediate value in eBPF programs.


---
### FD\_SBPF\_OP\_MUL64\_REG
- **Type**: `string`
- **Description**: `FD_SBPF_OP_MUL64_REG` is a constant of type `uchar` that represents a specific instruction opcode for a 64-bit multiplication operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value. This opcode is part of the ALU64 (Arithmetic Logic Unit 64-bit) instruction set, indicating that it operates on 64-bit registers.
- **Use**: This variable is used to specify the opcode for a multiplication operation involving 64-bit registers in BPF programs.


---
### FD\_SBPF\_OP\_DIV64\_IMM
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_DIV64_IMM` is a constant that represents a specific instruction opcode for dividing a 64-bit integer using an immediate value in the context of the eBPF (Extended Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the opcode for a division operation with an immediate value in 64-bit arithmetic within eBPF programs.


---
### FD\_SBPF\_OP\_DIV64\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_DIV64_REG` is a constant that represents a specific instruction opcode for a 64-bit division operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value. This opcode is part of the ALU64 (64-bit arithmetic logic unit) class, indicating that it operates on 64-bit registers.
- **Use**: This variable is used to define the opcode for performing a 64-bit division operation in BPF programs.


---
### FD\_SBPF\_OP\_OR64\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_OR64_IMM` is a constant of type `uchar` that represents a specific instruction opcode for the eBPF (Extended Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for ALU64 operations, the ALU operation mode for logical OR, and the immediate source mode. This opcode is used to perform a bitwise OR operation on 64-bit values with an immediate operand.
- **Use**: This variable is used to specify the opcode for a 64-bit logical OR operation in eBPF programs.


---
### FD\_SBPF\_OP\_OR64\_REG
- **Type**: `string`
- **Description**: `FD_SBPF_OP_OR64_REG` is a constant of type `uchar` that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for ALU64 operations, the ALU operation mode for logical OR, and the source mode indicating that the operation uses a register.
- **Use**: This variable is used to specify the opcode for performing a bitwise OR operation on 64-bit registers in BPF instructions.


---
### FD\_SBPF\_OP\_AND64\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_AND64_IMM` is a constant that represents a specific instruction opcode for the eBPF (Extended Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for ALU64 operations, the ALU operation mode for AND, and the source mode for immediate values. This opcode is used in the context of 64-bit ALU operations.
- **Use**: This variable is used to specify the AND operation with an immediate value in 64-bit ALU instructions.


---
### FD\_SBPF\_OP\_AND64\_REG
- **Type**: `string`
- **Description**: `FD_SBPF_OP_AND64_REG` is a constant of type `uchar` that represents a specific instruction opcode for the eBPF (Extended Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines opcode class, operation mode, and source mode to create a unique instruction identifier for the AND operation on 64-bit registers.
- **Use**: This variable is used to specify the AND operation for 64-bit registers in eBPF instructions.


---
### FD\_SBPF\_OP\_LSH64\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_LSH64_IMM` is a constant that represents a specific instruction opcode for a left shift operation (LSH) in a 64-bit arithmetic context. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value.
- **Use**: This variable is used to specify the opcode for a left shift immediate operation in the context of 64-bit BPF instructions.


---
### FD\_SBPF\_OP\_LSH64\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_LSH64_REG` is a constant that represents a left shift operation for 64-bit ALU instructions in the BPF (Berkeley Packet Filter) opcode set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single instruction code.
- **Use**: This variable is used to specify the left shift operation in 64-bit ALU instructions within the BPF instruction set.


---
### FD\_SBPF\_OP\_RSH64\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_RSH64_IMM` is a constant that represents a specific instruction opcode for a right shift operation (RSH) on 64-bit values, using an immediate value as the source. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components into a single instruction representation.
- **Use**: This variable is used to specify the opcode for a right shift operation in the context of 64-bit arithmetic instructions in the BPF (Berkeley Packet Filter) framework.


---
### FD\_SBPF\_OP\_RSH64\_REG
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_RSH64_REG` is a constant that represents a specific instruction opcode for a right shift operation on a 64-bit register in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value. This opcode is part of the ALU64 (64-bit arithmetic logic unit) operations.
- **Use**: This variable is used to encode the right shift operation for 64-bit registers in BPF instructions.


---
### FD\_SBPF\_OP\_NEG64
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_NEG64` is a constant that represents a specific instruction opcode for a 64-bit arithmetic operation in the eBPF (extended Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the negation operation.
- **Use**: This variable is used to specify the negation operation in 64-bit ALU instructions within the eBPF framework.


---
### FD\_SBPF\_OP\_MOD64\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_MOD64_IMM` is a constant of type `uchar` that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines opcode class, operation mode, and source mode to create a unique instruction identifier for the modulo operation in 64-bit ALU instructions.
- **Use**: This variable is used to identify the modulo operation instruction with an immediate value in the context of 64-bit ALU operations.


---
### FD\_SBPF\_OP\_MOD64\_REG
- **Type**: `string`
- **Description**: `FD_SBPF_OP_MOD64_REG` is a constant of type `uchar` that represents a specific instruction opcode for the 64-bit ALU operation mode of the BPF (Berkeley Packet Filter). It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines the opcode class, operation mode, and source mode into a single value. This particular opcode corresponds to the modulo operation performed on register values in the 64-bit ALU context.
- **Use**: This variable is used to define the opcode for the modulo operation in 64-bit ALU instructions within the BPF framework.


---
### FD\_SBPF\_OP\_XOR64\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_XOR64_IMM` is a constant that represents the instruction opcode for a 64-bit XOR operation with an immediate value in the context of the eBPF (Extended Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the XOR operation with an immediate value in 64-bit ALU instructions.


---
### FD\_SBPF\_OP\_XOR64\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_XOR64_REG` is a constant that represents the XOR operation for 64-bit registers in the BPF instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for ALU64, the XOR operation mode, and the source mode indicating that the operation is performed on registers.
- **Use**: This variable is used to specify the XOR operation in 64-bit register contexts within BPF programs.


---
### FD\_SBPF\_OP\_MOV64\_IMM
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_MOV64_IMM` is a constant that represents a specific instruction opcode for moving a 64-bit immediate value in the context of the eBPF (Extended Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the opcode for the MOV instruction that moves an immediate value into a 64-bit register.


---
### FD\_SBPF\_OP\_MOV64\_REG
- **Type**: `string`
- **Description**: `FD_SBPF_OP_MOV64_REG` is a constant of type `uchar` that represents a specific instruction opcode for moving a 64-bit value from one register to another in the eBPF instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value. This opcode is part of the ALU64 class, which is used for 64-bit arithmetic operations.
- **Use**: This variable is used to specify the MOV instruction for 64-bit registers in eBPF programs.


---
### FD\_SBPF\_OP\_ARSH64\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_ARSH64_IMM` is a constant of type `uchar` that represents a specific instruction opcode for the eBPF (Extended Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for ALU64 operations, the arithmetic right shift operation mode, and the immediate source mode. This opcode is used in the context of 64-bit arithmetic operations within the eBPF instruction set.
- **Use**: This variable is used to define the opcode for performing an arithmetic right shift operation with an immediate value in eBPF programs.


---
### FD\_SBPF\_OP\_ARSH64\_REG
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_ARSH64_REG` is a constant that represents the instruction opcode for the arithmetic right shift operation (ARSH) in a 64-bit context within the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single value.
- **Use**: This variable is used to specify the ARSH operation when constructing BPF instructions.


---
### FD\_SBPF\_OP\_END64\_LE
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_END64_LE` is a constant that represents a specific instruction opcode for the eBPF (extended Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components to create a normalized instruction for the ALU64 (64-bit arithmetic logic unit) class, specifically for the end operation in little-endian format.
- **Use**: This variable is used to define a specific operation in the eBPF instruction set, allowing for the execution of a 64-bit end operation in little-endian byte order.


---
### FD\_SBPF\_OP\_END64\_BE
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_END64_BE` is a constant variable that represents a specific instruction opcode for the 64-bit ALU operations in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and endianness mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the end operation in a 64-bit ALU context, particularly for converting data to big-endian format.


---
### FD\_SBPF\_OP\_JA
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JA` is a constant that represents a specific instruction opcode for the Jump Always (JA) operation in the BPF instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single byte value.
- **Use**: This variable is used to encode the Jump Always instruction for BPF programs, facilitating the execution of unconditional jumps in the instruction flow.


---
### FD\_SBPF\_OP\_JEQ\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JEQ_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for equality (JEQ), and the immediate source mode. This opcode is used to facilitate conditional jumps based on immediate values in BPF programs.
- **Use**: This variable is used to encode the JEQ immediate jump instruction in BPF bytecode.


---
### FD\_SBPF\_OP\_JEQ\_REG
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_JEQ_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for a jump equal operation that compares a register value.
- **Use**: This variable is used to specify the opcode for a jump instruction that checks for equality against a register in BPF programs.


---
### FD\_SBPF\_OP\_JGT\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JGT_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jump instructions, the jump operation mode for 'greater than', and the immediate source mode.
- **Use**: This variable is used to specify a jump instruction that checks if a value is greater than a specified immediate value in BPF programs.


---
### FD\_SBPF\_OP\_JGT\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JGT_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'greater than', and the source mode indicating that the comparison is made using a register.
- **Use**: This variable is used to specify the opcode for a jump instruction that checks if one register is greater than another in BPF programs.


---
### FD\_SBPF\_OP\_JGE\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JGE_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'greater than or equal to' (JGE), and the immediate source mode. This opcode is used in BPF programs to perform conditional jumps based on comparisons.
- **Use**: This variable is used to specify the JGE instruction in BPF opcode definitions.


---
### FD\_SBPF\_OP\_JGE\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JGE_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the 'Jump if Greater or Equal' operation using a register.
- **Use**: This variable is used to specify the opcode for the JGE instruction in BPF programs.


---
### FD\_SBPF\_OP\_JSET\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSET_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the jump operation that checks if a specified bit is set in a register.
- **Use**: This variable is used to define the opcode for the JSET instruction in BPF programs, allowing the execution of conditional jumps based on bitwise checks.


---
### FD\_SBPF\_OP\_JSET\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSET_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode into a single byte value. This particular opcode is used for the 'JSET' jump operation, which checks if a specific register is set.
- **Use**: This variable is used to define the behavior of the JSET instruction in BPF programs.


---
### FD\_SBPF\_OP\_JNE\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JNE_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) instruction set. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines the opcode class for jump instructions, the jump operation mode for 'not equal' (JNE), and the source mode for immediate values.
- **Use**: This variable is used to encode the JNE instruction in BPF programs, allowing for conditional jumps based on immediate values.


---
### FD\_SBPF\_OP\_JNE\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JNE_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the 'Jump if Not Equal' operation when using a register as the source.
- **Use**: This variable is used to define the opcode for the JNE (Jump if Not Equal) instruction in BPF programs.


---
### FD\_SBPF\_OP\_JSGT\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSGT_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) used in jump operations. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'jump if greater than' (JSGT), and the source mode for immediate values.
- **Use**: This variable is used to encode the JSGT instruction in BPF programs, allowing for conditional jumps based on immediate values.


---
### FD\_SBPF\_OP\_JSGT\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSGT_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines various opcode components such as class, operation mode, and source mode to create a unique instruction identifier for the 'jump if greater than' operation using a register.
- **Use**: This variable is used to define the opcode for a specific jump instruction in the BPF instruction set.


---
### FD\_SBPF\_OP\_JSGE\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSGE_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'jump if greater than or equal', and the immediate source mode.
- **Use**: This variable is used to specify a jump instruction in BPF programs that checks if a value is greater than or equal to a specified immediate value.


---
### FD\_SBPF\_OP\_JSGE\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSGE_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode to create a unique instruction identifier for the 'jump if greater than or equal' operation on a register.
- **Use**: This variable is used to define the opcode for a specific jump instruction in the BPF instruction set.


---
### FD\_SBPF\_OP\_CALL\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_CALL_IMM` is a constant of type `uchar` that represents a specific instruction opcode for a call operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the opcode for a call instruction with an immediate source mode in BPF programs.


---
### FD\_SBPF\_OP\_CALL\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_CALL_REG` is a constant variable that represents a specific instruction opcode for a call operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the opcode for a call operation when constructing BPF instructions.


---
### FD\_SBPF\_OP\_EXIT
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_EXIT` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines the opcode class for jump instructions, the specific jump operation mode for exiting, and a source mode indicating no source. This opcode is used to signal the termination of a BPF program.
- **Use**: This variable is used to define the exit operation in BPF programs, allowing the program to terminate execution.


---
### FD\_SBPF\_OP\_JLT\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JLT_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'less than', and the immediate source mode. This opcode is used to facilitate conditional branching in BPF programs.
- **Use**: This variable is used to encode the 'jump if less than' instruction with an immediate value in BPF programs.


---
### FD\_SBPF\_OP\_JLT\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JLT_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'less than' (JLT), and the source mode indicating that the source is a register.
- **Use**: This variable is used to specify a jump instruction that checks if a value is less than another value in BPF programs.


---
### FD\_SBPF\_OP\_JLE\_IMM
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_JLE_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'less than or equal to' (JLE), and the immediate source mode. This opcode is used in the context of BPF programs to facilitate conditional branching based on comparisons.
- **Use**: This variable is used to encode the JLE instruction for BPF, allowing the virtual machine to execute conditional jumps based on immediate values.


---
### FD\_SBPF\_OP\_JLE\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JLE_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the 'Jump if Less or Equal' operation using a register.
- **Use**: This variable is used to specify the opcode for the JLE (Jump if Less or Equal) instruction in BPF programs.


---
### FD\_SBPF\_OP\_JSLT\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_JSLT_IMM` is a constant of type `uchar` that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the macro `FD_SBPF_DEFINE_NORM_INSTR`, which combines the opcode class for jumps, the jump operation mode for 'jump if less than', and the immediate source mode.
- **Use**: This variable is used to specify the opcode for a jump instruction that checks if a value is less than a specified immediate value in BPF programs.


---
### FD\_SBPF\_OP\_JSLT\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSLT_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'jump if less than' (JSLT), and the source mode indicating that the source is a register.
- **Use**: This variable is used to define a specific jump instruction in BPF programs that checks if a value is less than another value.


---
### FD\_SBPF\_OP\_JSLE\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_JSLE_IMM` is a constant of type `uchar` that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the 'jump if less than or equal' operation with an immediate value.
- **Use**: This variable is used to specify the opcode for a conditional jump instruction in BPF programs.


---
### FD\_SBPF\_OP\_JSLE\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSLE_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the 'JSLE' (Jump if Less or Equal) operation that uses a register as its source.
- **Use**: This variable is used to define the opcode for a specific jump instruction in the BPF instruction set.


---
### FD\_SBPF\_OP\_JEQ32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JEQ32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for equality (JEQ), and the immediate source mode. This opcode is used to facilitate conditional jumps based on immediate values in BPF programs.
- **Use**: This variable is used to encode the JEQ32 immediate jump instruction in BPF programs.


---
### FD\_SBPF\_OP\_JEQ32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JEQ32_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode to create a unique instruction identifier.
- **Use**: This variable is used to specify the jump instruction that checks for equality against a register in the BPF instruction set.


---
### FD\_SBPF\_OP\_JGT32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JGT32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jump instructions, the jump operation mode for 'greater than', and the immediate source mode. This opcode is used to facilitate conditional jumps based on immediate values in BPF programs.
- **Use**: This variable is used to encode the 'jump if greater than' instruction with an immediate value in BPF.


---
### FD\_SBPF\_OP\_JGT32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JGT32_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'greater than', and the source mode indicating a register. This opcode is used in the context of BPF programs to facilitate conditional branching based on register values.
- **Use**: This variable is used to define a jump instruction that checks if a value in a register is greater than a specified threshold.


---
### FD\_SBPF\_OP\_JGE32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JGE32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'greater than or equal to' (JGE), and the immediate source mode.
- **Use**: This variable is used to encode the JGE instruction with an immediate value in the BPF instruction set.


---
### FD\_SBPF\_OP\_JGE32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JGE32_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'greater than or equal to' (JGE), and the source mode indicating that the source is a register.
- **Use**: This variable is used to encode the JGE operation in BPF instructions, allowing for conditional jumps based on register values.


---
### FD\_SBPF\_OP\_JSET32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSET32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the JSET operation with an immediate source.
- **Use**: This variable is used to specify the JSET instruction in BPF programs, allowing for conditional jumps based on the state of a register.


---
### FD\_SBPF\_OP\_JSET32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSET32_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode into a single byte value.
- **Use**: This variable is used to specify the JSET instruction in BPF programs, allowing for conditional jumps based on the state of a register.


---
### FD\_SBPF\_OP\_JNE32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JNE32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'not equal' (JNE), and the immediate source mode. This opcode is used in the context of BPF programs to facilitate conditional branching based on comparison results.
- **Use**: This variable is used to encode the 'jump if not equal' instruction with an immediate value in BPF programs.


---
### FD\_SBPF\_OP\_JNE32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JNE32_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode to create a unique instruction identifier for the 'Jump if Not Equal' operation with a register source.
- **Use**: This variable is used to define the opcode for the JNE (Jump if Not Equal) instruction in the BPF instruction set, facilitating the execution of conditional jumps based on register values.


---
### FD\_SBPF\_OP\_JSGT32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSGT32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) virtual machine. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jump instructions, the jump operation mode for signed greater than (JSGT), and the immediate source mode.
- **Use**: This variable is used to encode the JSGT32 immediate jump instruction in BPF programs.


---
### FD\_SBPF\_OP\_JSGT32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSGT32_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as class, operation mode, and source mode to create a unique instruction identifier for the 'jump if greater than' operation with a 32-bit register source.
- **Use**: This variable is used to define a specific BPF instruction that checks if a value in a register is greater than another value, facilitating conditional jumps in BPF programs.


---
### FD\_SBPF\_OP\_JSGE32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSGE32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'jump if greater than or equal', and the immediate source mode. This opcode is used in the context of BPF programs to facilitate conditional branching based on comparison results.
- **Use**: This variable is used to define a specific jump instruction in BPF programs that checks if a value is greater than or equal to a specified immediate value.


---
### FD\_SBPF\_OP\_JSGE32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSGE32_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as class, operation mode, and source mode to create a unique instruction identifier for the 'jump if greater than or equal to' operation on 32-bit registers.
- **Use**: This variable is used to define a specific BPF instruction that can be executed in the context of packet filtering.


---
### FD\_SBPF\_OP\_JLT32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JLT32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for a jump operation that checks if a value is less than a specified immediate value.
- **Use**: This variable is used to define a jump instruction in BPF that compares a register value against an immediate value, facilitating conditional branching in BPF programs.


---
### FD\_SBPF\_OP\_JLT32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JLT32_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'less than', and the source mode indicating a register. This opcode is used in the context of BPF programs to facilitate conditional jumps based on comparisons.
- **Use**: This variable is used to define a jump instruction that checks if a value in a register is less than another value in BPF programs.


---
### FD\_SBPF\_OP\_JLE32\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_JLE32_IMM` is a constant of type `uchar` that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'less than or equal to' (JLE), and the immediate source mode. This opcode is used in the context of BPF programs to facilitate conditional branching based on comparisons.
- **Use**: This variable is used to define a jump instruction that checks if a value is less than or equal to a specified immediate value in BPF programs.


---
### FD\_SBPF\_OP\_JLE32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JLE32_REG` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for the 'Jump if Less or Equal' operation using a register as the source.
- **Use**: This variable is used to define the opcode for a specific BPF instruction that checks if a value in a register is less than or equal to another value.


---
### FD\_SBPF\_OP\_JSLT32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSLT32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'jump if less than', and the immediate source mode. This opcode is used in the context of BPF programs to facilitate conditional branching based on comparison results.
- **Use**: This variable is used to define a specific jump instruction in BPF programs that checks if a value is less than a specified immediate value.


---
### FD\_SBPF\_OP\_JSLT32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSLT32_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines various opcode components such as the opcode class, operation mode, and source mode to create a unique instruction identifier for jump operations that compare values in registers.
- **Use**: This variable is used to define a jump instruction that checks if one register is less than another in the BPF instruction set.


---
### FD\_SBPF\_OP\_JSLE32\_IMM
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSLE32_IMM` is a constant that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class, operation mode, and source mode to create a unique instruction identifier for a jump operation that checks if a value is less than or equal to another value, using an immediate value.
- **Use**: This variable is used to define a specific jump instruction in the BPF instruction set, allowing for conditional branching based on immediate values.


---
### FD\_SBPF\_OP\_JSLE32\_REG
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_JSLE32_REG` is a constant variable that represents a specific instruction opcode for the BPF (Berkeley Packet Filter) architecture. It is defined using the `FD_SBPF_DEFINE_NORM_INSTR` macro, which combines the opcode class for jumps, the jump operation mode for 'JSLE' (jump if less than or equal), and the source mode indicating that the source is a register.
- **Use**: This variable is used to define a specific jump instruction in the BPF instruction set.


---
### FD\_SBPF\_OP\_LDDW
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_LDDW` is a constant that represents a specific memory instruction opcode for loading a double word in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_MEM_INSTR` macro, which combines the opcode class, address mode, and size mode into a single byte value.
- **Use**: This variable is used to specify the operation of loading a double word from immediate memory in BPF programs.


---
### FD\_SBPF\_OP\_LDXW
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_LDXW` is a constant variable that represents a specific memory instruction opcode for loading a word from memory in the context of the BPF (Berkeley Packet Filter) instruction set. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines the opcode class for loading (`FD_SBPF_OPCODE_CLASS_LDX`), the address mode for memory access (`FD_SBPF_OPCODE_ADDR_MODE_MEM`), and the size mode indicating a word size (`FD_SBPF_OPCODE_SIZE_MODE_WORD`).
- **Use**: This variable is used to specify the opcode for loading a word from memory in BPF programs.


---
### FD\_SBPF\_OP\_LDXH
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_LDXH` is a constant variable that represents a specific memory access instruction opcode for loading a half-word from memory in the context of the BPF (Berkeley Packet Filter) instruction set. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines the opcode class for loading (`FD_SBPF_OPCODE_CLASS_LDX`), the address mode for memory access (`FD_SBPF_OPCODE_ADDR_MODE_MEM`), and the size mode for half-word (`FD_SBPF_OPCODE_SIZE_MODE_HALF`). This variable is crucial for defining how the BPF virtual machine interprets and executes instructions related to loading data from memory.
- **Use**: This variable is used to specify the opcode for loading a half-word from memory in BPF instructions.


---
### FD\_SBPF\_OP\_LDXB
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_LDXB` is a constant variable that represents a specific memory access instruction opcode for loading a byte from memory in the context of the BPF (Berkeley Packet Filter) instruction set. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines the opcode class for loading (`FD_SBPF_OPCODE_CLASS_LDX`), the address mode for memory (`FD_SBPF_OPCODE_ADDR_MODE_MEM`), and the size mode for a byte (`FD_SBPF_OPCODE_SIZE_MODE_BYTE`). This opcode is part of a larger set of instructions used for packet filtering and processing.
- **Use**: This variable is used to define the opcode for loading a byte from memory in BPF instructions.


---
### FD\_SBPF\_OP\_LDXDW
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_LDXDW` is a constant that represents a specific instruction opcode for loading a double word from memory in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_MEM_INSTR` macro, which combines the opcode class, address mode, and size mode to create the final opcode value.
- **Use**: This variable is used to specify the opcode for loading a double word from memory in BPF instructions.


---
### FD\_SBPF\_OP\_STW
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_STW` is a constant variable that represents a specific memory store instruction opcode in the context of the BPF (Berkeley Packet Filter) architecture. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines various opcode components such as class, address mode, and size mode to create a unique instruction identifier for storing a word-sized value in memory.
- **Use**: This variable is used to specify the opcode for storing a word-sized value in memory during BPF instruction execution.


---
### FD\_SBPF\_OP\_STH
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_STH` is a constant that represents a specific memory store operation in the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_MEM_INSTR` macro, which combines opcode class, address mode, and size mode to create a unique instruction for storing half-word data.
- **Use**: This variable is used to specify the operation of storing half-word data in memory within BPF programs.


---
### FD\_SBPF\_OP\_STB
- **Type**: `string`
- **Description**: `FD_SBPF_OP_STB` is a constant of type `uchar` that represents a specific memory store instruction opcode in the context of the BPF (Berkeley Packet Filter) architecture. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines the opcode class for store operations, the addressing mode for memory, and the size mode indicating that the operation is for a byte-sized data type.
- **Use**: This variable is used to specify the opcode for storing a byte in memory during BPF instruction execution.


---
### FD\_SBPF\_OP\_STDW
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_STDW` is a constant variable that represents a specific instruction opcode for storing double-word values in memory within the context of the BPF (Berkeley Packet Filter) instruction set. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines the opcode class, address mode, and size mode to create a unique instruction identifier.
- **Use**: This variable is used to define the opcode for storing double-word values in memory, facilitating the execution of memory-related operations in BPF programs.


---
### FD\_SBPF\_OP\_STXW
- **Type**: `string`
- **Description**: `FD_SBPF_OP_STXW` is a constant of type `uchar` that represents a specific memory instruction opcode for storing a word in the BPF (Berkeley Packet Filter) instruction set. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines the opcode class for store instructions (`FD_SBPF_OPCODE_CLASS_STX`), the addressing mode for memory (`FD_SBPF_OPCODE_ADDR_MODE_MEM`), and the size mode for word-sized data (`FD_SBPF_OPCODE_SIZE_MODE_WORD`).
- **Use**: This variable is used to define the opcode for storing a word in memory within the BPF instruction set.


---
### FD\_SBPF\_OP\_STXH
- **Type**: `const uchar`
- **Description**: `FD_SBPF_OP_STXH` is a constant variable that represents a specific memory store instruction opcode in the context of the BPF (Berkeley Packet Filter) architecture. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines the opcode class for store instructions (`FD_SBPF_OPCODE_CLASS_STX`), the addressing mode for memory (`FD_SBPF_OPCODE_ADDR_MODE_MEM`), and the size mode for half-word (`FD_SBPF_OPCODE_SIZE_MODE_HALF`). This opcode is used to facilitate the storage of half-word data into memory.
- **Use**: This variable is used to define a specific operation code for storing half-word values in memory within the BPF instruction set.


---
### FD\_SBPF\_OP\_STXB
- **Type**: `string`
- **Description**: `FD_SBPF_OP_STXB` is a constant of type `uchar` that represents a specific memory instruction opcode for storing a byte in the context of the BPF (Berkeley Packet Filter) instruction set. It is defined using the macro `FD_SBPF_DEFINE_MEM_INSTR`, which combines the opcode class for store instructions (`FD_SBPF_OPCODE_CLASS_STX`), the addressing mode for memory (`FD_SBPF_OPCODE_ADDR_MODE_MEM`), and the size mode for a byte (`FD_SBPF_OPCODE_SIZE_MODE_BYTE`).
- **Use**: This variable is used to define the opcode for storing a byte in memory within the BPF instruction set.


---
### FD\_SBPF\_OP\_STXDW
- **Type**: `uchar`
- **Description**: `FD_SBPF_OP_STXDW` is a constant that represents a specific instruction opcode for storing a double word in memory within the context of the BPF (Berkeley Packet Filter) instruction set. It is defined using the `FD_SBPF_DEFINE_MEM_INSTR` macro, which combines the opcode class, address mode, and size mode to create a unique instruction identifier.
- **Use**: This variable is used to define the opcode for the STX (store indexed) operation that stores a double word in memory.


---
### FD\_SBPF\_OP\_ADDL\_IMM
- **Type**: `string`
- **Description**: `FD_SBPF_OP_ADDL_IMM` is a constant of type `uchar` that represents the opcode for the addition operation with an immediate value in the BPF instruction set. It is defined as `0x00`, which corresponds to the binary representation `0b00000000`. This opcode is part of the ALU (Arithmetic Logic Unit) operations in the BPF instruction set.
- **Use**: This variable is used to specify the opcode for addition with an immediate operand in BPF instructions.


