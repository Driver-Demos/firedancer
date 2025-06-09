# Purpose
This code is a C header file that defines function prototypes and an external variable related to workspace commands in a software application. It includes a configuration header file, `fd_config.h`, which suggests that it relies on shared configuration settings. The file declares two functions, [`wksp_cmd_perm`](#wksp_cmd_perm) and [`wksp_cmd_fn`](#wksp_cmd_fn), which likely handle permission checks and other workspace command functionalities, respectively, using arguments and configuration data. Additionally, it declares an external variable, `fd_action_wksp`, which is presumably used to represent or manage actions related to the workspace. The use of include guards ensures that the file's contents are only included once during compilation, preventing redefinition errors.
# Imports and Dependencies

---
- `../../shared/fd_config.h`


# Global Variables

---
### fd\_action\_wksp
- **Type**: `action_t`
- **Description**: The variable `fd_action_wksp` is a global variable of type `action_t`. It is declared as an external variable, indicating that its definition is likely found in another source file.
- **Use**: This variable is used to represent or store an action within the workspace context, accessible across multiple files in the application.


