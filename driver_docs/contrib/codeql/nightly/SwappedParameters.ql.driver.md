# Purpose
This code is a script designed to detect a specific type of programming error in C++ codebases, where parameters in a function's definition are swapped with those in its implementation. The script is written in a domain-specific language that appears to be used for static code analysis, likely as part of a larger tool or framework for identifying code issues. The primary functionality of this script is narrow, focusing specifically on identifying cases where parameters of the same type are swapped, which can lead to subtle bugs that compilers might not catch due to type compatibility.

The script imports modules named `cpp` and `filter`, indicating that it leverages existing functionality to parse and analyze C++ code. It defines a query that operates on `Function`, `ParameterDeclarationEntry`, and `Parameter` entities. The logic of the script involves checking if a function's parameters in its definition and implementation have the same name but different indices, which would indicate a swap. The script then selects these mismatched parameters and generates a warning message, highlighting the potential issue to developers.

This code is part of a static analysis tool, likely intended to be integrated into a larger code quality or bug detection system. It does not define public APIs or external interfaces but rather serves as a rule or check within a broader framework. The script's purpose is to enhance code reliability by automatically identifying and warning about parameter swaps, which are common sources of logical errors in software development.
# Imports and Dependencies

---
- `cpp`
- `filter`


