# Purpose
This source code file is a static analysis script designed to identify potential issues in C++ code where operations are inconsistently applied to the return values of function calls. The script is written in a query language, likely for use with a code analysis tool, and it focuses on detecting cases where operations such as `free`, `delete`, or `close` are typically performed on a function's return value but are omitted in certain instances. This inconsistency can lead to resource leaks or other reliability issues, making the script a valuable tool for improving code correctness and reliability.

The code defines several predicates to encapsulate the logic for identifying these inconsistencies. Key predicates include `exclude`, which filters out functions based on their names, and `checkExpr`, which checks if a specific operation is performed on a variable derived from a function call. The `checkedFunctionCall` and `relevantFunctionCall` predicates are used to determine whether a function call is relevant to the analysis and whether the expected operation is performed. The `functionStats` predicate calculates statistics on how often the operation is applied, providing a percentage that helps identify functions with inconsistent usage patterns.

The script concludes with a query that selects function calls where the expected operation is missing, provided that the operation is performed in at least 70% of other cases. This threshold helps focus the analysis on significant inconsistencies. The script is tailored to work within a specific codebase, as indicated by the file path filters, and it generates warnings to alert developers to potential issues, thereby aiding in the maintenance of high-quality, reliable software.
# Imports and Dependencies

---
- `cpp`


