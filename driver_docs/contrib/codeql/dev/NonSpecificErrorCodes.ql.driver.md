# Purpose
This code appears to be a script or rule definition for a static analysis tool, likely used to identify potential issues in C++ codebases. It provides a narrow functionality focused on detecting functions that return a defined constant on one execution path and a literal number on another, which can be a source of inconsistency or bugs. The code is not an executable or a library but rather a configuration or rule file that specifies a particular kind of problem to be flagged during code analysis. The purpose of this rule is to serve as a development hint, warning developers about mixed return values, although it acknowledges its low precision and potential failure cases, such as when a function returns either an error constant or a size.
# Imports and Dependencies

---
- `cpp`
- `filter`
- `rettypes`


