# Purpose
This code appears to be a query script, likely intended for use with a static analysis tool or a code quality checker, focusing on C++ code. It provides a narrow functionality by specifically identifying instances where functions marked as `const` or `pure` are calling known non-const/non-pure functions, which could lead to unexpected side effects or violations of function purity. The script defines abstract and concrete classes to represent functions with `const` and `pure` attributes and uses these to query a codebase for problematic function calls. The purpose of this script is to enhance code quality by warning developers about potential issues with function purity, thus maintaining the integrity and predictability of the code.
# Imports and Dependencies

---
- `cpp`


# Data Structures

---
### RFunc
- **Type**: `abstract class`
- **Members**:
    - `PureFunc`: A subclass of RFunc that sets its attribute name to 'pure'.
    - `ConstFunc`: A subclass of RFunc that sets its attribute name to 'const'.
- **Description**: RFunc is an abstract class that extends the Function class, serving as a base for defining function types that are either pure or const. It is used to identify and handle functions that are marked as const or pure, and to check for calls to known non-const/non-pure functions within these marked functions. The subclasses PureFunc and ConstFunc are specific implementations that set their respective attributes to 'pure' and 'const', indicating the nature of the function they represent.


---
### PureFunc
- **Type**: `class`
- **Members**:
    - `PureFunc`: Constructor that sets the attribute name to 'pure'.
- **Description**: The `PureFunc` class is a specialized type of `RFunc` that represents functions marked as 'pure'. It inherits from the abstract class `RFunc`, which in turn extends the `Function` class. The primary purpose of `PureFunc` is to identify and handle functions that are intended to be pure, meaning they do not cause side effects and their return value is only determined by their input values. The constructor of `PureFunc` sets an attribute's name to 'pure', indicating its purity status.


---
### ConstFunc
- **Type**: `class`
- **Members**:
    - `ConstFunc`: A class that extends RFunc and sets its attribute name to 'const'.
- **Description**: The ConstFunc class is a specialized type of RFunc, which itself is an abstract class extending Function. ConstFunc is designed to represent functions that are marked as 'const'. It overrides the constructor to set the attribute name to 'const', indicating that it is intended to be used in contexts where const correctness is enforced. This class is part of a system that checks for calls to non-const or non-pure functions from within functions that are marked as const or pure, helping to identify potential issues in code where const correctness might be violated.


