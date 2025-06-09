# Purpose
This C header file, `fd_dtrace.h`, is designed to provide conditional support for software-defined trace points using DTrace, a dynamic tracing framework. It checks for the availability of the `<sys/sdt.h>` header and whether the code is being compiled on a Linux system to determine if DTrace support is available (`FD_HAS_SDT`). If DTrace is supported, it defines macros that wrap DTrace probe functions, allowing the insertion of trace points with varying numbers of arguments. If DTrace is not supported, the macros are defined as no-operations, ensuring that the code remains functional without tracing capabilities. This approach allows developers to instrument their code with trace points that can be enabled or disabled based on the compilation environment, facilitating debugging and performance analysis without impacting production builds.
# Imports and Dependencies

---
- `sys/sdt.h`


