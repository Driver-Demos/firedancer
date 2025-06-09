# Purpose
This document appears to be a README file that provides detailed information about a specific implementation of the HTTP/2 framing layer within a software codebase. It outlines the limitations and specific behaviors of the library, such as the lack of support for certain HTTP/2 features like server push, priority hints, and the HPACK dynamic table. The document clarifies that this library is not a full HTTP library but focuses solely on the framing layer, which is a narrow functionality. It also highlights potential compatibility issues and quirks related to HTTP/2, such as header sequences and server-initiated streams. Additionally, the file includes a section on code coverage, providing a shell command for generating coverage reports using tools like `llvm-cov` and `genhtml`, which is relevant for developers looking to test and validate the implementation's robustness.
# Content Summary
This document provides an overview of the HTTP/2 framing layer implementation contained within a specific directory. It is crucial to note that this is not a full HTTP library; it only provides the framing layer, meaning it lacks the complete HTTP protocol as defined in RFC 9113 Section 8.

Key technical details include:

1. **HPACK Fragmentation**: The library assumes that a single HPACK header record is not fragmented across multiple HTTP frames. If fragmentation occurs, it will result in a connection error labeled as COMPRESSION_ERROR.

2. **Server Push**: The library does not support HTTP/2 Server Push, as the PUSH_PROMISE feature is disabled via SETTINGS.

3. **Priority Handling**: HTTP/2 priority hints are ignored by this implementation.

4. **HPACK Dynamic Table**: The dynamic table, which is used for stateful HTTP header compression, is disabled. This may lead to compatibility issues, particularly when the server is running, due to potential race conditions with client requests.

5. **END_STREAM/CONTINUATION State**: The library does not correctly support the scenario where a HEADERS frame with the END_STREAM flag is followed by CONTINUATION frames on the same stream.

The document also highlights some general quirks of HTTP/2, such as the ability to send multiple field blocks (headers or trailers) before data, which can create the appearance of conflicting headers, and the capability for servers to initiate streams, which is distinct from server push or regular responses.

Finally, the document includes a section on code coverage, providing a shell command for generating a coverage report using tools like `llvm-cov` and `genhtml`. This command is intended for use with a fuzz testing corpus, which should be specified by the user.
