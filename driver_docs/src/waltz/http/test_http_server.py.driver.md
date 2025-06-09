# Purpose
This Python script is designed to interact with a local server running on port 4321, utilizing both HTTP and WebSocket protocols. The script performs three main tasks: it first sends a series of HTTP GET requests to a specific endpoint and prints the response content. This is followed by sending a series of HTTP POST requests with JSON-RPC formatted data to the same server, which requests account information and prints the parsed JSON response. Finally, the script establishes a WebSocket connection to the server, subscribes to a service using JSON-RPC, and continuously receives and prints messages from the server.

The script demonstrates a combination of synchronous and asynchronous programming. It uses the `requests` library for synchronous HTTP requests and the `websockets` library for asynchronous WebSocket communication. The use of JSON-RPC indicates that the server is expected to handle remote procedure calls, and the script is likely part of a client-side application that interacts with a server providing JSON-RPC services. The script is not structured as a reusable library but rather as a standalone script intended for testing or demonstration purposes, as indicated by the final print statement "Test passed!"
# Imports and Dependencies

---
- `asyncio`
- `websockets`
- `requests`
- `json`


# Functions

---
### hello<!-- {{#callable:firedancer/src/waltz/http/test_http_server.hello}} -->
The `hello` function establishes a WebSocket connection to a local server and continuously sends a subscription request, printing received messages.
- **Decorators**: `@async`
- **Inputs**: None
- **Control Flow**:
    - The function defines a WebSocket URI pointing to a local server on port 4321.
    - It establishes an asynchronous WebSocket connection using the `websockets.connect` method.
    - A JSON-RPC request object is created with the method `slotSubscribe`.
    - The request object is serialized to a JSON string and sent over the WebSocket connection.
    - The function enters an infinite loop where it waits for messages from the WebSocket.
    - Each received message is deserialized from JSON, pretty-printed, and output to the console.
- **Output**: The function does not return any value; it continuously prints received WebSocket messages to the console.


