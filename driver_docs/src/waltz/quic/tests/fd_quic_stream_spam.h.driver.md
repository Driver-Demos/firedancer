# Purpose
This C header file defines a set of functions and types for generating and managing QUIC protocol streams, specifically for testing purposes by simulating spam-like traffic. It introduces a function pointer type, `fd_quic_stream_gen_spam_t`, which is used to generate random stream payloads for a given stream ID, filling a provided packet buffer with data. The `fd_quic_stream_spam_t` structure acts as a load generator, sending unidirectional streams at maximum rate, and is managed through functions that create, join, leave, and delete these spam stream generators. Additionally, the file provides a service function to initiate multiple random streams and a notification function to handle stream finalization. The implementation of the payload generation function, [`fd_quic_stream_spam_gen`](#fd_quic_stream_spam_gen), produces random bytes of random sizes, simulating the behavior of spam traffic in a QUIC connection.
# Imports and Dependencies

---
- `../fd_quic.h`


# Global Variables

---
### fd\_quic\_stream\_spam\_new
- **Type**: `function pointer`
- **Description**: The `fd_quic_stream_spam_new` is a function pointer that initializes a new QUIC stream spam generator. It takes a memory pointer, a function pointer for generating stream data, and a context pointer as arguments.
- **Use**: This function is used to create and initialize a new instance of a QUIC stream spam generator, which is responsible for generating and sending random stream data.


---
### fd\_quic\_stream\_spam\_join
- **Type**: `fd_quic_stream_spam_t *`
- **Description**: The `fd_quic_stream_spam_join` is a function that returns a pointer to an `fd_quic_stream_spam_t` structure. This structure is used to manage and generate QUIC stream spam, which involves sending sub-MTU size unidirectional streams at maximum rate.
- **Use**: This function is used to join or initialize a QUIC stream spam instance from a shared memory object.


---
### fd\_quic\_stream\_spam\_leave
- **Type**: `function pointer`
- **Description**: The `fd_quic_stream_spam_leave` is a function that takes a pointer to an `fd_quic_stream_spam_t` structure and returns a void pointer. This function is likely used to perform cleanup or disassociation tasks related to the `fd_quic_stream_spam_t` instance.
- **Use**: This function is used to leave or disassociate from a QUIC stream spam instance, potentially freeing resources or performing necessary cleanup.


---
### fd\_quic\_stream\_spam\_delete
- **Type**: `function pointer`
- **Description**: The `fd_quic_stream_spam_delete` is a function pointer that is used to delete or clean up resources associated with a QUIC stream spam object. It takes a single argument, `shspam`, which is a pointer to the shared memory or resource to be deleted.
- **Use**: This function is used to release resources or perform cleanup for a QUIC stream spam object when it is no longer needed.


# Data Structures

---
### fd\_quic\_stream\_spam\_private
- **Type**: `struct`
- **Members**:
    - `gen_fn`: A function pointer to a generator function that creates random stream buffers for QUIC streams.
    - `gen_ctx`: A pointer to the context used by the generator function.
    - `stream`: A pointer to a QUIC stream associated with the spam generator.
- **Description**: The `fd_quic_stream_spam_private` structure is designed to facilitate the generation of random QUIC stream payloads for testing purposes. It contains a function pointer `gen_fn` to a generator function that produces random data for a given stream, a context pointer `gen_ctx` for use by the generator function, and a pointer `stream` to the QUIC stream being manipulated. This structure is part of a load generator that sends unidirectional streams at maximum rate, primarily used for testing and performance evaluation of QUIC implementations.


---
### fd\_quic\_stream\_spam\_t
- **Type**: `struct`
- **Members**:
    - `gen_fn`: A function pointer to a generator function that creates random stream buffers.
    - `gen_ctx`: A pointer to the context used by the generator function.
    - `stream`: A pointer to the QUIC stream associated with the spam generator.
- **Description**: The `fd_quic_stream_spam_t` structure is a load generator designed to send unidirectional QUIC streams at maximum rate with sub-MTU size payloads. It utilizes a generator function to create random stream buffers, which are then sent over the associated QUIC stream. This structure is part of a system that tests QUIC stream handling by generating and sending random data streams.


# Function Declarations (Public API)

---
### fd\_quic\_stream\_spam\_new<!-- {{#callable_declaration:fd_quic_stream_spam_new}} -->
Allocate and initialize a QUIC stream spam generator.
- **Description**: This function sets up a new QUIC stream spam generator using the provided memory buffer. It initializes the generator with a function to produce stream data and an associated context. The memory buffer must be properly aligned and non-null. This function is typically used to prepare a spam generator for sending random QUIC stream data at maximum rate. It is important to ensure that the memory provided is correctly aligned to the requirements of `fd_quic_stream_spam_t` to avoid undefined behavior.
- **Inputs**:
    - `mem`: A pointer to a memory buffer where the spam generator will be initialized. Must not be null and must be aligned to `alignof(fd_quic_stream_spam_t)`. If these conditions are not met, the function returns null.
    - `gen_fn`: A function pointer of type `fd_quic_stream_gen_spam_t` that generates the stream data. This function will be called to fill the stream buffer with data.
    - `gen_ctx`: A context pointer that will be passed to the `gen_fn` each time it is called. The caller retains ownership of this context.
- **Output**: Returns a pointer to the initialized `fd_quic_stream_spam_t` structure on success, or null if the memory is null or misaligned.
- **See also**: [`fd_quic_stream_spam_new`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_new)  (Implementation)


---
### fd\_quic\_stream\_spam\_join<!-- {{#callable_declaration:fd_quic_stream_spam_join}} -->
Joins a shared QUIC stream spam object.
- **Description**: This function is used to join a shared QUIC stream spam object, which is a load generator for sending unidirectional streams at maximum rate. It should be called with a valid pointer to a shared memory region that represents a `fd_quic_stream_spam_t` object. The function checks for null pointers and proper alignment of the input pointer, returning null if these conditions are not met. This function is typically used after creating a shared spam object with `fd_quic_stream_spam_new` and before using it in operations like `fd_quic_stream_spam_service`.
- **Inputs**:
    - `shspam`: A pointer to a shared memory region representing a `fd_quic_stream_spam_t` object. Must not be null and must be properly aligned to the alignment requirements of `fd_quic_stream_spam_t`. If these conditions are not met, the function returns null.
- **Output**: Returns a pointer to a `fd_quic_stream_spam_t` object if successful, or null if the input is invalid.
- **See also**: [`fd_quic_stream_spam_join`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_join)  (Implementation)


---
### fd\_quic\_stream\_spam\_leave<!-- {{#callable_declaration:fd_quic_stream_spam_leave}} -->
Leaves a QUIC stream spam session.
- **Description**: This function is used to leave a QUIC stream spam session that was previously joined. It should be called when the spam session is no longer needed, allowing for any necessary cleanup or resource deallocation associated with the session. This function returns a pointer that can be used for further operations or cleanup. It is important to ensure that the `spam` parameter is valid and was obtained from a successful call to `fd_quic_stream_spam_join`.
- **Inputs**:
    - `spam`: A pointer to an `fd_quic_stream_spam_t` structure representing the spam session to leave. This must be a valid pointer obtained from a previous call to `fd_quic_stream_spam_join`. Passing an invalid or null pointer results in undefined behavior.
- **Output**: Returns a `void *` pointer, which is typically used for further operations or cleanup.
- **See also**: [`fd_quic_stream_spam_leave`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_leave)  (Implementation)


---
### fd\_quic\_stream\_spam\_delete<!-- {{#callable_declaration:fd_quic_stream_spam_delete}} -->
Deletes a QUIC stream spam object.
- **Description**: Use this function to delete a QUIC stream spam object that was previously created. It is typically called when the spam object is no longer needed, to clean up resources. The function expects a valid pointer to a spam object and will return the same pointer. Ensure that the pointer provided is not null and points to a valid spam object to avoid undefined behavior.
- **Inputs**:
    - `shspam`: A pointer to the QUIC stream spam object to be deleted. Must not be null and should point to a valid spam object. The function will return this pointer.
- **Output**: Returns the same pointer that was passed in, allowing for potential further handling or verification by the caller.
- **See also**: [`fd_quic_stream_spam_delete`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_delete)  (Implementation)


---
### fd\_quic\_stream\_spam\_service<!-- {{#callable_declaration:fd_quic_stream_spam_service}} -->
Initiates and sends as many random QUIC streams as possible.
- **Description**: This function is used to generate and send unidirectional QUIC streams at maximum rate using a specified load generator. It should be called when there is a need to test or simulate high-load conditions by sending multiple streams. The function attempts to create and send streams until it can no longer do so, either due to resource constraints or a fatal error. It is important to ensure that the connection and spam generator are properly initialized before calling this function. The function returns the number of streams successfully sent or -1 if a fatal error occurs.
- **Inputs**:
    - `conn`: A pointer to an fd_quic_conn_t structure representing the QUIC connection. Must not be null. The connection should be properly initialized and ready to handle new streams.
    - `spam`: A pointer to an fd_quic_stream_spam_t structure that acts as the load generator. Must not be null. It should be initialized with a valid stream generation function and context.
- **Output**: Returns the number of streams successfully sent. If a fatal error occurs, it returns -1.
- **See also**: [`fd_quic_stream_spam_service`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_service)  (Implementation)


---
### fd\_quic\_stream\_spam\_notify<!-- {{#callable_declaration:fd_quic_stream_spam_notify}} -->
Notifies the spammer of the impending finalization of a stream.
- **Description**: This function is used to inform the spammer that a QUIC stream is about to be finalized. It should be called when a stream, created during a `fd_quic_stream_spam_service()` call, is nearing its end of life. The function ensures that any pending operations related to the stream are marked appropriately to prevent further processing. It is important to note that the function assumes the stream was created by `fd_quic_stream_spam_service()`, and using it otherwise results in undefined behavior.
- **Inputs**:
    - `stream`: A pointer to the `fd_quic_stream_t` structure representing the stream to be finalized. The pointer must not be null.
    - `ctx`: A context pointer associated with the stream, which may point to a position in a pending list. If null, the function returns immediately, indicating no further action is needed.
    - `type`: An integer representing the type of notification. This parameter is currently unused and can be any value.
- **Output**: None
- **See also**: [`fd_quic_stream_spam_notify`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_notify)  (Implementation)


---
### fd\_quic\_stream\_spam\_gen<!-- {{#callable_declaration:fd_quic_stream_spam_gen}} -->
Generates a random QUIC stream payload.
- **Description**: This function is used to generate a random payload for a QUIC stream, filling the provided packet buffer with random data. It is typically used in scenarios where random data needs to be sent over a QUIC stream, such as in testing or load generation. The function modifies the packet buffer to contain the random payload and updates the buffer size to reflect the actual size of the generated payload. The context parameter is ignored, and the function relies on the stream ID to seed the random number generator.
- **Inputs**:
    - `ctx`: A context pointer that is ignored by this function. It can be null or any value, as it has no effect on the function's behavior.
    - `pkt`: A pointer to an fd_aio_pkt_info_t structure, which must not be null. On entry, pkt->buf should point to a writable buffer of pkt->buf_sz bytes. The function fills this buffer with random data and updates pkt->buf_sz to the actual size of the payload.
    - `stream_id`: An unsigned long integer representing the stream ID. It is used to seed the random number generator, ensuring that the generated data is unique to the stream.
- **Output**: None
- **See also**: [`fd_quic_stream_spam_gen`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_gen)  (Implementation)


