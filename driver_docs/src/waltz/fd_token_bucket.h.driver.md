# Purpose
This C header file defines a simple token bucket rate-limiting mechanism, which is a common algorithm used to control the amount of data that can be processed over time. The file includes the definition of a `struct fd_token_bucket`, which holds the state of the token bucket, including the last timestamp (`ts`), the rate of token generation (`rate`), the maximum burst size (`burst`), and the current token balance (`balance`). It also provides an inline function [`fd_token_bucket_consume`](#fd_token_bucket_consume) that attempts to consume a specified amount of tokens (`delta`) from the bucket, updating the token balance based on the elapsed time since the last operation and the rate of token generation. The function returns a boolean indicating whether the requested tokens could be successfully consumed, effectively enforcing the rate limit. This header file is designed to be included in other C source files that require rate-limiting functionality.
# Imports and Dependencies

---
- `../util/fd_util_base.h`
- `math.h`


# Data Structures

---
### fd\_token\_bucket
- **Type**: `struct`
- **Members**:
    - `ts`: Represents the timestamp of the last update to the token bucket.
    - `rate`: Indicates the rate at which tokens are added to the bucket over time.
    - `burst`: Defines the maximum number of tokens that the bucket can hold.
    - `balance`: Stores the current number of tokens available in the bucket.
- **Description**: The `fd_token_bucket` structure is used to implement a token bucket algorithm, which is a mechanism for controlling the amount of data that can be sent or received over a network. It consists of a timestamp (`ts`) to track the last update, a `rate` to determine how quickly tokens are added, a `burst` capacity to limit the maximum tokens, and a `balance` to keep track of the current token count. This structure is typically used in network traffic shaping and rate limiting scenarios.


---
### fd\_token\_bucket\_t
- **Type**: `struct`
- **Members**:
    - `ts`: A long integer representing the timestamp of the last token bucket update.
    - `rate`: A float representing the rate at which tokens are added to the bucket over time.
    - `burst`: A float representing the maximum number of tokens the bucket can hold.
    - `balance`: A float representing the current number of tokens available in the bucket.
- **Description**: The `fd_token_bucket_t` structure is used to implement a token bucket algorithm, which is a rate-limiting mechanism. It maintains a balance of tokens that are refilled over time at a specified rate, up to a maximum burst capacity. The structure tracks the last update timestamp, the rate of token addition, the maximum burst capacity, and the current token balance, allowing for controlled consumption of tokens based on these parameters.


# Functions

---
### fd\_token\_bucket\_consume<!-- {{#callable:fd_token_bucket_consume}} -->
The `fd_token_bucket_consume` function attempts to consume a specified amount of tokens from a token bucket, refilling it based on elapsed time and returning whether the consumption was successful.
- **Inputs**:
    - `bucket`: A pointer to an `fd_token_bucket_t` structure representing the token bucket from which tokens are to be consumed.
    - `delta`: A float representing the number of tokens to be consumed from the bucket.
    - `ts`: A long integer representing the current timestamp, used to calculate the elapsed time since the last operation on the bucket.
- **Control Flow**:
    - Calculate the elapsed time since the last token bucket operation by subtracting the stored timestamp from the current timestamp.
    - Refill the token bucket by adding tokens based on the elapsed time and the bucket's refill rate, ensuring the balance does not exceed the maximum burst capacity.
    - Check if the requested number of tokens (`delta`) can be consumed from the current balance.
    - If consumption is possible, subtract the requested tokens from the balance.
    - Update the token bucket's balance and timestamp with the new values.
    - Return a boolean indicating whether the token consumption was successful.
- **Output**: An integer value (boolean) indicating whether the token consumption was successful (1 if successful, 0 otherwise).


