# Purpose
This Rust source code file defines a gRPC server using the Tonic library, which provides services related to block engine validation and authentication. The file implements two main services: `BlockEngineValidatorService` and `Auth`. The `BlockEngineValidatorService` is responsible for handling requests related to subscribing to packet and bundle streams, as well as retrieving block builder fee information. It uses asynchronous streams to continuously provide packet and bundle data, simulating a real-time data feed. The `Auth` service handles authentication-related requests, such as generating authentication challenges and tokens, and refreshing access tokens. These services are defined using the Tonic `async_trait` macro, which allows for asynchronous method implementations.

The file also includes the necessary protocol buffer module imports, which are used to define the data structures and service interfaces. The `main` function initializes the server, sets up logging, and binds the server to a specified address. It then adds the `BlockEngineValidatorService` and `Auth` services to the server and starts serving requests. This code is structured as a server application, providing a specific set of functionalities related to block engine validation and authentication, and is intended to be run as a standalone service rather than being imported as a library.
# Imports and Dependencies

---
- `std::iter`
- `std::pin::Pin`
- `crate::proto::auth`
- `crate::proto::auth::auth_service_server`
- `crate::proto::bundle`
- `crate::proto::packet`
- `chrono`
- `futures`
- `log`
- `prost_types::Timestamp`
- `tonic`
- `futures_util::stream::Stream`
- `base64::prelude`
- `crate::proto::block_engine::block_engine_validator_server`
- `crate::proto::block_engine`
- `tokio`


# Data Structures

---
### Auth
- **Type**: `struct`
- **Description**: The `Auth` struct is a simple data structure that implements the `AuthService` trait, providing methods for generating authentication challenges and tokens, as well as refreshing access tokens. It serves as a server-side component in a gRPC service, handling authentication-related requests and responses. The struct itself does not contain any fields, indicating that it relies on external state or services to perform its functions.

**Methods**

---
#### Auth::generate\_auth\_challenge
The `generate_auth_challenge` method generates a simple authentication challenge response for a client request.
- **Inputs**:
    - `&self`: A reference to the instance of the `Auth` struct, which implements the `AuthService` trait.
    - `_request`: A `Request` object containing a `GenerateAuthChallengeRequest`, which is not used in the method.
- **Control Flow**:
    - The method is defined as asynchronous and part of the `AuthService` trait implementation for the `Auth` struct.
    - It returns a `Result` containing a `Response` with a `GenerateAuthChallengeResponse` object.
    - The `GenerateAuthChallengeResponse` is constructed with a hardcoded challenge string "012345678".
- **Output**: A `Result` containing a `Response` with a `GenerateAuthChallengeResponse` object, which includes a hardcoded challenge string.


---
#### Auth::generate\_auth\_tokens
The `generate_auth_tokens` method generates and returns a pair of access and refresh tokens with expiration timestamps.
- **Inputs**:
    - `&self`: A reference to the instance of the `Auth` struct, which implements the `AuthService` trait.
    - `_request`: A `Request` object containing a `GenerateAuthTokensRequest`, which is not used in the method.
- **Control Flow**:
    - The method constructs an `access_token` and a `refresh_token`, both of which are `Token` objects.
    - Each `Token` object is initialized with a `value` set to "token" and an `expires_at_utc` timestamp set to 60 seconds from the current UTC time.
    - The method returns a `GenerateAuthTokensResponse` containing the `access_token` and `refresh_token`.
- **Output**: A `Result` containing a `Response` with a `GenerateAuthTokensResponse` that includes the generated access and refresh tokens.


---
#### Auth::refresh\_access\_token
The `refresh_access_token` method generates a new access token with a set expiration time and returns it in a response.
- **Inputs**:
    - `&self`: A reference to the instance of the `Auth` struct, which implements the `AuthService` trait.
    - `_request`: A `Request` object containing a `RefreshAccessTokenRequest`, which is not used in the method body.
- **Control Flow**:
    - The method constructs a new `Token` with a hardcoded value '012345678'.
    - The expiration time for the token is set to 60 seconds from the current UTC time.
    - A `RefreshAccessTokenResponse` is created containing the new access token.
    - The method returns an `Ok` result wrapping a `Response` object that contains the `RefreshAccessTokenResponse`.
- **Output**: A `Result` containing a `Response` with a `RefreshAccessTokenResponse` that includes the new access token.



---
### BlockEngineValidatorService
- **Type**: `struct`
- **Description**: The `BlockEngineValidatorService` is a Rust struct that implements the `BlockEngineValidator` trait, providing asynchronous methods for subscribing to packet and bundle streams, as well as retrieving block builder fee information. It serves as a server-side component in a gRPC service, handling requests related to block engine validation. The struct itself does not contain any fields, indicating that its functionality is entirely defined by its trait implementations.

**Methods**

---
#### BlockEngineValidatorService::get\_block\_builder\_fee\_info
The `get_block_builder_fee_info` method returns a response containing the block builder's fee commission and public key information.
- **Inputs**:
    - `&self`: A reference to the instance of `BlockEngineValidatorService` on which the method is called.
    - `_request`: A `Request` object containing a `BlockBuilderFeeInfoRequest`, which is not used in the method.
- **Control Flow**:
    - A `BlockBuilderFeeInfoResponse` object is created with a fixed commission value of 5 and a predefined public key string.
    - The method returns an `Ok` result wrapping a `Response` object that contains the `BlockBuilderFeeInfoResponse`.
- **Output**: A `Result` containing a `Response` with a `BlockBuilderFeeInfoResponse` object, or a `Status` error.


---
#### BlockEngineValidatorService::subscribe\_bundles
The `subscribe_bundles` method in the `BlockEngineValidatorService` struct asynchronously returns a stream of `SubscribeBundlesResponse` objects, each containing a list of bundles with associated packets.
- **Inputs**:
    - `&self`: A reference to the instance of `BlockEngineValidatorService` on which the method is called.
    - `_request`: A `Request` object containing a `SubscribeBundlesRequest`, which is not used in the method's logic.
- **Control Flow**:
    - The method returns an `Ok` result containing a `Response` object.
    - The `Response` object wraps a stream created using `stream::iter` and `iter::repeat_with`.
    - The stream repeatedly generates `SubscribeBundlesResponse` objects.
    - Each `SubscribeBundlesResponse` contains a vector of `BundleUuid` objects.
    - Each `BundleUuid` has a `uuid` and an optional `Bundle` object.
    - The `Bundle` object contains a vector of `Packet` objects.
    - Each `Packet` object has a `meta` field set to `None` and a `data` field containing decoded base64 data.
- **Output**: A `Result` containing a `Response` object that wraps a stream of `SubscribeBundlesResponse` objects.


---
#### BlockEngineValidatorService::subscribe\_packets
The `subscribe_packets` method in the `BlockEngineValidatorService` asynchronously streams a repeated sequence of `SubscribePacketsResponse` objects containing packet batches.
- **Inputs**:
    - `&self`: A reference to the instance of `BlockEngineValidatorService` on which the method is called.
    - `_request`: A `Request` object containing a `SubscribePacketsRequest`, which is not used in the method.
- **Control Flow**:
    - The method returns an `Ok` result containing a `Response` object.
    - The `Response` object wraps a stream that is created using `stream::iter` and `iter::repeat_with`.
    - The stream repeatedly generates `SubscribePacketsResponse` objects.
    - Each `SubscribePacketsResponse` contains a `PacketBatch` with two `Packet` objects.
    - Each `Packet` object has a `data` field initialized with a vector of 1232 zeroes.
- **Output**: A `Result` containing a `Response` object that wraps a stream of `SubscribePacketsResponse` objects, or a `Status` error.



# Functions

---
### main
The `main` function initializes logging, sets up a gRPC server, and starts serving the Block Engine Validator and Auth services on a specified address.
- **Inputs**: None
- **Control Flow**:
    - Initialize the logger using `env_logger::init()` to enable logging for the application.
    - Parse the server address from the string "127.0.0.1:50051" into a `SocketAddr` object.
    - Log an informational message indicating that the Block Engine Validator Server is listening on the specified address.
    - Create a gRPC server builder using `Server::builder()`.
    - Add the `BlockEngineValidatorService` to the server using `add_service` with `BlockEngineValidatorServer::new`.
    - Add the `Auth` service to the server using `add_service` with `AuthServiceServer::new`.
    - Start the server to listen and serve on the specified address using `serve(addr).await`.
    - Return `Ok(())` if the server starts successfully, otherwise propagate any errors.
- **Output**: Returns `Result<(), Box<dyn std::error::Error>>`, indicating success or an error if the server fails to start.


