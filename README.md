# owl-crypto-py

A Python implementation of the Owl augmented PAKE (Password-Authenticated Key Exchange) protocol, based on the [Owl paper](https://eprint.iacr.org/2023/768.pdf).

## Installation

To install the package, run: 

```bash
pip install owl-crypto-py
```

Or install directly from the repository:

```bash
git clone https://github.com/Nick-Maro/owl-py.git
cd owl-crypto-py
pip install -e .
```

### Dependencies

```bash
pip install cryptography
```

## Features

- **Secure Password-Based Authentication**: Implements the Owl augmented PAKE protocol
- **Zero-Knowledge Proofs**: Password is never transmitted or revealed
- **Server Compromise Resistance**: Even if the server is compromised, passwords remain secure
- **Forward Secrecy**: Session keys cannot be recovered even if passwords are later compromised
- **Standard Elliptic Curves**: Support for P-256, P-384, P-521
## Documentation

For detailed information about the protocol and API:

- **[API Reference](api_reference.md)** - Complete API documentation for all classes and methods
- **[Protocol Flow](flow.md)** - Mathematical details and cryptographic flow of the Owl protocol
## Quick Start

### Basic Setup

```python
from owl_crypto_py import (
    OwlClient, 
    OwlServer, 
    Config, 
    Curves
)

# Create configuration (must be the same for client and server)
config = Config(
    curve=Curves.P256,
    serverId="example.com"
)

# Initialize client and server
client = OwlClient(config)
server = OwlServer(config)
```

### Supported Curves

The possible values of `Curves` are:
- `Curves.P256` - NIST P-256 curve (recommended for most uses)
- `Curves.P384` - NIST P-384 curve (higher security)
- `Curves.P521` - NIST P-521 curve (maximum security)





## Message Types

The Owl protocol uses structured messages for communication between client and server. All messages can be serialized to JSON using the `to_json()` method and deserialized using the `deserialize()` class method.

### Message Classes

- **`RegistrationRequest`** - Contains values from `OwlClient.register()`, used by `OwlServer.register()`
- **`UserCredentials`** - User credentials to be stored permanently in the database alongside the username
- **`AuthInitRequest`** - Contains values from `OwlClient.authInit()`, used by `OwlServer.authInit()`
- **`AuthInitialValues`** - Temporary values from `OwlServer.authInit()`, stored in session and used by `OwlServer.authFinish()`. Can be deleted after authentication completes
- **`AuthInitResponse`** - Contains values from `OwlServer.authInit()`, used by `OwlClient.authFinish()`
- **`AuthFinishRequest`** - Contains values from `OwlClient.authFinish()`, used by `OwlServer.authFinish()`



##  Exception Types

The library defines several exception types for error handling:

```python
from owl_crypto_py import (
    ZKPVerificationFailure,      # Zero-knowledge proof verification failed
    AuthenticationFailure,        # Authentication credentials invalid
    UninitialisedClientError,     # authInit must be called before authFinish
    DeserializationError          # Message deserialization failed
)
```

##  Architecture

The protocol follows a three-message authentication flow:

1. **Client → Server**: Authentication initialization with ephemeral values
2. **Server → Client**: Server response with ephemeral values and challenges
3. **Client → Server**: Final authentication proof

Both parties derive the same shared key without ever transmitting the password or any value that could be used to recover it.

##  Security Properties

- **Password Never Transmitted**: The password is never sent over the network
- **Zero-Knowledge**: Authentication doesn't reveal information about the password
- **Server Compromise Resistance**: Server breach doesn't expose passwords
- **Forward Secrecy**: Past session keys remain secure even if password is compromised
- **Mutual Authentication**: Both client and server authenticate each other
- **Active Attack Protection**: Zero-knowledge proofs prevent man-in-the-middle attacks

##  Complete Example

See the `examples/` directory for complete working examples:

```python
import asyncio
from owl_crypto_py import (
    OwlClient,
    OwlServer,
    Config,
    Curves,
    RegistrationRequest,
    UserCredentials,
    AuthInitRequest,
    AuthInitResponse,
    AuthInitialValues,
    AuthFinishRequest,
    ZKPVerificationFailure,
    AuthenticationFailure,
    UninitialisedClientError,
    DeserializationError
)


async def registration_flow():


    
    # Setup
    config = Config(curve=Curves.P256, serverId="example.com")
    client = OwlClient(config)
    server = OwlServer(config)
    
    # Step 1: Client creates registration request
    username = "alice"
    password = "secure_password_123"
    print(f"Client: Registering user '{username}'")
    registration_request = await client.register(username, password)
    
    # Step 2: Send registration_request to server (serialize)
    registration_json = registration_request.to_json()
    print(f"Client  Server: Sending registration request")
    
    # Step 3: Server receives and deserializes
    registration_request = RegistrationRequest.deserialize(registration_json, config)
    if isinstance(registration_request, DeserializationError):
        print(f"Server: Deserialization failed: {registration_request}")
        return None
    
    # Step 4: Server processes registration
    print(f"Server: Processing registration for '{username}'")
    user_credentials = await server.register(registration_request)
    
    # Step 5: Store credentials in database
    credentials_json = user_credentials.to_json()
    print(f"Server: User '{username}' registered successfully")
    print(f"Server: Credentials stored in database\n")
    
    return credentials_json


async def authentication_flow(credentials_from_db):

    
    # Setup
    config = Config(curve=Curves.P256, serverId="example.com")
    client = OwlClient(config)
    server = OwlServer(config)
    
    username = "alice"
    password = "secure_password_123"
    
    # Step 1: Client initiates authentication
    print(f"Client: Initiating authentication for '{username}'")
    auth_init_request = await client.authInit(username, password)
    
    # Step 2: Send auth_init_request to server
    auth_init_json = auth_init_request.to_json()
    print(f"Client Server: Sending authentication request")
    
    # Step 3: Server receives and deserializes
    auth_init_request = AuthInitRequest.deserialize(auth_init_json, config)
    if isinstance(auth_init_request, DeserializationError):
        print(f"Server: Deserialization failed: {auth_init_request}")
        return False
    
    # Load user credentials from database
    user_credentials = UserCredentials.deserialize(credentials_from_db, config)
    if isinstance(user_credentials, DeserializationError):
        print(f"Server: Failed to load credentials: {user_credentials}")
        return False
    
    # Step 4: Server processes initial authentication
    print(f"Server: Processing authentication for '{username}'")
    auth_init_result = await server.authInit(username, auth_init_request, user_credentials)
    
    if isinstance(auth_init_result, ZKPVerificationFailure):
        print("Server: Authentication failed - Invalid proof")
        return False
    
    # Step 5: Store initial values temporarily (in session)
    initial_values_json = auth_init_result.initial.to_json()
    print(f"Server: Storing session data for '{username}'")
    
    # Step 6: Send response to client
    response_json = auth_init_result.response.to_json()
    print(f"Server  Client: Sending authentication response")
    
    # Step 7: Client receives and deserializes
    auth_init_response = AuthInitResponse.deserialize(response_json, config)
    if isinstance(auth_init_response, DeserializationError):
        print(f"Client: Deserialization failed: {auth_init_response}")
        return False
    
    # Step 8: Client finishes authentication
    print(f"Client: Completing authentication")
    auth_finish_result = await client.authFinish(auth_init_response)
    
    if isinstance(auth_finish_result, ZKPVerificationFailure):
        print("Client: Authentication failed - Invalid server proof")
        return False
    elif isinstance(auth_finish_result, UninitialisedClientError):
        print("Client: Error - authInit must be called before authFinish")
        return False
    
    # Step 9: Send finish request to server
    finish_request_json = auth_finish_result.finishRequest.to_json()
    client_key = auth_finish_result.key
    client_kc = auth_finish_result.kc
    client_kcTest = auth_finish_result.kcTest
    print(f"Client  Server: Sending final authentication proof")
    
    # Step 10: Server receives and deserializes
    auth_finish_request = AuthFinishRequest.deserialize(finish_request_json, config)
    if isinstance(auth_finish_request, DeserializationError):
        print(f"Server: Deserialization failed: {auth_finish_request}")
        return False
    
    # Load initial values from session
    initial_values = AuthInitialValues.deserialize(initial_values_json, config)
    if isinstance(initial_values, DeserializationError):
        print(f"Server: Failed to load session data: {initial_values}")
        return False
    
    # Step 11: Server completes authentication
    print(f"Server: Verifying final authentication proof")
    server_finish_result = await server.authFinish(username, auth_finish_request, initial_values)
    
    if isinstance(server_finish_result, ZKPVerificationFailure):
        print("Server: Authentication failed - Invalid client proof")
        return False
    elif isinstance(server_finish_result, AuthenticationFailure):
        print("Server: Authentication failed - Invalid credentials")
        return False
    
    # Step 12: Both parties verify key confirmation
    server_key = server_finish_result.key
    server_kc = server_finish_result.kc
    server_kcTest = server_finish_result.kcTest
    
    print(f"\nVerifying key confirmation...")
    if client_kcTest == server_kc and server_kcTest == client_kc:
        print(" Key confirmation successful!")
        print(f" Authentication successful for '{username}'!")
        print(f"\nShared key established:")
        print(f"  Client key: {client_key.hex()}")
        print(f"  Server key: {server_key.hex()}")
        print(f"  Keys match: {client_key == server_key}")
        return True
    else:
        print(" Key confirmation failed")
        return False


async def main():
    """Main function to run complete flow"""
    print("\n" + "="*50)
    print("OWL PROTOCOL - COMPLETE EXAMPLE")
    print("="*50 + "\n")
    
    # Step 1: Registration
    credentials = await registration_flow()
    
    if credentials is None:
        print("\n Registration failed")
        return
    
    # Step 2: Authentication
    success = await authentication_flow(credentials)
    
    if success:
        print("\n" + "="*50)
        print(" ALL STEPS COMPLETED SUCCESSFULLY")
        print("="*50)
    else:
        print("\n" + "="*50)
        print(" AUTHENTICATION FAILED")
        print("="*50)


if __name__ == "__main__":
    asyncio.run(main())
```

##  Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a branch for your feature (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

##  License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for details.

##  Acknowledgments

- Based on the [Owl paper](https://eprint.iacr.org/2023/768.pdf) by Jarecki et al.
- Inspired by the TypeScript implementation [owl-ts](https://github.com/henry50/owl-ts)

##  References

- [Owl: Compositional Verification of Security Protocols via an Information-Flow Type System](https://eprint.iacr.org/2023/768.pdf)
- [NIST Elliptic Curves](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)

---

**Made with ❤️ in Python**