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
- **Elliptic Curves**: Supports P-256, P-384, P-521, and FourQ (experimental). Implementation of Curve25519 is in progress. could work on secp256k1 too
- **Constant-Time Key Confirmation**: Uses `hmac.compare_digest` to prevent timing attacks
- **Synchronous API**: Sync wrappers (`register_sync`, `authInit_sync`, `authFinish_sync`) for non-async contexts
- **Secret Cleanup**: Ephemeral secrets are cleared from memory after use

## Why Owl?

### Advantages over OPAQUE

Owl offers several practical improvements over OPAQUE:

1. **Simpler Implementation Without Hash-to-Curve**
   - OPAQUE needs a constant-time hash-to-curve function that's difficult to implement correctly
   - This requirement makes OPAQUE undefined for multiplicative groups
   - Owl works with standard elliptic curve operations and hash functions you already have

2. **Better Privacy for Password Changes**
   - OPAQUE sends a pre-computed ciphertext that changes whenever you update your password
   - Attackers monitoring login sessions can spot who hasn't changed their password and target them first
   - Owl doesn't leak this information

3. **Works Reliably in DSA Groups**
   - OPAQUE can produce invalid outputs when used with DSA groups
   - Owl handles these cases properly

4. **Use Any Elliptic Curve**
   - Owl works with any cryptographically suitable elliptic curve
   - OPAQUE only works where a correct hash-to-curve function exists

5. **Faster Registration**
   - Owl needs just one message exchange for registration
   - Other protocols require more back-and-forth

6. **Less Work for Clients**
   - In DSA implementations, Owl requires fewer computations on the client side than OPAQUE

### Advantages over Traditional Password Authentication (OAuth, etc.)

Traditional authentication systems like OAuth use symmetric approaches where both client and server know the password (or its hash). Owl's augmented approach provides important security benefits:

1. **Server Breaches Don't Expose Passwords**
   - In traditional systems, stolen credentials let attackers impersonate users immediately
   - With Owl, attackers must perform expensive offline cracking for each password
   - No need for hardware security modules or distributed servers

2. **One-Way Password Storage**
   - The server only stores a cryptographic transformation of the password
   - Recovery requires brute-force guessing through possible passwords

3. **More Efficient Than Similar Protocols**
   - Owl provides better security than symmetric PAKE protocols like J-PAKE
   - But uses less computation overall

4. **Protection for Old Sessions**
   - Even if an attacker learns your password later, they can't decrypt past session keys
   - Your previous communications stay secure

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
    OwlCommon,
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
- `Curves.FOURQ` - FourQ curve (high performance, experimental)

## Synchronous API

If you don't need `async`/`await`, every method has a `_sync` variant:

```python
client = OwlClient(config)
server = OwlServer(config)

# Registration
reg_request = client.register_sync("alice", "password123")
credentials = server.register_sync(reg_request)

# Authentication
auth_request = client.authInit_sync("alice", "password123")
result = server.authInit_sync("alice", auth_request, credentials)
finish = client.authFinish_sync(result.response)
server_result = server.authFinish_sync("alice", finish.finishRequest, result.initial)
```

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

### Key Confirmation Helper

Use `OwlCommon.verifyKeyConfirmation()` for constant-time comparison of key confirmation values (prevents timing attacks):

```python
from owl_crypto_py import OwlCommon

# After both sides complete authentication:
if OwlCommon.verifyKeyConfirmation(client_kcTest, server_kc):
    print("Key confirmation passed")
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
- **Identity Element Checks**: Rejects X₂ = 1 (server) and X₄ = 1 (client) to prevent small-subgroup attacks
- **Non-Zero π Validation**: Ensures the password verifier π != 0 mod n

##  Complete Example

Complete example:

```python
import asyncio
from owl_crypto_py import (
    OwlClient,
    OwlServer,
    OwlCommon,
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
    # Use constant-time comparison to prevent timing attacks
    if (OwlCommon.verifyKeyConfirmation(client_kcTest, server_kc)
            and OwlCommon.verifyKeyConfirmation(server_kcTest, client_kc)):
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
## Tests

Run the test suite:

```bash
python tests.py
```

Tests cover all four supported curves (P-256, P-384, P-521, FourQ) with both successful authentication and wrong-password rejection cases (8 tests total).

A comprehensive example covering the full async flow, sync API, serialization round-trips, and wrong-password handling is in `examples/example_full.py`.
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

- Based on the [Owl paper](https://eprint.iacr.org/2023/768.pdf) by Feng Hao, Samiran Bag, Liqun Chen, and Paul C. van Oorschot
- Inspired by the TypeScript implementation [owl-ts](https://github.com/henry50/owl-ts)

##  References

- [Owl: An Augmented Password-Authenticated Key Exchange Scheme](https://eprint.iacr.org/2023/768.pdf)
- [NIST Elliptic Curves](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)

---

**Owls have asymmetrical ears, which give them a natural advantage in locating the source of sound in darkness** -Feng Hao