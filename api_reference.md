# OWL Protocol - API Reference

## Overview

Implementation of a Password-Authenticated Key Exchange (PAKE) protocol using elliptic curve cryptography and Zero-Knowledge Proofs.

---

## Configuration

### `Config`

```python
Config(curve: Curves, serverId: str)
```

**Parameters:**
- `curve` - Elliptic curve to use (P256, P384, P521, or FOURQ)
- `serverId` - Unique identifier for the server

**Example:**
```python
config = Config(curve=Curves.P256, serverId="server123")
```

---

## Client API

### `OwlClient.register(username: str, password: str) -> RegistrationRequest`

Generate registration request without transmitting the password.

**Process:**
1. Computes `t = H(username || password) mod n`
2. Derives password verifier `pi = H(t) mod n` (raises `ValueError` if `pi == 0`)
3. Creates public commitment `T = G * t`

**Returns:** `RegistrationRequest(pi, T)` to send to server

**Example:**
```python
client = OwlClient(config)
reg_request = await client.register("alice", "password123")
```

---

### `OwlClient.authInit(username: str, password: str) -> AuthInitRequest`

Initialize authentication by generating ephemeral secrets and Zero-Knowledge Proofs.

**Process:**
1. Re-derives `t` and `pi` from credentials
2. Generates random secrets `x1`, `x2`
3. Computes `X1 = G * x1`, `X2 = G * x2`
4. Creates ZKPs proving knowledge of `x1` and `x2`

**Returns:** `AuthInitRequest(X1, X2, PI1, PI2)` to send to server

**Example:**
```python
auth_request = await client.authInit("alice", "password123")
```

---

### `OwlClient.authFinish(response: AuthInitResponse) -> AuthFinishResult`

Complete authentication and derive shared session key.

**Process:**
1. Verifies server's Zero-Knowledge Proofs
2. Verifies X₄ ≠ identity element
3. Computes shared secret point: `K = (beta - X4*(x2*pi)) * x2`
4. Derives session key: `k = H(K)`
5. Includes Π₄ in transcript hash for full protocol compliance
6. Generates proof of password knowledge: `r = x1 - (t * h) mod n`
7. Clears ephemeral secrets from memory after computation

**Returns:** 
- `finishRequest` - Final message to send to server
- `key` - 32-byte session key
- `kc` - Key confirmation for mutual verification

**Example:**
```python
result = await client.authFinish(server_response)
session_key = result.key  # Use this for encryption
```

---

### Synchronous Client Wrappers

```python
client.register_sync(username, password)   # RegistrationRequest
client.authInit_sync(username, password)    #  AuthInitRequest
client.authFinish_sync(response)            # AuthFinishResult
```

Convenience methods that call `asyncio.run()` internally. Use when running outside an async context.

---

## Server API

### `OwlServer.register(request: RegistrationRequest) -> UserCredentials`

Process registration and generate server credentials.

**Process:**
1. Generates server secret `x3`
2. Computes `X3 = G * x3`
3. Creates ZKP proving knowledge of `x3`

**Returns:** `UserCredentials` to store in database

**Example:**
```python
server = OwlServer(config)
credentials = await server.register(client_request)
database.save("alice", credentials)
```

---

### `OwlServer.authInit(username: str, request: AuthInitRequest, credentials: UserCredentials) -> AuthInitResult`

Process authentication initialization with ZKP verification.

**Process:**
1. Verifies client's ZKPs (PI1, PI2)
2. Verifies X₂ ≠ identity element
3. Generates ephemeral secret `x4`
4. Computes shared component: `beta = (X1+X2+X3) * (pi*x4)`
5. Creates ZKPs for `X4` and `beta`

**Returns:**
- `response` - Message to send to client
- `initial` - State to store for `authFinish()`

**Example:**
```python
credentials = database.get("alice")
result = await server.authInit("alice", client_request, credentials)
session.store(result.initial)
```

---

### `OwlServer.authFinish(username: str, request: AuthFinishRequest, initial: AuthInitialValues) -> AuthFinishResult`

Verify password and derive shared session key.

**Process:**
1. Verifies client's alpha ZKP
2. Derives shared key: `K = (alpha - X2*(x4*pi)) * x4`
3. **Verifies password:** `G*r + T*h == X1`
4. Generates session key: `k = H(K)`

**Returns:**
- `key` - 32-byte session key (matches client's)
- `kc` - Key confirmation for mutual verification

**Example:**
```python
result = await server.authFinish(username, client_request, initial)
if isinstance(result, AuthenticationFailure):
    return "Invalid password"
session_key = result.key
```

---

### Synchronous Server Wrappers

```python
server.register_sync(request)                              # UserCredentials
server.authInit_sync(username, request, credentials)       # AuthInitResult | ZKPVerificationFailure
server.authFinish_sync(username, request, initial)         # AuthFinishResult | AuthenticationFailure | ZKPVerificationFailure
```

Convenience methods that call `asyncio.run()` internally.

---

## OwlCommon

### `OwlCommon.verifyKeyConfirmation(my_kc_test: str, received_kc: str) -> bool`

Constant-time comparison of key confirmation values using `hmac.compare_digest`. Prevents timing side-channel attacks.

**Parameters:**
- `my_kc_test` - The expected key confirmation string computed locally
- `received_kc` - The key confirmation string received from the other party

**Returns:** `True` if the values match

**Example:**
```python
from owl_crypto_py import OwlCommon

client_ok = OwlCommon.verifyKeyConfirmation(client_result.kcTest, server_result.kc)
server_ok = OwlCommon.verifyKeyConfirmation(server_result.kcTest, client_result.kc)
if client_ok and server_ok:
    print("Mutual authentication confirmed")
```

---

## Core Cryptographic Functions

### `Point` Class

Elliptic curve point with cryptographic operations.

**Key Methods:**
```python
# Scalar multiplication (main operation for key derivation)
result = point.multiply(scalar)  # Returns scalar * point

# Point addition (for combining public keys)
sum = point1.add(point2)

# Point subtraction (for computing shared secrets)
diff = point1.subtract(point2)

# Serialization for network transmission
hex_str = point.to_hex()
point = Point.from_hex(hex_str, curve)
```

---

### `createZKP(x: int, G: Point, X: Point, prover: str) -> ZKP`

Create Zero-Knowledge Proof that proves knowledge of `x` where `X = G*x`, without revealing `x`.

**Process:**
1. Generates random nonce `v`
2. Computes commitment `V = G * v`
3. Computes challenge `h = H(G, V, X, prover)`
4. Computes response `r = v - x*h mod n`

**Returns:** `ZKP(h, r)` that can be verified by anyone

---

### `verifyZKP(zkp: ZKP, G: Point, X: Point, prover: str) -> bool`

Verify Zero-Knowledge Proof without learning the secret.

**Verification:**
1. Reconstructs commitment: `V = G*r + X*h`
2. Recomputes challenge: `h' = H(G, V, X, prover)`
3. Checks if `h == h'`

**Returns:** `True` if proof is valid