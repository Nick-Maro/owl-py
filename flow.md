# Owl Protocol - Mathematical Flow and Implementation

## Overview
Owl is an augmented PAKE (Password-Authenticated Key Exchange) protocol that allows client and server to establish a shared key based on a password, with protection against server compromise.

---

## 1. Initial Setup

### System Parameters
- **Group**: Elliptic curve (P-256, P-384, or P-521)
- **G**: Curve generator
- **n**: Group order (prime)
- **H**: SHA-256 hash function

### Implementation: `owl_common.py`
```python
class OwlCommon:
    def __init__(self, config: Config):
        # Curve selection and parameter setup
        if curve == Curves.P256:
            self.n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
            Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
            Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        self.G = Point(Gx, Gy, self.curve_obj)
```

---

## 2. Registration Phase

### Mathematics
```
Client (U, w):
    t = H(U || w) mod n
    π = H(t) mod n
    T = G * t
    
    → Sends (U, π, T) to server via secure channel

Server:
    x₃ ∈ R [1, n-1]
    X₃ = G * x₃
    Π₃ = ZKP{x₃}
    
    Stores: {U: X₃, Π₃, π, T}
```

### Implementation

#### Client: `owl_client.py::register()`
```python
async def register(self, username: str, password: str) -> RegistrationRequest:
    # t = H(U||w) mod n
    t = self.modN(await self.H(username + password))
    
    # π = H(t) mod n
    pi = self.modN(await self.H(t))
    
    # T = G * t
    T = self.G.multiply(t)
    
    return RegistrationRequest(pi, T)
```

#### Server: `owl_server.py::register()`
```python
async def register(self, request: RegistrationRequest) -> UserCredentials:
    pi = request.pi
    T = request.T
    
    # x₃ ∈ R [1, n-1]
    x3 = self.rand(1, self.n - 1)
    
    # X₃ = G * x₃
    X3 = self.G.multiply(x3)
    
    # Π₃ = ZKP{x₃}
    PI3 = await self.createZKP(x3, self.G, X3, self.serverId)
    
    return UserCredentials(X3, PI3, pi, T)
```

---

## 3. Login Phase - Flow 1: Client → Server

### Mathematics
```
Client (U, w):
    t = H(U || w) mod n
    π = H(t) mod n
    
    x₁ ∈ R [1, n-1]
    x₂ ∈ R [1, n-1]
    
    X₁ = G * x₁
    X₂ = G * x₂
    
    Π₁ = ZKP{x₁}: proves knowledge of x₁
    Π₂ = ZKP{x₂}: proves knowledge of x₂
    
    → Sends (U, X₁, X₂, Π₁, Π₂)
```

### Implementation: `owl_client.py::authInit()`
```python
async def authInit(self, username: str, password: str) -> AuthInitRequest:
    # t = H(U||w) mod n
    t = self.modN(await self.H(username + password))
    
    # π = H(t) mod n
    pi = self.modN(await self.H(t))
    
    # x₁ ∈ R [1, n-1]
    x1 = self.rand(1, self.n - 1)
    
    # x₂ ∈ R [1, n-1]
    x2 = self.rand(1, self.n - 1)
    
    # X₁ = G * x₁
    X1 = self.G.multiply(x1)
    
    # X₂ = G * x₂
    X2 = self.G.multiply(x2)
    
    # Π₁ = ZKP{x₁}
    PI1 = await self.createZKP(x1, self.G, X1, username)
    
    # Π₂ = ZKP{x₂}
    PI2 = await self.createZKP(x2, self.G, X2, username)
    
    # Save values for authFinish
    self.initValues = ClientInitVals(username, t, pi, x1, x2, X1, X2, PI1, PI2)
    
    return AuthInitRequest(X1, X2, PI1, PI2)
```

---

## 4. Login Phase - Flow 2: Server → Client

### Mathematics
```
Server:
    Verifies Π₁, Π₂
    Verifies X₂ ≠ 1
    
    x₄ ∈ R [1, n-1]
    X₄ = G * x₄
    Π₄ = ZKP{x₄}
    
    secret = x₄ * π mod n
    betaG = X₁ + X₂ + X₃
    β = betaG * secret = (X₁ + X₂ + X₃)^(x₄·π)
    Π_β = ZKP{x₄ · π}
    
    ← Sends (S, X₃, X₄, Π₃, Π₄, β, Π_β)
```

### Implementation: `owl_server.py::authInit()`
```python
async def authInit(
    self,
    username: str,
    request: AuthInitRequest,
    credentials: UserCredentials,
) -> Union[AuthInitResult, ZKPVerificationFailure]:
    X1 = request.X1
    X2 = request.X2
    PI1 = request.PI1
    PI2 = request.PI2
    
    X3 = credentials.X3
    PI3 = credentials.PI3
    pi = credentials.pi
    T = credentials.T
    
    # Verify ZKPs
    if (
        not await self.verifyZKP(PI1, self.G, X1, username)
        or not await self.verifyZKP(PI2, self.G, X2, username)
    ):
        return ZKPVerificationFailure()
    
    # x₄ ∈ R [1, n-1]
    x4 = self.rand(1, self.n - 1)
    
    # X₄ = G * x₄
    X4 = self.G.multiply(x4)
    
    # Π₄ = ZKP{x₄}
    PI4 = await self.createZKP(x4, self.G, X4, self.serverId)
    
    # secret = x₄ * π mod n
    secret = self.modN(x4 * pi)
    
    # betaG = X₁ + X₂ + X₃
    betaG = X1.add(X2).add(X3)
    
    # β = betaG * secret = (X₁+X₂+X₃)^(x₄·π)
    beta = betaG.multiply(secret)
    
    # Π_β = ZKP{x₄ · π}
    PIBeta = await self.createZKP(secret, betaG, beta, self.serverId)
    
    response = AuthInitResponse(X3, X4, PI3, PI4, beta, PIBeta)
    initial = AuthInitialValues(T, pi, x4, X1, X2, X3, X4, beta, PI1, PI2, PI3, PIBeta)
    
    return AuthInitResult(response=response, initial=initial)
```

---

## 5. Login Phase - Flow 3: Client → Server

### Mathematics
```
Client:
    Verifies Π₃, Π₄, Π_β
    Verifies X₄ ≠ 1
    
    secret = x₂ * π mod n
    alphaG = X₁ + X₃ + X₄
    α = alphaG * secret = (X₁ + X₃ + X₄)^(x₂·π)
    Π_α = ZKP{x₂ · π}
    
    K = (β - X₄^(x₂·π)) * x₂
    h = H(K || Transcript)
    r = x₁ - t·h mod n
    
    → Sends (α, Π_α, r)
```

### Implementation: `owl_client.py::authFinish()`
```python
async def authFinish(
    self, response: AuthInitResponse
) -> Union[AuthFinishResult, ZKPVerificationFailure, UninitialisedClientError]:
    # Retrieve saved values
    x1 = self.initValues.x1
    x2 = self.initValues.x2
    t = self.initValues.t
    pi = self.initValues.pi
    X1 = self.initValues.X1
    X2 = self.initValues.X2
    PI1 = self.initValues.PI1
    PI2 = self.initValues.PI2
    
    X3 = response.X3
    X4 = response.X4
    PI3 = response.PI3
    PI4 = response.PI4
    beta = response.beta
    PIBeta = response.PIBeta
    
    # Verify ZKPs
    betaG = X1.add(X2).add(X3)
    if (
        not await self.verifyZKP(PI3, self.G, X3, self.serverId)
        or not await self.verifyZKP(PI4, self.G, X4, self.serverId)
        or not await self.verifyZKP(PIBeta, betaG, beta, self.serverId)
    ):
        return ZKPVerificationFailure()
    
    # secret = x₂ * π mod n
    secret = self.modN(x2 * pi)
    
    # alphaG = X₁ + X₃ + X₄
    alphaG = X1.add(X3).add(X4)
    
    # α = alphaG * secret = (X₁+X₃+X₄)^(x₂·π)
    alpha = alphaG.multiply(secret)
    
    # Π_α = ZKP{x₂ · π}
    PIAlpha = await self.createZKP(secret, alphaG, alpha, username)
    
    # K = (β - X₄^(x₂·π)) * x₂
    K = beta.subtract(X4.multiply(secret)).multiply(x2)
    
    # h = H(K || Transcript)
    h = await self.H(
        K, username, X1, X2, PI1.h, PI1.r, PI2.h, PI2.r,
        self.serverId, X3, X4, PI3.h, PI3.r,
        beta, PIBeta.h, PIBeta.r,
        alpha, PIAlpha.h, PIAlpha.r,
    )
    
    # r = x₁ - t·h mod n
    r = self.modN(x1 - t * h)
    
    # k = H(K) - shared key
    k = hashlib.sha256(K.toRawBytes()).digest()
    
    # Key confirmation
    kc = await self.HMAC(K, username, self.serverId, X1, X2, X3, X4)
    kcTest = await self.HMAC(K, self.serverId, username, X3, X4, X1, X2)
    
    return AuthFinishResult(
        finishRequest=AuthFinishRequest(alpha, PIAlpha, r),
        key=k,
        kc=kc,
        kcTest=kcTest,
    )
```

---

## 6. Server Final Verification

### Mathematics
```
Server:
    Verifies Π_α
    
    K = (α - X₂^(x₄·π)) * x₄
    h = H(K || Transcript)
    
    Verifies: G*r + T*h = X₁
    
    If verified:
        k = H(K)
        kc = HMAC(K, ...)
```

### Implementation: `owl_server.py::authFinish()`
```python
async def authFinish(
    self,
    username: str,
    request: AuthFinishRequest,
    initial: AuthInitialValues,
) -> Union[AuthFinishResult, AuthenticationFailure, ZKPVerificationFailure]:
    T = initial.T
    pi = initial.pi
    x4 = initial.x4
    X1 = initial.X1
    X2 = initial.X2
    X3 = initial.X3
    X4 = initial.X4
    beta = initial.beta
    PI1 = initial.PI1
    PI2 = initial.PI2
    PI3 = initial.PI3
    PIBeta = initial.PIBeta
    
    alpha = request.alpha
    PIAlpha = request.PIAlpha
    r = request.r
    
    # Verify alpha ZKP
    alphaG = X1.add(X3).add(X4)
    if not await self.verifyZKP(PIAlpha, alphaG, alpha, username):
        return ZKPVerificationFailure()
    
    # K = (α - X₂^(x₄·π)) * x₄
    K = alpha.subtract(X2.multiply(self.modN(x4 * pi))).multiply(x4)
    
    # h = H(K || Transcript)
    h = await self.H(
        K, username, X1, X2, PI1.h, PI1.r, PI2.h, PI2.r,
        self.serverId, X3, X4, PI3.h, PI3.r, beta, PIBeta.h, PIBeta.r,
        alpha, PIAlpha.h, PIAlpha.r
    )
    
    # Verify: G*r + T*h = X₁
    if not self.G.multiply(r).add(T.multiply(h)).equals(X1):
        return AuthenticationFailure()
    
    # k = H(K) - shared key
    k = hashlib.sha256(K.toRawBytes()).digest()
    
    # Key confirmation
    kc = await self.HMAC(K, self.serverId, username, X3, X4, X1, X2)
    kcTest = await self.HMAC(K, username, self.serverId, X1, X2, X3, X4)
    
    return AuthFinishResult(key=k, kc=kc, kcTest=kcTest)
```

---

## 7. Zero-Knowledge Proofs (Schnorr NIZK)

### Mathematics
```
Creating ZKP{x} for X = G * x:
    v ∈ R [1, n-1]
    V = G * v
    h = H(G || V || X || ProverID)
    r = v - x·h mod n
    
    ZKP = (h, r)

Verifying ZKP:
    V' = G*r + X*h
    Verify: h = H(G || V' || X || ProverID)
```

### Implementation: `owl_common.py`

#### Creation
```python
async def createZKP(self, x: int, G: Point, X: Point, prover: str) -> ZKP:
    # v ∈ R [1, n-1]
    v = self.rand(1, self.n - 1)
    
    # V = G * v
    V = G.multiply(v)
    
    # h = H(G || V || X || prover)
    h = await self.H(G, V, X, prover)
    
    # r = v - x·h mod n
    r = self.modN(v - x * h)
    
    return ZKP(h=h, r=r)
```

#### Verification
```python
async def verifyZKP(self, zkp: ZKP, G: Point, X: Point, prover: str) -> bool:
    h = zkp.h
    r = zkp.r
    
    # Verify X validity
    try:
        X.assertValidity()
    except Exception:
        return False
    
    # V' = G*r + X*h
    V = G.multiply(r).add(X.multiply(h))
    
    # Verify: h = H(G || V' || X || prover)
    return h == await self.H(G, V, X, prover)
```

---

## 8. Shared Key Derivation

### Mathematical Formula
```
K = G^((x₁ + x₃) · x₂ · x₄ · π)
```

### Proof that Client and Server compute the same K

#### Client computes:
```
K = (β - X₄^(x₂·π)) · x₂
  = ((X₁+X₂+X₃)^(x₄·π) - (G^x₄)^(x₂·π)) · x₂
  = ((G^x₁ + G^x₂ + G^x₃)^(x₄·π) - G^(x₄·x₂·π)) · x₂
  = (G^((x₁+x₂+x₃)·x₄·π) - G^(x₄·x₂·π)) · x₂
  = G^((x₁+x₂+x₃-x₂)·x₄·π·x₂)
  = G^((x₁+x₃)·x₄·π·x₂)
```

#### Server computes:
```
K = (α - X₂^(x₄·π)) · x₄
  = ((X₁+X₃+X₄)^(x₂·π) - (G^x₂)^(x₄·π)) · x₄
  = ((G^x₁ + G^x₃ + G^x₄)^(x₂·π) - G^(x₂·x₄·π)) · x₄
  = (G^((x₁+x₃+x₄)·x₂·π) - G^(x₂·x₄·π)) · x₄
  = G^((x₁+x₃+x₄-x₄)·x₂·π·x₄)
  = G^((x₁+x₃)·x₂·π·x₄)
```

**Result**: K_client = K_server ✓

---

## 9. Security Properties

### 1. **Mutual Authentication**
- Client proves knowledge of `t` via `r = x₁ - t·h`
- Server verifies: `G*r + T*h = X₁`
- Both parties verify mutual ZKPs

### 2. **Forward Secrecy**
- Ephemeral values `x₁, x₂, x₄` generated per session
- Password compromise doesn't compromise past sessions

### 3. **Server Compromise Resistance**
- Server stores only `(π, T)` not the password
- Offline attack requires dictionary attack on `π = H(H(U||w))`

### 4. **Protection Against Active Attacks**
- ZKPs prevent man-in-the-middle attacks
- Complete transcript included in `h` prevents replay attacks

### 5. **Key Confirmation**
- `kc` and `kcTest` ensure both parties have the same key
- Prevents unknown key-share attacks

---

## Complete Flow Summary

```
┌─────────────────────────────────────────────────────────────────┐
│ REGISTRATION                                                     │
├─────────────────────────────────────────────────────────────────┤
│ Client: register(username, password)                            │
│   → t = H(U||w), π = H(t), T = G*t                             │
│   → Sends (π, T)                                                │
│                                                                  │
│ Server: register(RegistrationRequest)                           │
│   → x₃ ∈ R [1,n-1], X₃ = G*x₃, Π₃ = ZKP{x₃}                   │
│   → Stores {X₃, Π₃, π, T}                                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ LOGIN - FLOW 1                                                   │
├─────────────────────────────────────────────────────────────────┤
│ Client: authInit(username, password)                            │
│   → t = H(U||w), π = H(t)                                       │
│   → x₁, x₂ ∈ R [1,n-1]                                          │
│   → X₁ = G*x₁, X₂ = G*x₂                                        │
│   → Π₁ = ZKP{x₁}, Π₂ = ZKP{x₂}                                 │
│   → Sends (X₁, X₂, Π₁, Π₂)                                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ LOGIN - FLOW 2                                                   │
├─────────────────────────────────────────────────────────────────┤
│ Server: authInit(AuthInitRequest, UserCredentials)             │
│   → Verifies Π₁, Π₂                                             │
│   → x₄ ∈ R [1,n-1], X₄ = G*x₄, Π₄ = ZKP{x₄}                   │
│   → β = (X₁+X₂+X₃)^(x₄·π), Π_β = ZKP{x₄·π}                    │
│   → Sends (X₃, X₄, Π₃, Π₄, β, Π_β)                             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ LOGIN - FLOW 3                                                   │
├─────────────────────────────────────────────────────────────────┤
│ Client: authFinish(AuthInitResponse)                            │
│   → Verifies Π₃, Π₄, Π_β                                        │
│   → α = (X₁+X₃+X₄)^(x₂·π), Π_α = ZKP{x₂·π}                    │
│   → K = (β - X₄^(x₂·π)) * x₂                                   │
│   → h = H(K||Transcript), r = x₁ - t·h                          │
│   → k = H(K), kc = HMAC(...)                                    │
│   → Sends (α, Π_α, r)                                           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ FINAL VERIFICATION                                               │
├─────────────────────────────────────────────────────────────────┤
│ Server: authFinish(AuthFinishRequest, AuthInitialValues)       │
│   → Verifies Π_α                                                │
│   → K = (α - X₂^(x₄·π)) * x₄                                   │
│   → h = H(K||Transcript)                                         │
│   → Verifies G*r + T*h = X₁                                     │
│   → k = H(K), kc = HMAC(...)                                    │
│   → Compares key confirmation                                    │
└─────────────────────────────────────────────────────────────────┘

RESULT: Both have k = H(K) = H(G^((x₁+x₃)·x₂·x₄·π))
```