# Full Owl aPAKE example: async + sync API, all curves, key confirmation.

import asyncio
from typing import Optional

from owl_crypto_py import (
    OwlClient,
    OwlServer,
    OwlCommon,
    Config,
    Curves,
    ZKPVerificationFailure,
    AuthenticationFailure,
    UserCredentials,
)
from owl_crypto_py.owl_client import UninitialisedClientError


class Database:
    def __init__(self):
        self.users: dict[str, UserCredentials] = {}

    def save(self, username: str, creds: UserCredentials):
        self.users[username] = creds

    def get(self, username: str) -> Optional[UserCredentials]:
        return self.users.get(username)


async def full_async_flow(curve: Curves, label: str):
    

    print(f"  {label}")


    config = Config(curve=curve, serverId="auth.example.com")
    client = OwlClient(config)
    server = OwlServer(config)
    db = Database()

    username = "alice"
    password = "hunter2"

    #1. Registration 
    print("\n[1] Registration")
    reg_request = await client.register(username, password)
    credentials = await server.register(reg_request)
    db.save(username, credentials)
    print(f"    User '{username}' registered.")

    #  2. Login Flow 1: Client -> Server 
    print("\n[2] Login — Client sends X1, X2, PI1, PI2")
    auth_init_req = await client.authInit(username, password)

    #  3. Login — Flow 2: Server -> Client 
    print("[3] Login — Server responds with X3, X4, beta, proofs")
    stored = db.get(username)
    init_result = await server.authInit(username, auth_init_req, stored)
    if isinstance(init_result, ZKPVerificationFailure):
        print("    FAIL: server rejected client proofs")
        return False

    #4. Login  Flow 3: Client -> Server
    print("[4] Login — Client sends alpha, proof, r")
    finish_result = await client.authFinish(init_result.response)
    if isinstance(finish_result, (ZKPVerificationFailure, UninitialisedClientError)):
        print(f"    FAIL: {type(finish_result).__name__}")
        return False

    #5. Server verifies 
    print("[5] Server verifies final message")
    server_result = await server.authFinish(
        username, finish_result.finishRequest, init_result.initial
    )
    if isinstance(server_result, (ZKPVerificationFailure, AuthenticationFailure)):
        print(f"    FAIL: {type(server_result).__name__}")
        return False

    #6. Both sides verify key confirmation (constant-time)
    print("[6] Key confirmation (constant-time)")
    client_kc_ok = OwlCommon.verifyKeyConfirmation(
        finish_result.kcTest, server_result.kc
    )
    server_kc_ok = OwlCommon.verifyKeyConfirmation(
        server_result.kcTest, finish_result.kc
    )

    keys_match = finish_result.key == server_result.key

    print(f"    Keys match:  {'YES' if keys_match else 'NO'}")
    print(f"    KC verified: {'YES' if (client_kc_ok and server_kc_ok) else 'NO'}")
    print(f"    Session key: {finish_result.key.hex()}")

    return keys_match and client_kc_ok and server_kc_ok


#Wrong password test

async def wrong_password_test():

    print(f"  Wrong password test (P256)")

    config = Config(curve=Curves.P256, serverId="auth.example.com")
    client = OwlClient(config)
    server = OwlServer(config)
    db = Database()

    # Register with correct password
    reg = await client.register("bob", "correct_password")
    creds = await server.register(reg)
    db.save("bob", creds)
    print("\n    Registered 'bob' with correct password.")

    # Try to login with wrong password
    attacker = OwlClient(config)
    init_req = await attacker.authInit("bob", "wrong_password")
    init_result = await server.authInit("bob", init_req, db.get("bob"))

    if isinstance(init_result, ZKPVerificationFailure):
        print("    Rejected at server authInit (ZKP failed).")
        return True

    finish = await attacker.authFinish(init_result.response)
    if isinstance(finish, (ZKPVerificationFailure, UninitialisedClientError)):
        print("    Rejected at client authFinish.")
        return True

    result = await server.authFinish("bob", finish.finishRequest, init_result.initial)
    if isinstance(result, (AuthenticationFailure, ZKPVerificationFailure)):
        print(f"    Correctly rejected: {type(result).__name__}")
        return True

    print("    ERROR: should have been rejected!")
    return False




def sync_demo():
    

    print(f"  Sync API demo (P256)")


    config = Config(curve=Curves.P256, serverId="auth.example.com")
    client = OwlClient(config)
    server = OwlServer(config)

    # Registration (sync)
    reg = client.register_sync("carol", "my_secret")
    creds = server.register_sync(reg)
    print(f"    Registered 'carol' (sync).")

    # Auth init (sync)
    init_req = client.authInit_sync("carol", "my_secret")
    init_result = server.authInit_sync("carol", init_req, creds)
    print(f"    authInit done (sync).")

    # Auth finish (sync)
    finish = client.authFinish_sync(init_result.response)
    server_result = server.authFinish_sync(
        "carol", finish.finishRequest, init_result.initial
    )
    print(f"    authFinish done (sync).")

    # Verify
    ok = (
        finish.key == server_result.key
        and OwlCommon.verifyKeyConfirmation(finish.kcTest, server_result.kc)
        and OwlCommon.verifyKeyConfirmation(server_result.kcTest, finish.kc)
    )
    print(f"    Session key: {finish.key.hex()}")
    print(f"    All OK: {'YES' if ok else 'NO'}")
    return ok




async def serialization_demo():

    print(f"  Serialization round-trip demo")


    config = Config(curve=Curves.P256, serverId="auth.example.com")
    client = OwlClient(config)
    server = OwlServer(config)

    reg = await client.register("dave", "pass123")
    creds = await server.register(reg)

    # Serialize credentials to JSON (for database storage)
    json_str = creds.to_json()
    print(f"    Credentials JSON ({len(json_str)} bytes): {json_str[:80]}...")

    # Deserialize back
    restored = UserCredentials.deserialize(json_str, config)
    print(f"    Deserialized back successfully: {type(restored).__name__}")

    # Use restored credentials for auth
    init_req = await client.authInit("dave", "pass123")
    init_result = await server.authInit("dave", init_req, restored)
    assert not isinstance(init_result, ZKPVerificationFailure)

    finish = await client.authFinish(init_result.response)
    result = await server.authFinish("dave", finish.finishRequest, init_result.initial)
    assert not isinstance(result, (AuthenticationFailure, ZKPVerificationFailure))
    assert finish.key == result.key

    print(f"    Auth with deserialized credentials: OK")


# Main 

async def async_main():
    results = {}

    # Test all curves
    for curve, name in [
        (Curves.P256, "NIST P-256"),
        (Curves.P384, "NIST P-384"),
        (Curves.P521, "NIST P-521"),
        (Curves.FOURQ, "FourQ"),
    ]:
        results[name] = await full_async_flow(curve, f"Full flow {name}")

    # Wrong password
    results["Wrong password"] = await wrong_password_test()

    # Serialization
    await serialization_demo()
    results["Serialization"] = True

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"  Summary")
    print(f"{'=' * 60}\n")
    for name, ok in results.items():
        print(f"    {'PASS' if ok else 'FAIL'}  {name}")
    print()

    all_ok = all(results.values())
    print(f"    {'All passed!' if all_ok else 'Some tests failed.'}\n")
    return all_ok


if __name__ == "__main__":
    # async tests
    asyncio.run(async_main())

    # sync test (must be outside asyncio.run)
    sync_demo()
