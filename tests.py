import asyncio
from typing import Optional
#pip install owl-crypto-py first
from owl_crypto_py.owl_client import OwlClient, UninitialisedClientError
from owl_crypto_py.owl_server import OwlServer
from owl_crypto_py.owl_common import (
    Config,
    Curves,
    ZKPVerificationFailure,
    AuthenticationFailure,
)
from owl_crypto_py.messages import (
    RegistrationRequest,
    UserCredentials,
    AuthInitRequest,
    AuthInitResponse,
    AuthFinishRequest,
    DeserializationError,
)


class SimpleDatabase:
    
    
    def __init__(self):
        self.users = {}
    
    def save_user(self, username: str, credentials: UserCredentials):
        self.users[username] = credentials
        print(f"    User '{username}' registered in database")
    
    def get_user(self, username: str) -> Optional[UserCredentials]:
        return self.users.get(username)
    
    def user_exists(self, username: str) -> bool:
        return username in self.users


async def test_authentication_flow(curve: Curves, curve_name: str):
    
    
    
    print(f"TESTING CURVE: {curve_name}")
    
    
    config = Config(curve=curve, serverId="server.example.com")
    
    client = OwlClient(config)
    server = OwlServer(config)
    database = SimpleDatabase()
    
    username = "alice"
    password = "SecurePassword123!"
    
    
    print("PHASE 1: REGISTRATION")
    
    
    print(f" Client: Creating registration request for '{username}'...")
    try:
        registration_request = await client.register(username, password)
        print(f"    Registration request created")
        print(f"     - pi: {hex(registration_request.pi)[:24]}...")
        print(f"     - T: <Point on {curve_name}>")
    except Exception as e:
        print(f"     Error during registration request: {e}")
        return False

    print(f" Server: Processing registration...")
    try:
        credentials = await server.register(registration_request)
        database.save_user(username, credentials)
        print(f"    User registered successfully")
    except Exception as e:
        print(f"     Error during server registration: {e}")
        return False
    
    print()
    
    
    print("PHASE 2: AUTHENTICATION")
    
    
    print(f" Client: Initializing authentication for '{username}'...")
    try:
        auth_init_request = await client.authInit(username, password)
        print(f"    Authentication initialized")
        print(f"     - X1, X2: <Points on {curve_name}>")
        print(f"     - ZKP: verified")
    except Exception as e:
        print(f"     Error during authInit: {e}")
        return False
    
    print(f" Server: Verifying authentication request...")
    user_creds = database.get_user(username)
    if not user_creds:
        print(f"     User '{username}' not found")
        return False
    
    try:
        auth_init_result = await server.authInit(username, auth_init_request, user_creds)
        
        if isinstance(auth_init_result, ZKPVerificationFailure):
            print(f"     ZKP verification failed during authInit")
            return False
        
        print(f"    ZKP verified successfully")
        auth_init_response = auth_init_result.response
        auth_initial_values = auth_init_result.initial
        print(f"     - X3, X4, beta: <Points on {curve_name}>")
    except Exception as e:
        print(f"     Error during server authInit: {e}")
        return False
    
    print(f" Client: Completing authentication...")
    try:
        auth_finish_result = await client.authFinish(auth_init_response)
        
        if isinstance(auth_finish_result, UninitialisedClientError):
            print(f"     Client not initialized")
            return False
        elif isinstance(auth_finish_result, ZKPVerificationFailure):
            print(f"     ZKP verification failed during authFinish")
            return False
        
        auth_finish_request = auth_finish_result.finishRequest
        client_key = auth_finish_result.key
        client_kc = auth_finish_result.kc
        client_kc_test = auth_finish_result.kcTest
        
        print(f"    Authentication completed on client")
        print(f"     - Derived key: {client_key.hex()[:48]}...")
    except Exception as e:
        print(f"     Error during client authFinish: {e}")
        return False
    
    print(f" Server: Final verification...")
    try:
        server_auth_result = await server.authFinish(
            username, auth_finish_request, auth_initial_values
        )
        
        if isinstance(server_auth_result, ZKPVerificationFailure):
            print(f"     ZKP verification failed on server")
            return False
        elif isinstance(server_auth_result, AuthenticationFailure):
            print(f"     Authentication failed")
            return False
        
        server_key = server_auth_result.key
        server_kc = server_auth_result.kc
        server_kc_test = server_auth_result.kcTest
        
        print(f"    Authentication verified on server")
        print(f"     - Derived key: {server_key.hex()[:48]}...")
    except Exception as e:
        print(f"     Error during server authFinish: {e}")
        return False
    
    print()
    
    
    print("PHASE 3: VERIFICATION")
    
    
    keys_match = client_key == server_key
    kc_match = client_kc_test == server_kc and server_kc_test == client_kc
    
    print(f" Derived keys match: {' YES' if keys_match else ' NO'}")
    print(f" Key Confirmation matches: {' YES' if kc_match else ' NO'}")
    
    if keys_match and kc_match:
        
        print(f" AUTHENTICATION SUCCESSFUL FOR {curve_name}")
        
        print(f"\nShared secret key established:")
        print(f"  {client_key.hex()}")
        return True
    else:
        
        print(f" AUTHENTICATION FAILED FOR {curve_name}")
        
        return False


async def test_wrong_password(curve: Curves, curve_name: str):
    
    
    
    print(f"TESTING WRONG PASSWORD WITH {curve_name}")
    
    
    config = Config(curve=curve, serverId="server.example.com")
    client = OwlClient(config)
    server = OwlServer(config)
    database = SimpleDatabase()
    
    username = "bob"
    correct_password = "CorrectPassword456"
    wrong_password = "WrongPassword789"
    
    print(f" Registration with correct password...")
    reg_req = await client.register(username, correct_password)
    creds = await server.register(reg_req)
    database.save_user(username, creds)
    print(f"    User registered")
    
    print(f"\n Authentication attempt with WRONG password...")
    client2 = OwlClient(config)
    auth_init_req = await client2.authInit(username, wrong_password)
    
    auth_init_result = await server.authInit(username, auth_init_req, creds)
    if isinstance(auth_init_result, ZKPVerificationFailure):
        print(f"     Authentication correctly rejected (invalid ZKP)")
        
        print(f" WRONG PASSWORD TEST PASSED FOR {curve_name}")
        
        return True
    
    auth_finish_result = await client2.authFinish(auth_init_result.response)
    if isinstance(auth_finish_result, (ZKPVerificationFailure, UninitialisedClientError)):
        print(f"     Authentication correctly rejected during authFinish")
        
        print(f" WRONG PASSWORD TEST PASSED FOR {curve_name}")
        
        return True
    
    server_result = await server.authFinish(
        username, auth_finish_result.finishRequest, auth_init_result.initial
    )
    
    if isinstance(server_result, (AuthenticationFailure, ZKPVerificationFailure)):
        print(f"    Authentication correctly rejected by server")
        print(f"     Error type: {type(server_result).__name__}")
        
        print(f" WRONG PASSWORD TEST PASSED FOR {curve_name}")
        
        return True
    else:
        print(f"    ERROR: Authentication should have failed but succeeded!")
        
        print(f" WRONG PASSWORD TEST FAILED FOR {curve_name}")
        
        return False


async def main():
    
    
    
    print(" OWL PROTOCOL - NIST P-CURVES & FourQ TESTING SUITE ")
    
    
    
    curves_to_test = [
        (Curves.P256, "NIST P-256 (secp256r1)"),
        (Curves.P384, "NIST P-384 (secp384r1)"),
        (Curves.P521, "NIST P-521 (secp521r1)"),
        (Curves.FOURQ, "FourQ (Twisted Edwards over GF(p²))"),
    ]
    
    results = {}
    
    
    
    print(" PART 1: SUCCESSFUL AUTHENTICATION TESTS")
    
    
    for curve, curve_name in curves_to_test:
        try:
            success = await test_authentication_flow(curve, curve_name)
            results[f"{curve_name} (success)"] = success
            await asyncio.sleep(0.5)  # readability pause
        except Exception as e:
            print(f"\n EXCEPTION during {curve_name} test: {e}")
            import traceback
            traceback.print_exc()
            results[f"{curve_name} (success)"] = False
    
    
    
    print(" PART 2: WRONG PASSWORD TESTS")
   
    
    for curve, curve_name in curves_to_test:
        try:
            success = await test_wrong_password(curve, curve_name)
            results[f"{curve_name} (wrong pwd)"] = success
            await asyncio.sleep(0.5)  # readability pause
        except Exception as e:
            print(f"\n EXCEPTION during {curve_name} wrong password test: {e}")
            import traceback
            traceback.print_exc()
            results[f"{curve_name} (wrong pwd)"] = False
    
    print(" FINAL TEST RESULTS")
    

    total_tests = len(results)
    passed_tests = sum(1 for v in results.values() if v)
    
    for test_name, success in results.items():
        status = " PASS" if success else " FAIL"
        print(f"{status:8} | {test_name}")
    
    
    print(f"TOTAL: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("\n ALL TESTS PASSED!")
    else:
        print(f"\n {total_tests - passed_tests} test(s) failed")
    
   


if __name__ == "__main__":
    asyncio.run(main())