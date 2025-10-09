

import asyncio
from typing import Optional

from .owl_client import OwlClient, UninitialisedClientError
from .owl_server import OwlServer
from .owl_common import (
    Config,
    Curves,
    ZKPVerificationFailure,
    AuthenticationFailure,
)
from .messages import (
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
        print(f" User '{username}' registered in database")
    
    def get_user(self, username: str) -> Optional[UserCredentials]:

        return self.users.get(username)
    
    def user_exists(self, username: str) -> bool:

        return username in self.users


async def main():
    print()
    
    config = Config(curve=Curves.P256, serverId="server.example.com")
    
    client = OwlClient(config)
    server = OwlServer(config)
    database = SimpleDatabase()
    
    username = "alice"
    password = "password123"
    
    print("PHASE 1: REGISTRATION")
    print("-" * 60)
    
    print(f" Client: Creating registration request for '{username}'...")
    registration_request = await client.register(username, password)
    print(f"   pi: {hex(registration_request.pi)[:20]}...")
    print(f"   T: (Point)")
    
    print(f" Server: Processing registration...")
    credentials = await server.register(registration_request)
    
    database.save_user(username, credentials)
    print()
    
    print("SERIALIZATION (Optional)")
    print("-" * 60)
    credentials_json = credentials.to_json()
    print(f" Serialized credentials: {credentials_json[:100]}...")
    
    deserialized = UserCredentials.deserialize(credentials_json, config)
    if isinstance(deserialized, DeserializationError):
        print(f"✗ Deserialization error: {deserialized}")
        return
    print(f" Credentials deserialized successfully")
    print()
    
    print("PHASE 2: AUTHENTICATION")
    print("-" * 60)
    
    print(f" Client: Initializing authentication for '{username}'...")
    auth_init_request = await client.authInit(username, password)
    print(f"   X1: (Point)")
    print(f"   X2: (Point)")
    print(f"   ZKP for X1 and X2: ")
    
    print(f" Server: Verifying authentication request...")
    user_creds = database.get_user(username)
    if not user_creds:
        print(f" User '{username}' not found in database")
        return
    
    auth_init_result = await server.authInit(username, auth_init_request, user_creds)
    
    if isinstance(auth_init_result, ZKPVerificationFailure):
        print(f" Error: ZKP verification failed during authInit")
        return
    
    print(f" Server: ZKP verified successfully")
    auth_init_response = auth_init_result.response
    auth_initial_values = auth_init_result.initial
    print(f"   X3, X4: (Points)")
    print(f"   beta: (Point)")
    print(f"   ZKP for X3, X4, beta: ")
    
    print(f" Client: Completing authentication...")
    auth_finish_result = await client.authFinish(auth_init_response)
    
    if isinstance(auth_finish_result, UninitialisedClientError):
        print(f" Error: Client not initialized")
        return
    elif isinstance(auth_finish_result, ZKPVerificationFailure):
        print(f" Error: ZKP verification failed during authFinish")
        return
    
    auth_finish_request = auth_finish_result.finishRequest
    client_key = auth_finish_result.key
    client_kc = auth_finish_result.kc
    client_kc_test = auth_finish_result.kcTest
    
    print(f" Client: Authentication completed")
    print(f"   Derived key: {client_key.hex()[:40]}...")
    print(f"   Key Confirmation (KC): {client_kc[:40]}...")
    
    print(f" Server: Final verification...")
    server_auth_result = await server.authFinish(
        username, auth_finish_request, auth_initial_values
    )
    
    if isinstance(server_auth_result, ZKPVerificationFailure):
        print(f" Error: ZKP verification failed on server")
        return
    elif isinstance(server_auth_result, AuthenticationFailure):
        print(f" Error: Authentication failed")
        return
    
    server_key = server_auth_result.key
    server_kc = server_auth_result.kc
    server_kc_test = server_auth_result.kcTest
    
    print(f" Server: Authentication verified")
    print(f"   Derived key: {server_key.hex()[:40]}...")
    print(f"   Key Confirmation (KC): {server_kc[:40]}...")
    print()
    
    print("PHASE 3: VERIFICATION")
    
    keys_match = client_key == server_key
    kc_match = client_kc_test == server_kc and server_kc_test == client_kc
    
    print(f" Derived keys match: {' YES' if keys_match else ' NO'}")
    print(f" Key Confirmation matches: {' YES' if kc_match else ' NO'}")
    
    if keys_match and kc_match:
        print()

        print(" AUTHENTICATION COMPLETED SUCCESSFULLY")

        print(f"\nShared key established between client and server:")
        print(f"  {client_key.hex()}")
    else:
        print()
        print(" Authentication failed: keys do not match")


async def test_wrong_password():

    print("\n\n")

    print("TEST: AUTHENTICATION WITH WRONG PASSWORD")

    print()
    
    config = Config(curve=Curves.P256, serverId="server.example.com")
    client = OwlClient(config)
    server = OwlServer(config)
    database = SimpleDatabase()
    
    username = "bob"
    correct_password = "correct_password"
    wrong_password = "wrong_password"
    
    print(f" Registration with password: '{correct_password}'")
    reg_req = await client.register(username, correct_password)
    creds = await server.register(reg_req)
    database.save_user(username, creds)
    
    print(f" Authentication attempt with password: '{wrong_password}'")
    client2 = OwlClient(config)
    auth_init_req = await client2.authInit(username, wrong_password)
    
    auth_init_result = await server.authInit(username, auth_init_req, creds)
    if isinstance(auth_init_result, ZKPVerificationFailure):
        print(f" Authentication failed immediately (invalid ZKP)")
        return
    
    auth_finish_result = await client2.authFinish(auth_init_result.response)
    if isinstance(auth_finish_result, (ZKPVerificationFailure, UninitialisedClientError)):
        print(f" Authentication failed during authFinish")
        return
    
    server_result = await server.authFinish(
        username, auth_finish_result.finishRequest, auth_init_result.initial
    )
    
    if isinstance(server_result, (AuthenticationFailure, ZKPVerificationFailure)):
        print(f" Authentication correctly rejected by server")
        print(f"  Error type: {type(server_result).__name__}")
    else:
        print(f" ERROR: Authentication should have failed but succeeded!")


if __name__ == "__main__":
    asyncio.run(main())
    asyncio.run(test_wrong_password())