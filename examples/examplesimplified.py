import asyncio
from owl_crypto_py import (OwlClient, OwlServer, Config, Curves,UserCredentials,AuthInitRequest,AuthInitResponse,AuthFinishRequest,AuthInitialValues,ZKPVerificationFailure,AuthenticationFailure,)


async def main():
    config = Config(curve=Curves.P256, serverId="example.com")
    client = OwlClient(config)
    server = OwlServer(config)
    
    db_credentials = {}
    db_sessions = {}
    
    username = "alice"
    password = "secure_password_123"
    
    print("\n=== REGISTRATION ===\n")
    
    reg_request = await client.register(username, password)
    reg_result = await server.handleRegister(
        reg_request.to_json(),
        lambda u, creds: asyncio.coroutine(lambda: db_credentials.update({username: creds}) or True)()
    )
    
    print(f"Registration: {reg_result.success}")
    
    print("\n=== LOGIN (CORRECT PASSWORD) ===\n")
    
    async def send_init(json_data):
        auth_request = AuthInitRequest.deserialize(json_data, config)
        credentials = UserCredentials.deserialize(db_credentials[username], config)
        init_result = await server.authInit(username, auth_request, credentials)
        if isinstance(init_result, ZKPVerificationFailure):
            return None
        db_sessions[username] = init_result.initial.to_json()
        return init_result.response.to_json()
    
    async def send_finish(json_data):
        finish_request = AuthFinishRequest.deserialize(json_data, config)
        initial_values = AuthInitialValues.deserialize(db_sessions[username], config)
        finish_result = await server.authFinish(username, finish_request, initial_values)
        if isinstance(finish_result, (ZKPVerificationFailure, AuthenticationFailure)):
            return None
        return "OK"
    
    login_result = await client.login(username, password, send_init, send_finish)
    
    print(f"Login: {login_result.success}")
    if login_result.success:
        print(f"Key: {login_result.key.hex()[:32]}...")
    
    print("\n=== LOGIN (WRONG PASSWORD) ===\n")
    
    client2 = OwlClient(config)
    wrong_password = "wrong_password"
    
    async def send_init_wrong(json_data):
        auth_request = AuthInitRequest.deserialize(json_data, config)
        credentials = UserCredentials.deserialize(db_credentials[username], config)
        init_result = await server.authInit(username, auth_request, credentials)
        if isinstance(init_result, ZKPVerificationFailure):
            return None
        db_sessions[username + "_wrong"] = init_result.initial.to_json()
        return init_result.response.to_json()
    
    async def send_finish_wrong(json_data):
        finish_request = AuthFinishRequest.deserialize(json_data, config)
        initial_values = AuthInitialValues.deserialize(db_sessions[username + "_wrong"], config)
        finish_result = await server.authFinish(username, finish_request, initial_values)
        if isinstance(finish_result, (ZKPVerificationFailure, AuthenticationFailure)):
            return None
        return "OK"
    
    login_wrong = await client2.login(username, wrong_password, send_init_wrong, send_finish_wrong)
    
    print(f"Login: {login_wrong.success}")
    if not login_wrong.success:
        print(f"Error: {login_wrong.error}")
    
    print("\n=== LOGIN (USER NOT FOUND) ===\n")
    
    client3 = OwlClient(config)
    fake_user = "bob"
    
    async def send_init_fake(json_data):
        if fake_user not in db_credentials:
            return None
        return "OK"
    
    async def send_finish_fake(json_data):
        return None
    
    login_fake = await client3.login(fake_user, password, send_init_fake, send_finish_fake)
    
    print(f"Login: {login_fake.success}")
    if not login_fake.success:
        print(f"Error: {login_fake.error}")
    
    print("\n=== SUMMARY ===\n")
    print(f"Registration:     {reg_result.success}")
    print(f"Login (correct):  {login_result.success}")
    print(f"Login (wrong):    {not login_wrong.success}")
    print(f"Login (no user):  {not login_fake.success}")
    print()


if __name__ == "__main__":
    asyncio.run(main())