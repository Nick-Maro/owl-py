import asyncio
from owl_crypto_py import (  OwlClient,    OwlServer,    Config,    Curves,   AuthInitRequest,   AuthFinishRequest,   ZKPVerificationFailure,    AuthenticationFailure,)

async def main():
    # Setup
    config = Config(curve=Curves.P256, serverId="example.com")
    server = OwlServer(config)
    # Simulated databases
    db_credentials = {}
    db_sessions = {} 
    # User credentials
    username = "alice"
    password = "secure_password_123" 
    # REGISTRATION
    print("Registering user...")
    client = OwlClient(config)
    reg_request = await client.register(username, password)
    credentials = await server.register(reg_request)
    db_credentials[username] = credentials
    print(f" User '{username}' registered\n")
    
    # LOGIN WITH CORRECT PASSWORD
    print("Logging in with correct password...")
    client = OwlClient(config)
    
    auth_init = await client.authInit(username, password)
    
    init_result = await server.authInit(
        username, 
        AuthInitRequest.deserialize(auth_init.to_json(), config),
        db_credentials[username]
    )
    db_sessions[username] = init_result.initial
    
    finish_result = await client.authFinish(init_result.response)
     
    server_result = await server.authFinish(
        username,
        AuthFinishRequest.deserialize(finish_result.finishRequest.to_json(), config),
        db_sessions[username]
    )
    
    if not isinstance(server_result, (ZKPVerificationFailure, AuthenticationFailure)):
        print(f" Login successful!")
        print(f" Shared key: {finish_result.key.hex()[:32]}...\n")
    else:
        print(" Login failed\n")
    
    # LOGIN WITH WRONG PASSWORD
    print("Logging in with wrong password...")
    client2 = OwlClient(config)
    wrong_password = "wrong_password_456"

    auth_init_wrong = await client2.authInit(username, wrong_password)
    
    init_result_wrong = await server.authInit(
        username, 
        AuthInitRequest.deserialize(auth_init_wrong.to_json(), config),
        db_credentials[username]
    )
    db_sessions[username + "_wrong"] = init_result_wrong.initial

    finish_result_wrong = await client2.authFinish(init_result_wrong.response)
    
    server_result_wrong = await server.authFinish(
        username,
        AuthFinishRequest.deserialize(finish_result_wrong.finishRequest.to_json(), config),
        db_sessions[username + "_wrong"]
    )
    
    if not isinstance(server_result_wrong, (ZKPVerificationFailure, AuthenticationFailure)):
        print(f" Login successful!")
        print(f" Shared key: {finish_result_wrong.key.hex()[:32]}...")
    else:
        print(" Login failed - Authentication rejected")


if __name__ == "__main__":
    asyncio.run(main())