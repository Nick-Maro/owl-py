import asyncio
from owl_crypto_py import (OwlClient, OwlServer, Config, Curves,AuthInitRequest,AuthFinishRequest,ZKPVerificationFailure,AuthenticationFailure,)
async def main():
    # Setup
    config = Config(curve=Curves.P256, serverId="example.com")
    server = OwlServer(config)  
    # Simulated database
    db_credentials = {}
    db_sessions = {} 
    # REGISTRATION
    print("=== Registration ===")
    client = OwlClient(config)
    username = "alice"
    password = "secure_password_123"
    
    reg_request = await client.register(username, password)
    credentials = await server.register(reg_request)
    db_credentials[username] = credentials
    print(f" User registered\n") 
    # Helper function for authentication
    async def authenticate(user, pwd, session_key):
        client = OwlClient(config)
        
        async def send_init(json_data):
            req = AuthInitRequest.deserialize(json_data, config)
            result = await server.authInit(user, req, db_credentials[user])
            if isinstance(result, ZKPVerificationFailure):
                return None
            db_sessions[session_key] = result.initial
            return result.response.to_json()
        
        async def send_finish(json_data):
            req = AuthFinishRequest.deserialize(json_data, config)
            result = await server.authFinish(user, req, db_sessions[session_key])
            if isinstance(result, (ZKPVerificationFailure, AuthenticationFailure)):
                return None
            return "OK"
        
        return await client.login(user, pwd, send_init, send_finish)
    # LOGIN WITH CORRECT PASSWORD
    print("=== Login (correct password) ===")
    result = await authenticate(username, password, "session_1")
    
    if result.success:
        print(f" Success! Key: {result.key.hex()[:32]}...\n")
    else:
        print(f" Failed: {result.error}\n") 
    # LOGIN WITH WRONG PASSWORD
    print("=== Login (wrong password) ===")
    result = await authenticate(username, "wrong_password", "session_2")
    
    if result.success:
        print(f" Success! Key: {result.key.hex()[:32]}...")
    else:
        print(f" Failed: {result.error}")


if __name__ == "__main__":
    asyncio.run(main())