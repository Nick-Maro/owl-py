import hashlib
from typing import Union, Callable, Awaitable, Optional
from dataclasses import dataclass

from .owl_common import (
    OwlCommon,
    ZKPVerificationFailure,
    AuthenticationFailure,
)
from .messages import (
    AuthFinishRequest,
    AuthInitRequest,
    AuthInitResponse,
    AuthInitialValues,
    RegistrationRequest,
    UserCredentials,
)


@dataclass
class AuthInitResult:
    response: AuthInitResponse
    initial: AuthInitialValues


@dataclass
class AuthFinishResult:
    key: bytes
    kc: str
    kcTest: str


@dataclass
class HandleAuthResult:
    
    success: bool
    key: Optional[bytes] = None
    response_json: Optional[str] = None
    error: Optional[str] = None


class OwlServer(OwlCommon):
    async def register(self, request: RegistrationRequest) -> UserCredentials:
        pi = request.pi
        T = request.T
        
        x3 = self.rand(1, self.n - 1)
        X3 = self.G.multiply(x3)
        PI3 = await self.createZKP(x3, self.G, X3, self.serverId)
        
        return UserCredentials(X3, PI3, pi, T)
    
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
        
        # verify ZKPs
        if (
            not await self.verifyZKP(PI1, self.G, X1, username)
            or not await self.verifyZKP(PI2, self.G, X2, username)
        ):
            return ZKPVerificationFailure()
        
        # x4 = [1, n-1]
        x4 = self.rand(1, self.n - 1)
        # X4 = G * x4
        X4 = self.G.multiply(x4)
        # PI4 = ZKP{x4}
        PI4 = await self.createZKP(x4, self.G, X4, self.serverId)
        
        secret = self.modN(x4 * pi)
        betaG = X1.add(X2).add(X3)
        # beta = (X1+X2+X3) * (pi * x4)
        beta = betaG.multiply(secret)
        # PIBeta = ZKP{pi * x4}
        PIBeta = await self.createZKP(secret, betaG, beta, self.serverId)
        
        # package values
        response = AuthInitResponse(X3, X4, PI3, PI4, beta, PIBeta)
        initial = AuthInitialValues(
            T, pi, x4, X1, X2, X3, X4, beta,
            PI1, PI2, PI3, PIBeta
        )
        
        return AuthInitResult(response=response, initial=initial)
    
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
        
        # verify alpha ZKP
        alphaG = X1.add(X3).add(X4)
        if not await self.verifyZKP(PIAlpha, alphaG, alpha, username):
            return ZKPVerificationFailure()
        
        # K = (alpha - (X2 * (x4 * pi))) * x4
        K = alpha.subtract(X2.multiply(self.modN(x4 * pi))).multiply(x4)
        
        # h = H(K||Transcript)
        h = await self.H(
            K, username, X1, X2, PI1.h, PI1.r, PI2.h, PI2.r,
            self.serverId, X3, X4, PI3.h, PI3.r, beta, PIBeta.h, PIBeta.r,
            alpha, PIAlpha.h, PIAlpha.r
        )
        
        # (G * r) + (T * h) ?= X1
        if not self.G.multiply(r).add(T.multiply(h)).equals(X1):
            return AuthenticationFailure()
        
        # k = H(K)
        k = hashlib.sha256(K.toRawBytes()).digest()
        
        # kc = HMAC(K || "KC" || serverId || userId || X3 || X4 || X1 || X2)
        kc = await self.HMAC(K, self.serverId, username, X3, X4, X1, X2)
        
        # check received key confirmation matches expected result
        kcTest = await self.HMAC(K, username, self.serverId, X1, X2, X3, X4)
        
        return AuthFinishResult(key=k, kc=kc, kcTest=kcTest)

    # Simplified wrapper methods
    async def handleAuth(
        self,
        username: str,
        init_request_json: str,
        finish_request_json: str,
        get_credentials: Callable[[str], Awaitable[Optional[str]]],
        store_session: Callable[[str, str], Awaitable[bool]],
        get_session: Callable[[str], Awaitable[Optional[str]]]
    ) -> HandleAuthResult:

        try:
            
            auth_init_request = AuthInitRequest.deserialize(init_request_json, self.config)
            if hasattr(auth_init_request, '__class__') and auth_init_request.__class__.__name__ == 'DeserializationError':
                return HandleAuthResult(success=False, error="Failed to deserialize init request")
            
            
            credentials_json = await get_credentials(username)
            if not credentials_json:
                return HandleAuthResult(success=False, error="User not found")
            
            credentials = UserCredentials.deserialize(credentials_json, self.config)
            if hasattr(credentials, '__class__') and credentials.__class__.__name__ == 'DeserializationError':
                return HandleAuthResult(success=False, error="Failed to deserialize credentials")
            
            
            init_result = await self.authInit(username, auth_init_request, credentials)
            if isinstance(init_result, ZKPVerificationFailure):
                return HandleAuthResult(success=False, error="Client proof verification failed")
            
            
            session_id = username
            session_json = init_result.initial.to_json()
            if not await store_session(session_id, session_json):
                return HandleAuthResult(success=False, error="Failed to store session")
            
            response_json = init_result.response.to_json()
            
            
            auth_finish_request = AuthFinishRequest.deserialize(finish_request_json, self.config)
            if hasattr(auth_finish_request, '__class__') and auth_finish_request.__class__.__name__ == 'DeserializationError':
                return HandleAuthResult(success=False, error="Failed to deserialize finish request")
            
            
            initial_json = await get_session(session_id)
            if not initial_json:
                return HandleAuthResult(success=False, error="Session not found or expired")
            
            initial_values = AuthInitialValues.deserialize(initial_json, self.config)
            if hasattr(initial_values, '__class__') and initial_values.__class__.__name__ == 'DeserializationError':
                return HandleAuthResult(success=False, error="Failed to deserialize session")
            
           
            finish_result = await self.authFinish(username, auth_finish_request, initial_values)
            
            if isinstance(finish_result, ZKPVerificationFailure):
                return HandleAuthResult(success=False, error="Client proof verification failed")
            if isinstance(finish_result, AuthenticationFailure):
                return HandleAuthResult(success=False, error="Invalid credentials")
            
            return HandleAuthResult(
                success=True, 
                key=finish_result.key,
                response_json=response_json
            )
            
        except Exception as e:
            return HandleAuthResult(success=False, error=f"Unexpected error: {str(e)}")
    
    async def handleRegister(
        self,
        request_json: str,
        store_credentials: Callable[[str, str], Awaitable[bool]]
    ) -> HandleAuthResult:

        try:
            
            reg_request = RegistrationRequest.deserialize(request_json, self.config)
            if hasattr(reg_request, '__class__') and reg_request.__class__.__name__ == 'DeserializationError':
                return HandleAuthResult(success=False, error="Failed to deserialize request")
            
            
            credentials = await self.register(reg_request)
            
           
            credentials_json = credentials.to_json()
            
            return HandleAuthResult(success=True, response_json=credentials_json)
            
        except Exception as e:
            return HandleAuthResult(success=False, error=f"Unexpected error: {str(e)}")