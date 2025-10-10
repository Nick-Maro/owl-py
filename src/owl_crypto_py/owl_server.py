import hashlib
from typing import Union
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