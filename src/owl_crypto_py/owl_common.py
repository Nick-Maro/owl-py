import hashlib
import hmac
import secrets
from abc import ABC
from enum import Enum
from typing import List, Union, Tuple
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
#FourQ
from .extended_curves import FourQPoint, rand_scalar_fourq


class Point:
    
    def __init__(self, x: int, y: int, curve, is_infinity=False):
        self.x = x
        self.y = y
        self.curve = curve
        self.is_infinity = is_infinity
    
    @classmethod
    def infinity(cls, curve):
        return cls(0, 0, curve, is_infinity=True)
    
    @classmethod
    def from_hex(cls, hex_str: str, curve):
        try:
            data = bytes.fromhex(hex_str)
            
            if isinstance(curve, ec.SECP256R1):
                field_size = 32
            elif isinstance(curve, ec.SECP384R1):
                field_size = 48
            elif isinstance(curve, ec.SECP521R1):
                field_size = 66
            else:
                raise ValueError("Unsupported curve")
            
            if data[0] == 0x04:
                if len(data) != 1 + 2 * field_size:
                    raise ValueError("Invalid data length for uncompressed format")
                x = int.from_bytes(data[1:1+field_size], 'big')
                y = int.from_bytes(data[1+field_size:], 'big')
                return cls(x, y, curve)
            else:
                raise ValueError("Only uncompressed format (0x04) is supported")
        except Exception as e:
            raise ValueError(f"Unable to decode point: {e}")
    
    def to_hex(self) -> str:
        if self.is_infinity:
            return "00"
        
        if isinstance(self.curve, ec.SECP256R1):
            field_size = 32
        elif isinstance(self.curve, ec.SECP384R1):
            field_size = 48
        elif isinstance(self.curve, ec.SECP521R1):
            field_size = 66
        else:
            raise ValueError("Unsupported curve")
        
        x_bytes = self.x.to_bytes(field_size, 'big')
        y_bytes = self.y.to_bytes(field_size, 'big')
        return '04' + x_bytes.hex() + y_bytes.hex()
    
    def toRawBytes(self) -> bytes:
        return bytes.fromhex(self.to_hex())
    
    def multiply(self, scalar: int) -> 'Point':
        if self.is_infinity or scalar == 0:
            return Point.infinity(self.curve)
        
        result = Point.infinity(self.curve)
        addend = self
        
        while scalar:
            if scalar & 1:
                result = result.add(addend)
            addend = addend.double()
            scalar >>= 1
        
        return result
    
    def add(self, other: 'Point') -> 'Point':
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        
        p, a = self._get_curve_params()
        
        if self.x == other.x:
            if self.y == other.y:
                return self.double()
            else:
                return Point.infinity(self.curve)
        
        s = ((other.y - self.y) * pow(other.x - self.x, -1, p)) % p
        x3 = (s * s - self.x - other.x) % p
        y3 = (s * (self.x - x3) - self.y) % p
        
        return Point(x3, y3, self.curve)
    
    def double(self) -> 'Point':
        if self.is_infinity:
            return self
        
        p, a = self._get_curve_params()
        s = ((3 * self.x * self.x + a) * pow(2 * self.y, -1, p)) % p
        x3 = (s * s - 2 * self.x) % p
        y3 = (s * (self.x - x3) - self.y) % p
        
        return Point(x3, y3, self.curve)
    
    def subtract(self, other: 'Point') -> 'Point':
        if other.is_infinity:
            return self
        
        p, _ = self._get_curve_params()
        neg_other = Point(other.x, (-other.y) % p, self.curve)
        return self.add(neg_other)
    
    def equals(self, other: 'Point') -> bool:
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y
    
    def assertValidity(self):
        if self.is_infinity:
            return
        
        p, a, b = self._get_curve_params_full()
        left = (self.y * self.y) % p
        right = (self.x * self.x * self.x + a * self.x + b) % p
        
        if left != right:
            raise ValueError("Point is not on the curve")
    
    def _get_curve_params(self) -> Tuple[int, int]:
        if isinstance(self.curve, ec.SECP256R1):
            p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
            a = -3
        elif isinstance(self.curve, ec.SECP384R1):
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
            a = -3
        elif isinstance(self.curve, ec.SECP521R1):
            p = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            a = -3
        else:
            raise ValueError("Unsupported curve")
        
        return (p, a)
    
    def _get_curve_params_full(self) -> Tuple[int, int, int]:
        if isinstance(self.curve, ec.SECP256R1):
            p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
            a = -3
            b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
        elif isinstance(self.curve, ec.SECP384R1):
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
            a = -3
            b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
        elif isinstance(self.curve, ec.SECP521R1):
            p = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            a = -3
            b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
        else:
            raise ValueError("Unsupported curve")
        
        return (p, a, b)
    
    def __repr__(self):
        if self.is_infinity:
            return "Point(infinity)"
        return f"Point(x={hex(self.x)[:20]}..., y={hex(self.y)[:20]}...)"


@dataclass
class ZKP:
    h: int
    r: int


class ZKPVerificationFailure(Exception):
    def __init__(self):
        super().__init__("ZKP verification failed")
        self.name = "ZKPVerificationFailure"


class AuthenticationFailure(Exception):
    def __init__(self):
        super().__init__("Authentication failed")
        self.name = "AuthenticationFailure"


class Curves(Enum):
    P256 = 256
    P384 = 384
    P521 = 521
    FOURQ = 4  


@dataclass
class Config:
    curve: Curves
    serverId: str


class OwlCommon(ABC):
    def __init__(self, config: Config):
        curve = config.curve
        self.serverId = config.serverId
        
        if curve == Curves.P256:
            self.curve_obj = ec.SECP256R1()
            self.n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
            Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
            Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
            self.G = Point(Gx, Gy, self.curve_obj)
            
        elif curve == Curves.P384:
            self.curve_obj = ec.SECP384R1()
            self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
            Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
            Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
            self.G = Point(Gx, Gy, self.curve_obj)
            
        elif curve == Curves.P521:
            self.curve_obj = ec.SECP521R1()
            self.n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
            Gx = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
            Gy = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
            self.G = Point(Gx, Gy, self.curve_obj)
            
        elif curve == Curves.FOURQ:
            self.curve_obj = None
            self.n = FourQPoint.N
            self.G = FourQPoint.generator()
            
        else:
            raise ValueError(f"Unsupported curve: {curve}")
    
    def modN(self, x: int) -> int:
        return ((x % self.n) + self.n) % self.n
    
    def rand(self, from_val: int, to_val: int) -> int:
        range_val = to_val - from_val
        bytes_needed = (range_val.bit_length() + 7) // 8
        rand_bytes = secrets.token_bytes(bytes_needed)
        rand_val = int.from_bytes(rand_bytes, byteorder='big')
        return from_val + (rand_val % (range_val + 1))
    
    def concatToBytes(self, *args: Union[bytes, str, int, Point, FourQPoint]) -> bytes:
        result = b''
        for arg in args:
            if isinstance(arg, bytes):
                result += arg
            elif isinstance(arg, str):
                result += arg.encode('utf-8')
            elif isinstance(arg, int):
                byte_length = (arg.bit_length() + 7) // 8
                if byte_length == 0:
                    byte_length = 1
                result += arg.to_bytes(byte_length, byteorder='big')
            elif hasattr(arg, 'toRawBytes'):  # Point or FourQPoint
                result += arg.toRawBytes()
            else:
                raise TypeError("Unsupported type in concatToBytes")
        return result
    
    async def H(self, *args: Union[bytes, str, int, Point, FourQPoint]) -> int:
        bytes_data = self.concatToBytes(*args)
        hash_result = hashlib.sha256(bytes_data).digest()
        return int.from_bytes(hash_result, byteorder='big')
    
    async def HMAC(
        self,
        K: Union[Point, FourQPoint],
        senderId: str,
        receiverId: str,
        sender1: Union[Point, FourQPoint],
        sender2: Union[Point, FourQPoint],
        receiver1: Union[Point, FourQPoint],
        receiver2: Union[Point, FourQPoint],
    ) -> str:
        kc_key = hashlib.sha256(self.concatToBytes(K, "KC")).digest()
        
        bytes_data = self.concatToBytes(
            kc_key,
            senderId,
            receiverId,
            sender1,
            sender2,
            receiver1,
            receiver2,
        )
        
        hmac_result = hmac.new(kc_key, bytes_data, hashlib.sha256).digest()
        return hmac_result.hex()
    
    async def createZKP(self, x: int, G: Union[Point, FourQPoint], X: Union[Point, FourQPoint], prover: str) -> ZKP:
        
        if isinstance(G, FourQPoint):
            v = rand_scalar_fourq()
        else:
            v = self.rand(1, self.n - 1)
        
        V = G.multiply(v)
        h = await self.H(G, V, X, prover)
        r = self.modN(v - x * h)
        return ZKP(h=h, r=r)
    
    async def verifyZKP(self, zkp: ZKP, G: Union[Point, FourQPoint], X: Union[Point, FourQPoint], prover: str) -> bool:
        h = zkp.h
        r = zkp.r
        
        try:
            if hasattr(X, 'assertValidity'):
                X.assertValidity()
        except Exception:
            return False
        
        V = G.multiply(r).add(X.multiply(h))
        return h == await self.H(G, V, X, prover)