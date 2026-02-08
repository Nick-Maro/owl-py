import secrets
from typing import Tuple

class GFp2:
    
    p = 2**127 - 1
    
    @staticmethod
    def add(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
        return ((a[0] + b[0]) % GFp2.p, (a[1] + b[1]) % GFp2.p)
    
    @staticmethod
    def sub(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
        return ((a[0] - b[0]) % GFp2.p, (a[1] - b[1]) % GFp2.p)
    
    @staticmethod
    def mul(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
        a0, a1 = a
        b0, b1 = b
        c0 = (a0 * b0 - a1 * b1) % GFp2.p
        c1 = (a0 * b1 + a1 * b0) % GFp2.p
        return (c0, c1)
    
    @staticmethod
    def sqr(a: Tuple[int, int]) -> Tuple[int, int]:
        a0, a1 = a
        c0 = (a0 * a0 - a1 * a1) % GFp2.p
        c1 = (2 * a0 * a1) % GFp2.p
        return (c0, c1)
    
    @staticmethod
    def neg(a: Tuple[int, int]) -> Tuple[int, int]:
        return ((-a[0]) % GFp2.p, (-a[1]) % GFp2.p)
    
    @staticmethod
    def inv(a: Tuple[int, int]) -> Tuple[int, int]:
        a0, a1 = a
        denom = (a0 * a0 + a1 * a1) % GFp2.p
        denom_inv = pow(denom, GFp2.p - 2, GFp2.p)
        return ((a0 * denom_inv) % GFp2.p, ((-a1) * denom_inv) % GFp2.p)
    
    @staticmethod
    def conj(a: Tuple[int, int]) -> Tuple[int, int]:
        return (a[0], (-a[1]) % GFp2.p)


class FourQPoint:

    
    p = 2**127 - 1
    d = (0xe40000000000000142, 0x5e472f846657e0fcb3821488f1fc0c8d)
    N = 0x29CBC14E5E0A72F05397829CBC14E5DFBD004DFE0F79992FB2540EC7768CE7
    
    Ox = (0, 0)
    Oy = (1, 0)
    Gx = (0x1A3472237C2FB305286592AD7B3833AA, 0x1E1F553F2878AA9C96869FB360AC77F6)
    Gy = (0x0E3FEE9BA120785AB924A2462BCBB287, 0x6E1C4AF8630E024249A7C344844C8B5C)
    
    def __init__(self, x: Tuple[int, int], y: Tuple[int, int], z: Tuple[int, int] = None, 
                 ta: Tuple[int, int] = None, tb: Tuple[int, int] = None, is_infinity=False):
        self.x = x
        self.y = y
        self.z = z if z is not None else (1, 0)
        self.ta = ta if ta is not None else x
        self.tb = tb if tb is not None else y
        self.is_infinity = is_infinity
    
    @classmethod
    def infinity(cls):
        return cls(cls.Ox, cls.Oy, (1, 0), cls.Ox, cls.Oy, is_infinity=True)
    
    @classmethod
    def generator(cls):
        return cls(cls.Gx, cls.Gy)
    
    @classmethod
    def from_hex(cls, hex_str: str):
        data = bytes.fromhex(hex_str)
        if len(data) != 64:
            raise ValueError("FourQ requires exactly 64 bytes")
        
        x0 = int.from_bytes(data[0:16], 'little')
        x1 = int.from_bytes(data[16:32], 'little')
        y0 = int.from_bytes(data[32:48], 'little')
        y1 = int.from_bytes(data[48:64], 'little')
        
        return cls((x0, x1), (y0, y1))
    
    def to_hex(self) -> str:
        if self.is_infinity:
            return "00" * 64
        
        x_aff, y_aff = self.to_affine()
        
        result = b''
        result += x_aff[0].to_bytes(16, 'little')
        result += x_aff[1].to_bytes(16, 'little')
        result += y_aff[0].to_bytes(16, 'little')
        result += y_aff[1].to_bytes(16, 'little')
        
        return result.hex()
    
    def toRawBytes(self) -> bytes:
        return bytes.fromhex(self.to_hex())
    
    def to_affine(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        if self.is_infinity:
            return (self.Ox, self.Oy)
        
        z_inv = GFp2.inv(self.z)
        x_aff = GFp2.mul(self.x, z_inv)
        y_aff = GFp2.mul(self.y, z_inv)
        return (x_aff, y_aff)
    
    def double(self) -> 'FourQPoint':
        if self.is_infinity:
            return self
        
        X1, Y1, Z1 = self.x, self.y, self.z
        
        A = GFp2.sqr(X1)
        B = GFp2.sqr(Y1)
        C = GFp2.mul((2, 0), GFp2.sqr(Z1))
        D = GFp2.add(A, B)
        E = GFp2.sub(GFp2.sqr(GFp2.add(X1, Y1)), D)
        F = GFp2.sub(B, A)
        G = GFp2.sub(C, F)
        
        X3 = GFp2.mul(E, G)
        Y3 = GFp2.mul(D, F)
        Z3 = GFp2.mul(F, G)
        Ta3 = E
        Tb3 = D
        
        return FourQPoint(X3, Y3, Z3, Ta3, Tb3)
    
    def add(self, other: 'FourQPoint') -> 'FourQPoint':
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        
        X1, Y1, Z1, Ta1, Tb1 = self.x, self.y, self.z, self.ta, self.tb
        N1 = GFp2.add(X1, Y1)
        D1 = GFp2.sub(Y1, X1)
        E1 = Z1
        F1 = GFp2.mul(Ta1, Tb1)
        
        X2, Y2, Z2, Ta2, Tb2 = other.x, other.y, other.z, other.ta, other.tb
        N2 = GFp2.add(X2, Y2)
        D2 = GFp2.sub(Y2, X2)
        Z2_doubled = GFp2.add(Z2, Z2)
        T2 = GFp2.mul((2, 0), GFp2.mul(GFp2.mul(self.d, Ta2), Tb2))
        
        A = GFp2.mul(D1, D2)
        B = GFp2.mul(N1, N2)
        C = GFp2.mul(T2, F1)
        D = GFp2.mul(Z2_doubled, E1)
        E = GFp2.sub(B, A)
        F = GFp2.sub(D, C)
        G = GFp2.add(D, C)
        H = GFp2.add(B, A)
        
        X3 = GFp2.mul(E, F)
        Y3 = GFp2.mul(G, H)
        Z3 = GFp2.mul(F, G)
        Ta3 = E
        Tb3 = H
        
        return FourQPoint(X3, Y3, Z3, Ta3, Tb3)
    
    def multiply(self, scalar: int) -> 'FourQPoint':
        if self.is_infinity or scalar == 0:
            return FourQPoint.infinity()
        
        scalar = scalar % self.N
        
        R0 = FourQPoint.infinity()
        R1 = FourQPoint(self.x, self.y, self.z, self.ta, self.tb)
        
        for i in range(scalar.bit_length() - 1, -1, -1):
            if (scalar >> i) & 1:
                R0 = R0.add(R1)
                R1 = R1.double()
            else:
                R1 = R0.add(R1)
                R0 = R0.double()
        
        return R0
    
    def subtract(self, other: 'FourQPoint') -> 'FourQPoint':
        if other.is_infinity:
            return self
        
        neg_x = GFp2.neg(other.x)
        neg_other = FourQPoint(neg_x, other.y, other.z, 
                               GFp2.neg(other.ta), other.tb)
        return self.add(neg_other)
    
    def equals(self, other: 'FourQPoint') -> bool:
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        
        x1, y1 = self.to_affine()
        x2, y2 = other.to_affine()
        
        return x1 == x2 and y1 == y2
    
    def assertValidity(self):
        if self.is_infinity:
            return
        
        x_aff, y_aff = self.to_affine()
        
        x2 = GFp2.sqr(x_aff)
        y2 = GFp2.sqr(y_aff)
        
        lhs = GFp2.sub(y2, x2)
        rhs = GFp2.add((1, 0), GFp2.mul(GFp2.mul(self.d, x2), y2))
        
        if lhs != rhs:
            raise ValueError("Point not on FourQ curve")
    
    def __repr__(self):
        if self.is_infinity:
            return "FourQPoint(infinity)"
        x_aff, y_aff = self.to_affine()
        return f"FourQPoint(x=({hex(x_aff[0])[:16]}..., {hex(x_aff[1])[:16]}...), y=({hex(y_aff[0])[:16]}..., {hex(y_aff[1])[:16]}...))"


def rand_scalar_fourq() -> int:
    
    rand_bytes = secrets.token_bytes(32)
    return int.from_bytes(rand_bytes, 'big') % FourQPoint.N