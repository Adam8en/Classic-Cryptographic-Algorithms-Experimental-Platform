# app/core_algorithms/ecc_manual/ecc_core.py

import random
from hashlib import sha256
from itertools import cycle
from app.utils.math_utils import mod_inverse # power 函数在这里可能用不上

CURVE_PARAMETERS = {
    "secp192r1": { # NIST P-192
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
        "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC,
        "b": 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
        "Gx": 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
        "Gy": 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
        "h": 1
    },
    "secp256r1": { # NIST P-256 (与 secp256k1 不同)
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "Gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "Gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "h": 1
    },
    "secp256k1": { # 比特币使用的曲线
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "a": 0,
        "b": 7,
        "Gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        "Gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        "h": 1
    },
    "secp384r1": { # NIST P-384
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        "b": 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        "Gx": 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        "Gy": 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        "h": 1
    }
}

# 用于缓存已创建的曲线对象，避免重复实例化
_CURVE_INSTANCES = {}

def get_curve_by_name(name="secp256k1"):
    """根据名称获取或创建 EllipticCurve 对象"""
    if name not in _CURVE_INSTANCES:
        if name not in CURVE_PARAMETERS:
            raise ValueError(f"未知的椭圆曲线名称: {name}")
        params = CURVE_PARAMETERS[name]
        # 实例化 EllipticCurve 对象
        _CURVE_INSTANCES[name] = EllipticCurve(
            params["p"], params["a"], params["b"],
            params["Gx"], params["Gy"], params["n"], params["h"]
        )
    return _CURVE_INSTANCES[name]

class ECCKeyGenerationError(Exception):
    """自定义异常，用于ECC密钥生成过程中的错误。"""
    pass

class ECIESEncryptionError(Exception):
    """自定义异常，用于ECC加密过程中的错误。"""
    pass

class ECIESDecryptionError(Exception):
    """自定义异常，用于ECC解密过程中的错误。"""
    pass

class EllipticCurve:
    def __init__(self, p, a, b, Gx, Gy, n, h):
        self.p = p  # 有限域的素数模数
        self.a = a  # 曲线参数 a
        self.b = b  # 曲线参数 b
        self.Gx = Gx # 基点的 x 坐标
        self.Gy = Gy # 基点的 y 坐标
        self.G = CurvePoint(self, Gx, Gy) # 基点对象
        self.n = n  # 基点 G 的阶
        self.h = h  # 余因子

        # 检查点 G 是否在曲线上 (可选，但好的做法)
        if not self.is_on_curve(self.G):
            raise ValueError("基点 G 不在定义的椭圆曲线上")

    def is_on_curve(self, point):
        if point.is_infinity(): # 无穷远点总是在曲线上
            return True
        # 验证方程: y^2 = x^3 + ax + b (mod p)
        left_side = (point.y * point.y) % self.p
        right_side = (point.x**3 + self.a * point.x + self.b) % self.p
        return left_side == right_side

class CurvePoint:
    def __init__(self, curve, x, y):
        self.curve = curve # 点所在的椭圆曲线对象
        self.x = x         # 点的 x 坐标 (如果点是无穷远点，则为 None)
        self.y = y         # 点的 y 坐标 (如果点是无穷远点，则为 None)

    def is_infinity(self):
        # 判断当前点是否为无穷远点
        return self.x is None and self.y is None

    def __eq__(self, other):
        # 判断两个点是否相等
        if not isinstance(other, CurvePoint):
            return False # 类型不同，则不相等
        if self.curve != other.curve: # 不同曲线上的点不能直接比较
            # 或者可以抛出 TypeError 异常，取决于设计选择
            # print("警告: 正在比较不同曲线上的点") # 用于调试
            return False
        return self.x == other.x and self.y == other.y

    def __str__(self):
        # 返回点的字符串表示形式，方便打印和调试
        if self.is_infinity():
            return "点(无穷远点)"
        # 以十六进制表示坐标和模数，更符合密码学常规
        return f"点(x=0x{self.x:x}, y=0x{self.y:x}) 在曲线 y^2=x^3+{self.curve.a}x+{self.curve.b} mod 0x{self.curve.p:x}"

    def __repr__(self):
        # __repr__ 通常返回一个可以用来重新创建该对象的字符串表示
        return self.__str__()

    def __add__(self, other):
        # 实现椭圆曲线上的点加法 R = P + Q (self 代表 P, other 代表 Q)
        if not isinstance(other, CurvePoint):
            raise TypeError("点加法操作要求另一个操作数也是 CurvePoint 类型。")
        if self.curve != other.curve:
            raise TypeError("不能对不同椭圆曲线上的点进行相加。")

        # 情况 1: P 是无穷远点 (O + Q = Q)
        if self.is_infinity():
            return other
        # 情况 2: Q 是无穷远点 (P + O = P)
        if other.is_infinity():
            return self

        # 为了方便，获取坐标和曲线参数
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        p = self.curve.p
        a = self.curve.a # 对于 secp256k1, a = 0

        # 情况 3: P = -Q (即 x1 = x2 且 y1 + y2 = 0 mod p)
        # 此时 P + Q = O (无穷远点)
        if x1 == x2 and (y1 + y2) % p == 0:
            return CurvePoint(self.curve, None, None) # 返回无穷远点

        # 情况 4: P != Q (两个不同的点相加)
        if x1 != x2:
            # 计算斜率 lambda = (y2 - y1) * (x2 - x1)^-1 mod p
            # (x2 - x1)^-1 mod p 就是 mod_inverse(x2 - x1, p)
            
            # 计算 delta_x = (x2 - x1) mod p，确保结果在 [0, p-1] 范围内
            delta_x = (x2 - x1 + p) % p 
            if delta_x == 0:
                # 此情况理论上不应在这里发生，因为 x1 != x2 意味着 delta_x % p != 0。
                # 如果发生，说明逻辑有误或 (x2-x1) 是p的倍数但x1,x2模p不同，这不可能。
                # 或者 x1 == x2 但 y1 != y2 且 y1 != -y2，这在曲线上是不可能的。
                raise Exception("点加法中出现意外的 delta_x 为零情况 (当 x1 != x2 时)。")

            try:
                inv_delta_x = mod_inverse(delta_x, p) # 计算 (x2 - x1) 的模逆元
            except ValueError:
                # 如果 mod_inverse 抛出 ValueError，说明 delta_x 和 p 不互素，
                # 这意味着 delta_x 是 p 的倍数，即 delta_x % p == 0。
                # 这与 x1 != x2 的前提矛盾 (除非 p 非常小或者 x1, x2 的选择有问题)。
                # 对于大的素数 p，这种情况几乎不可能发生。
                raise Exception(f"计算 (x2-x1) 的模逆元失败: delta_x={delta_x}, p={p}。可能两点相同或互为逆元但未被正确处理。")

            # 计算 y2 - y1 (mod p)
            delta_y = (y2 - y1 + p) % p
            lambda_val = (delta_y * inv_delta_x) % p # 斜率 lambda
            
            # 计算新点的坐标 (x3, y3)
            # x3 = lambda^2 - x1 - x2 mod p
            x3 = (lambda_val**2 - x1 - x2 + 2*p) % p # +2*p 确保中间结果为正，再取模
            
            # y3 = lambda * (x1 - x3) - y1 mod p
            y3 = (lambda_val * ((x1 - x3 + p) % p) - y1 + p) % p # 确保中间结果为正
            
            return CurvePoint(self.curve, x3, y3)

        # 情况 5: P = Q (点倍积 self == other)
        if self == other: # self == other 意味着 x1=x2 且 y1=y2
                          # 并且 y1 != 0 (因为 y1=0 的情况在上面 Case 3 中 P+(-P) 时，如果 P=Q且y1=0, 则 P+P=O)
                          # 或者直接调用专门的倍点方法
            return self.double()
            
        # 理论上所有情况都应被覆盖，如果代码执行到这里，说明有未处理的逻辑分支
        raise Exception("点加法 __add__ 方法中存在未处理的情况。")

    def double(self):
        # 实现点倍积 R = 2P (self 代表 P)
        if self.is_infinity(): # O + O = O
            return self # 无穷远点的两倍还是无穷远点

        x1, y1 = self.x, self.y
        p = self.curve.p
        a = self.curve.a # 曲线参数 a (对于 secp256k1, a=0)

        # 情况：y1 = 0 (此时切线垂直，2P = O)
        # (例如，在曲线上 y^2 = x^3+7，如果y=0, 则 x^3+7=0 mod p。这样的点是存在的)
        if y1 == 0:
            return CurvePoint(self.curve, None, None) # 返回无穷远点

        # 计算斜率 lambda = (3*x1^2 + a) * (2*y1)^-1 mod p
        numerator = (3 * (x1**2) + a) % p
        denominator = (2 * y1) % p
        
        if denominator == 0:
            # 对于素数p > 2，2*y1 % p == 0 意味着 y1 % p == 0，
            # 这种情况应该在上面的 y1 == 0 中被捕获。
            # 这是一个额外的安全检查。
            return CurvePoint(self.curve, None, None) 

        try:
            inv_2y1 = mod_inverse(denominator, p) # 计算 (2*y1) 的模逆元
        except ValueError:
            # 如果 (2*y1) 和 p 不互素 (例如，当 p=2 时，或 2*y1 是 p 的倍数)
            # 对于 p>2 且 y1!=0，这不应发生。
            raise Exception(f"计算 (2*y1) 的模逆元失败: 2*y1={denominator}, p={p}。")
            
        lambda_val = (numerator * inv_2y1) % p # 斜率 lambda
        
        # 计算新点的坐标 (x3, y3)
        # x3 = lambda^2 - 2*x1 mod p
        x3 = (lambda_val**2 - 2 * x1 + 2*p) % p # +2*p 确保中间结果为正
        
        # y3 = lambda * (x1 - x3) - y1 mod p
        y3 = (lambda_val * ((x1 - x3 + p) % p) - y1 + p) % p # 确保中间结果为正
        
        new_point = CurvePoint(self.curve, x3, y3)
        
        # （调试时可选）检查新生成的点是否仍在曲线上
        # if not self.curve.is_on_curve(new_point):
        #     print(f"警告: 点倍积的结果 {new_point} 不在曲线上!")
        #     print(f"输入点 P={self}")
        #     print(f"lambda={lambda_val}, numerator={numerator}, denominator={denominator}, inv_2y1={inv_2y1}")
            
        return new_point
        
    def __mul__(self, scalar_k):
    # P * k (点在左，标量在右)
    # 通常 ECC 中我们说 k * P (标量在左)
    # 为了符合 Python 的习惯，scalar_k * P 会调用 P.__rmul__(scalar_k)
    # 而 P * scalar_k 会调用 P.__mul__(scalar_k)
    # 我们可以让它们行为一致
        if not isinstance(scalar_k, int):
            raise TypeError("点乘的标量必须是整数。")
        
        return self._scalar_multiply(scalar_k)

    def __rmul__(self, scalar_k):
        # k * P (标量在左，点在右) - 这是更常见的ECC表示法
        if not isinstance(scalar_k, int):
            raise TypeError("点乘的标量必须是整数。")
            
        return self._scalar_multiply(scalar_k)

    def _scalar_multiply(self, k):
        # 实现点乘 k * P (self 代表 P)
        # 使用 "倍点-加点" 算法 (从左到右扫描 k 的二进制位)

        if self.is_infinity(): # k * O = O
            return CurvePoint(self.curve, None, None)
        if k == 0: # 0 * P = O
            return CurvePoint(self.curve, None, None)
        if k < 0:
            # k * P = (-k) * (-P)
            # 首先计算 -P
            minus_self_y = (-self.y + self.curve.p) % self.curve.p
            minus_self = CurvePoint(self.curve, self.x, minus_self_y)
            # 然后计算 (-k) * (-P)
            return minus_self._scalar_multiply(-k)

        # 将 k 转换为二进制表示，例如 "0b1101"
        k_binary = bin(k)
        
        # 初始化结果点。
        # 如果从最高有效位开始，可以跳过第一个 '1' (因为它已经通过current_P体现)
        # 然后对其余位进行迭代。
        # current_P 对应于当前正在处理的 P 的倍数 (P, 2P, 4P, ...)
        # result_point 累加结果
        
        result_point = CurvePoint(self.curve, None, None) # 初始化为无穷远点 O
        current_P_multiple = self # 开始时是 1*P
        
        # 从 k 的最低有效位开始处理 (另一种常见的"倍点-加点"变体，从右到左)
        # k_temp = k
        # while k_temp > 0:
        #     if k_temp & 1: # 如果当前最低位是1
        #         result_point = result_point + current_P_multiple
        #     current_P_multiple = current_P_multiple.double() # P -> 2P -> 4P -> ...
        #     k_temp >>= 1 # 右移一位，处理下一位
        # return result_point

        # 我们采用从左到右的扫描方式 (更直观对应二进制展开)
        # k_binary[2:] 去掉 "0b" 前缀
        # 第一个 '1' (最高有效位) 直接将 P 赋值给结果
        
        # 找到第一个 '1' (最高有效位) 之后的部分
        # 例如 k=13 (0b1101)
        # 我们初始化 result_point = self (对应第一个 '1')
        # 然后迭代处理 "101"
        
        # 简单实现：
        # 从 k_binary[2:] 的第二位开始（即跳过最高位的'1'）
        # 例如 k=13 (0b1101)
        # result_point = P (对应最高位的1)
        # 处理 '1': result_point = double(result_point); result_point = result_point + P
        # 处理 '0': result_point = double(result_point);
        # 处理 '1': result_point = double(result_point); result_point = result_point + P
        
        # 更标准的从左到右：
        # R = O
        # for bit_i in k_binary[2:]: (从最高位开始)
        #   R = R.double()
        #   if bit_i == '1':
        #     R = R + self
        # return R
        
        # 优化：可以跳过前导的无穷远点加倍
        # R 初始化为 P (如果k>0)，然后从k的次高位开始
        if k == 0: return CurvePoint(self.curve, None, None) # 0*P = O
        
        # 使用 Pythonic 的从左到右方法
        # (从《Guide to Elliptic Curve Cryptography》by Hankerson, Menezes, Vanstone - Algorithm 3.26)
        # Input: Integer k >=0, Point P
        # Output: Q = kP
        # 1. If k = 0, return O.
        # 2. Let k = (k_{t-1} ... k_1 k_0)_2 with k_{t-1} = 1.  (t is bit length of k)
        # 3. Q <- P
        # 4. For i from t-2 down to 0 do
        # 5.   Q <- 2Q
        # 6.   If k_i = 1 then Q <- Q + P
        # 7. Return Q
        
        k_bin_str = k_binary[2:] # 去掉 "0b"
        t = len(k_bin_str)
        
        if t == 0: # 应该不会发生，因为 k>0
            return CurvePoint(self.curve, None, None)

        current_result = self # 对应 k_{t-1} = 1 (最高位)
        
        # 从次高位 (t-2) 开始到最低位 (0)
        for i in range(1, t): # i 从 1 到 t-1 (对应 k_bin_str 的索引)
            current_result = current_result.double()
            if k_bin_str[i] == '1':
                current_result = current_result + self
                
        return current_result

def generate_ecc_keys(curve_name="secp256k1"):
    """
    生成ECC密钥对 (私钥和公钥)。

    参数:
        curve (EllipticCurve, optional): 要使用的椭圆曲线对象。
                                         如果为 None，则默认使用 secp256k1_curve。

    返回:
        tuple: (private_key, public_key_point)
               private_key (int): ECC私钥 (一个整数)。
               public_key_point (CurvePoint): ECC公钥 (椭圆曲线上的一个点)。
    Raises:
        ECCKeyGenerationError: 如果密钥生成过程中发生错误。
    """
    curve = get_curve_by_name(curve_name)

    if not isinstance(curve, EllipticCurve):
        raise TypeError("curve must be an instance of EllipticCurve")
    
    # 1. 获取基点的阶 n
    n = curve.n
    if n is None or n <= 1:
        raise ECCKeyGenerationError("n is None or n <= 1")
    
    # 2. 生成私钥 d_priv
    try:
        private_key = random.randint(1, n-1)
    except ValueError:
        raise ECCKeyGenerationError("Failed to generate private key")

    # 3. 计算公钥 Q = d_priv * G
    base_point_G = curve.G

    try:
        public_key_point = private_key * base_point_G
    except Exception as e:
        raise ECCKeyGenerationError(f"Failed to generate public key: {e}")
    
    if public_key_point.is_infinity():
        raise ECCKeyGenerationError("Generated public key is at infinity")
    
    return private_key, public_key_point

def _xor_bytes(data, key):
    """
    对字节串 data 和 key 进行异或操作。
    如果 key 比 data 短，key 将被循环使用。
    """
    return bytes([d_byte ^ k_byte for d_byte, k_byte in zip(data, cycle(key))])

def _derive_symmetric_key_from_point(shared_point_S):
    """
    从共享密钥点 S 的 x 坐标派生对称密钥。
    使用 SHA256 哈希 S.x。
    """
    if shared_point_S.is_infinity():
        raise ECIESEncryptionError("Shared point S is at infinity")
    
    sx_bytes = shared_point_S.x.to_bytes((shared_point_S.x.bit_length() + 7) // 8, byteorder='big')

    symmetric_key = sha256(sx_bytes).digest()

    return symmetric_key

def encrypt_message_ecc(recipient_public_key_point, message_bytes):
    """
    使用简化的ECIES方案通过ECC公钥加密消息。

    参数:
        recipient_public_key_point (CurvePoint): 接收方的ECC公钥点 Q。
        message_bytes (bytes): 要加密的明文字节串。
        curve (EllipticCurve, optional): 使用的椭圆曲线。如果为None，使用默认的secp256k1。

    返回:
        tuple: (ephemeral_public_key_R, ciphertext_bytes)
               ephemeral_public_key_R (CurvePoint): 发送方生成的临时公钥点 R。
               ciphertext_bytes (bytes): 加密后的密文字节串。
    Raises:
        ECIESEncryptionError: 如果加密过程中发生错误。
        TypeError: 如果参数类型不正确。
    """
    curve = recipient_public_key_point.curve

    if not curve:
        raise ECIESEncryptionError("Curve is not initialized")
    
    if not isinstance(recipient_public_key_point, CurvePoint) or recipient_public_key_point.is_infinity():
        raise TypeError("recipient_public_key_point must be an instance of CurvePoint and not at infinity")
    if not isinstance(message_bytes, bytes):
        raise TypeError("message_bytes must be bytes")
    
    # 1. 随机生成临时私钥 k_e，范围 [1, n-1]
    n = curve.n
    try:
        k_e = random.randint(1, n-1)
    except ValueError:
        raise ECIESEncryptionError("Failed to generate ephemeral private key")
    
    # 2. 计算临时公钥 R = k_e * G
    G = curve.G
    ephemeral_public_key_R = k_e * G
    if ephemeral_public_key_R.is_infinity():
        raise ECIESEncryptionError("Generated ephemeral public key is at infinity")
    
    # 3. 计算共享密钥点 S = k_e * Q
    shared_point_S = k_e * recipient_public_key_point
    if shared_point_S.is_infinity():
        raise ECIESEncryptionError("Shared point S is at infinity")
    
    # 4. 派生对称密钥
    symmetric_key = _derive_symmetric_key_from_point(shared_point_S)
    
    # 5. 加密消息
    ciphertext_bytes = _xor_bytes(message_bytes, symmetric_key)
    
    return ephemeral_public_key_R, ciphertext_bytes

def decrypt_message_ecc(recipient_private_key, ephemeral_public_key_R, ciphertext_bytes):
    """
    使用简化的ECIES方案通过ECC私钥解密消息。

    参数:
        recipient_private_key (int): 接收方的ECC私钥 d。
        ephemeral_public_key_R (CurvePoint): 加密时发送方生成的临时公钥点 R。
        ciphertext_bytes (bytes): 要解密的密文字节串 C。
        curve (EllipticCurve, optional): 使用的椭圆曲线。如果为None，
                                         则尝试从 ephemeral_public_key_R 获取，
                                         或使用默认的secp256k1。

    返回:
        bytes: 解密后的明文字节串。
    Raises:
        ECIESDecryptionError: 如果解密过程中发生错误。
        TypeError: 如果参数类型不正确。
    """
    curve = ephemeral_public_key_R.curve
    if not curve:
        raise ECIESDecryptionError("Curve is not initialized")
    
    if not isinstance(recipient_private_key, int) or recipient_private_key <= 0 or recipient_private_key >= curve.n:
        raise TypeError("recipient_private_key must be a positive integer less than n")
    if not isinstance(ephemeral_public_key_R, CurvePoint) or ephemeral_public_key_R.is_infinity():
        raise TypeError("ephemeral_public_key_R must be an instance of CurvePoint and not at infinity")
    if not isinstance(ciphertext_bytes, bytes):
        raise TypeError("ciphertext_bytes must be bytes")    
        
    n = curve.n
    if not (1 <= recipient_private_key < n):
        raise ECIESDecryptionError("recipient_private_key out of range")
    
    # 1. 计算共享密钥点 S' = d_recipient * R
    shared_point_S = recipient_private_key * ephemeral_public_key_R
    if shared_point_S.is_infinity():
        raise ECIESDecryptionError("Shared point S' is at infinity")
    
    # 2. 派生对称密钥
    symmetric_key = _derive_symmetric_key_from_point(shared_point_S)
    
    # 3. 解密消息
    decrypted_message_bytes = _xor_bytes(ciphertext_bytes, symmetric_key)
    
    return decrypted_message_bytes

# --- 测试代码 ---
if __name__ == '__main__':
    print("\n--- 测试使用不同曲线的ECC密钥生成与加解密 ---")
    
    # 定义我们要测试的曲线名称列表
    curve_names_to_test = ["secp192r1", "secp256r1", "secp256k1", "secp384r1"]

    for name in curve_names_to_test:
        print(f"\n==================== 测试曲线: {name} ====================")
        try:
            # 1. 获取曲线对象
            current_curve = get_curve_by_name(name)

            # 2. 密钥生成
            priv_key, pub_key = generate_ecc_keys(curve_name=name)
            
            # 3. 验证公钥点在正确的曲线上
            assert current_curve.is_on_curve(pub_key), f"曲线 {name} 的公钥不在曲线上!"
            assert pub_key.curve == current_curve, f"公钥点的曲线属性不正确!"
            print(f"  公钥点在曲线 {name} 上验证通过。")

            # 4. 加解密循环测试
            message = f"这是一条用于测试曲线 {name} 的消息!".encode('utf-8')
            print(f"  将使用消息: \"{message.decode()}\" 进行加解密测试...")
            
            ephemeral_R, ciphertext = encrypt_message_ecc(pub_key, message)
            
            # 验证临时公钥R也在正确的曲线上
            assert ephemeral_R.curve == current_curve, "临时公钥R的曲线属性不正确！"
            
            decrypted_message = decrypt_message_ecc(priv_key, ephemeral_R, ciphertext)
            
            assert message == decrypted_message, f"曲线 {name} 上的加解密失败！"
            print(f"  曲线 {name} 的加解密循环测试成功！")

        except Exception as e:
            print(f"测试曲线 {name} 时发生严重错误: {e}")
            # raise e # 如果你想在出错时停止整个脚本，可以取消这行注释
    
    print("\n==================== 所有曲线测试完成 ====================")