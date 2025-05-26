# app/core_algorithms/rsa_manual/rsa_core.py

from app.utils.math_utils import power, extended_gcd, mod_inverse, generate_large_prime

import random
import os

class RSAKeyGenerationError(Exception):
    pass

class RSAEncryptionError(Exception):
    pass

class RSADecryptionError(Exception):
    pass

def generate_keys(bits=2048, k_miller_rabin=20, e_value=65537):
    """
    生成RSA公钥和私钥对。

    参数:
        bits (int): 模数 n 的期望比特长度。p 和 q 的比特长度将是 bits/2。
                    通常是 1024, 2048, 3072, 4096 等。
        k_miller_rabin (int): 用于素性检验的米勒-拉宾测试轮数。
        e_value (int): 公钥指数 e 的期望值。通常是 65537。

    返回:
        tuple: ((n, e), (n, d)) 其中 (n, e) 是公钥，(n, d) 是私钥。
               或者在错误时抛出 RSAKeyGenerationError。
    """
    # if bits < 512:
    #     raise RSAKeyGenerationError("Number of bits must be at least 512")
    if bits % 2 != 0:
        raise RSAKeyGenerationError("Number of bits must be even")
    
    prime_bits = bits // 2

    #  print(f"开始生成 {prime_bits}-bit 的素数 p 和 q...")
    p = generate_large_prime(prime_bits, k_miller_rabin)
    # print(f"p = {p}")

    q = generate_large_prime(prime_bits, k_miller_rabin)
    # print(f"q = {q}")

    max_attempts_for_distinct_q = 10
    attempts = 0
    while p == q and attempts < max_attempts_for_distinct_q:
        q = generate_large_prime(prime_bits, k_miller_rabin)
        attempts += 1

    if p == q:
        raise RSAKeyGenerationError("Failed to generate distinct primes p and q")
    
    n = p * q
    # print(f"n = {n}")
    
    phi_n = (p - 1) * (q - 1)
    # print(f"phi_n = {phi_n}")

    e = e_value
    if not (1 < e < phi_n):
        raise RSAKeyGenerationError("Invalid value of e")
    
    g, x_for_gcd, y_for_gcd = extended_gcd(e, phi_n)
    if g != 1:
        raise RSAKeyGenerationError("Invalid value of e")
    
    try:
        d = mod_inverse(e, phi_n)
    except ValueError as err:
        raise RSAKeyGenerationError("Invalid value of e") from err
    
    return ((n, e), (n, d))

def _pkcs1_v1_5_pad_for_encryption(message_bytes, n_byte_len):
    """
    对消息进行 RSAES-PKCS1-v1_5 填充。

    参数:
        message_bytes (bytes): 原始明文字节串。
        n_byte_len (int): RSA模数n的字节长度 (k)。

    返回:
        bytes: 填充后的编码消息 EM，长度为 n_byte_len。
    Raises:
        RSAEncryptionError: 如果消息太长无法填充。
    """
    m_len = len(message_bytes)

    if m_len > n_byte_len - 11:
        raise RSAEncryptionError("Message too long for RSAES-PKCS1-v1_5")
    
    ps_len = n_byte_len - m_len - 3

    ps = b''
    while len(ps) < ps_len:
        random_byte = os.urandom(1)
        if random_byte != b'\x00':
            ps += random_byte

    em = b'\x00\x02' + ps + b'\x00' + message_bytes

    return em

def _pkcs1_v1_5_unpad_for_encryption(encoded_message_bytes, n_byte_len):
    """
    对 RSAES-PKCS1-v1_5 编码的消息进行去填充。

    参数:
        encoded_message_bytes (bytes): 解密后得到的编码消息EM (字节串形式，长度应为n_byte_len)。
                                       注意：这是RSA解密大整数后转换成的字节串。
        n_byte_len (int): RSA模数n的字节长度 (k)。 (用于验证EM长度)


    返回:
        bytes: 原始明文字节串 M。
    Raises:
        RSADecryptionError: 如果填充格式不正确。
    """
    if len(encoded_message_bytes) != n_byte_len:
        pass

    if not encoded_message_bytes or encoded_message_bytes[0] != 0x00:
        raise RSADecryptionError("Invalid RSAES-PKCS1-v1_5 encoding")
    if len(encoded_message_bytes) < 2 or encoded_message_bytes[1] != 0x02:
        raise RSADecryptionError("Invalid RSAES-PKCS1-v1_5 encoding")
    
    separator_index = -1
    try:
        separator_index = encoded_message_bytes.index(b'\x00', 2)
    except ValueError:
        raise RSADecryptionError("Invalid RSAES-PKCS1-v1_5 encoding")

    ps_len = separator_index - 2
    if ps_len < 8:
        raise RSADecryptionError("Invalid RSAES-PKCS1-v1_5 encoding")
    
    message_bytes = encoded_message_bytes[separator_index + 1:]
    
    return message_bytes

def encrypt_with_padding(public_key, message_bytes):
    """
    使用RSA公钥和PKCS#1 v1.5填充来加密消息字节串。

    参数:
        public_key (tuple): RSA公钥 (n, e)。
        message_bytes (bytes): 要加密的原始明文字节串。

    返回:
        bytes: 加密后的密文字节串。
    Raises:
        RSAEncryptionError, TypeError, ValueError
    """
    n, e = public_key

    if not isinstance(message_bytes, bytes):
        raise TypeError("Message must be bytes")
    
    k = (n.bit_length() + 7) // 8
    
    encoded_message_em = _pkcs1_v1_5_pad_for_encryption(message_bytes, k)
    if len(encoded_message_em) != k:
        raise RSAEncryptionError("Message too long for RSAES-PKCS1-v1_5")
    
    m = int.from_bytes(encoded_message_em, byteorder='big')

    c_int = power(m, e, n)
    
    try:
        ciphertext_bytes = c_int.to_bytes(k, byteorder='big')
    except OverflowError:
        raise RSAEncryptionError("Message too long for RSAES-PKCS1-v1_5")
    
    return ciphertext_bytes

def decrypt_with_padding(private_key, ciphertext_bytes):
    """
    使用RSA私钥解密经过PKCS#1 v1.5填充的密文。

    参数:
        private_key (tuple): RSA私钥 (n, d)。
        ciphertext_bytes (bytes): 要解密的密文字节串。

    返回:
        bytes: 解密并去填充后的原始明文字节串。
    Raises:
        RSADecryptionError, TypeError, ValueError
    """
    n, d = private_key

    if not isinstance(ciphertext_bytes, bytes):
        raise TypeError("Ciphertext must be bytes")
    
    k = (n.bit_length() + 7) // 8
    
    if len(ciphertext_bytes) != k:
        raise RSADecryptionError("Ciphertext too long for RSAES-PKCS1-v1_5")
    
    c_int = int.from_bytes(ciphertext_bytes, byteorder='big')
    
    m_int = power(c_int, d, n)
    
    try:
        encoded_message_em = m_int.to_bytes(k, byteorder='big')
    except OverflowError:
        raise RSADecryptionError("Ciphertext too long for RSAES-PKCS1-v1_5")
    
    original_message_bytes = _pkcs1_v1_5_unpad_for_encryption(encoded_message_em, k)
    
    return original_message_bytes

if __name__ == '__main__':
    print("开始测试 RSA 密钥生成、加密(带填充)和解密(带去填充)...")
    
    test_bits = 2048 # 使用更实际的比特长度，因为填充需要空间
    test_e = 65537
    
    print(f"\n测试生成 {test_bits}-bit RSA 密钥 (e={test_e}):")
    try:
        public_key, private_key = generate_keys(bits=test_bits, k_miller_rabin=10, e_value=test_e)
        # print(f"  公钥 (n, e): {public_key}")
        # print(f"  私钥 (n, d): {private_key}") # 私钥 d 通常不直接打印

        # 准备一个要加密的明文消息 (字节串形式)
        original_message = b"This is a secret message for RSA with PKCS#1 v1.5 padding."
        # 可以尝试不同长度的消息
        # original_message = os.urandom(100) # 随机100字节消息

        print(f"\n原始明文 (解码后预览): \"{original_message.decode('utf-8', errors='ignore')[:60]}...\"")

        # 测试加密 (带填充)
        ciphertext = encrypt_with_padding(public_key, original_message)
        
        # 测试解密 (带去填充)
        decrypted_message = decrypt_with_padding(private_key, ciphertext)
        
        print("\n--- 验证结果 ---")
        # print(f"  原始明文 (bytes): {original_message}")
        # print(f"  解密明文 (bytes): {decrypted_message}")

        if decrypted_message == original_message:
            print("\n成功：解密后的明文与原始明文一致！")
        else:
            print("\n失败：解密后的明文与原始明文不一致。")
            print(f"  原始 (解码后): {original_message.decode('utf-8', errors='ignore')}")
            print(f"  解密 (解码后): {decrypted_message.decode('utf-8', errors='ignore')}")
            
        # 测试消息过长的情况
        n_val, _ = public_key
        k_len = (n_val.bit_length() + 7) // 8
        too_long_message = os.urandom(k_len - 10) # 应该失败 (k - 11 是最大)
        print(f"\n测试加密过长消息 (长度 {len(too_long_message)}, 最大允许 {k_len-11})...")
        try:
            encrypt_with_padding(public_key, too_long_message)
            print("错误：加密过长消息时未抛出异常！") # 如果执行到这里说明有问题
        except RSAEncryptionError as e:
            print(f"成功捕获到预期错误: {e}")
            
        # 测试错误的填充解密 (例如，修改密文或EM的格式)
        print("\n测试解密一个格式错误的密文...")
        if len(ciphertext) > 0 :
            bad_ciphertext = bytearray(ciphertext)
            bad_ciphertext[len(bad_ciphertext)//2] ^= 0xFF # 修改密文中间的一个字节
            try:
                decrypt_with_padding(private_key, bytes(bad_ciphertext))
                print("错误：解密格式错误的密文时未抛出异常！")
            except RSADecryptionError as e:
                print(f"成功捕获到预期错误: {e}")


    except (RSAKeyGenerationError, RSAEncryptionError, RSADecryptionError, ValueError, TypeError) as e:
        print(f"RSA操作过程中发生错误: {e}")
    except Exception as e:
        print(f"发生未知错误: {e}")