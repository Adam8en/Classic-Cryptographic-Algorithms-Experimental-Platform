# app/core_algorithms/elgamal_manual/elgamal_core.py

import random
from app.utils.math_utils import generate_large_prime, power, mod_inverse

class ElGamalKeyGenerationError(Exception):
    """自定义异常，用于ElGamal密钥生成过程中的错误。"""
    pass

class ElGamalEncryptionError(Exception):
    """自定义异常，用于ElGamal加密过程中的错误。"""
    pass

class ElGamalDecryptionError(Exception):
    """自定义异常，用于ElGamal解密过程中的错误。"""
    pass

def generate_keys(bits=512, k_miller_rabin=20):
    """
    生成ElGamal公钥和私钥对。
    公钥是 (p, g, y)，私钥是 (p, g, x)。
    为了方便，私钥通常只存储 x，因为 p 和 g 是公开参数。

    参数:
        bits (int): 模数 p 的期望比特长度。
        k_miller_rabin (int): 用于素性检验的米勒-拉宾测试轮数。
        g_value (int): 生成元 g 的期望值。实际应用中 g 的选择更复杂。

    返回:
        tuple: (public_key, private_key)
               public_key = (p, g, y)
               private_key = (x)  (p 和 g 也会被使用，所以通常也会包含它们以便解密时使用)
               或者在错误时抛出 ElGamalKeyGenerationError。
    """
    if bits < 16:
        raise ElGamalKeyGenerationError("Number of bits must be at least 16")
    
    # 1. 生成大素数 p
    p = generate_large_prime(bits, k_miller_rabin)

    # 2. 选择生成元 g
    # 为了演示简便，尝试使用一个小的固定值，并确保1 < g < p
    g = 0
    possible_gs = [2, 3, 5, 7]

    for g_candidate in possible_gs:
        if 1 < g_candidate < p:
            g = g_candidate
            break

    if g == 0:
        if p > 2:
            raise ElGamalKeyGenerationError("Could not find a suitable value for g")
        elif p == 2:
            raise ElGamalKeyGenerationError("The only suitable value for g is 1")
        
    # 3. 生成私钥 x
    try:
        x = random.randint(1, p - 2)
    except ValueError:
        raise ElGamalKeyGenerationError("Could not generate a suitable value for x")

    # 4. 计算公钥 y = g^x mod p
    y = power(g, x, p)

    public_key = (p, g, y)
    private_key = (x)

    return public_key, private_key

def encrypt(public_key, message_int):
    """
    使用ElGamal公钥加密一个整数表示的明文。

    参数:
        public_key (tuple): ElGamal公钥 (p, g, y)。
        message_int (int): 要加密的明文，表示为一个整数。
                           调用者需要确保 0 <= message_int < p。

    返回:
        tuple: 加密后的密文对 (c1, c2)。
    Raises:
        ElGamalEncryptionError: 如果明文格式不正确。
    """
    p, g, y = public_key

    if not isinstance(message_int, int) or message_int < 0 or message_int >= p:
        raise ElGamalEncryptionError("Invalid message format")

    try:
        k = random.randint(1, p - 1)
    except ValueError:
        raise ElGamalEncryptionError("Could not generate a suitable value for k")

    c1 = power(g, k, p)
    
    s = power(y, k, p)
    if s == 0:
        raise ElGamalEncryptionError("Could not generate a suitable value for s")
    
    c2 = (message_int * s) % p
    ciphertext = (c1, c2)

    return ciphertext

def decrypt(private_key_x, p, g, ciphertext):
    """
    使用ElGamal私钥 x 和公开参数 p, g 解密密文。

    参数:
        private_key_x (int): ElGamal私钥 x。
        p (int): 公开参数，大素数模数。
        g (int): 公开参数，生成元。 (注意: g 在标准ElGamal解密中并不直接使用，
                                     但通常与p一起作为域参数传递)
        ciphertext (tuple): 要解密的密文对 (c1, c2)。

    返回:
        int: 解密后的明文整数。
    Raises:
        ElGamalDecryptionError: 如果解密失败或参数错误。
    """
    if not isinstance(private_key_x, int) or private_key_x <= 0 or private_key_x >= p -1 :
        raise ElGamalDecryptionError("Invalid private key x")
    
    if not (isinstance(ciphertext, tuple) and len(ciphertext) == 2):
        raise ElGamalDecryptionError("Invalid ciphertext format")
    
    c1, c2 = ciphertext

    if not (isinstance(c1, int) and 0 <= c1 < p):
        raise ElGamalDecryptionError("Invalid ciphertext c1")
    
    if not (isinstance(c2, int) and 0 <= c2 < p):
        raise ElGamalDecryptionError("Invalid ciphertext c2")
    
    # 1. 计算共享密钥 s = c1^x mod p
    s = power(c1, private_key_x, p)

    if s == 0:
        raise ElGamalDecryptionError("shared key is zero")
    
    # 2. 计算 s 的模 p 乘法逆元 s_inv = s^-1 mod p
    try:
        s_inv = mod_inverse(s, p)
    except ValueError as e:
        raise ElGamalDecryptionError(f"modular inverse calculation failed:{e}")
    
    # 3. 计算明文 m = c2 * s_inv mod p
    message_int = (c2 * s_inv) % p

    return message_int

if __name__ == '__main__':
    print("测试 ElGamal 密钥生成、加密和解密 (简化g选择)...")
    try:
        bits = 64 # 保持一个相对较快但仍有意义的比特数
        k_mr_rounds = 10
        
        print(f"\n--- 密钥生成 (bits={bits}) ---")
        public_key, private_key_x = generate_keys(bits=bits, k_miller_rabin=k_mr_rounds)
        p_param, g_param, y_param = public_key # 解包公钥参数

        # 准备一个要加密的明文消息 (整数形式)
        # 确保 message_int < p_param
        message_original_int = random.randint(0, p_param - 1)
        if p_param <= message_original_int: # 以防万一
             message_original_int = p_param // 2 if p_param > 1 else 0
        
        print(f"\n--- 加密过程 (明文 M={message_original_int}) ---")
        ciphertext_pair = encrypt(public_key, message_original_int)
        
        print(f"\n--- 解密过程 ---")
        # 解密时需要私钥 x，以及公开参数 p (g在标准解密中不直接用，但常一起传递)
        decrypted_message_int = decrypt(private_key_x, p_param, g_param, ciphertext_pair)

        # 验证解密结果
        print("\n--- 验证结果 ---")
        if decrypted_message_int == message_original_int:
            print("成功：ElGamal解密后的明文与原始明文一致！")
        else:
            print("失败：ElGamal解密后的明文与原始明文不一致。")
            print(f"  原始明文: {message_original_int}")
            print(f"  解密得到: {decrypted_message_int}")

    except ElGamalKeyGenerationError as e:
        print(f"密钥生成错误: {e}")
    except ElGamalEncryptionError as e:
        print(f"加密错误: {e}")
    except ElGamalDecryptionError as e:
        print(f"解密错误: {e}")
    except ImportError as e:
        print(f"导入错误，请检查 math_utils 的路径: {e}")
    except Exception as e:
        print(f"发生未知错误: {e}")