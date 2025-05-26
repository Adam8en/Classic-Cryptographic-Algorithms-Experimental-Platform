# app/utils/math_utils.py
import random

def power(base, exp, mod):
    """
    计算 (base^exp) % mod 的高效模幂运算。
    使用平方-乘法算法。

    参数:
        base (int): 底数
        exp (int): 指数
        mod (int): 模数

    返回:
        int: (base^exp) % mod的结果
    """
    if mod == 0:
        raise ValueError("Modulo 0 is not allowed")
    if exp < 0:
        raise ValueError("Negative exponent is not allowed")
    
    res = 1
    base %= mod

    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2

    return res

def extended_gcd(a, b):
    """
    计算 a 和 b 的最大公约数，并找到整数 x 和 y 使得 ax + by = gcd(a, b)。
    使用扩展欧几里得算法。

    参数:
        a (int): 第一个整数
        b (int): 第二个整数

    返回:
        tuple: (gcd, x, y)
               gcd 是 a 和 b 的最大公约数
               x, y 是满足 ax + by = gcd(a, b) 的整数
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """
    计算 a 模 m 的乘法逆元 x，使得 (a*x) % m = 1。
    使用扩展欧几里得算法。

    参数:
        a (int): 要求逆元的整数
        m (int): 模数

    返回:
        int: a 模 m 的乘法逆元。
    Raises:
        ValueError: 如果逆元不存在 (即 a 和 m 不互素)。
                     或者如果 m <= 1。
    """
    if m <= 1:
        raise ValueError("Modulo must be greater than 1")

    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        inverse = (x % m + m) % m
        return inverse
    
def is_prime_miller_rabin(n, k=10): # k是测试轮数，对于实际应用可能需要更高
    """
    使用米勒-拉宾概率性算法检测 n 是否为素数。

    参数:
        n (int): 待检测的整数。
        k (int): 测试的轮数，轮数越多，结果越可靠。

    返回:
        bool: 如果 n 很可能是素数则为 True，否则为 False。
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = power(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = power(x, 2, n)
            if x == n - 1:
                break
            if x == 1:
                return False
        else:
            return False
    return True

def generate_random_n_bit_odd_number(bits):
    """
    生成一个指定比特长度的随机奇数。
    确保最高位和最低位为1，以保证比特长度和奇数特性。

    参数:
        bits (int): 希望生成的数字的比特长度 (例如 512, 1024)。

    返回:
        int: 一个具有指定比特长度的随机奇数。
    """
    if bits < 2:
        if bits == 1:
            return 1
        raise ValueError("Number of bits must be at least 2")
    
    if bits == 2:
        middle_bit_val = 0
    else:
        middle_bit_val = random.getrandbits(bits - 2)

    num = middle_bit_val << 1
    num |= 1
    num |= (1 << (bits - 1))

    return num

def generate_large_prime(bits, k_miller_rabin=20):
    """
    生成一个指定比特长度的大素数 (高概率)。

    参数:
        bits (int): 素数的期望比特长度 (例如 512, 1024)。
        k_miller_rabin (int): 米勒-拉宾测试的轮数。

    返回:
        int: 一个很可能是素数的大整数。
    """
    if bits < 2:
        raise ValueError("Number of bits must be at least 2")
    
    candidate_count = 0
    while True:
        candidate_count += 1
        candidate = generate_random_n_bit_odd_number(bits)

        if candidate % 3 == 0 and candidate > 3: continue
        if candidate % 5 == 0 and candidate > 5: continue
        if candidate % 7 == 0 and candidate > 7: continue
        # if candidate % 11 == 0 and candidate > 11: continue
        # ...

        if is_prime_miller_rabin(candidate, k_miller_rabin):
            return candidate

if __name__ == "__main__":
    print(f"1234567^891011 % 101 = {power(1234567, 891011, 101)}") # 大数测试

    a1, b1 = 48, 18
    gcd1, x1, y1 = extended_gcd(a1, b1)
    print(f"extended_gcd({a1}, {b1}) = (gcd={gcd1}, x={x1}, y={y1})")
    print(f"验证: {a1}*{x1} + {b1}*{y1} = {a1*x1 + b1*y1} (应等于 {gcd1})")

    a1, m1 = 3, 11
    try:
        inv1 = mod_inverse(a1, m1)
        print(f"mod_inverse({a1}, {m1}) = {inv1}")
        print(f"验证: ({a1} * {inv1}) % {m1} = {(a1 * inv1) % m1} (应为 1)")
    except ValueError as e:
        print(f"错误计算 mod_inverse({a1}, {m1}): {e}")

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
    small_composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24, 25]

    print("测试已知的小素数 (应该都返回 True):")
    for p in small_primes:
        print(f"is_prime_miller_rabin({p}, 5) = {is_prime_miller_rabin(p, 5)}")

    print("\n测试已知的小合数 (应该都返回 False):")
    for c in small_composites:
        print(f"is_prime_miller_rabin({c}, 5) = {is_prime_miller_rabin(c, 5)}")


    print("\n生成一个64位素数 (k=20):")
    prime_64bit = generate_large_prime(64, k_miller_rabin=20)
    print(f"  64-bit prime: {prime_64bit}")
    print(f"  Verifying with more rounds: {is_prime_miller_rabin(prime_64bit, 100)}")
    assert len(bin(prime_64bit)) - 2 == 64