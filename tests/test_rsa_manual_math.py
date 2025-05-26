# tests/test_rsa_manual_math.py

import unittest
import random

from app.utils.math_utils import (
    power,
    extended_gcd, 
    mod_inverse,
    is_prime_miller_rabin,
    generate_random_n_bit_odd_number,
    generate_large_prime
)

class TestMathUtils(unittest.TestCase):

    def test_power(self):
        # 确保 power 函数中的 mod == 0 检查已移到最前
        with self.assertRaises(ValueError, msg="模数为零应抛出ValueError"):
            power(5, 2, 0)
        self.assertEqual(power(7, 0, 13), 1)
        self.assertEqual(power(7, 1, 13), 7)
        self.assertEqual(power(7, 2, 13), 10)
        self.assertEqual(power(5, 117, 19), 1)
        self.assertEqual(power(1234567, 891011, 101), 57)
        with self.assertRaises(ValueError, msg="负指数应抛出ValueError"):
            power(5, -2, 10)

    def test_extended_gcd(self):
        # ax + by = gcd(a,b)
        # 注意：x 和 y 的具体值可能因算法实现细节而异，但 ax + by = gcd 必须成立
        
        # 测试用例 1: gcd(48, 18) = 6
        a1, b1 = 48, 18
        gcd1, x1, y1 = extended_gcd(a1, b1)
        self.assertEqual(gcd1, 6, f"gcd({a1},{b1}) 应该是 6, 得到 {gcd1}")
        self.assertEqual(a1 * x1 + b1 * y1, gcd1, f"{a1}*({x1}) + {b1}*({y1}) 不等于 {gcd1}")

        # 测试用例 2: gcd(35, 15) = 5
        a2, b2 = 35, 15
        gcd2, x2, y2 = extended_gcd(a2, b2)
        self.assertEqual(gcd2, 5, f"gcd({a2},{b2}) 应该是 5, 得到 {gcd2}")
        self.assertEqual(a2 * x2 + b2 * y2, gcd2, f"{a2}*({x2}) + {b2}*({y2}) 不等于 {gcd2}")
        
        # 测试用例 3: a=0, gcd(0, 28) = 28
        a3_a, b3_a = 0, 28
        gcd3_a, x3_a, y3_a = extended_gcd(a3_a, b3_a)
        self.assertEqual(gcd3_a, 28, f"gcd({a3_a},{b3_a}) 应该是 28, 得到 {gcd3_a}")
        self.assertEqual(a3_a * x3_a + b3_a * y3_a, gcd3_a, f"{a3_a}*({x3_a}) + {b3_a}*({y3_a}) 不等于 {gcd3_a}")

        # 测试用例 4: b=0, gcd(28, 0) = 28
        a3_b, b3_b = 28, 0
        gcd3_b, x3_b, y3_b = extended_gcd(a3_b, b3_b)
        self.assertEqual(gcd3_b, 28, f"gcd({a3_b},{b3_b}) 应该是 28, 得到 {gcd3_b}")
        self.assertEqual(a3_b * x3_b + b3_b * y3_b, gcd3_b, f"{a3_b}*({x3_b}) + {b3_b}*({y3_b}) 不等于 {gcd3_b}")

        # 测试用例 5: gcd(65537, 10200) = 3 (这是之前出问题的点)
        e_rsa_prob, phi_n_rsa_prob = 65537, 10200
        gcd_prob, x_prob, y_prob = extended_gcd(e_rsa_prob, phi_n_rsa_prob)
        self.assertEqual(gcd_prob, 1, f"gcd({e_rsa_prob},{phi_n_rsa_prob}) 应该是 1, 得到 {gcd_prob}")
        self.assertEqual(e_rsa_prob * x_prob + phi_n_rsa_prob * y_prob, gcd_prob,
                         f"{e_rsa_prob}*({x_prob}) + {phi_n_rsa_prob}*({y_prob}) 不等于 {gcd_prob}")
        
        # 测试用例 6: 互素的大数 gcd(65537, 10201) = 1 (10201 不是3的倍数)
        # (10201 % 3 = 1), (65537 % 3 = 2)
        # 实际上 10201 = 101 * 101, 65537 是素数. 所以它们应该是互素的.
        e_rsa_good, phi_n_rsa_good = 65537, 10201
        gcd_good, x_good, y_good = extended_gcd(e_rsa_good, phi_n_rsa_good)
        self.assertEqual(gcd_good, 1, f"gcd({e_rsa_good},{phi_n_rsa_good}) 应该是 1, 得到 {gcd_good}")
        self.assertEqual(e_rsa_good * x_good + phi_n_rsa_good * y_good, gcd_good,
                         f"{e_rsa_good}*({x_good}) + {phi_n_rsa_good}*({y_good}) 不等于 {gcd_good}")


    def test_mod_inverse(self):
        self.assertEqual(mod_inverse(3, 11), 4) # (3*4) % 11 = 1
        self.assertEqual(mod_inverse(10, 17), 12) # (10*12) % 17 = 1
        self.assertEqual(mod_inverse(7, 20), 3) # (7*3) % 20 = 1
        
        # 使用上面测试过的互素大数对
        e_rsa_good, phi_n_rsa_good = 65537, 10201
        # 我们需要知道 extended_gcd(65537, 10201) 返回的 x 是多少来确定期望值
        # 或者直接验证 (a * inv) % m == 1
        inv_good = mod_inverse(e_rsa_good, phi_n_rsa_good)
        self.assertEqual((e_rsa_good * inv_good) % phi_n_rsa_good, 1,
                         f"({e_rsa_good} * {inv_good}) % {phi_n_rsa_good} 不等于 1")

        with self.assertRaises(ValueError, msg="逆元不存在应抛出ValueError (gcd(4,10)=2)"):
            mod_inverse(4, 10)
        with self.assertRaises(ValueError, msg="模数 m <= 1 应抛出ValueError"):
            mod_inverse(5, 1)

    def test_is_prime_miller_rabin(self):
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        small_composites = [4, 6, 8, 9, 10, 12, 14, 15, 100, 561] # 561 is a Carmichael number
        
        for p in small_primes:
            self.assertTrue(is_prime_miller_rabin(p, k=10), f"{p} 应该被判断为素数")
        for c in small_composites:
            self.assertFalse(is_prime_miller_rabin(c, k=10), f"{c} 应该被判断为合数")
        
        self.assertFalse(is_prime_miller_rabin(1, k=5))
        # is_prime_miller_rabin(-7, k=5) 应该返回 False (因为 n<2)

    def test_generate_random_n_bit_odd_number(self):
        for bits_val in [1, 2, 3, 8, 16]: # 加入 bits=1 的测试
            num = generate_random_n_bit_odd_number(bits_val)
            if bits_val == 1:
                self.assertEqual(num, 1, "1-bit random odd number 应该是 1")
            else:
                self.assertEqual(len(bin(num)) - 2, bits_val, f"{bits_val}-bit 数 {num} (binary {bin(num)}) 的长度不正确")
                self.assertEqual(num % 2, 1, f"{num} (binary {bin(num)}) 不为奇数")
                self.assertTrue(num & (1 << (bits_val - 1)), f"{num} (binary {bin(num)}) 的最高位不为1")

    def test_generate_large_prime(self):
        for bits_val in [8, 10]: 
            prime_candidate = generate_large_prime(bits_val, k_miller_rabin=10)
            self.assertEqual(len(bin(prime_candidate)) - 2, bits_val, f"{bits_val}-bit 素数 {prime_candidate} 的长度不正确")
            self.assertTrue(is_prime_miller_rabin(prime_candidate, k=40), 
                            f"{prime_candidate} (生成为{bits_val}-bit素数) 未通过更严格的素性测试")

if __name__ == '__main__':
    unittest.main()