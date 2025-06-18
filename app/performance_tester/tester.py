# app/performance_tester/tester.py

import time
import os
import json

# 确保导入路径正确，假设你的项目结构已经调整好
try:
    from app.core_algorithms.rsa_manual.rsa_core import (
        generate_keys as rsa_generate_keys,
        encrypt_with_padding as rsa_encrypt,
        decrypt_with_padding as rsa_decrypt
    )
    from app.core_algorithms.elgamal_manual.elgamal_core import (
        generate_keys as elgamal_generate_keys,
        encrypt as elgamal_encrypt,
        decrypt as elgamal_decrypt
    )
    from app.core_algorithms.ecc_manual.ecc_core import (
        generate_ecc_keys,
        encrypt_message_ecc,
        decrypt_message_ecc,
        get_curve_by_name # 我们需要这个函数来获取曲线对象
    )
except ImportError as e:
    # 如果直接运行此文件遇到导入问题，请从项目根目录使用 `python -m app.performance_tester.tester`
    print(f"导入错误: {e}")
    print("请确保从项目根目录运行，例如: python -m app.performance_tester.tester")
    exit()

# --- 测试参数定义 ---
# 密钥生成测试的参数
RSA_KEY_SIZES = [512, 1024, 2048]
ELGAMAL_KEY_SIZES = [512, 1024, 2048]
ECC_CURVES = ["secp192r1", "secp256r1", "secp256k1", "secp384r1"]

# 核心操作加解密测试的参数
STANDARD_SHORT_BLOCK_SIZE_BYTES = 32 # 模拟一个256位的对称密钥

# 数据扩展性测试的参数 (主要用于ECC)
DATA_SCALABILITY_SIZES_BYTES = [1024, 16384, 65536] # 1KB, 16KB, 64KB

# 每个测试的重复次数，用于取平均值
NUM_ITERATIONS = 10 

def _generate_test_data(size_in_bytes):
    """生成指定大小的随机字节数据"""
    return os.urandom(size_in_bytes)

def run_rsa_tests():
    results = {}
    print("\n--- 正在运行 RSA 性能测试 ---")
    for bits in RSA_KEY_SIZES:
        key_config_name = f"RSA-{bits}"
        print(f"\n测试配置: {key_config_name}")
        results[key_config_name] = {}

        # 1. 密钥生成测试
        key_gen_times = []
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            pub_key, priv_key = rsa_generate_keys(bits=bits)
            end_time = time.perf_counter()
            key_gen_times.append((end_time - start_time) * 1000)
        avg_key_gen_time = sum(key_gen_times) / len(key_gen_times)
        results[key_config_name]["key_gen_ms"] = avg_key_gen_time
        print(f"  平均密钥生成时间: {avg_key_gen_time:.3f} ms")
        
        # 2. 核心操作加解密时间测试 (使用SSDB)
        ssdb_message = _generate_test_data(STANDARD_SHORT_BLOCK_SIZE_BYTES)
        
        # 加密
        encrypt_times = []
        ciphertext = rsa_encrypt(pub_key, ssdb_message) # 先加密一次得到密文
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            rsa_encrypt(pub_key, ssdb_message)
            end_time = time.perf_counter()
            encrypt_times.append((end_time - start_time) * 1000)
        avg_encrypt_time = sum(encrypt_times) / len(encrypt_times)
        results[key_config_name]["core_encryption_ms"] = avg_encrypt_time
        print(f"  核心加密时间 (对{STANDARD_SHORT_BLOCK_SIZE_BYTES}字节): {avg_encrypt_time:.3f} ms")

        # 解密
        decrypt_times = []
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            rsa_decrypt(priv_key, ciphertext)
            end_time = time.perf_counter()
            decrypt_times.append((end_time - start_time) * 1000)
        avg_decrypt_time = sum(decrypt_times) / len(decrypt_times)
        results[key_config_name]["core_decryption_ms"] = avg_decrypt_time
        print(f"  核心解密时间 (对{STANDARD_SHORT_BLOCK_SIZE_BYTES}字节): {avg_decrypt_time:.3f} ms")

    return results

def run_elgamal_tests():
    results = {}
    print("\n--- 正在运行 ElGamal 性能测试 ---")
    for bits in ELGAMAL_KEY_SIZES:
        key_config_name = f"ElGamal-{bits}"
        print(f"\n测试配置: {key_config_name}")
        results[key_config_name] = {}

        # 1. 密钥生成测试
        key_gen_times = []
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            pub_key, priv_key_x = elgamal_generate_keys(bits=bits)
            end_time = time.perf_counter()
            key_gen_times.append((end_time - start_time) * 1000)
        avg_key_gen_time = sum(key_gen_times) / len(key_gen_times)
        results[key_config_name]["key_gen_ms"] = avg_key_gen_time
        print(f"  平均密钥生成时间: {avg_key_gen_time:.3f} ms")

        p_param, g_param, _ = pub_key

        # 2. 核心操作加解密时间测试 (使用SSDB)
        ssdb_message_bytes = _generate_test_data(STANDARD_SHORT_BLOCK_SIZE_BYTES)
        ssdb_message_int = int.from_bytes(ssdb_message_bytes, 'big')

        # 加密
        encrypt_times = []
        ciphertext = elgamal_encrypt(pub_key, ssdb_message_int)
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            elgamal_encrypt(pub_key, ssdb_message_int)
            end_time = time.perf_counter()
            encrypt_times.append((end_time - start_time) * 1000)
        avg_encrypt_time = sum(encrypt_times) / len(encrypt_times)
        results[key_config_name]["core_encryption_ms"] = avg_encrypt_time
        print(f"  核心加密时间 (对{STANDARD_SHORT_BLOCK_SIZE_BYTES}字节): {avg_encrypt_time:.3f} ms")

        # 解密
        decrypt_times = []
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            elgamal_decrypt(priv_key_x, p_param, g_param, ciphertext)
            end_time = time.perf_counter()
            decrypt_times.append((end_time - start_time) * 1000)
        avg_decrypt_time = sum(decrypt_times) / len(decrypt_times)
        results[key_config_name]["core_decryption_ms"] = avg_decrypt_time
        print(f"  核心解密时间 (对{STANDARD_SHORT_BLOCK_SIZE_BYTES}字节): {avg_decrypt_time:.3f} ms")
        
    return results


def run_ecc_tests():
    results = {}
    print("\n--- 正在运行 ECC (简化ECIES) 性能测试 ---")
    for curve_name in ECC_CURVES:
        key_config_name = f"ECC-{curve_name}"
        print(f"\n测试配置: {key_config_name}")
        results[key_config_name] = {}
        
        # 1. 密钥生成测试
        key_gen_times = []
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            priv_key, pub_key = generate_ecc_keys(curve_name=curve_name)
            end_time = time.perf_counter()
            key_gen_times.append((end_time - start_time) * 1000)
        avg_key_gen_time = sum(key_gen_times) / len(key_gen_times)
        results[key_config_name]["key_gen_ms"] = avg_key_gen_time
        print(f"  平均密钥生成时间: {avg_key_gen_time:.3f} ms")

        # 2. 核心操作加解密时间测试 (使用SSDB)
        ssdb_message = _generate_test_data(STANDARD_SHORT_BLOCK_SIZE_BYTES)
        # 加密
        encrypt_times = []
        ephemeral_R, ciphertext = encrypt_message_ecc(pub_key, ssdb_message)
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            encrypt_message_ecc(pub_key, ssdb_message)
            end_time = time.perf_counter()
            encrypt_times.append((end_time - start_time) * 1000)
        avg_encrypt_time = sum(encrypt_times) / len(encrypt_times)
        results[key_config_name]["core_encryption_ms"] = avg_encrypt_time
        print(f"  核心加密时间 (对{STANDARD_SHORT_BLOCK_SIZE_BYTES}字节): {avg_encrypt_time:.3f} ms")
        # 解密
        decrypt_times = []
        for _ in range(NUM_ITERATIONS):
            start_time = time.perf_counter()
            decrypt_message_ecc(priv_key, ephemeral_R, ciphertext)
            end_time = time.perf_counter()
            decrypt_times.append((end_time - start_time) * 1000)
        avg_decrypt_time = sum(decrypt_times) / len(decrypt_times)
        results[key_config_name]["core_decryption_ms"] = avg_decrypt_time
        print(f"  核心解密时间 (对{STANDARD_SHORT_BLOCK_SIZE_BYTES}字节): {avg_decrypt_time:.3f} ms")

        # 3. 数据扩展性测试
        results[key_config_name]["scalability_encryption_ms"] = {}
        results[key_config_name]["scalability_decryption_ms"] = {}
        print("  数据扩展性测试 (加密不同大小的数据):")
        for data_size in DATA_SCALABILITY_SIZES_BYTES:
            message = _generate_test_data(data_size)
            encrypt_times = []
            ephemeral_R, ciphertext = encrypt_message_ecc(pub_key, message)
            for _ in range(NUM_ITERATIONS):
                start_time = time.perf_counter()
                encrypt_message_ecc(pub_key, message)
                end_time = time.perf_counter()
                encrypt_times.append((end_time - start_time) * 1000)
            avg_encrypt_time_long = sum(encrypt_times) / len(encrypt_times)
            results[key_config_name]["scalability_encryption_ms"][data_size] = avg_encrypt_time_long
            print(f"    - 加密 {data_size}字节 平均时间: {avg_encrypt_time_long:.3f} ms")

            # 解密扩展性测试
            decrypt_times = []
            for _ in range(NUM_ITERATIONS):
                start_time = time.perf_counter()
                decrypt_message_ecc(priv_key, ephemeral_R, ciphertext)
                end_time = time.perf_counter()
                decrypt_times.append((end_time - start_time) * 1000)
            avg_decrypt_time_long = sum(decrypt_times) / len(decrypt_times)
            results[key_config_name]["scalability_decryption_ms"][data_size] = avg_decrypt_time_long
            print(f"    - 解密 {data_size}字节 平均时间: {avg_decrypt_time_long:.3f} ms")

    return results

def run_all_performance_tests():
    """运行所有性能测试并返回结构化结果。"""
    all_results = {
        "RSA": run_rsa_tests(),
        "ElGamal": run_elgamal_tests(),
        "ECC": run_ecc_tests()
    }
    print("\n\n--- 所有性能测试结果汇总 ---")
    # 使用json.dumps美化打印输出
    print(json.dumps(all_results, indent=4))
    
    # 你也可以将结果保存到文件
    with open("performance_results.json", "w") as f:
        json.dump(all_results, f, indent=4)
    print("\n测试结果已保存到 performance_results.json")
    
    return all_results

if __name__ == '__main__':
    # 确保在运行此脚本前，你的工作目录是项目根目录，
    # 或者你需要调整sys.path来让Python找到app包。
    run_all_performance_tests()