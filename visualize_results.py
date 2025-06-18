# visualize_results.py (更新版)

import json
import matplotlib.pyplot as plt
import numpy as np
import sys # 用于在文件未找到时退出脚本

STANDARD_SHORT_BLOCK_SIZE_BYTES = 32

# --- 1. 从 performance_results.json 文件加载实验结果数据 ---
RESULTS_FILENAME = "performance_results.json"
try:
    # 使用 with open(...) 来安全地打开文件
    with open(RESULTS_FILENAME, 'r', encoding='utf-8') as f:
        results_data = json.load(f)
    print(f"成功从 '{RESULTS_FILENAME}' 文件加载数据。")
except FileNotFoundError:
    print(f"错误: 找不到结果文件 '{RESULTS_FILENAME}'。")
    print("请先运行 performance_tester.py 脚本来生成结果文件。")
    sys.exit(1) # 退出脚本，因为没有数据无法继续
except json.JSONDecodeError:
    print(f"错误: 文件 '{RESULTS_FILENAME}' 的格式不是有效的JSON。请检查文件内容。")
    sys.exit(1)


# 2. 设置 Matplotlib 支持中文显示
# 这是一个通用的方法，尝试找到系统中可用的中文字体
def set_chinese_font():
    try:
        # 优先使用黑体
        plt.rcParams['font.sans-serif'] = ['SimHei']
        plt.rcParams['axes.unicode_minus'] = False # 解决负号显示为方块的问题
    except Exception:
        try:
            # 如果没有黑体，尝试微软雅黑
            plt.rcParams['font.sans-serif'] = ['Microsoft YaHei']
            plt.rcParams['axes.unicode_minus'] = False
        except Exception:
            try:
                # Mac系统上的常见中文字体
                plt.rcParams['font.sans-serif'] = ['PingFang SC']
                plt.rcParams['axes.unicode_minus'] = False
            except Exception:
                # 如果都没有，可能需要用户自己安装字体
                print("警告：未找到可用的中文字体。图表中的中文可能显示为方块。")

# 3. 绘图函数

def plot_key_generation_time(data):
    """绘制密钥生成时间对比图"""
    labels = []
    times = []
    colors = []

    # 提取数据
    for algo, configs in data.items():
        for config_name, values in configs.items():
            labels.append(config_name.replace("ECC-secp", "ECC-p")) # 简化ECC标签
            times.append(values["key_gen_ms"])
            if algo == "RSA": colors.append('skyblue')
            elif algo == "ElGamal": colors.append('salmon')
            else: colors.append('lightgreen')
    
    plt.figure(figsize=(14, 8))
    bars = plt.bar(labels, times, color=colors)
    
    plt.ylabel('平均时间 (毫秒, ms)')
    plt.title('不同算法和密钥长度的密钥生成时间对比')
    plt.xticks(rotation=45, ha="right")
    plt.yscale('log') # 使用对数刻度，因为ElGamal-2048的值太大了
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # 在条形图上添加数值标签
    plt.bar_label(bars, fmt='%.2f', padding=3, fontsize=9)
    
    plt.tight_layout() # 调整布局防止标签重叠
    plt.savefig('key_generation_comparison.png', dpi=300) # 保存图表
    plt.show()

def plot_core_operations_time(data):
    """绘制核心加解密操作时间对比图 (分组条形图)"""
    labels = []
    enc_times = []
    dec_times = []
    
    # 提取数据
    for algo, configs in data.items():
        for config_name, values in configs.items():
            labels.append(config_name.replace("ECC-secp", "ECC-p"))
            enc_times.append(values["core_encryption_ms"])
            dec_times.append(values.get("core_decryption_ms", 0)) # ElGamal-2048可能没有这个键
    
    x = np.arange(len(labels))  # 标签位置
    width = 0.35  # 条形宽度

    fig, ax = plt.subplots(figsize=(16, 8))
    rects1 = ax.bar(x - width/2, enc_times, width, label='加密 (Encryption)', color='cornflowerblue')
    rects2 = ax.bar(x + width/2, dec_times, width, label='解密 (Decryption)', color='sandybrown')

    ax.set_ylabel('平均时间 (毫秒, ms)')
    ax.set_title(f'核心操作加解密时间对比 (对{STANDARD_SHORT_BLOCK_SIZE_BYTES}字节数据块)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    ax.bar_label(rects1, padding=3, fmt='%.2f', fontsize=8)
    ax.bar_label(rects2, padding=3, fmt='%.2f', fontsize=8)

    fig.tight_layout()
    plt.savefig('core_operations_comparison.png', dpi=300)
    plt.show()

def plot_ecc_scalability(data):
    """绘制ECC数据扩展性图表 (加密和解密)"""
    plt.figure(figsize=(12, 7))
    
    curves = data["ECC"].keys()
    # 提取数据大小 (x轴)
    # 我们假设所有曲线的扩展性测试使用了相同的数据大小
    first_curve_data = next(iter(data["ECC"].values()))
    data_sizes = [int(s) for s in first_curve_data["scalability_encryption_ms"].keys()]
    data_sizes.sort()

    for curve_name in curves:
        enc_scalability_times = [data["ECC"][curve_name]["scalability_encryption_ms"][str(s)] for s in data_sizes]
        dec_scalability_times = [data["ECC"][curve_name]["scalability_decryption_ms"][str(s)] for s in data_sizes]
        
        # 绘制加密性能曲线
        plt.plot(data_sizes, enc_scalability_times, marker='o', linestyle='-', label=f'{curve_name} 加密')
        # 绘制解密性能曲线
        plt.plot(data_sizes, dec_scalability_times, marker='x', linestyle='--', label=f'{curve_name} 解密')

    plt.xlabel('数据大小 (字节)')
    plt.ylabel('平均时间 (毫秒, ms)')
    plt.title('ECC (简化ECIES) 加解密时间随数据大小的变化')
    plt.xscale('log') # x轴使用对数刻度，因为数据点间距大
    plt.legend()
    plt.grid(True, which="both", ls="--")
    
    plt.tight_layout()
    plt.savefig('ecc_scalability.png', dpi=300)
    plt.show()

def plot_equivalent_security_comparison(data):
    """
    绘制在等效安全级别下的性能对比图。
    专门对比 RSA-2048, ElGamal-2048, 和 ECC-secp256r1。
    """
    print("正在生成等效安全级别下的性能对比图...")

    # 1. 定义我们要对比的配置名称
    configs_to_compare = {
        "RSA-2048": "RSA-2048 (~112-bit security)",
        "ElGamal-2048": "ElGamal-2048 (~112-bit security)",
        "ECC-secp256r1": "ECC-secp256r1 (~128-bit security)"
    }
    
    labels = list(configs_to_compare.values())
    
    # 2. 从完整数据中提取这三个配置的性能数据
    key_gen_times = [data["RSA"]["RSA-2048"]["key_gen_ms"],
                     data["ElGamal"]["ElGamal-2048"]["key_gen_ms"],
                     data["ECC"]["ECC-secp256r1"]["key_gen_ms"]]
                     
    encryption_times = [data["RSA"]["RSA-2048"]["core_encryption_ms"],
                        data["ElGamal"]["ElGamal-2048"]["core_encryption_ms"],
                        data["ECC"]["ECC-secp256r1"]["core_encryption_ms"]]

    decryption_times = [data["RSA"]["RSA-2048"]["core_decryption_ms"],
                        data["ElGamal"]["ElGamal-2048"]["core_decryption_ms"],
                        data["ECC"]["ECC-secp256r1"]["core_decryption_ms"]]

    # 3. 绘制分组条形图
    x = np.arange(len(labels))  # 标签位置
    width = 0.25  # 条形宽度

    fig, ax = plt.subplots(figsize=(12, 8))
    
    rects1 = ax.bar(x - width, key_gen_times, width, label='密钥生成', color='teal')
    rects2 = ax.bar(x, encryption_times, width, label='核心加密', color='orange')
    rects3 = ax.bar(x + width, decryption_times, width, label='核心解密', color='indianred')

    ax.set_ylabel('平均时间 (毫秒, ms) - 对数刻度')
    ax.set_title('等效安全级别下的性能对比')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(title='操作类型')
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Y轴使用对数刻度，因为密钥生成时间与其他两项差异巨大
    ax.set_yscale('log')

    # 为条形图添加数值标签
    ax.bar_label(rects1, padding=3, fmt='%.1f')
    ax.bar_label(rects2, padding=3, fmt='%.2f')
    ax.bar_label(rects3, padding=3, fmt='%.1f')

    fig.tight_layout()
    plt.savefig('equivalent_security_comparison.png', dpi=300)
    plt.show()

def plot_equivalent_security_subplots(data):
    """
    绘制在等效安全级别下的性能对比复合图。
    使用两个子图，分别以线性刻度展示密钥生成时间和加解密时间。
    """
    print("正在生成等效安全级别下的性能对比复合图...")

    # 1. 定义并提取要对比的数据点
    configs_to_compare = {
        "RSA-2048": "RSA-2048\n(~112-bit security)",
        "ElGamal-2048": "ElGamal-2048\n(~112-bit security)",
        "ECC-secp256r1": "ECC-secp256r1\n(~128-bit security)"
    }
    labels = list(configs_to_compare.values())
    
    key_gen_times = [data["RSA"]["RSA-2048"]["key_gen_ms"],
                     data["ElGamal"]["ElGamal-2048"]["key_gen_ms"],
                     data["ECC"]["ECC-secp256r1"]["key_gen_ms"]]
                     
    encryption_times = [data["RSA"]["RSA-2048"]["core_encryption_ms"],
                        data["ElGamal"]["ElGamal-2048"]["core_encryption_ms"],
                        data["ECC"]["ECC-secp256r1"]["core_encryption_ms"]]

    decryption_times = [data["RSA"]["RSA-2048"]["core_decryption_ms"],
                        data["ElGamal"]["ElGamal-2048"]["core_decryption_ms"],
                        data["ECC"]["ECC-secp256r1"]["core_decryption_ms"]]

    # 2. 创建一个包含两个子图的Figure
    #    2, 1 表示2行1列。 sharex=True 表示两个子图共享X轴标签。
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 10), sharex=True)
    fig.suptitle('等效安全级别下的性能对比', fontsize=16)

    # --- 子图1: 密钥生成时间 (线性刻度) ---
    colors1 = ['skyblue', 'salmon', 'lightgreen']
    bars1 = ax1.bar(labels, key_gen_times, color=colors1)
    ax1.set_ylabel('平均时间 (毫秒, ms)')
    ax1.set_title('密钥生成时间')
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    ax1.bar_label(bars1, fmt='%.1f', padding=3)

    # --- 子图2: 核心加解密时间 (线性刻度) ---
    x = np.arange(len(labels))
    width = 0.35
    rects2 = ax2.bar(x - width/2, encryption_times, width, label='核心加密', color='cornflowerblue')
    rects3 = ax2.bar(x + width/2, decryption_times, width, label='核心解密', color='sandybrown')

    ax2.set_ylabel('平均时间 (毫秒, ms)')
    ax2.set_title(f'核心加解密时间 (对{STANDARD_SHORT_BLOCK_SIZE_BYTES}字节数据块)')
    ax2.legend()
    ax2.grid(axis='y', linestyle='--', alpha=0.7)
    ax2.set_xticks(x) # 确保刻度位置正确
    ax2.set_xticklabels(labels) # 确保标签正确显示

    ax2.bar_label(rects2, padding=3, fmt='%.2f')
    ax2.bar_label(rects3, padding=3, fmt='%.1f')
    
    plt.xticks(rotation=10, ha="center") # 稍微旋转X轴标签以防重叠
    fig.tight_layout(rect=[0, 0.03, 1, 0.95]) # 调整布局并为总标题留出空间
    
    plt.savefig('equivalent_security_subplots_comparison.png', dpi=300)
    plt.show()

# 4. 主执行函数
if __name__ == '__main__':
    # 首先设置中文字体
    set_chinese_font()
    
    # 可以调用之前的绘图函数
    # plot_key_generation_time(results_data)
    # plot_core_operations_time(results_data)
    # plot_ecc_scalability(results_data)
    
    # --- 新增调用 ---
    # plot_equivalent_security_comparison(results_data)
    plot_equivalent_security_subplots(results_data)
    # -----------------
    
    print("所有图表已生成并显示，同时已保存为PNG文件。")