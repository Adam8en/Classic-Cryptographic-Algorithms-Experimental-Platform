# 经典密码算法实验平台

## 项目简介

本项目旨在手动实现并演示经典的公钥密码算法，包括RSA、ElGamal以及ECC（基于简化ECIES的加解密）。平台基于Flask后端和Layui前端构建，提供了一个用户友好的交互界面，用于密钥生成、文本加解密操作，并为后续的性能对比分析打下基础。

本项目为课程设计“经典密码算法的实现与性能对比”的核心实现部分，侧重于理解算法原理和手动复现核心逻辑。

## 功能特性

* **RSA算法模块 (手动实现，带PKCS#1 v1.5填充)**
    * 密钥生成 (指定位数，指定公钥指数e)
    * 文本加密 (使用公钥)
    * 文本解密 (使用私钥)
* **ElGamal算法模块 (手动实现)**
    * 密钥生成 (指定素数p的位数，内部选择小整数g)
    * 文本加密 (使用公钥)
    * 文本解密 (使用私钥和公开参数p,g)
* **ECC算法模块 (手动实现核心点运算，基于简化ECIES的加解密)**
    * 密钥生成 (基于secp256k1曲线)
    * 文本加密 (使用接收方公钥和临时密钥对生成共享密钥，SHA256派生对称密钥，XOR加密)
    * 文本解密 (使用接收方私钥和临时公钥生成共享密钥，SHA256派生对称密钥，XOR解密)
* **Web交互界面**
    * 基于Layui构建，为每种算法提供独立的操作页面。
    * 支持用户输入参数（如密钥位数、明文、密文等）。
    * 动态显示操作结果（生成的密钥、密文、解密后的明文）。

## 技术栈

* **后端**: Python, Flask
* **前端**: HTML, CSS, JavaScript, Layui, jQuery (通过Layui间接使用)
* **核心算法实现**: Python (手动实现，不依赖高级密码学库进行核心运算)
    * RSA: 手动实现大数模幂、模逆元、素性检验、密钥生成、PKCS#1 v1.5填充、加解密。
    * ElGamal: 手动实现模幂、模逆元、素性检验、密钥生成、加解密。
    * ECC: 手动实现椭圆曲线点加、倍点、点乘运算，密钥生成，以及基于此的简化ECIES加解密。
* **辅助数学库**: 无 (或仅用于大数运算的底层支持，如Python内置的int类型)

## 项目结构

/密码学课程设计项目/
├── app/
│   ├── __init__.py            # Flask应用工厂
│   ├── api/                   # API蓝图目录
│   │   ├── __init__.py
│   │   ├── rsa_routes.py      # RSA相关的API路由
│   │   ├── elgamal_routes.py  # ElGamal相关的API路由
│   │   └── ecc_routes.py      # ECC相关的API路由
│   ├── core_algorithms/       # 核心算法实现
│   │   ├── rsa_manual/
│   │   │   ├── __init__.py
│   │   │   └── rsa_core.py
│   │   ├── elgamal_manual/
│   │   │   ├── __init__.py
│   │   │   └── elgamal_core.py
│   │   └── ecc_manual/
│   │       ├── __init__.py
│   │       └── ecc_core.py
│   ├── static/                # 静态文件 (CSS, JS, Layui库, HTML页面)
│   │   ├── page/
│   │   │   ├── RSA.html
│   │   │   ├── ElGamal.html
│   │   │   └── ECC.html
│   │   ├── lib/               # layui, jquery等
│   │   └── js/                # rsa_logic.js, elgamal_logic.js, ecc_logic.js
│   ├── templates/             # (如果未来有需要后端渲染的HTML模板)
│   └── utils/                 # 通用工具模块
│       ├── __init__.py
│       └── math_utils.py      # 通用数学工具函数
│
├── tests/                   # 单元测试目录
│   ├── __init__.py
│   ├── test_math_utils.py
│   ├── test_rsa_core.py
│   └── ... (其他算法的测试文件)
│
├── venv/                    # Python虚拟环境
├── run.py                   # 启动Flask应用的脚本
└── requirements.txt         # 项目依赖

## 安装与运行

1.  **克隆或下载项目**
    ```bash
    # git clone [你的项目仓库地址] # 如果你用了git
    # cd [项目根目录]
    ```

2.  **创建并激活Python虚拟环境** (推荐)
    ```bash
    python -m venv venv
    # Windows CMD
    # venv\Scripts\activate.bat
    # Windows PowerShell
    # venv\Scripts\Activate.ps1
    # (如果PowerShell提示执行策略问题, 可能需要运行 Set-ExecutionPolicy Unrestricted -Scope Process)
    # macOS/Linux
    # source venv/bin/activate
    ```

3.  **安装依赖**
    ```bash
    pip install -r requirements.txt
    ```
    (请确保 `requirements.txt` 文件包含了所有必要的包，例如 `Flask`)

4.  **运行应用**
    ```bash
    python run.py
    ```
    应用默认会在 `http://127.0.0.1:5000/` (或 `http://0.0.0.0:5000/`) 启动。

5.  **访问实验页面**
    * **RSA实验页面**: `http://127.0.0.1:5000/static/page/RSA.html`
    * **ElGamal实验页面**: `http://127.0.0.1:5000/static/page/ElGamal.html`
    * **ECC实验页面**: `http://127.0.0.1:5000/static/page/ECC.html`
    (你也可以在主页 `/` 上提供这些页面的链接)

## API 端点说明

所有API端点都以 `/api` 为前缀。

* **RSA API (`/api/rsa`)**
    * `POST /api/rsa/generate_keys`: 生成RSA密钥对。
        * 请求体 (JSON): `{"bits": (int), "e_value": (int)}`
        * 响应体 (JSON): 成功或失败信息，以及公私钥。
    * `POST /api/rsa/encrypt`: RSA加密。
        * 请求体 (JSON): `{"plaintext": (str), "public_key_n": (str), "public_key_e": (str)}`
        * 响应体 (JSON): 成功或失败信息，以及十六进制密文。
    * `POST /api/rsa/decrypt`: RSA解密。
        * 请求体 (JSON): `{"ciphertext_hex": (str), "private_key_n": (str), "private_key_d": (str)}`
        * 响应体 (JSON): 成功或失败信息，以及解密后的明文。

* **ElGamal API (`/api/elgamal`)**
    * `POST /api/elgamal/generate_keys`: 生成ElGamal密钥对。
        * 请求体 (JSON): `{"bits": (int)}`
        * 响应体 (JSON): 成功或失败信息，以及公钥(p,g,y)和私钥(x)。
    * `POST /api/elgamal/encrypt`: ElGamal加密。
        * 请求体 (JSON): `{"plaintext": (str), "public_key_p": (str), "public_key_g": (str), "public_key_y": (str)}`
        * 响应体 (JSON): 成功或失败信息，以及密文对(c1,c2)。
    * `POST /api/elgamal/decrypt`: ElGamal解密。
        * 请求体 (JSON): `{"ciphertext_c1": (str), "ciphertext_c2": (str), "public_key_p_dec": (str), "public_key_g_dec": (str), "private_key_x_dec": (str)}`
        * 响应体 (JSON): 成功或失败信息，以及解密后的明文。

* **ECC API (`/api/ecc`)**
    * `POST /api/ecc/generate_keys`: 生成ECC密钥对 (secp256k1)。
        * 请求体 (JSON): `{}` (或 `{"curve_name": "secp256k1"}`)
        * 响应体 (JSON): 成功或失败信息，以及私钥d和公钥点Q(Qx, Qy)。
    * `POST /api/ecc/encrypt`: ECC加密 (简化ECIES)。
        * 请求体 (JSON): `{"plaintext": (str), "public_key_qx": (str), "public_key_qy": (str)}`
        * 响应体 (JSON): 成功或失败信息，以及临时公钥R(Rx, Ry)和十六进制密文。
    * `POST /api/ecc/decrypt`: ECC解密 (简化ECIES)。
        * 请求体 (JSON): `{"ephemeral_R_x": (str), "ephemeral_R_y": (str), "ciphertext_hex": (str), "private_key_d": (str)}`
        * 响应体 (JSON): 成功或失败信息，以及解密后的明文。

## 注意事项

* 本项目中的手动算法实现主要用于教学和演示目的，可能未进行完整的安全性审计和优化。
* **密钥管理**: 项目中为了演示方便，密钥的传递和存储可能采取了简化方式 (例如，密钥生成后直接显示在前端或填充到其他表单)。在实际安全应用中，密钥管理需要极其谨慎和专业的处理。
* **性能**: 手动实现的算法（尤其是ECC的点运算）在性能上会远低于经过高度优化的专业密码学库。性能对比分析时应考虑到这一点。
* **ECC简化**: ECC的加解密实现是基于简化ECIES思想的，使用了SHA256作为KDF，XOR作为对称加密，主要用于演示原理，不具备生产级安全性。

## 未来工作/可扩展方向

* 为RSA实现更安全的填充方案，如OAEP。
* 实现ElGamal和ECC的数字签名方案 (ElGamal签名, ECDSA)，如果课程主题允许或有额外时间。
* 完善性能测试模块，增加更多测试维度和更精确的计时。
* 进一步优化前端用户体验和界面美观度。
* 增加对不同椭圆曲线参数的支持。
