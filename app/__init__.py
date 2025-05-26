from flask import Flask

def create_app():
    """
    应用工厂函数，用于创建和配置Flask应用实例。
    """
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'a_very_secret_and_unique_key_for_your_project'

    try:
        from .routes import main_bp  
        app.register_blueprint(main_bp) 

    except ImportError as e:
        app.logger.error(f"无法导入或注册主蓝图 (main_bp): {e}")

    try:
        from .api.rsa_routes import rsa_api_bp 
        app.register_blueprint(rsa_api_bp, url_prefix='/api') 

    except ImportError as e:
        app.logger.error(f"无法导入或注册RSA API蓝图 (rsa_api_bp): {e}")

    try:
        from .api.elgamal_routes import elgamal_api_bp 
        app.register_blueprint(elgamal_api_bp, url_prefix='/api') 
    except ImportError as e:
        app.logger.error(f"无法导入或注册ElGamal API蓝图 (elgamal_api_bp): {e}")

    try:
        from .api.ecc_routes import ecc_api_bp 
        app.register_blueprint(ecc_api_bp, url_prefix='/api') 
    except ImportError as e:
        app.logger.error(f"无法导入或注册ECC API蓝图 (ecc_api_bp): {e}")


    if not app.url_map.bind('').match('/', 'GET'): 
        @app.route('/')
        def simple_index():
            return "密码学算法实验平台后端已启动。"

    return app