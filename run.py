# run.py

from app import create_app

# 调用应用工厂函数创建 app 实例
flask_app = create_app()

if __name__ == '__main__':
    # 运行Flask开发服务器
    # debug=True 会在代码更改时自动重载服务器，并提供详细的错误调试信息
    # host='0.0.0.0' 使服务器可以从局域网内任何IP访问，而不仅仅是本机localhost
    # port=5000 是默认端口，你可以改成其他的
    flask_app.run(debug=True, host='0.0.0.0', port=5000)